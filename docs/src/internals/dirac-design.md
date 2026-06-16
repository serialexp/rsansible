# Declarative front-end — design

Status: **design sketch, not yet built.** A paper-exercise spike lives
at `crates/declarative-spike/`; it defines the user-facing types and
signatures and is exercised by three working examples
(`nginx`, `postgres`, `postgres_with_roles`). No engine.

This document captures the reasoning behind the spike and the
architectural shape we'd build out if/when we commit. It is meant to
outlive the spike crate — if you delete the spike, this document is
what tells the next person what we agreed.

## The problem we are solving

Ansible playbooks execute author-ordered: task N+1 starts after every
host finishes task N. The implicit assumption is that each task
depends on the previous one, even when it doesn't — and Ansible has no
way to know which dependencies are real, because:

1. **Variable references are strings.** `{{ x }}` in a template is a
   text-substitution that the engine cannot see as an edge from "task
   that set `x`" to "task that reads it." Inference requires a
   Jinja-aware AST walk.
2. **Side-effect dependencies are invisible.** A `template:` writes a
   file; a `service:` reads it via `daemon-reload`. Nothing in the
   YAML says so. Authors express the link with `notify:` and handler
   flushes — a fourth-class DSL bolted on top.
3. **Control flow is reinvented.** `when:` / `loop:` / `block:` /
   `rescue:` / `import_tasks:` are Ansible's reinvention of
   `if`/`for`/`try`/`import` that already exist in every real
   language. Each one is its own bug surface and its own surprise.
4. **Variable precedence is a 22-level table** because there is no
   scoping mechanism — no `let` to look at, no module to consult.

The cost is the wall-clock: a play with 30 tasks where the critical
path is 4 deep finishes in 30 task-times, not 4. "Speed of slowest
dependency" — Pulumi's pitch — is unattainable in YAML-with-Jinja
because the engine cannot see the dependencies it would need to
parallelise around.

## Why a real language is the only honest answer

The DAG inference story falls out trivially if references *are*
bindings instead of strings:

- Pulumi can schedule `policy` after `bucket` because `bucket.arn` is
  a typed `Output<string>` the policy resource literally holds — the
  reference *is* the edge.
- No template walker, no "did the author typo a variable name and
  silently get `undefined`," no runtime shape-guessing.

Once you accept references must be bindings, you need scope; once you
need scope, you need a real language; once you have a real language,
the entire `when:` / `loop:` / `block:` / 22-level-precedence edifice
collapses into the host language's `if` / `for` / `try` / `let` /
module system.

YAML+Jinja is the past. Every workable "infra as code" attempt
eventually reinvents half a programming language badly. We stop at the
first half and pick a whole one.

## Two products, one engine

This is **not** an evolution of rsansible-the-compat-tool. It's a
sibling.

- **rsansible (compat layer).** Runs your existing Ansible playbooks,
  faster. Already at production-homelab parity. The migration on-ramp.
- **Dirac.** Pulumi-style declarative, typed, real language,
  DAG-native. Greenfield-only — no YAML compat layer, no translation
  tool. If you want to migrate, you migrate once and rewrite, with
  both old and new running in production during the transition.

The name "Dirac" comes from James Blish's "Beep" (1954) / *The
Quincunx of Time*, where the Dirac transmitter receives every message
ever sent compressed into a single beep. Two reasons it fits:

1. **The whole plan in one declaration.** A declarative plan is the
   entire DAG stated up front — one transmission, the engine unfolds
   it into the field over the wire. Same shape as the fictional
   device.
2. **Ship the whole binary.** rsansible already pushes a complete
   musl-static agent in one SSH push; the Dirac frontend pushes a
   complete plan in one declaration. Both layers of the product do
   the same thing the fictional device does.

(Free bonus: Paul Dirac the physicist gives us the Dirac delta —
"zero everywhere, all the mass at one point," which is accidentally
the metaphor for a declarative plan. No one needs to know to use
the tool.)

The reason Dirac earns its own product identity rather than hiding
behind a `--declarative` flag: the conceptual model is different
enough that "drop-in faster Ansible" stops being the right elevator
pitch. Pulumi made the same call against Terraform — same problem
space, different first principles, different brand, both ship.

Under the hood: same engine. The DAG IR is the contract. Multiple
frontends emit it; the engine consumes it. The Ansible-compat frontend
lifts YAML playbooks into a (less rich) DAG via Jinja inference and
module-resource declarations; the Dirac frontend lets users build the
DAG directly with no inference needed.

## Frontend choice

Two SDKs, both first-class:

1. **Rust SDK** — used by us to test the engine; used by power users
   who want a single static binary. The spike crate is this SDK's
   user-facing surface.
2. **TypeScript SDK** — recommended authoring surface for everyday
   use. Talks to the engine over JSON-RPC/stdio. Ships as
   `@aeolun/dirac` (the bare `dirac` npm slot is occupied by an
   abandoned Node-PG database layer; scoped is fine). Pulumi
   precedent, best DX, async maps perfectly to `Output<T>`, ops
   people will tolerate a Node runtime they won't tolerate a Rust
   toolchain.

The Rust SDK is what the spike validates. TypeScript is a port of the
same types and conventions; specifics deferred.

## Core abstractions

### `Output<T>` — deferred values

A value that may not be known at plan-construction time. Produced by
facts (`host.facts().default_ipv4()`), template renders, vault
lookups, and (future) other resources' outputs. Consumed by passing
into another resource's typed field — that act declares the dependency
edge.

`.apply(closure)` lifts a transformation into the deferred world.
Multi-input combinations use the `out!` macro from day one (the design
conversation flagged it as the common case before we wrote a single
example — sugar should not lag known pain).

```rust
let leader_ip: Output<IpAddr> = leader.facts().default_ipv4();
let cmd = out!(leader_ip => |ip| Shell::new(
    format!("pg_basebackup -h {ip} ...")
));
// `cmd: Output<Shell>` flows into InlineModule.apply; that flow is the edge.
```

`.apply()` takes `&self`, so the same `Output` is reusable across loop
iterations without explicit cloning. Validated by the postgres example
using `leader_ip` once per follower.

### Resources are struct values

Every resource is declared by constructing a struct and handing it to
a node sink:

```rust
node.file(File {
    path: "/etc/nginx/nginx.conf".into(),
    content: NginxConf { … }.render(),
    owner: Some("root".into()),
    mode: Some(0o644),
    after: deps![pkg],
    ..Default::default()
});
```

Decisions baked in:

- **No builder chaining.** No `node.file(…).owner("root").after(&pkg)`.
  Every optional or dependency field is a field on the struct.
  Confirmed user preference: builders make reading hard.
- **`..Default::default()` for elision.** Required fields default to
  obviously-broken values (empty string for `name`) so forgotten
  required fields are visible in code review. Optional fields default
  to `None` / `vec![]`.
- **`InlineModule` deliberately has no `Default`.** All four fields
  (`name`, `check`, `apply`, `triggers`) are required. The compile
  error if you forget any is the point — when you step out of the
  typed module world, you owe the engine the metadata it would
  otherwise infer, and the type system makes that owing visible.

### Dependencies — `deps!` and `AsDep`

Resource refs are typed (`ResourceRef<Package>`) for clarity at
construction sites; the dependency fields themselves are type-erased
`Vec<Dep>`. The `deps!` macro builds these vecs and the `AsDep` trait
(blanket-impl'd for `&T`) means both owned `ResourceRef` (which is
`Copy`) and `&ResourceRef` (the form role functions receive as
params) just work:

```rust
after: deps![pkg, hba],            // owned Copy refs from local scope
triggers: deps![repl_user, svc],   // &ResourceRef params from a role function
```

The `AsDep` trait was a fix discovered by writing the roles example
and hitting `&&ResourceRef`. The lesson: macros that wrap user refs
should desugar through a trait, not through a literal `&` insertion.

### Templates

```rust
pub trait Template: Send + Sync + 'static {
    fn render(&self) -> Output<String>;
}
```

Two impls live in the SDK; users add their own:

- `InlineTemplate(String)` — literal content, no substitution.
- `#[derive(Template)]` (proc-macro, not yet built) — typed fields
  driving a `templates/foo.tmpl` file. Typos in field references
  become compile errors instead of runtime "rendered as empty string."

The `Send + Sync + 'static` bound on the trait is deliberate: it
prevents templates from capturing non-parallel-safe state (`Rc`,
borrowed locals), keeping the parallel-execution story honest.

### Secrets

```rust
pub struct Secret<T>(T);
impl<T> Debug for Secret<T> { /* renders "Secret(***)" */ }
```

Real impl adds Zeroize-on-Drop. `Secret<String>` flows into resource
fields typed (`PostgresqlUser.password: Secret<String>`); no
string-template indirection, no `no_log:` flag, leaks are visible in
review because exposing the inner value requires calling
`.expose()` by name.

### Vault

```rust
pub fn get(&self, key: &str) -> Option<&Secret<String>>;     // optional
pub fn require(&self, key: &str) -> &Secret<String>;          // plan-time panic on miss
```

`.require()` is the right default for keys your plan needs to exist.
"Missing required vault key" is a programming error, not a runtime
condition to thread `Result`s through. `.get()` stays for the genuine
optional case.

### Inventory

One user-defined entry point — `fn inventory() -> Result<Inventory>` —
that may use any combination of:

```rust
// File-based:
Inventory::from_toml("hosts.toml")

// Hand-built:
let mut inv = Inventory::default();
inv.add_host("web-1", "10.0.0.1");
inv.add_to_group("web", "web-1");
Ok(inv)

// Dynamic — call your CMDB:
let hosts = my_cmdb::fetch_hosts()?;
let mut inv = Inventory::default();
for h in hosts { inv.add_host(&h.name, &h.addr); }
Ok(inv)
```

The "static vs dynamic inventory plugin zoo" disappears. The function
IS the dynamic hook; `from_toml` is one of the things it may call.

### Plan and Node

```rust
let plan = Plan::new();
let node = plan.node(host);
let pkg = node.package(Package { … });
```

`Plan` is interior-mutable (`RefCell` in the spike). `Node` is a
cheap per-host handle that pushes into the plan. `Node` does **not**
carry per-node `become_` or other context — every resource carries
its own `become_` field, so the precedence model is read at the
declaration site instead of in a separate "context" object.

### Roles are functions

There is no `roles/` directory convention, no `tasks/main.yml`, no
`defaults/`/`vars/`/`meta/` split, no role search path. A role is a
function that takes a `&Plan` and whatever it needs to know, and
returns a typed struct of handles:

```rust
struct PgBaseline {
    pkg: ResourceRef<Package>,
    hba: ResourceRef<File>,
    svc: ResourceRef<Service>,
}

fn postgres_baseline(plan: &Plan, host: &Host) -> PgBaseline { … }
```

Downstream consumers reference specific handles by name
(`bases["postgres-leader"].svc`) instead of fishing things out of a
register or hoping the right value lands on the right key. Adding a
resource to a role is one struct field plus one assignment; existing
consumers compile unchanged, new consumers opt in by referencing the
new field.

Validated by `examples/postgres_with_roles.rs`: same 12 resources as
the inline version, but the leader/follower phases read as three
top-level statements (`postgres_baseline_group`, `replication_user`,
`for follower in … { bootstrap_follower(…) }`) instead of
two-pass-collect-then-iterate.

### The escape hatch: `InlineModule`

```rust
pub struct InlineModule {
    pub name: String,
    pub check: ChangeCheck,      // PathExists | ShellExits | AlwaysApply
    pub apply: Output<Shell>,
    pub triggers: Vec<Dep>,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}
```

Run an arbitrary shell command as a resource. **All four fields are
required** — no `Default` impl. The ceremony is deliberate: the
engine cannot reason about a shell command on its own, so the author
must hand over the change-detection metadata (`check`) and the
re-run-on-upstream-change metadata (`triggers`) that the typed module
API would otherwise carry implicitly.

There is **no `RemoteCommand` / `command:` first-class resource.** If
you need to run a command and want the engine to reason about it, you
write an `InlineModule` with the ceremony, OR you upgrade it to a
typed module if the pattern recurs. The verbosity of `InlineModule`
is the signal that you're stepping out of the typed world.

## Engine architecture (sketch)

The engine consumes a DAG IR. Nodes are resources; edges come from:

1. **Value flow.** A resource that takes `Output<T>` from another
   resource (or a fact, or a template render) is downstream of the
   producer. No inference required — the value handle IS the edge.
2. **Explicit `after:` / `reload_on:` / `restart_on:` / `triggers:`**
   fields on resource structs.
3. **(Future)** Module-declared resource footprints
   (`Package::owns_files(["/etc/nginx/*"])`). Two resources writing
   the same path on the same host get an edge automatically.
   Deferred — explicit `.after()` is fine for v1, and shipping
   without footprint inference forces us to feel the cost up front.

Scheduling: topological sort. Nodes whose deps are all resolved get
dispatched; the engine drives them concurrently up to a per-host
concurrency limit. Handlers (the `reload_on:` semantics) collapse
into ordinary DAG edges — the service resource is downstream of every
config-file resource it watches, and a reload only fires when an
upstream actually changed (the engine knows because it ran the
upstream).

What rsansible-classic already provides that the engine inherits
unchanged:

- The musl-static agent + push-over-SSH transport.
- Per-host agent pools keyed by `BecomeKey` (`become:` routes to the
  right agent process; no per-op argv wrapping).
- Forward mode (collapse long-haul RTT by pushing the controller
  next to the targets).
- Wire-time accounting infrastructure.

The engine's job is the DAG walker and the per-host scheduler.
Everything below the transport is already built and known to work
against real fleets.

## Decisions explicitly deferred

These are real decisions we agreed to postpone rather than
not-yet-thought-about. When you start building, revisit:

1. **Resource outputs as `Output<T>`.** Currently resources return
   `ResourceRef<T>` (a handle for dep edges) but don't expose typed
   outputs. A `PostgresqlUser` could plausibly return `Output<UserOid>`
   that a grant resource consumes. Trivially additive when needed;
   the spike does not exercise it.
2. **Module-declared resource footprints.** Engine-side inference of
   "two resources touching the same path on the same host get an
   edge." Postponed so we feel the cost of explicit `.after()` and
   develop the footprint API against real usage rather than guessing.
3. **`#[derive(Template)]` proc-macro.** Spike hand-implements
   `Template`. The macro should read a `templates/foo.tmpl` file at
   compile time, parse its variable references, and emit a `render()`
   method against typed struct fields — typo = compile error.
4. **TypeScript SDK.** Same conventions, different language. Not
   started; do it once the Rust SDK + engine are real enough to
   speak JSON-RPC.
5. **The plan-time concurrency model.** `Plan` is currently
   `RefCell`-interior-mutable; sufficient for the spike's
   single-threaded examples. A real engine needs a `Sync`-safe Plan
   or a clear single-author-thread contract.

## The spike crate

`crates/declarative-spike/` exists as the executable record of the
above. It is **types and signatures only** — every method body is a
placeholder. Examples in `examples/` validate that the API surface
can express the cases we care about:

- `nginx.rs` — basic per-host (package + templated config + service
  with `reload_on:`).
- `postgres.rs` — cross-host coordination (leader/follower with
  fact-derived `Output<IpAddr>`, `InlineModule` escape hatch,
  secrets).
- `postgres_with_roles.rs` — same plan, refactored around roles as
  functions returning typed handle bundles.

If you delete the spike, this document still tells you what was
decided and why. If you delete this document, the spike still shows
the shape but loses the reasoning. Keep both, or replace this document
with whatever evolves out of starting the real build.

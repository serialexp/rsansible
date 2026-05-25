//! Declarative resource API spike for rsansible.
//!
//! This crate is a paper exercise: it defines the user-facing types and
//! signatures for a Pulumi-style declarative replacement for the YAML
//! playbook front-end. **Nothing here executes.** The goal is to stress-test
//! the API surface by writing real plans against it (`examples/nginx.rs`,
//! `examples/postgres.rs`) and surface awkward seams before any engine work
//! is started.
//!
//! Conventions:
//! - **Struct-form everywhere.** Resources are declared by constructing a
//!   struct and handing it to a sink (`node.file(File { … })`). No builder
//!   chaining. Optional/dependency fields (`after`, `reload_on`, `become_`,
//!   `triggers`) are fields on the struct, never methods.
//! - **`Output<T>` carries deferred values.** Produced by facts, vault
//!   lookups, template renders, and (in a real impl) other resources'
//!   outputs. Consumed by passing into another resource's field — that
//!   passing is what declares the edge.
//! - **`out!` macro sugars `.apply()`** for one-to-three Output inputs.
//!   We know from the design conversation that multi-input `.apply()` is
//!   the common case, so the sugar exists from day one.
//! - **Type-erased `Dep` for dependency fields.** Construct with the
//!   `deps![ref, ref, …]` macro. A `Dep` is just an ID — the type
//!   parameter on `ResourceRef<T>` is preserved at construction sites
//!   so that future APIs (e.g. `Output<T>::from(resource_output)`) can
//!   still be typed, but the edge list itself is uniform.
//! - **No automatic footprint inference.** A resource depends on another
//!   only when the user says so via `after:` (or by passing an `Output`
//!   from one into another). Module-declared resource footprints
//!   (`Package::owns_files(…)`) are a future feature; the spike keeps
//!   edges fully explicit so we can feel the cost.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;

// ============================================================
// Output<T>
// ============================================================

/// A value that may not be known at plan-construction time.
///
/// Produced by:
/// - **Facts** (`host.facts().default_ipv4()`) — gathered from the host
///   when the engine runs.
/// - **Template renders** (`template.render()`) — resolved once template
///   inputs are resolved.
/// - **Vault lookups** that defer decryption.
/// - (Future) **Resource outputs** — e.g. a `PostgresqlUser` returning
///   an `Output<UserId>` you can pass into a grant resource.
///
/// Consumed by passing into another resource's typed field. That act
/// declares the dependency edge: the consumer cannot run until every
/// `Output` it received has resolved.
///
/// `.apply(closure)` lifts a transformation into the deferred world.
/// For two- and three-input combinations use the [`out!`] macro.
pub struct Output<T> {
    _inner: Arc<OutputInner>,
    _ty: PhantomData<fn() -> T>,
}

// Opaque for the spike. A real impl would carry one of:
//   - Ready(T)
//   - Pending(future)
//   - Chain { upstream: Vec<Arc<OutputInner>>, transform: Box<dyn ...> }
struct OutputInner;

impl<T: Clone + Send + Sync + 'static> Output<T> {
    /// Construct from an already-known value.
    pub fn ready(_value: T) -> Self {
        Self {
            _inner: Arc::new(OutputInner),
            _ty: PhantomData,
        }
    }

    /// Transform the value when it resolves. Returns a new `Output<U>`
    /// that the engine schedules after this one.
    pub fn apply<U, F>(&self, _f: F) -> Output<U>
    where
        U: Clone + Send + Sync + 'static,
        F: FnOnce(T) -> U + Send + 'static,
    {
        Output {
            _inner: self._inner.clone(),
            _ty: PhantomData,
        }
    }

    /// Combine two outputs into one. The result resolves after both
    /// inputs resolve. Usually called via the [`out!`] macro.
    pub fn zip<B>(&self, other: &Output<B>) -> Output<(T, B)>
    where
        B: Clone + Send + Sync + 'static,
    {
        let _ = other;
        Output {
            _inner: self._inner.clone(),
            _ty: PhantomData,
        }
    }
}

impl<T> Clone for Output<T> {
    fn clone(&self) -> Self {
        Self {
            _inner: self._inner.clone(),
            _ty: PhantomData,
        }
    }
}

impl<T: Default + Clone + Send + Sync + 'static> Default for Output<T> {
    fn default() -> Self {
        Self::ready(T::default())
    }
}

impl From<&str> for Output<String> {
    fn from(s: &str) -> Self {
        Self::ready(s.to_string())
    }
}

impl From<String> for Output<String> {
    fn from(s: String) -> Self {
        Self::ready(s)
    }
}

/// Apply a closure across one to three [`Output`] values.
///
/// ```ignore
/// // single input — sugar for .apply()
/// out!(leader_ip => |ip| format!("server {ip}"))
///
/// // two inputs — sugar for .zip().apply()
/// out!(leader_ip, db_port => |ip, port| format!("{ip}:{port}"))
///
/// // three inputs
/// out!(a, b, c => |x, y, z| (x, y, z))
/// ```
///
/// The expressions are taken by reference (`.apply()` borrows `&self`),
/// so the same `Output` can be used in multiple `out!` calls without
/// cloning explicitly.
#[macro_export]
macro_rules! out {
    ($x:expr => |$p:ident| $body:expr) => {
        ($x).apply(move |$p| $body)
    };
    ($x:expr, $y:expr => |$p1:ident, $p2:ident| $body:expr) => {
        ($x).zip(&$y).apply(move |($p1, $p2)| $body)
    };
    ($x:expr, $y:expr, $z:expr => |$p1:ident, $p2:ident, $p3:ident| $body:expr) => {
        ($x).zip(&$y).zip(&$z).apply(move |(($p1, $p2), $p3)| $body)
    };
}

// ============================================================
// Resources
// ============================================================

/// Typed handle to a declared resource. Cheap (Copy) — pass by value
/// or by reference as convenient.
pub struct ResourceRef<T> {
    id: ResourceId,
    _ty: PhantomData<fn() -> T>,
}

impl<T> Clone for ResourceRef<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ResourceRef<T> {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResourceId(u64);

/// Type-erased dependency. Field type for `after:` / `reload_on:` /
/// `restart_on:` / `triggers:`. Construct with [`deps!`] or directly
/// via `Dep::from(&resource_ref)`.
#[derive(Copy, Clone, Debug)]
pub struct Dep(#[allow(dead_code)] ResourceId);

/// Anything that can be turned into a [`Dep`]. Blanket-implemented for
/// `&T where T: AsDep` so the [`deps!`] macro accepts both owned
/// `ResourceRef<T>` (which is `Copy`) and `&ResourceRef<T>` (the form
/// you get inside role functions that receive refs as parameters).
pub trait AsDep {
    fn as_dep(&self) -> Dep;
}

impl<T> AsDep for ResourceRef<T> {
    fn as_dep(&self) -> Dep {
        Dep(self.id)
    }
}

impl<T: AsDep + ?Sized> AsDep for &T {
    fn as_dep(&self) -> Dep {
        (**self).as_dep()
    }
}

/// Build a `Vec<Dep>` from any number of resource refs. Owned and
/// borrowed refs both work — the macro calls [`AsDep::as_dep`] which
/// auto-derefs through references.
///
/// ```ignore
/// after: deps![pkg, hba],            // owned Copy refs
/// triggers: deps![repl_user, svc],   // &ResourceRef params from a role fn
/// ```
#[macro_export]
macro_rules! deps {
    () => { ::std::vec::Vec::<$crate::Dep>::new() };
    ($($e:expr),+ $(,)?) => {
        vec![$( $crate::AsDep::as_dep(&$e) ),+]
    };
}

// ============================================================
// Templates
// ============================================================

/// A renderable template. The real version is implemented by a
/// `#[derive(Template)]` proc-macro that reads a `templates/foo.tmpl`
/// file and generates the `render()` method against typed fields. For
/// the spike, examples implement this trait by hand.
pub trait Template: Send + Sync + 'static {
    fn render(&self) -> Output<String>;
}

/// A literal string template — no variable substitution. Useful for
/// static content (config files that don't depend on host context).
pub struct InlineTemplate(pub String);

impl Template for InlineTemplate {
    fn render(&self) -> Output<String> {
        Output::ready(self.0.clone())
    }
}

impl From<&str> for InlineTemplate {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for InlineTemplate {
    fn from(s: String) -> Self {
        Self(s)
    }
}

// ============================================================
// Secrets
// ============================================================

/// A wrapper that prevents accidental Debug-printing of sensitive values.
/// A real impl would also implement Zeroize-on-Drop.
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
    /// Explicit unwrap — name reads "I know this is sensitive" at the
    /// call site, so leaks are visible in review.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(***)")
    }
}

// ============================================================
// Inventory
// ============================================================

pub struct Inventory {
    hosts: BTreeMap<String, Host>,
    groups: BTreeMap<String, BTreeSet<String>>,
}

pub struct Host {
    name: String,
    address: String,
}

impl Host {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn address(&self) -> &str {
        &self.address
    }
    pub fn facts(&self) -> Facts {
        Facts {
            host: self.name.clone(),
        }
    }
}

/// Handle to a host's gathered facts. Each accessor returns an
/// [`Output<T>`] — the engine schedules the fact-gather node before any
/// consumer runs.
pub struct Facts {
    host: String,
}

impl Facts {
    pub fn default_ipv4(&self) -> Output<IpAddr> {
        Output::ready("127.0.0.1".parse().unwrap())
    }
    pub fn os_family(&self) -> Output<String> {
        Output::ready("Debian".to_string())
    }
    pub fn hostname(&self) -> Output<String> {
        Output::ready(self.host.clone())
    }
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            hosts: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }
}

impl Inventory {
    /// Load from a TOML file. **Spike stub** returns empty — a real
    /// impl would parse the file. Users who want a file-based inventory
    /// use this constructor from inside their own `fn inventory()`.
    ///
    /// ```ignore
    /// fn inventory() -> Result<Inventory, Box<dyn Error>> {
    ///     // Pure file path:
    ///     Inventory::from_toml("inventory.toml")
    ///
    ///     // Hand-built:
    ///     let mut inv = Inventory::default();
    ///     inv.add_host("web-1", "10.0.0.1");
    ///     inv.add_to_group("web", "web-1");
    ///     Ok(inv)
    ///
    ///     // Dynamic — call out to your CMDB:
    ///     let hosts = my_cmdb::fetch_hosts()?;
    ///     let mut inv = Inventory::default();
    ///     for h in hosts { inv.add_host(&h.name, &h.addr); }
    ///     Ok(inv)
    /// }
    /// ```
    ///
    /// There is no separate "static" / "dynamic" inventory split — the
    /// function the user writes IS the dynamic-inventory hook, and one
    /// of the things it may call is [`Inventory::from_toml`].
    pub fn from_toml(_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::default())
    }

    pub fn host(&self, name: &str) -> Option<&Host> {
        self.hosts.get(name)
    }

    pub fn group(&self, name: &str) -> impl Iterator<Item = &Host> + '_ {
        self.groups
            .get(name)
            .into_iter()
            .flat_map(|s| s.iter())
            .filter_map(|n| self.hosts.get(n))
    }

    // ---- spike-only helpers ----

    pub fn add_host(&mut self, name: &str, address: &str) {
        self.hosts.insert(
            name.to_string(),
            Host {
                name: name.to_string(),
                address: address.to_string(),
            },
        );
    }

    pub fn add_to_group(&mut self, group: &str, host: &str) {
        self.groups
            .entry(group.to_string())
            .or_default()
            .insert(host.to_string());
    }
}

// ============================================================
// Vault
// ============================================================

pub struct Vault {
    secrets: BTreeMap<String, Secret<String>>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            secrets: BTreeMap::new(),
        }
    }
}

impl Vault {
    pub fn from_file(_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self::default())
    }

    /// Optional lookup. Returns `None` if absent. Prefer [`Vault::require`]
    /// for keys your plan *needs* — a missing required key is a plan-time
    /// programming error, not a runtime "handle the None" case.
    pub fn get(&self, key: &str) -> Option<&Secret<String>> {
        self.secrets.get(key)
    }

    /// Required lookup. Panics at plan time with a clear message if the
    /// key is missing — better than threading `Result`/`Option` through
    /// every consumer when "this key has to exist or my plan is wrong"
    /// is the actual semantics.
    pub fn require(&self, key: &str) -> &Secret<String> {
        self.secrets
            .get(key)
            .unwrap_or_else(|| panic!("vault: missing required key {key:?}"))
    }

    pub fn put(&mut self, key: &str, value: &str) {
        self.secrets
            .insert(key.to_string(), Secret::new(value.to_string()));
    }
}

// ============================================================
// Plan + Node
// ============================================================

pub struct Plan {
    inner: RefCell<PlanInner>,
}

#[derive(Default)]
struct PlanInner {
    resources: Vec<ResourceDecl>,
    next_id: u64,
}

#[allow(dead_code)]
struct ResourceDecl {
    id: ResourceId,
    host: HostId,
    kind: ResourceKind,
}

#[allow(dead_code)]
enum ResourceKind {
    Package(Package),
    File(File),
    Service(Service),
    Module(InlineModule),
    PostgresqlUser(PostgresqlUser),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostId(u64);

impl Default for Plan {
    fn default() -> Self {
        Self::new()
    }
}

impl Plan {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(PlanInner::default()),
        }
    }

    /// Get a [`Node`] handle scoped to `host`. Cheap (just an id wrap).
    pub fn node<'p>(&'p self, host: &Host) -> Node<'p> {
        Node {
            plan: self,
            host: HostId(host_id_hash(&host.name)),
        }
    }

    fn alloc_id(&self) -> ResourceId {
        let mut inner = self.inner.borrow_mut();
        inner.next_id += 1;
        ResourceId(inner.next_id)
    }

    fn push(&self, host: HostId, kind: ResourceKind) -> ResourceId {
        let id = self.alloc_id();
        self.inner
            .borrow_mut()
            .resources
            .push(ResourceDecl { id, host, kind });
        id
    }

    pub fn resource_count(&self) -> usize {
        self.inner.borrow().resources.len()
    }
}

fn host_id_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// Per-host handle for declaring resources. Construct via [`Plan::node`].
pub struct Node<'p> {
    plan: &'p Plan,
    host: HostId,
}

impl<'p> Node<'p> {
    pub fn package(&self, p: Package) -> ResourceRef<Package> {
        let id = self.plan.push(self.host, ResourceKind::Package(p));
        ResourceRef {
            id,
            _ty: PhantomData,
        }
    }

    pub fn file(&self, f: File) -> ResourceRef<File> {
        let id = self.plan.push(self.host, ResourceKind::File(f));
        ResourceRef {
            id,
            _ty: PhantomData,
        }
    }

    pub fn service(&self, s: Service) -> ResourceRef<Service> {
        let id = self.plan.push(self.host, ResourceKind::Service(s));
        ResourceRef {
            id,
            _ty: PhantomData,
        }
    }

    pub fn module(&self, m: InlineModule) -> ResourceRef<InlineModule> {
        let id = self.plan.push(self.host, ResourceKind::Module(m));
        ResourceRef {
            id,
            _ty: PhantomData,
        }
    }

    pub fn postgresql_user(&self, u: PostgresqlUser) -> ResourceRef<PostgresqlUser> {
        let id = self.plan.push(self.host, ResourceKind::PostgresqlUser(u));
        ResourceRef {
            id,
            _ty: PhantomData,
        }
    }
}

// ============================================================
// Become
// ============================================================

#[derive(Clone, Debug)]
pub enum BecomeUser {
    Root,
    Named(String),
}

// ============================================================
// Module: Package
// ============================================================

pub struct Package {
    pub name: String,
    pub state: PackageState,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}

impl Default for Package {
    fn default() -> Self {
        Self {
            name: String::new(),
            state: PackageState::Present,
            become_: None,
            after: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PackageState {
    Present,
    Absent,
    Latest,
}

// ============================================================
// Module: File
// ============================================================

pub struct File {
    pub path: String,
    pub content: Output<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: Option<u32>,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}

impl Default for File {
    fn default() -> Self {
        Self {
            path: String::new(),
            content: Output::ready(String::new()),
            owner: None,
            group: None,
            mode: None,
            become_: None,
            after: vec![],
        }
    }
}

// ============================================================
// Module: Service
// ============================================================

pub struct Service {
    pub name: String,
    pub running: bool,
    pub enabled: bool,
    pub reload_on: Vec<Dep>,
    pub restart_on: Vec<Dep>,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}

impl Default for Service {
    fn default() -> Self {
        Self {
            name: String::new(),
            running: false,
            enabled: false,
            reload_on: vec![],
            restart_on: vec![],
            become_: None,
            after: vec![],
        }
    }
}

// ============================================================
// Module: InlineModule (escape hatch)
// ============================================================

/// Run a shell command as a resource. The escape hatch for cases the
/// typed module API doesn't cover.
///
/// The ceremony is deliberate: the engine cannot reason about a shell
/// command on its own, so the author must hand over the metadata it
/// would otherwise infer. **All four required fields must be set
/// explicitly** — no `Default` impl, no shortcuts.
///
/// - [`ChangeCheck`] tells the engine when the work is already done.
/// - `apply` is the command to run when not done. Wrapped in
///   `Output<Shell>` so it can depend on fact-derived values.
/// - `triggers` are resources whose changes force a re-run regardless
///   of `check`.
///
/// If you find yourself reaching for `InlineModule` for something that
/// recurs across plans, that's the signal to add it as a first-class
/// typed module instead.
pub struct InlineModule {
    pub name: String,
    pub check: ChangeCheck,
    pub apply: Output<Shell>,
    pub triggers: Vec<Dep>,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}

pub enum ChangeCheck {
    /// Resource is already done if this path exists on the target.
    PathExists(String),
    /// Resource is already done if this shell command exits 0.
    ShellExits(String),
    /// Always run. Use only when re-running is harmless or `triggers:`
    /// fully expresses the change semantics.
    AlwaysApply,
}

#[derive(Clone)]
pub struct Shell {
    pub cmd: String,
}

impl Shell {
    pub fn new(cmd: impl Into<String>) -> Self {
        Self { cmd: cmd.into() }
    }
}

// ============================================================
// Module: PostgresqlUser (example of a domain-specific typed module)
// ============================================================

pub struct PostgresqlUser {
    pub name: String,
    pub password: Secret<String>,
    pub flags: Vec<RoleFlag>,
    pub become_: Option<BecomeUser>,
    pub after: Vec<Dep>,
}

#[derive(Clone, Copy, Debug)]
pub enum RoleFlag {
    Replication,
    Superuser,
    CreateDb,
    Login,
}

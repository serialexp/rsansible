# rsansible

An Ansible-shaped configuration tool that avoids Ansible's per-task SSH cost.

The model: push a single static binary to each host over SSH, talk a framed
binary RPC protocol to it for the duration of the run, then delete it. Modules
(exec, shell, file ops, templating, service control, …) are inline in the agent
binary, not separate scripts. Hosts execute in lockstep — per-task barrier by
default — so it feels like Ansible's linear strategy, just fast.

Status: **pre-v0**. See `~/.claude/plans/rustling-imagining-journal.md` for the
plan.

## Layout

- `crates/wire/` — wire types (generated from `schema/wire.schema.json5` via
  binschema) plus length-prefix framing helpers.
- `crates/agent/` — the pushed binary. Reads framed messages from stdin, writes
  to stdout, dispatches to module handlers.
- `crates/ctl/` — the controller CLI. Parses playbooks, opens SSH sessions,
  pushes agents, drives the barrier loop.
- `schema/wire.schema.json5` — protocol source of truth.
- `examples/` — sample playbooks.

## Building

```
just gen-wire          # regenerate crates/wire/src/generated.rs from the schema
cargo build            # workspace
just build-agent-musl  # static stripped agent for Linux x86_64
```

`just gen-wire` requires `bun` and a checkout of binschema at
`$BINSCHEMA_ROOT` (default `~/Projects/binschema`).

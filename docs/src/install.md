# Installation

rsansible builds from source. There are no published binaries yet.

## Prerequisites

- A Rust toolchain (stable). Install via [rustup](https://rustup.rs/).
- The `x86_64-unknown-linux-musl` target for building the static
  agent and controller binaries:
  ```
  rustup target add x86_64-unknown-linux-musl
  ```
- `bun` and a checkout of [binschema](https://github.com/serialexp/binschema)
  at `$BINSCHEMA_ROOT` (default `~/Projects/binschema`) — only needed
  if you intend to regenerate the wire schema.

## Building

```
git clone https://github.com/serialexp/rsansible
cd rsansible

just gen-wire           # regenerate crates/wire/src/generated.rs from schema (optional)
cargo build             # workspace
just build-agent-musl   # static stripped agent for Linux x86_64
just build-ctl-musl     # static ctl binary (required for forward mode)
```

After a release build you'll have:

- `target/release/rsansible` — the controller, on your operator host.
- `target/x86_64-unknown-linux-musl/release/rsansible-agent` — the
  agent, to be pushed to managed hosts.
- `target/x86_64-unknown-linux-musl/release/rsansible-ctl` — the
  static controller, used by forward mode to drive runs from a host
  near the targets.

The agent and the musl controller are both single static binaries.
You don't install them anywhere — the controller pushes whichever
agent path you give it on each run, into a per-run temp directory
on the target, and cleans up on exit.

## Platform support

- **Controller:** anything Rust runs on. Bart develops on Linux. macOS
  works for normal runs; forward mode currently requires a Linux
  controller.
- **Agent / forwarder:** Linux x86_64 only in v1. The agent uses
  Linux-specific paths in most modules; arm64-linux and a wider
  matrix are achievable but unscheduled.

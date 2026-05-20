# rsansible — task recipes.
#
# Most things here are about the codegen handoff from binschema. Regular
# build/test runs via `cargo` or `cargo burst` directly.

set shell := ["bash", "-euo", "pipefail", "-c"]

binschema_root := env_var_or_default("BINSCHEMA_ROOT", env_var("HOME") + "/Projects/binschema")
schema := justfile_directory() + "/schema/wire.schema.json5"
gen_out := justfile_directory() + "/target/wire-gen"

# Regenerate the wire-protocol Rust types from schema/wire.schema.json5.
#
# Writes crates/wire/src/generated.rs (CHECKED IN). The generated code depends
# on the `binschema_runtime` crate which we pull in as a path dependency to
# $BINSCHEMA_ROOT/rust/ — see crates/wire/Cargo.toml. The CLI itself only
# emits generated.rs (no project scaffolding, no runtime copy).
gen-wire:
    rm -rf {{gen_out}}
    # Invoke the binschema CLI from local source — NOT via `bunx binschema`,
    # which resolves a cached npm artifact and silently ignores in-tree fixes.
    cd {{binschema_root}}/packages/binschema && \
        bun run src/cli/index.ts generate \
            --language rust \
            --schema {{schema}} \
            --out {{gen_out}}
    install -D -m 0644 {{gen_out}}/src/generated.rs crates/wire/src/generated.rs
    # Refresh the vendored binschema_runtime so we don't depend on a sibling
    # checkout — keeps `cargo check` working in CI / fresh clones.
    rm -rf crates/wire-runtime
    cp -r {{gen_out}}/binschema_runtime crates/wire-runtime
    @echo "regenerated crates/wire/src/generated.rs + crates/wire-runtime/ — review the diff"

# Build the agent for x86_64 Linux musl, stripped.
build-agent-musl:
    cargo build -p rsansible-agent --profile agent --target x86_64-unknown-linux-musl
    @ls -lh target/x86_64-unknown-linux-musl/agent/rsansible-agent

# Build the controller for x86_64 Linux musl, release.
#
# Used by forward mode: argv[0] is shipped over SSH to the forwarder, so
# the local binary must be musl-static + Linux x86_64 to be portable to
# the remote. Same binary serves local + remote roles (subcommands
# `remote-run`, `local-agent`).
build-ctl-musl:
    cargo build -p rsansible-ctl --release --target x86_64-unknown-linux-musl
    @ls -lh target/x86_64-unknown-linux-musl/release/rsansible

# Record the agent binary's stripped size at the current HEAD into
# agent-size-history.tsv. No-op if HEAD's short SHA is already there.
size:
    @./scripts/record-agent-size.sh

# Crate-level bloat report against the stripped musl agent.
bloat:
    cargo bloat --target x86_64-unknown-linux-musl --profile agent -p rsansible-agent --crates -n 30

# Standard checks.
check:
    cargo check --workspace --all-targets

test:
    cargo nextest run --workspace || cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

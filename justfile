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
    # nextest isolates each test in its own process (distinct pid), so the
    # agent crate's pid+timestamp temp-dir tests don't collide. The plain
    # `cargo test` fallback shares one pid across threads and would flake, so
    # it runs single-threaded. See TODO.md for the proper fix.
    cargo nextest run --workspace || cargo test --workspace -- --test-threads=1

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all -- --check

fmt:
    cargo fmt --all

# Build the documentation site (mdBook) into docs/book/.
#
# Requires `mdbook` on PATH: `cargo install mdbook`.
docs:
    cd docs && mdbook build

# Serve the docs locally with live reload on http://localhost:3000.
docs-serve:
    cd docs && mdbook serve --open

# Build a release tarball for the host's musl/darwin target, mirroring the
# layout the release.yml workflow ships. Output lands in dist/. Useful for
# reproducing/debugging a release off-CI.
#
# TARGET defaults to x86_64 Linux musl; override for other hosts, e.g.
#   just dist aarch64-apple-darwin
dist target="x86_64-unknown-linux-musl":
    #!/usr/bin/env bash
    set -euo pipefail
    target="{{target}}"
    version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
    stage="rsansible-${version}-${target}"
    echo ">> building agent (x86_64 musl) + controller (${target})"
    cargo build -p rsansible-agent --profile agent --target x86_64-unknown-linux-musl
    cargo build -p rsansible-ctl --release --target "${target}"
    rm -rf "dist/${stage}"
    mkdir -p "dist/${stage}"
    cp "target/${target}/release/rsansible" "dist/${stage}/"
    cp "target/x86_64-unknown-linux-musl/agent/rsansible-agent" "dist/${stage}/"
    strip "dist/${stage}/rsansible" 2>/dev/null || true
    chmod +x "dist/${stage}/rsansible" "dist/${stage}/rsansible-agent"
    cp README.md LICENSE-MIT LICENSE-APACHE "dist/${stage}/"
    ( cd dist && tar -czf "${stage}.tar.gz" "${stage}" \
        && { command -v sha256sum >/dev/null 2>&1 \
               && sha256sum "${stage}.tar.gz" > "${stage}.tar.gz.sha256" \
               || shasum -a 256 "${stage}.tar.gz" > "${stage}.tar.gz.sha256"; } )
    echo ">> dist/${stage}.tar.gz"
    tar tzf "dist/${stage}.tar.gz"

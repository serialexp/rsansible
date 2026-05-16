#!/usr/bin/env bash
# Record the stripped musl agent binary size at the current HEAD into
# agent-size-history.tsv. No-op if HEAD's short SHA is already present.
#
# Columns (tab-separated):
#   commit          short SHA (git rev-parse --short HEAD)
#   date            commit author date (ISO-8601, UTC)
#   total_bytes     bytes of the stripped binary on disk
#   text            .text section (bytes, from `size`)
#   data            .data section (bytes, from `size`)
#   bss             .bss  section (bytes, from `size`)
#   subject         commit subject line (truncated to 60 chars)
#
# Run from the repo root via `just size` or directly.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

history_file="$repo_root/agent-size-history.tsv"
header=$'commit\tdate\ttotal_bytes\ttext\tdata\tbss\tsubject'

if [[ ! -f "$history_file" ]]; then
  printf '%s\n' "$header" > "$history_file"
fi

commit="$(git rev-parse --short HEAD)"
if grep -q "^${commit}"$'\t' "$history_file"; then
  echo "size already recorded for ${commit}; skipping" >&2
  grep "^${commit}"$'\t' "$history_file"
  exit 0
fi

date_iso="$(git show -s --format=%cI HEAD)"
subject="$(git show -s --format=%s HEAD | cut -c1-60)"

echo "building agent binary (profile=agent, musl)..." >&2
cargo build -p rsansible-agent --profile agent --target x86_64-unknown-linux-musl --quiet

bin="$repo_root/target/x86_64-unknown-linux-musl/agent/rsansible-agent"
if [[ ! -f "$bin" ]]; then
  echo "expected binary not found at $bin" >&2
  exit 1
fi

total_bytes="$(stat -c %s "$bin")"
# `size` is part of binutils; sysv format is the easiest to parse.
read -r text data bss _ _ <<<"$(size -A "$bin" 2>/dev/null \
  | awk '/^\.text/ {t=$2} /^\.data/ {d=$2} /^\.bss/ {b=$2} END {print t,d,b}')"
# Some musl-built ELFs have .data folded into other sections; default to 0.
text="${text:-0}"; data="${data:-0}"; bss="${bss:-0}"

row=$'\t'
printf '%s\n' "${commit}${row}${date_iso}${row}${total_bytes}${row}${text}${row}${data}${row}${bss}${row}${subject}" \
  >> "$history_file"

echo "recorded:" >&2
printf '  commit=%s date=%s total=%s text=%s data=%s bss=%s\n' \
  "$commit" "$date_iso" "$total_bytes" "$text" "$data" "$bss" >&2
echo "  subject=$subject" >&2

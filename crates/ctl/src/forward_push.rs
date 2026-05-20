//! Binary push and content-addressed caching for forward mode.
//!
//! Forward mode ships two musl-static binaries (the controller and the
//! agent) to the forwarder on every run. In the v1 implementation
//! they rode the same SSH session as the workflow payload, consumed
//! off stdin by `head -c N` from a bash one-liner — simple but
//! interacts poorly with SSH channel windowing + TCP slow-start. A
//! 20 MiB push from JP↔FI clocked ~7.5s, ~half the post-internal-IP
//! drill's wall time.
//!
//! This module amortizes that cost in two ways:
//!
//! 1. **Content-addressed cache** in `/tmp/rsansible-cache/<sha256>`
//!    on the forwarder. A first run uploads; subsequent runs against
//!    the same forwarder with the same binaries skip the push
//!    entirely. /tmp is the usual ephemeral story (cleared on reboot,
//!    pruned by tmpwatch policies on most distros). The cache is
//!    bounded by however long the OS keeps /tmp around — explicitly
//!    NOT a long-term store. We accept the cost of re-pushing after
//!    reboots; the win we care about is the dev-loop case where the
//!    same binary gets pushed twenty times in an hour.
//!
//! 2. **Per-binary parallel push** via separate SSH sessions. When a
//!    cache miss happens, ctl and agent push in parallel
//!    (`tokio::try_join!`) so the wall time is `max(ctl_push,
//!    agent_push)` instead of the sum. Each push is itself a single
//!    SSH session whose stdin streams the binary into a temp file in
//!    the cache dir, then renames into place atomically — concurrent
//!    runs against the same forwarder can't half-write each other.
//!
//! Opt-out: `--no-cache` falls back to the v1 per-run tmpdir behavior
//! ("leaves nothing behind on the forwarder"), at the cost of
//! re-pushing every run.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

/// On-disk location of a binary the remote bash script will `exec`.
///
/// `cache_hit` is informational — used by the caller to log whether
/// the run benefitted from the cache. The orchestration logic itself
/// only cares about `remote_path`.
#[derive(Debug, Clone)]
pub struct StagedBinary {
    /// Absolute path on the forwarder where the binary lives. Either
    /// inside `/tmp/rsansible-cache/` (cache hit or cache write) or
    /// inside a per-run tmpdir (with `--no-cache`).
    pub remote_path: String,
    /// `true` if the binary was already present in the cache before
    /// this run started; `false` if this run pushed it (or no-cache
    /// path was used).
    pub cache_hit: bool,
}

/// Coordinates the laptop uses to dial the forwarder for an
/// out-of-band push session. Mirrors `ForwarderTarget` but split out
/// here so this module doesn't depend on the parent.
#[derive(Debug, Clone)]
pub struct ForwarderDial {
    pub user: String,
    pub host: String,
    pub port: u16,
}

/// SHA-256 the binary bytes, lowercase hex. Used as the cache key
/// AND the on-disk filename — `/tmp/rsansible-cache/<hash>`. We hash
/// the bytes the laptop is about to push (post any local mtime/Sym
/// shenanigans), not the source path — two runs from two checkouts of
/// the same source tree that produce byte-identical binaries SHOULD
/// share a cache entry. Reverse: a cargo rebuild that bumps the
/// embedded build timestamp WILL miss the cache, which is what we
/// want (different bits → different identity).
pub fn hash_binary(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Probe the forwarder for which of the requested hashes are already
/// in `/tmp/rsansible-cache/`. One SSH session, one round-trip.
///
/// The remote script:
/// 1. `mkdir -p /tmp/rsansible-cache` so the dir exists for later
///    pushes even on an empty system. `chmod 0700` because the
///    binaries are executable and other users on the box shouldn't
///    be able to swap them out from under us.
/// 2. For each hash arg: print the hash if the file exists, else
///    don't print it. Caller diffs the requested set against the
///    printed set to find the misses.
///
/// On any SSH or remote failure: returns an error — we DON'T silently
/// fall back to "everything is a miss" because that would hide real
/// connectivity / permission problems behind extra upload work. If
/// the probe fails the caller should bail with a clear error.
pub async fn probe_cache(
    dial: &ForwarderDial,
    hashes: &[&str],
) -> Result<std::collections::BTreeSet<String>> {
    // Quote each hash for the bash for-loop. Hashes are
    // [0-9a-f]{64} so this is technically unnecessary, but
    // defense-in-depth costs nothing.
    let mut quoted_hashes = String::new();
    for h in hashes {
        if !h.chars().all(|c| c.is_ascii_hexdigit()) || h.len() != 64 {
            bail!("internal: probe_cache received non-sha256 hash {h:?}");
        }
        quoted_hashes.push(' ');
        quoted_hashes.push_str(h);
    }
    let script = format!(
        r#"set -eu
mkdir -p /tmp/rsansible-cache
chmod 0700 /tmp/rsansible-cache
for h in{quoted_hashes}; do
  if [ -f "/tmp/rsansible-cache/$h" ] && [ -x "/tmp/rsansible-cache/$h" ]; then
    echo "$h"
  fi
done
"#
    );
    let dest = format!("{}@{}", dial.user, dial.host);
    let quoted = shlex::try_quote(&script)
        .context("shell-quoting probe script (internal: should never fail)")?;
    let remote_cmd = format!("bash -c {quoted}");
    let output = tokio::process::Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-p")
        .arg(dial.port.to_string())
        .arg(&dest)
        .arg(&remote_cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .await
        .context("spawning ssh probe")?;
    if !output.status.success() {
        bail!(
            "cache-probe ssh failed: {} (see forwarder stderr above)",
            output.status,
        );
    }
    let hits: std::collections::BTreeSet<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(hits)
}

/// Push `bytes` to `/tmp/rsansible-cache/<hash>` on the forwarder via
/// a dedicated SSH session.
///
/// Atomic-write discipline: bytes stream into a sibling temp file
/// (`<hash>.tmp.<rand>`), then `mv` renames it onto the final path.
/// Two concurrent runs pushing the same hash both win — last writer
/// wins the rename, but since the content is byte-identical (same
/// hash), the file ends up correct either way.
///
/// `chmod 0700` ensures the file is executable + owner-only, so a
/// subsequent `exec` from a bash script picks it up cleanly.
pub async fn push_binary_to_cache(
    dial: &ForwarderDial,
    bytes: &[u8],
    hash: &str,
) -> Result<()> {
    let rand_suffix: u64 = rand::random();
    let tmp_name = format!("{hash}.tmp.{rand_suffix:016x}");
    // `cat > <tmp>` is the universal "stream stdin to a file"
    // primitive — no `dd`, no `head -c`. mv is atomic on the same fs
    // (and /tmp is always a single fs on the systems we care about).
    let script = format!(
        r#"set -eu
mkdir -p /tmp/rsansible-cache
chmod 0700 /tmp/rsansible-cache
cat > "/tmp/rsansible-cache/{tmp_name}"
chmod 0700 "/tmp/rsansible-cache/{tmp_name}"
mv "/tmp/rsansible-cache/{tmp_name}" "/tmp/rsansible-cache/{hash}"
"#
    );
    let dest = format!("{}@{}", dial.user, dial.host);
    let quoted = shlex::try_quote(&script)
        .context("shell-quoting push script (internal: should never fail)")?;
    let remote_cmd = format!("bash -c {quoted}");
    let mut child = tokio::process::Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-p")
        .arg(dial.port.to_string())
        .arg(&dest)
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawning ssh push")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("ssh push child has no stdin"))?;
    stdin
        .write_all(bytes)
        .await
        .context("streaming binary bytes to ssh push stdin")?;
    stdin.shutdown().await.context("closing ssh push stdin")?;
    drop(stdin);
    let status = child.wait().await.context("waiting on ssh push child")?;
    if !status.success() {
        bail!("ssh push failed: {status} (see forwarder stderr above)");
    }
    Ok(())
}

/// Tag identifying which binary a push is for. Only used for
/// log-message clarity ("ctl push 4.2s, agent push 3.9s").
#[derive(Debug, Clone, Copy)]
pub enum BinaryKind {
    Ctl,
    Agent,
}

impl BinaryKind {
    pub fn name(self) -> &'static str {
        match self {
            BinaryKind::Ctl => "ctl",
            BinaryKind::Agent => "agent",
        }
    }
}

/// Per-binary metadata for the caching push pipeline.
///
/// `bytes` is owned because [`push_all`] consumes it (no Cow needed —
/// the laptop already loaded the file fully and the orchestrator owns
/// the buffer until the run completes).
#[derive(Debug, Clone)]
pub struct BinaryToStage {
    pub kind: BinaryKind,
    pub local_path: PathBuf,
    pub bytes: Vec<u8>,
}

/// End-to-end: hash, probe, push misses in parallel. Returns the
/// remote path per binary so the main ssh's bash script can `exec`
/// directly from the cache.
///
/// This is the cached path. The non-caching path (with `--no-cache`)
/// stays in `forward.rs` because it interacts with the main SSH
/// session's stdin streaming.
pub async fn stage_binaries(
    dial: &ForwarderDial,
    binaries: Vec<BinaryToStage>,
) -> Result<Vec<StagedBinary>> {
    let hashes: Vec<String> = binaries.iter().map(|b| hash_binary(&b.bytes)).collect();
    let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
    let t_probe = std::time::Instant::now();
    let hits = probe_cache(dial, &hash_refs).await?;
    tracing::info!(
        elapsed_ms = t_probe.elapsed().as_millis() as u64,
        binaries = binaries.len(),
        cache_hits = hits.len(),
        "forward-mode phase: cache probe complete",
    );

    // Push misses concurrently. We collect futures into a Vec and
    // join_all rather than try_join! because the binary count is
    // dynamic (today 2, could be 3+ if we add a sidecar) — join_all
    // generalizes; try_join! doesn't.
    let mut push_futures = Vec::new();
    for (binary, hash) in binaries.iter().zip(hashes.iter()) {
        if hits.contains(hash) {
            continue;
        }
        let dial = dial.clone();
        let bytes = binary.bytes.clone();
        let hash = hash.clone();
        let kind = binary.kind;
        let path = binary.local_path.clone();
        push_futures.push(tokio::spawn(async move {
            let t = std::time::Instant::now();
            let n = bytes.len();
            push_binary_to_cache(&dial, &bytes, &hash).await.with_context(|| {
                format!(
                    "pushing {} binary {} to forwarder cache as {}",
                    kind.name(),
                    path.display(),
                    hash,
                )
            })?;
            tracing::info!(
                kind = kind.name(),
                bytes = n,
                elapsed_ms = t.elapsed().as_millis() as u64,
                mb_per_s = (n as f64 / 1_048_576.0) / t.elapsed().as_secs_f64().max(0.001),
                hash = %hash,
                "forward-mode phase: binary pushed to cache",
            );
            Ok::<(), anyhow::Error>(())
        }));
    }
    for fut in push_futures {
        fut.await
            .context("join push task")?
            .context("push task failed")?;
    }

    let staged = binaries
        .iter()
        .zip(hashes.iter())
        .map(|(_, hash)| StagedBinary {
            remote_path: format!("/tmp/rsansible-cache/{hash}"),
            cache_hit: hits.contains(hash),
        })
        .collect();
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_binary_is_stable_lowercase_hex_sha256() {
        let bytes = b"hello, rsansible";
        let h = hash_binary(bytes);
        // Length: SHA-256 = 32 bytes = 64 hex chars.
        assert_eq!(h.len(), 64);
        // All lowercase hex.
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Stable across calls.
        assert_eq!(h, hash_binary(bytes));
        // Different input → different hash.
        assert_ne!(h, hash_binary(b"hello, rsansible!"));
    }
}

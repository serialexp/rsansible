//! Per-host wire-cost model: how expensive is a round trip vs. shipping
//! bytes, on this particular SSH transport?
//!
//! Used to choose between two idempotency strategies for module-generated
//! file content (currently: `openssl_privatekey` PEM bodies):
//!
//! - **Ship-blind**: send `OpWriteFile { only_if_missing: 1, content }`
//!   directly. One round trip total; wastes `content.len()` bytes on the
//!   wire when the file already exists.
//! - **Probe-first**: send `OpStat { path }`, await response, conditionally
//!   send `OpWriteFile` only if the file is absent. Two round trips when
//!   the file is absent; one round trip and zero bytes shipped when it's
//!   present.
//!
//! On a low-latency LAN with small payloads (a 3 KB privkey, 5 ms RTT)
//! ship-blind is cheaper. On a long-haul link (~300 ms RTT) where the
//! probe round trip itself takes ~30 KB worth of bandwidth-time, shipping
//! 3 KB blind is far cheaper. The crossover scales with the
//! bandwidth-delay product (RTT × bandwidth, in bytes).

/// Per-host wire-cost estimate. Currently populated at SSH connection
/// time (`rtt_ms` from the `Hello`/`Ping`/`Pong` exchange) and from
/// inventory vars (`bw_bytes_per_s` via `wire_bandwidth_bytes_per_s`,
/// optional, defaults to a conservative 100 KB/s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireCost {
    /// Measured round-trip time on the SSH channel, in milliseconds.
    pub rtt_ms: u32,
    /// Estimated steady-state throughput on the SSH channel, in bytes
    /// per second. Conservative default — small enough that even a
    /// modest LAN beats it, large enough that we don't push everything
    /// to the probe path on a slow but reliable link.
    pub bw_bytes_per_s: u32,
}

impl Default for WireCost {
    fn default() -> Self {
        Self {
            // 50 ms is a reasonable WAN guess until the Ping/Pong probe
            // overwrites it with a real measurement.
            rtt_ms: 50,
            // 100 KB/s. Tune up via inventory if you know your links
            // are faster (especially relevant for big templates/copies).
            bw_bytes_per_s: 100_000,
        }
    }
}

/// Returns true iff probing first (stat → maybe-write) is cheaper in
/// expectation than shipping the bytes blind.
///
/// Model: ship-blind costs `size / bw` seconds of wire time. Probe
/// costs roughly one RTT (the stat). We approximate the "differ"
/// probability as zero — for the privkey case the file either exists
/// (and we never overwrite) or it doesn't (and we ship anyway), so the
/// expected probe cost is just the RTT. Probe wins iff:
///
/// ```text
/// rtt_ms < (size_bytes * 1000) / bw_bytes_per_s
/// ```
///
/// i.e. iff the payload would have taken longer than one RTT to ship.
/// Equivalently: probe iff `size > rtt × bw`, the bandwidth-delay
/// product. Below that threshold, the wire-time of the bytes is less
/// than a round trip, so just ship them.
///
/// Examples (sanity-check the calling convention):
///
/// - 300 ms RTT, 100 KB/s, 3 KB key → threshold = 30 KB → false (ship blind).
/// - 5 ms RTT, 1 MB/s, 3 KB key → threshold = 5 KB → false (ship blind).
/// - 5 ms RTT, 1 MB/s, 50 KB template → threshold = 5 KB → true (probe).
/// - 300 ms RTT, 100 KB/s, 1 MB file → threshold = 30 KB → true (probe).
pub fn should_probe_first(cost: &WireCost, size_bytes: usize) -> bool {
    let threshold_bytes =
        (cost.rtt_ms as u64).saturating_mul(cost.bw_bytes_per_s as u64) / 1000;
    (size_bytes as u64) > threshold_bytes
}

/// Hard override of the heuristic, plumbed in from the `--wire-strategy`
/// CLI flag. `Auto` defers to `should_probe_first`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireStrategy {
    #[default]
    Auto,
    /// Always ship blind. Useful when you know every host is far away
    /// and dominated by RTT.
    Blind,
    /// Always probe first. Useful when you know payloads are large and
    /// the link is fast, or for debugging idempotency.
    Probe,
}

impl WireStrategy {
    pub fn decide(&self, cost: &WireCost, size_bytes: usize) -> bool {
        match self {
            WireStrategy::Auto => should_probe_first(cost, size_bytes),
            WireStrategy::Blind => false,
            WireStrategy::Probe => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ship_blind_transcontinental_small_file() {
        // 300 ms RTT, 100 KB/s, 3 KB privkey: threshold = 30 KB. Ship.
        let cost = WireCost { rtt_ms: 300, bw_bytes_per_s: 100_000 };
        assert!(!should_probe_first(&cost, 3_000));
    }

    #[test]
    fn ship_blind_lan_small_file() {
        // 5 ms RTT, 1 MB/s, 3 KB privkey: threshold = 5 KB. Ship.
        let cost = WireCost { rtt_ms: 5, bw_bytes_per_s: 1_000_000 };
        assert!(!should_probe_first(&cost, 3_000));
    }

    #[test]
    fn probe_lan_medium_file() {
        // 5 ms RTT, 1 MB/s, 50 KB template: threshold = 5 KB. Probe.
        let cost = WireCost { rtt_ms: 5, bw_bytes_per_s: 1_000_000 };
        assert!(should_probe_first(&cost, 50_000));
    }

    #[test]
    fn probe_transcontinental_big_file() {
        // 300 ms RTT, 100 KB/s, 1 MB blob: threshold = 30 KB. Probe.
        let cost = WireCost { rtt_ms: 300, bw_bytes_per_s: 100_000 };
        assert!(should_probe_first(&cost, 1_000_000));
    }

    #[test]
    fn strategy_overrides_heuristic() {
        let cost = WireCost { rtt_ms: 5, bw_bytes_per_s: 1_000_000 };
        // Auto path matches should_probe_first.
        assert_eq!(WireStrategy::Auto.decide(&cost, 50_000), true);
        assert_eq!(WireStrategy::Auto.decide(&cost, 3_000), false);
        // Blind / Probe ignore the heuristic.
        assert_eq!(WireStrategy::Blind.decide(&cost, 50_000), false);
        assert_eq!(WireStrategy::Probe.decide(&cost, 3_000), true);
    }

    #[test]
    fn zero_bandwidth_does_not_panic() {
        // Degenerate input shouldn't divide-by-zero; saturating_mul +
        // unsigned division makes threshold = 0 → everything probes.
        let cost = WireCost { rtt_ms: 50, bw_bytes_per_s: 0 };
        assert!(should_probe_first(&cost, 1));
    }
}

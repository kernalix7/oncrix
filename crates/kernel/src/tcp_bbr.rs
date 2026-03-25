// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BBR (Bottleneck Bandwidth and Round-trip propagation time) TCP congestion
//! control algorithm.
//!
//! BBR is a model-based congestion control algorithm developed at Google that
//! aims to operate at the optimal point between bandwidth utilization and
//! queuing delay. Unlike loss-based algorithms (Reno, CUBIC), BBR estimates
//! the bottleneck bandwidth and minimum RTT to derive the sending rate directly.
//!
//! # Algorithm Phases
//!
//! | Phase        | Description                                             |
//! |-------------|----------------------------------------------------------|
//! | STARTUP      | Exponential bandwidth probing (like slow start)          |
//! | DRAIN        | Drains the queue built during STARTUP                    |
//! | PROBE_BW     | Steady state: cycles through pacing gain to probe BW    |
//! | PROBE_RTT    | Periodically reduce cwnd to measure min RTT              |
//!
//! # Key Mechanisms
//!
//! - **Bandwidth estimation**: windowed max filter over recent delivery rate
//!   samples (8-round window per PROBE_BW cycle).
//! - **RTT estimation**: windowed minimum filter to track propagation delay.
//! - **Pacing rate**: `bw * pacing_gain` — limits the send rate.
//! - **cwnd**: `BDP * cwnd_gain + 3 * MSS` — bounds inflight data.
//!
//! # Reference
//!
//! Cardwell et al., "BBR: Congestion-Based Congestion Control", ACM Queue 2016.
//! Linux kernel `net/ipv4/tcp_bbr.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of rounds per PROBE_BW cycle (8 rounds per cycle in BBR).
const BBR_BW_RTTS: u32 = 8;

/// Minimum RTT probe interval in milliseconds (10 seconds).
const BBR_PROBE_RTT_INTERVAL_MS: u64 = 10_000;

/// Duration spent in PROBE_RTT phase in milliseconds (200 ms).
const BBR_PROBE_RTT_DURATION_MS: u64 = 200;

/// Minimum cwnd during PROBE_RTT (4 packets).
const BBR_MIN_CWND_PROBE_RTT: u32 = 4;

/// Initial minimum cwnd (4 packets).
const BBR_MIN_CWND: u32 = 4;

/// High-gain multiplier numerator (2.885 ≈ ln2 growth per RTT in STARTUP).
/// Represented as fixed-point with [`GAIN_DENOM`] denominator.
const STARTUP_GAIN_NUM: u32 = 2885;

/// Fixed-point denominator for all pacing/cwnd gain values.
const GAIN_DENOM: u32 = 1000;

/// DRAIN gain (reciprocal of STARTUP_GAIN to drain the startup queue).
const DRAIN_GAIN_NUM: u32 = 347; // 1/2.885 ≈ 0.347

/// PROBE_RTT cwnd gain (1.0).
const PROBE_RTT_CWND_GAIN_NUM: u32 = GAIN_DENOM;

/// Steady-state pacing gain for PROBE_BW cycles (index into [`PROBE_BW_GAINS`]).
const PROBE_BW_GAIN_CYCLE_LEN: usize = 8;

/// Pacing gain values for the PROBE_BW cycle (fixed-point, denominator = 1000).
/// One slot per cycle round. The sequence probes up, then cruises level.
const PROBE_BW_GAINS: [u32; PROBE_BW_GAIN_CYCLE_LEN] =
    [1250, 750, 1000, 1000, 1000, 1000, 1000, 1000];

/// Cwnd gain during PROBE_BW (2.0 × BDP).
const PROBE_BW_CWND_GAIN_NUM: u32 = 2000;

/// Startup cwnd gain (2.0).
const STARTUP_CWND_GAIN_NUM: u32 = 2000;

/// Number of rounds without bandwidth increase before leaving STARTUP.
const FULL_BW_THRESH_ROUNDS: u32 = 3;

/// Bandwidth increase ratio threshold for leaving STARTUP (1.25 = 25% growth).
const FULL_BW_THRESH_NUM: u32 = 1250;

/// Maximum bandwidth history window (rounds, for the windowed max filter).
const BW_WINDOW_ROUNDS: usize = BBR_BW_RTTS as usize;

/// RTT history window (number of samples for windowed min filter).
const RTT_WINDOW_SAMPLES: usize = 16;

/// Upper bound on cwnd (64 KiB / MSS as a packet count, conservative ceiling).
const MAX_CWND: u32 = 65535;

/// Default MSS in bytes.
const DEFAULT_MSS: u32 = 1460;

/// Initial bandwidth estimate (1 Mbps in bytes/ms = 125 bytes/ms).
const INITIAL_BW_BYTES_PER_MS: u64 = 125;

// ── BbrPhase ──────────────────────────────────────────────────────────────────

/// BBR algorithm phase (state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BbrPhase {
    /// Exponential startup — probe for full bandwidth.
    #[default]
    Startup,
    /// Drain the excess queue built during STARTUP.
    Drain,
    /// Steady-state operation with periodic bandwidth probing.
    ProbeBw,
    /// Periodically reduce cwnd to re-measure min RTT.
    ProbeRtt,
}

// ── BwSample ──────────────────────────────────────────────────────────────────

/// A single bandwidth delivery-rate sample.
#[derive(Debug, Clone, Copy, Default)]
struct BwSample {
    /// Delivered bytes per millisecond.
    bw_bytes_per_ms: u64,
    /// Round number this sample was taken.
    round: u64,
}

// ── RttSample ─────────────────────────────────────────────────────────────────

/// A single RTT measurement.
#[derive(Debug, Clone, Copy, Default)]
struct RttSample {
    /// RTT measurement in microseconds.
    rtt_us: u64,
}

// ── BbrStats ──────────────────────────────────────────────────────────────────

/// Operational statistics for a BBR connection.
#[derive(Debug, Clone, Copy, Default)]
pub struct BbrStats {
    /// Total ACKed bytes.
    pub bytes_acked: u64,
    /// Total retransmitted bytes.
    pub bytes_retransmitted: u64,
    /// Number of bandwidth probes completed.
    pub bw_probes: u64,
    /// Number of RTT probes completed.
    pub rtt_probes: u64,
    /// Number of phase transitions.
    pub phase_transitions: u64,
}

// ── BbrState ──────────────────────────────────────────────────────────────────

/// Per-connection BBR congestion control state.
///
/// Holds all BBR-specific fields plus the derived cwnd and pacing rate that
/// are fed back to the TCP stack.
pub struct BbrState {
    // ── Phase & timing ─────────────────────────────────────────
    /// Current algorithm phase.
    pub phase: BbrPhase,
    /// Current BBR round number (incremented each RTT).
    round: u64,
    /// Round number at which the current phase started.
    phase_start_round: u64,
    /// Timestamp (ms) when the current phase started.
    phase_start_ms: u64,
    /// Timestamp (ms) of the last min-RTT probe.
    last_rtt_probe_ms: u64,
    /// Whether we are inside a PROBE_RTT window.
    in_probe_rtt: bool,
    /// Round at which PROBE_RTT started.
    probe_rtt_start_round: u64,
    /// Current PROBE_BW gain cycle index.
    cycle_idx: usize,

    // ── Bandwidth estimation ────────────────────────────────────
    /// Windowed max bandwidth samples (BW_WINDOW_ROUNDS rounds).
    bw_samples: [BwSample; BW_WINDOW_ROUNDS],
    /// Number of valid bandwidth samples.
    bw_sample_count: usize,
    /// Estimated bottleneck bandwidth (bytes/ms).
    bw: u64,
    /// Bandwidth at last STARTUP check (for full-pipe detection).
    full_bw: u64,
    /// Rounds without significant BW increase.
    full_bw_rounds: u32,

    // ── RTT estimation ──────────────────────────────────────────
    /// Windowed minimum RTT samples (microseconds).
    rtt_samples: [RttSample; RTT_WINDOW_SAMPLES],
    /// Number of valid RTT samples.
    rtt_sample_count: usize,
    /// Minimum RTT observed (propagation delay estimate, microseconds).
    min_rtt_us: u64,

    // ── TCP-facing outputs ──────────────────────────────────────
    /// Congestion window in packets (MSS units).
    pub cwnd: u32,
    /// Pacing rate in bytes per millisecond.
    pub pacing_rate: u64,
    /// Maximum segment size in bytes.
    pub mss: u32,

    // ── Statistics ──────────────────────────────────────────────
    /// Operational statistics.
    pub stats: BbrStats,
}

impl BbrState {
    /// Create a new BBR state for a connection with the given `mss`.
    pub fn new(mss: u32) -> Self {
        let mss = if mss == 0 { DEFAULT_MSS } else { mss };
        Self {
            phase: BbrPhase::Startup,
            round: 0,
            phase_start_round: 0,
            phase_start_ms: 0,
            last_rtt_probe_ms: 0,
            in_probe_rtt: false,
            probe_rtt_start_round: 0,
            cycle_idx: 0,
            bw_samples: [BwSample::default(); BW_WINDOW_ROUNDS],
            bw_sample_count: 0,
            bw: INITIAL_BW_BYTES_PER_MS,
            full_bw: 0,
            full_bw_rounds: 0,
            rtt_samples: [RttSample::default(); RTT_WINDOW_SAMPLES],
            rtt_sample_count: 0,
            min_rtt_us: u64::MAX,
            cwnd: BBR_MIN_CWND,
            pacing_rate: INITIAL_BW_BYTES_PER_MS,
            mss,
            stats: BbrStats::default(),
        }
    }

    // ── Bandwidth tracking ────────────────────────────────────────────────────

    /// Record a new bandwidth sample and update the windowed maximum.
    ///
    /// `delivered_bytes` — bytes delivered since the last sample.
    /// `elapsed_ms` — elapsed time in milliseconds since the last sample.
    fn record_bw_sample(&mut self, delivered_bytes: u64, elapsed_ms: u64) {
        if elapsed_ms == 0 {
            return;
        }
        let sample_bw = delivered_bytes / elapsed_ms.max(1);
        let slot = (self.round as usize) % BW_WINDOW_ROUNDS;
        self.bw_samples[slot] = BwSample {
            bw_bytes_per_ms: sample_bw,
            round: self.round,
        };
        if self.bw_sample_count < BW_WINDOW_ROUNDS {
            self.bw_sample_count += 1;
        }
        // Windowed maximum.
        let mut max_bw = 0u64;
        for s in &self.bw_samples[..self.bw_sample_count] {
            if s.bw_bytes_per_ms > max_bw {
                max_bw = s.bw_bytes_per_ms;
            }
        }
        if max_bw > 0 {
            self.bw = max_bw;
        }
    }

    // ── RTT tracking ──────────────────────────────────────────────────────────

    /// Record a new RTT sample and update the windowed minimum.
    ///
    /// `rtt_us` — measured RTT in microseconds.
    fn record_rtt_sample(&mut self, rtt_us: u64) {
        if rtt_us == 0 {
            return;
        }
        let slot = (self.rtt_sample_count) % RTT_WINDOW_SAMPLES;
        self.rtt_samples[slot] = RttSample { rtt_us };
        if self.rtt_sample_count < RTT_WINDOW_SAMPLES {
            self.rtt_sample_count += 1;
        }
        // Windowed minimum.
        let mut min_rtt = u64::MAX;
        for s in &self.rtt_samples[..self.rtt_sample_count] {
            if s.rtt_us < min_rtt {
                min_rtt = s.rtt_us;
            }
        }
        if min_rtt < u64::MAX {
            self.min_rtt_us = min_rtt;
        }
    }

    // ── Bandwidth-delay product ───────────────────────────────────────────────

    /// Compute the bandwidth-delay product (BDP) in bytes.
    ///
    /// BDP = bottleneck_bandwidth × min_RTT.
    fn bdp_bytes(&self) -> u64 {
        if self.min_rtt_us == u64::MAX || self.min_rtt_us == 0 {
            // No RTT yet — return minimal initial estimate.
            return (self.bw * 10) as u64; // 10 ms assumed
        }
        // bw is bytes/ms; min_rtt_us is µs → convert to ms.
        let min_rtt_ms = (self.min_rtt_us + 999) / 1000;
        self.bw * min_rtt_ms
    }

    // ── cwnd computation ──────────────────────────────────────────────────────

    /// Compute the target cwnd (in packets) for the current state.
    fn target_cwnd(&self, cwnd_gain_num: u32) -> u32 {
        let bdp_bytes = self.bdp_bytes();
        // cwnd_packets = ceil(BDP * gain / MSS) + BBR_MIN_CWND
        let bdp_gain = bdp_bytes.saturating_mul(cwnd_gain_num as u64) / GAIN_DENOM as u64;
        let bdp_pkts = ((bdp_gain + self.mss as u64 - 1) / self.mss as u64) as u32;
        bdp_pkts.saturating_add(BBR_MIN_CWND).min(MAX_CWND)
    }

    // ── Pacing rate computation ────────────────────────────────────────────────

    /// Compute the pacing rate (bytes/ms) for the given gain.
    fn target_pacing_rate(&self, pacing_gain_num: u32) -> u64 {
        self.bw.saturating_mul(pacing_gain_num as u64) / GAIN_DENOM as u64
    }

    // ── Phase transitions ─────────────────────────────────────────────────────

    /// Enter DRAIN phase.
    fn enter_drain(&mut self) {
        self.phase = BbrPhase::Drain;
        self.phase_start_round = self.round;
        self.stats.phase_transitions += 1;
    }

    /// Enter PROBE_BW phase.
    fn enter_probe_bw(&mut self, now_ms: u64) {
        self.phase = BbrPhase::ProbeBw;
        self.phase_start_round = self.round;
        self.phase_start_ms = now_ms;
        self.cycle_idx = 0;
        self.stats.bw_probes += 1;
        self.stats.phase_transitions += 1;
    }

    /// Enter PROBE_RTT phase.
    fn enter_probe_rtt(&mut self, now_ms: u64) {
        self.phase = BbrPhase::ProbeRtt;
        self.in_probe_rtt = true;
        self.probe_rtt_start_round = self.round;
        self.last_rtt_probe_ms = now_ms;
        self.stats.rtt_probes += 1;
        self.stats.phase_transitions += 1;
    }

    // ── Full-pipe detection ───────────────────────────────────────────────────

    /// Return `true` if BBR has detected the pipe is full (BW has plateaued).
    fn is_full_pipe(&mut self) -> bool {
        // Check if bandwidth has grown by at least 25% since the last check.
        let threshold = self.full_bw.saturating_mul(FULL_BW_THRESH_NUM as u64) / GAIN_DENOM as u64;
        if self.bw >= threshold {
            // Still growing — reset counter and update baseline.
            self.full_bw = self.bw;
            self.full_bw_rounds = 0;
            return false;
        }
        self.full_bw_rounds += 1;
        self.full_bw_rounds >= FULL_BW_THRESH_ROUNDS
    }

    // ── Main update entry point ───────────────────────────────────────────────

    /// Process an ACK event and update BBR state.
    ///
    /// This is the primary per-ACK callback from the TCP stack.
    ///
    /// # Parameters
    ///
    /// - `ack`: ACK event details.
    /// - `now_ms`: current wall-clock time in milliseconds.
    pub fn on_ack(&mut self, ack: &AckEvent, now_ms: u64) {
        self.round += 1;
        self.stats.bytes_acked += ack.delivered_bytes;

        // Update estimators.
        self.record_bw_sample(ack.delivered_bytes, ack.elapsed_ms);
        if ack.rtt_us > 0 {
            self.record_rtt_sample(ack.rtt_us);
        }

        // Run the BBR state machine.
        match self.phase {
            BbrPhase::Startup => self.on_ack_startup(now_ms),
            BbrPhase::Drain => self.on_ack_drain(),
            BbrPhase::ProbeBw => self.on_ack_probe_bw(now_ms),
            BbrPhase::ProbeRtt => self.on_ack_probe_rtt(now_ms),
        }

        // Check if it's time for a PROBE_RTT regardless of current phase.
        if self.phase != BbrPhase::ProbeRtt {
            let elapsed_since_probe = now_ms.saturating_sub(self.last_rtt_probe_ms);
            if elapsed_since_probe >= BBR_PROBE_RTT_INTERVAL_MS {
                self.enter_probe_rtt(now_ms);
            }
        }
    }

    fn on_ack_startup(&mut self, now_ms: u64) {
        let pacing_gain = STARTUP_GAIN_NUM;
        let cwnd_gain = STARTUP_CWND_GAIN_NUM;
        self.pacing_rate = self.target_pacing_rate(pacing_gain);
        self.cwnd = self.target_cwnd(cwnd_gain).max(BBR_MIN_CWND);

        if self.full_bw == 0 {
            self.full_bw = self.bw;
        }

        if self.is_full_pipe() {
            self.enter_drain();
        }
        let _ = now_ms;
    }

    fn on_ack_drain(&mut self) {
        self.pacing_rate = self.target_pacing_rate(DRAIN_GAIN_NUM);
        self.cwnd = self.target_cwnd(PROBE_BW_CWND_GAIN_NUM).max(BBR_MIN_CWND);

        // Leave DRAIN when inflight ≤ BDP (approximated: cwnd from gain ≤ BDP).
        let bdp_pkts = ((self.bdp_bytes() + self.mss as u64 - 1) / self.mss as u64) as u32;
        if self.cwnd <= bdp_pkts.max(BBR_MIN_CWND) {
            self.enter_probe_bw(0);
        }
    }

    fn on_ack_probe_bw(&mut self, now_ms: u64) {
        // Advance gain cycle every `BBR_BW_RTTS` rounds.
        let rounds_in_phase = self.round.saturating_sub(self.phase_start_round);
        if rounds_in_phase > 0 && rounds_in_phase % BBR_BW_RTTS as u64 == 0 {
            self.cycle_idx = (self.cycle_idx + 1) % PROBE_BW_GAIN_CYCLE_LEN;
        }

        let pacing_gain = PROBE_BW_GAINS[self.cycle_idx];
        self.pacing_rate = self.target_pacing_rate(pacing_gain);
        self.cwnd = self.target_cwnd(PROBE_BW_CWND_GAIN_NUM).max(BBR_MIN_CWND);
        let _ = now_ms;
    }

    fn on_ack_probe_rtt(&mut self, now_ms: u64) {
        // During PROBE_RTT, reduce cwnd to 4 packets to flush the queue.
        self.cwnd = BBR_MIN_CWND_PROBE_RTT;
        self.pacing_rate = self.target_pacing_rate(GAIN_DENOM); // 1.0× gain

        // Exit PROBE_RTT after the probe duration has elapsed.
        let elapsed = now_ms.saturating_sub(self.last_rtt_probe_ms);
        if elapsed >= BBR_PROBE_RTT_DURATION_MS {
            self.in_probe_rtt = false;
            self.enter_probe_bw(now_ms);
        }
    }

    /// Process a packet loss event.
    ///
    /// BBR does NOT reduce cwnd on loss (unlike Reno/CUBIC); loss is treated
    /// as a congestion signal only in edge cases. We record retransmission
    /// statistics only.
    pub fn on_loss(&mut self, lost_bytes: u64) {
        self.stats.bytes_retransmitted += lost_bytes;
        // BBR does not halve cwnd on loss; pacing rate governs the sending rate.
    }

    /// Process an RTO (retransmission timeout) event.
    ///
    /// On RTO, restart from STARTUP to re-probe bandwidth.
    pub fn on_rto(&mut self) {
        self.phase = BbrPhase::Startup;
        self.phase_start_round = self.round;
        self.full_bw = 0;
        self.full_bw_rounds = 0;
        self.bw_sample_count = 0;
        self.cwnd = BBR_MIN_CWND;
        self.stats.phase_transitions += 1;
    }

    /// Return `true` if the connection is in steady-state PROBE_BW.
    pub fn is_steady_state(&self) -> bool {
        self.phase == BbrPhase::ProbeBw
    }

    /// Return the current estimated bottleneck bandwidth (bytes/ms).
    pub fn bottleneck_bandwidth(&self) -> u64 {
        self.bw
    }

    /// Return the current minimum RTT estimate (microseconds).
    ///
    /// Returns `None` if no RTT has been measured yet.
    pub fn min_rtt_us(&self) -> Option<u64> {
        if self.min_rtt_us == u64::MAX {
            None
        } else {
            Some(self.min_rtt_us)
        }
    }

    /// Return the bandwidth-delay product in bytes.
    pub fn bdp(&self) -> u64 {
        self.bdp_bytes()
    }
}

// ── AckEvent ──────────────────────────────────────────────────────────────────

/// ACK event passed to [`BbrState::on_ack`].
///
/// The TCP stack fills in this structure on each ACK before calling into BBR.
#[derive(Debug, Clone, Copy)]
pub struct AckEvent {
    /// Bytes delivered since the previous ACK (from TCP's delivery accounting).
    pub delivered_bytes: u64,
    /// Elapsed milliseconds since the previous ACK.
    pub elapsed_ms: u64,
    /// Round-trip time for the ACKed segment, in microseconds.
    /// Zero if unavailable.
    pub rtt_us: u64,
    /// Number of packets acknowledged in this ACK (may be > 1 for cumulative ACK).
    pub packets_acked: u32,
}

impl AckEvent {
    /// Create a minimal ACK event with only the required fields.
    pub fn new(delivered_bytes: u64, elapsed_ms: u64, rtt_us: u64) -> Self {
        Self {
            delivered_bytes,
            elapsed_ms,
            rtt_us,
            packets_acked: 1,
        }
    }
}

// ── BbrRegistry ───────────────────────────────────────────────────────────────

/// Maximum number of concurrent BBR connections tracked.
const MAX_BBR_CONNECTIONS: usize = 128;

/// Identifier type for BBR connections.
pub type ConnectionId = u64;

/// Entry in the BBR connection registry.
struct BbrEntry {
    /// Connection identifier (matches the TCP connection's ID).
    id: ConnectionId,
    /// BBR state for this connection.
    state: BbrState,
    /// Whether this slot is occupied.
    active: bool,
}

impl BbrEntry {
    fn new(id: ConnectionId, mss: u32) -> Self {
        Self {
            id,
            state: BbrState::new(mss),
            active: true,
        }
    }
}

/// System-wide registry of BBR congestion control instances.
///
/// Allows the TCP stack to create, look up, and destroy per-connection BBR
/// state without heap allocation.
pub struct BbrRegistry {
    /// Connection entries.
    entries: [Option<BbrEntry>; MAX_BBR_CONNECTIONS],
    /// Number of active connections.
    count: usize,
}

impl BbrRegistry {
    /// Create an empty BBR registry.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Register a new BBR connection.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the registry is full or
    /// `Err(Error::AlreadyExists)` if `id` is already registered.
    pub fn create(&mut self, id: ConnectionId, mss: u32) -> Result<()> {
        if self.count >= MAX_BBR_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for entry in self.entries.iter().flatten() {
            if entry.id == id && entry.active {
                return Err(Error::AlreadyExists);
            }
        }
        // Find a free slot.
        let pos = self.entries.iter().position(|e| e.is_none());
        match pos {
            Some(idx) => {
                self.entries[idx] = Some(BbrEntry::new(id, mss));
                self.count += 1;
                Ok(())
            }
            None => Err(Error::OutOfMemory),
        }
    }

    /// Look up the BBR state for connection `id`.
    ///
    /// Returns `Err(Error::NotFound)` if no connection matches.
    pub fn get(&self, id: ConnectionId) -> Result<&BbrState> {
        for entry in self.entries.iter().flatten() {
            if entry.id == id && entry.active {
                return Ok(&entry.state);
            }
        }
        Err(Error::NotFound)
    }

    /// Look up the BBR state mutably for connection `id`.
    ///
    /// Returns `Err(Error::NotFound)` if no connection matches.
    pub fn get_mut(&mut self, id: ConnectionId) -> Result<&mut BbrState> {
        for entry in self.entries.iter_mut().flatten() {
            if entry.id == id && entry.active {
                return Ok(&mut entry.state);
            }
        }
        Err(Error::NotFound)
    }

    /// Remove the BBR state for connection `id`.
    ///
    /// Returns `Err(Error::NotFound)` if no connection matches.
    pub fn destroy(&mut self, id: ConnectionId) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if let Some(e) = entry {
                if e.id == id && e.active {
                    *entry = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active BBR connections.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no BBR connections are tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for BbrRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── BbrConfig ─────────────────────────────────────────────────────────────────

/// Tunable parameters for the BBR algorithm.
///
/// Values represent defaults that may be overridden per connection or
/// system-wide via sysctl.
#[derive(Debug, Clone, Copy)]
pub struct BbrConfig {
    /// PROBE_RTT interval in milliseconds (default: 10 000).
    pub probe_rtt_interval_ms: u64,
    /// PROBE_RTT duration in milliseconds (default: 200).
    pub probe_rtt_duration_ms: u64,
    /// Minimum cwnd in packets (default: 4).
    pub min_cwnd: u32,
    /// PROBE_RTT cwnd in packets (default: 4).
    pub probe_rtt_cwnd: u32,
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            probe_rtt_interval_ms: BBR_PROBE_RTT_INTERVAL_MS,
            probe_rtt_duration_ms: BBR_PROBE_RTT_DURATION_MS,
            min_cwnd: BBR_MIN_CWND,
            probe_rtt_cwnd: BBR_MIN_CWND_PROBE_RTT,
        }
    }
}

/// Validate a [`BbrConfig`] and return `Err(Error::InvalidArgument)` if any
/// field is out of a safe range.
pub fn validate_config(cfg: &BbrConfig) -> Result<()> {
    if cfg.probe_rtt_interval_ms < 1_000 {
        return Err(Error::InvalidArgument);
    }
    if cfg.probe_rtt_duration_ms < 50 {
        return Err(Error::InvalidArgument);
    }
    if cfg.min_cwnd < 2 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ack(bw_bytes: u64, elapsed_ms: u64, rtt_us: u64) -> AckEvent {
        AckEvent::new(bw_bytes, elapsed_ms, rtt_us)
    }

    #[test]
    fn startup_to_drain() {
        let mut bbr = BbrState::new(1460);
        // Simulate enough rounds with plateaued bandwidth to trigger full-pipe.
        bbr.bw = 10_000;
        bbr.full_bw = 10_000;
        bbr.full_bw_rounds = FULL_BW_THRESH_ROUNDS - 1;

        let ack = make_ack(1000, 1, 5_000);
        bbr.on_ack(&ack, 0);
        // After detecting full pipe, should move to Drain.
        assert_eq!(bbr.phase, BbrPhase::Drain);
    }

    #[test]
    fn drain_to_probe_bw() {
        let mut bbr = BbrState::new(1460);
        bbr.phase = BbrPhase::Drain;
        bbr.bw = 100;
        bbr.min_rtt_us = 10_000;

        let ack = make_ack(100, 10, 10_000);
        bbr.on_ack(&ack, 0);
        // After drain, should transition to ProbeBw.
        assert!(
            bbr.phase == BbrPhase::ProbeBw || bbr.phase == BbrPhase::ProbeRtt,
            "phase: {:?}",
            bbr.phase
        );
    }

    #[test]
    fn rto_resets_to_startup() {
        let mut bbr = BbrState::new(1460);
        bbr.phase = BbrPhase::ProbeBw;
        bbr.on_rto();
        assert_eq!(bbr.phase, BbrPhase::Startup);
        assert_eq!(bbr.cwnd, BBR_MIN_CWND);
    }

    #[test]
    fn min_rtt_none_before_sample() {
        let bbr = BbrState::new(1460);
        assert!(bbr.min_rtt_us().is_none());
    }

    #[test]
    fn min_rtt_tracked() {
        let mut bbr = BbrState::new(1460);
        let ack = make_ack(1000, 1, 5_000);
        bbr.on_ack(&ack, 0);
        assert_eq!(bbr.min_rtt_us(), Some(5_000));
    }

    #[test]
    fn registry_create_get_destroy() {
        let mut reg = BbrRegistry::new();
        reg.create(1, 1460).expect("create conn 1");
        assert!(reg.get(1).is_ok());
        reg.destroy(1).expect("destroy conn 1");
        assert!(reg.get(1).is_err());
    }

    #[test]
    fn default_config_is_valid() {
        assert!(validate_config(&BbrConfig::default()).is_ok());
    }

    #[test]
    fn config_invalid_interval() {
        let cfg = BbrConfig {
            probe_rtt_interval_ms: 100,
            ..BbrConfig::default()
        };
        assert!(validate_config(&cfg).is_err());
    }
}

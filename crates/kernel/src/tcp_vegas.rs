// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TCP Vegas congestion control algorithm.
//!
//! Vegas is a delay-based congestion control algorithm that adjusts the
//! congestion window based on the difference between expected and actual
//! throughput. Unlike loss-based algorithms (Reno, CUBIC), Vegas detects
//! congestion *before* packet loss occurs by monitoring RTT increases.
//!
//! # Algorithm Overview
//!
//! Vegas maintains a `base_rtt` — the minimum RTT observed — and uses it
//! to compute expected throughput: `expected = cwnd / base_rtt`. The
//! actual throughput is `actual = cwnd / current_rtt`. The difference
//! `diff = expected - actual` (in units of packets) determines the
//! cwnd adjustment:
//!
//! | Condition          | Action              |
//! |--------------------|---------------------|
//! | `diff < alpha`     | Increase cwnd by 1  |
//! | `diff > beta`      | Decrease cwnd by 1  |
//! | `alpha <= diff <= beta` | No change      |
//!
//! # Slow Start Modification
//!
//! Vegas modifies slow start by monitoring the difference between
//! expected and actual throughput every other RTT. If `diff > gamma`,
//! Vegas exits slow start early and enters linear increase mode.
//!
//! # Reference
//!
//! Brakmo & Peterson, "TCP Vegas: End to End Congestion Avoidance on
//! a Global Internet", IEEE JSAC, 1995.
//! Linux kernel `net/ipv4/tcp_vegas.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default alpha threshold (packets). If diff < alpha, increase cwnd.
const DEFAULT_ALPHA: u32 = 2;

/// Default beta threshold (packets). If diff > beta, decrease cwnd.
const DEFAULT_BETA: u32 = 4;

/// Default gamma threshold for slow-start exit.
const DEFAULT_GAMMA: u32 = 1;

/// Minimum congestion window (MSS units).
const MIN_CWND: u32 = 2;

/// Maximum congestion window (MSS units).
const MAX_CWND: u32 = 65535;

/// Initial congestion window (RFC 6928: 10 MSS).
const INITIAL_CWND: u32 = 10;

/// Initial slow-start threshold.
const INITIAL_SSTHRESH: u32 = 65535;

/// Maximum number of connections tracked by the Vegas manager.
const MAX_CONNECTIONS: usize = 256;

/// RTT value indicating no measurement has been taken yet.
const RTT_UNSET: u64 = u64::MAX;

/// Number of RTT samples to keep for smoothing.
const RTT_HISTORY_LEN: usize = 8;

/// Fixed-point scaling factor for throughput calculations.
const THROUGHPUT_SCALE: u64 = 1_000_000;

// ── VegasPhase ────────────────────────────────────────────────────────────────

/// Current phase of the Vegas congestion control state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VegasPhase {
    /// Modified slow start: exponential growth with early exit.
    #[default]
    SlowStart,
    /// Congestion avoidance: linear adjustment based on RTT diff.
    CongestionAvoidance,
    /// Fast recovery after packet loss detection.
    FastRecovery,
}

// ── VegasParams ───────────────────────────────────────────────────────────────

/// Tunable parameters for the Vegas algorithm.
///
/// These thresholds control how aggressively Vegas responds to
/// detected queuing delay.
#[derive(Debug, Clone, Copy)]
pub struct VegasParams {
    /// Alpha threshold: increase cwnd when diff < alpha.
    pub alpha: u32,
    /// Beta threshold: decrease cwnd when diff > beta.
    pub beta: u32,
    /// Gamma threshold: exit slow start when diff > gamma.
    pub gamma: u32,
}

impl VegasParams {
    /// Create parameters with default values.
    pub const fn new() -> Self {
        Self {
            alpha: DEFAULT_ALPHA,
            beta: DEFAULT_BETA,
            gamma: DEFAULT_GAMMA,
        }
    }

    /// Create parameters with custom thresholds.
    ///
    /// Returns an error if alpha > beta (the thresholds must form
    /// a valid range).
    pub const fn with_thresholds(alpha: u32, beta: u32, gamma: u32) -> Result<Self> {
        if alpha > beta {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { alpha, beta, gamma })
    }

    /// Validate the parameter set.
    pub const fn validate(&self) -> Result<()> {
        if self.alpha > self.beta {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for VegasParams {
    fn default() -> Self {
        Self::new()
    }
}

// ── RttSample ─────────────────────────────────────────────────────────────────

/// A single RTT measurement sample.
#[derive(Debug, Clone, Copy)]
pub struct RttSample {
    /// RTT value in microseconds.
    pub rtt_us: u64,
    /// Timestamp when this sample was taken (microseconds since boot).
    pub timestamp_us: u64,
}

impl RttSample {
    /// Create a new RTT sample.
    pub const fn new(rtt_us: u64, timestamp_us: u64) -> Self {
        Self {
            rtt_us,
            timestamp_us,
        }
    }
}

impl Default for RttSample {
    fn default() -> Self {
        Self {
            rtt_us: RTT_UNSET,
            timestamp_us: 0,
        }
    }
}

// ── RttHistory ────────────────────────────────────────────────────────────────

/// Circular buffer of RTT samples for smoothed RTT estimation.
#[derive(Debug)]
pub struct RttHistory {
    /// Ring buffer of samples.
    samples: [RttSample; RTT_HISTORY_LEN],
    /// Write index (wraps around).
    head: usize,
    /// Number of valid samples.
    count: usize,
}

impl RttHistory {
    /// Create an empty RTT history.
    pub const fn new() -> Self {
        Self {
            samples: [const {
                RttSample {
                    rtt_us: RTT_UNSET,
                    timestamp_us: 0,
                }
            }; RTT_HISTORY_LEN],
            head: 0,
            count: 0,
        }
    }

    /// Record a new RTT sample.
    pub fn push(&mut self, sample: RttSample) {
        self.samples[self.head] = sample;
        self.head = (self.head + 1) % RTT_HISTORY_LEN;
        if self.count < RTT_HISTORY_LEN {
            self.count += 1;
        }
    }

    /// Get the minimum RTT from recent history.
    pub fn min_rtt(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let mut min = u64::MAX;
        for i in 0..self.count {
            let rtt = self.samples[i].rtt_us;
            if rtt < min && rtt != RTT_UNSET {
                min = rtt;
            }
        }
        if min == u64::MAX { None } else { Some(min) }
    }

    /// Get the most recent RTT sample.
    pub fn latest_rtt(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            RTT_HISTORY_LEN - 1
        } else {
            self.head - 1
        };
        let rtt = self.samples[idx].rtt_us;
        if rtt == RTT_UNSET { None } else { Some(rtt) }
    }

    /// Compute smoothed RTT as the average of all valid samples.
    pub fn smoothed_rtt(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let mut sum: u64 = 0;
        let mut valid = 0u64;
        for i in 0..self.count {
            let rtt = self.samples[i].rtt_us;
            if rtt != RTT_UNSET {
                sum = sum.saturating_add(rtt);
                valid += 1;
            }
        }
        if valid == 0 { None } else { Some(sum / valid) }
    }

    /// Reset history.
    pub fn reset(&mut self) {
        self.head = 0;
        self.count = 0;
        for s in &mut self.samples {
            s.rtt_us = RTT_UNSET;
            s.timestamp_us = 0;
        }
    }
}

impl Default for RttHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ── VegasState ────────────────────────────────────────────────────────────────

/// Per-connection Vegas congestion control state.
///
/// Tracks the base RTT, current congestion window, and algorithm phase
/// for a single TCP connection.
#[derive(Debug)]
pub struct VegasState {
    /// Connection identifier.
    conn_id: u64,
    /// Current congestion window (MSS units).
    cwnd: u32,
    /// Slow-start threshold (MSS units).
    ssthresh: u32,
    /// Base RTT — minimum observed RTT (microseconds).
    base_rtt: u64,
    /// Current RTT measurement (microseconds).
    current_rtt: u64,
    /// RTT sample history.
    rtt_history: RttHistory,
    /// Current algorithm phase.
    phase: VegasPhase,
    /// Algorithm parameters.
    params: VegasParams,
    /// Count of ACKs received in current RTT round.
    ack_count: u64,
    /// Bytes acknowledged in current round.
    bytes_acked: u64,
    /// Round-trip counter (incremented each base_rtt interval).
    round_count: u64,
    /// Timestamp of the start of the current RTT round.
    round_start_us: u64,
    /// Whether this is an even-numbered round (for slow-start check).
    even_round: bool,
    /// Previous cwnd at start of slow-start check period.
    slow_start_prev_cwnd: u32,
    /// Number of retransmissions.
    retransmits: u64,
    /// Whether the connection is active.
    active: bool,
}

impl VegasState {
    /// Create a new Vegas state for a connection.
    pub const fn new(conn_id: u64) -> Self {
        Self {
            conn_id,
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            base_rtt: RTT_UNSET,
            current_rtt: RTT_UNSET,
            rtt_history: RttHistory::new(),
            phase: VegasPhase::SlowStart,
            params: VegasParams::new(),
            ack_count: 0,
            bytes_acked: 0,
            round_count: 0,
            round_start_us: 0,
            even_round: false,
            slow_start_prev_cwnd: INITIAL_CWND,
            retransmits: 0,
            active: true,
        }
    }

    /// Create with custom parameters.
    pub const fn with_params(conn_id: u64, params: VegasParams) -> Self {
        Self {
            conn_id,
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            base_rtt: RTT_UNSET,
            current_rtt: RTT_UNSET,
            rtt_history: RttHistory::new(),
            phase: VegasPhase::SlowStart,
            params,
            ack_count: 0,
            bytes_acked: 0,
            round_count: 0,
            round_start_us: 0,
            even_round: false,
            slow_start_prev_cwnd: INITIAL_CWND,
            retransmits: 0,
            active: true,
        }
    }

    /// Get the connection identifier.
    pub const fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// Get the current congestion window.
    pub const fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get the slow-start threshold.
    pub const fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Get the base (minimum) RTT in microseconds.
    pub const fn base_rtt(&self) -> u64 {
        self.base_rtt
    }

    /// Get the current RTT in microseconds.
    pub const fn current_rtt(&self) -> u64 {
        self.current_rtt
    }

    /// Get the current phase.
    pub const fn phase(&self) -> VegasPhase {
        self.phase
    }

    /// Get the retransmission count.
    pub const fn retransmits(&self) -> u64 {
        self.retransmits
    }

    /// Check if the connection is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Process an incoming ACK with the measured RTT.
    ///
    /// This is the main entry point called on each ACK. It updates
    /// the base RTT, records the sample, and runs the Vegas algorithm
    /// to adjust cwnd.
    pub fn on_ack(&mut self, rtt_us: u64, bytes: u32, now_us: u64) {
        if !self.active || rtt_us == 0 {
            return;
        }

        // Update base RTT (minimum ever observed).
        if rtt_us < self.base_rtt {
            self.base_rtt = rtt_us;
        }
        self.current_rtt = rtt_us;

        // Record sample.
        self.rtt_history.push(RttSample::new(rtt_us, now_us));
        self.ack_count += 1;
        self.bytes_acked += bytes as u64;

        // Check if we've completed an RTT round.
        if self.base_rtt != RTT_UNSET && now_us.saturating_sub(self.round_start_us) >= self.base_rtt
        {
            self.complete_round(now_us);
        }
    }

    /// Complete an RTT round and perform the Vegas cwnd adjustment.
    fn complete_round(&mut self, now_us: u64) {
        self.round_count += 1;
        self.round_start_us = now_us;
        self.even_round = !self.even_round;

        match self.phase {
            VegasPhase::SlowStart => self.slow_start_update(),
            VegasPhase::CongestionAvoidance => self.congestion_avoidance_update(),
            VegasPhase::FastRecovery => { /* handled by on_loss/on_recovery */ }
        }
    }

    /// Vegas-modified slow start.
    ///
    /// Every other RTT, compare expected vs actual throughput.
    /// If the difference exceeds gamma, exit slow start.
    fn slow_start_update(&mut self) {
        if self.base_rtt == RTT_UNSET || self.current_rtt == 0 {
            // Not enough data yet — standard exponential increase.
            self.cwnd = (self.cwnd + 1).min(MAX_CWND);
            return;
        }

        if !self.even_round {
            // Odd round: just save cwnd for comparison next round.
            self.slow_start_prev_cwnd = self.cwnd;
            self.cwnd = (self.cwnd + 1).min(MAX_CWND);
            return;
        }

        // Even round: check if we should exit slow start.
        let diff = self.compute_diff();

        if diff > self.params.gamma {
            // Congestion detected — exit slow start.
            self.phase = VegasPhase::CongestionAvoidance;
            self.ssthresh = self.cwnd;
            // Perform one CA adjustment immediately.
            self.congestion_avoidance_update();
        } else {
            // Still in slow start — grow exponentially.
            self.cwnd = (self.cwnd + 1).min(MAX_CWND);
        }
    }

    /// Vegas congestion avoidance: adjust cwnd based on diff.
    fn congestion_avoidance_update(&mut self) {
        let diff = self.compute_diff();

        if diff < self.params.alpha {
            // Under-utilizing: increase cwnd by 1.
            self.cwnd = (self.cwnd + 1).min(MAX_CWND);
        } else if diff > self.params.beta {
            // Over-utilizing (queue building): decrease cwnd by 1.
            self.cwnd = self.cwnd.saturating_sub(1).max(MIN_CWND);
        }
        // If alpha <= diff <= beta: no change (ideal operating point).
    }

    /// Compute the Vegas diff metric.
    ///
    /// `diff = (expected - actual) * base_rtt`
    /// where expected = cwnd/base_rtt, actual = cwnd/current_rtt.
    ///
    /// Result is in units of packets (MSS segments).
    fn compute_diff(&self) -> u32 {
        if self.base_rtt == 0 || self.current_rtt == 0 {
            return 0;
        }

        // expected_rate = cwnd / base_rtt (packets per microsecond, scaled)
        // actual_rate = cwnd / current_rtt
        // diff = (expected_rate - actual_rate) * base_rtt
        //      = cwnd * (1 - base_rtt/current_rtt)
        //      = cwnd * (current_rtt - base_rtt) / current_rtt

        let cwnd_scaled = self.cwnd as u64 * THROUGHPUT_SCALE;
        let rtt_diff = self.current_rtt.saturating_sub(self.base_rtt);
        let diff_scaled = cwnd_scaled * rtt_diff / self.current_rtt;

        (diff_scaled / THROUGHPUT_SCALE) as u32
    }

    /// Compute the expected throughput (packets per second, scaled).
    pub fn expected_throughput(&self) -> u64 {
        if self.base_rtt == 0 {
            return 0;
        }
        // cwnd / base_rtt, scaled to packets/second
        (self.cwnd as u64) * 1_000_000 / self.base_rtt
    }

    /// Compute the actual throughput (packets per second, scaled).
    pub fn actual_throughput(&self) -> u64 {
        if self.current_rtt == 0 || self.current_rtt == RTT_UNSET {
            return 0;
        }
        (self.cwnd as u64) * 1_000_000 / self.current_rtt
    }

    /// Handle a packet loss event.
    ///
    /// Vegas enters fast recovery: ssthresh is set to 3/4 of cwnd
    /// (less aggressive than Reno's 1/2 because Vegas has already
    /// been proactively reducing cwnd).
    pub fn on_loss(&mut self) {
        if !self.active {
            return;
        }

        self.retransmits += 1;
        self.phase = VegasPhase::FastRecovery;

        // Vegas uses 3/4 reduction (less aggressive than Reno's 1/2).
        self.ssthresh = (self.cwnd * 3 / 4).max(MIN_CWND);
        self.cwnd = self.ssthresh;
    }

    /// Handle recovery completion (all lost segments acknowledged).
    pub fn on_recovery_complete(&mut self) {
        if self.phase == VegasPhase::FastRecovery {
            self.phase = VegasPhase::CongestionAvoidance;
        }
    }

    /// Handle a retransmission timeout (RTO).
    pub fn on_timeout(&mut self) {
        if !self.active {
            return;
        }

        self.retransmits += 1;
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = MIN_CWND;
        self.phase = VegasPhase::SlowStart;
        self.round_count = 0;
        self.even_round = false;
    }

    /// Reset the connection state (e.g., for connection reuse).
    pub fn reset(&mut self) {
        self.cwnd = INITIAL_CWND;
        self.ssthresh = INITIAL_SSTHRESH;
        self.base_rtt = RTT_UNSET;
        self.current_rtt = RTT_UNSET;
        self.rtt_history.reset();
        self.phase = VegasPhase::SlowStart;
        self.ack_count = 0;
        self.bytes_acked = 0;
        self.round_count = 0;
        self.round_start_us = 0;
        self.even_round = false;
        self.slow_start_prev_cwnd = INITIAL_CWND;
        self.retransmits = 0;
    }

    /// Deactivate the connection.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Update algorithm parameters.
    pub fn set_params(&mut self, params: VegasParams) -> Result<()> {
        params.validate()?;
        self.params = params;
        Ok(())
    }
}

// ── VegasStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for the Vegas congestion control subsystem.
#[derive(Debug, Clone, Copy)]
pub struct VegasStats {
    /// Total active connections.
    pub active_connections: usize,
    /// Total ACKs processed across all connections.
    pub total_acks: u64,
    /// Total bytes acknowledged.
    pub total_bytes_acked: u64,
    /// Total retransmissions.
    pub total_retransmits: u64,
    /// Connections currently in slow start.
    pub in_slow_start: usize,
    /// Connections in congestion avoidance.
    pub in_congestion_avoidance: usize,
    /// Connections in fast recovery.
    pub in_fast_recovery: usize,
}

impl VegasStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            active_connections: 0,
            total_acks: 0,
            total_bytes_acked: 0,
            total_retransmits: 0,
            in_slow_start: 0,
            in_congestion_avoidance: 0,
            in_fast_recovery: 0,
        }
    }
}

impl Default for VegasStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── VegasManager ──────────────────────────────────────────────────────────────

/// Manages Vegas congestion control state for all TCP connections.
///
/// Provides connection registration, lookup, and aggregate statistics.
pub struct VegasManager {
    /// Per-connection Vegas state.
    connections: [VegasState; MAX_CONNECTIONS],
    /// Number of registered connections.
    count: usize,
    /// Global default parameters.
    default_params: VegasParams,
}

impl VegasManager {
    /// Create a new Vegas manager.
    pub const fn new() -> Self {
        Self {
            connections: [const { VegasState::new(0) }; MAX_CONNECTIONS],
            count: 0,
            default_params: VegasParams::new(),
        }
    }

    /// Register a new connection.
    ///
    /// Returns the slot index on success.
    pub fn register(&mut self, conn_id: u64) -> Result<usize> {
        if self.count >= MAX_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate.
        for i in 0..self.count {
            if self.connections[i].conn_id == conn_id && self.connections[i].active {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot (reuse inactive slots).
        let slot = self.find_free_slot()?;
        self.connections[slot] = VegasState::with_params(conn_id, self.default_params);
        if slot >= self.count {
            self.count = slot + 1;
        }
        Ok(slot)
    }

    /// Find a free slot, preferring inactive entries.
    fn find_free_slot(&self) -> Result<usize> {
        // First try inactive slots below count.
        for i in 0..self.count {
            if !self.connections[i].active {
                return Ok(i);
            }
        }
        // Then try the next unused slot.
        if self.count < MAX_CONNECTIONS {
            return Ok(self.count);
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a connection by ID.
    pub fn unregister(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].deactivate();
        Ok(())
    }

    /// Find a connection by ID, returning its index.
    fn find_connection(&self, conn_id: u64) -> Result<usize> {
        for i in 0..self.count {
            if self.connections[i].conn_id == conn_id && self.connections[i].active {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Process an ACK for a connection.
    pub fn on_ack(&mut self, conn_id: u64, rtt_us: u64, bytes: u32, now_us: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].on_ack(rtt_us, bytes, now_us);
        Ok(())
    }

    /// Report a loss event for a connection.
    pub fn on_loss(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].on_loss();
        Ok(())
    }

    /// Report recovery completion for a connection.
    pub fn on_recovery(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].on_recovery_complete();
        Ok(())
    }

    /// Report a timeout for a connection.
    pub fn on_timeout(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].on_timeout();
        Ok(())
    }

    /// Get the current cwnd for a connection.
    pub fn get_cwnd(&self, conn_id: u64) -> Result<u32> {
        let idx = self.find_connection(conn_id)?;
        Ok(self.connections[idx].cwnd())
    }

    /// Get the expected throughput for a connection.
    pub fn expected_throughput(&self, conn_id: u64) -> Result<u64> {
        let idx = self.find_connection(conn_id)?;
        Ok(self.connections[idx].expected_throughput())
    }

    /// Get the actual throughput for a connection.
    pub fn actual_throughput(&self, conn_id: u64) -> Result<u64> {
        let idx = self.find_connection(conn_id)?;
        Ok(self.connections[idx].actual_throughput())
    }

    /// Get a reference to a connection state.
    pub fn get_state(&self, conn_id: u64) -> Result<&VegasState> {
        let idx = self.find_connection(conn_id)?;
        Ok(&self.connections[idx])
    }

    /// Get a mutable reference to a connection state.
    pub fn get_state_mut(&mut self, conn_id: u64) -> Result<&mut VegasState> {
        let idx = self.find_connection(conn_id)?;
        Ok(&mut self.connections[idx])
    }

    /// Set default parameters for new connections.
    pub fn set_default_params(&mut self, params: VegasParams) -> Result<()> {
        params.validate()?;
        self.default_params = params;
        Ok(())
    }

    /// Gather aggregate statistics.
    pub fn stats(&self) -> VegasStats {
        let mut s = VegasStats::new();
        for i in 0..self.count {
            let c = &self.connections[i];
            if !c.active {
                continue;
            }
            s.active_connections += 1;
            s.total_acks += c.ack_count;
            s.total_bytes_acked += c.bytes_acked;
            s.total_retransmits += c.retransmits;
            match c.phase {
                VegasPhase::SlowStart => s.in_slow_start += 1,
                VegasPhase::CongestionAvoidance => {
                    s.in_congestion_avoidance += 1;
                }
                VegasPhase::FastRecovery => s.in_fast_recovery += 1,
            }
        }
        s
    }

    /// Number of active connections.
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.connections[i].active {
                n += 1;
            }
        }
        n
    }

    /// Reset a specific connection.
    pub fn reset_connection(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id)?;
        self.connections[idx].reset();
        Ok(())
    }

    /// Purge all inactive connections by compacting the array.
    pub fn compact(&mut self) {
        let mut write = 0;
        for read in 0..self.count {
            if self.connections[read].active {
                if write != read {
                    // Copy active entry down.
                    let conn_id = self.connections[read].conn_id;
                    let cwnd = self.connections[read].cwnd;
                    let ssthresh = self.connections[read].ssthresh;
                    let base_rtt = self.connections[read].base_rtt;
                    let phase = self.connections[read].phase;
                    let params = self.connections[read].params;

                    self.connections[write] = VegasState::with_params(conn_id, params);
                    self.connections[write].cwnd = cwnd;
                    self.connections[write].ssthresh = ssthresh;
                    self.connections[write].base_rtt = base_rtt;
                    self.connections[write].phase = phase;
                }
                write += 1;
            }
        }
        self.count = write;
    }
}

impl Default for VegasManager {
    fn default() -> Self {
        Self::new()
    }
}

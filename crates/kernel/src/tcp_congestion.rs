// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TCP congestion control algorithms.
//!
//! Implements multiple congestion control strategies that can be
//! selected per-connection. Each algorithm controls the congestion
//! window (cwnd) and slow-start threshold (ssthresh) based on
//! network feedback (ACKs, timeouts, duplicate ACKs).
//!
//! # Supported Algorithms
//!
//! | Algorithm | RFC    | Description                      |
//! |-----------|--------|----------------------------------|
//! | Reno      | 5681   | Classic AIMD with fast recovery  |
//! | NewReno   | 6582   | Improved fast recovery           |
//! | Cubic     | 9438   | Cubic function window growth     |
//!
//! # Usage
//!
//! Each TCP connection holds a [`CongestionState`] and a selected
//! [`CongestionAlgorithm`]. Events such as ACK receipt, timeout,
//! and duplicate ACK trigger state updates via the [`CongestionOps`]
//! trait.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default initial congestion window (in MSS units, RFC 6928).
const INITIAL_CWND: u32 = 10;

/// Minimum congestion window (1 MSS).
const MIN_CWND: u32 = 1;

/// Default slow-start threshold (64 KiB / MSS).
const DEFAULT_SSTHRESH: u32 = 65535;

/// Duplicate ACK threshold for fast retransmit (RFC 5681).
const DUP_ACK_THRESHOLD: u32 = 3;

/// Cubic scaling factor (beta = 0.7 in fixed-point, 7/10).
const CUBIC_BETA_NUM: u32 = 7;

/// Cubic scaling factor denominator.
const CUBIC_BETA_DEN: u32 = 10;

/// Cubic constant C (0.4 in fixed-point: 4/10).
const CUBIC_C_NUM: u32 = 4;

/// Cubic constant C denominator.
const CUBIC_C_DEN: u32 = 10;

// ---------------------------------------------------------------------------
// Congestion Algorithm Selection
// ---------------------------------------------------------------------------

/// Available congestion control algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionAlgorithm {
    /// TCP Reno (classic AIMD, RFC 5681).
    Reno,
    /// TCP NewReno (improved fast recovery, RFC 6582).
    NewReno,
    /// CUBIC (cubic function growth, RFC 9438).
    #[default]
    Cubic,
}

// ---------------------------------------------------------------------------
// Congestion State
// ---------------------------------------------------------------------------

/// TCP congestion control phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionPhase {
    /// Slow start: exponential growth.
    #[default]
    SlowStart,
    /// Congestion avoidance: linear growth.
    CongestionAvoidance,
    /// Fast recovery: recovering from packet loss.
    FastRecovery,
}

/// Per-connection congestion control state.
#[derive(Debug, Clone, Copy)]
pub struct CongestionState {
    /// Congestion window in MSS units.
    pub cwnd: u32,
    /// Slow-start threshold in MSS units.
    pub ssthresh: u32,
    /// Current phase.
    pub phase: CongestionPhase,
    /// Number of consecutive duplicate ACKs.
    pub dup_ack_count: u32,
    /// Maximum segment size (bytes).
    pub mss: u32,
    /// Selected algorithm.
    pub algorithm: CongestionAlgorithm,
    /// Bytes acknowledged in the current RTT (for Reno CA).
    pub bytes_acked: u32,
    /// Smoothed RTT in milliseconds.
    pub srtt_ms: u32,
    /// RTT variance in milliseconds.
    pub rttvar_ms: u32,
    /// Retransmission timeout in milliseconds.
    pub rto_ms: u32,
    /// Recovery sequence number (NewReno).
    pub recover_seq: u32,
    /// Cubic: window size at last loss event (W_max).
    pub cubic_w_max: u32,
    /// Cubic: time of last loss event (ms).
    pub cubic_epoch_start: u64,
    /// Cubic: origin point (W_max * beta).
    pub cubic_origin: u32,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes retransmitted.
    pub bytes_retransmitted: u64,
}

impl CongestionState {
    /// Create a new congestion state with the given MSS and algorithm.
    pub fn new(mss: u32, algorithm: CongestionAlgorithm) -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: DEFAULT_SSTHRESH,
            phase: CongestionPhase::SlowStart,
            dup_ack_count: 0,
            mss,
            algorithm,
            bytes_acked: 0,
            srtt_ms: 0,
            rttvar_ms: 0,
            rto_ms: 1000, // 1 second initial RTO
            recover_seq: 0,
            cubic_w_max: 0,
            cubic_epoch_start: 0,
            cubic_origin: 0,
            bytes_sent: 0,
            bytes_retransmitted: 0,
        }
    }

    /// Returns the current send window in bytes.
    pub fn window_bytes(&self) -> u32 {
        self.cwnd.saturating_mul(self.mss)
    }

    /// Returns `true` if in slow start.
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Update the smoothed RTT (RFC 6298).
    ///
    /// `sample_ms` is a fresh RTT measurement in milliseconds.
    pub fn update_rtt(&mut self, sample_ms: u32) {
        if self.srtt_ms == 0 {
            // First measurement
            self.srtt_ms = sample_ms;
            self.rttvar_ms = sample_ms / 2;
        } else {
            let diff = sample_ms.abs_diff(self.srtt_ms);
            // RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - R'|
            self.rttvar_ms = (3 * self.rttvar_ms + diff) / 4;
            // SRTT = (7/8) * SRTT + (1/8) * R'
            self.srtt_ms = (7 * self.srtt_ms + sample_ms) / 8;
        }
        // RTO = SRTT + max(1, 4 * RTTVAR), clamped to [200, 60000]
        let rto = self.srtt_ms + (4 * self.rttvar_ms).max(1);
        self.rto_ms = rto.clamp(200, 60_000);
    }
}

impl Default for CongestionState {
    fn default() -> Self {
        Self::new(1460, CongestionAlgorithm::default())
    }
}

// ---------------------------------------------------------------------------
// Congestion Events
// ---------------------------------------------------------------------------

/// Process a new ACK (non-duplicate).
///
/// Updates cwnd based on the current phase and algorithm.
pub fn on_ack(state: &mut CongestionState, acked_bytes: u32) {
    state.dup_ack_count = 0;

    match state.algorithm {
        CongestionAlgorithm::Reno | CongestionAlgorithm::NewReno => {
            reno_on_ack(state, acked_bytes);
        }
        CongestionAlgorithm::Cubic => {
            cubic_on_ack(state, acked_bytes);
        }
    }

    // Exit fast recovery on new ACK
    if state.phase == CongestionPhase::FastRecovery {
        state.cwnd = state.ssthresh;
        state.phase = CongestionPhase::CongestionAvoidance;
    }
}

/// Process a duplicate ACK.
///
/// After [`DUP_ACK_THRESHOLD`] consecutive duplicate ACKs, enter
/// fast retransmit / fast recovery.
pub fn on_dup_ack(state: &mut CongestionState, current_seq: u32) {
    state.dup_ack_count += 1;

    if state.dup_ack_count == DUP_ACK_THRESHOLD {
        // Enter fast retransmit / fast recovery
        match state.algorithm {
            CongestionAlgorithm::Reno => {
                state.ssthresh = (state.cwnd / 2).max(MIN_CWND);
                state.cwnd = state.ssthresh + DUP_ACK_THRESHOLD;
                state.phase = CongestionPhase::FastRecovery;
            }
            CongestionAlgorithm::NewReno => {
                state.ssthresh = (state.cwnd / 2).max(MIN_CWND);
                state.cwnd = state.ssthresh + DUP_ACK_THRESHOLD;
                state.recover_seq = current_seq;
                state.phase = CongestionPhase::FastRecovery;
            }
            CongestionAlgorithm::Cubic => {
                cubic_on_loss(state);
                state.cwnd = state.ssthresh + DUP_ACK_THRESHOLD;
                state.phase = CongestionPhase::FastRecovery;
            }
        }
        state.bytes_retransmitted += state.mss as u64;
    } else if state.dup_ack_count > DUP_ACK_THRESHOLD
        && state.phase == CongestionPhase::FastRecovery
    {
        // Inflate cwnd for each additional dup ACK
        state.cwnd += 1;
    }
}

/// Process a retransmission timeout (RTO).
///
/// Resets cwnd to 1 MSS and enters slow start.
pub fn on_timeout(state: &mut CongestionState) {
    match state.algorithm {
        CongestionAlgorithm::Cubic => {
            cubic_on_loss(state);
        }
        _ => {
            state.ssthresh = (state.cwnd / 2).max(MIN_CWND);
        }
    }
    state.cwnd = MIN_CWND;
    state.phase = CongestionPhase::SlowStart;
    state.dup_ack_count = 0;

    // Exponential backoff for RTO
    state.rto_ms = (state.rto_ms * 2).min(60_000);

    state.bytes_retransmitted += state.mss as u64;
}

// ---------------------------------------------------------------------------
// Reno / NewReno
// ---------------------------------------------------------------------------

/// Reno ACK processing.
fn reno_on_ack(state: &mut CongestionState, acked_bytes: u32) {
    if state.in_slow_start() {
        // Slow start: increase cwnd by 1 MSS per ACK
        state.cwnd += 1;
        if state.cwnd >= state.ssthresh {
            state.phase = CongestionPhase::CongestionAvoidance;
            state.bytes_acked = 0;
        }
    } else {
        // Congestion avoidance: increase cwnd by ~1 MSS per RTT
        state.bytes_acked += acked_bytes;
        if state.bytes_acked >= state.cwnd * state.mss {
            state.cwnd += 1;
            state.bytes_acked = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// CUBIC (RFC 9438)
// ---------------------------------------------------------------------------

/// CUBIC ACK processing.
fn cubic_on_ack(state: &mut CongestionState, _acked_bytes: u32) {
    if state.in_slow_start() {
        state.cwnd += 1;
        if state.cwnd >= state.ssthresh {
            state.phase = CongestionPhase::CongestionAvoidance;
        }
        return;
    }

    // CUBIC congestion avoidance
    // W_cubic(t) = C * (t - K)^3 + W_max
    // where K = cubic_root(W_max * (1 - beta) / C)
    //
    // Simplified integer approximation:
    // We increase cwnd by approximately
    // (cubic_target - cwnd) / cwnd per ACK
    let target = cubic_target(state);
    if target > state.cwnd {
        let inc = (target - state.cwnd) / state.cwnd;
        state.cwnd += inc.max(1);
    } else {
        // TCP-friendly region: at least Reno-equivalent growth
        state.cwnd += 1;
    }
}

/// CUBIC loss event.
fn cubic_on_loss(state: &mut CongestionState) {
    state.cubic_w_max = state.cwnd;
    state.ssthresh = (state.cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN).max(MIN_CWND);
    state.cubic_origin = state.cwnd * CUBIC_BETA_NUM / CUBIC_BETA_DEN;
}

/// Compute the CUBIC target window.
///
/// Uses an integer approximation of the cubic function.
fn cubic_target(state: &CongestionState) -> u32 {
    // Simplified: linear increase toward W_max, then cubic beyond
    if state.cubic_w_max == 0 {
        return state.cwnd + 1;
    }

    // If cwnd < W_max * beta, we're below the concave region
    let origin = state.cubic_origin;
    if state.cwnd < origin {
        // Concave region: grow toward origin
        let diff = origin - state.cwnd;
        state.cwnd + (diff / 16).max(1)
    } else {
        // Convex region: grow beyond W_max
        let excess = state.cwnd - origin;
        // Cubic growth: small increments based on distance
        let inc = (excess * CUBIC_C_NUM) / (CUBIC_C_DEN * 100);
        state.cwnd + inc.max(1)
    }
}

// ---------------------------------------------------------------------------
// Connection Statistics
// ---------------------------------------------------------------------------

/// Congestion control statistics for monitoring.
#[derive(Debug, Clone, Copy, Default)]
pub struct CongestionStats {
    /// Current cwnd in MSS units.
    pub cwnd: u32,
    /// Current ssthresh in MSS units.
    pub ssthresh: u32,
    /// Current phase.
    pub phase: CongestionPhase,
    /// Smoothed RTT in milliseconds.
    pub srtt_ms: u32,
    /// RTO in milliseconds.
    pub rto_ms: u32,
    /// Total bytes retransmitted.
    pub bytes_retransmitted: u64,
    /// Algorithm in use.
    pub algorithm: CongestionAlgorithm,
}

impl CongestionStats {
    /// Collect stats from a congestion state.
    pub fn from_state(state: &CongestionState) -> Self {
        Self {
            cwnd: state.cwnd,
            ssthresh: state.ssthresh,
            phase: state.phase,
            srtt_ms: state.srtt_ms,
            rto_ms: state.rto_ms,
            bytes_retransmitted: state.bytes_retransmitted,
            algorithm: state.algorithm,
        }
    }
}

// ---------------------------------------------------------------------------
// Algorithm Registry
// ---------------------------------------------------------------------------

/// Maximum registered algorithms.
const MAX_ALGORITHMS: usize = 8;

/// Registered congestion control algorithm descriptor.
#[derive(Debug, Clone, Copy)]
pub struct AlgorithmInfo {
    /// Algorithm identifier.
    pub algo: CongestionAlgorithm,
    /// Human-readable name.
    pub name: &'static str,
    /// Whether this is the system default.
    pub is_default: bool,
}

/// Registry of available congestion control algorithms.
pub struct AlgorithmRegistry {
    /// Registered algorithms.
    entries: [Option<AlgorithmInfo>; MAX_ALGORITHMS],
    /// Number of registered algorithms.
    count: usize,
}

impl AlgorithmRegistry {
    /// Create a registry with the built-in algorithms.
    pub fn new() -> Self {
        let mut reg = Self {
            entries: [None; MAX_ALGORITHMS],
            count: 0,
        };
        reg.entries[0] = Some(AlgorithmInfo {
            algo: CongestionAlgorithm::Reno,
            name: "reno",
            is_default: false,
        });
        reg.entries[1] = Some(AlgorithmInfo {
            algo: CongestionAlgorithm::NewReno,
            name: "newreno",
            is_default: false,
        });
        reg.entries[2] = Some(AlgorithmInfo {
            algo: CongestionAlgorithm::Cubic,
            name: "cubic",
            is_default: true,
        });
        reg.count = 3;
        reg
    }

    /// Look up an algorithm by name.
    pub fn find_by_name(&self, name: &str) -> Option<CongestionAlgorithm> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .find(|info| info.name == name)
            .map(|info| info.algo)
    }

    /// Returns the default algorithm.
    pub fn default_algorithm(&self) -> CongestionAlgorithm {
        self.entries[..self.count]
            .iter()
            .flatten()
            .find(|info| info.is_default)
            .map(|info| info.algo)
            .unwrap_or(CongestionAlgorithm::Cubic)
    }

    /// Returns the number of registered algorithms.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no algorithms are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

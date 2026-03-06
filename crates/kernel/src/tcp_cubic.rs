// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CUBIC congestion control algorithm (RFC 9438).
//!
//! Implements the CUBIC TCP congestion control algorithm, the default
//! congestion control in Linux since kernel 2.6.19. CUBIC uses a
//! cubic function for window growth during congestion avoidance,
//! providing better bandwidth utilization on high-BDP networks
//! compared to classic Reno/NewReno AIMD.
//!
//! # Key Concepts
//!
//! - **W_max**: The congestion window size at the last loss event.
//!   Serves as the inflection point of the cubic function.
//! - **Cubic function**: `W(t) = C * (t - K)^3 + W_max` where
//!   `K = cbrt(W_max * beta_cubic / C)` and `C = 0.4`.
//! - **beta_cubic**: Multiplicative decrease factor (0.7 for CUBIC,
//!   vs 0.5 for Reno).
//! - **HyStart**: Hybrid slow-start algorithm that exits slow start
//!   earlier to avoid excessive overshoot.
//! - **TCP-friendly region**: Ensures CUBIC is at least as aggressive
//!   as standard Reno in low-BDP environments.
//! - **Fast convergence**: When W_max decreases, the algorithm
//!   converges faster to the fair share.
//!
//! # Fixed-Point Arithmetic
//!
//! All calculations use integer arithmetic with fixed-point scaling
//! to avoid floating-point operations in kernel space. Window sizes
//! are in MSS units, times in milliseconds.
//!
//! Reference: RFC 9438, Linux `net/ipv4/tcp_cubic.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// CUBIC multiplicative decrease factor numerator (beta = 0.7).
const BETA_CUBIC_NUM: u32 = 7;

/// CUBIC multiplicative decrease factor denominator.
const BETA_CUBIC_DEN: u32 = 10;

/// CUBIC scaling constant C numerator (C = 0.4).
const CUBIC_C_NUM: u32 = 4;

/// CUBIC scaling constant C denominator.
const CUBIC_C_DEN: u32 = 10;

/// Fixed-point scale factor for cubic calculations (2^10 = 1024).
const SCALE: u64 = 1024;

/// Minimum congestion window (1 MSS).
const MIN_CWND: u32 = 1;

/// Default initial congestion window (RFC 6928: 10 MSS).
const INITIAL_CWND: u32 = 10;

/// Default slow-start threshold (effectively infinite).
const DEFAULT_SSTHRESH: u32 = u32::MAX;

/// HyStart low-latency threshold in microseconds.
const HYSTART_LOW_THRESHOLD_US: u64 = 4000;

/// HyStart high-latency threshold in microseconds.
const HYSTART_HIGH_THRESHOLD_US: u64 = 16000;

/// HyStart minimum round samples before making a decision.
const HYSTART_MIN_SAMPLES: u32 = 8;

/// HyStart ACK train detection: max inter-ACK gap (us).
const HYSTART_ACK_TRAIN_GAP_US: u64 = 2000;

/// Maximum RTT samples stored for HyStart.
const MAX_RTT_SAMPLES: usize = 16;

/// Maximum number of CUBIC connections tracked.
const MAX_CONNECTIONS: usize = 64;

/// TCP-friendly Reno equivalent additive increase numerator.
/// W_reno_inc = 3 * (1 - beta) / (1 + beta) per RTT.
/// For beta=0.7: 3 * 0.3 / 1.7 ≈ 0.529 ≈ 529/1000.
const RENO_INC_NUM: u32 = 529;

/// TCP-friendly Reno equivalent denominator.
const RENO_INC_DEN: u32 = 1000;

// ── CUBIC Phase ────────────────────────────────────────────────────

/// Current phase of the CUBIC congestion control state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CubicPhase {
    /// Slow start: exponential window growth.
    #[default]
    SlowStart,
    /// Congestion avoidance using the cubic function.
    CongestionAvoidance,
    /// Fast recovery after a loss event.
    Recovery,
    /// HyStart-triggered congestion avoidance (exited slow-start
    /// early due to increasing delay).
    HyStartCa,
}

// ── HyStart State ──────────────────────────────────────────────────

/// HyStart (Hybrid Slow-Start) state.
///
/// HyStart detects the onset of congestion during slow start by
/// monitoring RTT increases and ACK spacing. It exits slow start
/// before the classic ssthresh is reached, reducing loss.
#[derive(Debug, Clone, Copy)]
pub struct HyStartState {
    /// Whether HyStart is enabled.
    pub enabled: bool,
    /// Whether HyStart has triggered (exited slow start).
    pub found: bool,
    /// Round-trip counter (incremented each RTT).
    pub round: u32,
    /// Last round when an RTT sample was taken.
    pub last_round: u32,
    /// Current round minimum RTT (microseconds).
    pub curr_rtt_min_us: u64,
    /// Previous round minimum RTT (microseconds).
    pub prev_rtt_min_us: u64,
    /// Number of RTT samples in current round.
    pub sample_count: u32,
    /// RTT samples buffer.
    pub rtt_samples: [u64; MAX_RTT_SAMPLES],
    /// ACK train detection: timestamp of last ACK (us).
    pub last_ack_time_us: u64,
    /// Number of ACKs in current train.
    pub ack_train_count: u32,
    /// cwnd at the start of the current round.
    pub round_start_cwnd: u32,
}

impl HyStartState {
    /// Create a new HyStart state with detection enabled.
    const fn new() -> Self {
        Self {
            enabled: true,
            found: false,
            round: 0,
            last_round: 0,
            curr_rtt_min_us: u64::MAX,
            prev_rtt_min_us: u64::MAX,
            sample_count: 0,
            rtt_samples: [0u64; MAX_RTT_SAMPLES],
            last_ack_time_us: 0,
            ack_train_count: 0,
            round_start_cwnd: INITIAL_CWND,
        }
    }

    /// Reset HyStart state for a new connection or after a timeout.
    fn reset(&mut self) {
        self.found = false;
        self.round = 0;
        self.last_round = 0;
        self.curr_rtt_min_us = u64::MAX;
        self.prev_rtt_min_us = u64::MAX;
        self.sample_count = 0;
        self.ack_train_count = 0;
        self.round_start_cwnd = INITIAL_CWND;
    }

    /// Start a new round (called when a full cwnd of data is ACKed).
    fn new_round(&mut self, cwnd: u32) {
        self.round += 1;
        self.prev_rtt_min_us = self.curr_rtt_min_us;
        self.curr_rtt_min_us = u64::MAX;
        self.sample_count = 0;
        self.ack_train_count = 0;
        self.round_start_cwnd = cwnd;
    }

    /// Record an RTT sample during slow start.
    ///
    /// Returns `true` if HyStart triggers (should exit slow start).
    fn record_rtt(&mut self, rtt_us: u64, now_us: u64) -> bool {
        if !self.enabled || self.found {
            return false;
        }

        // Update minimum RTT for current round
        if rtt_us < self.curr_rtt_min_us {
            self.curr_rtt_min_us = rtt_us;
        }

        // Store sample
        let sample_idx = self.sample_count as usize;
        if sample_idx < MAX_RTT_SAMPLES {
            self.rtt_samples[sample_idx] = rtt_us;
        }
        self.sample_count += 1;

        // ACK train detection
        if self.last_ack_time_us > 0 {
            let gap = now_us.saturating_sub(self.last_ack_time_us);
            if gap <= HYSTART_ACK_TRAIN_GAP_US {
                self.ack_train_count += 1;
            }
        }
        self.last_ack_time_us = now_us;

        // Delay-increase detection requires enough samples
        if self.sample_count < HYSTART_MIN_SAMPLES {
            return false;
        }
        if self.prev_rtt_min_us == u64::MAX {
            return false;
        }

        // Compute the delay increase threshold (clamped)
        let threshold = self.prev_rtt_min_us / 8;
        let threshold = threshold.clamp(HYSTART_LOW_THRESHOLD_US, HYSTART_HIGH_THRESHOLD_US);

        // Trigger if current round min RTT exceeds previous by
        // threshold
        if self.curr_rtt_min_us > self.prev_rtt_min_us + threshold {
            self.found = true;
            return true;
        }

        false
    }
}

// ── CUBIC State ────────────────────────────────────────────────────

/// Per-connection CUBIC congestion control state.
///
/// Tracks the cubic function parameters, window sizes, and timing
/// needed to compute the congestion window at each ACK.
#[derive(Debug, Clone, Copy)]
pub struct CubicState {
    /// Connection identifier.
    pub conn_id: u64,
    /// Current congestion window (MSS units).
    pub cwnd: u32,
    /// Slow-start threshold (MSS units).
    pub ssthresh: u32,
    /// Current CUBIC phase.
    pub phase: CubicPhase,
    /// W_max: window size at last loss event (MSS units).
    pub w_max: u32,
    /// W_max before fast convergence adjustment.
    pub w_max_last: u32,
    /// K: time to reach W_max from the cubic origin (ms, scaled).
    pub k_scaled: u64,
    /// Epoch start time (ms since boot) — when current CA started.
    pub epoch_start_ms: u64,
    /// Origin point of the cubic function (cwnd at epoch start).
    pub origin_cwnd: u32,
    /// Number of ACKs received in current epoch.
    pub ack_count: u64,
    /// Accumulated fractional cwnd increase (scaled by SCALE).
    pub cwnd_cnt: u64,
    /// TCP-friendly Reno equivalent cwnd for comparison.
    pub w_tcp: u32,
    /// Minimum RTT observed (microseconds).
    pub min_rtt_us: u64,
    /// Smoothed RTT (microseconds).
    pub srtt_us: u64,
    /// Whether this connection slot is active.
    pub active: bool,
    /// HyStart state for this connection.
    pub hystart: HyStartState,
    /// Fast convergence enabled.
    pub fast_convergence: bool,
    /// Total bytes acknowledged.
    pub total_acked: u64,
    /// Total loss events.
    pub loss_events: u64,
    /// Total retransmissions.
    pub retransmissions: u64,
}

impl CubicState {
    /// Create an empty (inactive) CUBIC state.
    const fn empty() -> Self {
        Self {
            conn_id: 0,
            cwnd: INITIAL_CWND,
            ssthresh: DEFAULT_SSTHRESH,
            phase: CubicPhase::SlowStart,
            w_max: 0,
            w_max_last: 0,
            k_scaled: 0,
            epoch_start_ms: 0,
            origin_cwnd: 0,
            ack_count: 0,
            cwnd_cnt: 0,
            w_tcp: INITIAL_CWND,
            min_rtt_us: u64::MAX,
            srtt_us: 0,
            active: false,
            hystart: HyStartState::new(),
            fast_convergence: true,
            total_acked: 0,
            loss_events: 0,
            retransmissions: 0,
        }
    }

    /// Initialize a new CUBIC connection state.
    fn init(&mut self, conn_id: u64) {
        self.conn_id = conn_id;
        self.cwnd = INITIAL_CWND;
        self.ssthresh = DEFAULT_SSTHRESH;
        self.phase = CubicPhase::SlowStart;
        self.w_max = 0;
        self.w_max_last = 0;
        self.k_scaled = 0;
        self.epoch_start_ms = 0;
        self.origin_cwnd = 0;
        self.ack_count = 0;
        self.cwnd_cnt = 0;
        self.w_tcp = INITIAL_CWND;
        self.min_rtt_us = u64::MAX;
        self.srtt_us = 0;
        self.active = true;
        self.hystart.reset();
        self.fast_convergence = true;
        self.total_acked = 0;
        self.loss_events = 0;
        self.retransmissions = 0;
    }

    /// Compute K = cbrt(W_max * beta / C) in milliseconds (scaled).
    ///
    /// Uses integer cube-root approximation via Newton's method.
    fn compute_k(&mut self) {
        if self.w_max == 0 {
            self.k_scaled = 0;
            return;
        }
        // K^3 = W_max * (1-beta) / C
        //     = W_max * (3/10) / (4/10)
        //     = W_max * 3/4
        let k_cubed = (self.w_max as u64 * 3 * SCALE) / 4;
        self.k_scaled = integer_cbrt(k_cubed);
    }

    /// Compute the cubic function W(t) at time `elapsed_ms` since
    /// the epoch start.
    ///
    /// W(t) = C * (t - K)^3 + W_max
    fn cubic_window(&self, elapsed_ms: u64) -> u32 {
        let t_scaled = elapsed_ms * SCALE / 1000;

        let diff: i64;
        if t_scaled >= self.k_scaled {
            diff = (t_scaled - self.k_scaled) as i64;
        } else {
            diff = -((self.k_scaled - t_scaled) as i64);
        }

        // C * diff^3 / SCALE^2 + W_max
        // C = 4/10 so: 4 * diff^3 / (10 * SCALE^2)
        let diff_cubed = diff.wrapping_mul(diff).wrapping_mul(diff);
        let c_term = (CUBIC_C_NUM as i64).wrapping_mul(diff_cubed)
            / ((CUBIC_C_DEN as i64) * (SCALE as i64) * (SCALE as i64));

        let window = (self.w_max as i64) + c_term;
        if window < MIN_CWND as i64 {
            MIN_CWND
        } else {
            window as u32
        }
    }

    /// Compute the TCP-friendly Reno equivalent window.
    ///
    /// Ensures CUBIC is at least as aggressive as standard Reno.
    fn tcp_friendly_window(&self, elapsed_ms: u64) -> u32 {
        if elapsed_ms == 0 {
            return self.w_tcp;
        }
        // W_tcp = W_max * beta + (3 * (1-beta) / (1+beta)) * (t/RTT)
        let base = (self.w_max as u64 * BETA_CUBIC_NUM as u64) / BETA_CUBIC_DEN as u64;
        let rtt_ms = if self.srtt_us > 0 {
            self.srtt_us / 1000
        } else {
            1
        };
        let rounds = elapsed_ms / rtt_ms.max(1);
        let inc = (RENO_INC_NUM as u64 * rounds) / RENO_INC_DEN as u64;
        let w = base + inc;
        w.min(u32::MAX as u64) as u32
    }

    /// Handle a congestion event (packet loss or ECN mark).
    ///
    /// Performs the multiplicative decrease and records W_max for
    /// the cubic function. Fast convergence adjusts W_max downward
    /// if the new W_max is less than the previous one.
    fn on_loss(&mut self, now_ms: u64) {
        self.loss_events += 1;

        // Fast convergence: if cwnd < W_max_last, W_max is smaller
        if self.fast_convergence && self.cwnd < self.w_max_last {
            self.w_max_last = self.cwnd;
            // W_max = cwnd * (1 + beta) / 2
            self.w_max = (self.cwnd as u64 * (BETA_CUBIC_DEN as u64 + BETA_CUBIC_NUM as u64)
                / (2 * BETA_CUBIC_DEN as u64)) as u32;
        } else {
            self.w_max_last = self.w_max;
            self.w_max = self.cwnd;
        }

        // ssthresh = cwnd * beta
        self.ssthresh = ((self.cwnd as u64 * BETA_CUBIC_NUM as u64) / BETA_CUBIC_DEN as u64) as u32;
        if self.ssthresh < MIN_CWND {
            self.ssthresh = MIN_CWND;
        }

        self.cwnd = self.ssthresh;
        self.phase = CubicPhase::Recovery;
        self.epoch_start_ms = now_ms;
        self.ack_count = 0;
        self.cwnd_cnt = 0;
        self.compute_k();

        // Reset TCP-friendly baseline
        self.w_tcp = self.cwnd;
    }

    /// Handle an ACK received during congestion avoidance.
    ///
    /// Computes the target cwnd from both the cubic function and
    /// the TCP-friendly Reno window, choosing the larger to ensure
    /// CUBIC is at least as aggressive as standard TCP.
    fn on_ack_ca(&mut self, acked_bytes: u32, mss: u32, now_ms: u64) {
        if self.epoch_start_ms == 0 {
            self.epoch_start_ms = now_ms;
            self.origin_cwnd = self.cwnd;
        }

        let elapsed = now_ms.saturating_sub(self.epoch_start_ms);
        let cubic_target = self.cubic_window(elapsed);
        let reno_target = self.tcp_friendly_window(elapsed);

        // Use the larger of cubic and TCP-friendly
        let target = cubic_target.max(reno_target);

        if target > self.cwnd {
            // Increase cwnd by (target - cwnd) / cwnd per acked MSS
            let acked_mss = acked_bytes / mss.max(1);
            let delta = target.saturating_sub(self.cwnd);
            self.cwnd_cnt += (delta as u64 * acked_mss as u64 * SCALE) / self.cwnd.max(1) as u64;

            // Increment cwnd when we've accumulated enough
            while self.cwnd_cnt >= SCALE {
                self.cwnd += 1;
                self.cwnd_cnt -= SCALE;
            }
        }

        // Update TCP-friendly state
        self.w_tcp = reno_target;
        self.ack_count += 1;
    }

    /// Handle an ACK during slow start.
    ///
    /// Increases cwnd by the number of MSS segments ACKed (standard
    /// exponential growth). HyStart may trigger an early exit.
    fn on_ack_ss(&mut self, acked_bytes: u32, mss: u32, rtt_us: u64, now_us: u64) {
        // Standard slow-start: cwnd += acked_mss
        let acked_mss = acked_bytes / mss.max(1);
        self.cwnd += acked_mss;
        self.ack_count += 1;

        // HyStart detection
        if self.hystart.enabled && !self.hystart.found {
            // Check if we've completed a round
            let round_acks = self.hystart.round_start_cwnd;
            if self.ack_count >= round_acks as u64 {
                self.hystart.new_round(self.cwnd);
                self.ack_count = 0;
            }

            if self.hystart.record_rtt(rtt_us, now_us) {
                // HyStart triggered: exit slow start
                self.ssthresh = self.cwnd;
                self.phase = CubicPhase::HyStartCa;
                self.epoch_start_ms = now_us / 1000;
                self.w_max = self.cwnd;
                self.compute_k();
            }
        }

        // Standard ssthresh check
        if self.cwnd >= self.ssthresh {
            self.phase = CubicPhase::CongestionAvoidance;
            self.epoch_start_ms = now_us / 1000;
            self.w_max = self.cwnd;
            self.compute_k();
        }
    }
}

// ── CUBIC Connection Manager ───────────────────────────────────────

/// Manages multiple CUBIC congestion control connections.
///
/// Provides the top-level API for creating, updating, and querying
/// TCP connections using the CUBIC congestion control algorithm.
pub struct CubicManager {
    /// Per-connection CUBIC state.
    connections: [CubicState; MAX_CONNECTIONS],
    /// Number of active connections.
    active_count: usize,
    /// Total loss events across all connections.
    total_loss_events: u64,
    /// Total ACKs processed.
    total_acks: u64,
}

impl CubicManager {
    /// Create a new CUBIC connection manager.
    pub const fn new() -> Self {
        Self {
            connections: [CubicState::empty(); MAX_CONNECTIONS],
            active_count: 0,
            total_loss_events: 0,
            total_acks: 0,
        }
    }

    /// Create a new CUBIC connection.
    ///
    /// Returns the index of the newly created connection state.
    pub fn create_connection(&mut self, conn_id: u64) -> Result<usize> {
        if self.active_count >= MAX_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate
        if self.find_connection(conn_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .connections
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        self.connections[slot].init(conn_id);
        self.active_count += 1;
        Ok(slot)
    }

    /// Destroy a CUBIC connection.
    pub fn destroy_connection(&mut self, conn_id: u64) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        self.connections[idx].active = false;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Process an ACK for a connection.
    ///
    /// # Arguments
    /// * `conn_id` — connection identifier
    /// * `acked_bytes` — bytes acknowledged by this ACK
    /// * `mss` — maximum segment size
    /// * `rtt_us` — measured RTT in microseconds
    /// * `now_us` — current time in microseconds
    pub fn on_ack(
        &mut self,
        conn_id: u64,
        acked_bytes: u32,
        mss: u32,
        rtt_us: u64,
        now_us: u64,
    ) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        let state = &mut self.connections[idx];
        let now_ms = now_us / 1000;

        // Update RTT statistics
        if rtt_us < state.min_rtt_us {
            state.min_rtt_us = rtt_us;
        }
        // EWMA smoothed RTT: srtt = 7/8 * srtt + 1/8 * rtt
        if state.srtt_us == 0 {
            state.srtt_us = rtt_us;
        } else {
            state.srtt_us = (state.srtt_us * 7 + rtt_us) / 8;
        }
        state.total_acked += acked_bytes as u64;

        match state.phase {
            CubicPhase::SlowStart => {
                state.on_ack_ss(acked_bytes, mss, rtt_us, now_us);
            }
            CubicPhase::CongestionAvoidance | CubicPhase::HyStartCa => {
                state.on_ack_ca(acked_bytes, mss, now_ms);
            }
            CubicPhase::Recovery => {
                // In recovery, one MSS increase per RTT
                state.ack_count += 1;
                let cwnd_mss = state.cwnd as u64;
                if state.ack_count >= cwnd_mss {
                    state.cwnd += 1;
                    state.ack_count = 0;
                }
                // Exit recovery when cwnd >= ssthresh
                if state.cwnd >= state.ssthresh {
                    state.phase = CubicPhase::CongestionAvoidance;
                    state.epoch_start_ms = now_ms;
                    state.compute_k();
                }
            }
        }

        self.total_acks += 1;
        Ok(())
    }

    /// Report a packet loss for a connection.
    pub fn on_loss(&mut self, conn_id: u64, now_us: u64) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        let now_ms = now_us / 1000;
        self.connections[idx].on_loss(now_ms);
        self.total_loss_events += 1;
        Ok(())
    }

    /// Report a retransmission timeout (RTO) for a connection.
    ///
    /// Resets cwnd to minimum and enters slow start.
    pub fn on_rto(&mut self, conn_id: u64, now_us: u64) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        let state = &mut self.connections[idx];
        let now_ms = now_us / 1000;
        state.retransmissions += 1;
        state.ssthresh =
            ((state.cwnd as u64 * BETA_CUBIC_NUM as u64) / BETA_CUBIC_DEN as u64) as u32;
        if state.ssthresh < MIN_CWND {
            state.ssthresh = MIN_CWND;
        }
        state.cwnd = MIN_CWND;
        state.phase = CubicPhase::SlowStart;
        state.epoch_start_ms = now_ms;
        state.w_max = 0;
        state.k_scaled = 0;
        state.ack_count = 0;
        state.cwnd_cnt = 0;
        state.hystart.reset();
        Ok(())
    }

    /// Get the current congestion window for a connection.
    pub fn get_cwnd(&self, conn_id: u64) -> Result<u32> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        Ok(self.connections[idx].cwnd)
    }

    /// Get the current ssthresh for a connection.
    pub fn get_ssthresh(&self, conn_id: u64) -> Result<u32> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        Ok(self.connections[idx].ssthresh)
    }

    /// Get the current phase for a connection.
    pub fn get_phase(&self, conn_id: u64) -> Result<CubicPhase> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        Ok(self.connections[idx].phase)
    }

    /// Get full connection state (read-only).
    pub fn get_state(&self, conn_id: u64) -> Result<&CubicState> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        Ok(&self.connections[idx])
    }

    /// Enable or disable HyStart for a connection.
    pub fn set_hystart(&mut self, conn_id: u64, enabled: bool) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        self.connections[idx].hystart.enabled = enabled;
        Ok(())
    }

    /// Enable or disable fast convergence for a connection.
    pub fn set_fast_convergence(&mut self, conn_id: u64, enabled: bool) -> Result<()> {
        let idx = self.find_connection(conn_id).ok_or(Error::NotFound)?;
        self.connections[idx].fast_convergence = enabled;
        Ok(())
    }

    /// Return the total number of active connections.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return total loss events across all connections.
    pub fn total_loss_events(&self) -> u64 {
        self.total_loss_events
    }

    /// Return total ACKs processed.
    pub fn total_acks(&self) -> u64 {
        self.total_acks
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Find a connection by ID.
    fn find_connection(&self, conn_id: u64) -> Option<usize> {
        self.connections
            .iter()
            .position(|c| c.active && c.conn_id == conn_id)
    }
}

// ── Integer cube root ──────────────────────────────────────────────

/// Compute the integer cube root of `val` using Newton's method.
///
/// Returns `x` such that `x^3 <= val < (x+1)^3`.
fn integer_cbrt(val: u64) -> u64 {
    if val == 0 {
        return 0;
    }
    // Initial guess: use bit-length / 3
    let bits = 64 - val.leading_zeros();
    let mut x = 1u64 << ((bits + 2) / 3);

    // Newton's method: x_{n+1} = (2*x_n + val / x_n^2) / 3
    for _ in 0..32 {
        let x2 = x.saturating_mul(x);
        if x2 == 0 {
            break;
        }
        let next = (2 * x + val / x2) / 3;
        if next >= x {
            break;
        }
        x = next;
    }

    // Adjust for rounding
    while x.saturating_mul(x).saturating_mul(x) > val {
        x -= 1;
    }
    x
}

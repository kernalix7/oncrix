// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multipath TCP (MPTCP) protocol implementation.
//!
//! Provides Multipath TCP support per RFC 8684, allowing a single TCP
//! connection to use multiple network paths simultaneously for:
//!
//! - **Path management** ([`MptcpPath`], [`PathManager`]):
//!   tracking and scoring available subflows across interfaces.
//! - **Subflow control** ([`MptcpSubflow`]): individual TCP
//!   subflows with per-path sequence numbers and state machines.
//! - **Data-level sequencing** ([`DataSequenceMap`]):
//!   mapping data sequence numbers (DSN) to subflow sequence
//!   numbers (SSN) for reordering and reassembly.
//! - **Scheduler** ([`MptcpScheduler`]): pluggable scheduling
//!   policies (round-robin, lowest-RTT, redundant).
//! - **Connection state** ([`MptcpConnection`]): full MPTCP
//!   connection tracking with handshake, data transfer, and teardown.
//! - **Global controller** ([`MptcpController`]): manages up
//!   to 64 concurrent MPTCP connections.
//!
//! Reference: Linux `net/mptcp/`, RFC 8684, RFC 6824.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of MPTCP connections.
const MAX_CONNECTIONS: usize = 64;

/// Maximum subflows per connection.
const MAX_SUBFLOWS: usize = 8;

/// Maximum paths tracked per connection.
const MAX_PATHS: usize = 16;

/// Maximum data sequence mapping entries.
const MAX_DSN_MAPPINGS: usize = 256;

/// Maximum receive buffer entries.
const MAX_RECV_ENTRIES: usize = 128;

/// Maximum out-of-order entries.
const MAX_OOO_ENTRIES: usize = 64;

/// Maximum name length for paths.
const MAX_PATH_NAME_LEN: usize = 32;

/// Default subflow priority.
const DEFAULT_PRIORITY: u8 = 1;

/// Maximum RTT for a path to be considered healthy (ms).
const MAX_HEALTHY_RTT_MS: u32 = 5_000;

/// Retransmission timeout multiplier.
const RTO_MULTIPLIER: u32 = 3;

/// Initial smoothed RTT estimate (ms).
const INITIAL_SRTT_MS: u32 = 200;

/// Receive window scale factor.
const WINDOW_SCALE: u32 = 7;

/// Maximum receive window (bytes).
const MAX_RECV_WINDOW: u32 = 1 << (16 + WINDOW_SCALE);

/// MPTCP option kind in TCP header.
const _MPTCP_OPTION_KIND: u8 = 30;

// ── PathState ──────────────────────────────────────────────────────

/// State of a network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is available but not yet validated.
    Available,
    /// Path is validated and usable.
    Established,
    /// Path is degraded (high RTT or packet loss).
    Degraded,
    /// Path has failed and should not be used.
    Failed,
    /// Path is being closed.
    Closing,
}

impl Default for PathState {
    fn default() -> Self {
        Self::Available
    }
}

// ── SubflowState ───────────────────────────────────────────────────

/// State machine for an individual MPTCP subflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubflowState {
    /// Initial state, awaiting MP_JOIN handshake.
    Init,
    /// SYN sent with MP_JOIN option.
    SynSent,
    /// SYN+ACK received, awaiting final ACK.
    SynReceived,
    /// Subflow established and transferring data.
    Established,
    /// FIN sent, awaiting acknowledgment.
    FinWait,
    /// Subflow fully closed.
    Closed,
}

impl Default for SubflowState {
    fn default() -> Self {
        Self::Init
    }
}

// ── ConnectionState ────────────────────────────────────────────────

/// State of an MPTCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection not yet established.
    Init,
    /// MP_CAPABLE handshake in progress.
    Handshake,
    /// Connection established, data transfer active.
    Established,
    /// Connection teardown in progress (DATA_FIN sent).
    Closing,
    /// Connection fully closed.
    Closed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Init
    }
}

// ── SchedulerPolicy ────────────────────────────────────────────────

/// Scheduling policy for distributing data across subflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerPolicy {
    /// Round-robin across all established subflows.
    RoundRobin,
    /// Prefer the subflow with lowest RTT.
    LowestRtt,
    /// Send on all subflows for maximum reliability.
    Redundant,
    /// Weighted scheduling based on subflow capacity.
    Weighted,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self::LowestRtt
    }
}

// ── PathMetrics ────────────────────────────────────────────────────

/// Performance metrics for a network path.
#[derive(Debug, Clone, Copy)]
pub struct PathMetrics {
    /// Smoothed round-trip time (microseconds).
    pub srtt_us: u64,
    /// RTT variance (microseconds).
    pub rttvar_us: u64,
    /// Retransmission timeout (microseconds).
    pub rto_us: u64,
    /// Estimated bandwidth (bytes per second).
    pub bandwidth_bps: u64,
    /// Packet loss rate (per-mille, 0-1000).
    pub loss_rate_permille: u32,
    /// Congestion window (bytes).
    pub cwnd: u32,
    /// Slow-start threshold (bytes).
    pub ssthresh: u32,
    /// Total bytes sent on this path.
    pub bytes_sent: u64,
    /// Total bytes acknowledged.
    pub bytes_acked: u64,
    /// Total retransmissions.
    pub retransmissions: u64,
}

impl PathMetrics {
    /// Create a new set of path metrics with initial estimates.
    pub const fn new() -> Self {
        Self {
            srtt_us: (INITIAL_SRTT_MS as u64) * 1_000,
            rttvar_us: (INITIAL_SRTT_MS as u64) * 500,
            rto_us: (INITIAL_SRTT_MS as u64) * 1_000 * (RTO_MULTIPLIER as u64),
            bandwidth_bps: 0,
            loss_rate_permille: 0,
            cwnd: 10 * 1460, // 10 segments
            ssthresh: u32::MAX,
            bytes_sent: 0,
            bytes_acked: 0,
            retransmissions: 0,
        }
    }

    /// Update RTT estimates using an exponentially-weighted
    /// moving average (RFC 6298 algorithm).
    pub fn update_rtt(&mut self, sample_us: u64) {
        if self.srtt_us == 0 {
            self.srtt_us = sample_us;
            self.rttvar_us = sample_us / 2;
        } else {
            let diff = if sample_us > self.srtt_us {
                sample_us - self.srtt_us
            } else {
                self.srtt_us - sample_us
            };
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
            self.rttvar_us = (self.rttvar_us * 3 + diff) / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R
            self.srtt_us = (self.srtt_us * 7 + sample_us) / 8;
        }
        // RTO = SRTT + max(G, 4 * RTTVAR) where G=1ms
        let four_rttvar = self.rttvar_us * 4;
        let granularity = 1_000u64; // 1ms
        self.rto_us = self.srtt_us + four_rttvar.max(granularity);
    }

    /// Update loss rate based on a window of observations.
    pub fn update_loss(&mut self, lost: u32, total: u32) {
        if total > 0 {
            self.loss_rate_permille = (lost * 1000) / total;
        }
    }

    /// Compute a path quality score (lower is better).
    ///
    /// Combines RTT, loss rate, and bandwidth into a single
    /// metric for scheduling decisions.
    pub fn quality_score(&self) -> u64 {
        let rtt_factor = self.srtt_us / 1_000; // ms
        let loss_factor = self.loss_rate_permille as u64 * 10;
        let bw_factor = if self.bandwidth_bps > 0 {
            1_000_000 / self.bandwidth_bps.min(1_000_000)
        } else {
            1_000
        };
        rtt_factor + loss_factor + bw_factor
    }
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── MptcpPath ──────────────────────────────────────────────────────

/// A network path available for MPTCP subflows.
#[derive(Debug)]
pub struct MptcpPath {
    /// Path identifier (Address ID in MPTCP terms).
    pub addr_id: u8,
    /// Local address (IPv4 as 4 bytes, IPv6 placeholder).
    pub local_addr: [u8; 16],
    /// Remote address.
    pub remote_addr: [u8; 16],
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// Whether addresses are IPv6.
    pub is_ipv6: bool,
    /// Path state.
    pub state: PathState,
    /// Path performance metrics.
    pub metrics: PathMetrics,
    /// Path priority (lower = preferred).
    pub priority: u8,
    /// Human-readable interface name.
    iface_name: [u8; MAX_PATH_NAME_LEN],
    /// Interface name length.
    iface_name_len: usize,
    /// Whether this path entry is in use.
    active: bool,
}

impl MptcpPath {
    /// Create a new empty path.
    pub const fn new() -> Self {
        Self {
            addr_id: 0,
            local_addr: [0u8; 16],
            remote_addr: [0u8; 16],
            local_port: 0,
            remote_port: 0,
            is_ipv6: false,
            state: PathState::Available,
            metrics: PathMetrics::new(),
            priority: DEFAULT_PRIORITY,
            iface_name: [0u8; MAX_PATH_NAME_LEN],
            iface_name_len: 0,
            active: false,
        }
    }

    /// Initialize a path with addresses.
    pub fn init(
        &mut self,
        addr_id: u8,
        local_addr: &[u8],
        remote_addr: &[u8],
        local_port: u16,
        remote_port: u16,
        iface_name: &[u8],
    ) -> Result<()> {
        if local_addr.len() > 16 || remote_addr.len() > 16 {
            return Err(Error::InvalidArgument);
        }
        if iface_name.len() > MAX_PATH_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.addr_id = addr_id;
        self.local_addr[..local_addr.len()].copy_from_slice(local_addr);
        self.remote_addr[..remote_addr.len()].copy_from_slice(remote_addr);
        self.local_port = local_port;
        self.remote_port = remote_port;
        self.is_ipv6 = local_addr.len() == 16;
        self.iface_name[..iface_name.len()].copy_from_slice(iface_name);
        self.iface_name_len = iface_name.len();
        self.state = PathState::Available;
        self.metrics = PathMetrics::new();
        self.active = true;
        Ok(())
    }

    /// Return the interface name.
    pub fn iface_name(&self) -> &[u8] {
        &self.iface_name[..self.iface_name_len]
    }

    /// Whether this path is usable for data transfer.
    pub fn is_usable(&self) -> bool {
        self.active
            && self.state == PathState::Established
            && self.metrics.srtt_us < (MAX_HEALTHY_RTT_MS as u64) * 1_000
    }

    /// Whether this path entry is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Mark the path as failed.
    pub fn mark_failed(&mut self) {
        self.state = PathState::Failed;
    }

    /// Mark the path as established.
    pub fn mark_established(&mut self) {
        self.state = PathState::Established;
    }

    /// Deactivate this path.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.state = PathState::Closing;
    }
}

impl Default for MptcpPath {
    fn default() -> Self {
        Self::new()
    }
}

// ── DsnMapping ─────────────────────────────────────────────────────

/// Maps a data sequence number range to a subflow sequence range.
#[derive(Debug, Clone, Copy)]
pub struct DsnMapping {
    /// Data sequence number (connection-level).
    pub dsn: u64,
    /// Subflow sequence number.
    pub ssn: u32,
    /// Length of the mapping in bytes.
    pub length: u32,
    /// Subflow index this mapping belongs to.
    pub subflow_idx: u8,
    /// Whether this mapping has been acknowledged.
    pub acked: bool,
    /// Whether this entry is in use.
    pub active: bool,
}

impl DsnMapping {
    /// Create an empty mapping.
    pub const fn new() -> Self {
        Self {
            dsn: 0,
            ssn: 0,
            length: 0,
            subflow_idx: 0,
            acked: false,
            active: false,
        }
    }

    /// Check if a DSN falls within this mapping.
    pub fn contains_dsn(&self, dsn: u64) -> bool {
        self.active && dsn >= self.dsn && dsn < self.dsn + self.length as u64
    }

    /// Translate a DSN to the corresponding SSN.
    pub fn dsn_to_ssn(&self, dsn: u64) -> Option<u32> {
        if self.contains_dsn(dsn) {
            let offset = (dsn - self.dsn) as u32;
            Some(self.ssn.wrapping_add(offset))
        } else {
            None
        }
    }
}

impl Default for DsnMapping {
    fn default() -> Self {
        Self::new()
    }
}

// ── DataSequenceMap ────────────────────────────────────────────────

/// Manages DSN-to-SSN mappings for an MPTCP connection.
///
/// Provides ordered insertion, lookup by DSN, and acknowledgment
/// tracking for the data-level sequence space.
pub struct DataSequenceMap {
    /// Mapping entries.
    mappings: [DsnMapping; MAX_DSN_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Next expected DSN for in-order delivery.
    next_dsn: u64,
    /// Highest DSN acknowledged by the remote.
    ack_dsn: u64,
}

impl DataSequenceMap {
    /// Create an empty sequence map.
    pub const fn new() -> Self {
        Self {
            mappings: [const { DsnMapping::new() }; MAX_DSN_MAPPINGS],
            count: 0,
            next_dsn: 0,
            ack_dsn: 0,
        }
    }

    /// Insert a new DSN mapping.
    pub fn insert(&mut self, dsn: u64, ssn: u32, length: u32, subflow_idx: u8) -> Result<()> {
        let slot = self
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        self.mappings[slot] = DsnMapping {
            dsn,
            ssn,
            length,
            subflow_idx,
            acked: false,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Look up the mapping containing the given DSN.
    pub fn lookup(&self, dsn: u64) -> Option<&DsnMapping> {
        self.mappings.iter().find(|m| m.contains_dsn(dsn))
    }

    /// Acknowledge all mappings up to (exclusive) the given DSN.
    pub fn acknowledge(&mut self, dsn: u64) {
        for mapping in &mut self.mappings {
            if mapping.active && mapping.dsn + mapping.length as u64 <= dsn {
                mapping.acked = true;
            }
        }
        if dsn > self.ack_dsn {
            self.ack_dsn = dsn;
        }
    }

    /// Remove acknowledged mappings to free space.
    pub fn gc(&mut self) {
        for mapping in &mut self.mappings {
            if mapping.active && mapping.acked {
                mapping.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the next expected DSN.
    pub fn next_dsn(&self) -> u64 {
        self.next_dsn
    }

    /// Advance the next expected DSN.
    pub fn advance_dsn(&mut self, len: u64) {
        self.next_dsn = self.next_dsn.wrapping_add(len);
    }

    /// Return the highest acknowledged DSN.
    pub fn ack_dsn(&self) -> u64 {
        self.ack_dsn
    }

    /// Return the number of active mappings.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for DataSequenceMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── MptcpSubflow ───────────────────────────────────────────────────

/// An individual TCP subflow within an MPTCP connection.
#[derive(Debug)]
pub struct MptcpSubflow {
    /// Subflow identifier.
    pub id: u8,
    /// Index of the path this subflow uses.
    pub path_idx: u8,
    /// Subflow state machine.
    pub state: SubflowState,
    /// Local subflow sequence number.
    pub local_ssn: u32,
    /// Remote subflow sequence number.
    pub remote_ssn: u32,
    /// Send window (bytes).
    pub snd_wnd: u32,
    /// Receive window (bytes).
    pub rcv_wnd: u32,
    /// Whether this is a backup subflow.
    pub is_backup: bool,
    /// Congestion window (bytes).
    pub cwnd: u32,
    /// Slow-start threshold.
    pub ssthresh: u32,
    /// Bytes in flight (sent but not acknowledged).
    pub bytes_in_flight: u32,
    /// Total bytes sent on this subflow.
    pub total_sent: u64,
    /// Total bytes received on this subflow.
    pub total_received: u64,
    /// Number of retransmissions.
    pub retransmits: u32,
    /// Whether this entry is active.
    active: bool,
}

impl MptcpSubflow {
    /// Create a new empty subflow.
    pub const fn new() -> Self {
        Self {
            id: 0,
            path_idx: 0,
            state: SubflowState::Init,
            local_ssn: 0,
            remote_ssn: 0,
            snd_wnd: MAX_RECV_WINDOW,
            rcv_wnd: MAX_RECV_WINDOW,
            is_backup: false,
            cwnd: 10 * 1460,
            ssthresh: u32::MAX,
            bytes_in_flight: 0,
            total_sent: 0,
            total_received: 0,
            retransmits: 0,
            active: false,
        }
    }

    /// Initialize a subflow.
    pub fn init(&mut self, id: u8, path_idx: u8, initial_ssn: u32) {
        self.id = id;
        self.path_idx = path_idx;
        self.state = SubflowState::Init;
        self.local_ssn = initial_ssn;
        self.remote_ssn = 0;
        self.snd_wnd = MAX_RECV_WINDOW;
        self.rcv_wnd = MAX_RECV_WINDOW;
        self.is_backup = false;
        self.cwnd = 10 * 1460;
        self.ssthresh = u32::MAX;
        self.bytes_in_flight = 0;
        self.total_sent = 0;
        self.total_received = 0;
        self.retransmits = 0;
        self.active = true;
    }

    /// Whether the subflow can accept data for sending.
    pub fn can_send(&self) -> bool {
        self.active && self.state == SubflowState::Established && self.bytes_in_flight < self.cwnd
    }

    /// Record that bytes were sent on this subflow.
    pub fn on_send(&mut self, len: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(len);
        self.total_sent += len as u64;
        self.local_ssn = self.local_ssn.wrapping_add(len);
    }

    /// Record that bytes were acknowledged.
    pub fn on_ack(&mut self, len: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(len);
        // Additive increase for congestion avoidance
        if self.cwnd < self.ssthresh {
            // Slow start: increase by MSS per ACK
            self.cwnd = self.cwnd.saturating_add(1460);
        } else {
            // Congestion avoidance: increase by MSS^2/cwnd
            let inc = (1460u32 * 1460) / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(inc);
        }
    }

    /// Handle a retransmission event.
    pub fn on_retransmit(&mut self) {
        self.retransmits += 1;
        // Multiplicative decrease
        self.ssthresh = (self.cwnd / 2).max(2 * 1460);
        self.cwnd = self.ssthresh;
    }

    /// Record received data.
    pub fn on_receive(&mut self, len: u32) {
        self.total_received += len as u64;
        self.remote_ssn = self.remote_ssn.wrapping_add(len);
    }

    /// Whether this subflow is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Close this subflow.
    pub fn close(&mut self) {
        self.state = SubflowState::FinWait;
    }

    /// Fully deactivate.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.state = SubflowState::Closed;
    }
}

impl Default for MptcpSubflow {
    fn default() -> Self {
        Self::new()
    }
}

// ── MptcpScheduler ─────────────────────────────────────────────────

/// Scheduler that selects which subflow to use for sending data.
pub struct MptcpScheduler {
    /// Current scheduling policy.
    pub policy: SchedulerPolicy,
    /// Round-robin cursor index.
    rr_cursor: u8,
    /// Total segments scheduled.
    pub segments_scheduled: u64,
}

impl MptcpScheduler {
    /// Create a new scheduler with default policy.
    pub const fn new() -> Self {
        Self {
            policy: SchedulerPolicy::LowestRtt,
            rr_cursor: 0,
            segments_scheduled: 0,
        }
    }

    /// Select the next subflow to send on.
    ///
    /// Returns the index of the selected subflow, or `None` if
    /// no subflow is available.
    pub fn select(
        &mut self,
        subflows: &[MptcpSubflow; MAX_SUBFLOWS],
        paths: &[MptcpPath; MAX_PATHS],
    ) -> Option<u8> {
        match self.policy {
            SchedulerPolicy::RoundRobin => self.select_round_robin(subflows),
            SchedulerPolicy::LowestRtt => self.select_lowest_rtt(subflows, paths),
            SchedulerPolicy::Redundant => {
                // For redundant mode, return the first usable
                // (caller sends on all)
                self.select_first_usable(subflows)
            }
            SchedulerPolicy::Weighted => self.select_weighted(subflows, paths),
        }
    }

    /// Round-robin subflow selection.
    fn select_round_robin(&mut self, subflows: &[MptcpSubflow; MAX_SUBFLOWS]) -> Option<u8> {
        let start = self.rr_cursor;
        for i in 0..MAX_SUBFLOWS {
            let idx = ((start as usize + i) % MAX_SUBFLOWS) as u8;
            if subflows[idx as usize].can_send() && !subflows[idx as usize].is_backup {
                self.rr_cursor = idx.wrapping_add(1);
                self.segments_scheduled += 1;
                return Some(idx);
            }
        }
        None
    }

    /// Select subflow with lowest RTT path.
    fn select_lowest_rtt(
        &mut self,
        subflows: &[MptcpSubflow; MAX_SUBFLOWS],
        paths: &[MptcpPath; MAX_PATHS],
    ) -> Option<u8> {
        let mut best_idx: Option<u8> = None;
        let mut best_rtt = u64::MAX;

        for (i, sf) in subflows.iter().enumerate() {
            if !sf.can_send() || sf.is_backup {
                continue;
            }
            let pidx = sf.path_idx as usize;
            if pidx < MAX_PATHS && paths[pidx].is_active() {
                let rtt = paths[pidx].metrics.srtt_us;
                if rtt < best_rtt {
                    best_rtt = rtt;
                    best_idx = Some(i as u8);
                }
            }
        }

        if best_idx.is_some() {
            self.segments_scheduled += 1;
        }
        best_idx
    }

    /// Select first usable subflow.
    fn select_first_usable(&mut self, subflows: &[MptcpSubflow; MAX_SUBFLOWS]) -> Option<u8> {
        for (i, sf) in subflows.iter().enumerate() {
            if sf.can_send() {
                self.segments_scheduled += 1;
                return Some(i as u8);
            }
        }
        None
    }

    /// Weighted selection based on path quality.
    fn select_weighted(
        &mut self,
        subflows: &[MptcpSubflow; MAX_SUBFLOWS],
        paths: &[MptcpPath; MAX_PATHS],
    ) -> Option<u8> {
        let mut best_idx: Option<u8> = None;
        let mut best_score = u64::MAX;

        for (i, sf) in subflows.iter().enumerate() {
            if !sf.can_send() || sf.is_backup {
                continue;
            }
            let pidx = sf.path_idx as usize;
            if pidx < MAX_PATHS && paths[pidx].is_active() {
                let score = paths[pidx].metrics.quality_score();
                if score < best_score {
                    best_score = score;
                    best_idx = Some(i as u8);
                }
            }
        }

        if best_idx.is_some() {
            self.segments_scheduled += 1;
        }
        best_idx
    }
}

impl Default for MptcpScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ── MptcpConnection ────────────────────────────────────────────────

/// A complete MPTCP connection with multiple subflows.
pub struct MptcpConnection {
    /// Connection identifier.
    pub id: u32,
    /// Connection-level state.
    pub state: ConnectionState,
    /// Local key for MP_CAPABLE handshake.
    pub local_key: u64,
    /// Remote key from MP_CAPABLE handshake.
    pub remote_key: u64,
    /// Connection-level data sequence mapping.
    pub dsn_map: DataSequenceMap,
    /// Subflows in this connection.
    pub subflows: [MptcpSubflow; MAX_SUBFLOWS],
    /// Available paths.
    pub paths: [MptcpPath; MAX_PATHS],
    /// Packet scheduler.
    pub scheduler: MptcpScheduler,
    /// Number of active subflows.
    subflow_count: usize,
    /// Number of active paths.
    path_count: usize,
    /// Next subflow ID to assign.
    next_subflow_id: u8,
    /// Whether this connection slot is in use.
    active: bool,
    /// Connection creation timestamp (us since boot).
    created_us: u64,
    /// Total data bytes sent.
    pub total_data_sent: u64,
    /// Total data bytes received.
    pub total_data_received: u64,
}

impl MptcpConnection {
    /// Create a new empty connection.
    pub const fn new() -> Self {
        Self {
            id: 0,
            state: ConnectionState::Init,
            local_key: 0,
            remote_key: 0,
            dsn_map: DataSequenceMap::new(),
            subflows: [const { MptcpSubflow::new() }; MAX_SUBFLOWS],
            paths: [const { MptcpPath::new() }; MAX_PATHS],
            scheduler: MptcpScheduler::new(),
            subflow_count: 0,
            path_count: 0,
            next_subflow_id: 1,
            active: false,
            created_us: 0,
            total_data_sent: 0,
            total_data_received: 0,
        }
    }

    /// Initialize a connection.
    pub fn init(&mut self, id: u32, local_key: u64, now_us: u64) {
        self.id = id;
        self.state = ConnectionState::Handshake;
        self.local_key = local_key;
        self.remote_key = 0;
        self.dsn_map = DataSequenceMap::new();
        self.subflow_count = 0;
        self.path_count = 0;
        self.next_subflow_id = 1;
        self.active = true;
        self.created_us = now_us;
        self.total_data_sent = 0;
        self.total_data_received = 0;
    }

    /// Complete the handshake with the remote key.
    pub fn complete_handshake(&mut self, remote_key: u64) -> Result<()> {
        if self.state != ConnectionState::Handshake {
            return Err(Error::InvalidArgument);
        }
        self.remote_key = remote_key;
        self.state = ConnectionState::Established;
        Ok(())
    }

    /// Add a path to this connection.
    pub fn add_path(
        &mut self,
        addr_id: u8,
        local_addr: &[u8],
        remote_addr: &[u8],
        local_port: u16,
        remote_port: u16,
        iface_name: &[u8],
    ) -> Result<u8> {
        if self.path_count >= MAX_PATHS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .paths
            .iter()
            .position(|p| !p.is_active())
            .ok_or(Error::OutOfMemory)?;
        self.paths[slot].init(
            addr_id,
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            iface_name,
        )?;
        self.path_count += 1;
        Ok(slot as u8)
    }

    /// Add a subflow on a given path.
    pub fn add_subflow(&mut self, path_idx: u8, initial_ssn: u32) -> Result<u8> {
        if self.subflow_count >= MAX_SUBFLOWS {
            return Err(Error::OutOfMemory);
        }
        if path_idx as usize >= MAX_PATHS || !self.paths[path_idx as usize].is_active() {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .subflows
            .iter()
            .position(|s| !s.is_active())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_subflow_id;
        self.next_subflow_id = self.next_subflow_id.wrapping_add(1);
        self.subflows[slot].init(id, path_idx, initial_ssn);
        self.subflow_count += 1;
        Ok(slot as u8)
    }

    /// Establish a subflow after successful MP_JOIN.
    pub fn establish_subflow(&mut self, subflow_idx: u8) -> Result<()> {
        let idx = subflow_idx as usize;
        if idx >= MAX_SUBFLOWS || !self.subflows[idx].is_active() {
            return Err(Error::NotFound);
        }
        self.subflows[idx].state = SubflowState::Established;
        let pidx = self.subflows[idx].path_idx as usize;
        if pidx < MAX_PATHS {
            self.paths[pidx].mark_established();
        }
        Ok(())
    }

    /// Send data on the connection.
    ///
    /// Selects a subflow via the scheduler, creates a DSN mapping,
    /// and returns the selected subflow index.
    pub fn send_data(&mut self, len: u32) -> Result<u8> {
        if self.state != ConnectionState::Established {
            return Err(Error::InvalidArgument);
        }
        let sf_idx = self
            .scheduler
            .select(&self.subflows, &self.paths)
            .ok_or(Error::WouldBlock)?;

        let dsn = self.dsn_map.next_dsn();
        let ssn = self.subflows[sf_idx as usize].local_ssn;

        self.dsn_map.insert(dsn, ssn, len, sf_idx)?;
        self.dsn_map.advance_dsn(len as u64);
        self.subflows[sf_idx as usize].on_send(len);
        self.total_data_sent += len as u64;

        Ok(sf_idx)
    }

    /// Process received data acknowledgment.
    pub fn on_data_ack(&mut self, ack_dsn: u64, subflow_idx: u8, ack_len: u32) -> Result<()> {
        let idx = subflow_idx as usize;
        if idx >= MAX_SUBFLOWS || !self.subflows[idx].is_active() {
            return Err(Error::NotFound);
        }
        self.subflows[idx].on_ack(ack_len);
        self.dsn_map.acknowledge(ack_dsn);
        Ok(())
    }

    /// Process received data.
    pub fn on_data_received(&mut self, subflow_idx: u8, len: u32) -> Result<()> {
        let idx = subflow_idx as usize;
        if idx >= MAX_SUBFLOWS || !self.subflows[idx].is_active() {
            return Err(Error::NotFound);
        }
        self.subflows[idx].on_receive(len);
        self.total_data_received += len as u64;
        Ok(())
    }

    /// Remove a failed subflow.
    pub fn remove_subflow(&mut self, subflow_idx: u8) -> Result<()> {
        let idx = subflow_idx as usize;
        if idx >= MAX_SUBFLOWS || !self.subflows[idx].is_active() {
            return Err(Error::NotFound);
        }
        self.subflows[idx].deactivate();
        self.subflow_count = self.subflow_count.saturating_sub(1);
        Ok(())
    }

    /// Initiate connection close (DATA_FIN).
    pub fn close(&mut self) -> Result<()> {
        if self.state != ConnectionState::Established {
            return Err(Error::InvalidArgument);
        }
        self.state = ConnectionState::Closing;
        for sf in &mut self.subflows {
            if sf.is_active() {
                sf.close();
            }
        }
        Ok(())
    }

    /// Finalize connection teardown.
    pub fn finalize_close(&mut self) {
        self.state = ConnectionState::Closed;
        for sf in &mut self.subflows {
            sf.deactivate();
        }
        for path in &mut self.paths {
            path.deactivate();
        }
        self.active = false;
    }

    /// Return active subflow count.
    pub fn subflow_count(&self) -> usize {
        self.subflow_count
    }

    /// Return active path count.
    pub fn path_count(&self) -> usize {
        self.path_count
    }

    /// Whether this connection is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Perform periodic maintenance (GC, RTT updates).
    pub fn tick(&mut self) {
        self.dsn_map.gc();
    }
}

impl Default for MptcpConnection {
    fn default() -> Self {
        Self::new()
    }
}

// ── MptcpController ────────────────────────────────────────────────

/// System-wide MPTCP connection manager.
///
/// Tracks all active MPTCP connections and provides an interface
/// for creating, looking up, and tearing down connections.
pub struct MptcpController {
    /// All connection slots.
    connections: [MptcpConnection; MAX_CONNECTIONS],
    /// Next connection ID.
    next_id: u32,
    /// Number of active connections.
    active_count: usize,
    /// Total connections created over lifetime.
    total_created: u64,
    /// Total connections closed over lifetime.
    total_closed: u64,
    /// Whether the controller is initialized.
    initialized: bool,
}

impl MptcpController {
    /// Create a new uninitialized controller.
    pub const fn new() -> Self {
        Self {
            connections: [const { MptcpConnection::new() }; MAX_CONNECTIONS],
            next_id: 1,
            active_count: 0,
            total_created: 0,
            total_closed: 0,
            initialized: false,
        }
    }

    /// Initialize the controller.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a new MPTCP connection.
    ///
    /// Returns the connection ID.
    pub fn create_connection(&mut self, local_key: u64, now_us: u64) -> Result<u32> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if self.active_count >= MAX_CONNECTIONS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .connections
            .iter()
            .position(|c| !c.is_active())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.connections[slot].init(id, local_key, now_us);
        self.active_count += 1;
        self.total_created += 1;
        Ok(id)
    }

    /// Look up a connection by ID.
    pub fn get_connection(&self, id: u32) -> Result<&MptcpConnection> {
        self.connections
            .iter()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Look up a mutable connection by ID.
    pub fn get_connection_mut(&mut self, id: u32) -> Result<&mut MptcpConnection> {
        self.connections
            .iter_mut()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Close and destroy a connection.
    pub fn destroy_connection(&mut self, id: u32) -> Result<()> {
        let conn = self
            .connections
            .iter_mut()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)?;
        conn.finalize_close();
        self.active_count = self.active_count.saturating_sub(1);
        self.total_closed += 1;
        Ok(())
    }

    /// Perform periodic maintenance on all connections.
    pub fn tick(&mut self) {
        for conn in &mut self.connections {
            if conn.is_active() {
                conn.tick();
            }
        }
    }

    /// Return the number of active connections.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return total connections created.
    pub fn total_created(&self) -> u64 {
        self.total_created
    }

    /// Return total connections closed.
    pub fn total_closed(&self) -> u64 {
        self.total_closed
    }
}

impl Default for MptcpController {
    fn default() -> Self {
        Self::new()
    }
}

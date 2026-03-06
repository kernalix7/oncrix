// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reclaim throttling and backoff.
//!
//! When direct reclaim cannot make progress, reclaimers must wait
//! rather than spinning. This module implements Linux-style reclaim
//! throttling: each NUMA node has a throttle state that tracks the
//! reason for stalling, a timeout, and a logical wait queue. When
//! progress is made (pages freed, writeback completes), waiting
//! reclaimers are woken.
//!
//! # Throttle Reasons
//!
//! - **Writeback** — dirty pages are under writeback; wait for I/O.
//! - **Isolated** — too many pages are isolated for migration.
//! - **NoProgress** — reclaim scanned but freed nothing.
//! - **Congested** — the backing device is congested.
//!
//! # Key Types
//!
//! - [`ThrottleReason`] — why reclaim is being throttled
//! - [`ThrottleState`] — current throttle lifecycle
//! - [`ThrottleWaiter`] — a reclaimer waiting on a throttle
//! - [`NodeThrottle`] — per-NUMA-node throttle descriptor
//! - [`ThrottleManager`] — top-level manager for all nodes
//! - [`ThrottleStats`] — global throttle statistics
//!
//! Reference: Linux `mm/vmscan.c` (`reclaim_throttle`,
//! `wake_all_throttle_waiters`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum NUMA nodes.
const MAX_NUMA_NODES: usize = 8;

/// Maximum waiters per node.
const MAX_WAITERS_PER_NODE: usize = 64;

/// Default writeback throttle timeout in milliseconds.
const THROTTLE_WRITEBACK_MS: u64 = 100;

/// Default isolated throttle timeout in milliseconds.
const THROTTLE_ISOLATED_MS: u64 = 50;

/// Default no-progress throttle timeout in milliseconds.
const THROTTLE_NOPROGRESS_MS: u64 = 200;

/// Default congestion throttle timeout in milliseconds.
const THROTTLE_CONGESTED_MS: u64 = 100;

/// Maximum consecutive no-progress cycles before OOM escalation.
const MAX_NOPROGRESS_LOOPS: u32 = 16;

// -------------------------------------------------------------------
// ThrottleReason
// -------------------------------------------------------------------

/// Reason reclaim is being throttled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThrottleReason {
    /// Dirty pages are under active writeback.
    #[default]
    Writeback,
    /// Too many pages are isolated for migration/compaction.
    Isolated,
    /// Reclaim scanned pages but made no progress.
    NoProgress,
    /// The backing block device is congested.
    Congested,
}

impl ThrottleReason {
    /// Returns the default timeout in milliseconds for this reason.
    pub fn default_timeout_ms(self) -> u64 {
        match self {
            Self::Writeback => THROTTLE_WRITEBACK_MS,
            Self::Isolated => THROTTLE_ISOLATED_MS,
            Self::NoProgress => THROTTLE_NOPROGRESS_MS,
            Self::Congested => THROTTLE_CONGESTED_MS,
        }
    }
}

// -------------------------------------------------------------------
// ThrottleState
// -------------------------------------------------------------------

/// Lifecycle state of a throttle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThrottleState {
    /// No throttling in effect.
    #[default]
    Idle,
    /// Reclaimers are throttled and waiting.
    Throttled,
    /// Wake-up has been signalled; waiters are being released.
    Waking,
}

// -------------------------------------------------------------------
// ThrottleWaiter
// -------------------------------------------------------------------

/// A reclaimer task waiting on a throttle.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleWaiter {
    /// Identifier for the waiting task (e.g., thread/process ID).
    pub task_id: u64,
    /// Reason this task is waiting.
    pub reason: ThrottleReason,
    /// Timestamp (in ms) when the wait started.
    pub wait_start_ms: u64,
    /// Timeout duration in ms.
    pub timeout_ms: u64,
    /// Whether this waiter has been woken.
    pub woken: bool,
}

impl Default for ThrottleWaiter {
    fn default() -> Self {
        Self {
            task_id: 0,
            reason: ThrottleReason::Writeback,
            wait_start_ms: 0,
            timeout_ms: 0,
            woken: false,
        }
    }
}

impl ThrottleWaiter {
    /// Returns true if this waiter has timed out.
    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        now_ms >= self.wait_start_ms + self.timeout_ms
    }
}

// -------------------------------------------------------------------
// NodeThrottle
// -------------------------------------------------------------------

/// Per-NUMA-node throttle state.
///
/// Each node tracks its own throttle independently because reclaim
/// pressure is often node-local.
#[derive(Debug)]
pub struct NodeThrottle {
    /// NUMA node identifier.
    pub node_id: u8,
    /// Current throttle state.
    pub state: ThrottleState,
    /// Active throttle reason (valid when state != Idle).
    pub reason: ThrottleReason,
    /// Waiters on this node.
    waiters: [ThrottleWaiter; MAX_WAITERS_PER_NODE],
    /// Number of active waiters.
    nr_waiters: usize,
    /// Consecutive no-progress cycles.
    noprogress_loops: u32,
    /// Total times this node entered throttled state.
    throttle_count: u64,
    /// Total waiters that were woken on this node.
    wake_count: u64,
    /// Total waiters that timed out on this node.
    timeout_count: u64,
}

impl NodeThrottle {
    /// Creates a new idle throttle for a node.
    pub fn new(node_id: u8) -> Self {
        Self {
            node_id,
            state: ThrottleState::Idle,
            reason: ThrottleReason::Writeback,
            waiters: [const {
                ThrottleWaiter {
                    task_id: 0,
                    reason: ThrottleReason::Writeback,
                    wait_start_ms: 0,
                    timeout_ms: 0,
                    woken: false,
                }
            }; MAX_WAITERS_PER_NODE],
            nr_waiters: 0,
            noprogress_loops: 0,
            throttle_count: 0,
            wake_count: 0,
            timeout_count: 0,
        }
    }

    /// Returns the number of active waiters.
    pub fn waiter_count(&self) -> usize {
        self.nr_waiters
    }

    /// Returns the consecutive no-progress loop count.
    pub fn noprogress_loops(&self) -> u32 {
        self.noprogress_loops
    }

    /// Returns true if this node has exceeded the maximum
    /// no-progress loops (suggesting OOM escalation).
    pub fn should_oom(&self) -> bool {
        self.noprogress_loops >= MAX_NOPROGRESS_LOOPS
    }

    /// Adds a waiter to this node's throttle.
    fn add_waiter(&mut self, task_id: u64, reason: ThrottleReason, now_ms: u64) -> Result<()> {
        if self.nr_waiters >= MAX_WAITERS_PER_NODE {
            return Err(Error::Busy);
        }
        self.waiters[self.nr_waiters] = ThrottleWaiter {
            task_id,
            reason,
            wait_start_ms: now_ms,
            timeout_ms: reason.default_timeout_ms(),
            woken: false,
        };
        self.nr_waiters += 1;
        Ok(())
    }

    /// Wakes all waiters on this node.
    fn wake_all(&mut self) -> usize {
        let mut woken = 0usize;
        for i in 0..self.nr_waiters {
            if !self.waiters[i].woken {
                self.waiters[i].woken = true;
                woken += 1;
            }
        }
        self.wake_count += woken as u64;
        self.nr_waiters = 0;
        self.state = ThrottleState::Idle;
        woken
    }

    /// Expires waiters that have timed out.
    fn expire_timeouts(&mut self, now_ms: u64) -> usize {
        let mut expired = 0usize;
        let mut write_idx = 0usize;
        for read_idx in 0..self.nr_waiters {
            if self.waiters[read_idx].is_timed_out(now_ms) {
                expired += 1;
                self.timeout_count += 1;
            } else {
                self.waiters[write_idx] = self.waiters[read_idx];
                write_idx += 1;
            }
        }
        self.nr_waiters = write_idx;
        if self.nr_waiters == 0 {
            self.state = ThrottleState::Idle;
        }
        expired
    }
}

// -------------------------------------------------------------------
// ThrottleStats
// -------------------------------------------------------------------

/// Global throttle statistics across all nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThrottleStats {
    /// Total throttle activations.
    pub total_throttles: u64,
    /// Total waiters enqueued.
    pub total_waiters: u64,
    /// Total waiters woken by progress.
    pub total_wakes: u64,
    /// Total waiters that timed out.
    pub total_timeouts: u64,
    /// Throttles due to writeback.
    pub writeback_throttles: u64,
    /// Throttles due to isolation.
    pub isolated_throttles: u64,
    /// Throttles due to no-progress.
    pub noprogress_throttles: u64,
    /// Throttles due to congestion.
    pub congested_throttles: u64,
    /// Times OOM escalation was suggested.
    pub oom_suggestions: u64,
}

// -------------------------------------------------------------------
// ThrottleManager
// -------------------------------------------------------------------

/// Top-level reclaim throttle manager for all NUMA nodes.
///
/// Coordinates per-node throttle states, processes waiter timeouts,
/// and handles wake-on-progress notifications.
pub struct ThrottleManager {
    /// Per-node throttle states.
    nodes: [NodeThrottle; MAX_NUMA_NODES],
    /// Number of active nodes.
    nr_nodes: usize,
    /// Global statistics.
    stats: ThrottleStats,
}

impl ThrottleManager {
    /// Creates a new throttle manager with `nr_nodes` NUMA nodes.
    pub fn new(nr_nodes: usize) -> Result<Self> {
        if nr_nodes > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        let mut nodes = [const {
            NodeThrottle {
                node_id: 0,
                state: ThrottleState::Idle,
                reason: ThrottleReason::Writeback,
                waiters: [ThrottleWaiter {
                    task_id: 0,
                    reason: ThrottleReason::Writeback,
                    wait_start_ms: 0,
                    timeout_ms: 0,
                    woken: false,
                }; MAX_WAITERS_PER_NODE],
                nr_waiters: 0,
                noprogress_loops: 0,
                throttle_count: 0,
                wake_count: 0,
                timeout_count: 0,
            }
        }; MAX_NUMA_NODES];
        for i in 0..nr_nodes {
            nodes[i] = NodeThrottle::new(i as u8);
        }
        Ok(Self {
            nodes,
            nr_nodes,
            stats: ThrottleStats::default(),
        })
    }

    /// Returns global statistics.
    pub fn stats(&self) -> &ThrottleStats {
        &self.stats
    }

    /// Returns per-node throttle state.
    pub fn node_throttle(&self, node_id: usize) -> Result<&NodeThrottle> {
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[node_id])
    }

    /// Throttles a reclaimer on a given node.
    ///
    /// The reclaimer is added to the node's wait queue and will be
    /// woken when progress is made or the timeout expires.
    pub fn throttle(
        &mut self,
        node_id: usize,
        task_id: u64,
        reason: ThrottleReason,
        now_ms: u64,
    ) -> Result<()> {
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }

        self.nodes[node_id].add_waiter(task_id, reason, now_ms)?;
        self.nodes[node_id].state = ThrottleState::Throttled;
        self.nodes[node_id].reason = reason;
        self.nodes[node_id].throttle_count += 1;

        if reason == ThrottleReason::NoProgress {
            self.nodes[node_id].noprogress_loops += 1;
        }

        self.stats.total_throttles += 1;
        self.stats.total_waiters += 1;
        match reason {
            ThrottleReason::Writeback => {
                self.stats.writeback_throttles += 1;
            }
            ThrottleReason::Isolated => {
                self.stats.isolated_throttles += 1;
            }
            ThrottleReason::NoProgress => {
                self.stats.noprogress_throttles += 1;
            }
            ThrottleReason::Congested => {
                self.stats.congested_throttles += 1;
            }
        }

        Ok(())
    }

    /// Signals progress on a node, waking all throttled reclaimers.
    ///
    /// Called when pages are freed, writeback completes, or
    /// congestion clears.
    pub fn wake_on_progress(&mut self, node_id: usize) -> Result<usize> {
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        if self.nodes[node_id].state != ThrottleState::Throttled {
            return Ok(0);
        }
        self.nodes[node_id].state = ThrottleState::Waking;
        self.nodes[node_id].noprogress_loops = 0;
        let woken = self.nodes[node_id].wake_all();
        self.stats.total_wakes += woken as u64;
        Ok(woken)
    }

    /// Processes timeout expiry for all nodes.
    ///
    /// Should be called periodically (e.g., from a timer tick).
    /// Returns the total number of waiters that timed out.
    pub fn process_timeouts(&mut self, now_ms: u64) -> u64 {
        let mut total_expired = 0u64;
        for i in 0..self.nr_nodes {
            if self.nodes[i].state == ThrottleState::Throttled {
                let expired = self.nodes[i].expire_timeouts(now_ms);
                total_expired += expired as u64;
            }
        }
        self.stats.total_timeouts += total_expired;
        total_expired
    }

    /// Checks if any node suggests OOM escalation.
    ///
    /// Returns the node ID if OOM should be triggered, or `None`.
    pub fn check_oom_suggestion(&mut self) -> Option<usize> {
        for i in 0..self.nr_nodes {
            if self.nodes[i].should_oom() {
                self.stats.oom_suggestions += 1;
                return Some(i);
            }
        }
        None
    }

    /// Resets the no-progress loop counter for a node.
    ///
    /// Called after successful reclaim or OOM kill.
    pub fn reset_noprogress(&mut self, node_id: usize) -> Result<()> {
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        self.nodes[node_id].noprogress_loops = 0;
        Ok(())
    }

    /// Returns the total number of throttled waiters across all
    /// nodes.
    pub fn total_waiters(&self) -> usize {
        let mut total = 0usize;
        for i in 0..self.nr_nodes {
            total += self.nodes[i].waiter_count();
        }
        total
    }

    /// Returns the number of nodes currently in throttled state.
    pub fn throttled_node_count(&self) -> usize {
        let mut count = 0usize;
        for i in 0..self.nr_nodes {
            if self.nodes[i].state == ThrottleState::Throttled {
                count += 1;
            }
        }
        count
    }
}

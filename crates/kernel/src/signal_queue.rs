// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Signal queue — pending signal management per task.
//!
//! Each task has a queue of pending signals. Standard signals
//! (1-31) are coalesced (only one pending per signal number),
//! while real-time signals (32-64) are queued (multiple instances
//! can be pending).
//!
//! # Architecture
//!
//! ```text
//! SignalQueueManager
//!  ├── queues[MAX_TASKS]
//!  │    ├── pending_mask: u64
//!  │    ├── rt_queue[MAX_RT_QUEUED]
//!  │    └── info per signal (siginfo)
//!  └── stats: SignalQueueStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/signal.c` — signal queueing logic.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum tasks with signal queues.
const MAX_TASKS: usize = 256;

/// Maximum queued RT signals per task.
const MAX_RT_QUEUED: usize = 64;

/// Standard signals range: 1-31.
const STD_SIGNAL_MAX: u32 = 31;

/// RT signals start at 32.
const RT_SIGNAL_MIN: u32 = 32;

/// Maximum signal number.
const SIGNAL_MAX: u32 = 64;

// ══════════════════════════════════════════════════════════════
// SigInfo — signal metadata
// ══════════════════════════════════════════════════════════════

/// Metadata accompanying a queued signal.
#[derive(Debug, Clone, Copy)]
pub struct SigInfo {
    /// Signal number.
    pub signo: u32,
    /// Error number (errno).
    pub errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.).
    pub code: i32,
    /// Sender PID.
    pub sender_pid: u64,
    /// Sender UID.
    pub sender_uid: u32,
    /// Signal value (for sigqueue / RT signals).
    pub value: u64,
    /// Whether this entry is used.
    pub active: bool,
}

impl SigInfo {
    /// Create an inactive siginfo.
    const fn empty() -> Self {
        Self {
            signo: 0,
            errno: 0,
            code: 0,
            sender_pid: 0,
            sender_uid: 0,
            value: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskSignalQueue
// ══════════════════════════════════════════════════════════════

/// Per-task signal queue.
pub struct TaskSignalQueue {
    /// Task identifier.
    pub task_id: u64,
    /// Bitmask of pending signals (bit N = signal N).
    pub pending_mask: u64,
    /// Bitmask of blocked signals.
    pub blocked_mask: u64,
    /// Real-time signal queue.
    rt_queue: [SigInfo; MAX_RT_QUEUED],
    /// Number of queued RT signals.
    pub rt_queued: u32,
    /// Total signals delivered.
    pub delivered: u64,
    /// Total signals dropped (queue full).
    pub dropped: u64,
    /// Whether this queue is active.
    pub active: bool,
}

impl TaskSignalQueue {
    /// Create an inactive queue.
    const fn new() -> Self {
        Self {
            task_id: 0,
            pending_mask: 0,
            blocked_mask: 0,
            rt_queue: [const { SigInfo::empty() }; MAX_RT_QUEUED],
            rt_queued: 0,
            delivered: 0,
            dropped: 0,
            active: false,
        }
    }

    /// Check if a signal is pending.
    pub fn is_pending(&self, signo: u32) -> bool {
        signo > 0 && signo <= SIGNAL_MAX && (self.pending_mask & (1u64 << signo)) != 0
    }

    /// Check if a signal is blocked.
    pub fn is_blocked(&self, signo: u32) -> bool {
        signo > 0 && signo <= SIGNAL_MAX && (self.blocked_mask & (1u64 << signo)) != 0
    }
}

// ══════════════════════════════════════════════════════════════
// SignalQueueStats
// ══════════════════════════════════════════════════════════════

/// Signal queue subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct SignalQueueStats {
    /// Total signals queued.
    pub total_queued: u64,
    /// Total signals delivered.
    pub total_delivered: u64,
    /// Total signals dropped.
    pub total_dropped: u64,
    /// Total RT signals queued.
    pub total_rt_queued: u64,
}

impl SignalQueueStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_queued: 0,
            total_delivered: 0,
            total_dropped: 0,
            total_rt_queued: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SignalQueueManager
// ══════════════════════════════════════════════════════════════

/// Manages per-task signal queues.
pub struct SignalQueueManager {
    /// Per-task queues.
    queues: [TaskSignalQueue; MAX_TASKS],
    /// Statistics.
    stats: SignalQueueStats,
}

impl SignalQueueManager {
    /// Create a new signal queue manager.
    pub const fn new() -> Self {
        Self {
            queues: [const { TaskSignalQueue::new() }; MAX_TASKS],
            stats: SignalQueueStats::new(),
        }
    }

    /// Allocate a signal queue for a task.
    pub fn alloc_queue(&mut self, task_id: u64) -> Result<usize> {
        let slot = self
            .queues
            .iter()
            .position(|q| !q.active)
            .ok_or(Error::OutOfMemory)?;
        self.queues[slot].task_id = task_id;
        self.queues[slot].active = true;
        Ok(slot)
    }

    /// Free a signal queue.
    pub fn free_queue(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_TASKS {
            return Err(Error::InvalidArgument);
        }
        self.queues[slot] = TaskSignalQueue::new();
        Ok(())
    }

    /// Send a signal to a task.
    ///
    /// Standard signals are coalesced. RT signals are queued.
    pub fn send_signal(&mut self, slot: usize, info: SigInfo) -> Result<()> {
        if slot >= MAX_TASKS || !self.queues[slot].active {
            return Err(Error::InvalidArgument);
        }
        let signo = info.signo;
        if signo == 0 || signo > SIGNAL_MAX {
            return Err(Error::InvalidArgument);
        }

        let queue = &mut self.queues[slot];

        if signo <= STD_SIGNAL_MAX {
            // Standard signal: set the bit (coalesce).
            queue.pending_mask |= 1u64 << signo;
            self.stats.total_queued += 1;
        } else if signo >= RT_SIGNAL_MIN {
            // RT signal: queue the siginfo.
            let rt_slot = queue.rt_queue.iter().position(|s| !s.active);
            match rt_slot {
                Some(idx) => {
                    queue.rt_queue[idx] = info;
                    queue.rt_queue[idx].active = true;
                    queue.rt_queued += 1;
                    queue.pending_mask |= 1u64 << signo;
                    self.stats.total_queued += 1;
                    self.stats.total_rt_queued += 1;
                }
                None => {
                    queue.dropped += 1;
                    self.stats.total_dropped += 1;
                    return Err(Error::OutOfMemory);
                }
            }
        }
        Ok(())
    }

    /// Dequeue the next deliverable signal (not blocked).
    ///
    /// Returns the signal number and optional siginfo for RT.
    pub fn dequeue_signal(&mut self, slot: usize) -> Result<Option<(u32, Option<SigInfo>)>> {
        if slot >= MAX_TASKS || !self.queues[slot].active {
            return Err(Error::InvalidArgument);
        }
        let queue = &mut self.queues[slot];
        let deliverable = queue.pending_mask & !queue.blocked_mask;
        if deliverable == 0 {
            return Ok(None);
        }
        // Find lowest set bit.
        let signo = deliverable.trailing_zeros();
        if signo == 0 || signo > SIGNAL_MAX {
            return Ok(None);
        }

        // Clear the pending bit.
        queue.pending_mask &= !(1u64 << signo);
        queue.delivered += 1;
        self.stats.total_delivered += 1;

        if signo >= RT_SIGNAL_MIN {
            // Find and dequeue the RT siginfo.
            if let Some(idx) = queue
                .rt_queue
                .iter()
                .position(|s| s.active && s.signo == signo)
            {
                let info = queue.rt_queue[idx];
                queue.rt_queue[idx] = SigInfo::empty();
                queue.rt_queued = queue.rt_queued.saturating_sub(1);
                // Re-check if more of the same RT signal are queued.
                if queue.rt_queue.iter().any(|s| s.active && s.signo == signo) {
                    queue.pending_mask |= 1u64 << signo;
                }
                return Ok(Some((signo, Some(info))));
            }
        }
        Ok(Some((signo, None)))
    }

    /// Set the blocked signal mask for a task.
    pub fn set_blocked(&mut self, slot: usize, mask: u64) -> Result<()> {
        if slot >= MAX_TASKS || !self.queues[slot].active {
            return Err(Error::InvalidArgument);
        }
        // SIGKILL (9) and SIGSTOP (19) cannot be blocked.
        let sanitised = mask & !((1u64 << 9) | (1u64 << 19));
        self.queues[slot].blocked_mask = sanitised;
        Ok(())
    }

    /// Return queue info for a task.
    pub fn get_queue(&self, slot: usize) -> Result<&TaskSignalQueue> {
        if slot >= MAX_TASKS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.queues[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> SignalQueueStats {
        self.stats
    }
}

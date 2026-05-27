// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Priority-aware round-robin scheduler with credit aging.
//!
//! The scheduler keeps a fixed-size array of thread slots and a cursor
//! for round-robin fairness. On top of plain round-robin it consumes
//! [`Thread::priority`](crate::thread::Thread::priority) through a
//! lightweight **credit / aging** scheme so higher-priority (lower
//! nice) threads run preferentially without starving low-priority ones:
//!
//! * Each Ready thread carries an integer `sched_credit`.
//! * On every pick pass, every *Ready* thread earns credit equal to its
//!   [`Priority::weight`](crate::thread::Priority::weight) (`256 - level`,
//!   so HIGHEST earns 256/pass, IDLE earns 1/pass).
//! * The Ready thread with the **most accumulated credit** is selected;
//!   ties break by round-robin cursor order (the first such thread the
//!   scan reaches), preserving fairness among equal-priority peers.
//! * The picked thread's credit is reset to zero, so it must re-earn its
//!   way back to the front.
//!
//! Because every weight is `>= 1`, a low-priority thread's credit only
//! ever grows while it waits and is guaranteed to eventually exceed any
//! repeatedly-reset high-priority thread — this is the anti-starvation
//! (aging) guarantee. Credit uses saturating arithmetic so a long wait
//! cannot overflow.
//!
//! This is intentionally conservative: the ring scan, slot layout, and
//! the `current`/`cursor` bookkeeping are unchanged from the original
//! round-robin picker — only the *selection rule* within the Ready set
//! is upgraded, which keeps the context-switch datapath identical.

use crate::context::CpuContext;
use crate::pid::Tid;
use crate::thread::{Thread, ThreadState};
use oncrix_lib::{Error, Result};

/// Maximum number of threads the scheduler can manage.
const MAX_THREADS: usize = 256;

/// Information needed by the architecture-specific context switch.
///
/// Returned by [`RoundRobinScheduler::prepare_switch`]. Consumers
/// (the kernel's scheduler glue) must treat `prev_ctx`/`next_ctx`
/// as raw pointers that live until the next scheduler mutation,
/// and must update `TSS.RSP0` to `next_kstack_top` (if non-zero)
/// before running the switch.
pub struct SwitchTargets {
    /// Destination for the outgoing thread's register save.
    pub prev_ctx: *mut CpuContext,
    /// Source of the incoming thread's register state.
    pub next_ctx: *const CpuContext,
    /// Kernel-stack top to install into `TSS.RSP0` (0 = keep global).
    pub next_kstack_top: u64,
    /// TID of the selected successor (for bookkeeping / tracing).
    pub next_tid: Option<Tid>,
}

/// Round-robin scheduler.
///
/// Maintains a fixed-size array of thread slots and a cursor pointing
/// to the next candidate. Scheduling is O(N) worst-case per pick,
/// where N = MAX_THREADS.
pub struct RoundRobinScheduler {
    /// Thread slots (None = empty).
    threads: [Option<Thread>; MAX_THREADS],
    /// Number of threads currently registered.
    count: usize,
    /// Index of the currently running thread (None if idle).
    current: Option<usize>,
    /// Cursor for round-robin scanning.
    cursor: usize,
}

impl Default for RoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinScheduler {
    /// Create a new empty scheduler.
    pub const fn new() -> Self {
        // SAFETY: Option<Thread> is None when zero-initialized for
        // types without non-zero requirements, but we use explicit
        // None initialization via const array.
        const NONE: Option<Thread> = None;
        Self {
            threads: [NONE; MAX_THREADS],
            count: 0,
            current: None,
            cursor: 0,
        }
    }

    /// Select the next Ready slot using priority credit + aging.
    ///
    /// Scans the ring starting at `start` (wrapping), and over the
    /// candidates it considers (every slot except `exclude`):
    ///
    /// 1. Grants each *Ready* candidate credit equal to its priority
    ///    [`weight`](crate::thread::Priority::weight) for this pass.
    /// 2. Tracks the Ready candidate with the highest resulting credit;
    ///    ties keep the earliest-scanned slot (round-robin tie-break).
    ///
    /// Returns the chosen slot index, or `None` if no candidate is
    /// Ready. The caller is responsible for the state transition and for
    /// calling [`Thread::reset_sched_credit`] on the winner. Aging is
    /// applied to *all* Ready candidates (including the winner) so the
    /// winner's pre-reset credit reflects this pass; the reset then
    /// clears it.
    ///
    /// `O(MAX_THREADS)` — same scan cost as the original picker.
    fn select_ready(&mut self, start: usize, exclude: Option<usize>) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_credit: u32 = 0;
        for offset in 0..MAX_THREADS {
            let idx = (start + offset) % MAX_THREADS;
            if exclude == Some(idx) {
                continue;
            }
            if let Some(t) = self.threads[idx].as_mut()
                && t.state() == ThreadState::Ready
            {
                t.add_sched_credit(t.priority().weight());
                let credit = t.sched_credit();
                // Strictly-greater keeps the earliest slot on ties,
                // which is the round-robin order of the scan.
                if best.is_none() || credit > best_credit {
                    best = Some(idx);
                    best_credit = credit;
                }
            }
        }
        best
    }

    /// Add a thread to the scheduler.
    ///
    /// The thread must be in the `Ready` state.
    pub fn add(&mut self, thread: Thread) -> Result<()> {
        if thread.state() != ThreadState::Ready {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_THREADS {
            return Err(Error::OutOfMemory);
        }

        // Find first empty slot.
        for slot in self.threads.iter_mut() {
            if slot.is_none() {
                *slot = Some(thread);
                self.count += 1;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Remove a thread by TID.
    ///
    /// Returns the removed thread, or `Err` if not found.
    pub fn remove(&mut self, tid: Tid) -> Result<Thread> {
        for (i, slot) in self.threads.iter_mut().enumerate() {
            if let Some(t) = slot.as_ref() {
                if t.tid() == tid {
                    let thread = slot.take().ok_or(Error::NotFound)?;
                    self.count -= 1;
                    // If we removed the current thread, clear it.
                    if self.current == Some(i) {
                        self.current = None;
                    }
                    return Ok(thread);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Pick the next ready thread to run (round-robin).
    ///
    /// If a thread is currently running, it is moved back to `Ready`.
    /// The next `Ready` thread in circular order is moved to `Running`.
    ///
    /// Returns the TID of the newly scheduled thread, or `None` if
    /// no threads are ready.
    pub fn schedule(&mut self) -> Option<Tid> {
        // Move current thread back to Ready.
        if let Some(idx) = self.current {
            if let Some(ref mut t) = self.threads[idx] {
                if t.state() == ThreadState::Running {
                    t.set_state(ThreadState::Ready);
                }
            }
            self.current = None;
        }

        // Pick the highest-credit Ready thread starting from the cursor
        // (priority-aware, with aging). See module docs.
        let start = self.cursor % MAX_THREADS;
        let idx = self.select_ready(start, None)?;
        if let Some(ref mut t) = self.threads[idx] {
            t.set_state(ThreadState::Running);
            t.reset_sched_credit();
            self.current = Some(idx);
            self.cursor = (idx + 1) % MAX_THREADS;
            return Some(t.tid());
        }
        None
    }

    /// Get the currently running thread's TID.
    pub fn current_tid(&self) -> Option<Tid> {
        self.current
            .and_then(|idx| self.threads[idx].as_ref())
            .map(|t| t.tid())
    }

    /// Get a reference to a thread by TID.
    pub fn get(&self, tid: Tid) -> Option<&Thread> {
        self.threads
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|t| t.tid() == tid)
    }

    /// Get a mutable reference to a thread by TID.
    pub fn get_mut(&mut self, tid: Tid) -> Option<&mut Thread> {
        self.threads
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|t| t.tid() == tid)
    }

    /// Iterate every slot mutably (occupied or empty).
    ///
    /// Used by the kernel's wait4 reaper to locate a thread by PID
    /// (rather than TID) and release its [`UserAddressSpace`] before
    /// the slot is removed.
    pub fn threads_iter_mut(&mut self) -> core::slice::IterMut<'_, Option<Thread>> {
        self.threads.iter_mut()
    }

    /// Return a reference to the currently running thread, if any.
    ///
    /// Consumed by the kernel's `current_thread()` accessor. Single-
    /// CPU assumption: the caller holds the usual interrupts-off /
    /// syscall-context invariant that rules out concurrent mutation.
    pub fn current(&self) -> Option<&Thread> {
        self.current.and_then(|idx| self.threads[idx].as_ref())
    }

    /// Return a mutable reference to the currently running thread.
    pub fn current_mut(&mut self) -> Option<&mut Thread> {
        self.current.and_then(|idx| self.threads[idx].as_mut())
    }

    /// Return the kernel-stack top of the currently running thread.
    ///
    /// Returns `None` if no thread is selected or if the current
    /// thread uses the global bootstrap stack (top == 0).
    pub fn current_kernel_stack_top(&self) -> Option<u64> {
        let top = self.current()?.kernel_stack_top();
        if top == 0 { None } else { Some(top) }
    }

    /// Pick a context-switch target by advancing the round-robin
    /// cursor without changing the `current` pointer first.
    ///
    /// Returns `(prev_ctx_ptr, next_ctx_ptr)` raw pointers suitable
    /// for the architecture-specific context switch routine, plus
    /// the next thread's kernel-stack top (for `TSS.RSP0`). The
    /// caller is responsible for invoking the arch switch with
    /// interrupts disabled.
    ///
    /// Returns `None` if the scheduler has no runnable thread
    /// besides the current one.
    pub fn prepare_switch(&mut self) -> Option<SwitchTargets> {
        let prev_idx = self.current?;
        // Move prev: Running -> Ready (if still Running) BEFORE selecting,
        // so the outgoing thread is a candidate for re-selection and its
        // priority credit is aged alongside its peers.
        if let Some(prev) = self.threads[prev_idx].as_mut()
            && prev.state() == ThreadState::Running
        {
            prev.set_state(ThreadState::Ready);
        }

        // Pick the highest-credit Ready thread (priority-aware, aging),
        // excluding the just-descheduled `prev_idx` so a switch always
        // makes forward progress when another runnable thread exists.
        // Start the scan after `prev_idx` for round-robin tie-breaking.
        let start = (prev_idx + 1) % MAX_THREADS;
        let next_idx = match self.select_ready(start, Some(prev_idx)) {
            Some(idx) => idx,
            None => {
                // No other runnable thread: restore prev to Running and
                // report "nothing to switch to".
                if let Some(prev) = self.threads[prev_idx].as_mut() {
                    prev.set_state(ThreadState::Running);
                }
                return None;
            }
        };

        // Move next: Ready -> Running and reset its earned credit.
        if let Some(next) = self.threads[next_idx].as_mut() {
            next.set_state(ThreadState::Running);
            next.reset_sched_credit();
        }

        // Extract raw pointers and the kstack top. We intentionally
        // use raw pointers so the caller can pass them to the arch
        // switch without holding a `&mut self` borrow.
        let prev_ctx = self.threads[prev_idx]
            .as_mut()
            .map(|t| t.cpu_context_mut() as *mut CpuContext)
            .unwrap_or(core::ptr::null_mut());
        let next_ctx = self.threads[next_idx]
            .as_ref()
            .map(|t| t.cpu_context() as *const CpuContext)
            .unwrap_or(core::ptr::null());
        let next_kstack_top = self.threads[next_idx]
            .as_ref()
            .map(|t| t.kernel_stack_top())
            .unwrap_or(0);
        let next_tid = self.threads[next_idx].as_ref().map(|t| t.tid());

        self.current = Some(next_idx);
        self.cursor = (next_idx + 1) % MAX_THREADS;

        Some(SwitchTargets {
            prev_ctx,
            next_ctx,
            next_kstack_top,
            next_tid,
        })
    }

    /// Block the currently running thread (e.g., waiting for IPC).
    ///
    /// The blocked thread will not be picked by `schedule()` until
    /// it is explicitly unblocked.
    pub fn block_current(&mut self) -> Result<()> {
        let idx = self.current.ok_or(Error::NotFound)?;
        if let Some(ref mut t) = self.threads[idx] {
            t.set_state(ThreadState::Blocked);
        }
        self.current = None;
        Ok(())
    }

    /// Unblock a thread by TID, moving it to `Ready`.
    pub fn unblock(&mut self, tid: Tid) -> Result<()> {
        let thread = self.get_mut(tid).ok_or(Error::NotFound)?;
        if thread.state() != ThreadState::Blocked {
            return Err(Error::InvalidArgument);
        }
        thread.set_state(ThreadState::Ready);
        Ok(())
    }

    /// Return the total number of registered threads.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the number of ready threads.
    pub fn ready_count(&self) -> usize {
        self.threads
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|t| t.state() == ThreadState::Ready)
            .count()
    }
}

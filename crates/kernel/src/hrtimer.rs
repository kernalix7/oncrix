// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! High-resolution timer (hrtimer) framework.
//!
//! Implements a monotonic timer queue backed by a min-heap. Timers fire
//! when the system monotonic clock reaches their expiry time. Callbacks
//! return a `TimerRestart` value indicating whether to re-arm.
//!
//! Clock bases:
//! - `Monotonic` — never goes backward; based on `CLOCK_MONOTONIC`
//! - `Realtime` — wall clock; can jump on NTP adjustments
//! - `Boottime` — includes time spent in suspend
//! - `TaiTime` — International Atomic Time (leap-second free)

use core::sync::atomic::{AtomicU64, Ordering};

use oncrix_lib::{Error, Result};

/// Maximum timers in the heap per clock base.
pub const HRTIMER_MAX_TIMERS: usize = 256;

/// Clock base identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HrClockBase {
    /// `CLOCK_MONOTONIC` — monotonically increasing.
    Monotonic = 0,
    /// `CLOCK_REALTIME` — wall clock, can leap.
    Realtime = 1,
    /// `CLOCK_BOOTTIME` — includes suspend time.
    Boottime = 2,
    /// `CLOCK_TAI` — International Atomic Time.
    TaiTime = 3,
}

/// Return value from a timer callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerRestart {
    /// Do not re-arm the timer.
    NoRestart,
    /// Re-arm the timer (expiry already updated by the callback).
    Restart,
}

/// Timer callback function type.
pub type HrTimerFn = fn(timer_id: u32, data: u64) -> TimerRestart;

/// High-resolution timer descriptor.
#[derive(Clone, Copy)]
pub struct HrTimer {
    /// Timer ID (0 = unused).
    pub id: u32,
    /// Absolute expiry time in nanoseconds.
    pub expiry_ns: u64,
    /// Re-arm interval in nanoseconds (0 = one-shot).
    pub interval_ns: u64,
    /// Clock base.
    pub base: HrClockBase,
    /// Callback.
    pub func: Option<HrTimerFn>,
    /// User data passed to callback.
    pub data: u64,
    /// Whether this timer is active.
    pub active: bool,
}

impl HrTimer {
    /// Creates an empty timer slot.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            expiry_ns: 0,
            interval_ns: 0,
            base: HrClockBase::Monotonic,
            func: None,
            data: 0,
            active: false,
        }
    }

    /// Creates a new one-shot timer.
    pub const fn new_oneshot(
        id: u32,
        expiry_ns: u64,
        func: HrTimerFn,
        data: u64,
        base: HrClockBase,
    ) -> Self {
        Self {
            id,
            expiry_ns,
            interval_ns: 0,
            base,
            func: Some(func),
            data,
            active: true,
        }
    }

    /// Creates a new periodic timer.
    pub const fn new_periodic(
        id: u32,
        expiry_ns: u64,
        interval_ns: u64,
        func: HrTimerFn,
        data: u64,
        base: HrClockBase,
    ) -> Self {
        Self {
            id,
            expiry_ns,
            interval_ns,
            base,
            func: Some(func),
            data,
            active: true,
        }
    }
}

/// Global monotonic clock (nanoseconds since boot). Updated by the tick.
static MONO_CLOCK_NS: AtomicU64 = AtomicU64::new(0);

/// Advances the global monotonic clock by `delta_ns`.
pub fn advance_clock(delta_ns: u64) {
    MONO_CLOCK_NS.fetch_add(delta_ns, Ordering::Relaxed);
}

/// Returns the current monotonic time in nanoseconds.
#[inline]
pub fn now_monotonic_ns() -> u64 {
    MONO_CLOCK_NS.load(Ordering::Relaxed)
}

/// Min-heap timer queue for one clock base.
pub struct HrTimerQueue {
    /// Timer slots (heap property: heap[0] has the smallest expiry).
    heap: [HrTimer; HRTIMER_MAX_TIMERS],
    /// Number of active timers in the heap.
    count: usize,
    /// Next timer ID to assign.
    next_id: u32,
}

impl HrTimerQueue {
    /// Creates an empty timer queue.
    pub const fn new() -> Self {
        Self {
            heap: [const { HrTimer::empty() }; HRTIMER_MAX_TIMERS],
            count: 0,
            next_id: 1,
        }
    }

    /// Adds a timer to the queue. Returns the assigned timer ID.
    pub fn add(&mut self, mut timer: HrTimer) -> Result<u32> {
        if self.count >= HRTIMER_MAX_TIMERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        timer.id = id;
        timer.active = true;
        self.heap[self.count] = timer;
        self.count += 1;
        self.sift_up(self.count - 1);
        Ok(id)
    }

    /// Cancels the timer with the given `id`. Returns `Err(NotFound)` if absent.
    pub fn cancel(&mut self, id: u32) -> Result<()> {
        let idx = (0..self.count)
            .find(|&i| self.heap[i].id == id)
            .ok_or(Error::NotFound)?;
        let last = self.count - 1;
        self.heap.swap(idx, last);
        self.heap[last] = HrTimer::empty();
        self.count -= 1;
        if idx < self.count {
            self.sift_down(idx);
            self.sift_up(idx);
        }
        Ok(())
    }

    /// Fires all timers whose expiry is ≤ `now_ns`.
    ///
    /// Returns the number of timers that fired.
    pub fn process_expired(&mut self, now_ns: u64) -> usize {
        let mut fired = 0usize;
        loop {
            if self.count == 0 {
                break;
            }
            if self.heap[0].expiry_ns > now_ns {
                break;
            }
            // Pop the minimum-expiry timer.
            let timer = self.heap[0];
            let last = self.count - 1;
            self.heap.swap(0, last);
            self.heap[last] = HrTimer::empty();
            self.count -= 1;
            if self.count > 0 {
                self.sift_down(0);
            }

            // Invoke callback.
            let restart = if let Some(func) = timer.func {
                func(timer.id, timer.data)
            } else {
                TimerRestart::NoRestart
            };

            // Re-arm if periodic or callback requested restart.
            if restart == TimerRestart::Restart
                || (timer.interval_ns > 0 && restart == TimerRestart::NoRestart)
            {
                let next_expiry = if timer.interval_ns > 0 {
                    timer.expiry_ns.wrapping_add(timer.interval_ns)
                } else {
                    timer.expiry_ns
                };
                let rearmed = HrTimer {
                    expiry_ns: next_expiry,
                    id: 0, // will be reassigned
                    ..timer
                };
                let _ = self.add(rearmed);
            }

            fired += 1;
        }
        fired
    }

    /// Returns the expiry of the next timer, or `None` if queue is empty.
    pub fn next_expiry(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.heap[0].expiry_ns)
        }
    }

    /// Returns the number of active timers.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    // --- Heap maintenance ---

    fn sift_up(&mut self, mut idx: usize) {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.heap[parent].expiry_ns > self.heap[idx].expiry_ns {
                self.heap.swap(parent, idx);
                idx = parent;
            } else {
                break;
            }
        }
    }

    fn sift_down(&mut self, mut idx: usize) {
        loop {
            let left = 2 * idx + 1;
            let right = 2 * idx + 2;
            let mut smallest = idx;

            if left < self.count && self.heap[left].expiry_ns < self.heap[smallest].expiry_ns {
                smallest = left;
            }
            if right < self.count && self.heap[right].expiry_ns < self.heap[smallest].expiry_ns {
                smallest = right;
            }
            if smallest == idx {
                break;
            }
            self.heap.swap(idx, smallest);
            idx = smallest;
        }
    }
}

impl Default for HrTimerQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU hrtimer state (one queue per clock base).
pub struct HrTimerCpu {
    /// Timer queues indexed by `HrClockBase as usize`.
    queues: [HrTimerQueue; 4],
}

impl HrTimerCpu {
    /// Creates a new per-CPU hrtimer state.
    pub const fn new() -> Self {
        Self {
            queues: [
                HrTimerQueue::new(),
                HrTimerQueue::new(),
                HrTimerQueue::new(),
                HrTimerQueue::new(),
            ],
        }
    }

    /// Queues a timer on the appropriate clock base.
    pub fn queue(&mut self, timer: HrTimer) -> Result<u32> {
        self.queues[timer.base as usize].add(timer)
    }

    /// Cancels a timer by ID on the given base.
    pub fn cancel(&mut self, base: HrClockBase, id: u32) -> Result<()> {
        self.queues[base as usize].cancel(id)
    }

    /// Fires all expired timers across all bases.
    pub fn tick(&mut self, now_ns: u64) -> usize {
        let mut total = 0;
        for q in &mut self.queues {
            total += q.process_expired(now_ns);
        }
        total
    }

    /// Returns the earliest next expiry across all bases.
    pub fn next_expiry(&self) -> Option<u64> {
        self.queues.iter().filter_map(|q| q.next_expiry()).min()
    }
}

impl Default for HrTimerCpu {
    fn default() -> Self {
        Self::new()
    }
}

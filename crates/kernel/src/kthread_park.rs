// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread parking.
//!
//! Implements a mechanism to temporarily park (suspend) kernel threads
//! and unpark (resume) them on demand. Parked threads enter a sleep
//! state and consume no CPU cycles. Used during CPU hotplug to stop
//! per-CPU kernel threads.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of parkable kernel threads.
const MAX_PARKABLE_THREADS: usize = 128;

/// Maximum park/unpark events in the log.
const MAX_PARK_EVENTS: usize = 256;

/// Thread park state flags.
const KTHREAD_SHOULD_PARK: u32 = 1 << 0;
const KTHREAD_IS_PARKED: u32 = 1 << 1;
const KTHREAD_SHOULD_STOP: u32 = 1 << 2;

// ── Types ────────────────────────────────────────────────────────────

/// State of a parkable kernel thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkState {
    /// Thread is running normally.
    Running,
    /// Park has been requested but not yet acknowledged.
    ParkRequested,
    /// Thread is parked (sleeping).
    Parked,
    /// Unpark has been requested.
    UnparkRequested,
    /// Thread has been stopped.
    Stopped,
}

impl Default for ParkState {
    fn default() -> Self {
        Self::Running
    }
}

/// A parkable kernel thread record.
#[derive(Debug, Clone)]
pub struct ParkableThread {
    /// Thread identifier.
    thread_id: u64,
    /// Current park state.
    state: ParkState,
    /// State flags.
    flags: u32,
    /// CPU this thread is bound to.
    bound_cpu: u32,
    /// Number of times this thread was parked.
    park_count: u64,
    /// Number of times this thread was unparked.
    unpark_count: u64,
    /// Total time spent parked (nanoseconds).
    total_parked_ns: u64,
    /// Timestamp of last park (nanoseconds).
    last_park_ns: u64,
    /// Thread name bytes.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl ParkableThread {
    /// Creates a new parkable thread record.
    pub const fn new(thread_id: u64, bound_cpu: u32) -> Self {
        Self {
            thread_id,
            state: ParkState::Running,
            flags: 0,
            bound_cpu,
            park_count: 0,
            unpark_count: 0,
            total_parked_ns: 0,
            last_park_ns: 0,
            name: [0u8; 32],
            name_len: 0,
        }
    }

    /// Returns the thread identifier.
    pub const fn thread_id(&self) -> u64 {
        self.thread_id
    }

    /// Returns the current park state.
    pub const fn state(&self) -> ParkState {
        self.state
    }

    /// Returns whether the thread is currently parked.
    pub const fn is_parked(&self) -> bool {
        self.flags & KTHREAD_IS_PARKED != 0
    }

    /// Returns the bound CPU.
    pub const fn bound_cpu(&self) -> u32 {
        self.bound_cpu
    }
}

/// A park/unpark event record.
#[derive(Debug, Clone)]
pub struct ParkEvent {
    /// Thread that was parked/unparked.
    thread_id: u64,
    /// Event type (true = park, false = unpark).
    is_park: bool,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
    /// CPU at the time of the event.
    cpu: u32,
}

impl ParkEvent {
    /// Creates a new park event.
    pub const fn new(thread_id: u64, is_park: bool, timestamp_ns: u64, cpu: u32) -> Self {
        Self {
            thread_id,
            is_park,
            timestamp_ns,
            cpu,
        }
    }
}

/// Kernel thread parking statistics.
#[derive(Debug, Clone)]
pub struct KthreadParkStats {
    /// Total registered threads.
    pub total_threads: u32,
    /// Currently parked threads.
    pub currently_parked: u32,
    /// Total park operations.
    pub total_parks: u64,
    /// Total unpark operations.
    pub total_unparks: u64,
    /// Total time all threads spent parked (nanoseconds).
    pub total_parked_ns: u64,
}

impl Default for KthreadParkStats {
    fn default() -> Self {
        Self::new()
    }
}

impl KthreadParkStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_threads: 0,
            currently_parked: 0,
            total_parks: 0,
            total_unparks: 0,
            total_parked_ns: 0,
        }
    }
}

/// Central kernel thread parking manager.
#[derive(Debug)]
pub struct KthreadParkManager {
    /// Registered parkable threads.
    threads: [Option<ParkableThread>; MAX_PARKABLE_THREADS],
    /// Event log ring buffer.
    events: [Option<ParkEvent>; MAX_PARK_EVENTS],
    /// Event log write position.
    event_pos: usize,
    /// Number of registered threads.
    thread_count: usize,
    /// Total park operations.
    total_parks: u64,
    /// Total unpark operations.
    total_unparks: u64,
}

impl Default for KthreadParkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KthreadParkManager {
    /// Creates a new kernel thread parking manager.
    pub const fn new() -> Self {
        Self {
            threads: [const { None }; MAX_PARKABLE_THREADS],
            events: [const { None }; MAX_PARK_EVENTS],
            event_pos: 0,
            thread_count: 0,
            total_parks: 0,
            total_unparks: 0,
        }
    }

    /// Registers a kernel thread as parkable.
    pub fn register_thread(&mut self, thread_id: u64, bound_cpu: u32) -> Result<()> {
        if self.thread_count >= MAX_PARKABLE_THREADS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.threads.iter().flatten() {
            if slot.thread_id == thread_id {
                return Err(Error::AlreadyExists);
            }
        }
        let thread = ParkableThread::new(thread_id, bound_cpu);
        if let Some(slot) = self.threads.iter_mut().find(|s| s.is_none()) {
            *slot = Some(thread);
            self.thread_count += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Requests a thread to park.
    pub fn park_thread(&mut self, thread_id: u64, timestamp_ns: u64) -> Result<()> {
        let thread = self
            .threads
            .iter_mut()
            .flatten()
            .find(|t| t.thread_id == thread_id)
            .ok_or(Error::NotFound)?;
        if thread.is_parked() {
            return Ok(());
        }
        thread.flags |= KTHREAD_SHOULD_PARK | KTHREAD_IS_PARKED;
        thread.state = ParkState::Parked;
        thread.park_count += 1;
        thread.last_park_ns = timestamp_ns;
        self.total_parks += 1;
        let event = ParkEvent::new(thread_id, true, timestamp_ns, thread.bound_cpu);
        self.events[self.event_pos] = Some(event);
        self.event_pos = (self.event_pos + 1) % MAX_PARK_EVENTS;
        Ok(())
    }

    /// Unparks a thread.
    pub fn unpark_thread(&mut self, thread_id: u64, timestamp_ns: u64) -> Result<()> {
        let thread = self
            .threads
            .iter_mut()
            .flatten()
            .find(|t| t.thread_id == thread_id)
            .ok_or(Error::NotFound)?;
        if !thread.is_parked() {
            return Ok(());
        }
        let parked_duration = timestamp_ns.saturating_sub(thread.last_park_ns);
        thread.total_parked_ns += parked_duration;
        thread.flags &= !(KTHREAD_SHOULD_PARK | KTHREAD_IS_PARKED);
        thread.state = ParkState::Running;
        thread.unpark_count += 1;
        self.total_unparks += 1;
        let event = ParkEvent::new(thread_id, false, timestamp_ns, thread.bound_cpu);
        self.events[self.event_pos] = Some(event);
        self.event_pos = (self.event_pos + 1) % MAX_PARK_EVENTS;
        Ok(())
    }

    /// Parks all threads bound to a specific CPU.
    pub fn park_cpu_threads(&mut self, cpu: u32, timestamp_ns: u64) -> Result<u32> {
        let mut parked = 0u32;
        let thread_ids: [Option<u64>; MAX_PARKABLE_THREADS] = {
            let mut ids = [None; MAX_PARKABLE_THREADS];
            for (i, slot) in self.threads.iter().enumerate() {
                if let Some(t) = slot {
                    if t.bound_cpu == cpu && !t.is_parked() {
                        ids[i] = Some(t.thread_id);
                    }
                }
            }
            ids
        };
        for tid in thread_ids.iter().flatten() {
            if self.park_thread(*tid, timestamp_ns).is_ok() {
                parked += 1;
            }
        }
        Ok(parked)
    }

    /// Unparks all threads bound to a specific CPU.
    pub fn unpark_cpu_threads(&mut self, cpu: u32, timestamp_ns: u64) -> Result<u32> {
        let mut unparked = 0u32;
        let thread_ids: [Option<u64>; MAX_PARKABLE_THREADS] = {
            let mut ids = [None; MAX_PARKABLE_THREADS];
            for (i, slot) in self.threads.iter().enumerate() {
                if let Some(t) = slot {
                    if t.bound_cpu == cpu && t.is_parked() {
                        ids[i] = Some(t.thread_id);
                    }
                }
            }
            ids
        };
        for tid in thread_ids.iter().flatten() {
            if self.unpark_thread(*tid, timestamp_ns).is_ok() {
                unparked += 1;
            }
        }
        Ok(unparked)
    }

    /// Unregisters a thread.
    pub fn unregister_thread(&mut self, thread_id: u64) -> Result<()> {
        let slot = self
            .threads
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |t| t.thread_id == thread_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.thread_count -= 1;
        Ok(())
    }

    /// Returns parking statistics.
    pub fn stats(&self) -> KthreadParkStats {
        let currently_parked = self
            .threads
            .iter()
            .flatten()
            .filter(|t| t.is_parked())
            .count() as u32;
        let total_parked_ns: u64 = self
            .threads
            .iter()
            .flatten()
            .map(|t| t.total_parked_ns)
            .sum();
        KthreadParkStats {
            total_threads: self.thread_count as u32,
            currently_parked,
            total_parks: self.total_parks,
            total_unparks: self.total_unparks,
            total_parked_ns,
        }
    }

    /// Returns the number of registered threads.
    pub const fn thread_count(&self) -> usize {
        self.thread_count
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread (kthread) management.
//!
//! Provides infrastructure for creating and managing kernel threads,
//! modeled after Linux's `kthread` subsystem (`kernel/kthread.c`).
//! Kernel threads run entirely in kernel space and are used for
//! background tasks such as memory reclaim, workqueue processing,
//! and periodic housekeeping.
//!
//! Key features:
//! - Create, run, stop, park, and unpark kernel threads
//! - CPU affinity binding for per-CPU kthreads
//! - Kthread workers for deferred work execution
//! - Fixed-size registry with no heap allocation
//!
//! All structures use fixed-size arrays, suitable for `#![no_std]`
//! kernel environments.

use core::fmt;

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum kernel threads in the registry.
const MAX_KTHREADS: usize = 64;

/// Maximum length of a kthread name.
const KTHREAD_NAME_LEN: usize = 32;

/// Maximum work items per kthread worker.
const WORKER_WORK_CAPACITY: usize = 16;

// ======================================================================
// Kthread flags
// ======================================================================

/// Flag: kthread is bound to a specific CPU.
pub const KTHREAD_IS_PER_CPU: u32 = 1;

/// Flag: kthread has been requested to stop.
pub const KTHREAD_SHOULD_STOP: u32 = 2;

/// Flag: kthread has been requested to park.
pub const KTHREAD_SHOULD_PARK: u32 = 4;

// ======================================================================
// KthreadState
// ======================================================================

/// Lifecycle state of a kernel thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KthreadState {
    /// Thread has been created but not yet started.
    #[default]
    Created,
    /// Thread is actively running.
    Running,
    /// Thread is parked (suspended, waiting for unpark).
    Parked,
    /// Thread has been requested to stop but has not yet exited.
    Stopping,
    /// Thread has fully stopped and its result is available.
    Stopped,
}

impl fmt::Display for KthreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => f.write_str("Created"),
            Self::Running => f.write_str("Running"),
            Self::Parked => f.write_str("Parked"),
            Self::Stopping => f.write_str("Stopping"),
            Self::Stopped => f.write_str("Stopped"),
        }
    }
}

// ======================================================================
// Kthread
// ======================================================================

/// A kernel thread descriptor.
///
/// Each `Kthread` tracks the thread's identity, lifecycle state,
/// flags, CPU affinity, and the function/data pair it executes.
pub struct Kthread {
    /// Unique thread identifier.
    pub id: u64,
    /// Human-readable name (fixed buffer, NUL-padded).
    name: [u8; KTHREAD_NAME_LEN],
    /// Valid length of `name` in bytes.
    name_len: usize,
    /// Current lifecycle state.
    pub state: KthreadState,
    /// Combination of `KTHREAD_*` flag constants.
    pub flags: u32,
    /// Identifies the function this thread executes.
    pub func_id: u64,
    /// Opaque data passed to the thread function.
    pub data: u64,
    /// CPU affinity bitmask (bit N = may run on CPU N).
    pub cpu_affinity: u64,
    /// Exit result code set when the thread stops.
    pub result: i64,
    /// Whether this slot is occupied in the registry.
    pub in_use: bool,
}

impl Kthread {
    /// Create an empty (inactive) kthread for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; KTHREAD_NAME_LEN],
            name_len: 0,
            state: KthreadState::Created,
            flags: 0,
            func_id: 0,
            data: 0,
            cpu_affinity: u64::MAX, // all CPUs by default
            result: 0,
            in_use: false,
        }
    }

    /// Return the kthread name as a `&str`.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(KTHREAD_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Return `true` if this thread has been requested to stop.
    pub fn should_stop(&self) -> bool {
        self.flags & KTHREAD_SHOULD_STOP != 0
    }

    /// Return `true` if this thread has been requested to park.
    pub fn should_park(&self) -> bool {
        self.flags & KTHREAD_SHOULD_PARK != 0
    }

    /// Park this thread (transition to [`KthreadState::Parked`]).
    ///
    /// The thread must be in the [`KthreadState::Running`] state and
    /// have the [`KTHREAD_SHOULD_PARK`] flag set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the thread is not running
    /// or has not been requested to park.
    pub fn park(&mut self) -> Result<()> {
        if self.state != KthreadState::Running {
            return Err(Error::InvalidArgument);
        }
        if !self.should_park() {
            return Err(Error::InvalidArgument);
        }
        self.state = KthreadState::Parked;
        self.flags &= !KTHREAD_SHOULD_PARK;
        Ok(())
    }

    /// Unpark this thread (transition from [`KthreadState::Parked`]
    /// back to [`KthreadState::Running`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the thread is not parked.
    pub fn unpark(&mut self) -> Result<()> {
        if self.state != KthreadState::Parked {
            return Err(Error::InvalidArgument);
        }
        self.state = KthreadState::Running;
        Ok(())
    }

    /// Set the CPU affinity bitmask for this thread.
    pub fn set_affinity(&mut self, cpu_mask: u64) {
        self.cpu_affinity = cpu_mask;
    }

    /// Return the current CPU affinity bitmask.
    pub fn get_affinity(&self) -> u64 {
        self.cpu_affinity
    }
}

impl Default for Kthread {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Kthread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kthread")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("state", &self.state)
            .field("flags", &self.flags)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ======================================================================
// KthreadWorker
// ======================================================================

/// A kthread-based worker that processes a queue of work items.
///
/// Each worker is associated with a kernel thread and maintains a
/// fixed-size list of work item IDs to process sequentially.
#[derive(Debug, Clone, Copy)]
pub struct KthreadWorker {
    /// Unique worker identifier.
    pub id: u64,
    /// ID of the kernel thread running this worker.
    pub thread_id: u64,
    /// Queue of work item IDs to process.
    pub work_list: [u64; WORKER_WORK_CAPACITY],
    /// Number of queued work items.
    pub work_count: usize,
    /// Whether this worker is currently active.
    pub active: bool,
}

impl KthreadWorker {
    /// Create an empty (inactive) worker for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            thread_id: 0,
            work_list: [0u64; WORKER_WORK_CAPACITY],
            work_count: 0,
            active: false,
        }
    }

    /// Enqueue a work item ID for this worker to process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the work list is full.
    pub fn enqueue_work(&mut self, work_id: u64) -> Result<()> {
        if self.work_count >= WORKER_WORK_CAPACITY {
            return Err(Error::OutOfMemory);
        }
        self.work_list[self.work_count] = work_id;
        self.work_count = self.work_count.saturating_add(1);
        Ok(())
    }

    /// Dequeue the next work item ID.
    ///
    /// Returns `None` if the work list is empty.
    pub fn dequeue_work(&mut self) -> Option<u64> {
        if self.work_count == 0 {
            return None;
        }
        let work_id = self.work_list[0];
        // Shift remaining items forward.
        let mut i = 1;
        while i < self.work_count {
            self.work_list[i - 1] = self.work_list[i];
            i += 1;
        }
        self.work_count = self.work_count.saturating_sub(1);
        // Clear the now-unused tail slot.
        self.work_list[self.work_count] = 0;
        Some(work_id)
    }

    /// Return the number of queued work items.
    pub fn pending(&self) -> usize {
        self.work_count
    }
}

impl Default for KthreadWorker {
    fn default() -> Self {
        Self::empty()
    }
}

// ======================================================================
// KthreadRegistry
// ======================================================================

/// Global registry of kernel threads.
///
/// Manages up to [`MAX_KTHREADS`] kernel threads, each identified by
/// a unique ID. Provides the kernel-facing API for creating, running,
/// stopping, parking, and binding kthreads.
pub struct KthreadRegistry {
    /// Kthread slots.
    threads: [Kthread; MAX_KTHREADS],
    /// Number of active (in-use) kthreads.
    count: usize,
    /// Monotonically increasing thread ID counter.
    next_id: u64,
}

impl KthreadRegistry {
    /// Create a new, empty registry.
    #[allow(clippy::large_stack_frames)]
    pub fn new() -> Self {
        // Use a const initialiser to avoid repeating 64 elements.
        const EMPTY: Kthread = Kthread::empty();
        Self {
            threads: [EMPTY; MAX_KTHREADS],
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate the next thread ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Create a new kernel thread in the [`KthreadState::Created`] state.
    ///
    /// The thread is not started automatically — call
    /// [`wake_up_process`](Self::wake_up_process) or use
    /// [`kthread_run`](Self::kthread_run) to create and start in one step.
    ///
    /// Returns the new thread's unique ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    pub fn kthread_create(&mut self, name: &str, func_id: u64, data: u64) -> Result<u64> {
        let slot = self
            .threads
            .iter()
            .position(|t| !t.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.alloc_id();

        let mut name_buf = [0u8; KTHREAD_NAME_LEN];
        let copy_len = name.len().min(KTHREAD_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let kt = &mut self.threads[slot];
        kt.id = id;
        kt.name = name_buf;
        kt.name_len = copy_len;
        kt.state = KthreadState::Created;
        kt.flags = 0;
        kt.func_id = func_id;
        kt.data = data;
        kt.cpu_affinity = u64::MAX;
        kt.result = 0;
        kt.in_use = true;

        self.count = self.count.saturating_add(1);
        Ok(id)
    }

    /// Create and immediately start a kernel thread.
    ///
    /// Equivalent to [`kthread_create`](Self::kthread_create) followed
    /// by [`wake_up_process`](Self::wake_up_process).
    ///
    /// Returns the new thread's unique ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    pub fn kthread_run(&mut self, name: &str, func_id: u64, data: u64) -> Result<u64> {
        let id = self.kthread_create(name, func_id, data)?;
        self.wake_up_process(id)?;
        Ok(id)
    }

    /// Signal a kernel thread to stop and return its result code.
    ///
    /// Sets the [`KTHREAD_SHOULD_STOP`] flag, transitions the thread
    /// to [`KthreadState::Stopping`] (then [`KthreadState::Stopped`]),
    /// and returns the thread's result code.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no thread with the given ID exists.
    /// Returns [`Error::InvalidArgument`] if the thread is already stopped.
    pub fn kthread_stop(&mut self, id: u64) -> Result<i64> {
        let kt = self.get_mut(id)?;
        if kt.state == KthreadState::Stopped {
            return Err(Error::InvalidArgument);
        }
        kt.flags |= KTHREAD_SHOULD_STOP;
        kt.state = KthreadState::Stopping;
        // In a real kernel the thread would observe the flag, clean up,
        // and set its result. Here we immediately transition to Stopped.
        kt.state = KthreadState::Stopped;
        let result = kt.result;
        // Free the slot.
        kt.in_use = false;
        self.count = self.count.saturating_sub(1);
        Ok(result)
    }

    /// Request a kernel thread to park.
    ///
    /// Sets the [`KTHREAD_SHOULD_PARK`] flag. The thread itself must
    /// call [`Kthread::park`] to complete the transition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no thread with the given ID exists.
    /// Returns [`Error::InvalidArgument`] if the thread is not running.
    pub fn kthread_park(&mut self, id: u64) -> Result<()> {
        let kt = self.get_mut(id)?;
        if kt.state != KthreadState::Running {
            return Err(Error::InvalidArgument);
        }
        kt.flags |= KTHREAD_SHOULD_PARK;
        Ok(())
    }

    /// Unpark a parked kernel thread.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no thread with the given ID exists.
    /// Returns [`Error::InvalidArgument`] if the thread is not parked.
    pub fn kthread_unpark(&mut self, id: u64) -> Result<()> {
        let kt = self.get_mut(id)?;
        kt.unpark()
    }

    /// Bind a kernel thread to a specific CPU.
    ///
    /// Sets the CPU affinity to a single CPU and marks the thread as
    /// per-CPU. The thread must be in the [`KthreadState::Created`]
    /// state (not yet started).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no thread with the given ID exists.
    /// Returns [`Error::InvalidArgument`] if the thread has already started.
    pub fn kthread_bind(&mut self, id: u64, cpu: u32) -> Result<()> {
        let kt = self.get_mut(id)?;
        if kt.state != KthreadState::Created {
            return Err(Error::InvalidArgument);
        }
        kt.cpu_affinity = 1u64 << (cpu as u64);
        kt.flags |= KTHREAD_IS_PER_CPU;
        Ok(())
    }

    /// Wake up (start) a kernel thread.
    ///
    /// Transitions the thread from [`KthreadState::Created`] to
    /// [`KthreadState::Running`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no thread with the given ID exists.
    /// Returns [`Error::InvalidArgument`] if the thread is not in the
    /// `Created` state.
    pub fn wake_up_process(&mut self, id: u64) -> Result<()> {
        let kt = self.get_mut(id)?;
        if kt.state != KthreadState::Created {
            return Err(Error::InvalidArgument);
        }
        kt.state = KthreadState::Running;
        Ok(())
    }

    /// Return a shared reference to a kthread by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no in-use thread with the
    /// given ID exists.
    pub fn get(&self, id: u64) -> Result<&Kthread> {
        self.threads
            .iter()
            .find(|t| t.in_use && t.id == id)
            .ok_or(Error::NotFound)
    }

    /// Return a mutable reference to a kthread by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no in-use thread with the
    /// given ID exists.
    pub fn get_mut(&mut self, id: u64) -> Result<&mut Kthread> {
        self.threads
            .iter_mut()
            .find(|t| t.in_use && t.id == id)
            .ok_or(Error::NotFound)
    }

    /// Return the number of active kernel threads.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry has no active kernel threads.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for KthreadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KthreadRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KthreadRegistry")
            .field("count", &self.count)
            .field("capacity", &MAX_KTHREADS)
            .field("next_id", &self.next_id)
            .finish()
    }
}

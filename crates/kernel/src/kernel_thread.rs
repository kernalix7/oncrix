// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread creation and management.
//!
//! Provides the infrastructure for creating, managing, and stopping kernel
//! threads (kthreads). Kernel threads are lightweight in-kernel execution
//! contexts that run in kernel address space and are used for background
//! tasks such as workqueue workers, memory reclaim, network processing,
//! and other kernel subsystem daemons.
//!
//! Key primitives:
//! - [`KthreadHandle`] — reference to a running kernel thread
//! - [`KthreadData`] — per-thread control block
//! - [`KthreadBuilder`] — builder pattern for configuring new kthreads
//! - [`spawn_kthread`] — spawns a kernel thread

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use oncrix_lib::{Error, Result};

extern crate alloc;

/// Maximum length of a kernel thread name.
pub const KTHREAD_NAME_MAX: usize = 64;

/// Maximum number of simultaneously live kernel threads.
pub const KTHREAD_MAX: usize = 4096;

/// Kernel thread function signature.
///
/// The function receives a pointer-sized data argument and returns an
/// `i32` exit code. Zero indicates success.
pub type KthreadFn = fn(data: usize) -> i32;

/// State of a kernel thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KthreadState {
    /// Thread has been created but not yet started.
    Created,
    /// Thread is running.
    Running,
    /// Thread is sleeping/blocked waiting for work.
    Sleeping,
    /// A stop request has been issued; thread should exit.
    ShouldStop,
    /// Thread has exited.
    Stopped,
}

/// Unique identifier for a kernel thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KthreadId(u64);

impl KthreadId {
    /// Creates a kernel thread ID from a raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Per-thread control data stored in the kernel thread's stack region.
pub struct KthreadData {
    /// Unique ID for this kernel thread.
    id: KthreadId,
    /// Name of the thread (NUL-terminated byte array).
    name: [u8; KTHREAD_NAME_MAX],
    /// Current state of the thread.
    state: KthreadState,
    /// CPU affinity mask (bit N = CPU N is allowed).
    cpu_affinity: AtomicU64,
    /// Stop flag — set when the thread should exit.
    should_stop: AtomicBool,
    /// Park flag — set when the thread should sleep until unparked.
    should_park: AtomicBool,
    /// Whether the thread is currently parked.
    parked: AtomicBool,
    /// Exit code returned by the thread function.
    exit_code: AtomicU32,
    /// Whether the thread runs as a real-time priority thread.
    is_realtime: bool,
    /// Scheduling priority (0 = normal, 1-99 = RT).
    priority: u32,
}

impl KthreadData {
    /// Creates a new kernel thread control block.
    pub fn new(id: KthreadId, name: &[u8]) -> Result<Self> {
        if name.len() >= KTHREAD_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut data = Self {
            id,
            name: [0u8; KTHREAD_NAME_MAX],
            state: KthreadState::Created,
            cpu_affinity: AtomicU64::new(u64::MAX), // all CPUs
            should_stop: AtomicBool::new(false),
            should_park: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
            is_realtime: false,
            priority: 0,
        };
        data.name[..name.len()].copy_from_slice(name);
        Ok(data)
    }

    /// Returns the kernel thread's unique ID.
    pub fn id(&self) -> KthreadId {
        self.id
    }

    /// Returns the name of the kernel thread as a byte slice.
    pub fn name(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(KTHREAD_NAME_MAX);
        &self.name[..end]
    }

    /// Returns the current state of the thread.
    pub fn state(&self) -> KthreadState {
        self.state
    }

    /// Sets the thread state.
    pub fn set_state(&mut self, state: KthreadState) {
        self.state = state;
    }

    /// Returns true if the thread should stop (checked by the thread itself).
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::Acquire)
    }

    /// Returns true if the thread should park (checked by the thread itself).
    pub fn should_park(&self) -> bool {
        self.should_park.load(Ordering::Acquire)
    }

    /// Signals the thread to stop at its next opportunity.
    pub fn request_stop(&self) {
        self.should_stop.store(true, Ordering::Release);
    }

    /// Signals the thread to park (sleep until unparked).
    pub fn request_park(&self) {
        self.should_park.store(true, Ordering::Release);
    }

    /// Clears the park request and wakes the thread.
    pub fn unpark(&self) {
        self.should_park.store(false, Ordering::Release);
        self.parked.store(false, Ordering::Release);
    }

    /// Marks the thread as parked.
    pub fn set_parked(&self) {
        self.parked.store(true, Ordering::Release);
    }

    /// Returns true if the thread is currently parked.
    pub fn is_parked(&self) -> bool {
        self.parked.load(Ordering::Acquire)
    }

    /// Sets the exit code.
    pub fn set_exit_code(&self, code: i32) {
        // Store as u32 bit-cast of i32.
        self.exit_code.store(code as u32, Ordering::Release);
    }

    /// Returns the exit code.
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire) as i32
    }

    /// Returns the CPU affinity mask.
    pub fn cpu_affinity(&self) -> u64 {
        self.cpu_affinity.load(Ordering::Relaxed)
    }

    /// Sets the CPU affinity mask.
    ///
    /// A mask of `u64::MAX` means all CPUs are allowed.
    pub fn set_cpu_affinity(&self, mask: u64) {
        self.cpu_affinity.store(mask, Ordering::Relaxed);
    }

    /// Returns true if this is a real-time priority thread.
    pub fn is_realtime(&self) -> bool {
        self.is_realtime
    }

    /// Returns the scheduling priority.
    pub fn priority(&self) -> u32 {
        self.priority
    }
}

impl Default for KthreadData {
    fn default() -> Self {
        Self {
            id: KthreadId(0),
            name: [0u8; KTHREAD_NAME_MAX],
            state: KthreadState::Created,
            cpu_affinity: AtomicU64::new(u64::MAX),
            should_stop: AtomicBool::new(false),
            should_park: AtomicBool::new(false),
            parked: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
            is_realtime: false,
            priority: 0,
        }
    }
}

/// A handle to a live kernel thread.
///
/// Holding a `KthreadHandle` keeps a reference to the thread's control
/// block. Dropping all handles does NOT automatically stop the thread —
/// you must call `request_stop()` and then wait for the thread to exit.
pub struct KthreadHandle {
    id: KthreadId,
    name: [u8; KTHREAD_NAME_MAX],
    // In a real system this would be Arc<KthreadData> or a raw pointer.
    // For now we carry a snapshot of the essential fields.
    stop_requested: AtomicBool,
}

impl KthreadHandle {
    /// Creates a handle from a thread ID and name.
    pub fn new(id: KthreadId, name: &[u8]) -> Result<Self> {
        if name.len() >= KTHREAD_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut h = Self {
            id,
            name: [0u8; KTHREAD_NAME_MAX],
            stop_requested: AtomicBool::new(false),
        };
        h.name[..name.len()].copy_from_slice(name);
        Ok(h)
    }

    /// Returns the kernel thread's ID.
    pub fn id(&self) -> KthreadId {
        self.id
    }

    /// Returns the kernel thread's name as a byte slice.
    pub fn name(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(KTHREAD_NAME_MAX);
        &self.name[..end]
    }

    /// Sends a stop request to the thread.
    pub fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Release);
    }

    /// Returns true if a stop has been requested.
    pub fn stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::Acquire)
    }
}

/// Builder for configuring and spawning a new kernel thread.
pub struct KthreadBuilder {
    name: [u8; KTHREAD_NAME_MAX],
    name_len: usize,
    cpu_affinity: u64,
    is_realtime: bool,
    priority: u32,
    stack_size_hint: usize,
}

impl KthreadBuilder {
    /// Creates a new builder with the given thread name.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() >= KTHREAD_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut builder = Self {
            name: [0u8; KTHREAD_NAME_MAX],
            name_len: name.len(),
            cpu_affinity: u64::MAX,
            is_realtime: false,
            priority: 0,
            stack_size_hint: 16 * 1024, // 16 KiB default
        };
        builder.name[..name.len()].copy_from_slice(name);
        Ok(builder)
    }

    /// Pins the thread to a specific set of CPUs (bitmask).
    pub fn cpu_affinity(mut self, mask: u64) -> Self {
        self.cpu_affinity = mask;
        self
    }

    /// Sets the thread to run at real-time priority.
    pub fn realtime(mut self, priority: u32) -> Self {
        self.is_realtime = true;
        self.priority = priority.min(99);
        self
    }

    /// Sets the stack size hint in bytes.
    pub fn stack_size(mut self, size: usize) -> Self {
        self.stack_size_hint = size;
        self
    }

    /// Returns the configured name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the configured CPU affinity mask.
    pub fn get_cpu_affinity(&self) -> u64 {
        self.cpu_affinity
    }

    /// Returns whether the thread is configured as real-time.
    pub fn get_is_realtime(&self) -> bool {
        self.is_realtime
    }

    /// Returns the configured priority.
    pub fn get_priority(&self) -> u32 {
        self.priority
    }

    /// Returns the stack size hint.
    pub fn get_stack_size(&self) -> usize {
        self.stack_size_hint
    }
}

/// Global kernel thread ID allocator.
static NEXT_KTHREAD_ID: AtomicU64 = AtomicU64::new(1);

/// Global count of live kernel threads.
static LIVE_KTHREAD_COUNT: AtomicU32 = AtomicU32::new(0);

/// Allocates a new unique kernel thread ID.
pub fn alloc_kthread_id() -> Result<KthreadId> {
    let count = LIVE_KTHREAD_COUNT.load(Ordering::Relaxed);
    if count as usize >= KTHREAD_MAX {
        return Err(Error::OutOfMemory);
    }
    let id = NEXT_KTHREAD_ID.fetch_add(1, Ordering::Relaxed);
    LIVE_KTHREAD_COUNT.fetch_add(1, Ordering::Relaxed);
    Ok(KthreadId::new(id))
}

/// Called when a kernel thread exits to decrement the live count.
pub fn on_kthread_exit() {
    LIVE_KTHREAD_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// Returns the number of currently live kernel threads.
pub fn kthread_count() -> u32 {
    LIVE_KTHREAD_COUNT.load(Ordering::Relaxed)
}

/// Spawns a new kernel thread using a builder configuration.
///
/// In a full implementation this would allocate a stack, set up the
/// initial register state, and add the thread to the scheduler run queue.
/// This stub validates the parameters and returns a handle.
pub fn spawn_kthread(
    builder: KthreadBuilder,
    _function: KthreadFn,
    _data: usize,
) -> Result<KthreadHandle> {
    let id = alloc_kthread_id()?;
    let handle = KthreadHandle::new(id, builder.name())?;
    Ok(handle)
}

/// Spawns a named kernel thread with default settings.
///
/// Convenience wrapper around [`spawn_kthread`] + [`KthreadBuilder`].
pub fn kthread_run(name: &[u8], function: KthreadFn, data: usize) -> Result<KthreadHandle> {
    let builder = KthreadBuilder::new(name)?;
    spawn_kthread(builder, function, data)
}

/// Checks whether the calling kernel thread should stop.
///
/// Kernel thread functions should call this (or the equivalent via their
/// [`KthreadData`] handle) in their main loop to cooperatively handle
/// stop requests.
///
/// Returns true if the thread should exit its main loop.
pub fn kthread_should_stop(data: &KthreadData) -> bool {
    data.should_stop()
}

/// Parks the calling kernel thread until unparked.
///
/// Sets the parked flag and yields. The thread will resume when
/// `KthreadData::unpark()` is called by another thread.
pub fn kthread_park(data: &KthreadData) {
    data.set_parked();
    // In a real implementation: schedule() here.
}

/// Returns true if the calling kernel thread should park.
pub fn kthread_should_park(data: &KthreadData) -> bool {
    data.should_park()
}

/// Well-known kernel thread names for system daemons.
pub mod names {
    /// Memory reclaim daemon.
    pub const KSWAPD: &[u8] = b"kswapd";
    /// Write-back daemon.
    pub const WRITEBACK: &[u8] = b"kworker/writeback";
    /// RCU grace-period daemon.
    pub const RCU_GP: &[u8] = b"rcu_gp";
    /// Migration thread per CPU.
    pub const MIGRATION: &[u8] = b"migration";
    /// Soft IRQ daemon.
    pub const KSOFTIRQD: &[u8] = b"ksoftirqd";
    /// OOM reaper.
    pub const OOM_REAPER: &[u8] = b"oom_reaper";
    /// Watchdog reset thread.
    pub const WATCHDOG: &[u8] = b"watchdog";
}

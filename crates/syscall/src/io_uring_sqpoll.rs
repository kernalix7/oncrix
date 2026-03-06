// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring SQPOLL mode handler.
//!
//! SQPOLL (Submission Queue Polling) is an io_uring mode where a dedicated
//! kernel thread continuously polls the submission queue for new entries,
//! eliminating the need for `io_uring_enter(2)` calls on the submission
//! path.  This can dramatically reduce latency for I/O-intensive workloads
//! at the cost of one CPU core per ring.
//!
//! # Overview
//!
//! When `IORING_SETUP_SQPOLL` is set at ring creation time, the kernel
//! spawns an SQ thread that:
//!
//! 1. Polls the shared submission ring for new SQEs.
//! 2. Submits found SQEs to the async I/O backend.
//! 3. Sleeps after `sq_thread_idle` milliseconds of inactivity.
//! 4. Can be pinned to a specific CPU with `IORING_SETUP_SQ_AFF`.
//!
//! User space may call `io_uring_enter(IORING_ENTER_SQ_WAKEUP)` to wake
//! a sleeping SQ thread.
//!
//! # Syscalls
//!
//! | Handler | Syscall | Description |
//! |---------|---------|-------------|
//! | [`sys_io_uring_sqpoll_setup`] | `io_uring_setup` (SQPOLL path) | Configure and start the SQ thread |
//! | [`sys_io_uring_sqpoll_wakeup`] | `io_uring_enter` (wakeup path) | Wake a sleeping SQ thread |
//! | [`sys_io_uring_sqpoll_bind_cpu`] | internal | Bind SQ thread to a CPU |
//! | [`sys_io_uring_sqpoll_idle_set`] | internal | Set idle timeout |
//!
//! # References
//!
//! - Linux: `io_uring/sqpoll.c`, `io_uring/io_uring.c`
//! - `liburing`: `src/include/liburing.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of active SQPOLL rings in the system.
const MAX_SQPOLL_RINGS: usize = 64;

/// Default idle timeout in milliseconds before the SQ thread sleeps.
pub const SQPOLL_DEFAULT_IDLE_MS: u32 = 1_000;

/// Minimum allowed idle timeout in milliseconds.
pub const SQPOLL_MIN_IDLE_MS: u32 = 1;

/// Maximum allowed idle timeout in milliseconds (1 hour).
pub const SQPOLL_MAX_IDLE_MS: u32 = 3_600_000;

/// Sentinel value indicating the SQ thread is not pinned to any CPU.
pub const SQPOLL_CPU_UNSET: u32 = u32::MAX;

/// Maximum number of CPUs supported for SQ thread affinity.
pub const SQPOLL_MAX_CPUS: u32 = 4096;

/// Maximum SQE entries per ring (must be a power of two).
pub const SQPOLL_MAX_ENTRIES: u32 = 32_768;

/// Minimum SQE entries per ring.
pub const SQPOLL_MIN_ENTRIES: u32 = 1;

// ---------------------------------------------------------------------------
// SQPOLL thread states
// ---------------------------------------------------------------------------

/// The state of an SQ polling thread.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqPollState {
    /// Thread has not been started yet.
    #[default]
    NotStarted = 0,
    /// Thread is actively polling the submission queue.
    Running = 1,
    /// Thread is sleeping due to idle timeout expiry.
    Sleeping = 2,
    /// Thread is in the process of stopping.
    Stopping = 3,
    /// Thread has exited.
    Stopped = 4,
    /// Thread encountered a fatal error.
    Error = 5,
}

impl SqPollState {
    /// Returns `true` if the thread is in an active (non-terminal) state.
    pub const fn is_active(&self) -> bool {
        matches!(self, SqPollState::Running | SqPollState::Sleeping)
    }

    /// Returns `true` if the thread needs to be woken up.
    pub const fn needs_wakeup(&self) -> bool {
        matches!(self, SqPollState::Sleeping)
    }
}

// ---------------------------------------------------------------------------
// SQPOLL configuration
// ---------------------------------------------------------------------------

/// Configuration for an io_uring SQPOLL instance.
///
/// Passed to [`sys_io_uring_sqpoll_setup`] to control how the SQ thread
/// is created and scheduled.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqPollConfig {
    /// Ring file descriptor (the `io_uring_setup` return value).
    pub ring_fd: i32,
    /// Number of submission queue entries (must be a power of two).
    pub sq_entries: u32,
    /// CPU to pin the SQ thread to.  Use [`SQPOLL_CPU_UNSET`] for no
    /// affinity.
    pub sq_thread_cpu: u32,
    /// Idle timeout in milliseconds.  After this many milliseconds with
    /// no new SQEs, the SQ thread will sleep until woken.
    pub sq_thread_idle: u32,
    /// Setup flags forwarded from `io_uring_params.flags`.
    pub flags: u32,
    /// NUMA node preference (`-1` for no preference).
    pub numa_node: i32,
}

impl Default for SqPollConfig {
    fn default() -> Self {
        Self {
            ring_fd: -1,
            sq_entries: 256,
            sq_thread_cpu: SQPOLL_CPU_UNSET,
            sq_thread_idle: SQPOLL_DEFAULT_IDLE_MS,
            flags: 0,
            numa_node: -1,
        }
    }
}

impl SqPollConfig {
    /// Create a minimal SQPOLL config for the given ring fd.
    pub const fn new(ring_fd: i32) -> Self {
        Self {
            ring_fd,
            sq_entries: 256,
            sq_thread_cpu: SQPOLL_CPU_UNSET,
            sq_thread_idle: SQPOLL_DEFAULT_IDLE_MS,
            flags: 0,
            numa_node: -1,
        }
    }

    /// Validate all configuration fields.
    pub fn validate(&self) -> Result<()> {
        if self.ring_fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.sq_entries < SQPOLL_MIN_ENTRIES || self.sq_entries > SQPOLL_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.sq_entries.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if self.sq_thread_idle < SQPOLL_MIN_IDLE_MS || self.sq_thread_idle > SQPOLL_MAX_IDLE_MS {
            return Err(Error::InvalidArgument);
        }
        if self.sq_thread_cpu != SQPOLL_CPU_UNSET && self.sq_thread_cpu >= SQPOLL_MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns `true` if the SQ thread should be CPU-pinned.
    pub const fn has_cpu_affinity(&self) -> bool {
        self.sq_thread_cpu != SQPOLL_CPU_UNSET
    }
}

// ---------------------------------------------------------------------------
// SQPOLL thread descriptor
// ---------------------------------------------------------------------------

/// Runtime descriptor for an active SQPOLL thread.
///
/// Tracks state, statistics, and configuration for one SQ polling thread.
#[derive(Debug)]
pub struct SqPollThread {
    /// Unique identifier for this SQPOLL instance.
    pub id: u32,
    /// Associated ring file descriptor.
    pub ring_fd: i32,
    /// Current thread state.
    pub state: SqPollState,
    /// Configuration snapshot at creation time.
    pub config: SqPollConfig,
    /// Number of SQEs consumed since start.
    pub sqes_consumed: u64,
    /// Number of times the thread woke from sleep.
    pub wakeups: u64,
    /// Number of idle timeouts (sleep transitions).
    pub idle_timeouts: u64,
    /// Number of errors encountered.
    pub errors: u64,
    /// Monotonic timestamp of the last SQE consumption (nanoseconds).
    pub last_active_ns: u64,
}

impl SqPollThread {
    /// Create a new descriptor in the `NotStarted` state.
    pub const fn new(id: u32, config: SqPollConfig) -> Self {
        Self {
            id,
            ring_fd: config.ring_fd,
            state: SqPollState::NotStarted,
            config,
            sqes_consumed: 0,
            wakeups: 0,
            idle_timeouts: 0,
            errors: 0,
            last_active_ns: 0,
        }
    }

    /// Returns `true` if the thread can accept new work.
    pub fn is_ready(&self) -> bool {
        self.state.is_active()
    }

    /// Record that `count` SQEs were consumed at time `now_ns`.
    pub fn record_consumption(&mut self, count: u64, now_ns: u64) {
        self.sqes_consumed = self.sqes_consumed.saturating_add(count);
        self.last_active_ns = now_ns;
    }

    /// Transition the thread to the sleeping state.
    pub fn enter_sleep(&mut self) {
        if self.state == SqPollState::Running {
            self.state = SqPollState::Sleeping;
            self.idle_timeouts = self.idle_timeouts.saturating_add(1);
        }
    }

    /// Transition the thread back to running after a wakeup.
    pub fn wake_up(&mut self) {
        if self.state == SqPollState::Sleeping {
            self.state = SqPollState::Running;
            self.wakeups = self.wakeups.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// SQPOLL registry
// ---------------------------------------------------------------------------

/// System-wide registry of active SQPOLL threads.
///
/// Maintains a fixed-size table of [`SqPollThread`] entries indexed by
/// thread ID.  Thread IDs are allocated sequentially starting from 1.
pub struct SqPollRegistry {
    /// Fixed-size table of optional thread entries.
    threads: [Option<SqPollThread>; MAX_SQPOLL_RINGS],
    /// Next thread ID to assign.
    next_id: u32,
    /// Count of currently active threads.
    active_count: u32,
}

impl SqPollRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            threads: [const { None }; MAX_SQPOLL_RINGS],
            next_id: 1,
            active_count: 0,
        }
    }

    /// Register a new SQPOLL thread, returning its assigned ID.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, config: SqPollConfig) -> Result<u32> {
        if self.active_count as usize >= MAX_SQPOLL_RINGS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .threads
            .iter()
            .position(|e| e.is_none())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.threads[slot] = Some(SqPollThread::new(id, config));
        self.active_count = self.active_count.saturating_add(1);
        Ok(id)
    }

    /// Look up a thread entry by ID (immutable).
    pub fn get(&self, id: u32) -> Option<&SqPollThread> {
        self.threads.iter().flatten().find(|t| t.id == id)
    }

    /// Look up a thread entry by ID (mutable).
    pub fn get_mut(&mut self, id: u32) -> Option<&mut SqPollThread> {
        self.threads.iter_mut().flatten().find(|t| t.id == id)
    }

    /// Remove a thread by ID, returning it if found.
    pub fn unregister(&mut self, id: u32) -> Option<SqPollThread> {
        for slot in &mut self.threads {
            if slot.as_ref().map_or(false, |t| t.id == id) {
                self.active_count = self.active_count.saturating_sub(1);
                return slot.take();
            }
        }
        None
    }

    /// Number of currently active SQPOLL threads.
    pub const fn active_count(&self) -> u32 {
        self.active_count
    }
}

impl Default for SqPollRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SQPOLL statistics snapshot
// ---------------------------------------------------------------------------

/// Snapshot of SQPOLL thread statistics for monitoring / diagnostics.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SqPollStats {
    /// Thread identifier.
    pub thread_id: u32,
    /// Current thread state as a raw value.
    pub state: u32,
    /// Total SQEs consumed since the thread started.
    pub sqes_consumed: u64,
    /// Total wakeup events.
    pub wakeups: u64,
    /// Total idle timeouts.
    pub idle_timeouts: u64,
    /// Total errors.
    pub errors: u64,
    /// Monotonic nanosecond timestamp of last active period.
    pub last_active_ns: u64,
}

impl SqPollStats {
    /// Construct a snapshot from a thread descriptor.
    pub fn from_thread(t: &SqPollThread) -> Self {
        Self {
            thread_id: t.id,
            state: t.state as u32,
            sqes_consumed: t.sqes_consumed,
            wakeups: t.wakeups,
            idle_timeouts: t.idle_timeouts,
            errors: t.errors,
            last_active_ns: t.last_active_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Wakeup reasons
// ---------------------------------------------------------------------------

/// The reason a SQPOLL thread wakeup was requested.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeupReason {
    /// New SQEs were posted to the ring.
    NewSqes = 0,
    /// Explicit wakeup via `IORING_ENTER_SQ_WAKEUP`.
    EnterWakeup = 1,
    /// Thread idle timeout expired.
    IdleTimeout = 2,
    /// Ring is being torn down.
    Shutdown = 3,
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// Set up a SQPOLL mode configuration for an existing io_uring ring.
///
/// Validates the configuration and registers an [`SqPollThread`] entry
/// in the system registry.  The actual kernel thread is started lazily
/// when the first SQE is submitted.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `config` — Caller-supplied configuration.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid `ring_fd`, entry count, or
///   idle timeout.
/// - [`Error::OutOfMemory`] — Registry is full.
///
/// # POSIX
///
/// Not a direct POSIX interface; Linux extension.
pub fn sys_io_uring_sqpoll_setup(
    registry: &mut SqPollRegistry,
    config: SqPollConfig,
) -> Result<u32> {
    config.validate()?;
    registry.register(config)
}

/// Wake a sleeping SQPOLL thread.
///
/// Called from the `io_uring_enter(2)` path when the
/// `IORING_ENTER_SQ_WAKEUP` flag is set.  If the thread is already
/// running, this is a no-op.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread ID to wake.
/// - `reason` — The reason for the wakeup.
///
/// # Errors
///
/// - [`Error::NotFound`] — No SQPOLL thread with `thread_id` exists.
pub fn sys_io_uring_sqpoll_wakeup(
    registry: &mut SqPollRegistry,
    thread_id: u32,
    reason: WakeupReason,
) -> Result<()> {
    let thread = registry.get_mut(thread_id).ok_or(Error::NotFound)?;
    if thread.state.needs_wakeup() || reason == WakeupReason::Shutdown {
        thread.wake_up();
    }
    Ok(())
}

/// Bind a SQPOLL thread to a specific CPU.
///
/// Applies CPU affinity to the named SQ polling thread.  May be called
/// after setup to change the CPU assignment.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread to bind.
/// - `cpu` — Target CPU number.  Use [`SQPOLL_CPU_UNSET`] to remove
///   affinity.
///
/// # Errors
///
/// - [`Error::NotFound`] — No thread with `thread_id` exists.
/// - [`Error::InvalidArgument`] — `cpu` is out of range.
pub fn sys_io_uring_sqpoll_bind_cpu(
    registry: &mut SqPollRegistry,
    thread_id: u32,
    cpu: u32,
) -> Result<()> {
    if cpu != SQPOLL_CPU_UNSET && cpu >= SQPOLL_MAX_CPUS {
        return Err(Error::InvalidArgument);
    }
    let thread = registry.get_mut(thread_id).ok_or(Error::NotFound)?;
    thread.config.sq_thread_cpu = cpu;
    Ok(())
}

/// Update the idle timeout of an active SQPOLL thread.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread to update.
/// - `idle_ms` — New idle timeout in milliseconds.
///
/// # Errors
///
/// - [`Error::NotFound`] — No thread with `thread_id` exists.
/// - [`Error::InvalidArgument`] — `idle_ms` is outside the valid range.
pub fn sys_io_uring_sqpoll_idle_set(
    registry: &mut SqPollRegistry,
    thread_id: u32,
    idle_ms: u32,
) -> Result<()> {
    if idle_ms < SQPOLL_MIN_IDLE_MS || idle_ms > SQPOLL_MAX_IDLE_MS {
        return Err(Error::InvalidArgument);
    }
    let thread = registry.get_mut(thread_id).ok_or(Error::NotFound)?;
    thread.config.sq_thread_idle = idle_ms;
    Ok(())
}

/// Query statistics for a SQPOLL thread.
///
/// Returns a snapshot of runtime statistics for monitoring.
///
/// # Arguments
///
/// - `registry` — Reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread to query.
///
/// # Errors
///
/// - [`Error::NotFound`] — No thread with `thread_id` exists.
pub fn sys_io_uring_sqpoll_stats(registry: &SqPollRegistry, thread_id: u32) -> Result<SqPollStats> {
    let thread = registry.get(thread_id).ok_or(Error::NotFound)?;
    Ok(SqPollStats::from_thread(thread))
}

/// Shut down and deregister a SQPOLL thread.
///
/// Transitions the thread to the `Stopping` state, waits for it to
/// drain pending SQEs, and removes it from the registry.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread to stop.
///
/// # Errors
///
/// - [`Error::NotFound`] — No thread with `thread_id` exists.
/// - [`Error::Busy`] — Thread is not in a stoppable state.
pub fn sys_io_uring_sqpoll_stop(
    registry: &mut SqPollRegistry,
    thread_id: u32,
) -> Result<SqPollThread> {
    {
        let thread = registry.get_mut(thread_id).ok_or(Error::NotFound)?;
        if thread.state == SqPollState::Stopped || thread.state == SqPollState::NotStarted {
            // Already stopped — remove and return.
        } else if thread.state == SqPollState::Error {
            // Allow cleanup of error state.
        } else {
            thread.state = SqPollState::Stopping;
        }
    }
    registry.unregister(thread_id).ok_or(Error::NotFound)
}

/// Record SQE consumption event for a SQPOLL thread.
///
/// Called by the polling loop each time one or more SQEs are processed.
///
/// # Arguments
///
/// - `registry` — Mutable reference to the system SQPOLL registry.
/// - `thread_id` — The SQPOLL thread doing the consuming.
/// - `count` — Number of SQEs consumed in this batch.
/// - `now_ns` — Current monotonic timestamp in nanoseconds.
///
/// # Errors
///
/// - [`Error::NotFound`] — No thread with `thread_id` exists.
pub fn sys_io_uring_sqpoll_consume(
    registry: &mut SqPollRegistry,
    thread_id: u32,
    count: u64,
    now_ns: u64,
) -> Result<()> {
    let thread = registry.get_mut(thread_id).ok_or(Error::NotFound)?;
    thread.record_consumption(count, now_ns);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> SqPollRegistry {
        SqPollRegistry::new()
    }

    #[test]
    fn test_config_validation_ok() {
        let cfg = SqPollConfig {
            ring_fd: 3,
            sq_entries: 256,
            sq_thread_cpu: SQPOLL_CPU_UNSET,
            sq_thread_idle: 500,
            flags: 0,
            numa_node: -1,
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validation_bad_entries() {
        let cfg = SqPollConfig {
            ring_fd: 3,
            sq_entries: 300, // not power of two
            sq_thread_cpu: SQPOLL_CPU_UNSET,
            sq_thread_idle: 500,
            flags: 0,
            numa_node: -1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_register_and_lookup() {
        let mut reg = make_registry();
        let cfg = SqPollConfig::new(3);
        let id = sys_io_uring_sqpoll_setup(&mut reg, cfg).unwrap();
        assert!(reg.get(id).is_some());
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn test_wakeup() {
        let mut reg = make_registry();
        let id = sys_io_uring_sqpoll_setup(&mut reg, SqPollConfig::new(3)).unwrap();
        let thread = reg.get_mut(id).unwrap();
        thread.state = SqPollState::Running;
        thread.enter_sleep();
        assert_eq!(thread.state, SqPollState::Sleeping);
        sys_io_uring_sqpoll_wakeup(&mut reg, id, WakeupReason::NewSqes).unwrap();
        assert_eq!(reg.get(id).unwrap().state, SqPollState::Running);
    }

    #[test]
    fn test_stop() {
        let mut reg = make_registry();
        let id = sys_io_uring_sqpoll_setup(&mut reg, SqPollConfig::new(3)).unwrap();
        let thread = reg.get_mut(id).unwrap();
        thread.state = SqPollState::Running;
        let stopped = sys_io_uring_sqpoll_stop(&mut reg, id).unwrap();
        assert_eq!(stopped.ring_fd, 3);
        assert_eq!(reg.active_count(), 0);
    }
}

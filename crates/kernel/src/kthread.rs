// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread (kthread) management.
//!
//! Provides infrastructure for creating, running, stopping, parking,
//! and unparking kernel threads, modelled after Linux `kernel/kthread.c`.
//!
//! # Architecture
//!
//! ```text
//! KthreadManager
//!  ├── KthreadInfo[MAX_KTHREADS]
//!  │    ├── name, pid, cpu_affinity
//!  │    ├── state (Created/Running/Parked/Stopped)
//!  │    ├── should_stop flag
//!  │    └── function pointer id + argument
//!  └── KthreadStats
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum kernel threads.
const MAX_KTHREADS: usize = 128;

/// Maximum name length.
const NAME_LEN: usize = 32;

/// No CPU affinity (can run on any CPU).
const CPU_ANY: u32 = u32::MAX;

// ======================================================================
// Types
// ======================================================================

/// Kthread lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KthreadState {
    /// Created but not yet started.
    Created,
    /// Running.
    Running,
    /// Parked (temporarily suspended).
    Parked,
    /// Exiting.
    Exiting,
    /// Stopped (terminated).
    Stopped,
}

/// Kernel thread descriptor.
pub struct KthreadInfo {
    /// Thread name.
    pub name: [u8; NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Assigned PID (kernel-assigned).
    pub pid: u64,
    /// Current state.
    pub state: KthreadState,
    /// CPU affinity (CPU_ANY = no affinity).
    pub cpu_affinity: u32,
    /// Function identifier (application-specific).
    pub func_id: u64,
    /// Argument to the thread function.
    pub func_arg: u64,
    /// Whether someone has requested this thread to stop.
    pub should_stop: bool,
    /// Whether this thread should be parked.
    pub should_park: bool,
    /// Exit code when the thread terminates.
    pub exit_code: i32,
    /// Whether this slot is used.
    pub active: bool,
    /// Total run time in nanoseconds.
    pub total_runtime_ns: u64,
    /// Start timestamp.
    pub start_time_ns: u64,
}

impl Default for KthreadInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl KthreadInfo {
    /// Creates an inactive kthread slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            name_len: 0,
            pid: 0,
            state: KthreadState::Stopped,
            cpu_affinity: CPU_ANY,
            func_id: 0,
            func_arg: 0,
            should_stop: false,
            should_park: false,
            exit_code: 0,
            active: false,
            total_runtime_ns: 0,
            start_time_ns: 0,
        }
    }

    /// Returns the thread name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Parameters for creating a kernel thread.
pub struct KthreadCreateInfo {
    /// Thread name.
    pub name: [u8; NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Function identifier.
    pub func_id: u64,
    /// Argument.
    pub func_arg: u64,
    /// CPU affinity.
    pub cpu_affinity: u32,
}

impl KthreadCreateInfo {
    /// Creates creation parameters.
    pub fn with_name(name: &[u8], func_id: u64) -> Self {
        let mut n = [0u8; NAME_LEN];
        let len = name.len().min(NAME_LEN);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            name: n,
            name_len: len,
            func_id,
            func_arg: 0,
            cpu_affinity: CPU_ANY,
        }
    }
}

/// Statistics for the kthread subsystem.
pub struct KthreadStats {
    /// Total kthreads created.
    pub total_created: u64,
    /// Total kthreads stopped.
    pub total_stopped: u64,
    /// Currently running kthreads.
    pub nr_running: u32,
    /// Currently parked kthreads.
    pub nr_parked: u32,
}

impl Default for KthreadStats {
    fn default() -> Self {
        Self::new()
    }
}

impl KthreadStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_created: 0,
            total_stopped: 0,
            nr_running: 0,
            nr_parked: 0,
        }
    }
}

// ======================================================================
// KthreadManager
// ======================================================================

/// Manages all kernel threads.
pub struct KthreadManager {
    /// Kthread registry.
    threads: [KthreadInfo; MAX_KTHREADS],
    /// Next PID to assign.
    next_pid: u64,
    /// Statistics.
    pub stats: KthreadStats,
}

impl Default for KthreadManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KthreadManager {
    /// Creates the kthread manager.
    pub const fn new() -> Self {
        Self {
            threads: [const { KthreadInfo::new() }; MAX_KTHREADS],
            next_pid: 1,
            stats: KthreadStats::new(),
        }
    }

    /// Creates a kernel thread (but does not start it).
    /// Returns the kthread index.
    pub fn kthread_create(&mut self, info: &KthreadCreateInfo) -> Result<usize> {
        let slot = self
            .threads
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let pid = self.next_pid;
        self.next_pid += 1;

        self.threads[slot].name = info.name;
        self.threads[slot].name_len = info.name_len;
        self.threads[slot].pid = pid;
        self.threads[slot].state = KthreadState::Created;
        self.threads[slot].cpu_affinity = info.cpu_affinity;
        self.threads[slot].func_id = info.func_id;
        self.threads[slot].func_arg = info.func_arg;
        self.threads[slot].should_stop = false;
        self.threads[slot].should_park = false;
        self.threads[slot].exit_code = 0;
        self.threads[slot].active = true;
        self.threads[slot].total_runtime_ns = 0;
        self.threads[slot].start_time_ns = 0;

        self.stats.total_created += 1;

        Ok(slot)
    }

    /// Starts a created kernel thread. Equivalent to wake_up_process.
    pub fn kthread_run(&mut self, slot: usize, now_ns: u64) -> Result<u64> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        if self.threads[slot].state != KthreadState::Created {
            return Err(Error::InvalidArgument);
        }
        self.threads[slot].state = KthreadState::Running;
        self.threads[slot].start_time_ns = now_ns;
        self.stats.nr_running += 1;
        Ok(self.threads[slot].pid)
    }

    /// Creates and immediately starts a kernel thread.
    pub fn kthread_create_and_run(
        &mut self,
        info: &KthreadCreateInfo,
        now_ns: u64,
    ) -> Result<(usize, u64)> {
        let slot = self.kthread_create(info)?;
        let pid = self.kthread_run(slot, now_ns)?;
        Ok((slot, pid))
    }

    /// Requests a kernel thread to stop.
    pub fn kthread_stop(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        self.threads[slot].should_stop = true;
        // If parked, unpark so it can exit.
        if self.threads[slot].state == KthreadState::Parked {
            self.threads[slot].state = KthreadState::Running;
            self.stats.nr_parked = self.stats.nr_parked.saturating_sub(1);
            self.stats.nr_running += 1;
        }
        Ok(())
    }

    /// Called by the kthread itself to check if it should stop.
    pub fn kthread_should_stop(&self, slot: usize) -> bool {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return true;
        }
        self.threads[slot].should_stop
    }

    /// Called by the kthread itself to check if it should park.
    pub fn kthread_should_park(&self, slot: usize) -> bool {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return false;
        }
        self.threads[slot].should_park
    }

    /// Parks a kernel thread (temporarily suspends it).
    pub fn kthread_park(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        if self.threads[slot].state != KthreadState::Running {
            return Err(Error::InvalidArgument);
        }
        self.threads[slot].should_park = true;
        self.threads[slot].state = KthreadState::Parked;
        self.stats.nr_running = self.stats.nr_running.saturating_sub(1);
        self.stats.nr_parked += 1;
        Ok(())
    }

    /// Unparks a parked kernel thread.
    pub fn kthread_unpark(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        if self.threads[slot].state != KthreadState::Parked {
            return Err(Error::InvalidArgument);
        }
        self.threads[slot].should_park = false;
        self.threads[slot].state = KthreadState::Running;
        self.stats.nr_parked = self.stats.nr_parked.saturating_sub(1);
        self.stats.nr_running += 1;
        Ok(())
    }

    /// Called when a kthread exits. Transitions to Stopped.
    pub fn kthread_exit(&mut self, slot: usize, exit_code: i32, now_ns: u64) -> Result<()> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        let was_running = self.threads[slot].state == KthreadState::Running;
        self.threads[slot].state = KthreadState::Stopped;
        self.threads[slot].exit_code = exit_code;
        self.threads[slot].total_runtime_ns =
            now_ns.saturating_sub(self.threads[slot].start_time_ns);
        self.threads[slot].active = false;

        if was_running {
            self.stats.nr_running = self.stats.nr_running.saturating_sub(1);
        }
        self.stats.total_stopped += 1;
        Ok(())
    }

    /// Sets CPU affinity for a kthread.
    pub fn set_affinity(&mut self, slot: usize, cpu: u32) -> Result<()> {
        if slot >= MAX_KTHREADS || !self.threads[slot].active {
            return Err(Error::NotFound);
        }
        self.threads[slot].cpu_affinity = cpu;
        Ok(())
    }

    /// Returns kthread info by slot.
    pub fn thread(&self, slot: usize) -> Option<&KthreadInfo> {
        if slot < MAX_KTHREADS && self.threads[slot].active {
            Some(&self.threads[slot])
        } else {
            None
        }
    }

    /// Finds a kthread by PID.
    pub fn find_by_pid(&self, pid: u64) -> Option<usize> {
        self.threads.iter().position(|t| t.active && t.pid == pid)
    }

    /// Finds a kthread by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        self.threads
            .iter()
            .position(|t| t.active && t.name_len == name.len() && t.name[..t.name_len] == *name)
    }

    /// Returns the number of active kthreads.
    pub fn nr_active(&self) -> usize {
        self.threads.iter().filter(|t| t.active).count()
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Restartable sequences (rseq) for per-CPU atomic operations.
//!
//! Restartable sequences allow user-space code to perform per-CPU
//! atomic operations without requiring heavy synchronization. The
//! kernel tracks critical sections and restarts them (by jumping
//! to an abort handler) if the thread is preempted, receives a
//! signal, or is migrated to another CPU.
//!
//! Reference: Linux `kernel/rseq.c`, rseq(2) man page.

use oncrix_lib::{Error, Result};

/// Maximum number of concurrent rseq registrations.
const _MAX_RSEQ_REGISTRATIONS: usize = 256;

/// Signature value that must match for valid registration.
const _RSEQ_SIG: u32 = 0x5305_3053;

/// Flag indicating an unregister operation.
const _RSEQ_FLAG_UNREGISTER: u32 = 1;

/// Critical section flag: do not restart on preemption.
const _RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT: u32 = 1;

/// Critical section flag: do not restart on signal delivery.
const _RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL: u32 = 2;

/// Critical section flag: do not restart on CPU migration.
const _RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE: u32 = 4;

/// Describes a restartable critical section.
///
/// This structure is laid out in C representation so it can be
/// shared between user space and the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RseqCs {
    /// Structure version (currently 0).
    pub version: u32,
    /// Flags controlling restart behavior.
    pub flags: u32,
    /// Instruction pointer where the critical section starts.
    pub start_ip: u64,
    /// Offset from `start_ip` to the post-commit instruction.
    pub post_commit_offset: u32,
    /// Instruction pointer of the abort handler.
    pub abort_ip: u64,
}

impl RseqCs {
    /// Returns the end instruction pointer of the critical
    /// section (start_ip + post_commit_offset).
    pub fn end_ip(&self) -> u64 {
        self.start_ip.wrapping_add(self.post_commit_offset as u64)
    }

    /// Returns `true` if this critical section descriptor is
    /// valid (non-zero range and abort_ip outside the section).
    pub fn is_valid(&self) -> bool {
        let end = self.end_ip();
        self.post_commit_offset > 0
            && end > self.start_ip
            && (self.abort_ip < self.start_ip || self.abort_ip >= end)
    }
}

/// State of an rseq registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RseqState {
    /// Thread has no active rseq registration.
    #[default]
    Unregistered,
    /// Thread is registered but not inside a critical section.
    Registered,
    /// Thread is inside a restartable critical section.
    InCritical,
}

/// Per-thread rseq registration record.
#[derive(Debug, Clone, Copy)]
pub struct RseqRegistration {
    /// Thread identifier that owns this registration.
    pub tid: u64,
    /// Currently active critical section descriptor, if any.
    pub rseq_cs: Option<RseqCs>,
    /// CPU on which this thread is currently running.
    pub cpu_id: u32,
    /// Current registration state.
    pub state: RseqState,
    /// Expected signature for validation.
    pub signature: u32,
    /// Whether this slot is actively in use.
    pub active: bool,
    /// Number of times this thread was preempted in a CS.
    pub preempt_count: u64,
    /// Number of signals delivered while in a CS.
    pub signal_count: u64,
    /// Number of CPU migrations while in a CS.
    pub migrate_count: u64,
}

impl Default for RseqRegistration {
    fn default() -> Self {
        Self::new()
    }
}

impl RseqRegistration {
    /// Creates an empty, inactive registration.
    const fn new() -> Self {
        Self {
            tid: 0,
            rseq_cs: None,
            cpu_id: 0,
            state: RseqState::Unregistered,
            signature: 0,
            active: false,
            preempt_count: 0,
            signal_count: 0,
            migrate_count: 0,
        }
    }
}

/// Registry managing all rseq registrations system-wide.
pub struct RseqRegistry {
    /// Fixed-size array of registration slots.
    registrations: [RseqRegistration; 256],
    /// Number of active registrations.
    count: usize,
}

impl Default for RseqRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RseqRegistry {
    /// Creates an empty registry with no active registrations.
    pub const fn new() -> Self {
        Self {
            registrations: [RseqRegistration::new(); 256],
            count: 0,
        }
    }

    /// Registers a thread for rseq notifications.
    ///
    /// The signature must match [`_RSEQ_SIG`] for the
    /// registration to succeed.
    pub fn register(&mut self, tid: u64, sig: u32) -> Result<()> {
        if sig != _RSEQ_SIG {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate registration.
        for reg in &self.registrations {
            if reg.active && reg.tid == tid {
                return Err(Error::AlreadyExists);
            }
        }
        // Find a free slot.
        let slot = self
            .registrations
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = RseqRegistration {
            tid,
            rseq_cs: None,
            cpu_id: 0,
            state: RseqState::Registered,
            signature: sig,
            active: true,
            preempt_count: 0,
            signal_count: 0,
            migrate_count: 0,
        };
        self.count += 1;
        Ok(())
    }

    /// Unregisters a thread from rseq notifications.
    pub fn unregister(&mut self, tid: u64) -> Result<()> {
        let reg = self.find_mut(tid)?;
        reg.active = false;
        reg.state = RseqState::Unregistered;
        reg.rseq_cs = None;
        self.count -= 1;
        Ok(())
    }

    /// Sets the active critical section for a registered thread.
    pub fn set_critical_section(&mut self, tid: u64, cs: RseqCs) -> Result<()> {
        if !cs.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let reg = self.find_mut(tid)?;
        reg.rseq_cs = Some(cs);
        reg.state = RseqState::InCritical;
        Ok(())
    }

    /// Clears the active critical section for a registered
    /// thread, returning it to the `Registered` state.
    pub fn clear_critical_section(&mut self, tid: u64) -> Result<()> {
        let reg = self.find_mut(tid)?;
        reg.rseq_cs = None;
        reg.state = RseqState::Registered;
        Ok(())
    }

    /// Handles a preemption event for the given thread.
    ///
    /// If the thread is inside a critical section (and the
    /// section does not have `NO_RESTART_ON_PREEMPT` set),
    /// returns `Some(abort_ip)` so the scheduler can redirect
    /// execution to the abort handler.
    pub fn on_preempt(&mut self, tid: u64) -> Option<u64> {
        let reg = self.find_mut(tid).ok()?;
        if reg.state != RseqState::InCritical {
            return None;
        }
        let cs = reg.rseq_cs?;
        reg.preempt_count += 1;
        if cs.flags & _RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT != 0 {
            return None;
        }
        reg.state = RseqState::Registered;
        reg.rseq_cs = None;
        Some(cs.abort_ip)
    }

    /// Handles a signal delivery event for the given thread.
    ///
    /// If the thread is inside a critical section (and the
    /// section does not have `NO_RESTART_ON_SIGNAL` set),
    /// returns `Some(abort_ip)`.
    pub fn on_signal(&mut self, tid: u64) -> Option<u64> {
        let reg = self.find_mut(tid).ok()?;
        if reg.state != RseqState::InCritical {
            return None;
        }
        let cs = reg.rseq_cs?;
        reg.signal_count += 1;
        if cs.flags & _RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL != 0 {
            return None;
        }
        reg.state = RseqState::Registered;
        reg.rseq_cs = None;
        Some(cs.abort_ip)
    }

    /// Handles a CPU migration event for the given thread.
    ///
    /// Updates the thread's CPU id and, if it is inside a
    /// critical section (without `NO_RESTART_ON_MIGRATE`),
    /// returns `Some(abort_ip)`.
    pub fn on_migrate(&mut self, tid: u64, new_cpu: u32) -> Option<u64> {
        let reg = self.find_mut(tid).ok()?;
        reg.cpu_id = new_cpu;
        if reg.state != RseqState::InCritical {
            return None;
        }
        let cs = reg.rseq_cs?;
        reg.migrate_count += 1;
        if cs.flags & _RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE != 0 {
            return None;
        }
        reg.state = RseqState::Registered;
        reg.rseq_cs = None;
        Some(cs.abort_ip)
    }

    /// Updates the current CPU id for a registered thread.
    pub fn update_cpu(&mut self, tid: u64, cpu: u32) {
        if let Ok(reg) = self.find_mut(tid) {
            reg.cpu_id = cpu;
        }
    }

    /// Returns the current CPU id for a registered thread,
    /// or `None` if the thread is not registered.
    pub fn get_cpu(&self, tid: u64) -> Option<u32> {
        self.find(tid).map(|r| r.cpu_id)
    }

    /// Returns `true` if the given thread is registered.
    pub fn is_registered(&self, tid: u64) -> bool {
        self.find(tid).is_some()
    }

    /// Returns the number of active registrations.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active registrations.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds an active registration by thread id (immutable).
    fn find(&self, tid: u64) -> Option<&RseqRegistration> {
        self.registrations.iter().find(|r| r.active && r.tid == tid)
    }

    /// Finds an active registration by thread id (mutable).
    fn find_mut(&mut self, tid: u64) -> Result<&mut RseqRegistration> {
        self.registrations
            .iter_mut()
            .find(|r| r.active && r.tid == tid)
            .ok_or(Error::NotFound)
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thread representation and state management.

use crate::pid::{Pid, Tid};

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Ready to be scheduled.
    Ready,
    /// Currently running on a CPU.
    Running,
    /// Blocked waiting for an event (IPC, timer, etc.).
    Blocked,
    /// Thread has exited and is awaiting cleanup.
    Exited,
}

/// Thread priority level (0 = highest, 255 = lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(u8);

impl Priority {
    /// Highest priority (real-time / kernel threads).
    pub const HIGHEST: Self = Self(0);
    /// Normal user-space priority.
    pub const NORMAL: Self = Self(128);
    /// Lowest priority (idle).
    pub const IDLE: Self = Self(255);

    /// Create a priority from a raw value.
    pub const fn new(level: u8) -> Self {
        Self(level)
    }

    /// Return the raw priority value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// A kernel thread.
///
/// Each thread belongs to exactly one process and maintains its own
/// execution context (register state, stack pointer, etc.).
#[derive(Debug)]
pub struct Thread {
    /// Thread identifier.
    tid: Tid,
    /// Owning process.
    pid: Pid,
    /// Current execution state.
    state: ThreadState,
    /// Scheduling priority.
    priority: Priority,
    /// Stack pointer (saved during context switch).
    stack_pointer: u64,
    /// Thread-local storage base address (FS base on x86_64).
    ///
    /// Set via `arch_prctl(ARCH_SET_FS, addr)` or `clone(CLONE_SETTLS)`.
    /// The hardware FS segment base is loaded from this field on
    /// context switch, enabling `__thread` / TLS access in user space.
    tls_base: u64,
}

impl Thread {
    /// Create a new thread in the Ready state.
    pub const fn new(tid: Tid, pid: Pid, priority: Priority) -> Self {
        Self {
            tid,
            pid,
            state: ThreadState::Ready,
            priority,
            stack_pointer: 0,
            tls_base: 0,
        }
    }

    /// Return the thread ID.
    pub const fn tid(&self) -> Tid {
        self.tid
    }

    /// Return the owning process ID.
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Return the current thread state.
    pub const fn state(&self) -> ThreadState {
        self.state
    }

    /// Return the scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Set the thread state.
    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Set the saved stack pointer.
    pub fn set_stack_pointer(&mut self, sp: u64) {
        self.stack_pointer = sp;
    }

    /// Get the saved stack pointer.
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    /// Set the TLS base address.
    pub fn set_tls_base(&mut self, addr: u64) {
        self.tls_base = addr;
    }

    /// Get the TLS base address.
    pub const fn tls_base(&self) -> u64 {
        self.tls_base
    }
}

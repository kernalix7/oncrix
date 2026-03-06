// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process forking (creating a child process).
//!
//! `fork()` creates a near-identical copy of the calling process.
//! The child gets a new PID and its own address space. In a full
//! implementation, pages are shared copy-on-write (CoW) and only
//! duplicated on first write.
//!
//! This module provides the process-level fork logic. The kernel
//! is responsible for the actual page table duplication and context
//! setup.

use crate::pid::{Pid, Tid, alloc_pid, alloc_tid};
use crate::process::Process;
use crate::thread::{Priority, Thread};
use oncrix_lib::Result;

/// Information returned after a successful fork.
#[derive(Debug, Clone, Copy)]
pub struct ForkResult {
    /// PID of the child process.
    pub child_pid: Pid,
    /// TID of the child's first thread.
    pub child_tid: Tid,
}

/// Fork a process: create a child Process and its first Thread.
///
/// The caller is responsible for:
/// 1. Duplicating the address space (page tables, CoW mappings)
/// 2. Copying the parent's CPU context for the child thread
/// 3. Setting up the child's return value (0 in RAX)
/// 4. Adding the child thread to the scheduler
pub fn fork_process(
    parent: &Process,
    parent_priority: Priority,
) -> Result<(ForkResult, Process, Thread)> {
    let child_pid = alloc_pid();
    let child_tid = alloc_tid();

    // Create the child process.
    let mut child = Process::new(child_pid);
    child.add_thread(child_tid)?;

    // Create the child's first thread (inherits parent's priority).
    let child_thread = Thread::new(child_tid, child_pid, parent_priority);

    let result = ForkResult {
        child_pid,
        child_tid,
    };

    // Suppress unused-variable warning for parent — it will be used
    // when we implement fd table and signal mask inheritance.
    let _ = parent;

    Ok((result, child, child_thread))
}

/// Copy-on-Write page state for a single page frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowState {
    /// Page is shared read-only between parent and child.
    /// The reference count tracks how many processes share it.
    Shared(u16),
    /// Page is exclusively owned (writable).
    Exclusive,
}

/// Per-frame CoW reference tracker.
///
/// Tracks which physical frames are shared between forked processes.
/// When a process writes to a shared page, the page fault handler
/// copies the frame and marks the new copy as exclusive.
pub struct CowTracker {
    /// Frame states indexed by frame number.
    states: [CowState; Self::MAX_TRACKED],
    /// Number of tracked frames.
    count: usize,
}

impl CowTracker {
    /// Maximum number of frames we can track.
    const MAX_TRACKED: usize = 4096;

    /// Create an empty CoW tracker.
    pub const fn new() -> Self {
        Self {
            states: [CowState::Exclusive; Self::MAX_TRACKED],
            count: 0,
        }
    }

    /// Mark a frame as shared between two processes.
    ///
    /// Returns the new reference count.
    pub fn share(&mut self, frame_idx: usize) -> Option<u16> {
        if frame_idx >= Self::MAX_TRACKED {
            return None;
        }
        let new_count = match self.states[frame_idx] {
            CowState::Exclusive => {
                self.count += 1;
                2
            }
            CowState::Shared(n) => n.saturating_add(1),
        };
        self.states[frame_idx] = CowState::Shared(new_count);
        Some(new_count)
    }

    /// Decrement the reference count when a process copies a page.
    ///
    /// Returns the new reference count. If it reaches 1, the
    /// remaining owner can be upgraded to exclusive.
    pub fn unshare(&mut self, frame_idx: usize) -> Option<u16> {
        if frame_idx >= Self::MAX_TRACKED {
            return None;
        }
        match self.states[frame_idx] {
            CowState::Shared(n) if n > 2 => {
                let new = n - 1;
                self.states[frame_idx] = CowState::Shared(new);
                Some(new)
            }
            CowState::Shared(_) => {
                // Down to 1 reference — mark as exclusive.
                self.states[frame_idx] = CowState::Exclusive;
                self.count = self.count.saturating_sub(1);
                Some(1)
            }
            CowState::Exclusive => Some(1),
        }
    }

    /// Check the state of a frame.
    pub fn state(&self, frame_idx: usize) -> CowState {
        if frame_idx >= Self::MAX_TRACKED {
            return CowState::Exclusive;
        }
        self.states[frame_idx]
    }

    /// Return the number of shared frames.
    pub fn shared_count(&self) -> usize {
        self.count
    }
}

impl Default for CowTracker {
    fn default() -> Self {
        Self::new()
    }
}

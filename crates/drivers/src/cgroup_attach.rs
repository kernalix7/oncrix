// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup process attachment and migration adapter.
//!
//! Implements the cgroup controller-side logic for attaching tasks to
//! cgroups, migrating tasks between cgroups, and driving the
//! can_attach / cancel_attach / post_attach lifecycle callbacks that
//! each cgroup controller subsystem must support.
//!
//! This module acts as a cgroup controller adapter; it does not own the
//! actual task or cgroup data structures (those live in `crates/kernel/`),
//! but provides the type definitions and registry machinery used by
//! individual subsystem controllers to participate in task migration.
//!
//! # Architecture
//!
//! - [`AttachOps`] — trait with `can_attach`, `cancel_attach`, and
//!   `post_attach` callbacks, implemented per controller.
//! - [`MigrateCtx`] — context describing a pending task migration.
//! - [`CtrlEntry`] — one registered controller participating in attach.
//! - [`CgroupAttach`] — orchestrator driving the multi-controller
//!   attach protocol, including threadgroup migration.
//!
//! Reference: Linux `kernel/cgroup/cgroup.c` (cgroup_attach_task,
//! cgroup_migrate_execute).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of controllers registered in the adapter.
const MAX_CONTROLLERS: usize = 16;
/// Maximum name length for a controller or cgroup.
const NAME_LEN: usize = 32;
/// Maximum tasks in a single migration context (threadgroup size limit).
const MAX_TASKS: usize = 64;

// ---------------------------------------------------------------------------
// NameBuf
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct NameBuf {
    bytes: [u8; NAME_LEN],
    len: usize,
}

impl NameBuf {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; NAME_LEN],
            len: 0,
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; NAME_LEN];
        buf[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes: buf,
            len: b.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn matches_str(&self, s: &str) -> bool {
        self.as_bytes() == s.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// AttachOps — per-controller callback trait
// ---------------------------------------------------------------------------

/// Callbacks that a cgroup controller must implement to participate in
/// task attachment and migration.
///
/// The attach protocol is:
/// 1. `can_attach` — called for each controller; returns `Ok(())` or an
///    error. If any controller rejects, the attach is aborted and
///    `cancel_attach` is called on all controllers that previously
///    returned `Ok`.
/// 2. `post_attach` — called for each controller once all `can_attach`
///    checks have passed and the task has been moved in the task table.
pub trait AttachOps {
    /// Checks whether the migration described by `ctx` is permitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] or another error if the
    /// controller rejects the migration.
    fn can_attach(&self, ctx: &MigrateCtx) -> Result<()>;

    /// Rolls back any preparatory work done in `can_attach`.
    ///
    /// Called when a later controller rejects the migration after this
    /// controller already returned `Ok` from `can_attach`.
    fn cancel_attach(&self, ctx: &MigrateCtx);

    /// Completes the migration from the controller's perspective.
    ///
    /// Called after the task has been successfully moved in the task table.
    fn post_attach(&mut self, ctx: &MigrateCtx);
}

// ---------------------------------------------------------------------------
// MigrateCtx
// ---------------------------------------------------------------------------

/// Context describing a pending or completed cgroup task migration.
#[derive(Clone, Copy)]
pub struct MigrateCtx {
    /// Process ID of the task being migrated (or thread-group leader).
    pub pid: u32,
    /// Cgroup ID from which the task is migrating.
    pub src_cgroup_id: u32,
    /// Cgroup ID to which the task is migrating.
    pub dst_cgroup_id: u32,
    /// Number of PIDs in the threadgroup migration set (`tids` prefix).
    pub thread_count: usize,
    /// PID array for threadgroup migration (valid up to `thread_count`).
    pub tids: [u32; MAX_TASKS],
    /// Whether this is a threadgroup migration (all threads move together).
    pub threadgroup: bool,
}

impl MigrateCtx {
    /// Creates a context for migrating a single task.
    pub fn single(pid: u32, src: u32, dst: u32) -> Self {
        let mut ctx = Self {
            pid,
            src_cgroup_id: src,
            dst_cgroup_id: dst,
            thread_count: 1,
            tids: [0u32; MAX_TASKS],
            threadgroup: false,
        };
        ctx.tids[0] = pid;
        ctx
    }

    /// Creates a context for migrating a threadgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `tids` is empty or longer
    /// than [`MAX_TASKS`].
    pub fn threadgroup(leader_pid: u32, src: u32, dst: u32, tids: &[u32]) -> Result<Self> {
        if tids.is_empty() || tids.len() > MAX_TASKS {
            return Err(Error::InvalidArgument);
        }
        let mut ctx = Self {
            pid: leader_pid,
            src_cgroup_id: src,
            dst_cgroup_id: dst,
            thread_count: tids.len(),
            tids: [0u32; MAX_TASKS],
            threadgroup: true,
        };
        ctx.tids[..tids.len()].copy_from_slice(tids);
        Ok(ctx)
    }

    /// Returns the slice of task IDs being migrated.
    pub fn tasks(&self) -> &[u32] {
        &self.tids[..self.thread_count]
    }
}

// ---------------------------------------------------------------------------
// AttachResult — outcome per controller during a migration
// ---------------------------------------------------------------------------

/// Result of a `can_attach` call for a single controller.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachResult {
    /// Not yet called.
    Pending,
    /// `can_attach` returned `Ok(())`.
    Accepted,
    /// `can_attach` returned an error.
    Rejected,
}

// ---------------------------------------------------------------------------
// CtrlEntry
// ---------------------------------------------------------------------------

/// A registered cgroup controller participating in task attachment.
pub struct CtrlEntry {
    /// Controller subsystem ID (unique per registration).
    pub id: u32,
    /// Subsystem name (e.g., "memory", "cpu", "pids").
    name: NameBuf,
    /// Whether this controller slot is active.
    pub active: bool,
}

const EMPTY_CTRL: CtrlEntry = CtrlEntry {
    id: 0,
    name: NameBuf {
        bytes: [0u8; NAME_LEN],
        len: 0,
    },
    active: false,
};

impl CtrlEntry {
    /// Creates a new controller entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(id: u32, name: &str) -> Result<Self> {
        Ok(Self {
            id,
            name: NameBuf::from_str(name)?,
            active: true,
        })
    }

    /// Returns the controller name as a byte slice.
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// CgroupAttach
// ---------------------------------------------------------------------------

/// Orchestrator for the multi-controller cgroup attach protocol.
///
/// Drives `can_attach` → `post_attach` (or `cancel_attach` on failure)
/// across all registered controllers for a given [`MigrateCtx`].
///
/// Individual controller implementations are passed as closures or
/// objects implementing [`AttachOps`] at call sites; the registry holds
/// only the metadata entries.
pub struct CgroupAttach {
    /// Registered controller metadata.
    ctrls: [CtrlEntry; MAX_CONTROLLERS],
    /// Number of registered controllers.
    ctrl_count: usize,
    /// Total successful attaches performed.
    pub attach_count: u64,
    /// Total cancelled (failed) attaches.
    pub cancel_count: u64,
}

impl CgroupAttach {
    /// Creates an empty attachment orchestrator.
    pub const fn new() -> Self {
        Self {
            ctrls: [EMPTY_CTRL; MAX_CONTROLLERS],
            ctrl_count: 0,
            attach_count: 0,
            cancel_count: 0,
        }
    }

    /// Registers a controller entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if a controller with the same ID
    /// is already registered, or [`Error::OutOfMemory`] if the table is full.
    pub fn register_controller(&mut self, entry: CtrlEntry) -> Result<()> {
        for c in &self.ctrls[..self.ctrl_count] {
            if c.id == entry.id && c.active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.ctrl_count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.ctrls[self.ctrl_count] = entry;
        self.ctrl_count += 1;
        Ok(())
    }

    /// Unregisters a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the controller is not registered.
    pub fn unregister_controller(&mut self, id: u32) -> Result<()> {
        let idx = self.ctrl_index(id)?;
        let last = self.ctrl_count - 1;
        if idx != last {
            self.ctrls.swap(idx, last);
        }
        self.ctrls[last] = EMPTY_CTRL;
        self.ctrl_count -= 1;
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn controller_count(&self) -> usize {
        self.ctrl_count
    }

    /// Finds a controller by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no match exists.
    pub fn find_by_name(&self, name: &str) -> Result<&CtrlEntry> {
        self.ctrls[..self.ctrl_count]
            .iter()
            .find(|c| c.active && c.name.matches_str(name))
            .ok_or(Error::NotFound)
    }

    /// Executes the full attach protocol for `ctx` against `ops`.
    ///
    /// The `ops` slice must contain one [`AttachOps`] implementation per
    /// registered active controller, in registration order.
    ///
    /// Protocol:
    /// 1. Call `can_attach` on each controller in order.
    /// 2. On the first rejection, call `cancel_attach` on all controllers
    ///    that previously accepted, then return the error.
    /// 3. On full acceptance, call `post_attach` on every controller.
    ///
    /// # Errors
    ///
    /// Returns the first error returned by a `can_attach` call.
    pub fn attach<O: AttachOps>(&mut self, ctx: &MigrateCtx, ops: &mut [O]) -> Result<()> {
        let n = self.ctrl_count.min(ops.len());
        let mut results = [AttachResult::Pending; MAX_CONTROLLERS];

        // Phase 1: can_attach.
        let mut failed_at = None;
        for i in 0..n {
            if !self.ctrls[i].active {
                results[i] = AttachResult::Accepted;
                continue;
            }
            match ops[i].can_attach(ctx) {
                Ok(()) => results[i] = AttachResult::Accepted,
                Err(e) => {
                    results[i] = AttachResult::Rejected;
                    failed_at = Some((i, e));
                    break;
                }
            }
        }

        if let Some((fail_idx, err)) = failed_at {
            // Phase 1b: cancel_attach for all previously accepted.
            for i in 0..fail_idx {
                if results[i] == AttachResult::Accepted {
                    ops[i].cancel_attach(ctx);
                }
            }
            self.cancel_count = self.cancel_count.saturating_add(1);
            return Err(err);
        }

        // Phase 2: post_attach.
        for i in 0..n {
            if results[i] == AttachResult::Accepted {
                ops[i].post_attach(ctx);
            }
        }
        self.attach_count = self.attach_count.saturating_add(1);
        Ok(())
    }

    /// Performs a threadgroup migration: builds a [`MigrateCtx`] for the
    /// entire thread list and runs the attach protocol.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`MigrateCtx::threadgroup`] or [`Self::attach`].
    pub fn migrate_threadgroup<O: AttachOps>(
        &mut self,
        leader: u32,
        src: u32,
        dst: u32,
        tids: &[u32],
        ops: &mut [O],
    ) -> Result<()> {
        let ctx = MigrateCtx::threadgroup(leader, src, dst, tids)?;
        self.attach(&ctx, ops)
    }

    /// Handles a `cgroup.procs` write, attaching a single task.
    ///
    /// `pid` is the task to move; `src_cgroup_id` and `dst_cgroup_id`
    /// describe the migration direction.
    ///
    /// # Errors
    ///
    /// Propagates errors from `attach`.
    pub fn procs_write<O: AttachOps>(
        &mut self,
        pid: u32,
        src_cgroup_id: u32,
        dst_cgroup_id: u32,
        ops: &mut [O],
    ) -> Result<()> {
        let ctx = MigrateCtx::single(pid, src_cgroup_id, dst_cgroup_id);
        self.attach(&ctx, ops)
    }

    // -- internal -----------------------------------------------------------

    fn ctrl_index(&self, id: u32) -> Result<usize> {
        self.ctrls[..self.ctrl_count]
            .iter()
            .position(|c| c.id == id && c.active)
            .ok_or(Error::NotFound)
    }
}

impl Default for CgroupAttach {
    fn default() -> Self {
        Self::new()
    }
}

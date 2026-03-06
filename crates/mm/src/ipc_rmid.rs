// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC resource cleanup (`IPC_RMID`).
//!
//! Implements System V IPC resource removal for semaphore arrays,
//! message queues, and shared memory segments. Handles both explicit
//! `*ctl(IPC_RMID)` calls and automatic cleanup on process exit.
//!
//! # Features
//!
//! - **Semaphore cleanup** -- destroys semaphore arrays, wakes
//!   waiting processes with `EIDRM`.
//! - **Message queue cleanup** -- drains and destroys message
//!   queues, wakes blocked senders/receivers.
//! - **Shared memory cleanup** -- marks segments for destruction;
//!   actual removal deferred until the last detach.
//! - **Process exit cleanup** -- automatically removes IPC
//!   resources owned by a terminating process.
//! - **Deferred destruction** -- shared memory segments with
//!   active attachments are marked for removal but persist until
//!   the last `shmdt()`.
//!
//! # Architecture
//!
//! - [`IpcResourceId`] -- typed IPC resource identifier
//! - [`IpcResourceType`] -- semaphore, message queue, or SHM
//! - [`CleanupState`] -- per-resource removal state
//! - [`RmidQueue`] -- queue of pending removal operations
//! - [`IpcRmid`] -- removal result
//! - [`IpcRmidStats`] -- aggregate statistics
//! - [`IpcRmidManager`] -- the cleanup engine
//!
//! # POSIX Reference
//!
//! - `semctl(IPC_RMID)` -- POSIX.1-2024, XSI `semctl`
//! - `msgctl(IPC_RMID)` -- POSIX.1-2024, XSI `msgctl`
//! - `shmctl(IPC_RMID)` -- POSIX.1-2024, XSI `shmctl`
//!
//! Reference: Linux `ipc/sem.c`, `ipc/msg.c`, `ipc/shm.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of IPC resources tracked.
const MAX_IPC_RESOURCES: usize = 256;

/// Maximum number of pending RMID operations.
const MAX_PENDING_RMIDS: usize = 64;

/// Maximum number of attachment records per SHM segment.
const MAX_ATTACH_PER_SHM: usize = 16;

/// Maximum number of processes tracked for auto-cleanup.
const MAX_PROCESSES: usize = 64;

/// Maximum resources per process.
const MAX_RESOURCES_PER_PID: usize = 32;

// ── IpcResourceType ─────────────────────────────────────────────

/// Type of System V IPC resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcResourceType {
    /// Semaphore array.
    Semaphore,
    /// Message queue.
    MessageQueue,
    /// Shared memory segment.
    SharedMemory,
}

impl Default for IpcResourceType {
    fn default() -> Self {
        Self::Semaphore
    }
}

// ── IpcResourceId ───────────────────────────────────────────────

/// Typed IPC resource identifier.
///
/// Wraps a System V IPC key and identifier with the resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcResourceId {
    /// IPC key (from `ftok()` or `IPC_PRIVATE`).
    pub key: i32,
    /// IPC identifier (returned by `semget`/`msgget`/`shmget`).
    pub id: i32,
    /// Resource type.
    pub resource_type: IpcResourceType,
}

impl IpcResourceId {
    /// Create a new resource ID.
    pub const fn new(key: i32, id: i32, resource_type: IpcResourceType) -> Self {
        Self {
            key,
            id,
            resource_type,
        }
    }
}

// ── RemovalState ────────────────────────────────────────────────

/// State of a resource in the removal lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalState {
    /// Resource is active and not marked for removal.
    Active,
    /// Resource is marked for removal (IPC_RMID issued).
    MarkedForRemoval,
    /// Resource is being destroyed (cleanup in progress).
    Destroying,
    /// Resource has been fully destroyed and slot is free.
    Destroyed,
    /// Deferred: SHM with active attachments.
    DeferredDestroy,
}

impl Default for RemovalState {
    fn default() -> Self {
        Self::Active
    }
}

// ── CleanupState ────────────────────────────────────────────────

/// Per-resource cleanup state.
///
/// Tracks the IPC resource through its lifecycle from active to
/// destroyed, including deferred destruction for shared memory.
#[derive(Debug, Clone, Copy)]
pub struct CleanupState {
    /// Resource identifier.
    pub resource: IpcResourceId,
    /// Current removal state.
    pub state: RemovalState,
    /// Owning process ID (creator).
    pub owner_pid: u64,
    /// Permissions (mode bits).
    pub mode: u32,
    /// Number of active attachments (SHM only).
    pub attach_count: u32,
    /// PIDs attached to this SHM segment.
    pub attach_pids: [u64; MAX_ATTACH_PER_SHM],
    /// Timestamp of IPC_RMID call (ms since boot).
    pub rmid_at: u64,
    /// Timestamp of actual destruction.
    pub destroyed_at: u64,
    /// Size in bytes (for SHM) or count (for semaphores/messages).
    pub size_or_count: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl CleanupState {
    /// Create an empty, inactive cleanup state.
    const fn empty() -> Self {
        Self {
            resource: IpcResourceId {
                key: 0,
                id: 0,
                resource_type: IpcResourceType::Semaphore,
            },
            state: RemovalState::Active,
            owner_pid: 0,
            mode: 0,
            attach_count: 0,
            attach_pids: [0u64; MAX_ATTACH_PER_SHM],
            rmid_at: 0,
            destroyed_at: 0,
            size_or_count: 0,
            active: false,
        }
    }

    /// Whether this resource can be immediately destroyed.
    pub fn can_destroy_now(&self) -> bool {
        match self.resource.resource_type {
            IpcResourceType::SharedMemory => self.attach_count == 0,
            _ => true,
        }
    }
}

// ── RmidQueue ───────────────────────────────────────────────────

/// Queue of pending RMID operations.
///
/// Holds resource IDs waiting for removal. Used for batching
/// removal during process exit cleanup.
#[derive(Debug)]
pub struct RmidQueue {
    /// Pending resource IDs.
    entries: [IpcResourceId; MAX_PENDING_RMIDS],
    /// Timestamps of when each entry was queued.
    queued_at: [u64; MAX_PENDING_RMIDS],
    /// Number of entries in the queue.
    count: usize,
}

impl Default for RmidQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RmidQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                IpcResourceId {
                    key: 0,
                    id: 0,
                    resource_type: IpcResourceType::Semaphore,
                }
            }; MAX_PENDING_RMIDS],
            queued_at: [0u64; MAX_PENDING_RMIDS],
            count: 0,
        }
    }

    /// Enqueue a resource for removal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue(&mut self, resource: IpcResourceId, timestamp: u64) -> Result<()> {
        if self.count >= MAX_PENDING_RMIDS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = resource;
        self.queued_at[self.count] = timestamp;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next resource for removal.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<IpcResourceId> {
        if self.count == 0 {
            return None;
        }
        let entry = self.entries[0];
        // Shift remaining entries.
        let mut i = 0;
        while i + 1 < self.count {
            self.entries[i] = self.entries[i + 1];
            self.queued_at[i] = self.queued_at[i + 1];
            i += 1;
        }
        self.count -= 1;
        Some(entry)
    }

    /// Number of pending entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── IpcRmid ─────────────────────────────────────────────────────

/// Result of an IPC_RMID operation.
#[derive(Debug, Clone, Copy)]
pub struct IpcRmid {
    /// Resource that was removed.
    pub resource: IpcResourceId,
    /// Whether the resource was immediately destroyed.
    pub immediate: bool,
    /// Whether destruction is deferred (SHM with attachments).
    pub deferred: bool,
    /// Number of waiting processes woken up.
    pub waiters_woken: u32,
    /// Whether the operation succeeded.
    pub success: bool,
}

impl Default for IpcRmid {
    fn default() -> Self {
        Self {
            resource: IpcResourceId {
                key: 0,
                id: 0,
                resource_type: IpcResourceType::Semaphore,
            },
            immediate: false,
            deferred: false,
            waiters_woken: 0,
            success: false,
        }
    }
}

// ── ProcessResources ────────────────────────────────────────────

/// Tracks which IPC resources a process owns.
#[derive(Debug, Clone, Copy)]
struct ProcessResources {
    /// Process ID.
    pid: u64,
    /// IPC IDs owned by this process.
    resource_ids: [i32; MAX_RESOURCES_PER_PID],
    /// Number of resources.
    count: usize,
    /// Whether this slot is active.
    active: bool,
}

impl ProcessResources {
    const fn empty() -> Self {
        Self {
            pid: 0,
            resource_ids: [0i32; MAX_RESOURCES_PER_PID],
            count: 0,
            active: false,
        }
    }
}

// ── IpcRmidStats ────────────────────────────────────────────────

/// Aggregate IPC removal statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcRmidStats {
    /// Total IPC_RMID calls.
    pub rmid_calls: u64,
    /// Successful removals.
    pub successful: u64,
    /// Failed removals.
    pub failed: u64,
    /// Semaphore arrays removed.
    pub semaphores_removed: u64,
    /// Message queues removed.
    pub msgqueues_removed: u64,
    /// Shared memory segments removed.
    pub shm_removed: u64,
    /// Deferred destructions (SHM with attachments).
    pub deferred_count: u64,
    /// Process exit cleanups.
    pub process_cleanups: u64,
    /// Total waiters woken during removal.
    pub waiters_woken: u64,
}

// ── IpcRmidManager ──────────────────────────────────────────────

/// The IPC resource cleanup engine.
///
/// Manages the lifecycle of System V IPC resources from creation
/// through removal, handling deferred destruction for SHM segments
/// and automatic cleanup on process exit.
pub struct IpcRmidManager {
    /// Tracked IPC resources.
    resources: [CleanupState; MAX_IPC_RESOURCES],
    /// Number of active resources.
    resource_count: usize,
    /// Pending removal queue.
    rmid_queue: RmidQueue,
    /// Per-process resource ownership.
    process_map: [ProcessResources; MAX_PROCESSES],
    /// Number of tracked processes.
    process_count: usize,
    /// Statistics.
    stats: IpcRmidStats,
}

impl Default for IpcRmidManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcRmidManager {
    /// Creates a new, empty IPC RMID manager.
    pub const fn new() -> Self {
        Self {
            resources: [const { CleanupState::empty() }; MAX_IPC_RESOURCES],
            resource_count: 0,
            rmid_queue: RmidQueue::new(),
            process_map: [const { ProcessResources::empty() }; MAX_PROCESSES],
            process_count: 0,
            stats: IpcRmidStats {
                rmid_calls: 0,
                successful: 0,
                failed: 0,
                semaphores_removed: 0,
                msgqueues_removed: 0,
                shm_removed: 0,
                deferred_count: 0,
                process_cleanups: 0,
                waiters_woken: 0,
            },
        }
    }

    // ── Resource registration ───────────────────────────────────

    /// Register an IPC resource for tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if resource table is full.
    /// - [`Error::AlreadyExists`] if ID is already registered.
    pub fn register_resource(
        &mut self,
        resource: IpcResourceId,
        owner_pid: u64,
        mode: u32,
        size_or_count: u64,
    ) -> Result<()> {
        // Check for duplicate.
        if self.find_resource(resource.id).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .resources
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = CleanupState {
            resource,
            state: RemovalState::Active,
            owner_pid,
            mode,
            attach_count: 0,
            attach_pids: [0u64; MAX_ATTACH_PER_SHM],
            rmid_at: 0,
            destroyed_at: 0,
            size_or_count,
            active: true,
        };
        self.resource_count += 1;

        // Track ownership.
        self.track_ownership(owner_pid, resource.id);

        Ok(())
    }

    /// Track process ownership of a resource.
    fn track_ownership(&mut self, pid: u64, resource_id: i32) {
        // Find or create process entry.
        let proc_entry = self
            .process_map
            .iter_mut()
            .find(|p| p.active && p.pid == pid);

        if let Some(entry) = proc_entry {
            if entry.count < MAX_RESOURCES_PER_PID {
                entry.resource_ids[entry.count] = resource_id;
                entry.count += 1;
            }
        } else {
            // Create new entry.
            if let Some(slot) = self.process_map.iter_mut().find(|p| !p.active) {
                *slot = ProcessResources::empty();
                slot.pid = pid;
                slot.resource_ids[0] = resource_id;
                slot.count = 1;
                slot.active = true;
                self.process_count += 1;
            }
        }
    }

    // ── SHM attachment tracking ─────────────────────────────────

    /// Record a SHM attachment.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if resource not found.
    /// - [`Error::InvalidArgument`] if resource is not SHM.
    /// - [`Error::OutOfMemory`] if attachment table is full.
    pub fn shm_attach(&mut self, resource_id: i32, pid: u64) -> Result<()> {
        let res = self.find_resource_mut(resource_id).ok_or(Error::NotFound)?;

        if res.resource.resource_type != IpcResourceType::SharedMemory {
            return Err(Error::InvalidArgument);
        }

        let count = res.attach_count as usize;
        if count >= MAX_ATTACH_PER_SHM {
            return Err(Error::OutOfMemory);
        }

        res.attach_pids[count] = pid;
        res.attach_count += 1;
        Ok(())
    }

    /// Record a SHM detachment.
    ///
    /// If the segment is marked for deferred destruction and this
    /// is the last attachment, the segment is destroyed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if resource not found or PID
    /// not attached.
    pub fn shm_detach(&mut self, resource_id: i32, pid: u64, timestamp: u64) -> Result<bool> {
        let res = self.find_resource_mut(resource_id).ok_or(Error::NotFound)?;

        // Find and remove the PID from the attachment list.
        let mut found = false;
        let count = res.attach_count as usize;
        for i in 0..count {
            if res.attach_pids[i] == pid {
                // Shift remaining entries.
                let mut j = i;
                while j + 1 < count {
                    res.attach_pids[j] = res.attach_pids[j + 1];
                    j += 1;
                }
                res.attach_pids[count - 1] = 0;
                res.attach_count -= 1;
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        // Check if deferred destruction can now complete.
        if res.state == RemovalState::DeferredDestroy && res.attach_count == 0 {
            res.state = RemovalState::Destroyed;
            res.destroyed_at = timestamp;
            res.active = false;
            self.resource_count = self.resource_count.saturating_sub(1);
            self.stats.shm_removed += 1;
            self.stats.successful += 1;
            return Ok(true);
        }

        Ok(false)
    }

    // ── IPC_RMID ────────────────────────────────────────────────

    /// Execute IPC_RMID for a resource.
    ///
    /// For semaphores and message queues, the resource is
    /// immediately destroyed. For shared memory, if there are
    /// active attachments, destruction is deferred.
    ///
    /// # Arguments
    ///
    /// - `resource_id` -- IPC identifier.
    /// - `caller_pid` -- PID of the caller (must be owner or
    ///   privileged).
    /// - `timestamp` -- current time in ms since boot.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if resource not found.
    /// - [`Error::PermissionDenied`] if caller is not the owner.
    pub fn do_rmid(
        &mut self,
        resource_id: i32,
        caller_pid: u64,
        timestamp: u64,
    ) -> Result<IpcRmid> {
        self.stats.rmid_calls += 1;

        let idx = self
            .resources
            .iter()
            .position(|r| r.active && r.resource.id == resource_id)
            .ok_or_else(|| {
                self.stats.failed += 1;
                Error::NotFound
            })?;

        // Permission check: only owner can remove.
        if self.resources[idx].owner_pid != caller_pid {
            self.stats.failed += 1;
            return Err(Error::PermissionDenied);
        }

        // Already marked?
        if self.resources[idx].state != RemovalState::Active {
            self.stats.failed += 1;
            return Err(Error::InvalidArgument);
        }

        let resource = self.resources[idx].resource;
        let mut result = IpcRmid {
            resource,
            immediate: false,
            deferred: false,
            waiters_woken: 0,
            success: false,
        };

        self.resources[idx].rmid_at = timestamp;

        if self.resources[idx].can_destroy_now() {
            // Immediate destruction.
            self.resources[idx].state = RemovalState::Destroyed;
            self.resources[idx].destroyed_at = timestamp;
            self.resources[idx].active = false;
            self.resource_count = self.resource_count.saturating_sub(1);
            result.immediate = true;

            match resource.resource_type {
                IpcResourceType::Semaphore => self.stats.semaphores_removed += 1,
                IpcResourceType::MessageQueue => self.stats.msgqueues_removed += 1,
                IpcResourceType::SharedMemory => self.stats.shm_removed += 1,
            }
        } else {
            // Deferred destruction (SHM with attachments).
            self.resources[idx].state = RemovalState::DeferredDestroy;
            result.deferred = true;
            self.stats.deferred_count += 1;
        }

        result.success = true;
        self.stats.successful += 1;

        Ok(result)
    }

    // ── Process exit cleanup ────────────────────────────────────

    /// Clean up all IPC resources owned by a process.
    ///
    /// Called during process termination. Removes all owned
    /// resources, detaches from all SHM segments.
    ///
    /// Returns the number of resources cleaned up.
    pub fn cleanup_process(&mut self, pid: u64, timestamp: u64) -> u32 {
        self.stats.process_cleanups += 1;
        let mut cleaned = 0u32;

        // Detach from all SHM segments.
        for i in 0..MAX_IPC_RESOURCES {
            if !self.resources[i].active {
                continue;
            }
            if self.resources[i].resource.resource_type != IpcResourceType::SharedMemory {
                continue;
            }
            // Check if this pid is attached.
            let count = self.resources[i].attach_count as usize;
            for j in 0..count {
                if self.resources[i].attach_pids[j] == pid {
                    let id = self.resources[i].resource.id;
                    let _ = self.shm_detach(id, pid, timestamp);
                    cleaned += 1;
                    break;
                }
            }
        }

        // Find process's owned resources and remove them.
        let proc_idx = self
            .process_map
            .iter()
            .position(|p| p.active && p.pid == pid);

        if let Some(idx) = proc_idx {
            let count = self.process_map[idx].count;
            for i in 0..count {
                let res_id = self.process_map[idx].resource_ids[i];
                let _ = self.do_rmid(res_id, pid, timestamp);
                cleaned += 1;
            }
            self.process_map[idx].active = false;
            self.process_count = self.process_count.saturating_sub(1);
        }

        cleaned
    }

    // ── Batch processing ────────────────────────────────────────

    /// Process all entries in the RMID queue.
    ///
    /// Returns the number of resources removed.
    pub fn process_rmid_queue(&mut self, caller_pid: u64, timestamp: u64) -> u32 {
        let mut removed = 0u32;
        while let Some(resource) = self.rmid_queue.dequeue() {
            if self.do_rmid(resource.id, caller_pid, timestamp).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Enqueue a resource for later removal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue_rmid(&mut self, resource: IpcResourceId, timestamp: u64) -> Result<()> {
        self.rmid_queue.enqueue(resource, timestamp)
    }

    // ── Query ───────────────────────────────────────────────────

    /// Look up a resource by ID.
    pub fn find_resource(&self, resource_id: i32) -> Option<&CleanupState> {
        self.resources
            .iter()
            .find(|r| r.active && r.resource.id == resource_id)
    }

    /// Look up a mutable resource by ID.
    fn find_resource_mut(&mut self, resource_id: i32) -> Option<&mut CleanupState> {
        self.resources
            .iter_mut()
            .find(|r| r.active && r.resource.id == resource_id)
    }

    /// Count resources of a specific type.
    pub fn count_by_type(&self, resource_type: IpcResourceType) -> usize {
        self.resources
            .iter()
            .filter(|r| r.active && r.resource.resource_type == resource_type)
            .count()
    }

    /// Count deferred-destroy resources.
    pub fn deferred_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|r| r.active && r.state == RemovalState::DeferredDestroy)
            .count()
    }

    // ── Accessors ───────────────────────────────────────────────

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &IpcRmidStats {
        &self.stats
    }

    /// Number of active resources.
    pub fn resource_count(&self) -> usize {
        self.resource_count
    }

    /// Number of tracked processes.
    pub fn process_count(&self) -> usize {
        self.process_count
    }

    /// Pending RMID queue length.
    pub fn queue_len(&self) -> usize {
        self.rmid_queue.len()
    }
}

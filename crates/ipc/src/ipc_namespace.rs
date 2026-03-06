// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC namespace isolation for container-style process separation.
//!
//! Provides per-namespace isolation for System V IPC objects (shared
//! memory, semaphores, message queues) and POSIX message queues.
//! Each namespace maintains its own ID spaces and resource limits,
//! preventing cross-namespace visibility.
//!
//! # Design
//!
//! - Up to [`NS_REGISTRY_MAX`] namespaces may exist concurrently.
//! - The initial namespace (ID 0) is pre-created and never destroyed.
//! - `clone_ipc_ns` copies resource limits and resets ID counters,
//!   implementing the `CLONE_NEWIPC` / `unshare(CLONE_NEWIPC)` path.
//!
//! # POSIX Reference
//!
//! Namespaces are a Linux extension; POSIX does not specify them.
//! SysV IPC limits follow the values described in
//! `.TheOpenGroup/susv5-html/functions/shmget.html` et al.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of IPC namespaces.
const NS_REGISTRY_MAX: usize = 32;

/// Maximum SysV shared memory segments per namespace.
pub const IPC_NS_SHM_SLOTS: usize = 128;

/// Maximum SysV semaphore sets per namespace.
pub const IPC_NS_SEM_SLOTS: usize = 128;

/// Maximum SysV message queue objects per namespace.
pub const IPC_NS_MSG_SLOTS: usize = 64;

/// Maximum POSIX message queues per namespace.
pub const IPC_NS_MQ_SLOTS: usize = 32;

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------

/// Per-namespace resource limits for IPC objects.
///
/// Default values follow Linux kernel defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcNsLimits {
    /// Maximum size of a single shared memory segment (bytes).
    pub shmmax: u64,
    /// Maximum total shared memory (pages).
    pub shmall: u64,
    /// Maximum number of shared memory segments.
    pub shmmni: u32,
    /// Maximum message size (bytes).
    pub msgmax: u32,
    /// Maximum bytes in a message queue.
    pub msgmnb: u32,
    /// Maximum number of message queues.
    pub msgmni: u32,
    /// Maximum number of semaphores per set.
    pub sem_nsems_max: u32,
    /// Maximum number of semaphore sets.
    pub semmni: u32,
    /// Maximum number of semaphore operations per semop call.
    pub semopm: u32,
    /// Maximum value of a semaphore.
    pub semvmx: u32,
}

impl IpcNsLimits {
    /// Create limits with Linux kernel defaults.
    pub const fn new() -> Self {
        Self {
            shmmax: 0x2000_0000, // 512 MiB
            shmall: 0x0200_0000, // 32 MiB in pages
            shmmni: 4096,
            msgmax: 8192,
            msgmnb: 16384,
            msgmni: 32000,
            sem_nsems_max: 32000,
            semmni: 32000,
            semopm: 500,
            semvmx: 32767,
        }
    }
}

impl Default for IpcNsLimits {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IpcIds — per-object-type ID allocator
// ---------------------------------------------------------------------------

/// ID allocator and usage counter for one IPC object type within a namespace.
///
/// Tracks how many objects of this type are in use, the highest ID
/// ever assigned, and a sequence counter for generating unique IPC keys.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcIds {
    /// Number of objects currently in use.
    pub in_use: u32,
    /// Highest index / ID ever assigned in this namespace.
    pub max_id: u32,
    /// Monotonically increasing sequence counter (for key generation).
    pub seq: u32,
}

impl IpcIds {
    /// Create a zeroed `IpcIds` allocator.
    pub const fn new() -> Self {
        Self {
            in_use: 0,
            max_id: 0,
            seq: 0,
        }
    }

    /// Allocate the next ID and advance the sequence.
    ///
    /// Returns `OutOfMemory` if `max_id` would exceed the slot limit.
    pub fn alloc(&mut self, slot_limit: u32) -> Result<u32> {
        if self.max_id >= slot_limit {
            return Err(Error::OutOfMemory);
        }
        let id = self.max_id;
        self.max_id = self.max_id.saturating_add(1);
        self.in_use = self.in_use.saturating_add(1);
        self.seq = self.seq.wrapping_add(1);
        Ok(id)
    }

    /// Free one object, decrementing the in-use counter.
    pub fn free(&mut self) {
        self.in_use = self.in_use.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// IpcNamespace
// ---------------------------------------------------------------------------

/// A single IPC namespace.
///
/// Each namespace has its own SysV shm, sem, msg, and POSIX mqueue ID
/// spaces, isolated from all other namespaces.
pub struct IpcNamespace {
    /// Unique namespace identifier.
    pub ns_id: u32,
    /// Reference count (number of processes using this namespace).
    ref_count: u32,
    /// Resource limits for this namespace.
    pub limits: IpcNsLimits,
    /// SysV shared memory ID allocator.
    pub shm_ids: IpcIds,
    /// SysV semaphore ID allocator.
    pub sem_ids: IpcIds,
    /// SysV message queue ID allocator.
    pub msg_ids: IpcIds,
    /// POSIX message queue ID allocator.
    pub mqueue_ids: IpcIds,
    /// Whether this namespace is still alive.
    active: bool,
}

impl IpcNamespace {
    /// Create a new namespace with default limits.
    const fn new(ns_id: u32) -> Self {
        Self {
            ns_id,
            ref_count: 0,
            limits: IpcNsLimits::new(),
            shm_ids: IpcIds::new(),
            sem_ids: IpcIds::new(),
            msg_ids: IpcIds::new(),
            mqueue_ids: IpcIds::new(),
            active: false,
        }
    }

    /// Return the current reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Return `true` if this namespace is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Increment the reference count, saturating at `u32::MAX`.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count.  Returns `true` if the namespace
    /// should be destroyed (ref_count reached zero).
    pub fn put(&mut self) -> bool {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count == 0 && self.ns_id != 0
    }
}

// ---------------------------------------------------------------------------
// IpcNamespaceStats
// ---------------------------------------------------------------------------

/// Usage statistics snapshot for an IPC namespace.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcNamespaceStats {
    /// Number of active SysV shared memory segments.
    pub shm_count: u32,
    /// Number of active SysV semaphore sets.
    pub sem_count: u32,
    /// Number of active SysV message queues.
    pub msg_count: u32,
    /// Number of active POSIX message queues.
    pub mq_count: u32,
    /// Total bytes locked in SHM segments.
    pub shm_bytes: u64,
}

// ---------------------------------------------------------------------------
// IpcNamespaceRegistry
// ---------------------------------------------------------------------------

/// Global registry of all IPC namespaces.
///
/// The initial namespace always occupies slot 0.
pub struct IpcNamespaceRegistry {
    slots: [IpcNamespace; NS_REGISTRY_MAX],
    /// Total number of active (alive) namespaces.
    count: usize,
    /// Next available namespace ID (monotonically increasing).
    next_ns_id: u32,
}

impl IpcNamespaceRegistry {
    /// Create a new registry and initialise the initial namespace.
    pub fn new() -> Self {
        let mut reg = Self {
            slots: core::array::from_fn(|i| IpcNamespace::new(i as u32)),
            count: 0,
            next_ns_id: 0,
        };
        // Initialise the initial namespace (ns_id = 0).
        reg.slots[0].active = true;
        reg.slots[0].ref_count = 1; // kernel holds a ref
        reg.count = 1;
        reg.next_ns_id = 1;
        reg
    }

    /// Return the total number of active namespaces.
    pub const fn count(&self) -> usize {
        self.count
    }

    // -- Internal helpers --------------------------------------------------

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if !slot.active {
                return Some(i);
            }
        }
        None
    }

    /// Validate a namespace ID and return the slot index.
    fn find_ns(&self, ns_id: u32) -> Option<usize> {
        self.slots.iter().position(|s| s.active && s.ns_id == ns_id)
    }

    /// Get a shared reference to a namespace by ID.
    fn get_ns(&self, ns_id: u32) -> Result<&IpcNamespace> {
        let idx = self.find_ns(ns_id).ok_or(Error::NotFound)?;
        Ok(&self.slots[idx])
    }

    /// Get a mutable reference to a namespace by ID.
    fn get_ns_mut(&mut self, ns_id: u32) -> Result<&mut IpcNamespace> {
        let idx = self.find_ns(ns_id).ok_or(Error::NotFound)?;
        Ok(&mut self.slots[idx])
    }
}

impl Default for IpcNamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new, empty IPC namespace.
///
/// The initial resource limits are copied from the creating process's
/// namespace (`parent_ns_id`), unless `parent_ns_id` is zero (initial ns).
///
/// Returns the ID of the new namespace.
pub fn ipc_ns_create(registry: &mut IpcNamespaceRegistry, parent_ns_id: u32) -> Result<u32> {
    let idx = registry.find_free().ok_or(Error::OutOfMemory)?;

    // Copy limits from parent namespace.
    let limits = if parent_ns_id == 0 || registry.find_ns(parent_ns_id).is_some() {
        match registry.find_ns(parent_ns_id) {
            Some(pidx) => registry.slots[pidx].limits,
            None => IpcNsLimits::new(),
        }
    } else {
        IpcNsLimits::new()
    };

    let ns_id = registry.next_ns_id;
    registry.next_ns_id = registry.next_ns_id.wrapping_add(1);

    registry.slots[idx].ns_id = ns_id;
    registry.slots[idx].ref_count = 1;
    registry.slots[idx].limits = limits;
    registry.slots[idx].shm_ids = IpcIds::new();
    registry.slots[idx].sem_ids = IpcIds::new();
    registry.slots[idx].msg_ids = IpcIds::new();
    registry.slots[idx].mqueue_ids = IpcIds::new();
    registry.slots[idx].active = true;
    registry.count += 1;

    Ok(ns_id)
}

/// Increment the reference count of a namespace.
///
/// Called when a process enters or inherits the namespace.
pub fn ipc_ns_get(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<()> {
    registry.get_ns_mut(ns_id)?.get();
    Ok(())
}

/// Decrement the reference count of a namespace.
///
/// If the count drops to zero (and this is not the initial namespace),
/// the namespace is destroyed.  Returns `true` if the namespace was
/// destroyed.
pub fn ipc_ns_put(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<bool> {
    // Initial namespace (ID 0) is never destroyed.
    if ns_id == 0 {
        return Ok(false);
    }

    let idx = registry.find_ns(ns_id).ok_or(Error::NotFound)?;
    let destroyed = registry.slots[idx].put();
    if destroyed {
        registry.slots[idx].active = false;
        registry.count = registry.count.saturating_sub(1);
    }
    Ok(destroyed)
}

/// Copy (clone) an IPC namespace for `unshare(CLONE_NEWIPC)`.
///
/// Creates a new namespace with limits inherited from `src_ns_id`
/// but with all ID counters reset to zero (empty namespace).
///
/// If `flags` does not include `CLONE_NEWIPC` (bit 27), the source
/// namespace ID is returned without modification.
pub fn copy_ipc_ns(registry: &mut IpcNamespaceRegistry, flags: u32, src_ns_id: u32) -> Result<u32> {
    const CLONE_NEWIPC: u32 = 1 << 27;

    if flags & CLONE_NEWIPC == 0 {
        // Share the existing namespace; just bump its refcount.
        ipc_ns_get(registry, src_ns_id)?;
        return Ok(src_ns_id);
    }

    ipc_ns_create(registry, src_ns_id)
}

/// Retrieve resource limits for a namespace.
pub fn ipc_ns_get_limits(registry: &IpcNamespaceRegistry, ns_id: u32) -> Result<IpcNsLimits> {
    Ok(registry.get_ns(ns_id)?.limits)
}

/// Update resource limits for a namespace.
///
/// Requires `is_privileged == true` (models `CAP_SYS_RESOURCE`).
pub fn ipc_ns_set_limits(
    registry: &mut IpcNamespaceRegistry,
    ns_id: u32,
    limits: &IpcNsLimits,
    is_privileged: bool,
) -> Result<()> {
    if !is_privileged {
        return Err(Error::PermissionDenied);
    }

    // Sanity-check a few key limits.
    if limits.shmmax == 0 || limits.msgmax == 0 || limits.semvmx == 0 {
        return Err(Error::InvalidArgument);
    }

    registry.get_ns_mut(ns_id)?.limits = *limits;
    Ok(())
}

/// Return a statistics snapshot for a namespace.
pub fn ipc_ns_stats(registry: &IpcNamespaceRegistry, ns_id: u32) -> Result<IpcNamespaceStats> {
    let ns = registry.get_ns(ns_id)?;
    Ok(IpcNamespaceStats {
        shm_count: ns.shm_ids.in_use,
        sem_count: ns.sem_ids.in_use,
        msg_count: ns.msg_ids.in_use,
        mq_count: ns.mqueue_ids.in_use,
        shm_bytes: 0, // stub: tracked by shm_ipc layer
    })
}

/// Allocate a new SysV shared memory ID within a namespace.
pub fn ipc_ns_alloc_shm(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<u32> {
    let ns = registry.get_ns_mut(ns_id)?;
    if ns.shm_ids.in_use >= ns.limits.shmmni {
        return Err(Error::OutOfMemory);
    }
    ns.shm_ids.alloc(IPC_NS_SHM_SLOTS as u32)
}

/// Allocate a new SysV semaphore set ID within a namespace.
pub fn ipc_ns_alloc_sem(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<u32> {
    let ns = registry.get_ns_mut(ns_id)?;
    if ns.sem_ids.in_use >= ns.limits.semmni {
        return Err(Error::OutOfMemory);
    }
    ns.sem_ids.alloc(IPC_NS_SEM_SLOTS as u32)
}

/// Allocate a new SysV message queue ID within a namespace.
pub fn ipc_ns_alloc_msg(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<u32> {
    let ns = registry.get_ns_mut(ns_id)?;
    if ns.msg_ids.in_use >= ns.limits.msgmni {
        return Err(Error::OutOfMemory);
    }
    ns.msg_ids.alloc(IPC_NS_MSG_SLOTS as u32)
}

/// Allocate a new POSIX message queue ID within a namespace.
pub fn ipc_ns_alloc_mqueue(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<u32> {
    let ns = registry.get_ns_mut(ns_id)?;
    if ns.mqueue_ids.in_use >= IPC_NS_MQ_SLOTS as u32 {
        return Err(Error::OutOfMemory);
    }
    ns.mqueue_ids.alloc(IPC_NS_MQ_SLOTS as u32)
}

/// Free a SysV shared memory ID within a namespace.
pub fn ipc_ns_free_shm(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<()> {
    registry.get_ns_mut(ns_id)?.shm_ids.free();
    Ok(())
}

/// Free a SysV semaphore set ID within a namespace.
pub fn ipc_ns_free_sem(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<()> {
    registry.get_ns_mut(ns_id)?.sem_ids.free();
    Ok(())
}

/// Free a SysV message queue ID within a namespace.
pub fn ipc_ns_free_msg(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<()> {
    registry.get_ns_mut(ns_id)?.msg_ids.free();
    Ok(())
}

/// Free a POSIX message queue ID within a namespace.
pub fn ipc_ns_free_mqueue(registry: &mut IpcNamespaceRegistry, ns_id: u32) -> Result<()> {
    registry.get_ns_mut(ns_id)?.mqueue_ids.free();
    Ok(())
}

/// Return `true` if the namespace identified by `ns_id` exists and is active.
pub fn ipc_ns_exists(registry: &IpcNamespaceRegistry, ns_id: u32) -> bool {
    registry.find_ns(ns_id).is_some()
}

/// Return the initial (root) namespace ID (always 0).
pub const fn ipc_initial_ns_id() -> u32 {
    0
}

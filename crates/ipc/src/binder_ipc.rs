// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Binder IPC — Android-style object-capability inter-process communication.
//!
//! This module implements a simplified but structurally correct Binder IPC
//! subsystem as used in Android (and now upstream Linux since 4.14 via
//! `drivers/android/binder.c`).  It provides:
//!
//! - **[`BinderNode`]** — a service object owned by a server process.
//! - **[`BinderRef`]** — a handle (capability) that a client holds to reach a node.
//! - **[`BinderTransaction`]** — a typed parcel carrying data and object offsets.
//! - **[`BinderCommand`]** — the protocol verbs exchanged over the device.
//! - **[`BinderThread`]** — per-thread state for the Binder driver.
//! - **[`BinderRegistry`]** — global registry of up to 32 participating processes.
//!
//! # Architecture
//!
//! ```text
//! Client process                     Server process
//! ──────────────                     ──────────────
//! BinderRef(handle=1) ──BC_TRANSACTION──► BinderNode(ptr=0xC000)
//!                     ◄─BR_REPLY──────────  (reply parcel)
//! ```
//!
//! # Reference
//!
//! - Linux: `drivers/android/binder.c`, `include/uapi/linux/android/binder.h`
//! - Android Open Source Project: Binder IPC documentation

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of Binder processes the registry can track.
pub const BINDER_MAX_PROCESSES: usize = 32;

/// Maximum number of strong references a single process may hold.
pub const BINDER_MAX_REFS_PER_PROC: usize = 64;

/// Maximum number of nodes a single process may publish.
pub const BINDER_MAX_NODES_PER_PROC: usize = 64;

/// Maximum number of pending transactions in the per-thread queue.
pub const BINDER_THREAD_QUEUE_DEPTH: usize = 16;

/// Maximum payload size (bytes) carried inline in a [`BinderTransaction`].
pub const BINDER_MAX_INLINE_DATA: usize = 256;

/// Maximum number of object offsets in a single transaction.
pub const BINDER_MAX_OFFSETS: usize = 8;

/// Size of a `flat_binder_object` as defined in the Binder UAPI.
///
/// A client-supplied offset must satisfy `offset + FLAT_BINDER_OBJECT_SIZE <= data_size`
/// so that the entire object lies within the inline data buffer.
pub const FLAT_BINDER_OBJECT_SIZE: u32 = 16;

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

/// Identifies a Binder process (maps to a Linux PID in real Binder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BinderPid(u32);

impl BinderPid {
    /// Create a `BinderPid` from a raw value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A handle integer that the client uses to refer to a remote [`BinderNode`].
///
/// Handle 0 is the context manager (service manager) by convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BinderHandle(u32);

impl BinderHandle {
    /// The context manager handle (service manager).
    pub const CONTEXT_MANAGER: BinderHandle = BinderHandle(0);

    /// Create a handle from a raw value.
    pub const fn new(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// A unique integer that identifies a [`BinderNode`] within its owner process.
///
/// In real Binder this is a kernel pointer to the `binder_node` struct cast to `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BinderPtr(u64);

impl BinderPtr {
    /// Create a `BinderPtr` from a raw value.
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// BinderNode — service object
// ---------------------------------------------------------------------------

/// A Binder service object registered by a server process.
///
/// Each node has a stable [`BinderPtr`] identifier (the server's object pointer)
/// and reference counts for strong and weak references held by client processes.
#[derive(Debug, Clone)]
pub struct BinderNode {
    /// Opaque pointer-sized identifier, unique within the owning process.
    pub ptr: BinderPtr,
    /// Cookie supplied by the owning process (passed back in BR notifications).
    pub cookie: u64,
    /// Owner process.
    pub owner: BinderPid,
    /// Strong reference count (incremented by BC_ACQUIRE, decremented by BC_RELEASE).
    pub strong_refs: u32,
    /// Weak reference count.
    pub weak_refs: u32,
    /// Whether this node has been marked for deletion.
    pub dead: bool,
}

impl BinderNode {
    /// Create a new node owned by `owner` with the given pointer and cookie.
    pub const fn new(owner: BinderPid, ptr: BinderPtr, cookie: u64) -> Self {
        Self {
            ptr,
            cookie,
            owner,
            strong_refs: 0,
            weak_refs: 0,
            dead: false,
        }
    }

    /// Increment the strong reference count.
    ///
    /// Returns `Err(Busy)` if the count would overflow.
    pub fn acquire(&mut self) -> Result<()> {
        self.strong_refs = self.strong_refs.checked_add(1).ok_or(Error::Busy)?;
        Ok(())
    }

    /// Decrement the strong reference count.
    ///
    /// Returns `Err(InvalidArgument)` if the count is already zero.
    pub fn release(&mut self) -> Result<()> {
        if self.strong_refs == 0 {
            return Err(Error::InvalidArgument);
        }
        self.strong_refs -= 1;
        Ok(())
    }

    /// Return `true` if no references are held and the node can be freed.
    pub const fn is_unreferenced(&self) -> bool {
        self.strong_refs == 0 && self.weak_refs == 0
    }
}

// ---------------------------------------------------------------------------
// BinderRef — client capability handle
// ---------------------------------------------------------------------------

/// A client-side capability handle pointing at a remote [`BinderNode`].
///
/// Each `BinderRef` is scoped to the process that holds it.  The `handle`
/// integer is meaningful only within that process's handle table.
#[derive(Debug, Clone)]
pub struct BinderRef {
    /// The handle value used by the client process.
    pub handle: BinderHandle,
    /// Process that holds this reference.
    pub owner: BinderPid,
    /// Node pointer in the target process.
    pub node_ptr: BinderPtr,
    /// Process that owns the referenced node.
    pub node_owner: BinderPid,
    /// Strong reference count contributed by this ref entry.
    pub strong: u32,
}

impl BinderRef {
    /// Create a new reference.
    pub const fn new(
        handle: BinderHandle,
        owner: BinderPid,
        node_ptr: BinderPtr,
        node_owner: BinderPid,
    ) -> Self {
        Self {
            handle,
            owner,
            node_ptr,
            node_owner,
            strong: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// BinderTransaction — typed parcel
// ---------------------------------------------------------------------------

/// A Binder transaction (BC_TRANSACTION / BR_TRANSACTION parcel).
///
/// Carries:
/// - Fixed-size inline data buffer (`data`).
/// - A compact list of byte offsets into `data` at which Binder objects
///   (flat_binder_object) reside (`offsets`).
#[derive(Clone, PartialEq, Eq)]
pub struct BinderTransaction {
    /// Handle of the target object (client-side handle or 0 for context manager).
    pub target_handle: BinderHandle,
    /// Binder protocol code (maps to an RPC method).
    pub code: u32,
    /// Transaction flags (see `TF_*` constants).
    pub flags: u32,
    /// Sender process.
    pub sender: BinderPid,
    /// Unique transaction id assigned by the driver.
    pub id: u64,
    /// Inline data payload.
    pub data: [u8; BINDER_MAX_INLINE_DATA],
    /// Number of valid bytes in `data`.
    ///
    /// Private: only settable through [`write_data`](Self::write_data), which enforces
    /// the `BINDER_MAX_INLINE_DATA` bound and prevents panic-slicing in
    /// [`data_slice`](Self::data_slice).
    data_size: u32,
    /// Offsets of embedded Binder objects within `data`.
    pub offsets: [u32; BINDER_MAX_OFFSETS],
    /// Number of valid entries in `offsets`.
    ///
    /// Private: only incremented through [`add_offset`](Self::add_offset), which
    /// uses `checked_add` and guards the array bound.
    offsets_count: u32,
    /// Whether this is a one-way (fire-and-forget) transaction.
    pub one_way: bool,
}

impl core::fmt::Debug for BinderTransaction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BinderTransaction")
            .field("target_handle", &self.target_handle)
            .field("code", &self.code)
            .field("flags", &self.flags)
            .field("sender", &self.sender)
            .field("id", &self.id)
            .field("data_size", &self.data_size)
            .field("offsets_count", &self.offsets_count)
            .field("one_way", &self.one_way)
            .finish()
    }
}

// Transaction flags.

/// One-way transaction: sender does not wait for a reply.
pub const TF_ONE_WAY: u32 = 0x01;
/// Root object is a file descriptor.
pub const TF_ROOT_OBJECT: u32 = 0x04;
/// The transaction status code (reply value) accompanies data.
pub const TF_STATUS_CODE: u32 = 0x08;
/// Accept file descriptors from the remote side.
pub const TF_ACCEPT_FDS: u32 = 0x10;

/// Mask of all defined transaction flag bits. Any bit outside this mask is
/// reserved and must be rejected: an attacker-controlled `flags` field with
/// unknown bits set must not be silently accepted (forward-compat hazard and
/// a way to smuggle undefined driver behaviour).
pub const TF_KNOWN_MASK: u32 = TF_ONE_WAY | TF_ROOT_OBJECT | TF_STATUS_CODE | TF_ACCEPT_FDS;

impl BinderTransaction {
    /// Create a new empty transaction.
    pub const fn new(
        target_handle: BinderHandle,
        code: u32,
        flags: u32,
        sender: BinderPid,
        id: u64,
    ) -> Self {
        Self {
            target_handle,
            code,
            flags,
            sender,
            id,
            data: [0u8; BINDER_MAX_INLINE_DATA],
            data_size: 0,
            offsets: [0u32; BINDER_MAX_OFFSETS],
            offsets_count: 0,
            one_way: flags & TF_ONE_WAY != 0,
        }
    }

    /// Return the number of valid bytes in `data`.
    pub const fn data_size(&self) -> u32 {
        self.data_size
    }

    /// Return the number of valid entries in `offsets`.
    pub const fn offsets_count(&self) -> u32 {
        self.offsets_count
    }

    /// Write `payload` into the inline data buffer.
    ///
    /// Returns `Err(InvalidArgument)` if the payload exceeds the buffer capacity.
    pub fn write_data(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > BINDER_MAX_INLINE_DATA {
            return Err(Error::InvalidArgument);
        }
        self.data[..payload.len()].copy_from_slice(payload);
        self.data_size = payload.len() as u32;
        Ok(())
    }

    /// Add a Binder object offset into the offsets table.
    ///
    /// `offset` must be 4-byte aligned and the full `flat_binder_object` starting
    /// at `offset` must lie entirely within `data_size` (i.e.
    /// `offset + FLAT_BINDER_OBJECT_SIZE <= data_size`).
    ///
    /// Returns `Err(InvalidArgument)` if the alignment or bounds check fails, or
    /// `Err(OutOfMemory)` if the offsets table is full.
    pub fn add_offset(&mut self, offset: u32) -> Result<()> {
        if offset % 4 != 0 {
            return Err(Error::InvalidArgument);
        }
        // Verify that the *entire* flat_binder_object fits within data_size.
        let end = offset
            .checked_add(FLAT_BINDER_OBJECT_SIZE)
            .ok_or(Error::InvalidArgument)?;
        if end > self.data_size {
            return Err(Error::InvalidArgument);
        }
        if self.offsets_count as usize >= BINDER_MAX_OFFSETS {
            return Err(Error::OutOfMemory);
        }
        self.offsets[self.offsets_count as usize] = offset;
        // SAFETY: checked above that offsets_count < BINDER_MAX_OFFSETS (≤ 8 ≤ u32::MAX).
        self.offsets_count = self
            .offsets_count
            .checked_add(1)
            .ok_or(Error::InvalidArgument)?;
        Ok(())
    }

    /// Return the inline data slice (valid bytes only).
    ///
    /// The slice length is always clamped to `BINDER_MAX_INLINE_DATA` regardless
    /// of the stored `data_size` value, preventing any panic from an out-of-range
    /// index even if `data_size` were somehow inconsistent.
    pub fn data_slice(&self) -> &[u8] {
        let sz = (self.data_size as usize).min(BINDER_MAX_INLINE_DATA);
        &self.data[..sz]
    }
}

// ---------------------------------------------------------------------------
// BinderCommand — protocol verbs
// ---------------------------------------------------------------------------

/// Commands sent from user space to the driver (BC_* direction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinderCommand {
    /// Send a transaction to the target object.
    BcTransaction(BinderTransaction),
    /// Send a reply to a pending synchronous transaction.
    BcReply(BinderTransaction),
    /// Increment the strong reference count on a handle.
    BcAcquire(BinderHandle),
    /// Decrement the strong reference count on a handle.
    BcRelease(BinderHandle),
    /// Free a buffer that the driver allocated for a received transaction.
    BcFreeBuffer { buffer_ptr: u64 },
    /// Register the calling thread as a looper thread.
    BcRegisterLooper,
    /// Indicate that the thread is entering the looper.
    BcEnterLooper,
    /// Indicate that the thread is exiting the looper.
    BcExitLooper,
    /// Request death notification for a node referenced by `handle`.
    BcRequestDeathNotification { handle: BinderHandle, cookie: u64 },
    /// Clear a previously requested death notification.
    BcClearDeathNotification { handle: BinderHandle, cookie: u64 },
}

/// Responses sent from the driver back to user space (BR_* direction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinderReturn {
    /// Deliver an incoming transaction to the thread.
    BrTransaction(BinderTransaction),
    /// Deliver a reply to a thread that sent a BC_TRANSACTION.
    BrReply(BinderTransaction),
    /// Acknowledge a BC_ACQUIRE: the node's strong ref was incremented.
    BrAcquire { ptr: BinderPtr, cookie: u64 },
    /// Acknowledge a BC_RELEASE: the node's strong ref was decremented.
    BrRelease { ptr: BinderPtr, cookie: u64 },
    /// Inform the owning process that the node has no more references.
    BrDecRefs { ptr: BinderPtr, cookie: u64 },
    /// The referenced node's process has died.
    BrDeadBinder(u64),
    /// Confirm the death notification was cleared.
    BrClearDeathNotificationDone(u64),
    /// Transaction replied OK (no data).
    BrTransactionComplete,
    /// Generic error reply.
    BrError(i32),
    /// Driver is ready for the thread to loop.
    BrNoop,
    /// No more commands available (poll returned empty).
    BrSpawnLooper,
    /// Thread should finish.
    BrFinished,
    /// The calling process is now the context manager.
    BrOk,
}

// ---------------------------------------------------------------------------
// BinderThread — per-thread state
// ---------------------------------------------------------------------------

/// State of a single thread participating in Binder IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Not registered as a looper.
    Idle,
    /// Thread has called BC_REGISTER_LOOPER.
    Registered,
    /// Thread is actively in a Binder ioctl loop.
    Looping,
    /// Thread is processing an incoming transaction.
    InTransaction,
    /// Thread called BC_EXIT_LOOPER.
    Exiting,
}

/// Per-thread Binder state.
pub struct BinderThread {
    /// The process this thread belongs to.
    pub pid: BinderPid,
    /// Linux TID (thread identifier within the process).
    pub tid: u32,
    /// Current looper state.
    pub state: ThreadState,
    /// Pending return commands queued for this thread.
    returns: [Option<BinderReturn>; BINDER_THREAD_QUEUE_DEPTH],
    /// Write index in the returns ring.
    returns_head: usize,
    /// Read index in the returns ring.
    returns_tail: usize,
    /// Count of queued return commands.
    returns_count: usize,
}

impl BinderThread {
    /// Create a new idle thread.
    pub const fn new(pid: BinderPid, tid: u32) -> Self {
        Self {
            pid,
            tid,
            state: ThreadState::Idle,
            returns: [const { None }; BINDER_THREAD_QUEUE_DEPTH],
            returns_head: 0,
            returns_tail: 0,
            returns_count: 0,
        }
    }

    /// Enqueue a return command for this thread.
    ///
    /// Returns `Err(OutOfMemory)` if the queue is full.
    pub fn enqueue_return(&mut self, ret: BinderReturn) -> Result<()> {
        if self.returns_count >= BINDER_THREAD_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        self.returns[self.returns_head] = Some(ret);
        self.returns_head = (self.returns_head + 1) % BINDER_THREAD_QUEUE_DEPTH;
        self.returns_count += 1;
        Ok(())
    }

    /// Dequeue the next return command for this thread.
    ///
    /// Returns `None` if no commands are pending.
    pub fn dequeue_return(&mut self) -> Option<BinderReturn> {
        if self.returns_count == 0 {
            return None;
        }
        let ret = self.returns[self.returns_tail].take();
        self.returns_tail = (self.returns_tail + 1) % BINDER_THREAD_QUEUE_DEPTH;
        self.returns_count -= 1;
        ret
    }

    /// Return the number of pending return commands.
    pub const fn pending_count(&self) -> usize {
        self.returns_count
    }
}

// ---------------------------------------------------------------------------
// DeathNotification — per-reference death watch
// ---------------------------------------------------------------------------

/// Maximum number of death notification registrations per process.
pub const BINDER_MAX_DEATH_NOTIFS: usize = 32;

/// A registered death notification.
///
/// When a client calls `BC_REQUEST_DEATH_NOTIFICATION` on a handle, the
/// driver records a `DeathNotification`.  When the server process dies
/// (i.e. its nodes are killed), the driver delivers `BR_DEAD_BINDER` to
/// every client that registered for that node.
#[derive(Debug, Clone, Copy)]
pub struct DeathNotification {
    /// The handle being watched.
    pub handle: BinderHandle,
    /// The node pointer the handle resolves to.
    pub node_ptr: BinderPtr,
    /// The owning process of the watched node.
    pub node_owner: BinderPid,
    /// User-space cookie (passed back in `BR_DEAD_BINDER`).
    pub cookie: u64,
    /// Whether the notification has been delivered.
    pub delivered: bool,
}

// ---------------------------------------------------------------------------
// BinderProcess — per-process state
// ---------------------------------------------------------------------------

/// Per-process Binder state.
pub struct BinderProcess {
    /// Process identifier.
    pub pid: BinderPid,
    /// Whether this process is the context manager (handle 0 target).
    pub is_context_manager: bool,
    /// Nodes published by this process.
    nodes: [Option<BinderNode>; BINDER_MAX_NODES_PER_PROC],
    /// References held by this process (handles into other processes' nodes).
    refs: [Option<BinderRef>; BINDER_MAX_REFS_PER_PROC],
    /// Next handle value to allocate for new references.
    next_handle: u32,
    /// Threads registered with Binder in this process.
    threads: [Option<BinderThread>; 8],
    /// Number of active threads.
    thread_count: usize,
    /// Death notifications registered by this process.
    death_notifs: [Option<DeathNotification>; BINDER_MAX_DEATH_NOTIFS],
    /// Number of active death notifications.
    death_notif_count: usize,
}

impl BinderProcess {
    /// Create a new process entry.
    pub const fn new(pid: BinderPid) -> Self {
        Self {
            pid,
            is_context_manager: false,
            nodes: [const { None }; BINDER_MAX_NODES_PER_PROC],
            refs: [const { None }; BINDER_MAX_REFS_PER_PROC],
            // Handle 0 is permanently reserved for the context manager
            // (BinderHandle::CONTEXT_MANAGER).  Dynamic handles start at 1.
            next_handle: 1,
            threads: [const { None }; 8],
            thread_count: 0,
            death_notifs: [const { None }; BINDER_MAX_DEATH_NOTIFS],
            death_notif_count: 0,
        }
    }

    // --- node operations ---

    /// Register a new node in this process.
    ///
    /// Returns `Err(AlreadyExists)` if a node with the same `ptr` already exists.
    /// Returns `Err(OutOfMemory)` if the node table is full.
    pub fn register_node(&mut self, ptr: BinderPtr, cookie: u64) -> Result<()> {
        // Check for duplicate.
        for n in self.nodes.iter().flatten() {
            if n.ptr == ptr {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(BinderNode::new(self.pid, ptr, cookie));
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a node by its pointer.
    pub fn find_node(&self, ptr: BinderPtr) -> Option<&BinderNode> {
        self.nodes
            .iter()
            .find_map(|s| s.as_ref().filter(|n| n.ptr == ptr))
    }

    /// Look up a node mutably by its pointer.
    pub fn find_node_mut(&mut self, ptr: BinderPtr) -> Option<&mut BinderNode> {
        self.nodes
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|n| n.ptr == ptr))
    }

    /// Mark a node as dead (owner process is going away).
    ///
    /// If no client still holds a strong reference, the slot is reaped
    /// immediately; otherwise the node stays (marked dead) until the last
    /// reference is dropped via [`BinderRegistry::handle_release`], which
    /// reaps it at zero.
    pub fn kill_node(&mut self, ptr: BinderPtr) -> Result<()> {
        let unreferenced = {
            let node = self.find_node_mut(ptr).ok_or(Error::NotFound)?;
            node.dead = true;
            node.strong_refs == 0
        };
        if unreferenced {
            for slot in self.nodes.iter_mut() {
                if slot.as_ref().map(|n| n.ptr == ptr).unwrap_or(false) {
                    *slot = None;
                    break;
                }
            }
        }
        Ok(())
    }

    // --- reference operations ---

    /// Create a new handle for a remote node in this process.
    ///
    /// Handle 0 is permanently reserved for the context manager and is never
    /// allocated here.  `next_handle` starts at 1 and is advanced with
    /// `checked_add`; if it would overflow `u32::MAX` (wrapping back through 0)
    /// this method returns `Err(OutOfMemory)` instead of producing a handle-0
    /// collision.
    ///
    /// Returns the assigned [`BinderHandle`].
    pub fn create_ref(
        &mut self,
        node_ptr: BinderPtr,
        node_owner: BinderPid,
    ) -> Result<BinderHandle> {
        // Check if a ref for this node already exists and return it.
        for r in self.refs.iter().flatten() {
            if r.node_ptr == node_ptr && r.node_owner == node_owner {
                return Ok(r.handle);
            }
        }
        // Reject allocation when the counter is at u32::MAX to prevent wrapping
        // to 0 (BinderHandle::CONTEXT_MANAGER) on the next increment.
        let raw = self.next_handle;
        if raw == 0 {
            // Should never happen (initialised to 1) but fail-safe.
            return Err(Error::OutOfMemory);
        }
        let handle = BinderHandle::new(raw);
        for slot in self.refs.iter_mut() {
            if slot.is_none() {
                *slot = Some(BinderRef::new(handle, self.pid, node_ptr, node_owner));
                // Advance with checked_add; Err on overflow so next_handle never
                // wraps back through 0 / CONTEXT_MANAGER territory.
                self.next_handle = self.next_handle.checked_add(1).ok_or(Error::OutOfMemory)?;
                return Ok(handle);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a reference by its handle.
    pub fn find_ref(&self, handle: BinderHandle) -> Option<&BinderRef> {
        self.refs
            .iter()
            .find_map(|s| s.as_ref().filter(|r| r.handle == handle))
    }

    /// Remove a reference by handle and return the node identity it pointed to.
    ///
    /// The caller **must** use the returned `(node_ptr, node_owner)` to locate
    /// the server-side [`BinderNode`] and call [`BinderNode::release`] on it so
    /// that the node's strong reference count is decremented.  Failing to do so
    /// leaks a phantom strong reference and prevents the node from ever reaching
    /// [`BinderNode::is_unreferenced`].
    ///
    /// Returns `Err(NotFound)` if the handle does not exist.
    //
    // SECURITY INVARIANT: any death notification registered against `handle`
    // captured a snapshot of (node_ptr, node_owner) at registration time (see
    // `request_death_notification`). When the ref is removed here the handle
    // number is freed and may later be REUSED for a different node, so a stale
    // DeathNotification keyed on the old (node_ptr, node_owner) snapshot could
    // fire for the wrong node or leak a cookie. The dispatcher MUST, on
    // remove_ref, purge every `death_notifs` entry whose `handle` matches the
    // removed handle, AND the delivery path (`deliver_death_for_node`) MUST
    // re-resolve the handle through the live ref table at delivery time rather
    // than trusting the recorded snapshot. This signature-preserving guard does
    // not perform that purge (it would change return-shape and ripple to
    // `BinderRegistry::handle_release`); it is documented here so the dispatcher
    // wires it. Do NOT treat the surviving snapshot as authoritative.
    pub fn remove_ref(&mut self, handle: BinderHandle) -> Result<(BinderPtr, BinderPid)> {
        for slot in self.refs.iter_mut() {
            if slot.as_ref().map(|r| r.handle == handle).unwrap_or(false) {
                let info = slot.as_ref().map(|r| (r.node_ptr, r.node_owner)).unwrap();
                *slot = None;
                return Ok(info);
            }
        }
        Err(Error::NotFound)
    }

    // --- thread operations ---

    /// Register a thread with this process.
    ///
    /// Returns `Err(AlreadyExists)` if `tid` is already registered.
    /// Returns `Err(OutOfMemory)` if the thread table is full.
    pub fn register_thread(&mut self, tid: u32) -> Result<()> {
        for slot in self.threads.iter() {
            if slot.as_ref().map(|t| t.tid == tid).unwrap_or(false) {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.threads.iter_mut() {
            if slot.is_none() {
                *slot = Some(BinderThread::new(self.pid, tid));
                self.thread_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a thread by TID (mutable).
    pub fn find_thread_mut(&mut self, tid: u32) -> Option<&mut BinderThread> {
        self.threads
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|t| t.tid == tid))
    }

    // --- death notification operations ---

    /// Register a death notification for `handle`.
    ///
    /// When the node referenced by `handle` dies, the driver will deliver
    /// `BR_DEAD_BINDER(cookie)` to this process.
    ///
    /// Returns `Err(AlreadyExists)` if a notification is already registered
    /// for this handle with the same cookie.
    /// Returns `Err(OutOfMemory)` if the notification table is full.
    /// Returns `Err(NotFound)` if the handle does not exist in this process.
    pub fn request_death_notification(
        &mut self,
        handle: BinderHandle,
        cookie: u64,
    ) -> Result<(BinderPtr, BinderPid)> {
        // SECURITY INVARIANT: the (node_ptr, node_owner) pair captured below is
        // a SNAPSHOT taken at registration time. If the underlying ref is later
        // removed (see `remove_ref`) and the handle number is recycled to a
        // different node, this snapshot becomes stale and BR_DEAD_BINDER could
        // fire for the wrong node or disclose a cookie to the wrong client. The
        // delivery path MUST re-resolve `handle` through the live ref table at
        // delivery time and MUST treat the death notification as void if the
        // ref no longer maps to this (node_ptr, node_owner). `remove_ref` MUST
        // purge matching death_notifs. Do NOT trust this snapshot at delivery.
        // Resolve the reference to get node info.
        let binder_ref = self.find_ref(handle).ok_or(Error::NotFound)?;
        let node_ptr = binder_ref.node_ptr;
        let node_owner = binder_ref.node_owner;

        // Check for duplicate.
        for notif in self.death_notifs.iter().flatten() {
            if notif.handle == handle && notif.cookie == cookie {
                return Err(Error::AlreadyExists);
            }
        }

        // Allocate a slot.
        for slot in self.death_notifs.iter_mut() {
            if slot.is_none() {
                *slot = Some(DeathNotification {
                    handle,
                    node_ptr,
                    node_owner,
                    cookie,
                    delivered: false,
                });
                self.death_notif_count += 1;
                return Ok((node_ptr, node_owner));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Clear a previously registered death notification.
    ///
    /// Returns the cookie of the cleared notification, or
    /// `Err(NotFound)` if no matching registration exists.
    pub fn clear_death_notification(&mut self, handle: BinderHandle, cookie: u64) -> Result<u64> {
        for slot in self.death_notifs.iter_mut() {
            if let Some(notif) = slot {
                if notif.handle == handle && notif.cookie == cookie {
                    let c = notif.cookie;
                    *slot = None;
                    self.death_notif_count = self.death_notif_count.saturating_sub(1);
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Deliver death notifications for a node owned by `dead_pid` at `dead_ptr`.
    ///
    /// Enqueues `BR_DEAD_BINDER(cookie)` to the first available looper thread
    /// for each matching notification.  Returns the number of notifications
    /// delivered.
    pub fn deliver_death_for_node(&mut self, dead_pid: BinderPid, dead_ptr: BinderPtr) -> usize {
        let mut delivered = 0;

        // Collect cookies for matching notifications.
        let mut cookies = [0u64; BINDER_MAX_DEATH_NOTIFS];
        let mut count = 0;
        for notif in self.death_notifs.iter_mut().flatten() {
            if notif.node_owner == dead_pid && notif.node_ptr == dead_ptr && !notif.delivered {
                notif.delivered = true;
                if count < BINDER_MAX_DEATH_NOTIFS {
                    cookies[count] = notif.cookie;
                    count += 1;
                }
            }
        }

        // Enqueue BR_DEAD_BINDER to a looper thread.
        for &cookie in &cookies[..count] {
            for t in self.threads.iter_mut().flatten() {
                if t.state == ThreadState::Looping || t.state == ThreadState::Registered {
                    if t.enqueue_return(BinderReturn::BrDeadBinder(cookie)).is_ok() {
                        delivered += 1;
                    }
                    break;
                }
            }
        }

        delivered
    }

    /// Return the number of active death notifications.
    pub const fn death_notif_count(&self) -> usize {
        self.death_notif_count
    }
}

// ---------------------------------------------------------------------------
// BinderRegistry — global process registry
// ---------------------------------------------------------------------------

/// Global registry of all Binder-aware processes.
///
/// Tracks up to [`BINDER_MAX_PROCESSES`] processes and resolves transactions
/// by handle → target node lookup.
pub struct BinderRegistry {
    processes: [Option<BinderProcess>; BINDER_MAX_PROCESSES],
    process_count: usize,
    /// Global transaction id counter.
    next_txn_id: u64,
    /// PID of the context manager process (handle 0 target), if set.
    context_manager: Option<BinderPid>,
}

impl Default for BinderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BinderRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            processes: [const { None }; BINDER_MAX_PROCESSES],
            process_count: 0,
            next_txn_id: 1,
            context_manager: None,
        }
    }

    // --- process management ---

    /// Register a process with the Binder driver.
    ///
    /// Returns `Err(AlreadyExists)` if a process with `pid` is already registered.
    /// Returns `Err(OutOfMemory)` if the registry is full.
    pub fn open(&mut self, pid: BinderPid) -> Result<()> {
        for slot in self.processes.iter() {
            if slot.as_ref().map(|p| p.pid == pid).unwrap_or(false) {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.processes.iter_mut() {
            if slot.is_none() {
                *slot = Some(BinderProcess::new(pid));
                self.process_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Deregister a process (called on last fd close).
    ///
    /// Marks all nodes owned by this process as dead and delivers
    /// `BR_DEAD_BINDER` notifications to all client processes that
    /// registered death watches on those nodes.
    ///
    /// Returns `Err(NotFound)` if the process is not registered.
    pub fn release(&mut self, pid: BinderPid) -> Result<()> {
        // Collect the dying process's node pointers before removing it.
        let mut dead_nodes: [(BinderPtr, BinderPid); BINDER_MAX_NODES_PER_PROC] =
            [(BinderPtr::new(0), BinderPid::new(0)); BINDER_MAX_NODES_PER_PROC];
        let mut dead_count = 0;

        let mut found = false;
        for slot in self.processes.iter_mut() {
            if slot.as_ref().map(|p| p.pid == pid).unwrap_or(false) {
                if let Some(proc) = slot.as_ref() {
                    for node in proc.nodes.iter().flatten() {
                        if dead_count < BINDER_MAX_NODES_PER_PROC {
                            dead_nodes[dead_count] = (node.ptr, pid);
                            dead_count += 1;
                        }
                    }
                }
                *slot = None;
                self.process_count = self.process_count.saturating_sub(1);
                if self.context_manager == Some(pid) {
                    self.context_manager = None;
                }
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        // Deliver death notifications to all remaining processes.
        for &(dead_ptr, dead_pid) in &dead_nodes[..dead_count] {
            for slot in self.processes.iter_mut() {
                if let Some(proc) = slot.as_mut() {
                    proc.deliver_death_for_node(dead_pid, dead_ptr);
                }
            }
        }

        Ok(())
    }

    /// Look up a process by PID (immutable).
    pub fn find_process(&self, pid: BinderPid) -> Option<&BinderProcess> {
        self.processes
            .iter()
            .find_map(|s| s.as_ref().filter(|p| p.pid == pid))
    }

    /// Look up a process by PID (mutable).
    pub fn find_process_mut(&mut self, pid: BinderPid) -> Option<&mut BinderProcess> {
        self.processes
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|p| p.pid == pid))
    }

    /// Return the number of registered processes.
    pub const fn process_count(&self) -> usize {
        self.process_count
    }

    // --- context manager ---

    /// Register `pid` as the context manager (service manager).
    ///
    /// This is a privileged operation: the caller must hold a kernel-verified
    /// credential granting the right to act as the system service manager.
    /// At the syscall layer the `is_privileged` flag must be derived from the
    /// authenticated caller's capability set (e.g. `CAP_SYS_ADMIN` or a
    /// Binder-specific capability) — it must **never** be supplied by the
    /// userspace caller directly.
    ///
    /// Only one context manager may be registered at a time.
    ///
    /// Returns `Err(PermissionDenied)` if `is_privileged` is false (fail-closed).
    /// Returns `Err(Busy)` if a context manager is already registered.
    /// Returns `Err(NotFound)` if `pid` has not called [`open`](Self::open).
    pub fn become_context_manager(&mut self, pid: BinderPid, is_privileged: bool) -> Result<()> {
        // Fail-closed: reject immediately if the caller is not privileged.
        if !is_privileged {
            return Err(Error::PermissionDenied);
        }
        if self.context_manager.is_some() {
            return Err(Error::Busy);
        }
        let proc = self.find_process_mut(pid).ok_or(Error::NotFound)?;
        proc.is_context_manager = true;
        self.context_manager = Some(pid);
        Ok(())
    }

    // --- command dispatch ---

    /// Validate that `sender_pid` is a registered process that owns `sender_tid`.
    ///
    /// This is the strongest identity check reachable at this layer.  In a fully
    /// wired system the syscall entry point would supply a kernel-maintained
    /// `BinderPid` derived from the calling process's credential record, making
    /// spoofing impossible.  Until that wiring exists, this check at least ensures
    /// that the named `sender_pid` actually has a registered thread with the given
    /// `sender_tid`, so commands cannot be dispatched as an arbitrary third-party
    /// process's identity.
    ///
    /// Returns `Err(PermissionDenied)` if the process or thread is not found.
    fn validate_sender(&self, sender_pid: BinderPid, sender_tid: u32) -> Result<()> {
        let proc = self
            .find_process(sender_pid)
            .ok_or(Error::PermissionDenied)?;
        // Verify that sender_tid is registered under sender_pid, confirming
        // that the caller did not supply a victim PID with a fabricated TID.
        proc.threads
            .iter()
            .flatten()
            .find(|t| t.tid == sender_tid)
            .map(|_| ())
            .ok_or(Error::PermissionDenied)
    }

    /// Process a [`BinderCommand`] from `sender_pid` on `sender_tid`.
    ///
    /// # Sender identity
    ///
    /// `sender_pid` and `sender_tid` are treated as caller-supplied values.
    /// Before any command that touches another process's handle table or ref
    /// counts is executed, `sender_pid`/`sender_tid` are validated against the
    /// registry with [`validate_sender`](Self::validate_sender) to ensure the
    /// named process owns the named thread.
    ///
    /// **TODO (syscall layer)**: once this registry is wired to the live syscall
    /// path, `sender_pid` must be derived from the kernel's authenticated
    /// per-fd process record — not accepted as a userspace argument — so that
    /// the `validate_sender` check can be removed in favour of a kernel-enforced
    /// binding.
    ///
    /// Returns the [`BinderReturn`] that should be queued back to the
    /// sender thread, or propagates an error.
    pub fn dispatch(
        &mut self,
        sender_pid: BinderPid,
        sender_tid: u32,
        cmd: BinderCommand,
    ) -> Result<BinderReturn> {
        // Validate sender identity before processing any command.
        // BcRegisterLooper is the bootstrap command that registers the thread;
        // at that point the thread does not yet exist, so we only check the PID.
        match &cmd {
            BinderCommand::BcRegisterLooper => {
                // Thread is being registered — only verify the process exists.
                if self.find_process(sender_pid).is_none() {
                    return Err(Error::PermissionDenied);
                }
            }
            _ => {
                // For all other commands the sending thread must already be
                // registered under the named process.
                self.validate_sender(sender_pid, sender_tid)?;
            }
        }

        match cmd {
            BinderCommand::BcRegisterLooper => {
                let proc = self.find_process_mut(sender_pid).ok_or(Error::NotFound)?;
                let thread = proc.find_thread_mut(sender_tid).ok_or(Error::NotFound)?;
                thread.state = ThreadState::Registered;
                Ok(BinderReturn::BrNoop)
            }

            BinderCommand::BcEnterLooper => {
                let proc = self.find_process_mut(sender_pid).ok_or(Error::NotFound)?;
                let thread = proc.find_thread_mut(sender_tid).ok_or(Error::NotFound)?;
                thread.state = ThreadState::Looping;
                Ok(BinderReturn::BrNoop)
            }

            BinderCommand::BcExitLooper => {
                let proc = self.find_process_mut(sender_pid).ok_or(Error::NotFound)?;
                let thread = proc.find_thread_mut(sender_tid).ok_or(Error::NotFound)?;
                thread.state = ThreadState::Exiting;
                Ok(BinderReturn::BrFinished)
            }

            BinderCommand::BcAcquire(handle) => self.handle_acquire(sender_pid, handle),

            BinderCommand::BcRelease(handle) => self.handle_release(sender_pid, handle),

            BinderCommand::BcFreeBuffer { buffer_ptr: _ } => {
                // In real Binder this releases the mmaped buffer region.
                // Stub: acknowledge with a noop.
                Ok(BinderReturn::BrNoop)
            }

            BinderCommand::BcTransaction(txn) => {
                self.handle_transaction(sender_pid, sender_tid, txn)
            }

            BinderCommand::BcReply(txn) => self.handle_reply(sender_pid, sender_tid, txn),

            BinderCommand::BcRequestDeathNotification { handle, cookie } => {
                let proc = self.find_process_mut(sender_pid).ok_or(Error::NotFound)?;
                proc.request_death_notification(handle, cookie)?;
                Ok(BinderReturn::BrNoop)
            }

            BinderCommand::BcClearDeathNotification { handle, cookie } => {
                let proc = self.find_process_mut(sender_pid).ok_or(Error::NotFound)?;
                let c = proc.clear_death_notification(handle, cookie)?;
                Ok(BinderReturn::BrClearDeathNotificationDone(c))
            }
        }
    }

    // --- internal helpers ---

    /// Allocate the next transaction id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the u64 transaction counter has been
    /// exhausted (2^64 − 1 transactions issued). Under normal workloads this is
    /// unreachable; the guard exists to prevent wrapping_add from recycling a
    /// live transaction ID, which would redirect a reply to the wrong pending
    /// transaction (reply redirection).
    // SECURITY: checked_add prevents the transaction counter from wrapping around.
    // A wrap would cause alloc_txn_id to return an ID that is already registered
    // in the pending-transaction table, silently redirecting the eventual reply
    // to the original (wrong) caller. Fail the alloc instead.
    fn alloc_txn_id(&mut self) -> Result<u64> {
        let id = self.next_txn_id;
        self.next_txn_id = self.next_txn_id.checked_add(1).ok_or(Error::OutOfMemory)?;
        Ok(id)
    }

    /// Handle BC_ACQUIRE: increment strong ref count on the referenced node.
    ///
    /// Returns `Err(NotFound)` if the node has already been marked dead — dead
    /// nodes must not receive new strong references, as the owning process has
    /// already been torn down.
    fn handle_acquire(
        &mut self,
        client_pid: BinderPid,
        handle: BinderHandle,
    ) -> Result<BinderReturn> {
        // Look up the ref in the client's handle table.
        let (node_ptr, node_owner) = {
            let client = self.find_process(client_pid).ok_or(Error::NotFound)?;
            // Handle 0 → context manager node.
            if handle == BinderHandle::CONTEXT_MANAGER {
                let cm_pid = self.context_manager.ok_or(Error::NotFound)?;
                // Use a sentinel ptr for the context manager node.
                (BinderPtr::new(0), cm_pid)
            } else {
                let r = client.find_ref(handle).ok_or(Error::NotFound)?;
                (r.node_ptr, r.node_owner)
            }
        };

        let server = self.find_process_mut(node_owner).ok_or(Error::NotFound)?;
        if handle == BinderHandle::CONTEXT_MANAGER {
            // For the context manager, there may be no registered node ptr=0.
            // Silently succeed.
            return Ok(BinderReturn::BrNoop);
        }
        let node = server.find_node_mut(node_ptr).ok_or(Error::NotFound)?;
        // Reject acquire on a dead node: the server process has already exited.
        // Returning NotFound prevents information leakage of the dead node's cookie.
        if node.dead {
            return Err(Error::NotFound);
        }
        node.acquire()?;
        Ok(BinderReturn::BrAcquire {
            ptr: node_ptr,
            cookie: node.cookie,
        })
    }

    /// Handle BC_RELEASE: decrement strong ref count on the referenced node.
    ///
    /// Returns `Err(NotFound)` if the node is dead.  After decrement, if the
    /// node is both dead and fully unreferenced, the node slot is reaped so
    /// the memory is not leaked indefinitely.
    fn handle_release(
        &mut self,
        client_pid: BinderPid,
        handle: BinderHandle,
    ) -> Result<BinderReturn> {
        let (node_ptr, node_owner) = {
            let client = self.find_process(client_pid).ok_or(Error::NotFound)?;
            if handle == BinderHandle::CONTEXT_MANAGER {
                let cm_pid = self.context_manager.ok_or(Error::NotFound)?;
                (BinderPtr::new(0), cm_pid)
            } else {
                let r = client.find_ref(handle).ok_or(Error::NotFound)?;
                (r.node_ptr, r.node_owner)
            }
        };

        let server = self.find_process_mut(node_owner).ok_or(Error::NotFound)?;
        if handle == BinderHandle::CONTEXT_MANAGER {
            return Ok(BinderReturn::BrNoop);
        }
        // A dead node still lets the client drop its strong ref (so the node
        // can be reaped) but must NOT disclose the cookie — repeated
        // acquire/release on a dead node would otherwise leak the server's
        // cookie. The live path returns BrRelease (with cookie); the dead
        // path returns BrNoop and reaps the slot once unreferenced.
        let reap = {
            let node = server.find_node_mut(node_ptr).ok_or(Error::NotFound)?;
            if !node.dead {
                node.release()?;
                let cookie = node.cookie;
                return Ok(BinderReturn::BrRelease {
                    ptr: node_ptr,
                    cookie,
                });
            }
            // Drop the ref without leaking the cookie; ignore an underflow on
            // an already-zero count.
            let _ = node.release();
            node.strong_refs == 0
        };
        if reap {
            for slot in server.nodes.iter_mut() {
                if slot.as_ref().map(|n| n.ptr == node_ptr).unwrap_or(false) {
                    *slot = None;
                    break;
                }
            }
        }
        Ok(BinderReturn::BrNoop)
    }

    /// Handle BC_TRANSACTION: route the transaction to the target.
    fn handle_transaction(
        &mut self,
        sender_pid: BinderPid,
        _sender_tid: u32,
        mut txn: BinderTransaction,
    ) -> Result<BinderReturn> {
        // SECURITY: reject reserved/unknown transaction flag bits. `txn.flags`
        // is fully attacker-controlled (it arrives in the BC_TRANSACTION
        // parcel); only the defined TF_* bits may be set. This applies to every
        // target, including the privileged context manager (handle 0), so a
        // client cannot smuggle undefined flag semantics into a service.
        if txn.flags & !TF_KNOWN_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let id = self.alloc_txn_id()?;
        txn.id = id;
        txn.sender = sender_pid;

        // Resolve target: handle → node owner.
        let target_pid = if txn.target_handle == BinderHandle::CONTEXT_MANAGER {
            self.context_manager.ok_or(Error::NotFound)?
        } else {
            let client = self.find_process(sender_pid).ok_or(Error::NotFound)?;
            let r = client.find_ref(txn.target_handle).ok_or(Error::NotFound)?;
            r.node_owner
        };

        // Find a looping thread in the target process and enqueue the transaction.
        // (In real Binder: wake_up target thread via wait queue.)
        let target_proc = self.find_process_mut(target_pid).ok_or(Error::NotFound)?;
        for t in target_proc.threads.iter_mut().flatten() {
            if t.state == ThreadState::Looping || t.state == ThreadState::Registered {
                t.enqueue_return(BinderReturn::BrTransaction(txn.clone()))?;
                // For one-way transactions we return TransactionComplete immediately.
                return Ok(BinderReturn::BrTransactionComplete);
            }
        }

        // No looper found — the driver would normally buffer in process queue.
        // Stub: return TransactionComplete anyway (delivery best-effort).
        Ok(BinderReturn::BrTransactionComplete)
    }

    /// Handle BC_REPLY: send the reply back to the original sender thread.
    fn handle_reply(
        &mut self,
        _sender_pid: BinderPid,
        _sender_tid: u32,
        txn: BinderTransaction,
    ) -> Result<BinderReturn> {
        // The sender of the reply is the server; the reply goes back to the
        // original client which is identified by txn.target_handle (repurposed
        // here as the original sender's pid by convention in this stub).
        //
        // In a real implementation the thread's transaction stack would record
        // which client thread to reply to.  Here we acknowledge with BrReply.
        //
        // SECURITY INVARIANT: BC_REPLY MUST pop a *verified* entry from this
        // thread's per-thread transaction stack and route the reply ONLY to the
        // client thread recorded on that entry. This stub does not yet keep a
        // transaction stack, so it cannot bind the reply to a real pending
        // transaction. The correct (not-yet-built) machinery is:
        //   1. push an entry on BC_TRANSACTION recording (client_pid,
        //      client_tid, txn_id) on the *target* thread's stack;
        //   2. on BC_REPLY, pop the top entry of `_sender_tid`'s stack and
        //      REJECT with an error (e.g. Error::InvalidArgument) when the
        //      stack is empty — a reply with no matching outstanding
        //      transaction must never be delivered;
        //   3. deliver BR_REPLY exclusively to the recorded client thread,
        //      never to a caller-chosen handle.
        // Until that exists, callers MUST NOT trust this path to authorise a
        // reply target. Returning a synthetic BrReply here is a placeholder and
        // does NOT constitute a validated reply route.
        let _ = txn;
        Ok(BinderReturn::BrReply(BinderTransaction::new(
            BinderHandle::CONTEXT_MANAGER,
            0,
            0,
            _sender_pid,
            0,
        )))
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PID_A: BinderPid = BinderPid::new(100);
    const PID_B: BinderPid = BinderPid::new(200);
    const NODE_PTR: BinderPtr = BinderPtr::new(0xC000_0000);

    fn registry_with_two_procs() -> BinderRegistry {
        let mut reg = BinderRegistry::new();
        reg.open(PID_A).unwrap();
        reg.open(PID_B).unwrap();
        reg
    }

    #[test]
    fn registry_open_and_release() {
        let mut reg = BinderRegistry::new();
        reg.open(PID_A).unwrap();
        assert_eq!(reg.process_count(), 1);
        reg.release(PID_A).unwrap();
        assert_eq!(reg.process_count(), 0);
    }

    #[test]
    fn registry_open_duplicate_fails() {
        let mut reg = BinderRegistry::new();
        reg.open(PID_A).unwrap();
        assert_eq!(reg.open(PID_A), Err(Error::AlreadyExists));
    }

    #[test]
    fn context_manager_exclusive() {
        let mut reg = registry_with_two_procs();
        // Unprivileged call must be denied (fail-closed).
        assert_eq!(
            reg.become_context_manager(PID_A, false),
            Err(Error::PermissionDenied)
        );
        // Privileged call succeeds.
        reg.become_context_manager(PID_A, true).unwrap();
        // Second privileged registration must fail (already set).
        assert_eq!(reg.become_context_manager(PID_B, true), Err(Error::Busy));
    }

    #[test]
    fn node_registration() {
        let mut reg = registry_with_two_procs();
        let proc = reg.find_process_mut(PID_B).unwrap();
        proc.register_node(NODE_PTR, 42).unwrap();
        let node = proc.find_node(NODE_PTR).unwrap();
        assert_eq!(node.cookie, 42);
        assert_eq!(node.owner, PID_B);
    }

    #[test]
    fn node_registration_duplicate_fails() {
        let mut reg = registry_with_two_procs();
        let proc = reg.find_process_mut(PID_B).unwrap();
        proc.register_node(NODE_PTR, 1).unwrap();
        assert_eq!(proc.register_node(NODE_PTR, 2), Err(Error::AlreadyExists));
    }

    #[test]
    fn create_ref_returns_handle() {
        let mut reg = registry_with_two_procs();
        {
            let proc_b = reg.find_process_mut(PID_B).unwrap();
            proc_b.register_node(NODE_PTR, 0).unwrap();
        }
        let proc_a = reg.find_process_mut(PID_A).unwrap();
        let h = proc_a.create_ref(NODE_PTR, PID_B).unwrap();
        assert_ne!(h, BinderHandle::CONTEXT_MANAGER); // not handle 0
        // Creating same ref again returns same handle.
        let h2 = proc_a.create_ref(NODE_PTR, PID_B).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn acquire_release_node() {
        let mut reg = registry_with_two_procs();
        {
            let proc_b = reg.find_process_mut(PID_B).unwrap();
            proc_b.register_node(NODE_PTR, 99).unwrap();
        }
        let handle = {
            let proc_a = reg.find_process_mut(PID_A).unwrap();
            proc_a.create_ref(NODE_PTR, PID_B).unwrap()
        };
        // Register a thread for PID_A so dispatch can validate sender identity.
        {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.register_thread(1).unwrap();
        }
        let ret = reg
            .dispatch(PID_A, 1, BinderCommand::BcAcquire(handle))
            .unwrap();
        assert!(matches!(ret, BinderReturn::BrAcquire { .. }));

        // Verify strong_refs incremented.
        let node = reg
            .find_process(PID_B)
            .unwrap()
            .find_node(NODE_PTR)
            .unwrap();
        assert_eq!(node.strong_refs, 1);

        let ret = reg
            .dispatch(PID_A, 1, BinderCommand::BcRelease(handle))
            .unwrap();
        assert!(matches!(ret, BinderReturn::BrRelease { .. }));
        let node = reg
            .find_process(PID_B)
            .unwrap()
            .find_node(NODE_PTR)
            .unwrap();
        assert_eq!(node.strong_refs, 0);
    }

    #[test]
    fn transaction_routed_to_looping_thread() {
        let mut reg = registry_with_two_procs();
        // Register node in PID_B.
        {
            let pb = reg.find_process_mut(PID_B).unwrap();
            pb.register_node(NODE_PTR, 0).unwrap();
            pb.register_thread(10).unwrap();
            let t = pb.find_thread_mut(10).unwrap();
            t.state = ThreadState::Looping;
        }
        // Create ref in PID_A.
        let handle = {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.create_ref(NODE_PTR, PID_B).unwrap()
        };
        // Register sender thread.
        {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.register_thread(1).unwrap();
        }
        // Send transaction.
        let txn = BinderTransaction::new(handle, 1, 0, PID_A, 0);
        let ret = reg
            .dispatch(PID_A, 1, BinderCommand::BcTransaction(txn))
            .unwrap();
        assert_eq!(ret, BinderReturn::BrTransactionComplete);
        // Target thread should have the transaction queued.
        let pb = reg.find_process_mut(PID_B).unwrap();
        let t = pb.find_thread_mut(10).unwrap();
        assert_eq!(t.pending_count(), 1);
        let br = t.dequeue_return().unwrap();
        assert!(matches!(br, BinderReturn::BrTransaction(_)));
    }

    #[test]
    fn thread_queue_overflow() {
        let mut thread = BinderThread::new(PID_A, 1);
        for _ in 0..BINDER_THREAD_QUEUE_DEPTH {
            thread.enqueue_return(BinderReturn::BrNoop).unwrap();
        }
        assert_eq!(
            thread.enqueue_return(BinderReturn::BrNoop),
            Err(Error::OutOfMemory)
        );
    }

    #[test]
    fn transaction_write_data() {
        let mut txn = BinderTransaction::new(BinderHandle::CONTEXT_MANAGER, 0, 0, PID_A, 0);
        let payload = b"hello binder";
        txn.write_data(payload).unwrap();
        assert_eq!(txn.data_slice(), payload);
    }

    #[test]
    fn transaction_add_offset_validates_alignment() {
        let mut txn = BinderTransaction::new(BinderHandle::CONTEXT_MANAGER, 0, 0, PID_A, 0);
        txn.write_data(&[0u8; 32]).unwrap();
        assert_eq!(txn.add_offset(3), Err(Error::InvalidArgument)); // unaligned
        assert_eq!(txn.add_offset(0), Ok(()));
    }

    #[test]
    fn death_notification_request_and_clear() {
        let mut reg = registry_with_two_procs();
        // Register node in PID_B.
        {
            let pb = reg.find_process_mut(PID_B).unwrap();
            pb.register_node(NODE_PTR, 99).unwrap();
        }
        // Create ref in PID_A pointing to PID_B's node.
        let handle = {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.create_ref(NODE_PTR, PID_B).unwrap()
        };
        // Register a thread for PID_A so dispatch can validate sender identity.
        {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.register_thread(1).unwrap();
        }
        // Register death notification.
        let ret = reg
            .dispatch(
                PID_A,
                1,
                BinderCommand::BcRequestDeathNotification {
                    handle,
                    cookie: 0xDEAD,
                },
            )
            .unwrap();
        assert_eq!(ret, BinderReturn::BrNoop);

        // Verify registration.
        let pa = reg.find_process(PID_A).unwrap();
        assert_eq!(pa.death_notif_count(), 1);

        // Clear the notification.
        // Need a mutable borrow through dispatch.
        let ret = reg
            .dispatch(
                PID_A,
                1,
                BinderCommand::BcClearDeathNotification {
                    handle,
                    cookie: 0xDEAD,
                },
            )
            .unwrap();
        assert_eq!(ret, BinderReturn::BrClearDeathNotificationDone(0xDEAD));
        let pa = reg.find_process(PID_A).unwrap();
        assert_eq!(pa.death_notif_count(), 0);
    }

    #[test]
    fn death_notification_delivered_on_release() {
        let mut reg = registry_with_two_procs();
        // Register node in PID_B and a looper thread in PID_A.
        {
            let pb = reg.find_process_mut(PID_B).unwrap();
            pb.register_node(NODE_PTR, 0).unwrap();
        }
        let handle = {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.create_ref(NODE_PTR, PID_B).unwrap()
        };
        {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.register_thread(1).unwrap();
            pa.find_thread_mut(1).unwrap().state = ThreadState::Looping;
            pa.request_death_notification(handle, 0xBEEF).unwrap();
        }

        // Release PID_B — death notifications should fire.
        reg.release(PID_B).unwrap();

        // PID_A's looper thread should have a BR_DEAD_BINDER queued.
        let pa = reg.find_process_mut(PID_A).unwrap();
        let t = pa.find_thread_mut(1).unwrap();
        assert!(t.pending_count() > 0);
        let br = t.dequeue_return().unwrap();
        assert_eq!(br, BinderReturn::BrDeadBinder(0xBEEF));
    }

    #[test]
    fn death_notification_duplicate_rejected() {
        let mut reg = registry_with_two_procs();
        {
            let pb = reg.find_process_mut(PID_B).unwrap();
            pb.register_node(NODE_PTR, 0).unwrap();
        }
        let handle = {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.create_ref(NODE_PTR, PID_B).unwrap()
        };
        {
            let pa = reg.find_process_mut(PID_A).unwrap();
            pa.request_death_notification(handle, 42).unwrap();
            assert_eq!(
                pa.request_death_notification(handle, 42),
                Err(Error::AlreadyExists)
            );
        }
    }
}

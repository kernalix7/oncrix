// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX message queue implementation.
//!
//! Provides named, priority-ordered message queues following the
//! POSIX.1-2024 `mq_open` / `mq_send` / `mq_receive` semantics.
//! Messages are delivered highest-priority-first (largest numerical
//! value first); within the same priority, FIFO ordering is preserved.
//!
//! This is a kernel-internal implementation; the syscall layer maps
//! `mq_open`, `mq_close`, `mq_unlink`, `mq_send`, `mq_receive`,
//! `mq_getattr`, and `mq_setattr` onto these primitives.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of bytes in a single message payload.
const MQ_MSG_MAX_SIZE: usize = 256;

/// Maximum number of messages a queue can hold.
const MQ_MAX_MESSAGES: usize = 32;

/// Maximum length of a message queue name (including the leading `/`).
const MQ_NAME_MAX: usize = 64;

/// Maximum number of named message queues in the registry.
const MQ_REGISTRY_MAX: usize = 32;

// -------------------------------------------------------------------
// MqOpenFlags
// -------------------------------------------------------------------

/// Flags for [`mq_open`].
///
/// Mirrors the POSIX `O_*` flags relevant to message queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqOpenFlags(u32);

impl MqOpenFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Open for reading only.
    pub const O_RDONLY: Self = Self(1 << 0);
    /// Open for writing only.
    pub const O_WRONLY: Self = Self(1 << 1);
    /// Open for reading and writing.
    pub const O_RDWR: Self = Self(1 << 2);
    /// Create the queue if it does not exist.
    pub const O_CREAT: Self = Self(1 << 3);
    /// Fail if the queue already exists (used with `O_CREAT`).
    pub const O_EXCL: Self = Self(1 << 4);
    /// Enable non-blocking mode for send/receive.
    pub const O_NONBLOCK: Self = Self(1 << 5);

    /// Create flags from a raw `u32` value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check whether `other` flags are all set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for MqOpenFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// -------------------------------------------------------------------
// MqAttr
// -------------------------------------------------------------------

/// Message queue attributes (`mq_attr`).
///
/// Corresponds to the POSIX `struct mq_attr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqAttr {
    /// Flags (currently only `O_NONBLOCK` is meaningful).
    pub mq_flags: u32,
    /// Maximum number of messages on the queue.
    pub mq_maxmsg: u32,
    /// Maximum message size in bytes.
    pub mq_msgsize: u32,
    /// Current number of messages on the queue (read-only).
    pub mq_curmsgs: u32,
}

impl MqAttr {
    /// Create a new `MqAttr` with default limits.
    pub const fn new() -> Self {
        Self {
            mq_flags: 0,
            mq_maxmsg: MQ_MAX_MESSAGES as u32,
            mq_msgsize: MQ_MSG_MAX_SIZE as u32,
            mq_curmsgs: 0,
        }
    }
}

impl Default for MqAttr {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MqMessage
// -------------------------------------------------------------------

/// A single message stored in a queue.
///
/// Carries a priority value (higher = delivered first) and up to
/// [`MQ_MSG_MAX_SIZE`] bytes of payload data.
#[derive(Clone)]
pub struct MqMessage {
    /// Message priority (higher value = higher priority).
    priority: u32,
    /// Number of valid bytes in `data`.
    len: usize,
    /// Payload data.
    data: [u8; MQ_MSG_MAX_SIZE],
}

impl MqMessage {
    /// Create an empty message with priority 0.
    pub const fn new() -> Self {
        Self {
            priority: 0,
            len: 0,
            data: [0u8; MQ_MSG_MAX_SIZE],
        }
    }

    /// Return the message priority.
    pub const fn priority(&self) -> u32 {
        self.priority
    }

    /// Return the payload length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the payload is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return a slice over the valid payload bytes.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Default for MqMessage {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MessageQueue
// -------------------------------------------------------------------

/// A named, priority-sorted message queue.
///
/// Messages are stored in a fixed-size array sorted by descending
/// priority.  Receive always returns the highest-priority message.
pub struct MessageQueue {
    /// Queue name (UTF-8, starts with `/`).
    name: [u8; MQ_NAME_MAX],
    /// Length of the name (bytes).
    name_len: usize,
    /// Queue attributes.
    attrs: MqAttr,
    /// Permission mode (POSIX-style, e.g. 0o644).
    permissions: u32,
    /// Stored messages, sorted by descending priority.
    messages: [MqMessage; MQ_MAX_MESSAGES],
    /// Number of messages currently stored.
    count: usize,
    /// Whether this queue has been unlinked (pending removal).
    unlinked: bool,
    /// Number of open descriptors referencing this queue.
    ref_count: usize,
}

impl MessageQueue {
    /// Create a new, empty message queue.
    const fn new() -> Self {
        Self {
            name: [0u8; MQ_NAME_MAX],
            name_len: 0,
            attrs: MqAttr::new(),
            permissions: 0o644,
            messages: [const { MqMessage::new() }; MQ_MAX_MESSAGES],
            count: 0,
            unlinked: false,
            ref_count: 0,
        }
    }

    /// Return the queue name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the current attributes (snapshot).
    pub fn attrs(&self) -> MqAttr {
        let mut a = self.attrs;
        a.mq_curmsgs = self.count as u32;
        a
    }

    /// Set mutable attributes (only `mq_flags` is writable).
    pub fn set_attrs(&mut self, new: &MqAttr) -> MqAttr {
        let old = self.attrs();
        self.attrs.mq_flags = new.mq_flags;
        old
    }

    /// Return the permission mode.
    pub const fn permissions(&self) -> u32 {
        self.permissions
    }

    /// Return the number of messages.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count >= self.attrs.mq_maxmsg as usize
    }

    /// Insert a message in priority-sorted order.
    ///
    /// Returns `WouldBlock` if the queue is full.
    fn push(&mut self, data: &[u8], len: usize, priority: u32) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        let actual_len = len.min(self.attrs.mq_msgsize as usize);

        // Find insertion point: keep descending priority order.
        let mut pos = self.count;
        while pos > 0 && self.messages[pos - 1].priority < priority {
            pos -= 1;
        }

        // Shift messages after `pos` one slot to the right.
        let mut i = self.count;
        while i > pos {
            // Clone the message from the previous slot.
            self.messages[i] = self.messages[i - 1].clone();
            i -= 1;
        }

        // Write the new message into the insertion slot.
        let slot = &mut self.messages[pos];
        slot.priority = priority;
        slot.len = actual_len;
        slot.data[..actual_len].copy_from_slice(&data[..actual_len]);

        self.count += 1;
        Ok(())
    }

    /// Remove and return the highest-priority message.
    ///
    /// Returns `WouldBlock` if the queue is empty.
    fn pop(&mut self, buf: &mut [u8]) -> Result<(usize, u32)> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }

        let msg = &self.messages[0];
        let copy_len = msg.len.min(buf.len());
        buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
        let priority = msg.priority;
        let msg_len = msg.len;

        // Shift remaining messages forward.
        let mut i = 1;
        while i < self.count {
            self.messages[i - 1] = self.messages[i].clone();
            i += 1;
        }
        // Clear the vacated last slot.
        self.messages[self.count - 1] = MqMessage::new();
        self.count -= 1;

        Ok((msg_len.min(copy_len), priority))
    }
}

// -------------------------------------------------------------------
// MqDescriptor
// -------------------------------------------------------------------

/// Opaque descriptor handle for an open message queue.
///
/// Combines a registry index with a generation counter to detect
/// use-after-close / use-after-unlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqDescriptor {
    /// Index into the registry's queue array.
    index: usize,
    /// Generation counter at the time the descriptor was issued.
    generation: u32,
    /// Access flags the descriptor was opened with.
    flags: MqOpenFlags,
}

impl MqDescriptor {
    /// Create a new descriptor.
    const fn new(index: usize, generation: u32, flags: MqOpenFlags) -> Self {
        Self {
            index,
            generation,
            flags,
        }
    }

    /// Return the registry index.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Return the generation counter.
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Return the flags the descriptor was opened with.
    pub const fn flags(&self) -> MqOpenFlags {
        self.flags
    }
}

// -------------------------------------------------------------------
// MqRegistry
// -------------------------------------------------------------------

/// Registry slot holding an optional queue and its generation counter.
struct MqSlot {
    /// The queue (if active).
    queue: Option<MessageQueue>,
    /// Generation counter; incremented on each unlink.
    generation: u32,
}

impl MqSlot {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self {
            queue: None,
            generation: 0,
        }
    }
}

/// Global registry of named POSIX message queues.
///
/// Holds up to [`MQ_REGISTRY_MAX`] queues, identified by name.
pub struct MqRegistry {
    /// Slot array.
    slots: [MqSlot; MQ_REGISTRY_MAX],
    /// Number of active (non-unlinked) queues.
    count: usize,
}

impl MqRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [const { MqSlot::empty() }; MQ_REGISTRY_MAX],
            count: 0,
        }
    }

    /// Return the number of active queues.
    pub const fn count(&self) -> usize {
        self.count
    }

    // -- helpers ---------------------------------------------------

    /// Find a slot index by queue name, considering only active
    /// (non-unlinked) queues.
    fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(ref q) = slot.queue {
                if !q.unlinked && q.name() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find a free slot index.
    fn find_free(&self) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.queue.is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Validate a descriptor against the registry.
    fn validate(&self, mqd: &MqDescriptor) -> Result<()> {
        if mqd.index >= MQ_REGISTRY_MAX {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.slots[mqd.index];
        match slot.queue {
            Some(_) if slot.generation == mqd.generation => Ok(()),
            _ => Err(Error::NotFound),
        }
    }

    /// Validate and return a mutable reference to the queue.
    fn get_queue_mut(&mut self, mqd: &MqDescriptor) -> Result<&mut MessageQueue> {
        self.validate(mqd)?;
        self.slots[mqd.index].queue.as_mut().ok_or(Error::NotFound)
    }

    /// Validate and return a shared reference to the queue.
    fn get_queue(&self, mqd: &MqDescriptor) -> Result<&MessageQueue> {
        self.validate(mqd)?;
        self.slots[mqd.index].queue.as_ref().ok_or(Error::NotFound)
    }

    /// Remove a queue if it is both unlinked and has zero references.
    fn maybe_destroy(&mut self, index: usize) {
        if let Some(ref q) = self.slots[index].queue {
            if q.unlinked && q.ref_count == 0 {
                self.slots[index].queue = None;
                self.slots[index].generation = self.slots[index].generation.wrapping_add(1);
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for MqRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// POSIX-like API functions
// -------------------------------------------------------------------

/// Validate that a queue name starts with `/` and is not too long.
fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > MQ_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    if name[0] != b'/' {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Open or create a POSIX message queue.
///
/// `name` must start with `/` and be at most [`MQ_NAME_MAX`] bytes.
/// `flags` controls creation and access mode.  `mode` sets POSIX
/// permissions (only used when creating).  `attr` optionally overrides
/// the default queue attributes (only used when creating).
///
/// Returns a [`MqDescriptor`] on success.
pub fn mq_open(
    registry: &mut MqRegistry,
    name: &[u8],
    flags: MqOpenFlags,
    mode: u32,
    attr: Option<&MqAttr>,
) -> Result<MqDescriptor> {
    validate_name(name)?;

    let existing = registry.find_by_name(name);

    if let Some(idx) = existing {
        // Queue exists.
        if flags.contains(MqOpenFlags::O_CREAT) && flags.contains(MqOpenFlags::O_EXCL) {
            return Err(Error::AlreadyExists);
        }
        if let Some(ref mut q) = registry.slots[idx].queue {
            q.ref_count = q.ref_count.saturating_add(1);
        }
        let generation = registry.slots[idx].generation;
        return Ok(MqDescriptor::new(idx, generation, flags));
    }

    // Queue does not exist — must have O_CREAT.
    if !flags.contains(MqOpenFlags::O_CREAT) {
        return Err(Error::NotFound);
    }

    let idx = registry.find_free().ok_or(Error::OutOfMemory)?;

    let mut queue = MessageQueue::new();
    queue.name[..name.len()].copy_from_slice(name);
    queue.name_len = name.len();
    queue.permissions = mode;
    if let Some(a) = attr {
        if a.mq_maxmsg == 0 || a.mq_maxmsg > MQ_MAX_MESSAGES as u32 {
            return Err(Error::InvalidArgument);
        }
        if a.mq_msgsize == 0 || a.mq_msgsize > MQ_MSG_MAX_SIZE as u32 {
            return Err(Error::InvalidArgument);
        }
        queue.attrs.mq_maxmsg = a.mq_maxmsg;
        queue.attrs.mq_msgsize = a.mq_msgsize;
    }
    queue.ref_count = 1;

    let generation = registry.slots[idx].generation;
    registry.slots[idx].queue = Some(queue);
    registry.count += 1;

    Ok(MqDescriptor::new(idx, generation, flags))
}

/// Close a message queue descriptor.
///
/// Decrements the reference count.  If the queue has been unlinked
/// and no descriptors remain, the queue is destroyed.
pub fn mq_close(registry: &mut MqRegistry, mqd: &MqDescriptor) -> Result<()> {
    registry.validate(mqd)?;

    if let Some(ref mut q) = registry.slots[mqd.index].queue {
        q.ref_count = q.ref_count.saturating_sub(1);
    }
    registry.maybe_destroy(mqd.index);
    Ok(())
}

/// Remove a named message queue.
///
/// The name is removed immediately so that new `mq_open` calls will
/// not find it.  The queue itself persists until all descriptors are
/// closed.
pub fn mq_unlink(registry: &mut MqRegistry, name: &[u8]) -> Result<()> {
    validate_name(name)?;
    let idx = registry.find_by_name(name).ok_or(Error::NotFound)?;

    if let Some(ref mut q) = registry.slots[idx].queue {
        q.unlinked = true;
    }
    registry.maybe_destroy(idx);
    Ok(())
}

/// Send a message to a message queue.
///
/// The message is inserted in priority-sorted order (highest first).
/// Returns `WouldBlock` if the queue is full and `O_NONBLOCK` is set
/// (or always in the current non-blocking implementation).
pub fn mq_send(
    registry: &mut MqRegistry,
    mqd: &MqDescriptor,
    msg: &[u8],
    len: usize,
    priority: u32,
) -> Result<()> {
    // Must have write access.
    if !mqd.flags().contains(MqOpenFlags::O_WRONLY) && !mqd.flags().contains(MqOpenFlags::O_RDWR) {
        return Err(Error::PermissionDenied);
    }
    let actual_len = len.min(msg.len());
    let queue = registry.get_queue_mut(mqd)?;

    if actual_len > queue.attrs.mq_msgsize as usize {
        return Err(Error::InvalidArgument);
    }

    queue.push(msg, actual_len, priority)
}

/// Receive the highest-priority message from a queue.
///
/// Copies the message data into `buf` and returns `(bytes_copied,
/// priority)`.  Returns `WouldBlock` if the queue is empty.
pub fn mq_receive(
    registry: &mut MqRegistry,
    mqd: &MqDescriptor,
    buf: &mut [u8],
    len: usize,
) -> Result<(usize, u32)> {
    // Must have read access.
    if !mqd.flags().contains(MqOpenFlags::O_RDONLY) && !mqd.flags().contains(MqOpenFlags::O_RDWR) {
        return Err(Error::PermissionDenied);
    }
    let max_len = len.min(buf.len());
    let queue = registry.get_queue_mut(mqd)?;
    queue.pop(&mut buf[..max_len])
}

/// Get the attributes of an open message queue.
pub fn mq_getattr(registry: &MqRegistry, mqd: &MqDescriptor) -> Result<MqAttr> {
    let queue = registry.get_queue(mqd)?;
    Ok(queue.attrs())
}

/// Set attributes on an open message queue.
///
/// Only `mq_flags` can be modified (to toggle `O_NONBLOCK`).
/// Returns the previous attributes.
pub fn mq_setattr(
    registry: &mut MqRegistry,
    mqd: &MqDescriptor,
    new_attr: &MqAttr,
) -> Result<MqAttr> {
    let queue = registry.get_queue_mut(mqd)?;
    Ok(queue.set_attrs(new_attr))
}

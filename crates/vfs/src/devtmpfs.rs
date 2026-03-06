// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! devtmpfs — automatic device node filesystem.
//!
//! Implements the devtmpfs subsystem that automatically creates and removes
//! device nodes under `/dev` in response to device hotplug events:
//! - [`DevtmpfsEntry`] — a device node descriptor (name, mode, devno, uid, gid)
//! - [`devtmpfs_create_node`] — create a device node
//! - [`devtmpfs_delete_node`] — remove a device node
//! - Auto-creation triggered by `device_add` uevent (stubbed)
//! - `/dev` population logic: populate static nodes at boot
//!
//! # Design
//!
//! devtmpfs mounts a tmpfs at `/dev` during early boot and then services
//! a kernel thread (`kdevtmpfs`) which receives device-add/remove requests
//! from the driver core and calls `mknod`/`unlink` accordingly.
//!
//! # References
//! - Linux `drivers/base/devtmpfs.c`
//! - Linux `Documentation/filesystems/devtmpfs.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum device node name length.
pub const DEVTMPFS_NAME_MAX: usize = 256;

/// Maximum number of device nodes.
const MAX_DEVICE_NODES: usize = 1024;

/// Maximum pending uevent requests.
const MAX_PENDING_UEVENTS: usize = 64;

// ---------------------------------------------------------------------------
// Device type
// ---------------------------------------------------------------------------

/// Type of a device node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevNodeType {
    /// Character device.
    Char,
    /// Block device.
    Block,
}

// ---------------------------------------------------------------------------
// DevtmpfsEntry
// ---------------------------------------------------------------------------

/// A single devtmpfs device node entry.
#[derive(Clone)]
pub struct DevtmpfsEntry {
    /// Node name (relative path under `/dev`).
    pub name: [u8; DEVTMPFS_NAME_MAX],
    /// Length of name.
    pub name_len: usize,
    /// File mode (type bits + permission bits). The top bits encode whether
    /// this is a char or block device.
    pub mode: u32,
    /// Major device number.
    pub major: u32,
    /// Minor device number.
    pub minor: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Node type.
    pub node_type: DevNodeType,
}

impl DevtmpfsEntry {
    /// Create a new character device node entry.
    pub fn new_chr(
        name: &[u8],
        mode: u32,
        major: u32,
        minor: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        if name.len() > DEVTMPFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            name: [0u8; DEVTMPFS_NAME_MAX],
            name_len: name.len(),
            mode: 0o020000 | (mode & 0o7777),
            major,
            minor,
            uid,
            gid,
            node_type: DevNodeType::Char,
        };
        entry.name[..name.len()].copy_from_slice(name);
        Ok(entry)
    }

    /// Create a new block device node entry.
    pub fn new_blk(
        name: &[u8],
        mode: u32,
        major: u32,
        minor: u32,
        uid: u32,
        gid: u32,
    ) -> Result<Self> {
        if name.len() > DEVTMPFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            name: [0u8; DEVTMPFS_NAME_MAX],
            name_len: name.len(),
            mode: 0o060000 | (mode & 0o7777),
            major,
            minor,
            uid,
            gid,
            node_type: DevNodeType::Block,
        };
        entry.name[..name.len()].copy_from_slice(name);
        Ok(entry)
    }

    /// Return the node name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Encode major/minor into a `dev_t` (Linux MKDEV(major, minor) convention).
    pub fn devno(&self) -> u64 {
        ((self.major as u64) << 8) | (self.minor as u64)
    }
}

// ---------------------------------------------------------------------------
// DevtmpfsState — the /dev filesystem state
// ---------------------------------------------------------------------------

/// The in-memory state of the devtmpfs `/dev` filesystem.
pub struct DevtmpfsState {
    nodes: [Option<DevtmpfsEntry>; MAX_DEVICE_NODES],
    count: usize,
}

impl DevtmpfsState {
    /// Create an empty devtmpfs state.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.nodes[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for DevtmpfsState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// devtmpfs_create_node
// ---------------------------------------------------------------------------

/// Create a device node in devtmpfs.
///
/// Returns `Err(AlreadyExists)` if a node with the same name already exists.
/// Returns `Err(OutOfMemory)` if the node table is full.
pub fn devtmpfs_create_node(state: &mut DevtmpfsState, entry: DevtmpfsEntry) -> Result<()> {
    if state.find(entry.name_bytes()).is_some() {
        return Err(Error::AlreadyExists);
    }
    if state.count >= MAX_DEVICE_NODES {
        return Err(Error::OutOfMemory);
    }
    state.nodes[state.count] = Some(entry);
    state.count += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// devtmpfs_delete_node
// ---------------------------------------------------------------------------

/// Delete a device node from devtmpfs by name.
///
/// Returns `Err(NotFound)` if the node does not exist.
pub fn devtmpfs_delete_node(state: &mut DevtmpfsState, name: &[u8]) -> Result<()> {
    let idx = state.find(name).ok_or(Error::NotFound)?;
    if idx < state.count - 1 {
        state.nodes.swap(idx, state.count - 1);
    }
    state.nodes[state.count - 1] = None;
    state.count -= 1;
    Ok(())
}

/// Look up a device node by name.
pub fn devtmpfs_lookup<'a>(state: &'a DevtmpfsState, name: &[u8]) -> Option<&'a DevtmpfsEntry> {
    let idx = state.find(name)?;
    state.nodes[idx].as_ref()
}

// ---------------------------------------------------------------------------
// Uevent request queue
// ---------------------------------------------------------------------------

/// Type of uevent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UeventAction {
    /// Device added.
    Add,
    /// Device removed.
    Remove,
}

/// A pending uevent request for the kdevtmpfs thread.
pub struct UeventRequest {
    /// Action to perform.
    pub action: UeventAction,
    /// Device node to create or remove.
    pub entry: Option<DevtmpfsEntry>,
    /// Name of the node to remove (used when action == Remove).
    pub remove_name: [u8; DEVTMPFS_NAME_MAX],
    /// Length of remove_name.
    pub remove_name_len: usize,
}

/// Uevent request queue.
pub struct UeventQueue {
    requests: [Option<UeventRequest>; MAX_PENDING_UEVENTS],
    head: usize,
    tail: usize,
    count: usize,
}

impl UeventQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self {
            requests: core::array::from_fn(|_| None),
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueue an ADD request.
    pub fn enqueue_add(&mut self, entry: DevtmpfsEntry) -> Result<()> {
        if self.count >= MAX_PENDING_UEVENTS {
            return Err(Error::WouldBlock);
        }
        self.requests[self.tail] = Some(UeventRequest {
            action: UeventAction::Add,
            entry: Some(entry),
            remove_name: [0u8; DEVTMPFS_NAME_MAX],
            remove_name_len: 0,
        });
        self.tail = (self.tail + 1) % MAX_PENDING_UEVENTS;
        self.count += 1;
        Ok(())
    }

    /// Enqueue a REMOVE request.
    pub fn enqueue_remove(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > DEVTMPFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_PENDING_UEVENTS {
            return Err(Error::WouldBlock);
        }
        let mut req = UeventRequest {
            action: UeventAction::Remove,
            entry: None,
            remove_name: [0u8; DEVTMPFS_NAME_MAX],
            remove_name_len: name.len(),
        };
        req.remove_name[..name.len()].copy_from_slice(name);
        self.requests[self.tail] = Some(req);
        self.tail = (self.tail + 1) % MAX_PENDING_UEVENTS;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next pending request.
    pub fn dequeue(&mut self) -> Option<UeventRequest> {
        if self.count == 0 {
            return None;
        }
        let req = self.requests[self.head].take();
        self.head = (self.head + 1) % MAX_PENDING_UEVENTS;
        self.count -= 1;
        req
    }

    /// Return the number of pending requests.
    pub fn pending(&self) -> usize {
        self.count
    }
}

impl Default for UeventQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Process a uevent batch (kdevtmpfs thread body simulation)
// ---------------------------------------------------------------------------

/// Process all pending uevent requests against the devtmpfs state.
///
/// Returns the number of requests processed.
pub fn process_uevents(state: &mut DevtmpfsState, queue: &mut UeventQueue) -> usize {
    let mut processed = 0;
    while let Some(req) = queue.dequeue() {
        match req.action {
            UeventAction::Add => {
                if let Some(entry) = req.entry {
                    devtmpfs_create_node(state, entry).ok();
                }
            }
            UeventAction::Remove => {
                let name = &req.remove_name[..req.remove_name_len];
                devtmpfs_delete_node(state, name).ok();
            }
        }
        processed += 1;
    }
    processed
}

// ---------------------------------------------------------------------------
// Boot-time /dev population
// ---------------------------------------------------------------------------

/// Populate the initial `/dev` with mandatory static device nodes.
///
/// Creates the standard character devices that must be present before any
/// udev daemon starts (e.g., `/dev/null`, `/dev/zero`, `/dev/random`).
pub fn devtmpfs_populate_boot(state: &mut DevtmpfsState) -> Result<()> {
    let nodes: &[(&[u8], u32, u32)] = &[
        (b"null", 1, 3),
        (b"zero", 1, 5),
        (b"full", 1, 7),
        (b"random", 1, 8),
        (b"urandom", 1, 9),
        (b"console", 5, 1),
        (b"tty", 5, 0),
        (b"ptmx", 5, 2),
        (b"kmsg", 1, 11),
    ];
    for (name, major, minor) in nodes {
        let entry = DevtmpfsEntry::new_chr(name, 0o666, *major, *minor, 0, 0)?;
        // Ignore AlreadyExists on re-population.
        devtmpfs_create_node(state, entry).ok();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_lookup_delete() {
        let mut state = DevtmpfsState::new();
        let entry = DevtmpfsEntry::new_chr(b"ttyS0", 0o666, 4, 64, 0, 0).unwrap();
        devtmpfs_create_node(&mut state, entry).unwrap();
        assert!(devtmpfs_lookup(&state, b"ttyS0").is_some());
        devtmpfs_delete_node(&mut state, b"ttyS0").unwrap();
        assert!(devtmpfs_lookup(&state, b"ttyS0").is_none());
    }

    #[test]
    fn test_boot_populate() {
        let mut state = DevtmpfsState::new();
        devtmpfs_populate_boot(&mut state).unwrap();
        assert!(devtmpfs_lookup(&state, b"null").is_some());
        assert!(devtmpfs_lookup(&state, b"urandom").is_some());
    }

    #[test]
    fn test_uevent_queue() {
        let mut state = DevtmpfsState::new();
        let mut queue = UeventQueue::new();
        let entry = DevtmpfsEntry::new_blk(b"sda", 0o660, 8, 0, 0, 0).unwrap();
        queue.enqueue_add(entry).unwrap();
        queue.enqueue_remove(b"sda").unwrap();
        assert_eq!(queue.pending(), 2);
        process_uevents(&mut state, &mut queue);
        assert_eq!(queue.pending(), 0);
    }
}

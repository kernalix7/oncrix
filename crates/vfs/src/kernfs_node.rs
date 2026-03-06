// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernfs internal node management.
//!
//! kernfs is the infrastructure layer underlying both sysfs and debugfs.
//! Each node in the kernfs tree is a [`KernfsNode`] with a name, mode, parent
//! link, type flags (DIR/FILE/LINK), and an active reference count.
//!
//! # Design
//!
//! - [`KernfsNode`] — the core node structure
//! - [`KernfsFlags`] — node type and state flags
//! - `kernfs_new_node` / `kernfs_activate` / `kernfs_deactivate` / `kernfs_remove`
//! - `kernfs_dir_ops` — lookup and readdir for directory nodes
//! - Attribute file operations (read/write dispatch)
//! - Active reference counting via `activate` / `deactivate`
//!
//! # References
//!
//! - Linux `fs/kernfs/dir.c`, `fs/kernfs/file.c`
//! - `include/linux/kernfs.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum nodes in the kernfs tree.
pub const MAX_KERNFS_NODES: usize = 2048;

/// Maximum name length for a node.
pub const MAX_NODE_NAME: usize = 128;

/// Maximum attribute data size.
pub const MAX_ATTR_DATA: usize = 4096;

/// Base inode number for kernfs nodes.
pub const KERNFS_INO_BASE: u64 = 0xE0000;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Node type: directory.
pub const KERNFS_DIR: u32 = 1 << 0;
/// Node type: regular attribute file.
pub const KERNFS_FILE: u32 = 1 << 1;
/// Node type: symbolic link.
pub const KERNFS_LINK: u32 = 1 << 2;
/// Node state: active (visible to VFS).
pub const KERNFS_ACTIVE: u32 = 1 << 8;
/// Node state: deactivated (draining active refs).
pub const KERNFS_DEACTIVATED: u32 = 1 << 9;
/// Node state: removed (not visible, ref == 0 pending free).
pub const KERNFS_REMOVED: u32 = 1 << 10;
/// Node flag: hidden (not returned from readdir).
pub const KERNFS_HIDDEN: u32 = 1 << 11;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Kernfs node flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernfsFlags(pub u32);

impl KernfsFlags {
    /// Returns true if this is a directory node.
    pub fn is_dir(self) -> bool {
        self.0 & KERNFS_DIR != 0
    }

    /// Returns true if this is a file node.
    pub fn is_file(self) -> bool {
        self.0 & KERNFS_FILE != 0
    }

    /// Returns true if this is a link node.
    pub fn is_link(self) -> bool {
        self.0 & KERNFS_LINK != 0
    }

    /// Returns true if the node is active.
    pub fn is_active(self) -> bool {
        self.0 & KERNFS_ACTIVE != 0
    }

    /// Returns true if the node is deactivated.
    pub fn is_deactivated(self) -> bool {
        self.0 & KERNFS_DEACTIVATED != 0
    }

    /// Returns true if the node has been removed.
    pub fn is_removed(self) -> bool {
        self.0 & KERNFS_REMOVED != 0
    }
}

/// A kernfs node.
#[derive(Clone)]
pub struct KernfsNode {
    /// Node name.
    pub name: [u8; MAX_NODE_NAME],
    /// Name length.
    pub name_len: usize,
    /// File mode (permission bits + type bits).
    pub mode: u32,
    /// Parent node inode (0 = root / no parent).
    pub parent_ino: u64,
    /// This node's inode number.
    pub ino: u64,
    /// Node type and state flags.
    pub flags: KernfsFlags,
    /// Active reference count.
    pub active_refs: i32,
    /// Symlink target (only valid for KERNFS_LINK nodes).
    pub link_target_ino: u64,
    /// Attribute data (only valid for KERNFS_FILE nodes).
    pub attr_data: [u8; MAX_ATTR_DATA],
    /// Length of valid data in `attr_data`.
    pub attr_data_len: usize,
    /// Private data pointer (simulated as u64).
    pub priv_data: u64,
    /// Slot in use.
    pub in_use: bool,
}

impl KernfsNode {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_NODE_NAME],
            name_len: 0,
            mode: 0,
            parent_ino: 0,
            ino: 0,
            flags: KernfsFlags(0),
            active_refs: 0,
            link_target_ino: 0,
            attr_data: [0u8; MAX_ATTR_DATA],
            attr_data_len: 0,
            priv_data: 0,
            in_use: false,
        }
    }

    /// Return the node name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// The kernfs node table.
pub struct KernfsTree {
    nodes: [KernfsNode; MAX_KERNFS_NODES],
    count: usize,
    next_ino: u64,
}

impl KernfsTree {
    /// Create a new empty kernfs tree.
    pub fn new() -> Self {
        Self {
            nodes: core::array::from_fn(|_| KernfsNode::empty()),
            count: 0,
            next_ino: KERNFS_INO_BASE + 1,
        }
    }

    fn find_by_ino(&self, ino: u64) -> Option<usize> {
        for i in 0..MAX_KERNFS_NODES {
            if self.nodes[i].in_use && self.nodes[i].ino == ino {
                return Some(i);
            }
        }
        None
    }

    fn find_by_name(&self, parent_ino: u64, name: &[u8]) -> Option<usize> {
        for i in 0..MAX_KERNFS_NODES {
            if self.nodes[i].in_use
                && self.nodes[i].parent_ino == parent_ino
                && self.nodes[i].name_bytes() == name
                && !self.nodes[i].flags.is_removed()
            {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_KERNFS_NODES {
            if !self.nodes[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

impl Default for KernfsTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a new kernfs node.
///
/// Returns the inode number of the new node.
pub fn kernfs_new_node(
    tree: &mut KernfsTree,
    parent_ino: u64,
    name: &[u8],
    mode: u32,
    type_flag: u32, // KERNFS_DIR / KERNFS_FILE / KERNFS_LINK
) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_NODE_NAME {
        return Err(Error::InvalidArgument);
    }
    if tree.find_by_name(parent_ino, name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = tree.free_slot().ok_or(Error::OutOfMemory)?;
    let ino = tree.alloc_ino();

    let mut node = KernfsNode::empty();
    node.name[..name.len()].copy_from_slice(name);
    node.name_len = name.len();
    node.mode = mode;
    node.parent_ino = parent_ino;
    node.ino = ino;
    node.flags = KernfsFlags(type_flag);
    node.in_use = true;

    tree.nodes[slot] = node;
    tree.count += 1;
    Ok(ino)
}

/// Activate a node — make it visible in the VFS.
///
/// Increments active_refs to 1 and sets the KERNFS_ACTIVE flag.
pub fn kernfs_activate(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    if tree.nodes[slot].flags.is_active() {
        return Err(Error::InvalidArgument);
    }
    tree.nodes[slot].flags.0 |= KERNFS_ACTIVE;
    tree.nodes[slot].flags.0 &= !KERNFS_DEACTIVATED;
    tree.nodes[slot].active_refs = 1;
    Ok(())
}

/// Deactivate a node — begin the removal process.
///
/// Sets the KERNFS_DEACTIVATED flag; new lookups will fail but existing
/// references continue until `active_refs` drops to 0.
pub fn kernfs_deactivate(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].flags.0 &= !KERNFS_ACTIVE;
    tree.nodes[slot].flags.0 |= KERNFS_DEACTIVATED;
    Ok(())
}

/// Remove a node from the tree.
///
/// The node is marked KERNFS_REMOVED. The slot is freed when `active_refs`
/// drops to 0 (call `kernfs_put` for each reference).
pub fn kernfs_remove(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].flags.0 |= KERNFS_REMOVED;
    tree.nodes[slot].flags.0 &= !KERNFS_ACTIVE;
    if tree.nodes[slot].active_refs <= 0 {
        tree.nodes[slot] = KernfsNode::empty();
        tree.count = tree.count.saturating_sub(1);
    }
    Ok(())
}

/// Increment the active reference count for a node.
pub fn kernfs_get(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].active_refs += 1;
    Ok(())
}

/// Decrement the active reference count for a node.
///
/// If the count reaches 0 and the node is marked removed, the slot is freed.
pub fn kernfs_put(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].active_refs -= 1;
    if tree.nodes[slot].active_refs <= 0 && tree.nodes[slot].flags.is_removed() {
        tree.nodes[slot] = KernfsNode::empty();
        tree.count = tree.count.saturating_sub(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dir ops
// ---------------------------------------------------------------------------

/// Lookup a child node in a directory by name.
///
/// Returns the child's inode number, or `Err(NotFound)`.
pub fn kernfs_lookup(tree: &KernfsTree, dir_ino: u64, name: &[u8]) -> Result<u64> {
    let slot = tree.find_by_name(dir_ino, name).ok_or(Error::NotFound)?;
    if !tree.nodes[slot].flags.is_active() {
        return Err(Error::NotFound);
    }
    Ok(tree.nodes[slot].ino)
}

/// Read directory entries for `dir_ino`.
///
/// Fills `out` with `(ino, flags, name_buf, name_len)` tuples.
/// Returns the number of entries written.
pub fn kernfs_readdir(
    tree: &KernfsTree,
    dir_ino: u64,
    out: &mut [(u64, KernfsFlags, [u8; MAX_NODE_NAME], usize)],
) -> usize {
    let mut written = 0;
    for i in 0..MAX_KERNFS_NODES {
        if written >= out.len() {
            break;
        }
        let node = &tree.nodes[i];
        if !node.in_use {
            continue;
        }
        if node.parent_ino != dir_ino {
            continue;
        }
        if node.flags.is_removed() {
            continue;
        }
        if node.flags.0 & KERNFS_HIDDEN != 0 {
            continue;
        }
        out[written] = (node.ino, node.flags, node.name, node.name_len);
        written += 1;
    }
    written
}

// ---------------------------------------------------------------------------
// Attribute file ops
// ---------------------------------------------------------------------------

/// Read attribute data for a KERNFS_FILE node.
///
/// Returns bytes copied.
pub fn kernfs_attr_read(
    tree: &KernfsTree,
    ino: u64,
    offset: usize,
    out: &mut [u8],
) -> Result<usize> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    if !tree.nodes[slot].flags.is_file() {
        return Err(Error::InvalidArgument);
    }
    let len = tree.nodes[slot].attr_data_len;
    if offset >= len {
        return Ok(0);
    }
    let copy = (len - offset).min(out.len());
    out[..copy].copy_from_slice(&tree.nodes[slot].attr_data[offset..offset + copy]);
    Ok(copy)
}

/// Write attribute data for a KERNFS_FILE node.
///
/// Returns bytes written.
pub fn kernfs_attr_write(tree: &mut KernfsTree, ino: u64, data: &[u8]) -> Result<usize> {
    if data.len() > MAX_ATTR_DATA {
        return Err(Error::InvalidArgument);
    }
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    if !tree.nodes[slot].flags.is_file() {
        return Err(Error::InvalidArgument);
    }
    tree.nodes[slot].attr_data[..data.len()].copy_from_slice(data);
    tree.nodes[slot].attr_data_len = data.len();
    Ok(data.len())
}

/// Set the symlink target for a KERNFS_LINK node.
pub fn kernfs_set_link_target(tree: &mut KernfsTree, ino: u64, target_ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    if !tree.nodes[slot].flags.is_link() {
        return Err(Error::InvalidArgument);
    }
    tree.nodes[slot].link_target_ino = target_ino;
    Ok(())
}

/// Look up a node by inode number.
pub fn kernfs_find_by_ino(tree: &KernfsTree, ino: u64) -> Option<&KernfsNode> {
    let slot = tree.find_by_ino(ino)?;
    Some(&tree.nodes[slot])
}

/// Return the total number of nodes in the tree.
pub fn kernfs_node_count(tree: &KernfsTree) -> usize {
    tree.count
}

/// Hide a node (exclude from readdir but keep accessible by ino).
pub fn kernfs_hide(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].flags.0 |= KERNFS_HIDDEN;
    Ok(())
}

/// Unhide a previously hidden node.
pub fn kernfs_unhide(tree: &mut KernfsTree, ino: u64) -> Result<()> {
    let slot = tree.find_by_ino(ino).ok_or(Error::NotFound)?;
    tree.nodes[slot].flags.0 &= !KERNFS_HIDDEN;
    Ok(())
}

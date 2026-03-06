// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF filesystem (bpffs) — pinning and linking of BPF objects.
//!
//! The BPF filesystem is mounted at `/sys/fs/bpf` and allows BPF programs,
//! maps, links, and other BPF objects to be pinned (persisted) by name
//! so that they outlive the process that created them.
//!
//! # Pinning
//!
//! A BPF object is pinned by calling `bpf(BPF_OBJ_PIN)`, which creates a
//! filesystem node in bpffs. A pinned object can be retrieved later via
//! `bpf(BPF_OBJ_GET)` by path.
//!
//! # Object Types
//!
//! bpffs nodes represent different BPF object types:
//! - `BPF_TYPE_PROG`: BPF program.
//! - `BPF_TYPE_MAP`: BPF map.
//! - `BPF_TYPE_LINK`: BPF link (attachment point).
//! - `BPF_TYPE_BTF`: BPF Type Format object.

use oncrix_lib::{Error, Result};

/// BPF object types pinned in bpffs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum BpfObjType {
    /// BPF program.
    Prog = 1,
    /// BPF map.
    Map = 2,
    /// BPF link.
    Link = 3,
    /// BPF Type Format object.
    Btf = 4,
    /// Directory node.
    Dir = 0,
}

impl Default for BpfObjType {
    fn default() -> Self {
        Self::Dir
    }
}

impl BpfObjType {
    /// Parses from u32.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::Dir),
            1 => Ok(Self::Prog),
            2 => Ok(Self::Map),
            3 => Ok(Self::Link),
            4 => Ok(Self::Btf),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Maximum length of a bpffs path component.
pub const BPFFS_NAME_MAX: usize = 64;

/// Maximum number of pinned objects per bpffs instance.
pub const BPFFS_MAX_OBJECTS: usize = 512;

/// A pinned BPF object node in bpffs.
#[derive(Clone, Copy)]
pub struct BpfPinNode {
    /// Object type.
    pub obj_type: BpfObjType,
    /// Inode number assigned to this node.
    pub ino: u64,
    /// Parent inode number (0 = bpffs root).
    pub parent_ino: u64,
    /// Node name.
    pub name: [u8; BPFFS_NAME_MAX],
    /// Name length.
    pub name_len: usize,
    /// Reference count (number of file descriptors pointing here).
    pub ref_count: u32,
    /// Kernel-internal object ID (for retrieving the actual BPF object).
    pub obj_id: u32,
}

impl Default for BpfPinNode {
    fn default() -> Self {
        Self {
            obj_type: BpfObjType::Dir,
            ino: 0,
            parent_ino: 0,
            name: [0u8; BPFFS_NAME_MAX],
            name_len: 0,
            ref_count: 0,
            obj_id: 0,
        }
    }
}

impl BpfPinNode {
    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if this node is a directory.
    pub const fn is_dir(&self) -> bool {
        matches!(self.obj_type, BpfObjType::Dir)
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` if the object should be freed (ref_count reached 0).
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// The bpffs node table.
pub struct BpfFs {
    nodes: [BpfPinNode; BPFFS_MAX_OBJECTS],
    count: usize,
    next_ino: u64,
}

impl Default for BpfFs {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfFs {
    /// Creates a new bpffs instance with an empty root directory.
    pub fn new() -> Self {
        let mut fs = Self {
            nodes: core::array::from_fn(|_| BpfPinNode::default()),
            count: 0,
            next_ino: 2,
        };
        // Insert root directory at inode 1.
        fs.nodes[0] = BpfPinNode {
            obj_type: BpfObjType::Dir,
            ino: 1,
            parent_ino: 0,
            name: [0u8; BPFFS_NAME_MAX],
            name_len: 0,
            ref_count: 1,
            obj_id: 0,
        };
        fs.count = 1;
        fs
    }

    /// Returns the root inode number.
    pub const fn root_ino(&self) -> u64 {
        1
    }

    /// Allocates a new inode number.
    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Pins a BPF object at `path` under `parent_ino`.
    ///
    /// Returns the new node's inode number.
    pub fn pin(
        &mut self,
        parent_ino: u64,
        name: &[u8],
        obj_type: BpfObjType,
        obj_id: u32,
    ) -> Result<u64> {
        if self.count >= BPFFS_MAX_OBJECTS {
            return Err(Error::OutOfMemory);
        }
        if name.len() > BPFFS_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate name in same directory.
        if self.lookup(parent_ino, name).is_some() {
            return Err(Error::AlreadyExists);
        }
        let ino = self.alloc_ino();
        let mut node = BpfPinNode {
            obj_type,
            ino,
            parent_ino,
            ref_count: 1,
            obj_id,
            ..BpfPinNode::default()
        };
        let copy_len = name.len().min(BPFFS_NAME_MAX);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        self.nodes[self.count] = node;
        self.count += 1;
        Ok(ino)
    }

    /// Creates a directory under `parent_ino`.
    pub fn mkdir(&mut self, parent_ino: u64, name: &[u8]) -> Result<u64> {
        self.pin(parent_ino, name, BpfObjType::Dir, 0)
    }

    /// Looks up a node by parent inode and name.
    pub fn lookup(&self, parent_ino: u64, name: &[u8]) -> Option<&BpfPinNode> {
        self.nodes[..self.count]
            .iter()
            .find(|n| n.parent_ino == parent_ino && n.name_bytes() == name)
    }

    /// Finds a node by inode number.
    pub fn find_by_ino(&self, ino: u64) -> Option<&BpfPinNode> {
        self.nodes[..self.count].iter().find(|n| n.ino == ino)
    }

    /// Retrieves the BPF object ID for a pinned path.
    pub fn get_obj_id(&self, parent_ino: u64, name: &[u8]) -> Result<u32> {
        let node = self.lookup(parent_ino, name).ok_or(Error::NotFound)?;
        if node.is_dir() {
            return Err(Error::InvalidArgument);
        }
        Ok(node.obj_id)
    }

    /// Unpins (removes) a node by inode number.
    ///
    /// Fails if the node is a non-empty directory.
    pub fn unpin(&mut self, ino: u64) -> Result<()> {
        // Check for children (for directories).
        let is_dir = self.find_by_ino(ino).ok_or(Error::NotFound)?.is_dir();
        if is_dir {
            let has_children = self.nodes[..self.count].iter().any(|n| n.parent_ino == ino);
            if has_children {
                return Err(Error::Busy);
            }
        }
        let pos = self.nodes[..self.count]
            .iter()
            .position(|n| n.ino == ino)
            .ok_or(Error::NotFound)?;
        self.count -= 1;
        self.nodes[pos] = self.nodes[self.count];
        self.nodes[self.count] = BpfPinNode::default();
        Ok(())
    }
}

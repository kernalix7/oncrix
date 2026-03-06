// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! nsfs (namespace filesystem) operations.
//!
//! nsfs is the pseudo-filesystem used to represent Linux namespace objects.
//! Each namespace (PID, UTS, IPC, net, mount, user, time, cgroup) is exposed
//! as a file under `/proc/<pid>/ns/` backed by the nsfs inode.
//!
//! # Namespace File Operations
//!
//! Namespace files support:
//! - `open()`: Returns a file descriptor bound to the namespace.
//! - `ioctl(NS_GET_USERNS)`: Returns a fd for the user namespace that owns
//!   this namespace.
//! - `ioctl(NS_GET_PARENT)`: Returns a fd for the parent namespace (PID/user).
//! - `ioctl(NS_GET_NSTYPE)`: Returns the namespace type (CLONE_* flag).
//! - `stat()`: Reports the inode number (encodes ns type + id).
//!
//! # Inode Number Encoding
//!
//! nsfs inode numbers are stable identifiers: `(ns_type << 32) | ns_id`.
//! This allows userspace to detect namespace identity by comparing inodes.

use oncrix_lib::{Error, Result};

/// Linux namespace type flags (CLONE_* flags from clone(2)).
pub mod ns_type {
    /// User namespace.
    pub const CLONE_NEWUSER: u32 = 0x10000000;
    /// Mount namespace.
    pub const CLONE_NEWNS: u32 = 0x00020000;
    /// UTS namespace.
    pub const CLONE_NEWUTS: u32 = 0x04000000;
    /// IPC namespace.
    pub const CLONE_NEWIPC: u32 = 0x08000000;
    /// Network namespace.
    pub const CLONE_NEWNET: u32 = 0x40000000;
    /// PID namespace.
    pub const CLONE_NEWPID: u32 = 0x20000000;
    /// Cgroup namespace.
    pub const CLONE_NEWCGROUP: u32 = 0x02000000;
    /// Time namespace.
    pub const CLONE_NEWTIME: u32 = 0x00000080;
}

/// ioctl command codes for nsfs.
pub mod ioctl_cmd {
    pub const NS_GET_USERNS: u32 = 0xb701;
    pub const NS_GET_PARENT: u32 = 0xb702;
    pub const NS_GET_NSTYPE: u32 = 0xb703;
    pub const NS_GET_OWNER_UID: u32 = 0xb704;
}

/// A namespace descriptor tracked by nsfs.
#[derive(Clone, Copy, Default)]
pub struct NsDescriptor {
    /// Namespace ID (kernel-internal identifier, unique per ns type).
    pub ns_id: u32,
    /// Namespace type (CLONE_* flag).
    pub ns_type: u32,
    /// Inode number used in `/proc/<pid>/ns/`.
    pub ino: u64,
    /// ID of the owning user namespace.
    pub owner_user_ns_id: u32,
    /// ID of the parent namespace (for hierarchical namespaces).
    pub parent_ns_id: u32,
    /// Reference count.
    pub ref_count: u32,
}

impl NsDescriptor {
    /// Creates a new namespace descriptor.
    pub fn new(ns_id: u32, ns_type: u32, owner_user_ns_id: u32) -> Self {
        // Encode inode: upper 32 = ns_type (compressed to u8 index), lower 32 = ns_id.
        let type_idx = Self::type_index(ns_type) as u64;
        let ino = (type_idx << 32) | (ns_id as u64);
        Self {
            ns_id,
            ns_type,
            ino,
            owner_user_ns_id,
            parent_ns_id: 0,
            ref_count: 1,
        }
    }

    /// Maps ns_type CLONE_* to a small index for inode encoding.
    fn type_index(ns_type: u32) -> u8 {
        match ns_type {
            ns_type::CLONE_NEWUSER => 1,
            ns_type::CLONE_NEWNS => 2,
            ns_type::CLONE_NEWUTS => 3,
            ns_type::CLONE_NEWIPC => 4,
            ns_type::CLONE_NEWNET => 5,
            ns_type::CLONE_NEWPID => 6,
            ns_type::CLONE_NEWCGROUP => 7,
            ns_type::CLONE_NEWTIME => 8,
            _ => 0,
        }
    }

    /// Returns the proc filename for this namespace (e.g., `"pid"`, `"net"`).
    pub fn proc_name(&self) -> &'static str {
        match self.ns_type {
            ns_type::CLONE_NEWUSER => "user",
            ns_type::CLONE_NEWNS => "mnt",
            ns_type::CLONE_NEWUTS => "uts",
            ns_type::CLONE_NEWIPC => "ipc",
            ns_type::CLONE_NEWNET => "net",
            ns_type::CLONE_NEWPID => "pid",
            ns_type::CLONE_NEWCGROUP => "cgroup",
            ns_type::CLONE_NEWTIME => "time",
            _ => "unknown",
        }
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` if the namespace should be freed.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }
}

/// nsfs ioctl handler.
///
/// Processes ioctl commands on an open namespace file descriptor.
pub struct NsIoctlHandler<'a> {
    /// The namespace this fd refers to.
    desc: &'a NsDescriptor,
}

impl<'a> NsIoctlHandler<'a> {
    /// Creates a new ioctl handler for `desc`.
    pub const fn new(desc: &'a NsDescriptor) -> Self {
        Self { desc }
    }

    /// Handles an ioctl command.
    ///
    /// Returns a namespace ID (the caller must open it as a new fd).
    pub fn ioctl(&self, cmd: u32) -> Result<u32> {
        match cmd {
            ioctl_cmd::NS_GET_USERNS => Ok(self.desc.owner_user_ns_id),
            ioctl_cmd::NS_GET_PARENT => {
                if self.desc.parent_ns_id == 0 {
                    Err(Error::NotFound)
                } else {
                    Ok(self.desc.parent_ns_id)
                }
            }
            ioctl_cmd::NS_GET_NSTYPE => Ok(self.desc.ns_type),
            _ => Err(Error::NotImplemented),
        }
    }
}

/// A table of namespace descriptors managed by nsfs.
pub struct NsTable {
    descriptors: [NsDescriptor; 256],
    count: usize,
}

impl Default for NsTable {
    fn default() -> Self {
        Self {
            descriptors: [NsDescriptor::default(); 256],
            count: 0,
        }
    }
}

impl NsTable {
    /// Registers a new namespace.
    pub fn register(&mut self, desc: NsDescriptor) -> Result<()> {
        if self.count >= 256 {
            return Err(Error::OutOfMemory);
        }
        self.descriptors[self.count] = desc;
        self.count += 1;
        Ok(())
    }

    /// Finds a namespace by its ID and type.
    pub fn find(&self, ns_id: u32, ns_type: u32) -> Option<&NsDescriptor> {
        self.descriptors[..self.count]
            .iter()
            .find(|d| d.ns_id == ns_id && d.ns_type == ns_type)
    }

    /// Finds a namespace by inode number.
    pub fn find_by_ino(&self, ino: u64) -> Option<&NsDescriptor> {
        self.descriptors[..self.count].iter().find(|d| d.ino == ino)
    }

    /// Returns a mutable reference to a namespace by ID and type.
    pub fn find_mut(&mut self, ns_id: u32, ns_type: u32) -> Option<&mut NsDescriptor> {
        let count = self.count;
        self.descriptors[..count]
            .iter_mut()
            .find(|d| d.ns_id == ns_id && d.ns_type == ns_type)
    }

    /// Removes a namespace when its reference count drops to zero.
    pub fn remove(&mut self, ns_id: u32, ns_type: u32) -> Result<()> {
        let pos = self.descriptors[..self.count]
            .iter()
            .position(|d| d.ns_id == ns_id && d.ns_type == ns_type)
            .ok_or(Error::NotFound)?;
        self.count -= 1;
        self.descriptors[pos] = self.descriptors[self.count];
        self.descriptors[self.count] = NsDescriptor::default();
        Ok(())
    }
}

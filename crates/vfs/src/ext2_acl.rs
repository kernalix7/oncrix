// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext2/Ext3 POSIX ACL implementation.
//!
//! Ext2 stores POSIX ACLs in extended attributes under the names
//! `system.posix_acl_access` and `system.posix_acl_default`.  This module
//! implements the on-disk binary encoding (version 2 format) and the
//! in-memory representation used by the VFS ACL layer.

use oncrix_lib::{Error, Result};

/// ACL version stored in the header.
pub const EXT2_ACL_VERSION: u32 = 0x0002;

/// On-disk ACL header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext2AclHeader {
    /// Must equal `EXT2_ACL_VERSION`.
    pub version: u32,
}

/// ACL entry tag values (matches POSIX extended ACL tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Ext2AclTag {
    Undefined = 0x00,
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

impl Ext2AclTag {
    /// Parse from the on-disk u16.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0x00 => Ok(Self::Undefined),
            0x01 => Ok(Self::UserObj),
            0x02 => Ok(Self::User),
            0x04 => Ok(Self::GroupObj),
            0x08 => Ok(Self::Group),
            0x10 => Ok(Self::Mask),
            0x20 => Ok(Self::Other),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Whether this tag requires an explicit id field.
    pub fn has_id(self) -> bool {
        matches!(self, Self::User | Self::Group)
    }
}

/// On-disk ACL entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext2AclEntryDisk {
    pub tag: u16,
    pub perm: u16,
    /// UID/GID (present only for User/Group tags; otherwise the xattr value
    /// jumps directly to the next tag/perm pair — this is a variable-length
    /// format on disk, but we store it uniformly here).
    pub id: u32,
}

/// In-memory ACL entry.
#[derive(Debug, Clone, Copy)]
pub struct Ext2AclEntry {
    pub tag: Ext2AclTag,
    pub perm: u16,
    pub id: u32,
}

impl Ext2AclEntry {
    /// Validate permission bits (only rwx = bits 0-2 are used).
    pub fn validate(&self) -> Result<()> {
        if self.perm & !0x07 != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Maximum number of ACL entries (Linux limit is 32 per ACL).
pub const EXT2_ACL_MAX_ENTRIES: usize = 32;

/// In-memory ext2 ACL (access or default).
pub struct Ext2Acl {
    pub entries: [Option<Ext2AclEntry>; EXT2_ACL_MAX_ENTRIES],
    pub count: usize,
}

impl Ext2Acl {
    /// Create an empty ACL.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; EXT2_ACL_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Add an ACL entry.
    pub fn add(&mut self, entry: Ext2AclEntry) -> Result<()> {
        entry.validate()?;
        if self.count >= EXT2_ACL_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Find an entry by tag (and optional id for User/Group).
    pub fn find(&self, tag: Ext2AclTag, id: u32) -> Option<&Ext2AclEntry> {
        for slot in &self.entries[..self.count] {
            if let Some(entry) = slot.as_ref() {
                if entry.tag == tag && (!tag.has_id() || entry.id == id) {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Compute the on-disk byte size of this ACL.
    pub fn encoded_size(&self) -> usize {
        // header (4 bytes) + entries.
        let entries_size: usize = self.entries[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|e| if e.tag.has_id() { 8 } else { 4 })
            .sum();
        4 + entries_size
    }

    /// Encode the ACL into `buf` in the ext2 on-disk format.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let needed = self.encoded_size();
        if buf.len() < needed {
            return Err(Error::InvalidArgument);
        }
        buf[0..4].copy_from_slice(&EXT2_ACL_VERSION.to_le_bytes());
        let mut off = 4;
        for slot in &self.entries[..self.count] {
            if let Some(entry) = slot.as_ref() {
                buf[off..off + 2].copy_from_slice(&(entry.tag as u16).to_le_bytes());
                buf[off + 2..off + 4].copy_from_slice(&entry.perm.to_le_bytes());
                off += 4;
                if entry.tag.has_id() {
                    buf[off..off + 4].copy_from_slice(&entry.id.to_le_bytes());
                    off += 4;
                }
            }
        }
        Ok(off)
    }

    /// Decode an ext2 ACL from an xattr value buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        let version = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if version != EXT2_ACL_VERSION {
            return Err(Error::InvalidArgument);
        }
        let mut acl = Self::new();
        let mut off = 4;
        while off + 4 <= buf.len() {
            let tag_raw = u16::from_le_bytes([buf[off], buf[off + 1]]);
            let perm = u16::from_le_bytes([buf[off + 2], buf[off + 3]]);
            off += 4;
            let tag = Ext2AclTag::from_u16(tag_raw)?;
            let id = if tag.has_id() {
                if off + 4 > buf.len() {
                    return Err(Error::InvalidArgument);
                }
                let v = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                off += 4;
                v
            } else {
                0
            };
            acl.add(Ext2AclEntry { tag, perm, id })?;
        }
        Ok(acl)
    }
}

impl Default for Ext2Acl {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a minimal POSIX mode (rwx bits × 3 = 9 bits) to a minimal ext2 ACL
/// with only `UserObj`, `GroupObj`, and `Other` entries.
pub fn acl_from_mode(mode: u16) -> Ext2Acl {
    let mut acl = Ext2Acl::new();
    let _ = acl.add(Ext2AclEntry {
        tag: Ext2AclTag::UserObj,
        perm: (mode >> 6) as u16 & 0x7,
        id: 0,
    });
    let _ = acl.add(Ext2AclEntry {
        tag: Ext2AclTag::GroupObj,
        perm: (mode >> 3) as u16 & 0x7,
        id: 0,
    });
    let _ = acl.add(Ext2AclEntry {
        tag: Ext2AclTag::Other,
        perm: mode as u16 & 0x7,
        id: 0,
    });
    acl
}

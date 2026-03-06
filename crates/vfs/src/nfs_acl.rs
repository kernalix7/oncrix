// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS ACL extension (NFSACL protocol).
//!
//! The NFSACL protocol is a Sun extension to NFS v2/v3 that allows POSIX
//! access control lists to be retrieved and set over the network.  This
//! module implements the XDR encoding/decoding of NFSACL data and the
//! in-memory ACL types used by the NFS server and client.

use oncrix_lib::{Error, Result};

/// Maximum number of ACL entries per ACL (POSIX limit).
pub const NFSACL_MAX_ENTRIES: usize = 1024;

/// ACL tag values as defined by POSIX / NFSv3 ACL extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AclTag {
    /// Owning user.
    UserObj = 0x0001,
    /// Named user.
    User = 0x0002,
    /// Owning group.
    GroupObj = 0x0004,
    /// Named group.
    Group = 0x0008,
    /// Mask entry.
    Mask = 0x0010,
    /// Others.
    Other = 0x0020,
}

impl AclTag {
    /// Parse from an on-wire u32.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            0x0001 => Ok(Self::UserObj),
            0x0002 => Ok(Self::User),
            0x0004 => Ok(Self::GroupObj),
            0x0008 => Ok(Self::Group),
            0x0010 => Ok(Self::Mask),
            0x0020 => Ok(Self::Other),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Permission bits in an ACL entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct AclPerms(pub u32);

impl AclPerms {
    pub const READ: u32 = 0x04;
    pub const WRITE: u32 = 0x02;
    pub const EXEC: u32 = 0x01;

    pub fn can_read(&self) -> bool {
        self.0 & Self::READ != 0
    }
    pub fn can_write(&self) -> bool {
        self.0 & Self::WRITE != 0
    }
    pub fn can_exec(&self) -> bool {
        self.0 & Self::EXEC != 0
    }
}

/// A single NFS ACL entry.
#[derive(Debug, Clone, Copy)]
pub struct NfsAclEntry {
    pub tag: AclTag,
    /// UID or GID for `User` / `Group` entries; 0xffffffff for others.
    pub id: u32,
    pub perms: AclPerms,
}

impl NfsAclEntry {
    /// Create a new ACL entry.
    pub fn new(tag: AclTag, id: u32, perms: u32) -> Self {
        Self {
            tag,
            id,
            perms: AclPerms(perms),
        }
    }

    /// Whether this entry needs an explicit `id` field.
    pub fn has_id(&self) -> bool {
        matches!(self.tag, AclTag::User | AclTag::Group)
    }
}

/// An NFS ACL (access or default).
pub struct NfsAcl {
    pub entries: [Option<NfsAclEntry>; NFSACL_MAX_ENTRIES],
    pub count: usize,
}

impl NfsAcl {
    /// Create an empty ACL.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; NFSACL_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Add an ACL entry.
    pub fn add(&mut self, entry: NfsAclEntry) -> Result<()> {
        if self.count >= NFSACL_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Find the effective permissions for a given (tag, id) pair.
    pub fn lookup(&self, tag: AclTag, id: u32) -> Option<AclPerms> {
        for slot in &self.entries[..self.count] {
            if let Some(entry) = slot {
                if entry.tag == tag && (!entry.has_id() || entry.id == id) {
                    return Some(entry.perms);
                }
            }
        }
        None
    }

    /// Compute effective read/write/exec for user `uid` in groups `gids`.
    ///
    /// Follows POSIX ACL evaluation order with mask.
    pub fn check_access(&self, uid: u32, gids: &[u32], owner_uid: u32, owner_gid: u32) -> u32 {
        let mask = self
            .lookup(AclTag::Mask, 0)
            .map(|p| p.0)
            .unwrap_or(AclPerms::READ | AclPerms::WRITE | AclPerms::EXEC);

        if uid == owner_uid {
            return self.lookup(AclTag::UserObj, 0).map(|p| p.0).unwrap_or(0);
        }
        // Named user?
        if let Some(p) = self.lookup(AclTag::User, uid) {
            return p.0 & mask;
        }
        // Owner group or named group?
        let mut matched_group = false;
        if gids.contains(&owner_gid) {
            matched_group = true;
            if let Some(p) = self.lookup(AclTag::GroupObj, 0) {
                if p.0 & mask != 0 {
                    return p.0 & mask;
                }
            }
        }
        for &gid in gids {
            if let Some(p) = self.lookup(AclTag::Group, gid) {
                matched_group = true;
                if p.0 & mask != 0 {
                    return p.0 & mask;
                }
            }
        }
        if matched_group {
            return 0; // access denied by mask
        }
        // Other.
        self.lookup(AclTag::Other, 0).map(|p| p.0).unwrap_or(0)
    }
}

impl Default for NfsAcl {
    fn default() -> Self {
        Self::new()
    }
}

/// XDR-encoded byte length of a single ACL entry (tag + id + perms).
pub const NFSACL_ENTRY_XDR_SIZE: usize = 12;

/// Compute the XDR buffer size needed for an ACL with `n` entries.
pub fn nfsacl_xdr_size(n: usize) -> usize {
    // 4-byte count + n * entry_size
    4 + n * NFSACL_ENTRY_XDR_SIZE
}

/// Encode an `NfsAcl` into an XDR byte buffer.
///
/// Returns the number of bytes written, or `Err(InvalidArgument)` if the
/// buffer is too small.
pub fn encode_nfsacl(acl: &NfsAcl, buf: &mut [u8]) -> Result<usize> {
    let needed = nfsacl_xdr_size(acl.count);
    if buf.len() < needed {
        return Err(Error::InvalidArgument);
    }
    // Write entry count (big-endian).
    let count = acl.count as u32;
    buf[0..4].copy_from_slice(&count.to_be_bytes());
    let mut off = 4;
    for slot in &acl.entries[..acl.count] {
        if let Some(entry) = slot {
            buf[off..off + 4].copy_from_slice(&(entry.tag as u32).to_be_bytes());
            buf[off + 4..off + 8].copy_from_slice(&entry.id.to_be_bytes());
            buf[off + 8..off + 12].copy_from_slice(&entry.perms.0.to_be_bytes());
            off += NFSACL_ENTRY_XDR_SIZE;
        }
    }
    Ok(off)
}

/// Decode an XDR byte buffer into an `NfsAcl`.
pub fn decode_nfsacl(buf: &[u8]) -> Result<NfsAcl> {
    if buf.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let count = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if count > NFSACL_MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    if buf.len() < nfsacl_xdr_size(count) {
        return Err(Error::InvalidArgument);
    }
    let mut acl = NfsAcl::new();
    let mut off = 4;
    for _ in 0..count {
        let tag_raw = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let id = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let perms = u32::from_be_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
        let tag = AclTag::from_u32(tag_raw)?;
        acl.add(NfsAclEntry::new(tag, id, perms))?;
        off += NFSACL_ENTRY_XDR_SIZE;
    }
    Ok(acl)
}

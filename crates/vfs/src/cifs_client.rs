// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMB/CIFS client filesystem integration for the ONCRIX VFS.
//!
//! Provides the VFS-side client state and dispatch for SMB2/3 network shares.
//! Network I/O is handled by the networking crate; this module owns the
//! VFS inode mapping, credential caching, and mount options for CIFS mounts.

use oncrix_lib::{Error, Result};

/// Maximum length of a CIFS share name (UNC path component).
pub const CIFS_MAX_SHARE_LEN: usize = 256;

/// Maximum number of simultaneously mounted CIFS shares.
pub const CIFS_MAX_MOUNTS: usize = 16;

/// Maximum number of cached file handles per mount.
pub const CIFS_MAX_FILE_HANDLES: usize = 64;

/// SMB protocol dialect negotiated with the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CifsDialect {
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb210 = 0x0210,
    /// SMB 3.0
    Smb300 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    Smb311 = 0x0311,
}

/// Security mode bits returned by the server during negotiation.
#[derive(Debug, Clone, Copy, Default)]
pub struct CifsSecurityMode {
    /// Server requires message signing.
    pub signing_required: bool,
    /// Server supports message signing.
    pub signing_enabled: bool,
    /// Encrypted transport is in use.
    pub encrypted: bool,
}

/// Mount options for a CIFS filesystem.
#[derive(Debug, Clone, Copy)]
pub struct CifsMountOptions {
    /// Default Unix file mode for new files (e.g., 0o644).
    pub file_mode: u32,
    /// Default Unix directory mode for new directories (e.g., 0o755).
    pub dir_mode: u32,
    /// UID to report for all inodes when server does not support Unix extensions.
    pub uid: u32,
    /// GID to report for all inodes when server does not support Unix extensions.
    pub gid: u32,
    /// Enable Unix extensions (if server advertises them).
    pub unix_extensions: bool,
    /// Mount read-only.
    pub read_only: bool,
    /// Enable server-side caching (oplocks / leases).
    pub cache_enabled: bool,
    /// Negotiated SMB dialect.
    pub dialect: CifsDialect,
}

impl CifsMountOptions {
    /// Construct default mount options for SMB 3.1.1.
    pub const fn new() -> Self {
        Self {
            file_mode: 0o644,
            dir_mode: 0o755,
            uid: 0,
            gid: 0,
            unix_extensions: false,
            read_only: false,
            cache_enabled: true,
            dialect: CifsDialect::Smb311,
        }
    }
}

impl Default for CifsMountOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A cached open file handle on the server.
#[derive(Debug, Clone, Copy)]
pub struct CifsFileHandle {
    /// Server-assigned persistent file handle ID.
    pub persistent_id: u64,
    /// Server-assigned volatile file handle ID.
    pub volatile_id: u64,
    /// Access mask used when opening (e.g., read/write).
    pub access_mask: u32,
    /// Whether this handle holds a byte-range lock.
    pub has_lock: bool,
    /// Whether a lease has been granted for this handle.
    pub leased: bool,
}

impl CifsFileHandle {
    /// Construct a new file handle descriptor.
    pub const fn new(persistent_id: u64, volatile_id: u64, access_mask: u32) -> Self {
        Self {
            persistent_id,
            volatile_id,
            access_mask,
            has_lock: false,
            leased: false,
        }
    }

    /// Return `true` if this handle was opened with write access.
    pub fn is_writable(&self) -> bool {
        self.access_mask & 0x0002 != 0
    }
}

impl Default for CifsFileHandle {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Per-mount CIFS session state.
pub struct CifsMount {
    /// Human-readable share path (\\server\share).
    pub share_name: [u8; CIFS_MAX_SHARE_LEN],
    /// Length of share_name in bytes.
    pub share_name_len: usize,
    /// Negotiated session ID.
    pub session_id: u64,
    /// Negotiated tree ID for this share.
    pub tree_id: u32,
    /// Mount options.
    pub options: CifsMountOptions,
    /// Security mode in effect.
    pub security: CifsSecurityMode,
    /// Pool of cached open file handles.
    pub handles: [CifsFileHandle; CIFS_MAX_FILE_HANDLES],
    /// Number of active handles.
    pub handle_count: usize,
    /// Whether this mount entry is occupied.
    pub active: bool,
}

impl CifsMount {
    /// Construct an empty (inactive) mount entry.
    pub const fn new() -> Self {
        Self {
            share_name: [0u8; CIFS_MAX_SHARE_LEN],
            share_name_len: 0,
            session_id: 0,
            tree_id: 0,
            options: CifsMountOptions::new(),
            security: CifsSecurityMode {
                signing_required: false,
                signing_enabled: false,
                encrypted: false,
            },
            handles: [const { CifsFileHandle::new(0, 0, 0) }; CIFS_MAX_FILE_HANDLES],
            handle_count: 0,
            active: false,
        }
    }

    /// Allocate a handle slot, returning its index or `OutOfMemory`.
    pub fn alloc_handle(&mut self, handle: CifsFileHandle) -> Result<usize> {
        if self.handle_count >= CIFS_MAX_FILE_HANDLES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.handle_count;
        self.handles[idx] = handle;
        self.handle_count += 1;
        Ok(idx)
    }

    /// Release a handle by index.
    pub fn free_handle(&mut self, idx: usize) -> Result<()> {
        if idx >= self.handle_count {
            return Err(Error::InvalidArgument);
        }
        // Swap-remove to keep handles packed.
        self.handle_count -= 1;
        self.handles[idx] = self.handles[self.handle_count];
        self.handles[self.handle_count] = CifsFileHandle::new(0, 0, 0);
        Ok(())
    }
}

impl Default for CifsMount {
    fn default() -> Self {
        Self::new()
    }
}

/// Global table of active CIFS mounts.
pub struct CifsMountTable {
    mounts: [CifsMount; CIFS_MAX_MOUNTS],
}

impl CifsMountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            mounts: [const { CifsMount::new() }; CIFS_MAX_MOUNTS],
        }
    }

    /// Register a new mount, returning its index or `OutOfMemory`.
    pub fn register(&mut self, mount: CifsMount) -> Result<usize> {
        for (i, slot) in self.mounts.iter_mut().enumerate() {
            if !slot.active {
                *slot = mount;
                slot.active = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Deregister a mount by index.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= CIFS_MAX_MOUNTS {
            return Err(Error::InvalidArgument);
        }
        if !self.mounts[idx].active {
            return Err(Error::NotFound);
        }
        self.mounts[idx] = CifsMount::new();
        Ok(())
    }

    /// Get an immutable reference to a mount.
    pub fn get(&self, idx: usize) -> Result<&CifsMount> {
        if idx >= CIFS_MAX_MOUNTS || !self.mounts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.mounts[idx])
    }

    /// Get a mutable reference to a mount.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut CifsMount> {
        if idx >= CIFS_MAX_MOUNTS || !self.mounts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.mounts[idx])
    }
}

impl Default for CifsMountTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a UNC path has the form `\\server\share`.
pub fn validate_unc_path(path: &[u8]) -> Result<()> {
    if path.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    if path[0] != b'\\' || path[1] != b'\\' {
        return Err(Error::InvalidArgument);
    }
    // Must contain at least one more backslash after the server name.
    if !path[2..].contains(&b'\\') {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Encode a UTF-8 string as a null-terminated UTF-16LE byte sequence into `dst`.
///
/// Returns the number of bytes written, or `InvalidArgument` if `dst` is too small.
pub fn encode_utf16le(src: &str, dst: &mut [u8]) -> Result<usize> {
    let mut pos = 0usize;
    for c in src.chars() {
        let mut buf = [0u16; 2];
        let encoded = c.encode_utf16(&mut buf);
        for &unit in encoded.iter() {
            let bytes = unit.to_le_bytes();
            if pos + 2 > dst.len() {
                return Err(Error::InvalidArgument);
            }
            dst[pos] = bytes[0];
            dst[pos + 1] = bytes[1];
            pos += 2;
        }
    }
    // Null terminator
    if pos + 2 > dst.len() {
        return Err(Error::InvalidArgument);
    }
    dst[pos] = 0;
    dst[pos + 1] = 0;
    pos += 2;
    Ok(pos)
}

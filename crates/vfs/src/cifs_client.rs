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

/// A generation-stamped token returned by [`CifsMount::alloc_handle`].
///
/// Callers must supply this token to [`CifsMount::free_handle`] and
/// [`CifsMount::get_handle`].  The generation counter ensures that a stale
/// index produced by a previous swap-remove cannot alias a newly allocated
/// handle in the same slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleToken {
    /// Slot index inside [`CifsMount::handles`].
    pub index: usize,
    /// Generation stamp of the slot at allocation time.
    pub generation: u32,
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
    /// Generation stamp: incremented each time this slot is reused.
    /// A `HandleToken` whose generation does not match this field is stale.
    pub generation: u32,
    /// `true` while this slot holds a live handle.
    pub occupied: bool,
}

impl CifsFileHandle {
    /// Construct a new (unoccupied) file handle descriptor.
    pub const fn new(persistent_id: u64, volatile_id: u64, access_mask: u32) -> Self {
        Self {
            persistent_id,
            volatile_id,
            access_mask,
            has_lock: false,
            leased: false,
            generation: 0,
            occupied: false,
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

    /// Allocate a handle slot, returning a [`HandleToken`] that encodes both
    /// the slot index and the current generation stamp.
    ///
    /// The token must be passed to [`free_handle`] and [`get_handle`];
    /// a stale token whose generation no longer matches the slot is rejected,
    /// preventing a post-swap-remove aliasing attack.
    pub fn alloc_handle(&mut self, mut handle: CifsFileHandle) -> Result<HandleToken> {
        // Search for any unoccupied slot (not just the tail) so that freed
        // interior slots are reused instead of always growing the high-water mark.
        let idx = self.handles[..CIFS_MAX_FILE_HANDLES]
            .iter()
            .position(|h| !h.occupied)
            .ok_or(Error::OutOfMemory)?;
        // Bump the generation so that any HandleToken that was issued for this
        // slot before the previous free_handle is now detectably stale.
        let next_gen = self.handles[idx].generation.wrapping_add(1);
        handle.generation = next_gen;
        handle.occupied = true;
        self.handles[idx] = handle;
        // Update high-water mark for handle_count (used only as a hint).
        if idx >= self.handle_count {
            self.handle_count = idx + 1;
        }
        Ok(HandleToken {
            index: idx,
            generation: next_gen,
        })
    }

    /// Release a handle identified by its [`HandleToken`].
    ///
    /// Returns `InvalidArgument` if `token.index` is out of range, `NotFound`
    /// if the slot is not occupied, or `PermissionDenied` if the generation
    /// stamp does not match (stale token — possible use-after-free attempt).
    pub fn free_handle(&mut self, token: HandleToken) -> Result<()> {
        let idx = token.index;
        if idx >= CIFS_MAX_FILE_HANDLES {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.handles[idx];
        if !slot.occupied {
            return Err(Error::NotFound);
        }
        // SECURITY: generation mismatch means the caller holds a stale token
        // from before a previous free; reject to prevent double-free /
        // use-after-reallocation aliasing.
        if slot.generation != token.generation {
            return Err(Error::PermissionDenied);
        }
        // Preserve the generation so the next alloc_handle will bump it.
        let saved_gen = slot.generation;
        *slot = CifsFileHandle::new(0, 0, 0);
        slot.generation = saved_gen;
        // Recompute handle_count high-water mark.
        while self.handle_count > 0 && !self.handles[self.handle_count - 1].occupied {
            self.handle_count -= 1;
        }
        Ok(())
    }

    /// Look up a handle by its [`HandleToken`].
    ///
    /// Returns `PermissionDenied` for a stale token, `NotFound` for an
    /// unoccupied slot, `InvalidArgument` for an out-of-range index.
    pub fn get_handle(&self, token: HandleToken) -> Result<&CifsFileHandle> {
        let idx = token.index;
        if idx >= CIFS_MAX_FILE_HANDLES {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.handles[idx];
        if !slot.occupied {
            return Err(Error::NotFound);
        }
        // SECURITY: generation mismatch — stale token, could alias a
        // subsequently allocated handle in the same slot.  Reject.
        if slot.generation != token.generation {
            return Err(Error::PermissionDenied);
        }
        Ok(slot)
    }

    /// Enforce the session signing policy on an inbound SMB2 response.
    ///
    /// Must be called after [`cifs_smb2::decode_header`] succeeds.  When
    /// `self.security.signing_required` is set and the response flags indicate
    /// `SMB2_FLAGS_SIGNED`, this function **rejects the message** because
    /// HMAC-SHA256/AES-CMAC verification is not available at this layer.
    ///
    /// # Security
    ///
    /// // SECURITY: when `signing_required` is true we fail closed rather than
    /// // accepting an unverified signature.  Real HMAC-SHA256 (SMB ≤ 3.0) or
    /// // AES-CMAC (SMB 3.x) verification over the full message with the 16-byte
    /// // signature field zeroed must be wired here before this guard is relaxed.
    /// // The session signing key is available after SESSION_SETUP completes.
    pub fn validate_response_signing(&self, response_flags: u32) -> Result<()> {
        // SMB2_FLAGS_SIGNED = 0x0000_0008 (defined in cifs_smb2)
        const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
        if self.security.signing_required && (response_flags & SMB2_FLAGS_SIGNED != 0) {
            // SECURITY: wiring point — replace this Err with actual
            // HMAC-SHA256/AES-CMAC verification when the session key is
            // available.  Never accept an unverified signed message.
            return Err(Error::PermissionDenied);
        }
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

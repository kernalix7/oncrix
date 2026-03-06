// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs metacopy feature.
//!
//! Implements the overlayfs metacopy optimisation: when a file's metadata
//! is modified (e.g. `chmod`, `chown`) but its data is not written, only
//! the metadata is copied up to the upper layer.  The data layer remains
//! in the lower layer, referenced via a redirect xattr.  On the first write
//! a full data copy-up is performed lazily.
//!
//! # Design
//!
//! - [`OvlFlags`] — per-inode overlay flags (METACOPY, HAS_DIGEST, REDIRECT)
//! - [`OverlayInode`] — combined overlay inode state
//! - [`MetacopyState`] — overlay metacopy layer manager
//! - [`MetacopyDigest`] — content hash for data integrity verification

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// xattr name for the metacopy marker.
pub const OVL_XATTR_METACOPY: &[u8] = b"trusted.overlay.metacopy";

/// xattr name for the redirect target path.
pub const OVL_XATTR_REDIRECT: &[u8] = b"trusted.overlay.redirect";

/// xattr name for the content digest.
pub const OVL_XATTR_DIGEST: &[u8] = b"trusted.overlay.digest";

/// Maximum path length for redirect xattr.
const MAX_REDIRECT_LEN: usize = 256;

/// Digest size in bytes (SHA-256 = 32 bytes).
const DIGEST_SIZE: usize = 32;

/// Maximum number of inodes tracked by the metacopy state.
const MAX_INODES: usize = 128;

// ── OvlFlags ─────────────────────────────────────────────────────────────────

/// Overlay inode flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OvlFlags(pub u32);

impl OvlFlags {
    /// Inode is in metacopy state (metadata only, data in lower layer).
    pub const METACOPY: u32 = 1 << 0;
    /// Inode has a content digest stored in xattr.
    pub const HAS_DIGEST: u32 = 1 << 1;
    /// Inode has a redirect xattr pointing to the data source.
    pub const REDIRECT: u32 = 1 << 2;
    /// Inode's data has been fully copied up.
    pub const DATA_COPIED: u32 = 1 << 3;
    /// Inode originated in upper layer (not a copy-up).
    pub const UPPER: u32 = 1 << 4;

    /// Test a flag.
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Returns true if the inode is a metacopy-only inode.
    pub fn is_metacopy(&self) -> bool {
        self.has(Self::METACOPY) && !self.has(Self::DATA_COPIED)
    }
}

// ── MetacopyDigest ────────────────────────────────────────────────────────────

/// Content hash stored in the digest xattr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetacopyDigest {
    /// Raw hash bytes (SHA-256).
    pub bytes: [u8; DIGEST_SIZE],
}

impl MetacopyDigest {
    /// Create a digest from raw bytes.
    pub fn new(bytes: [u8; DIGEST_SIZE]) -> Self {
        Self { bytes }
    }

    /// Create a zeroed (placeholder) digest.
    pub fn zeroed() -> Self {
        Self {
            bytes: [0u8; DIGEST_SIZE],
        }
    }

    /// Encode the digest as xattr value: "sha256:<hex>".
    pub fn encode(&self) -> Vec<u8> {
        // "sha256:" prefix (7 bytes) + 64 hex chars + NUL
        let mut v = Vec::with_capacity(71);
        v.extend_from_slice(b"sha256:");
        for byte in &self.bytes {
            let hi = (byte >> 4) as u8;
            let lo = (byte & 0xf) as u8;
            v.push(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
            v.push(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
        }
        v
    }

    /// Decode from xattr value bytes.
    pub fn decode(xattr: &[u8]) -> Result<Self> {
        // Expect "sha256:<64 hex chars>"
        if xattr.len() < 71 || &xattr[..7] != b"sha256:" {
            return Err(Error::InvalidArgument);
        }
        let hex = &xattr[7..71];
        let mut bytes = [0u8; DIGEST_SIZE];
        for (i, chunk) in hex.chunks(2).enumerate() {
            if chunk.len() < 2 {
                return Err(Error::InvalidArgument);
            }
            let hi = Self::hex_nibble(chunk[0])?;
            let lo = Self::hex_nibble(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self { bytes })
    }

    fn hex_nibble(c: u8) -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── OverlayInode ──────────────────────────────────────────────────────────────

/// Overlay layer designation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OvlLayer {
    /// File resides entirely in the upper layer.
    Upper,
    /// File resides entirely in a lower layer.
    Lower(u8),
    /// Metadata in upper, data in lower (metacopy).
    Metacopy { lower_idx: u8 },
}

/// Per-inode overlay state.
#[derive(Debug, Clone)]
pub struct OverlayInode {
    /// Inode number within the overlay.
    pub ino: u64,
    /// Overlay flags.
    pub flags: OvlFlags,
    /// Current layer state.
    pub layer: OvlLayer,
    /// Redirect path (path in lower layer, set for renamed files).
    pub redirect: Option<Vec<u8>>,
    /// Content digest (set when HAS_DIGEST flag is set).
    pub digest: Option<MetacopyDigest>,
    /// File mode bits.
    pub mode: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
}

impl OverlayInode {
    /// Create a new lower-layer inode.
    pub fn new_lower(ino: u64, lower_idx: u8, mode: u32, uid: u32, gid: u32, size: u64) -> Self {
        Self {
            ino,
            flags: OvlFlags::default(),
            layer: OvlLayer::Lower(lower_idx),
            redirect: None,
            digest: None,
            mode,
            uid,
            gid,
            size,
        }
    }

    /// Create a new upper-layer inode.
    pub fn new_upper(ino: u64, mode: u32, uid: u32, gid: u32, size: u64) -> Self {
        let mut flags = OvlFlags::default();
        flags.set(OvlFlags::UPPER);
        Self {
            ino,
            flags,
            layer: OvlLayer::Upper,
            redirect: None,
            digest: None,
            mode,
            uid,
            gid,
            size,
        }
    }

    /// Returns true if this inode requires a data copy-up before writing.
    pub fn needs_data_copyup(&self) -> bool {
        self.flags.is_metacopy()
            || matches!(self.layer, OvlLayer::Lower(_) | OvlLayer::Metacopy { .. })
    }

    /// Returns true if only the metadata has been copied up.
    pub fn is_metacopy(&self) -> bool {
        matches!(self.layer, OvlLayer::Metacopy { .. })
    }

    /// Set the redirect xattr value.
    pub fn set_redirect(&mut self, path: Vec<u8>) {
        if !path.is_empty() {
            self.flags.set(OvlFlags::REDIRECT);
        }
        self.redirect = Some(path);
    }

    /// Clear redirect.
    pub fn clear_redirect(&mut self) {
        self.flags.clear(OvlFlags::REDIRECT);
        self.redirect = None;
    }

    /// Set the content digest.
    pub fn set_digest(&mut self, digest: MetacopyDigest) {
        self.flags.set(OvlFlags::HAS_DIGEST);
        self.digest = Some(digest);
    }
}

// ── MetacopyState ─────────────────────────────────────────────────────────────

/// Overlay metacopy layer manager.
pub struct MetacopyState {
    inodes: [Option<OverlayInode>; MAX_INODES],
    count: usize,
    /// Number of metacopy-only inodes.
    pub metacopy_count: u64,
    /// Number of full data copy-ups performed.
    pub data_copyup_count: u64,
}

impl MetacopyState {
    /// Create a new metacopy state.
    pub fn new() -> Self {
        Self {
            inodes: core::array::from_fn(|_| None),
            count: 0,
            metacopy_count: 0,
            data_copyup_count: 0,
        }
    }

    /// Insert an inode into the tracked table.
    pub fn insert(&mut self, inode: OverlayInode) -> Result<()> {
        if self.count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.inodes {
            if slot.is_none() {
                *slot = Some(inode);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an inode by number.
    pub fn get(&self, ino: u64) -> Option<&OverlayInode> {
        self.inodes.iter().flatten().find(|i| i.ino == ino)
    }

    /// Look up a mutable inode by number.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut OverlayInode> {
        self.inodes.iter_mut().flatten().find(|i| i.ino == ino)
    }

    /// Perform a metadata-only copy-up for `ino`.
    ///
    /// Copies inode attributes to the upper layer without copying data.
    /// Sets the METACOPY flag and records a redirect to the lower layer path.
    pub fn metacopy_up(&mut self, ino: u64, lower_path: Vec<u8>) -> Result<()> {
        if lower_path.len() > MAX_REDIRECT_LEN {
            return Err(Error::InvalidArgument);
        }
        let inode = self.get_mut(ino).ok_or(Error::NotFound)?;
        if inode.is_metacopy() {
            // Already metacopy — refresh redirect only
            inode.set_redirect(lower_path);
            return Ok(());
        }
        let lower_idx = match inode.layer {
            OvlLayer::Lower(idx) => idx,
            _ => return Err(Error::InvalidArgument),
        };
        inode.flags.set(OvlFlags::METACOPY);
        inode.layer = OvlLayer::Metacopy { lower_idx };
        inode.set_redirect(lower_path);
        self.metacopy_count += 1;
        Ok(())
    }

    /// Perform a full data copy-up for `ino`.
    ///
    /// Called on first write to a metacopy inode.  In a real implementation
    /// this would read the data from the lower layer and write it to upper.
    /// Here we mark the inode as fully copied.
    pub fn data_copy_up(&mut self, ino: u64) -> Result<()> {
        let inode = self.get_mut(ino).ok_or(Error::NotFound)?;
        if !inode.needs_data_copyup() {
            return Ok(());
        }
        inode.flags.set(OvlFlags::DATA_COPIED);
        inode.flags.clear(OvlFlags::METACOPY);
        inode.layer = OvlLayer::Upper;
        inode.clear_redirect();
        self.data_copyup_count += 1;
        Ok(())
    }

    /// Check whether an inode is in the metacopy state.
    pub fn is_metacopy(&self, ino: u64) -> bool {
        self.get(ino).map(|i| i.is_metacopy()).unwrap_or(false)
    }

    /// Read the metacopy xattr value for `ino`.
    ///
    /// Returns the encoded metacopy marker if the inode is in metacopy state,
    /// or `NotFound` if the inode is not metacopy.
    pub fn get_metacopy_xattr(&self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.get(ino).ok_or(Error::NotFound)?;
        if inode.is_metacopy() {
            // Metacopy xattr value is a binary marker (0x00 version byte)
            Ok(alloc::vec![0u8])
        } else {
            Err(Error::NotFound)
        }
    }

    /// Read the redirect xattr value for `ino`.
    pub fn get_redirect_xattr(&self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.get(ino).ok_or(Error::NotFound)?;
        inode.redirect.clone().ok_or(Error::NotFound)
    }

    /// Read the digest xattr for `ino`.
    pub fn get_digest_xattr(&self, ino: u64) -> Result<Vec<u8>> {
        let inode = self.get(ino).ok_or(Error::NotFound)?;
        if let Some(digest) = &inode.digest {
            Ok(digest.encode())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Set the content digest on `ino`.
    pub fn set_digest(&mut self, ino: u64, digest: MetacopyDigest) -> Result<()> {
        let inode = self.get_mut(ino).ok_or(Error::NotFound)?;
        inode.set_digest(digest);
        Ok(())
    }

    /// Verify the digest of `ino` against provided data.
    ///
    /// In a real implementation this would compute SHA-256 over the file data.
    /// Here we check whether a digest is stored and return its bytes.
    pub fn verify_digest(&self, ino: u64) -> Result<MetacopyDigest> {
        let inode = self.get(ino).ok_or(Error::NotFound)?;
        inode.digest.ok_or(Error::NotFound)
    }

    /// Remove an inode from tracking.
    pub fn remove(&mut self, ino: u64) -> Option<OverlayInode> {
        for slot in &mut self.inodes {
            if let Some(inode) = slot {
                if inode.ino == ino {
                    let removed = slot.take();
                    if removed.is_some() {
                        self.count -= 1;
                    }
                    return removed;
                }
            }
        }
        None
    }

    /// Number of tracked inodes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no inodes are tracked.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MetacopyState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Returns true if the given xattr name is the metacopy marker.
pub fn is_metacopy_xattr(name: &[u8]) -> bool {
    name == OVL_XATTR_METACOPY
}

/// Returns true if the given xattr name is the redirect xattr.
pub fn is_redirect_xattr(name: &[u8]) -> bool {
    name == OVL_XATTR_REDIRECT
}

/// Returns true if the given xattr name is the digest xattr.
pub fn is_digest_xattr(name: &[u8]) -> bool {
    name == OVL_XATTR_DIGEST
}

/// Encode a redirect path for storage in the redirect xattr.
///
/// The path must be absolute (starts with `/`).
pub fn encode_redirect(path: &[u8]) -> Result<Vec<u8>> {
    if path.is_empty() || path[0] != b'/' {
        return Err(Error::InvalidArgument);
    }
    if path.len() > MAX_REDIRECT_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(path.to_vec())
}

/// Decode a redirect xattr value to a path.
pub fn decode_redirect(xattr: &[u8]) -> Result<Vec<u8>> {
    if xattr.is_empty() {
        return Err(Error::InvalidArgument);
    }
    Ok(xattr.to_vec())
}

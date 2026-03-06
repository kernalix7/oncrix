// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AFS (Andrew File System) callback management.
//!
//! AFS uses a callback mechanism to provide cache consistency across clients.
//! When a client caches a file or directory, the fileserver registers a
//! "callback promise" with the client. If another client modifies the file,
//! the fileserver breaks the callback, invalidating the first client's cache.
//!
//! # Callback Types
//!
//! - **CB_TYPE_ICB**: Individual callback — covers a single file or directory.
//! - **CB_TYPE_MCB**: Mass callback — breaks all callbacks (used during server
//!   restart or when the callback database is full).
//!
//! # Callback Expiry
//!
//! Each callback has an expiry time. Clients must refetch metadata before
//! the callback expires. Typical expiry is 1800 seconds (30 minutes).
//!
//! # FID (File Identifier)
//!
//! Every AFS file is identified by a triple: `(cell, volume, vnode, unique)`.
//! The cell is implicit in the mount; the volume, vnode, and unique form the FID.

use oncrix_lib::{Error, Result};

/// Callback type codes.
pub mod cb_type {
    /// Individual callback for a specific file.
    pub const ICB: u32 = 1;
    /// Mass callback (break all cached callbacks).
    pub const MCB: u32 = 2;
    /// No callback (file not cached).
    pub const NONE: u32 = 3;
}

/// AFS File Identifier (FID).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct Fid {
    /// Volume ID within the cell.
    pub volume: u32,
    /// Vnode number within the volume.
    pub vnode: u32,
    /// Uniquifier — incremented on each file recreation.
    pub unique: u32,
}

impl Fid {
    /// Creates a new FID.
    pub const fn new(volume: u32, vnode: u32, unique: u32) -> Self {
        Self {
            volume,
            vnode,
            unique,
        }
    }

    /// Parses a FID from 12 bytes (network byte order).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            volume: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            vnode: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            unique: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// Serializes this FID to 12 bytes (network byte order).
    pub fn to_bytes(&self, b: &mut [u8; 12]) {
        b[0..4].copy_from_slice(&self.volume.to_be_bytes());
        b[4..8].copy_from_slice(&self.vnode.to_be_bytes());
        b[8..12].copy_from_slice(&self.unique.to_be_bytes());
    }
}

/// An AFS callback record (AFSCallBack XDR struct).
#[derive(Clone, Copy, Default, Debug)]
pub struct AfsCallback {
    /// Version / expiry time in seconds relative to the epoch used by
    /// the fileserver (typically seconds since 1970-01-01).
    pub version: u32,
    /// Expiry time in seconds.
    pub expiry_time: u32,
    /// Callback type (ICB, MCB, or NONE).
    pub cb_type: u32,
}

impl AfsCallback {
    /// Parses an AFS callback from 12 bytes (XDR / big-endian).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            version: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            expiry_time: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            cb_type: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// Returns `true` if this callback is an individual (per-file) callback.
    pub const fn is_individual(&self) -> bool {
        self.cb_type == cb_type::ICB
    }

    /// Returns `true` if this is a mass callback (break all).
    pub const fn is_mass(&self) -> bool {
        self.cb_type == cb_type::MCB
    }

    /// Returns `true` if the callback has expired given `now` (seconds since epoch).
    pub const fn is_expired(&self, now: u32) -> bool {
        now >= self.expiry_time
    }
}

/// Callback state for a cached inode.
#[derive(Clone, Copy, Default, Debug)]
pub struct CallbackState {
    /// The FID this callback covers.
    pub fid: Fid,
    /// The callback promise received from the fileserver.
    pub callback: AfsCallback,
    /// Whether the callback is currently valid.
    pub valid: bool,
}

impl CallbackState {
    /// Creates a new `CallbackState` with a valid callback.
    pub const fn new(fid: Fid, callback: AfsCallback) -> Self {
        Self {
            fid,
            callback,
            valid: true,
        }
    }

    /// Breaks this callback (called when the fileserver sends a CB_Break RPC).
    pub fn break_callback(&mut self) {
        self.valid = false;
    }

    /// Returns `true` if the cache is still valid.
    pub const fn is_valid(&self, now: u32) -> bool {
        self.valid && !self.callback.is_expired(now)
    }
}

/// A fixed-size callback table tracking callbacks for up to N cached inodes.
pub struct CallbackTable<const N: usize> {
    /// Callback entries.
    entries: [CallbackState; N],
    /// Number of valid entries.
    count: usize,
}

impl<const N: usize> CallbackTable<N> {
    /// Creates an empty callback table.
    pub fn new() -> Self {
        // SAFETY: CallbackState is plain data with a safe Default.
        Self {
            entries: [const {
                CallbackState {
                    fid: Fid {
                        volume: 0,
                        vnode: 0,
                        unique: 0,
                    },
                    callback: AfsCallback {
                        version: 0,
                        expiry_time: 0,
                        cb_type: 0,
                    },
                    valid: false,
                }
            }; N],
            count: 0,
        }
    }

    /// Registers a new callback for `fid`.
    ///
    /// If a callback for `fid` already exists, it is replaced.
    pub fn register(&mut self, fid: Fid, cb: AfsCallback) -> Result<()> {
        // Check for existing entry.
        for e in &mut self.entries[..self.count] {
            if e.fid == fid {
                e.callback = cb;
                e.valid = true;
                return Ok(());
            }
        }
        if self.count >= N {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = CallbackState::new(fid, cb);
        self.count += 1;
        Ok(())
    }

    /// Breaks the callback for `fid`.
    pub fn break_callback(&mut self, fid: &Fid) {
        for e in &mut self.entries[..self.count] {
            if &e.fid == fid {
                e.break_callback();
                return;
            }
        }
    }

    /// Breaks all callbacks (mass callback).
    pub fn break_all(&mut self) {
        for e in &mut self.entries[..self.count] {
            e.valid = false;
        }
    }

    /// Returns `true` if the cache for `fid` is still valid at time `now`.
    pub fn is_valid(&self, fid: &Fid, now: u32) -> bool {
        for e in &self.entries[..self.count] {
            if &e.fid == fid {
                return e.is_valid(now);
            }
        }
        false
    }

    /// Removes expired callbacks to free table space.
    pub fn evict_expired(&mut self, now: u32) {
        let mut write = 0usize;
        for i in 0..self.count {
            if self.entries[i].is_valid(now) {
                self.entries[write] = self.entries[i];
                write += 1;
            }
        }
        self.count = write;
    }
}

impl<const N: usize> Default for CallbackTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

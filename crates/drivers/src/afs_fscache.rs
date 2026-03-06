// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AFS filesystem cache integration (driver-level cache adapter).
//!
//! Provides a cache adapter for the AFS (Andrew File System) client that
//! maps AFS volume/vnode identity to persistent cache cookies, manages
//! cache key generation, and handles cache invalidation on server callback.
//!
//! This module does NOT implement full AFS protocol or a real persistent
//! cache backend. It provides the integration layer (cookie lifecycle,
//! coherency checks, index keys) that a real fscache backing store would
//! consume. Modeled after Linux `fs/afs/cache.c` patterns.
//!
//! # Architecture
//!
//! - [`AfsVolumeKey`] — index key for a cached AFS volume.
//! - [`AfsVnodeKey`] — index key for a cached AFS vnode (file/dir).
//! - [`AfsCacheCoherency`] — coherency record stored with the cache entry.
//! - [`AfsCacheCookie`] — opaque cookie representing a cached object.
//! - [`AfsCacheRegistry`] — tracks active cookies; supports acquire/relinquish.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent cache cookies.
const MAX_COOKIES: usize = 128;

/// Maximum number of cache volumes tracked.
const MAX_VOLUMES: usize = 32;

/// AFS volume types.
pub const AFSVL_RWVOL: u8 = 0; // read-write volume
pub const AFSVL_ROVOL: u8 = 1; // read-only volume
pub const AFSVL_BACKVOL: u8 = 2; // backup volume

// ---------------------------------------------------------------------------
// Volume Key
// ---------------------------------------------------------------------------

/// Index key identifying a cached AFS volume.
///
/// The combination of (cell ID, volume ID, volume type) uniquely identifies
/// an AFS volume within a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AfsVolumeKey {
    /// Cell identifier (hash of cell name, simplified).
    pub cell_id: u32,
    /// AFS Volume ID.
    pub volume_id: u32,
    /// Volume type: `AFSVL_RWVOL`, `AFSVL_ROVOL`, or `AFSVL_BACKVOL`.
    pub volume_type: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

impl AfsVolumeKey {
    /// Create a volume key.
    pub const fn new(cell_id: u32, volume_id: u32, volume_type: u8) -> Self {
        Self {
            cell_id,
            volume_id,
            volume_type,
            _pad: [0u8; 3],
        }
    }

    /// Generate a compact 64-bit cache index key from this volume key.
    pub fn to_index_key(self) -> u64 {
        (u64::from(self.cell_id) << 33)
            | (u64::from(self.volume_id) << 1)
            | u64::from(self.volume_type & 0x1)
    }
}

// ---------------------------------------------------------------------------
// Vnode Key
// ---------------------------------------------------------------------------

/// Index key identifying a cached AFS vnode (file or directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AfsVnodeKey {
    /// Volume this vnode belongs to.
    pub volume_key: AfsVolumeKey,
    /// AFS file identifier: vnode number.
    pub vnode_id: u32,
    /// AFS file identifier: unique identifier.
    pub unique: u32,
}

impl AfsVnodeKey {
    /// Create a vnode key.
    pub const fn new(volume_key: AfsVolumeKey, vnode_id: u32, unique: u32) -> Self {
        Self {
            volume_key,
            vnode_id,
            unique,
        }
    }

    /// Generate a 64-bit cache index key for this vnode.
    pub fn to_index_key(self) -> u64 {
        let vol = self.volume_key.to_index_key();
        // XOR with vnode-specific bits; real impl uses a structured binary key.
        vol ^ (u64::from(self.vnode_id) << 32) ^ u64::from(self.unique)
    }
}

// ---------------------------------------------------------------------------
// Coherency Record
// ---------------------------------------------------------------------------

/// Coherency data stored alongside a cache entry.
///
/// Used to detect stale cache entries after server callback invalidation or
/// volume version changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AfsCacheCoherency {
    /// Data version number from the server.
    pub data_version: u64,
    /// VNode data version (file content version).
    pub vnode_data_version: u64,
    /// Server change time (seconds since epoch, simplified).
    pub server_time: u64,
    /// Locally cached size in bytes.
    pub cached_size: u64,
}

impl AfsCacheCoherency {
    /// Returns `true` if this record is consistent with a fresh server response.
    ///
    /// `server_dv` — data version reported by the server.
    /// `server_time` — file modification time from the server.
    pub fn is_coherent(&self, server_dv: u64, server_time: u64) -> bool {
        self.data_version == server_dv && self.server_time == server_time
    }
}

// ---------------------------------------------------------------------------
// Cache Cookie
// ---------------------------------------------------------------------------

/// State of a cache cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieState {
    /// Cookie is active and the cache entry is valid.
    Active,
    /// Cookie has been invalidated (server callback received).
    Invalidated,
    /// Cookie has been relinquished.
    Relinquished,
}

/// An opaque cookie representing a cached AFS object (volume or vnode).
#[derive(Debug, Clone, Copy)]
pub struct AfsCacheCookie {
    /// Unique cookie identifier.
    pub id: u32,
    /// 64-bit cache index key derived from volume/vnode key.
    pub index_key: u64,
    /// Object type: 0 = volume index, 1 = vnode data.
    pub object_type: u8,
    /// Current state.
    pub state: CookieState,
    /// Coherency record.
    pub coherency: AfsCacheCoherency,
    /// Number of active users of this cookie.
    pub use_count: u32,
}

impl AfsCacheCookie {
    /// Create a new active volume-level cookie.
    pub const fn volume(id: u32, _key: &AfsVolumeKey) -> Self {
        Self {
            id,
            index_key: 0, // computed post-construction
            object_type: 0,
            state: CookieState::Active,
            coherency: AfsCacheCoherency {
                data_version: 0,
                vnode_data_version: 0,
                server_time: 0,
                cached_size: 0,
            },
            use_count: 1,
        }
    }

    /// Create a new active vnode-level cookie.
    pub const fn vnode(id: u32) -> Self {
        Self {
            id,
            index_key: 0,
            object_type: 1,
            state: CookieState::Active,
            coherency: AfsCacheCoherency {
                data_version: 0,
                vnode_data_version: 0,
                server_time: 0,
                cached_size: 0,
            },
            use_count: 1,
        }
    }

    /// Returns `true` if the cookie is usable (active and not invalidated).
    pub fn is_valid(&self) -> bool {
        self.state == CookieState::Active
    }

    /// Increment use count.
    pub fn get(&mut self) {
        self.use_count = self.use_count.saturating_add(1);
    }

    /// Decrement use count.
    pub fn put(&mut self) {
        self.use_count = self.use_count.saturating_sub(1);
    }

    /// Perform a coherency check against server values.
    ///
    /// Marks the cookie as invalidated if the data version has changed.
    ///
    /// Returns `true` if the cached data is still coherent.
    pub fn check_coherency(&mut self, server_dv: u64, server_time: u64) -> bool {
        if self.coherency.is_coherent(server_dv, server_time) {
            true
        } else {
            self.state = CookieState::Invalidated;
            false
        }
    }

    /// Update the coherency record after a successful read from the server.
    pub fn update_coherency(&mut self, coh: AfsCacheCoherency) {
        self.coherency = coh;
        if self.state == CookieState::Invalidated {
            self.state = CookieState::Active;
        }
    }
}

// ---------------------------------------------------------------------------
// Volume Cache Entry
// ---------------------------------------------------------------------------

/// A cached AFS volume entry.
#[derive(Debug, Clone, Copy)]
pub struct AfsVolumeCacheEntry {
    /// Volume identity key.
    pub key: AfsVolumeKey,
    /// Cookie ID for the volume index.
    pub cookie_id: u32,
    /// Last known volume version (for invalidation).
    pub volume_version: u64,
}

// ---------------------------------------------------------------------------
// Cache Registry
// ---------------------------------------------------------------------------

/// Registry of all active AFS cache cookies.
pub struct AfsCacheRegistry {
    cookies: [Option<AfsCacheCookie>; MAX_COOKIES],
    volumes: [Option<AfsVolumeCacheEntry>; MAX_VOLUMES],
    cookie_count: usize,
    volume_count: usize,
    next_cookie_id: u32,
}

impl AfsCacheRegistry {
    /// Create an empty cache registry.
    pub const fn new() -> Self {
        const COOKIE_NONE: Option<AfsCacheCookie> = None;
        const VOLUME_NONE: Option<AfsVolumeCacheEntry> = None;
        Self {
            cookies: [COOKIE_NONE; MAX_COOKIES],
            volumes: [VOLUME_NONE; MAX_VOLUMES],
            cookie_count: 0,
            volume_count: 0,
            next_cookie_id: 1,
        }
    }

    // -----------------------------------------------------------------------
    // Cookie lifecycle
    // -----------------------------------------------------------------------

    /// Acquire a volume-level cache cookie.
    ///
    /// If a cookie already exists for `key`, increments its use count and
    /// returns the existing cookie ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slot is available.
    pub fn acquire_volume_cookie(&mut self, key: AfsVolumeKey) -> Result<u32> {
        // Check for existing.
        for slot in self.cookies.iter_mut().flatten() {
            if slot.object_type == 0 && slot.index_key == key.to_index_key() {
                slot.get();
                return Ok(slot.id);
            }
        }
        let idx = self
            .cookies
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_cookie_id;
        self.next_cookie_id = self.next_cookie_id.wrapping_add(1).max(1);
        let mut cookie = AfsCacheCookie::volume(id, &key);
        cookie.index_key = key.to_index_key();
        self.cookies[idx] = Some(cookie);
        self.cookie_count += 1;
        Ok(id)
    }

    /// Acquire a vnode-level cache cookie.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no slot is available.
    pub fn acquire_vnode_cookie(&mut self, vnode_key: AfsVnodeKey) -> Result<u32> {
        let index_key = vnode_key.to_index_key();
        // Check for existing.
        for slot in self.cookies.iter_mut().flatten() {
            if slot.object_type == 1 && slot.index_key == index_key {
                slot.get();
                return Ok(slot.id);
            }
        }
        let idx = self
            .cookies
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_cookie_id;
        self.next_cookie_id = self.next_cookie_id.wrapping_add(1).max(1);
        let mut cookie = AfsCacheCookie::vnode(id);
        cookie.index_key = index_key;
        self.cookies[idx] = Some(cookie);
        self.cookie_count += 1;
        Ok(id)
    }

    /// Relinquish a cookie (decrement use count, mark relinquished if zero).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cookie ID is unknown.
    pub fn relinquish_cookie(&mut self, cookie_id: u32) -> Result<()> {
        let idx = self
            .cookies
            .iter()
            .position(|s| s.map_or(false, |c| c.id == cookie_id))
            .ok_or(Error::NotFound)?;
        let cookie = self.cookies[idx].as_mut().ok_or(Error::NotFound)?;
        cookie.put();
        if cookie.use_count == 0 {
            cookie.state = CookieState::Relinquished;
            self.cookies[idx] = None;
            self.cookie_count -= 1;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Cache invalidation (server callback)
    // -----------------------------------------------------------------------

    /// Invalidate all cookies associated with the given vnode key.
    ///
    /// Called when the AFS server issues a callback break for a vnode.
    /// Returns the number of cookies invalidated.
    pub fn invalidate_vnode(&mut self, vnode_key: AfsVnodeKey) -> usize {
        let index_key = vnode_key.to_index_key();
        let mut count = 0usize;
        for slot in self.cookies.iter_mut().flatten() {
            if slot.index_key == index_key {
                slot.state = CookieState::Invalidated;
                count += 1;
            }
        }
        count
    }

    /// Invalidate all cookies for an entire volume (volume callback break).
    ///
    /// Returns the number of cookies invalidated.
    pub fn invalidate_volume(&mut self, volume_key: AfsVolumeKey) -> usize {
        let vol_index = volume_key.to_index_key();
        let mut count = 0usize;
        for slot in self.cookies.iter_mut().flatten() {
            // Invalidate volume cookie and any vnode cookie in the same volume
            // (vnode index keys XOR the volume bits, so check prefix overlap).
            let key_vol_bits = slot.index_key >> 1 & 0xFFFF_FFFF;
            if key_vol_bits == (vol_index >> 1 & 0xFFFF_FFFF) {
                slot.state = CookieState::Invalidated;
                count += 1;
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Data read from cache (stub)
    // -----------------------------------------------------------------------

    /// Attempt to read cached data into `buf` for a given cookie.
    ///
    /// In a real implementation this would invoke the fscache read I/O path.
    /// This stub validates the cookie state and returns [`Error::NotFound`]
    /// to signal that a server fetch is required.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cookie is not active (cache miss).
    /// Returns [`Error::InvalidArgument`] if `cookie_id` is unknown.
    pub fn read_data(&self, cookie_id: u32, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        let cookie = self
            .cookies
            .iter()
            .flatten()
            .find(|c| c.id == cookie_id)
            .ok_or(Error::InvalidArgument)?;
        if !cookie.is_valid() {
            return Err(Error::NotFound);
        }
        // Stub: cache is always a miss in this implementation.
        Err(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Coherency helpers
    // -----------------------------------------------------------------------

    /// Update the coherency record for a cookie after a server fetch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `cookie_id` is unknown.
    pub fn update_coherency(&mut self, cookie_id: u32, coherency: AfsCacheCoherency) -> Result<()> {
        let cookie = self
            .cookies
            .iter_mut()
            .flatten()
            .find(|c| c.id == cookie_id)
            .ok_or(Error::NotFound)?;
        cookie.update_coherency(coherency);
        Ok(())
    }

    /// Check coherency of a cookie against fresh server values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cookie is unknown.
    pub fn check_coherency(
        &mut self,
        cookie_id: u32,
        server_dv: u64,
        server_time: u64,
    ) -> Result<bool> {
        let cookie = self
            .cookies
            .iter_mut()
            .flatten()
            .find(|c| c.id == cookie_id)
            .ok_or(Error::NotFound)?;
        Ok(cookie.check_coherency(server_dv, server_time))
    }

    // -----------------------------------------------------------------------
    // Volume registry
    // -----------------------------------------------------------------------

    /// Register a cached volume (associates a volume key with its cookie).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the volume table is full.
    /// Returns [`Error::AlreadyExists`] if the volume is already registered.
    pub fn register_volume(
        &mut self,
        key: AfsVolumeKey,
        cookie_id: u32,
        volume_version: u64,
    ) -> Result<()> {
        for slot in self.volumes.iter().flatten() {
            if slot.key == key {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .volumes
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.volumes[idx] = Some(AfsVolumeCacheEntry {
            key,
            cookie_id,
            volume_version,
        });
        self.volume_count += 1;
        Ok(())
    }

    /// Returns the number of active cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookie_count
    }

    /// Returns the number of registered volumes.
    pub fn volume_count(&self) -> usize {
        self.volume_count
    }
}

impl Default for AfsCacheRegistry {
    fn default() -> Self {
        Self::new()
    }
}

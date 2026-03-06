// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CacheFiles cache backend.
//!
//! CacheFiles provides a persistent on-disk cache for network filesystems
//! (NFS, Ceph, AFS, …) and EROFS images by storing cached data as regular
//! files in a directory tree on a local filesystem.  The kernel's fscache
//! layer calls into this backend when it needs to read from or write to the
//! persistent cache.
//!
//! # Architecture
//!
//! ```text
//! fscache volume (CacheVolume)
//!   → cache root directory on local FS
//!     → per-object files (CacheObject)
//!       → block-indexed data pages (CacheBlock)
//!         → CacheBackend::read() / write()
//! ```
//!
//! # Object naming
//!
//! Each cached object is identified by a (volume_key, object_key) pair.
//! The file path inside the cache root is:
//!
//! ```text
//! <root>/<vol_hash[0..2]>/<vol_hash[2..4]>/<vol_hash[4..]>+<obj_hash>
//! ```
//!
//! # Structures
//!
//! - [`CacheState`]       — object lifecycle state
//! - [`CacheObjectKey`]   — (volume, object) identity
//! - [`CacheBlock`]       — single cached data page
//! - [`CacheObject`]      — full cached object with block map
//! - [`CacheVolume`]      — group of objects sharing a volume key
//! - [`CacheBackend`]     — top-level backend with volume table
//! - [`CacheStats`]       — aggregate hit/miss counters
//!
//! # References
//!
//! - Linux `fs/cachefiles/`, `include/linux/fscache.h`
//! - `Documentation/filesystems/caching/cachefiles.rst`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of volumes managed by a single backend.
pub const MAX_VOLUMES: usize = 32;

/// Maximum objects per volume.
pub const MAX_OBJECTS_PER_VOLUME: usize = 128;

/// Maximum cached blocks (pages) per object.
pub const MAX_BLOCKS_PER_OBJECT: usize = 256;

/// Block (page) size for cache storage (4 KiB).
pub const CACHE_BLOCK_SIZE: usize = 4096;

/// Maximum length of a volume key.
pub const MAX_VOLUME_KEY: usize = 64;

/// Maximum length of an object key.
pub const MAX_OBJECT_KEY: usize = 64;

/// Maximum cache root path length.
pub const MAX_ROOT_PATH: usize = 128;

// ── CacheState ────────────────────────────────────────────────────────────────

/// Lifecycle state of a cache object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CacheState {
    /// Object slot is empty / not allocated.
    #[default]
    Empty = 0,
    /// Object is being created; not yet readable.
    Creating = 1,
    /// Object is available and fully usable.
    Available = 2,
    /// Object is being invalidated.
    Invalidating = 3,
    /// Object has been withdrawn; pending reclaim.
    Withdrawn = 4,
}

// ── CacheObjectKey ────────────────────────────────────────────────────────────

/// Identity key for a cached object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheObjectKey {
    /// Volume key bytes.
    pub vol_key: [u8; MAX_VOLUME_KEY],
    /// Volume key length.
    pub vol_key_len: usize,
    /// Object key bytes.
    pub obj_key: [u8; MAX_OBJECT_KEY],
    /// Object key length.
    pub obj_key_len: usize,
}

impl Default for CacheObjectKey {
    fn default() -> Self {
        Self {
            vol_key: [0u8; MAX_VOLUME_KEY],
            vol_key_len: 0,
            obj_key: [0u8; MAX_OBJECT_KEY],
            obj_key_len: 0,
        }
    }
}

impl CacheObjectKey {
    /// Create a new key from byte slices.
    pub fn new(vol_key: &[u8], obj_key: &[u8]) -> Result<Self> {
        if vol_key.len() > MAX_VOLUME_KEY || obj_key.len() > MAX_OBJECT_KEY {
            return Err(Error::InvalidArgument);
        }
        let mut key = Self::default();
        key.vol_key[..vol_key.len()].copy_from_slice(vol_key);
        key.vol_key_len = vol_key.len();
        key.obj_key[..obj_key.len()].copy_from_slice(obj_key);
        key.obj_key_len = obj_key.len();
        Ok(key)
    }

    /// Compute a simple hash of the key for path sharding.
    pub fn hash(&self) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        for &b in &self.vol_key[..self.vol_key_len] {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        for &b in &self.obj_key[..self.obj_key_len] {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    }
}

// ── CacheBlock ────────────────────────────────────────────────────────────────

/// A single 4 KiB block stored in the cache for an object.
#[derive(Clone, Copy)]
pub struct CacheBlock {
    /// Block index within the object (page-frame index).
    pub index: u64,
    /// Whether this block contains valid data.
    pub valid: bool,
    /// Whether the block has unsaved modifications (dirty).
    pub dirty: bool,
    /// Block data.
    pub data: [u8; CACHE_BLOCK_SIZE],
}

impl Default for CacheBlock {
    fn default() -> Self {
        Self {
            index: 0,
            valid: false,
            dirty: false,
            data: [0u8; CACHE_BLOCK_SIZE],
        }
    }
}

// ── CacheObject ───────────────────────────────────────────────────────────────

/// A single cached object (file or data stream).
pub struct CacheObject {
    /// Object identity.
    pub key: CacheObjectKey,
    /// Current state.
    pub state: CacheState,
    /// Total object size in bytes.
    pub size: u64,
    /// Block map.
    blocks: [CacheBlock; MAX_BLOCKS_PER_OBJECT],
    block_count: usize,
    /// Number of cache hits served from this object.
    pub hits: u64,
    /// Number of cache misses for this object.
    pub misses: u64,
}

impl Default for CacheObject {
    fn default() -> Self {
        Self {
            key: CacheObjectKey::default(),
            state: CacheState::Empty,
            size: 0,
            blocks: [CacheBlock::default(); MAX_BLOCKS_PER_OBJECT],
            block_count: 0,
            hits: 0,
            misses: 0,
        }
    }
}

impl CacheObject {
    /// Find or allocate a block for the given block index.
    fn get_or_alloc_block(&mut self, block_idx: u64) -> Result<usize> {
        // Search existing blocks.
        if let Some(pos) = self.blocks[..self.block_count]
            .iter()
            .position(|b| b.index == block_idx)
        {
            return Ok(pos);
        }
        // Allocate new slot.
        if self.block_count >= MAX_BLOCKS_PER_OBJECT {
            return Err(Error::OutOfMemory);
        }
        let pos = self.block_count;
        self.blocks[pos].index = block_idx;
        self.blocks[pos].valid = false;
        self.blocks[pos].dirty = false;
        self.block_count += 1;
        Ok(pos)
    }

    /// Read `dst.len()` bytes from `offset`.
    ///
    /// Returns [`Error::NotFound`] for blocks not yet cached (cache miss).
    pub fn read(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let block_idx = offset / CACHE_BLOCK_SIZE as u64;
        let block_off = (offset % CACHE_BLOCK_SIZE as u64) as usize;

        match self.blocks[..self.block_count]
            .iter()
            .find(|b| b.index == block_idx)
        {
            Some(block) if block.valid => {
                let available = CACHE_BLOCK_SIZE - block_off;
                let to_copy = available.min(dst.len());
                dst[..to_copy].copy_from_slice(&block.data[block_off..block_off + to_copy]);
                self.hits += 1;
                Ok(to_copy)
            }
            _ => {
                self.misses += 1;
                Err(Error::NotFound)
            }
        }
    }

    /// Write `src` bytes at `offset` into the cache.
    pub fn write(&mut self, offset: u64, src: &[u8]) -> Result<usize> {
        let block_idx = offset / CACHE_BLOCK_SIZE as u64;
        let block_off = (offset % CACHE_BLOCK_SIZE as u64) as usize;
        let to_copy = src.len().min(CACHE_BLOCK_SIZE - block_off);

        let pos = self.get_or_alloc_block(block_idx)?;
        let block = &mut self.blocks[pos];
        block.data[block_off..block_off + to_copy].copy_from_slice(&src[..to_copy]);
        block.valid = true;
        block.dirty = true;
        if offset + to_copy as u64 > self.size {
            self.size = offset + to_copy as u64;
        }
        Ok(to_copy)
    }

    /// Mark all dirty blocks as clean (simulating a write-back flush).
    pub fn flush(&mut self) {
        for block in self.blocks[..self.block_count].iter_mut() {
            block.dirty = false;
        }
    }

    /// Invalidate all blocks — next read will be a cache miss.
    pub fn invalidate(&mut self) {
        for block in self.blocks[..self.block_count].iter_mut() {
            block.valid = false;
        }
        self.block_count = 0;
        self.state = CacheState::Invalidating;
    }
}

// ── CacheVolume ───────────────────────────────────────────────────────────────

/// A group of cache objects sharing the same volume key.
pub struct CacheVolume {
    /// Volume key.
    vol_key: [u8; MAX_VOLUME_KEY],
    vol_key_len: usize,
    /// Objects in this volume.
    objects: [Option<CacheObject>; MAX_OBJECTS_PER_VOLUME],
    object_count: usize,
    /// Whether this volume slot is active.
    pub active: bool,
}

impl Default for CacheVolume {
    fn default() -> Self {
        Self {
            vol_key: [0u8; MAX_VOLUME_KEY],
            vol_key_len: 0,
            objects: core::array::from_fn(|_| None),
            object_count: 0,
            active: false,
        }
    }
}

impl CacheVolume {
    /// Set the volume key.
    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() > MAX_VOLUME_KEY {
            return Err(Error::InvalidArgument);
        }
        self.vol_key[..key.len()].copy_from_slice(key);
        self.vol_key_len = key.len();
        Ok(())
    }

    /// Return the volume key as a byte slice.
    pub fn vol_key(&self) -> &[u8] {
        &self.vol_key[..self.vol_key_len]
    }

    /// Find a mutable reference to a cached object by key.
    pub fn get_object_mut(&mut self, obj_key: &[u8]) -> Option<&mut CacheObject> {
        self.objects[..self.object_count]
            .iter_mut()
            .find_map(|slot| {
                slot.as_mut()
                    .filter(|o| &o.key.obj_key[..o.key.obj_key_len] == obj_key)
            })
    }

    /// Find an immutable reference to a cached object by key.
    pub fn get_object(&self, obj_key: &[u8]) -> Option<&CacheObject> {
        self.objects[..self.object_count].iter().find_map(|slot| {
            slot.as_ref()
                .filter(|o| &o.key.obj_key[..o.key.obj_key_len] == obj_key)
        })
    }

    /// Insert a new object.  Returns [`Error::OutOfMemory`] if the volume is full.
    pub fn insert_object(&mut self, obj: CacheObject) -> Result<()> {
        if self.object_count >= MAX_OBJECTS_PER_VOLUME {
            return Err(Error::OutOfMemory);
        }
        // Find an empty Option slot.
        let slot = self.objects[..self.object_count]
            .iter()
            .position(|s| s.is_none())
            .unwrap_or(self.object_count);
        if slot == self.object_count {
            self.object_count += 1;
        }
        self.objects[slot] = Some(obj);
        Ok(())
    }

    /// Remove an object by key.
    pub fn remove_object(&mut self, obj_key: &[u8]) -> Result<()> {
        let pos = self.objects[..self.object_count]
            .iter()
            .position(|s| {
                s.as_ref()
                    .is_some_and(|o| &o.key.obj_key[..o.key.obj_key_len] == obj_key)
            })
            .ok_or(Error::NotFound)?;
        self.objects[pos] = None;
        Ok(())
    }
}

// ── CacheStats ────────────────────────────────────────────────────────────────

/// Aggregate hit/miss statistics for the cache backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    /// Total cache-hit reads (data served from cache).
    pub hits: u64,
    /// Total cache-miss reads (data not in cache, needed network fetch).
    pub misses: u64,
    /// Total bytes written into the cache.
    pub bytes_written: u64,
    /// Total bytes read from the cache.
    pub bytes_read: u64,
    /// Objects currently present in the cache.
    pub objects: u64,
    /// Volumes currently present in the cache.
    pub volumes: u64,
}

impl CacheStats {
    /// Cache hit ratio as a percentage (0–100).
    pub fn hit_ratio(&self) -> u64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0
        } else {
            self.hits * 100 / total
        }
    }
}

// ── CacheBackend ──────────────────────────────────────────────────────────────

/// Top-level CacheFiles backend.
pub struct CacheBackend {
    /// Root path for the on-disk cache directory.
    root_path: [u8; MAX_ROOT_PATH],
    root_path_len: usize,
    /// Volume table.
    volumes: [Option<CacheVolume>; MAX_VOLUMES],
    volume_count: usize,
    /// Whether the backend is currently active.
    pub active: bool,
    /// Aggregate statistics.
    pub stats: CacheStats,
}

impl Default for CacheBackend {
    fn default() -> Self {
        Self {
            root_path: [0u8; MAX_ROOT_PATH],
            root_path_len: 0,
            volumes: core::array::from_fn(|_| None),
            volume_count: 0,
            active: false,
            stats: CacheStats::default(),
        }
    }
}

impl CacheBackend {
    /// Initialise the backend with a root path.
    pub fn init(&mut self, root_path: &[u8]) -> Result<()> {
        if root_path.len() > MAX_ROOT_PATH {
            return Err(Error::InvalidArgument);
        }
        self.root_path[..root_path.len()].copy_from_slice(root_path);
        self.root_path_len = root_path.len();
        self.active = true;
        Ok(())
    }

    /// Return the cache root path.
    pub fn root_path(&self) -> &[u8] {
        &self.root_path[..self.root_path_len]
    }

    /// Look up or create a volume for `vol_key`.
    fn get_or_create_volume(&mut self, vol_key: &[u8]) -> Result<usize> {
        // Search existing volumes.
        if let Some(idx) = self.volumes[..self.volume_count]
            .iter()
            .position(|v| v.as_ref().is_some_and(|vol| vol.vol_key() == vol_key))
        {
            return Ok(idx);
        }
        // Create new volume.
        if self.volume_count >= MAX_VOLUMES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.volume_count;
        let mut vol = CacheVolume::default();
        vol.set_key(vol_key)?;
        vol.active = true;
        self.volumes[idx] = Some(vol);
        self.volume_count += 1;
        self.stats.volumes += 1;
        Ok(idx)
    }

    /// Acquire (look up or create) a cache object.
    pub fn acquire(&mut self, key: CacheObjectKey) -> Result<()> {
        if !self.active {
            return Err(Error::Busy);
        }
        let vol_key = &key.vol_key[..key.vol_key_len];
        let vol_idx = self.get_or_create_volume(vol_key)?;

        let vol = self.volumes[vol_idx].as_mut().ok_or(Error::IoError)?;
        let obj_key = &key.obj_key[..key.obj_key_len];
        if vol.get_object(obj_key).is_none() {
            let mut obj = CacheObject::default();
            obj.key = key;
            obj.state = CacheState::Available;
            vol.insert_object(obj)?;
            self.stats.objects += 1;
        }
        Ok(())
    }

    /// Read from a cached object.  Returns a cache miss error when the data
    /// is not in the cache.
    pub fn read(&mut self, key: &CacheObjectKey, offset: u64, dst: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::Busy);
        }
        let vol_key = &key.vol_key[..key.vol_key_len];
        let obj_key = &key.obj_key[..key.obj_key_len];

        let vol_idx = self.volumes[..self.volume_count]
            .iter()
            .position(|v| v.as_ref().is_some_and(|vol| vol.vol_key() == vol_key))
            .ok_or(Error::NotFound)?;

        let vol = self.volumes[vol_idx].as_mut().ok_or(Error::NotFound)?;
        let obj = vol.get_object_mut(obj_key).ok_or(Error::NotFound)?;
        match obj.read(offset, dst) {
            Ok(n) => {
                self.stats.hits += 1;
                self.stats.bytes_read += n as u64;
                Ok(n)
            }
            Err(Error::NotFound) => {
                self.stats.misses += 1;
                Err(Error::NotFound)
            }
            Err(e) => Err(e),
        }
    }

    /// Write data into a cached object.
    pub fn write(&mut self, key: &CacheObjectKey, offset: u64, src: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::Busy);
        }
        let vol_key = &key.vol_key[..key.vol_key_len];
        let obj_key = &key.obj_key[..key.obj_key_len];

        let vol_idx = self.volumes[..self.volume_count]
            .iter()
            .position(|v| v.as_ref().is_some_and(|vol| vol.vol_key() == vol_key))
            .ok_or(Error::NotFound)?;

        let vol = self.volumes[vol_idx].as_mut().ok_or(Error::NotFound)?;
        let obj = vol.get_object_mut(obj_key).ok_or(Error::NotFound)?;
        let n = obj.write(offset, src)?;
        self.stats.bytes_written += n as u64;
        Ok(n)
    }

    /// Invalidate all cached data for an object.
    pub fn invalidate(&mut self, key: &CacheObjectKey) -> Result<()> {
        if !self.active {
            return Err(Error::Busy);
        }
        let vol_key = &key.vol_key[..key.vol_key_len];
        let obj_key = &key.obj_key[..key.obj_key_len];

        let vol_idx = self.volumes[..self.volume_count]
            .iter()
            .position(|v| v.as_ref().is_some_and(|vol| vol.vol_key() == vol_key))
            .ok_or(Error::NotFound)?;

        let vol = self.volumes[vol_idx].as_mut().ok_or(Error::NotFound)?;
        let obj = vol.get_object_mut(obj_key).ok_or(Error::NotFound)?;
        obj.invalidate();
        Ok(())
    }

    /// Withdraw (remove) a cache object.
    pub fn withdraw(&mut self, key: &CacheObjectKey) -> Result<()> {
        if !self.active {
            return Err(Error::Busy);
        }
        let vol_key = &key.vol_key[..key.vol_key_len];
        let obj_key = &key.obj_key[..key.obj_key_len];

        let vol_idx = self.volumes[..self.volume_count]
            .iter()
            .position(|v| v.as_ref().is_some_and(|vol| vol.vol_key() == vol_key))
            .ok_or(Error::NotFound)?;

        let vol = self.volumes[vol_idx].as_mut().ok_or(Error::NotFound)?;
        vol.remove_object(obj_key)?;
        if self.stats.objects > 0 {
            self.stats.objects -= 1;
        }
        Ok(())
    }
}

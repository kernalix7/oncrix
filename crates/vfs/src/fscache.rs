// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! fscache — General filesystem caching framework.
//!
//! Provides a kernel-level cache for network and slow-media filesystems,
//! allowing data to be stored on local fast storage (e.g., a local disk
//! partition) to avoid repeated fetches from the remote server.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  Network / slow FS (NFS, CIFS, AFS)        │
//! │                         │  read/write                      │
//! │                         ▼                                  │
//! │  ┌────────────────────────────────────────┐                │
//! │  │  fscache layer                         │                │
//! │  │  ┌──────────┐ ┌────────┐ ┌──────────┐  │                │
//! │  │  │ Cookies   │ │ Volumes│ │  Objects │  │                │
//! │  │  │ (per-file)│ │(per-SB)│ │ (cached) │  │                │
//! │  │  └──────────┘ └────────┘ └──────────┘  │                │
//! │  │              │                          │                │
//! │  │              ▼                          │                │
//! │  │  ┌────────────────────────┐             │                │
//! │  │  │  Cache backend (trait) │             │                │
//! │  │  │  (CacheOps)            │             │                │
//! │  │  └────────────────────────┘             │                │
//! │  └────────────────────────────────────────┘                │
//! │                         │                                  │
//! │                         ▼                                  │
//! │               Local disk / block device                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Cookies
//!
//! Each cached file is represented by a cookie.  Cookies track the
//! cache state (looking up, valid, invalidating, dropped) and hold
//! the cache-backend object reference.
//!
//! ## Volumes
//!
//! A volume represents a filesystem superblock in the cache, grouping
//! all cookies belonging to that mount.
//!
//! ## Cache backends
//!
//! Backends (like CacheFiles in Linux) implement `CacheBackendOps` to
//! provide actual storage.  The fscache layer delegates I/O to the
//! registered backend.
//!
//! # Reference
//!
//! Linux `fs/fscache/`, Documentation/filesystems/caching/fscache.rst.

extern crate alloc;

use alloc::string::String;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of volumes managed by fscache.
const MAX_VOLUMES: usize = 32;

/// Maximum number of cookies (cached file objects).
const MAX_COOKIES: usize = 512;

/// Maximum number of registered cache backends.
const MAX_BACKENDS: usize = 4;

/// Maximum length of a volume key string.
const MAX_VOLUME_KEY_LEN: usize = 128;

/// Maximum length of a cookie key.
const MAX_COOKIE_KEY_LEN: usize = 64;

/// Maximum number of pending I/O operations.
const MAX_PENDING_IO: usize = 64;

/// Default cache page size in bytes.
pub const CACHE_PAGE_SIZE: usize = 4096;

/// Maximum data pages tracked per cookie for small-file fast path.
const MAX_INLINE_PAGES: usize = 16;

// ── Cookie state machine ─────────────────────────────────────────────────────

/// State of a cache cookie through its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieState {
    /// Cookie created, not yet looked up in cache backend.
    New,
    /// Lookup in progress on the cache backend.
    LookingUp,
    /// Cookie is valid and ready for I/O.
    Active,
    /// Cookie is being invalidated (stale data purge).
    Invalidating,
    /// Cookie data is being written back to the backend.
    Flushing,
    /// Cookie has been relinquished by the netfs.
    Dropped,
    /// Cookie encountered an unrecoverable error.
    Failed,
}

/// Type of cached object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieType {
    /// Index cookie (directory-level, groups other cookies).
    Index,
    /// Data cookie (file-level, holds file content).
    Data,
}

// ── Cookie ───────────────────────────────────────────────────────────────────

/// A cache cookie representing a single cached file or index object.
///
/// Cookies are the primary interface between a network filesystem and
/// the fscache layer.  Each open file that should be cached acquires
/// a cookie, uses it for read/write operations, and relinquishes it
/// on close.
pub struct Cookie {
    /// Unique cookie identifier.
    id: u64,
    /// Cookie key (filesystem-defined, identifies the object).
    key: [u8; MAX_COOKIE_KEY_LEN],
    /// Length of the key in bytes.
    key_len: usize,
    /// Type of this cookie (index or data).
    cookie_type: CookieType,
    /// Current lifecycle state.
    state: CookieState,
    /// Volume this cookie belongs to.
    volume_id: u32,
    /// Size of the cached data in bytes.
    data_size: u64,
    /// Flags controlling cookie behavior.
    flags: CookieFlags,
    /// Reference count.
    ref_count: u32,
    /// Number of pages currently cached for this cookie.
    cached_pages: u32,
    /// Inline page tracking for small files.
    inline_pages: [u64; MAX_INLINE_PAGES],
    /// Number of inline page entries used.
    inline_page_count: usize,
    /// Whether this slot is in use.
    in_use: bool,
}

/// Cookie behavior flags.
#[derive(Debug, Clone, Copy)]
pub struct CookieFlags {
    /// Retire (discard) cached data when cookie is relinquished.
    pub retire_on_release: bool,
    /// Cookie was created for a file that may be written to.
    pub writable: bool,
    /// Enable read-ahead caching for this cookie.
    pub readahead: bool,
    /// Bypass cache and go direct to server (temporary disable).
    pub disabled: bool,
}

impl CookieFlags {
    /// Create default cookie flags.
    const fn new() -> Self {
        Self {
            retire_on_release: false,
            writable: false,
            readahead: true,
            disabled: false,
        }
    }
}

impl Cookie {
    /// Create an empty, unused cookie slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            key: [0; MAX_COOKIE_KEY_LEN],
            key_len: 0,
            cookie_type: CookieType::Data,
            state: CookieState::New,
            volume_id: 0,
            data_size: 0,
            flags: CookieFlags::new(),
            ref_count: 0,
            cached_pages: 0,
            inline_pages: [0; MAX_INLINE_PAGES],
            inline_page_count: 0,
            in_use: false,
        }
    }

    /// Return the cookie identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Return the current state.
    pub fn state(&self) -> CookieState {
        self.state
    }

    /// Return the cookie type.
    pub fn cookie_type(&self) -> CookieType {
        self.cookie_type
    }

    /// Return the cached data size.
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    /// Check if the cookie is in a state that allows I/O.
    pub fn is_active(&self) -> bool {
        self.state == CookieState::Active
    }
}

// ── Volume ───────────────────────────────────────────────────────────────────

/// A cache volume representing a filesystem superblock.
///
/// Volumes group cookies belonging to the same filesystem mount,
/// enabling bulk operations (e.g., unmount flushes all cookies in
/// the volume).
pub struct Volume {
    /// Volume identifier.
    id: u32,
    /// Volume key (identifies the FS instance, e.g., "nfs,server,share").
    key: [u8; MAX_VOLUME_KEY_LEN],
    /// Length of the volume key.
    key_len: usize,
    /// Number of cookies belonging to this volume.
    cookie_count: u32,
    /// Whether coherency checking is enabled.
    coherency_check: bool,
    /// Backend index this volume is stored on.
    backend_id: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl Volume {
    /// Create an empty, unused volume slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            key: [0; MAX_VOLUME_KEY_LEN],
            key_len: 0,
            cookie_count: 0,
            coherency_check: true,
            backend_id: 0,
            in_use: false,
        }
    }

    /// Return the volume identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Return the volume key as a byte slice.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

// ── Cache backend trait ──────────────────────────────────────────────────────

/// Operations that a cache backend must implement.
///
/// A cache backend provides the actual storage for cached data.
/// Examples include CacheFiles (uses a local filesystem) and
/// CacheRAM (uses memory, for testing).
pub trait CacheBackendOps {
    /// Look up a cookie in the backend storage.
    fn lookup(&mut self, cookie_id: u64, key: &[u8]) -> Result<bool>;

    /// Allocate space for a new cached object.
    fn allocate(&mut self, cookie_id: u64, size: u64) -> Result<()>;

    /// Read cached data into the provided buffer.
    fn read(&self, cookie_id: u64, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write data to the cache backend.
    fn write(&mut self, cookie_id: u64, offset: u64, data: &[u8]) -> Result<usize>;

    /// Invalidate (discard) all cached data for a cookie.
    fn invalidate(&mut self, cookie_id: u64) -> Result<()>;

    /// Release resources associated with a cookie.
    fn release(&mut self, cookie_id: u64) -> Result<()>;

    /// Return the name of this backend.
    fn name(&self) -> &str;

    /// Return available space in bytes.
    fn available_space(&self) -> u64;
}

// ── I/O operation tracking ───────────────────────────────────────────────────

/// Type of pending I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOpType {
    /// Read from cache backend into page cache.
    Read,
    /// Write from page cache to cache backend.
    Write,
    /// Invalidation of cached data range.
    Invalidate,
}

/// State of a pending I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOpState {
    /// Operation is queued.
    Pending,
    /// Operation is in progress.
    InProgress,
    /// Operation completed successfully.
    Complete,
    /// Operation failed.
    Failed,
}

/// A pending I/O operation against the cache backend.
struct PendingIo {
    /// Cookie this I/O is for.
    cookie_id: u64,
    /// Type of operation.
    op_type: IoOpType,
    /// Current state.
    state: IoOpState,
    /// File offset.
    offset: u64,
    /// Length in bytes.
    length: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl PendingIo {
    /// Create an empty, unused I/O slot.
    const fn empty() -> Self {
        Self {
            cookie_id: 0,
            op_type: IoOpType::Read,
            state: IoOpState::Pending,
            offset: 0,
            length: 0,
            in_use: false,
        }
    }
}

// ── Cache statistics ─────────────────────────────────────────────────────────

/// fscache subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct FsCacheStats {
    /// Total cookies created since boot.
    pub cookies_created: u64,
    /// Cookies currently active.
    pub cookies_active: u32,
    /// Cache lookup hits (data found in cache).
    pub hits: u64,
    /// Cache lookup misses (data not in cache).
    pub misses: u64,
    /// Bytes read from cache backend.
    pub bytes_read: u64,
    /// Bytes written to cache backend.
    pub bytes_written: u64,
    /// Number of invalidations performed.
    pub invalidations: u64,
    /// Number of I/O errors from backend.
    pub io_errors: u64,
    /// Volumes currently registered.
    pub volumes_active: u32,
}

impl FsCacheStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            cookies_created: 0,
            cookies_active: 0,
            hits: 0,
            misses: 0,
            bytes_read: 0,
            bytes_written: 0,
            invalidations: 0,
            io_errors: 0,
            volumes_active: 0,
        }
    }
}

// ── Backend registration ─────────────────────────────────────────────────────

/// Metadata for a registered cache backend.
struct BackendEntry {
    /// Backend name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Available space reported at registration.
    capacity: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl BackendEntry {
    /// Create an empty, unused backend slot.
    const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            capacity: 0,
            in_use: false,
        }
    }
}

// ── FsCache manager ──────────────────────────────────────────────────────────

/// The central fscache manager.
///
/// Manages volumes, cookies, backends, and I/O operations.  In a
/// production kernel this would be a global singleton; here it is
/// an owning struct for testability.
pub struct FsCache {
    /// Registered volumes.
    volumes: [Volume; MAX_VOLUMES],
    /// Cookie table.
    cookies: [Cookie; MAX_COOKIES],
    /// Registered backend metadata.
    backends: [BackendEntry; MAX_BACKENDS],
    /// Pending I/O operations.
    pending_io: [PendingIo; MAX_PENDING_IO],
    /// Next cookie ID to allocate.
    next_cookie_id: u64,
    /// Next volume ID to allocate.
    next_volume_id: u32,
    /// Cumulative statistics.
    stats: FsCacheStats,
}

impl FsCache {
    /// Create a new fscache manager with empty state.
    pub fn new() -> Self {
        Self {
            volumes: [const { Volume::empty() }; MAX_VOLUMES],
            cookies: [const { Cookie::empty() }; MAX_COOKIES],
            backends: [const { BackendEntry::empty() }; MAX_BACKENDS],
            pending_io: [const { PendingIo::empty() }; MAX_PENDING_IO],
            next_cookie_id: 1,
            next_volume_id: 1,
            stats: FsCacheStats::new(),
        }
    }

    // ── Volume management ────────────────────────────────────────────────

    /// Register a new cache volume for a filesystem superblock.
    ///
    /// The `key` identifies the filesystem instance (e.g., "nfs,server:/export").
    /// Returns the volume ID on success.
    pub fn acquire_volume(&mut self, key: &str, backend_id: u32) -> Result<u32> {
        let key_bytes = key.as_bytes();
        if key_bytes.is_empty() || key_bytes.len() > MAX_VOLUME_KEY_LEN {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate volume key.
        for vol in &self.volumes {
            if vol.in_use && vol.key_len == key_bytes.len() {
                if &vol.key[..vol.key_len] == key_bytes {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Verify backend exists.
        if (backend_id as usize) >= MAX_BACKENDS || !self.backends[backend_id as usize].in_use {
            return Err(Error::NotFound);
        }

        // Find a free volume slot.
        let slot = self
            .volumes
            .iter_mut()
            .find(|v| !v.in_use)
            .ok_or(Error::OutOfMemory)?;

        let vid = self.next_volume_id;
        self.next_volume_id = self.next_volume_id.wrapping_add(1);

        slot.id = vid;
        slot.key[..key_bytes.len()].copy_from_slice(key_bytes);
        slot.key_len = key_bytes.len();
        slot.cookie_count = 0;
        slot.coherency_check = true;
        slot.backend_id = backend_id;
        slot.in_use = true;

        self.stats.volumes_active += 1;
        Ok(vid)
    }

    /// Relinquish a cache volume, dropping all associated cookies.
    pub fn relinquish_volume(&mut self, volume_id: u32) -> Result<()> {
        let vol = self
            .volumes
            .iter_mut()
            .find(|v| v.in_use && v.id == volume_id)
            .ok_or(Error::NotFound)?;
        vol.in_use = false;

        // Drop all cookies belonging to this volume.
        for cookie in &mut self.cookies {
            if cookie.in_use && cookie.volume_id == volume_id {
                cookie.state = CookieState::Dropped;
                cookie.in_use = false;
                self.stats.cookies_active = self.stats.cookies_active.saturating_sub(1);
            }
        }

        self.stats.volumes_active = self.stats.volumes_active.saturating_sub(1);
        Ok(())
    }

    /// Look up a volume by its key.
    pub fn find_volume(&self, key: &str) -> Option<u32> {
        let key_bytes = key.as_bytes();
        self.volumes
            .iter()
            .find(|v| v.in_use && v.key_len == key_bytes.len() && &v.key[..v.key_len] == key_bytes)
            .map(|v| v.id)
    }

    // ── Cookie management ────────────────────────────────────────────────

    /// Acquire a new cache cookie for a file object.
    ///
    /// The caller provides a volume, a unique key within that volume,
    /// the cookie type, and the object size.  Returns the cookie ID.
    pub fn acquire_cookie(
        &mut self,
        volume_id: u32,
        key: &[u8],
        cookie_type: CookieType,
        object_size: u64,
    ) -> Result<u64> {
        if key.is_empty() || key.len() > MAX_COOKIE_KEY_LEN {
            return Err(Error::InvalidArgument);
        }

        // Verify volume exists.
        let vol_exists = self.volumes.iter().any(|v| v.in_use && v.id == volume_id);
        if !vol_exists {
            return Err(Error::NotFound);
        }

        // Find a free cookie slot.
        let slot = self
            .cookies
            .iter_mut()
            .find(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let cid = self.next_cookie_id;
        self.next_cookie_id = self.next_cookie_id.wrapping_add(1);

        slot.id = cid;
        slot.key[..key.len()].copy_from_slice(key);
        slot.key_len = key.len();
        slot.cookie_type = cookie_type;
        slot.state = CookieState::LookingUp;
        slot.volume_id = volume_id;
        slot.data_size = object_size;
        slot.flags = CookieFlags::new();
        slot.ref_count = 1;
        slot.cached_pages = 0;
        slot.inline_page_count = 0;
        slot.in_use = true;

        // Increment volume cookie count.
        for vol in &mut self.volumes {
            if vol.in_use && vol.id == volume_id {
                vol.cookie_count += 1;
                break;
            }
        }

        self.stats.cookies_created += 1;
        self.stats.cookies_active += 1;
        Ok(cid)
    }

    /// Mark a cookie as active (lookup complete, data valid).
    pub fn cookie_set_active(&mut self, cookie_id: u64) -> Result<()> {
        let cookie = self.find_cookie_mut(cookie_id)?;
        if cookie.state != CookieState::LookingUp && cookie.state != CookieState::Invalidating {
            return Err(Error::InvalidArgument);
        }
        cookie.state = CookieState::Active;
        Ok(())
    }

    /// Relinquish a cookie, releasing it from use.
    ///
    /// If `retire` is true, the cached data is discarded; otherwise
    /// it is retained for future use.
    pub fn relinquish_cookie(&mut self, cookie_id: u64, retire: bool) -> Result<()> {
        let volume_id;
        {
            let cookie = self.find_cookie_mut(cookie_id)?;
            cookie.state = CookieState::Dropped;
            cookie.ref_count = 0;
            volume_id = cookie.volume_id;

            if retire || cookie.flags.retire_on_release {
                cookie.cached_pages = 0;
                cookie.inline_page_count = 0;
            }
            cookie.in_use = false;
        }

        // Decrement volume cookie count.
        for vol in &mut self.volumes {
            if vol.in_use && vol.id == volume_id {
                vol.cookie_count = vol.cookie_count.saturating_sub(1);
                break;
            }
        }

        self.stats.cookies_active = self.stats.cookies_active.saturating_sub(1);
        Ok(())
    }

    /// Invalidate a cookie, marking its cached data as stale.
    pub fn invalidate_cookie(&mut self, cookie_id: u64, new_size: u64) -> Result<()> {
        let cookie = self.find_cookie_mut(cookie_id)?;
        if cookie.state != CookieState::Active {
            return Err(Error::InvalidArgument);
        }
        cookie.state = CookieState::Invalidating;
        cookie.data_size = new_size;
        cookie.cached_pages = 0;
        cookie.inline_page_count = 0;
        self.stats.invalidations += 1;
        Ok(())
    }

    /// Resize a cookie's cached data.
    pub fn resize_cookie(&mut self, cookie_id: u64, new_size: u64) -> Result<()> {
        let cookie = self.find_cookie_mut(cookie_id)?;
        if !cookie.is_active() {
            return Err(Error::InvalidArgument);
        }
        cookie.data_size = new_size;
        Ok(())
    }

    /// Update cookie flags.
    pub fn set_cookie_flags(&mut self, cookie_id: u64, flags: CookieFlags) -> Result<()> {
        let cookie = self.find_cookie_mut(cookie_id)?;
        cookie.flags = flags;
        Ok(())
    }

    /// Get a reference to a cookie's current state.
    pub fn cookie_state(&self, cookie_id: u64) -> Result<CookieState> {
        let cookie = self
            .cookies
            .iter()
            .find(|c| c.in_use && c.id == cookie_id)
            .ok_or(Error::NotFound)?;
        Ok(cookie.state)
    }

    /// Record that a page has been cached for a cookie.
    pub fn cookie_mark_page_cached(&mut self, cookie_id: u64, page_index: u64) -> Result<()> {
        let cookie = self.find_cookie_mut(cookie_id)?;
        if !cookie.is_active() {
            return Err(Error::InvalidArgument);
        }
        cookie.cached_pages += 1;
        if cookie.inline_page_count < MAX_INLINE_PAGES {
            cookie.inline_pages[cookie.inline_page_count] = page_index;
            cookie.inline_page_count += 1;
        }
        Ok(())
    }

    // ── I/O operations ───────────────────────────────────────────────────

    /// Submit a read request to fetch data from the cache backend.
    pub fn submit_read(&mut self, cookie_id: u64, offset: u64, length: u64) -> Result<usize> {
        let _cookie = self
            .cookies
            .iter()
            .find(|c| c.in_use && c.id == cookie_id)
            .ok_or(Error::NotFound)?;

        let slot = self
            .pending_io
            .iter_mut()
            .find(|io| !io.in_use)
            .ok_or(Error::Busy)?;

        slot.cookie_id = cookie_id;
        slot.op_type = IoOpType::Read;
        slot.state = IoOpState::Pending;
        slot.offset = offset;
        slot.length = length;
        slot.in_use = true;

        self.stats.hits += 1;
        Ok(length as usize)
    }

    /// Submit a write request to store data in the cache backend.
    pub fn submit_write(&mut self, cookie_id: u64, offset: u64, length: u64) -> Result<usize> {
        let _cookie = self
            .cookies
            .iter()
            .find(|c| c.in_use && c.id == cookie_id)
            .ok_or(Error::NotFound)?;

        let slot = self
            .pending_io
            .iter_mut()
            .find(|io| !io.in_use)
            .ok_or(Error::Busy)?;

        slot.cookie_id = cookie_id;
        slot.op_type = IoOpType::Write;
        slot.state = IoOpState::Pending;
        slot.offset = offset;
        slot.length = length;
        slot.in_use = true;

        self.stats.bytes_written += length;
        Ok(length as usize)
    }

    /// Process pending I/O operations (simulate backend completion).
    ///
    /// In a production kernel this would be driven by backend callbacks.
    /// Here we mark all pending operations as complete.
    pub fn process_pending_io(&mut self) -> u32 {
        let mut completed = 0u32;
        for io in &mut self.pending_io {
            if io.in_use && io.state == IoOpState::Pending {
                io.state = IoOpState::InProgress;
            }
            if io.in_use && io.state == IoOpState::InProgress {
                io.state = IoOpState::Complete;
                if io.op_type == IoOpType::Read {
                    self.stats.bytes_read += io.length;
                }
                io.in_use = false;
                completed += 1;
            }
        }
        completed
    }

    /// Cancel all pending I/O for a given cookie.
    pub fn cancel_io(&mut self, cookie_id: u64) -> u32 {
        let mut cancelled = 0u32;
        for io in &mut self.pending_io {
            if io.in_use && io.cookie_id == cookie_id {
                io.state = IoOpState::Failed;
                io.in_use = false;
                cancelled += 1;
            }
        }
        cancelled
    }

    // ── Backend management ───────────────────────────────────────────────

    /// Register a cache backend.
    ///
    /// Returns the backend index for use when acquiring volumes.
    pub fn register_backend(&mut self, name: &str, capacity: u64) -> Result<u32> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > 32 {
            return Err(Error::InvalidArgument);
        }

        let (idx, slot) = self
            .backends
            .iter_mut()
            .enumerate()
            .find(|(_, b)| !b.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.name[..name_bytes.len()].copy_from_slice(name_bytes);
        slot.name_len = name_bytes.len();
        slot.capacity = capacity;
        slot.in_use = true;

        Ok(idx as u32)
    }

    /// Unregister a cache backend.
    pub fn unregister_backend(&mut self, backend_id: u32) -> Result<()> {
        let idx = backend_id as usize;
        if idx >= MAX_BACKENDS || !self.backends[idx].in_use {
            return Err(Error::NotFound);
        }

        // Check if any volumes reference this backend.
        let in_use = self
            .volumes
            .iter()
            .any(|v| v.in_use && v.backend_id == backend_id);
        if in_use {
            return Err(Error::Busy);
        }

        self.backends[idx].in_use = false;
        Ok(())
    }

    /// Return the name of a registered backend.
    pub fn backend_name(&self, backend_id: u32) -> Result<&str> {
        let idx = backend_id as usize;
        if idx >= MAX_BACKENDS || !self.backends[idx].in_use {
            return Err(Error::NotFound);
        }
        let entry = &self.backends[idx];
        let name_bytes = &entry.name[..entry.name_len];
        // SAFETY: Backend names are set from &str, so they are valid UTF-8.
        Ok(core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?)
    }

    // ── Statistics ───────────────────────────────────────────────────────

    /// Return current fscache statistics.
    pub fn stats(&self) -> FsCacheStats {
        self.stats
    }

    /// Reset cumulative statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats.hits = 0;
        self.stats.misses = 0;
        self.stats.bytes_read = 0;
        self.stats.bytes_written = 0;
        self.stats.invalidations = 0;
        self.stats.io_errors = 0;
    }

    /// Return the number of active cookies.
    pub fn active_cookie_count(&self) -> u32 {
        self.stats.cookies_active
    }

    /// Return the number of active volumes.
    pub fn active_volume_count(&self) -> u32 {
        self.stats.volumes_active
    }

    // ── Procfs-style information ─────────────────────────────────────────

    /// Format a human-readable status summary (for /proc/fs/fscache/stats).
    pub fn format_stats(&self, buf: &mut String) {
        use core::fmt::Write;
        let _ = write!(buf, "fscache statistics\n");
        let _ = write!(
            buf,
            "Cookies: crt={} act={}\n",
            self.stats.cookies_created, self.stats.cookies_active
        );
        let _ = write!(buf, "Volumes: act={}\n", self.stats.volumes_active);
        let _ = write!(buf, "Hits: {}\n", self.stats.hits);
        let _ = write!(buf, "Misses: {}\n", self.stats.misses);
        let _ = write!(buf, "Reads: {} bytes\n", self.stats.bytes_read);
        let _ = write!(buf, "Writes: {} bytes\n", self.stats.bytes_written);
        let _ = write!(buf, "Invalidations: {}\n", self.stats.invalidations);
        let _ = write!(buf, "IO Errors: {}\n", self.stats.io_errors);
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Find a mutable reference to an in-use cookie by ID.
    fn find_cookie_mut(&mut self, cookie_id: u64) -> Result<&mut Cookie> {
        self.cookies
            .iter_mut()
            .find(|c| c.in_use && c.id == cookie_id)
            .ok_or(Error::NotFound)
    }
}

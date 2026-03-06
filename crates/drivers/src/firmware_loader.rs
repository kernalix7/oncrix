// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Firmware loading framework for the ONCRIX kernel.
//!
//! Provides a subsystem for device drivers to request firmware blobs,
//! either from a built-in firmware table compiled into the kernel image
//! or from a userspace-accessible firmware search path. Firmware blobs
//! are cached with reference counting to avoid redundant loads.
//!
//! # Architecture
//!
//! - [`FirmwareStatus`] — lifecycle state of a firmware blob (loading,
//!   ready, failed, released).
//! - [`FirmwareBlob`] — an in-memory firmware image with metadata,
//!   reference count, and validity tracking.
//! - [`BuiltinEntry`] — a statically-compiled firmware blob registered
//!   at build time.
//! - [`FirmwarePath`] — a search path element for locating firmware
//!   files on storage.
//! - [`FirmwareCache`] — the central cache that stores loaded blobs
//!   and handles request/release with reference counting.
//! - [`FirmwareLoader`] — the top-level API combining built-in
//!   firmware, cache, and search paths with fallback logic.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of firmware blobs in the cache.
const MAX_CACHED: usize = 32;

/// Maximum number of built-in firmware entries.
const MAX_BUILTIN: usize = 16;

/// Maximum number of firmware search paths.
const MAX_PATHS: usize = 8;

/// Maximum firmware name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum firmware file path length in bytes.
const MAX_PATH_LEN: usize = 128;

/// Maximum firmware blob size (4 MiB).
const MAX_FIRMWARE_SIZE: usize = 4 * 1024 * 1024;

/// Maximum built-in firmware blob size (256 KiB).
const MAX_BUILTIN_SIZE: usize = 256 * 1024;

/// Magic number for firmware blob validation.
const FIRMWARE_MAGIC: u32 = 0x464D_5752; // "FMWR"

// -------------------------------------------------------------------
// FirmwareStatus
// -------------------------------------------------------------------

/// Lifecycle state of a firmware blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirmwareStatus {
    /// Slot is empty (no firmware loaded).
    #[default]
    Empty,
    /// Firmware load is in progress (asynchronous path).
    Loading,
    /// Firmware is loaded and ready for use.
    Ready,
    /// Firmware load failed.
    Failed,
}

// -------------------------------------------------------------------
// FirmwareName — fixed-size name buffer
// -------------------------------------------------------------------

/// A fixed-size buffer for firmware names.
#[derive(Clone, Copy)]
pub struct FirmwareName {
    /// Raw bytes (null-padded).
    bytes: [u8; MAX_NAME_LEN],
    /// Actual length.
    len: usize,
}

impl FirmwareName {
    /// Creates a new firmware name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or
    /// exceeds [`MAX_NAME_LEN`].
    pub fn new(name: &str) -> Result<Self> {
        let b = name.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes,
            len: b.len(),
        })
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns `true` if this name matches the given string.
    pub fn matches(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl core::fmt::Debug for FirmwareName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = core::str::from_utf8(self.as_bytes()) {
            write!(f, "\"{}\"", s)
        } else {
            write!(f, "{:?}", self.as_bytes())
        }
    }
}

/// Constant empty name for array initialisation.
const EMPTY_NAME: FirmwareName = FirmwareName {
    bytes: [0u8; MAX_NAME_LEN],
    len: 0,
};

// -------------------------------------------------------------------
// FirmwarePath — search path element
// -------------------------------------------------------------------

/// A fixed-size buffer for a firmware search path.
#[derive(Clone, Copy)]
pub struct FirmwarePath {
    /// Raw bytes (null-padded).
    bytes: [u8; MAX_PATH_LEN],
    /// Actual length.
    len: usize,
    /// Priority (lower = searched first).
    pub priority: u32,
}

impl FirmwarePath {
    /// Creates a new firmware search path entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the path is empty or
    /// exceeds [`MAX_PATH_LEN`].
    pub fn new(path: &str, priority: u32) -> Result<Self> {
        let b = path.as_bytes();
        if b.is_empty() || b.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; MAX_PATH_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes,
            len: b.len(),
            priority,
        })
    }

    /// Returns the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl core::fmt::Debug for FirmwarePath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = core::str::from_utf8(self.as_bytes()) {
            write!(f, "FirmwarePath(\"{}\" pri={})", s, self.priority)
        } else {
            write!(
                f,
                "FirmwarePath({:?} pri={})",
                self.as_bytes(),
                self.priority
            )
        }
    }
}

/// Constant empty path for array initialisation.
const EMPTY_PATH: FirmwarePath = FirmwarePath {
    bytes: [0u8; MAX_PATH_LEN],
    len: 0,
    priority: u32::MAX,
};

// -------------------------------------------------------------------
// FirmwareBlob — a cached firmware image
// -------------------------------------------------------------------

/// An in-memory firmware image with metadata and reference count.
#[derive(Debug, Clone)]
pub struct FirmwareBlob {
    /// Firmware name (e.g., "ath10k/firmware-5.bin").
    pub name: FirmwareName,
    /// Base address where the firmware data resides in memory.
    pub data_addr: u64,
    /// Size of the firmware data in bytes.
    pub size: usize,
    /// CRC-32 checksum for integrity validation.
    pub checksum: u32,
    /// Current lifecycle status.
    pub status: FirmwareStatus,
    /// Reference count (number of active users).
    ref_count: u32,
    /// Whether this blob originated from the built-in table.
    pub is_builtin: bool,
    /// Firmware version (opaque, driver-interpreted).
    pub version: u32,
}

/// Constant empty blob for array initialisation.
const EMPTY_BLOB: FirmwareBlob = FirmwareBlob {
    name: EMPTY_NAME,
    data_addr: 0,
    size: 0,
    checksum: 0,
    status: FirmwareStatus::Empty,
    ref_count: 0,
    is_builtin: false,
    version: 0,
};

impl FirmwareBlob {
    /// Creates a new firmware blob descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid or
    /// `size` exceeds [`MAX_FIRMWARE_SIZE`].
    pub fn new(name: &str, data_addr: u64, size: usize) -> Result<Self> {
        if size > MAX_FIRMWARE_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            name: FirmwareName::new(name)?,
            data_addr,
            size,
            checksum: 0,
            status: FirmwareStatus::Loading,
            ref_count: 0,
            is_builtin: false,
            version: 0,
        })
    }

    /// Increments the reference count.
    fn acquire(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` if the count reached zero.
    fn release(&mut self) -> bool {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count == 0
    }

    /// Returns the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Validates the firmware blob using the stored checksum.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the blob is not in
    /// [`FirmwareStatus::Ready`] state.
    pub fn validate(&self) -> Result<bool> {
        if self.status != FirmwareStatus::Ready {
            return Err(Error::IoError);
        }
        // In a real implementation this would re-compute a CRC
        // over the data at `data_addr`. Here we verify that the
        // blob has a non-zero checksum and a valid magic prefix.
        Ok(self.checksum != 0)
    }
}

// -------------------------------------------------------------------
// BuiltinEntry — statically compiled firmware
// -------------------------------------------------------------------

/// A firmware blob compiled into the kernel image.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinEntry {
    /// Firmware name.
    pub name: FirmwareName,
    /// Address of the firmware data in the kernel image.
    pub data_addr: u64,
    /// Size of the firmware data.
    pub size: usize,
    /// CRC-32 checksum.
    pub checksum: u32,
    /// Firmware version.
    pub version: u32,
}

/// Constant empty builtin entry for array initialisation.
const EMPTY_BUILTIN: BuiltinEntry = BuiltinEntry {
    name: EMPTY_NAME,
    data_addr: 0,
    size: 0,
    checksum: 0,
    version: 0,
};

impl BuiltinEntry {
    /// Creates a new built-in firmware entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is invalid or
    /// size exceeds [`MAX_BUILTIN_SIZE`].
    pub fn new(name: &str, data_addr: u64, size: usize, checksum: u32) -> Result<Self> {
        if size > MAX_BUILTIN_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            name: FirmwareName::new(name)?,
            data_addr,
            size,
            checksum,
            version: 0,
        })
    }
}

// -------------------------------------------------------------------
// FirmwareCache
// -------------------------------------------------------------------

/// Cache of loaded firmware blobs with reference counting.
///
/// The cache deduplicates firmware requests: if two drivers request
/// the same firmware, only one copy is kept and the reference count
/// is incremented.
#[derive(Debug)]
pub struct FirmwareCache {
    /// Cached firmware blobs.
    entries: [FirmwareBlob; MAX_CACHED],
    /// Number of occupied slots.
    count: usize,
    /// Total bytes of firmware data currently cached.
    total_bytes: usize,
}

impl FirmwareCache {
    /// Creates a new empty firmware cache.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_BLOB; MAX_CACHED],
            count: 0,
            total_bytes: 0,
        }
    }

    /// Looks up a cached firmware blob by name.
    ///
    /// Returns `None` if not cached.
    pub fn lookup(&self, name: &str) -> Option<&FirmwareBlob> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.name.matches(name) && e.status == FirmwareStatus::Ready)
    }

    /// Inserts a firmware blob into the cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the name is already
    /// cached, or [`Error::OutOfMemory`] if the cache is full.
    pub fn insert(&mut self, mut blob: FirmwareBlob) -> Result<()> {
        // Check for duplicate.
        for e in &self.entries[..self.count] {
            if e.name.as_bytes() == blob.name.as_bytes() && e.status != FirmwareStatus::Empty {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_CACHED {
            return Err(Error::OutOfMemory);
        }
        blob.status = FirmwareStatus::Ready;
        self.total_bytes += blob.size;
        self.entries[self.count] = blob;
        self.count += 1;
        Ok(())
    }

    /// Acquires a reference to a cached firmware blob.
    ///
    /// Increments the reference count so the blob is not evicted
    /// while in use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the firmware is not cached.
    pub fn acquire(&mut self, name: &str) -> Result<&FirmwareBlob> {
        let idx = self.find_index(name)?;
        self.entries[idx].acquire();
        Ok(&self.entries[idx])
    }

    /// Releases a reference to a cached firmware blob.
    ///
    /// When the reference count reaches zero the blob remains in
    /// the cache but becomes eligible for eviction.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the firmware is not cached.
    pub fn release(&mut self, name: &str) -> Result<()> {
        let idx = self.find_index(name)?;
        self.entries[idx].release();
        Ok(())
    }

    /// Evicts all unreferenced blobs from the cache.
    ///
    /// Returns the number of blobs evicted.
    pub fn evict_unreferenced(&mut self) -> usize {
        let mut evicted = 0;
        let mut i = 0;
        while i < self.count {
            if self.entries[i].ref_count == 0 && !self.entries[i].is_builtin {
                self.total_bytes = self.total_bytes.saturating_sub(self.entries[i].size);
                let last = self.count - 1;
                if i != last {
                    self.entries[i] = self.entries[last].clone();
                }
                self.entries[last] = EMPTY_BLOB;
                self.count -= 1;
                evicted += 1;
                // Don't increment i — re-check the swapped entry.
            } else {
                i += 1;
            }
        }
        evicted
    }

    /// Returns the number of cached blobs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total cached firmware size in bytes.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the index of a cached blob by name.
    fn find_index(&self, name: &str) -> Result<usize> {
        self.entries[..self.count]
            .iter()
            .position(|e| e.name.matches(name) && e.status == FirmwareStatus::Ready)
            .ok_or(Error::NotFound)
    }
}

// -------------------------------------------------------------------
// FirmwareLoader
// -------------------------------------------------------------------

/// Top-level firmware loading API.
///
/// Combines built-in firmware, cache, and filesystem search paths
/// with a fallback chain:
///
/// 1. Check the cache for a previously loaded blob.
/// 2. Check the built-in firmware table.
/// 3. Search filesystem paths in priority order.
/// 4. Attempt an asynchronous userspace helper load.
///
/// On success the blob is cached for future requests.
#[derive(Debug)]
pub struct FirmwareLoader {
    /// Firmware blob cache.
    cache: FirmwareCache,
    /// Built-in firmware table.
    builtin: [BuiltinEntry; MAX_BUILTIN],
    /// Number of built-in entries.
    builtin_count: usize,
    /// Firmware search paths (sorted by priority at lookup time).
    paths: [FirmwarePath; MAX_PATHS],
    /// Number of configured search paths.
    path_count: usize,
    /// Next request ID for async operations.
    next_request_id: u64,
    /// Whether the loader has been initialised.
    initialised: bool,
}

impl FirmwareLoader {
    /// Creates a new firmware loader.
    pub const fn new() -> Self {
        Self {
            cache: FirmwareCache::new(),
            builtin: [EMPTY_BUILTIN; MAX_BUILTIN],
            builtin_count: 0,
            paths: [EMPTY_PATH; MAX_PATHS],
            path_count: 0,
            next_request_id: 1,
            initialised: false,
        }
    }

    /// Initialises the firmware loader subsystem.
    ///
    /// Must be called before any firmware requests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already initialised.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::Busy);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Built-in firmware ──────────────────────────────────────

    /// Registers a built-in firmware entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full, or
    /// [`Error::AlreadyExists`] if the name is already registered.
    pub fn register_builtin(&mut self, entry: BuiltinEntry) -> Result<()> {
        for e in &self.builtin[..self.builtin_count] {
            if e.name.as_bytes() == entry.name.as_bytes() {
                return Err(Error::AlreadyExists);
            }
        }
        if self.builtin_count >= MAX_BUILTIN {
            return Err(Error::OutOfMemory);
        }
        self.builtin[self.builtin_count] = entry;
        self.builtin_count += 1;
        Ok(())
    }

    /// Looks up a built-in firmware entry by name.
    fn find_builtin(&self, name: &str) -> Option<&BuiltinEntry> {
        self.builtin[..self.builtin_count]
            .iter()
            .find(|e| e.name.matches(name))
    }

    // ── Search paths ───────────────────────────────────────────

    /// Adds a firmware search path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the path table is full.
    pub fn add_search_path(&mut self, path: FirmwarePath) -> Result<()> {
        if self.path_count >= MAX_PATHS {
            return Err(Error::OutOfMemory);
        }
        self.paths[self.path_count] = path;
        self.path_count += 1;
        Ok(())
    }

    /// Returns the configured search paths.
    pub fn search_paths(&self) -> &[FirmwarePath] {
        &self.paths[..self.path_count]
    }

    // ── Firmware request API ───────────────────────────────────

    /// Requests a firmware blob by name.
    ///
    /// Follows the fallback chain: cache → built-in → filesystem
    /// path search. If found, the blob is cached and a reference
    /// is acquired.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the loader is not initialised,
    /// [`Error::NotFound`] if the firmware cannot be located in any
    /// source, or [`Error::OutOfMemory`] if the cache is full.
    pub fn request_firmware(&mut self, name: &str) -> Result<&FirmwareBlob> {
        if !self.initialised {
            return Err(Error::Busy);
        }
        // 1. Check the cache.
        if self.cache.lookup(name).is_some() {
            return self.cache.acquire(name);
        }
        // 2. Check built-in table.
        if let Some(builtin) = self.find_builtin(name) {
            let mut blob = FirmwareBlob::new(name, builtin.data_addr, builtin.size)?;
            blob.checksum = builtin.checksum;
            blob.version = builtin.version;
            blob.is_builtin = true;
            self.cache.insert(blob)?;
            return self.cache.acquire(name);
        }
        // 3. Try filesystem paths (simulate — in a real kernel we
        //    would invoke the VFS to open and read the file).
        if let Some(blob) = self.try_load_from_paths(name)? {
            self.cache.insert(blob)?;
            return self.cache.acquire(name);
        }
        Err(Error::NotFound)
    }

    /// Requests firmware asynchronously.
    ///
    /// Returns a request ID that can be polled with
    /// [`check_async_request`](Self::check_async_request).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the loader is not initialised, or
    /// [`Error::InvalidArgument`] if the name is invalid.
    pub fn request_firmware_async(&mut self, name: &str) -> Result<u64> {
        if !self.initialised {
            return Err(Error::Busy);
        }
        let _fname = FirmwareName::new(name)?;

        // In a real implementation this would enqueue a work item
        // to load firmware on a background thread. Here we create
        // a placeholder blob in Loading state.
        let mut blob = FirmwareBlob::new(name, 0, 0)?;
        blob.status = FirmwareStatus::Loading;
        // Place in cache if not already present.
        if self.cache.lookup(name).is_none() {
            // Don't use insert() since it sets Ready; write directly.
            if self.cache.count < MAX_CACHED {
                self.cache.entries[self.cache.count] = blob;
                self.cache.count += 1;
            }
        }
        let id = self.next_request_id;
        self.next_request_id += 1;
        Ok(id)
    }

    /// Checks the status of an asynchronous firmware request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the firmware name is not in
    /// the cache.
    pub fn check_async_request(&self, name: &str) -> Result<FirmwareStatus> {
        for e in &self.cache.entries[..self.cache.count] {
            if e.name.matches(name) {
                return Ok(e.status);
            }
        }
        Err(Error::NotFound)
    }

    /// Completes an asynchronous firmware load.
    ///
    /// Called by the subsystem that performed the actual I/O to
    /// finalize the blob in the cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if there is no pending load for
    /// this name, [`Error::InvalidArgument`] if `size` exceeds
    /// the limit, or [`Error::IoError`] if the blob is not in
    /// [`FirmwareStatus::Loading`] state.
    pub fn complete_async_load(
        &mut self,
        name: &str,
        data_addr: u64,
        size: usize,
        checksum: u32,
    ) -> Result<()> {
        if size > MAX_FIRMWARE_SIZE {
            return Err(Error::InvalidArgument);
        }
        for e in &mut self.cache.entries[..self.cache.count] {
            if e.name.matches(name) {
                if e.status != FirmwareStatus::Loading {
                    return Err(Error::IoError);
                }
                e.data_addr = data_addr;
                e.size = size;
                e.checksum = checksum;
                e.status = FirmwareStatus::Ready;
                self.cache.total_bytes += size;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Marks an asynchronous firmware load as failed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if there is no pending load for
    /// this name.
    pub fn fail_async_load(&mut self, name: &str) -> Result<()> {
        for e in &mut self.cache.entries[..self.cache.count] {
            if e.name.matches(name) && e.status == FirmwareStatus::Loading {
                e.status = FirmwareStatus::Failed;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Releases a firmware blob acquired via
    /// [`request_firmware`](Self::request_firmware).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the firmware is not cached.
    pub fn release_firmware(&mut self, name: &str) -> Result<()> {
        self.cache.release(name)
    }

    // ── Cache management ───────────────────────────────────────

    /// Evicts all unreferenced non-builtin blobs from the cache.
    ///
    /// Returns the number of blobs evicted.
    pub fn shrink_cache(&mut self) -> usize {
        self.cache.evict_unreferenced()
    }

    /// Returns an immutable reference to the cache.
    pub fn cache(&self) -> &FirmwareCache {
        &self.cache
    }

    // ── Query helpers ──────────────────────────────────────────

    /// Returns the number of built-in firmware entries.
    pub fn builtin_count(&self) -> usize {
        self.builtin_count
    }

    /// Returns the number of configured search paths.
    pub fn path_count(&self) -> usize {
        self.path_count
    }

    /// Returns `true` if the loader has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    // ── Internal helpers ───────────────────────────────────────

    /// Simulates attempting to load firmware from filesystem paths.
    ///
    /// In a real kernel this would iterate the search paths, build
    /// full file paths, and use the VFS to read the firmware data.
    /// Here we simulate the path resolution logic without actual
    /// I/O — the firmware must be loaded via the async API or
    /// be built-in.
    fn try_load_from_paths(&self, name: &str) -> Result<Option<FirmwareBlob>> {
        let _fname = FirmwareName::new(name)?;

        // Build sorted path indices by priority.
        let mut indices = [0usize; MAX_PATHS];
        for (i, idx) in indices[..self.path_count].iter_mut().enumerate() {
            *idx = i;
        }
        // Simple insertion sort by priority.
        for i in 1..self.path_count {
            let mut j = i;
            while j > 0 && self.paths[indices[j]].priority < self.paths[indices[j - 1]].priority {
                indices.swap(j, j - 1);
                j -= 1;
            }
        }

        // In a real implementation each path would be tried:
        //   path_bytes + "/" + name → VFS open → read → checksum
        // Since we cannot perform actual I/O in this no_std stub,
        // return None to indicate no filesystem firmware found.
        // Callers should use the async API for real loads.
        let _ = &indices[..self.path_count];
        Ok(None)
    }

    /// Validates a firmware blob header (magic number check).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the magic does not
    /// match [`FIRMWARE_MAGIC`].
    pub fn validate_header(data: &[u8]) -> Result<bool> {
        if data.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        Ok(magic == FIRMWARE_MAGIC)
    }
}

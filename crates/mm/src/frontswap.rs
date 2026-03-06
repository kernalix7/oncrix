// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Frontswap — transcendent memory backend for swap pages.
//!
//! Frontswap provides an indirection layer between the swap subsystem
//! and a transcendent memory backend (e.g., tmem, Xen, KVM). When
//! a page is swapped out, frontswap attempts to store it in the
//! backend; if the backend accepts the page, the swap device write
//! is bypassed entirely. On swap-in, frontswap is checked first.
//!
//! # Architecture
//!
//! - [`FrontswapOps`] — trait defining backend operations
//!   (init, store, load, invalidate_page, invalidate_area)
//! - [`FrontswapEntry`] — per-page stored data with metadata
//! - [`SwapTypeInfo`] — per-swap-type tracking and state
//! - [`FrontswapStats`] — aggregate statistics
//! - [`FrontswapManager`] — top-level manager dispatching to backend
//!
//! # Fast Path
//!
//! The store/load fast path checks registration and swap-type validity
//! before invoking the backend, minimising overhead when frontswap is
//! disabled or the swap type has no backend.
//!
//! Reference: Linux `mm/frontswap.c`,
//! `include/linux/frontswap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of swap types (devices/files) tracked.
const MAX_SWAP_TYPES: usize = 8;

/// Maximum number of frontswap entries across all swap types.
const MAX_ENTRIES: usize = 4096;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of registered backends.
const MAX_BACKENDS: usize = 4;

// -------------------------------------------------------------------
// FrontswapOps
// -------------------------------------------------------------------

/// Trait defining the operations a frontswap backend must provide.
///
/// Each method corresponds to a lifecycle event in the swap path.
/// Backends that do not support a particular operation should return
/// `Err(Error::NotImplemented)`.
pub trait FrontswapOps {
    /// Initialise the backend for the given swap type.
    ///
    /// Called when a new swap area is activated. Returns `Ok(())`
    /// if the backend accepts pages for this swap type.
    fn init(&mut self, swap_type: usize) -> Result<()>;

    /// Store a page's data in the backend.
    ///
    /// `swap_type` and `offset` together identify the swap slot.
    /// `data` contains the page contents (exactly [`PAGE_SIZE`] bytes
    /// when called from the swap path, but the slice length is
    /// authoritative).
    ///
    /// Returns `Ok(())` on success or `Err(OutOfMemory)` if the
    /// backend has no capacity.
    fn store(&mut self, swap_type: usize, offset: u64, data: &[u8]) -> Result<()>;

    /// Load a previously stored page from the backend.
    ///
    /// On success, fills `buf` with the page data and returns
    /// `Ok(())`. Returns `Err(NotFound)` if the page is not in the
    /// backend.
    fn load(&mut self, swap_type: usize, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Invalidate a single page in the backend.
    ///
    /// Called when a swap slot is freed. The backend should discard
    /// any stored data for this slot.
    fn invalidate_page(&mut self, swap_type: usize, offset: u64) -> Result<()>;

    /// Invalidate all pages belonging to a swap type.
    ///
    /// Called when a swap area is deactivated.
    fn invalidate_area(&mut self, swap_type: usize) -> Result<()>;
}

// -------------------------------------------------------------------
// SwapTypeState
// -------------------------------------------------------------------

/// Lifecycle state of a swap type in frontswap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwapTypeState {
    /// Swap type is not registered with frontswap.
    #[default]
    Inactive,
    /// Swap type is registered and accepting pages.
    Active,
    /// Swap type is being invalidated (draining).
    Draining,
}

// -------------------------------------------------------------------
// SwapTypeInfo
// -------------------------------------------------------------------

/// Per-swap-type tracking information.
///
/// Maintains the state and statistics for a single swap area
/// registered with frontswap.
#[derive(Debug, Clone, Copy)]
pub struct SwapTypeInfo {
    /// Current lifecycle state.
    pub state: SwapTypeState,
    /// Number of pages currently stored in the backend.
    pub stored_pages: u64,
    /// Total store requests for this swap type.
    pub store_requests: u64,
    /// Successful store operations.
    pub store_successes: u64,
    /// Total load requests.
    pub load_requests: u64,
    /// Successful load operations (backend hits).
    pub load_successes: u64,
    /// Total invalidate_page calls.
    pub invalidations: u64,
    /// Backend index handling this swap type (or `usize::MAX` if none).
    pub backend_id: usize,
}

impl SwapTypeInfo {
    /// Create a new inactive swap type info.
    const fn new() -> Self {
        Self {
            state: SwapTypeState::Inactive,
            stored_pages: 0,
            store_requests: 0,
            store_successes: 0,
            load_requests: 0,
            load_successes: 0,
            invalidations: 0,
            backend_id: usize::MAX,
        }
    }
}

impl Default for SwapTypeInfo {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FrontswapEntry
// -------------------------------------------------------------------

/// A single page stored via frontswap.
///
/// Contains the page data buffer and metadata linking it to a
/// specific swap slot.
#[derive(Clone, Copy)]
pub struct FrontswapEntry {
    /// Swap type this entry belongs to.
    swap_type: usize,
    /// Slot offset within the swap type.
    offset: u64,
    /// Stored page data.
    data: [u8; PAGE_SIZE],
    /// Number of valid bytes in `data`.
    data_len: usize,
    /// Whether this slot is occupied.
    active: bool,
    /// Monotonic timestamp for LRU ordering.
    timestamp: u64,
}

impl FrontswapEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            swap_type: 0,
            offset: 0,
            data: [0u8; PAGE_SIZE],
            data_len: 0,
            active: false,
            timestamp: 0,
        }
    }
}

impl Default for FrontswapEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// BackendRegistration
// -------------------------------------------------------------------

/// Registration record for a frontswap backend.
#[derive(Debug, Clone, Copy)]
pub struct BackendRegistration {
    /// Human-readable backend name (truncated to 32 bytes).
    name: [u8; 32],
    /// Length of the name.
    name_len: usize,
    /// Whether this registration slot is active.
    active: bool,
}

impl BackendRegistration {
    /// Create an empty registration slot.
    const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            active: false,
        }
    }

    /// Return the backend name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

impl Default for BackendRegistration {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FrontswapStats
// -------------------------------------------------------------------

/// Aggregate frontswap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrontswapStats {
    /// Total pages currently stored across all swap types.
    pub total_stored: u64,
    /// Total store requests across all swap types.
    pub total_store_requests: u64,
    /// Total successful stores.
    pub total_store_successes: u64,
    /// Total load requests.
    pub total_load_requests: u64,
    /// Total successful loads (backend hits).
    pub total_load_successes: u64,
    /// Total page invalidations.
    pub total_invalidations: u64,
    /// Total area invalidations.
    pub total_area_invalidations: u64,
    /// Number of registered backends.
    pub registered_backends: u64,
    /// Number of active swap types.
    pub active_swap_types: u64,
    /// Store failures due to backend rejection.
    pub store_failures: u64,
}

// -------------------------------------------------------------------
// InMemoryBackend
// -------------------------------------------------------------------

/// Simple in-memory frontswap backend for testing and default use.
///
/// Stores page data in a fixed-size array of [`FrontswapEntry`]
/// slots. Uses linear search for lookup and first-fit for allocation.
pub struct InMemoryBackend {
    /// Stored entries.
    entries: [FrontswapEntry; MAX_ENTRIES],
    /// Number of occupied entries.
    count: usize,
    /// Per-swap-type initialisation flags.
    initialised: [bool; MAX_SWAP_TYPES],
    /// Monotonic clock for LRU ordering.
    clock: u64,
}

impl InMemoryBackend {
    /// Create a new in-memory backend with empty storage.
    pub const fn new() -> Self {
        Self {
            entries: [const { FrontswapEntry::empty() }; MAX_ENTRIES],
            count: 0,
            initialised: [false; MAX_SWAP_TYPES],
            clock: 0,
        }
    }

    /// Find the index of an entry by swap_type and offset.
    fn find_entry(&self, swap_type: usize, offset: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.swap_type == swap_type && e.offset == offset)
    }

    /// Find the first free slot.
    fn find_free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.active)
    }

    /// Find the oldest entry for eviction.
    fn find_oldest(&self) -> Option<usize> {
        let mut oldest_idx = None;
        let mut oldest_ts = u64::MAX;
        for (i, e) in self.entries.iter().enumerate() {
            if e.active && e.timestamp < oldest_ts {
                oldest_ts = e.timestamp;
                oldest_idx = Some(i);
            }
        }
        oldest_idx
    }

    /// Advance the monotonic clock and return the new value.
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontswapOps for InMemoryBackend {
    fn init(&mut self, swap_type: usize) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        self.initialised[swap_type] = true;
        Ok(())
    }

    fn store(&mut self, swap_type: usize, offset: u64, data: &[u8]) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if !self.initialised[swap_type] {
            return Err(Error::InvalidArgument);
        }
        if data.len() > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        let ts = self.tick();

        // Update existing entry if present.
        if let Some(idx) = self.find_entry(swap_type, offset) {
            let entry = &mut self.entries[idx];
            entry.data[..data.len()].copy_from_slice(data);
            entry.data_len = data.len();
            entry.timestamp = ts;
            return Ok(());
        }

        // Allocate a new slot, evicting if necessary.
        let idx = match self.find_free_slot() {
            Some(i) => i,
            None => {
                // Evict the oldest entry.
                let evict = self.find_oldest().ok_or(Error::OutOfMemory)?;
                self.entries[evict].active = false;
                self.count = self.count.saturating_sub(1);
                evict
            }
        };

        let entry = &mut self.entries[idx];
        entry.swap_type = swap_type;
        entry.offset = offset;
        entry.data[..data.len()].copy_from_slice(data);
        entry.data_len = data.len();
        entry.active = true;
        entry.timestamp = ts;
        self.count += 1;
        Ok(())
    }

    fn load(&mut self, swap_type: usize, offset: u64, buf: &mut [u8]) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_entry(swap_type, offset).ok_or(Error::NotFound)?;

        let entry = &self.entries[idx];
        let copy_len = entry.data_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&entry.data[..copy_len]);

        // Update timestamp (LRU touch).
        let ts = self.tick();
        self.entries[idx].timestamp = ts;
        Ok(())
    }

    fn invalidate_page(&mut self, swap_type: usize, offset: u64) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if let Some(idx) = self.find_entry(swap_type, offset) {
            self.entries[idx].active = false;
            self.count = self.count.saturating_sub(1);
        }
        Ok(())
    }

    fn invalidate_area(&mut self, swap_type: usize) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        for entry in &mut self.entries {
            if entry.active && entry.swap_type == swap_type {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
        self.initialised[swap_type] = false;
        Ok(())
    }
}

// -------------------------------------------------------------------
// FrontswapManager
// -------------------------------------------------------------------

/// Top-level frontswap manager.
///
/// Dispatches store/load/invalidate operations to the registered
/// in-memory backend and maintains per-swap-type tracking information
/// and aggregate statistics.
///
/// # Fast Path
///
/// Each public method first checks that the swap type is active and
/// that a backend is registered before performing any work, keeping
/// the common case (frontswap disabled) as fast as possible.
pub struct FrontswapManager {
    /// Per-swap-type tracking.
    swap_types: [SwapTypeInfo; MAX_SWAP_TYPES],
    /// Backend registrations.
    backends: [BackendRegistration; MAX_BACKENDS],
    /// Number of registered backends.
    backend_count: usize,
    /// In-memory backend instance.
    backend: InMemoryBackend,
    /// Aggregate statistics.
    stats: FrontswapStats,
    /// Whether frontswap is globally enabled.
    enabled: bool,
}

impl FrontswapManager {
    /// Create a new frontswap manager with no backends registered.
    pub const fn new() -> Self {
        Self {
            swap_types: [const { SwapTypeInfo::new() }; MAX_SWAP_TYPES],
            backends: [const { BackendRegistration::empty() }; MAX_BACKENDS],
            backend_count: 0,
            backend: InMemoryBackend::new(),
            stats: FrontswapStats {
                total_stored: 0,
                total_store_requests: 0,
                total_store_successes: 0,
                total_load_requests: 0,
                total_load_successes: 0,
                total_invalidations: 0,
                total_area_invalidations: 0,
                registered_backends: 0,
                active_swap_types: 0,
                store_failures: 0,
            },
            enabled: false,
        }
    }

    /// Register a backend by name.
    ///
    /// Returns the backend index on success. The manager is
    /// automatically enabled when the first backend registers.
    pub fn register_backend(&mut self, name: &[u8]) -> Result<usize> {
        if self.backend_count >= MAX_BACKENDS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.backend_count;
        let reg = &mut self.backends[idx];
        let copy_len = name.len().min(32);
        reg.name[..copy_len].copy_from_slice(&name[..copy_len]);
        reg.name_len = copy_len;
        reg.active = true;
        self.backend_count += 1;
        self.enabled = true;
        self.stats.registered_backends += 1;
        Ok(idx)
    }

    /// Unregister a backend by index.
    pub fn unregister_backend(&mut self, backend_id: usize) -> Result<()> {
        if backend_id >= self.backend_count {
            return Err(Error::InvalidArgument);
        }
        if !self.backends[backend_id].active {
            return Err(Error::NotFound);
        }
        self.backends[backend_id].active = false;
        self.stats.registered_backends = self.stats.registered_backends.saturating_sub(1);
        // Disable if no backends remain.
        if self.stats.registered_backends == 0 {
            self.enabled = false;
        }
        Ok(())
    }

    /// Initialise frontswap for a swap type.
    ///
    /// Called when a swap area is activated. Registers the swap type
    /// with the backend and marks it as active.
    pub fn init_swap_type(&mut self, swap_type: usize) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if self.swap_types[swap_type].state == SwapTypeState::Active {
            return Err(Error::AlreadyExists);
        }

        self.backend.init(swap_type)?;
        self.swap_types[swap_type].state = SwapTypeState::Active;
        self.swap_types[swap_type].backend_id = 0; // default backend
        self.stats.active_swap_types += 1;
        Ok(())
    }

    /// Store a page in the frontswap backend.
    ///
    /// Fast path: returns immediately if the swap type is not active.
    /// On success, the page data is stored in the backend and the
    /// swap device write can be skipped.
    pub fn store(&mut self, swap_type: usize, offset: u64, data: &[u8]) -> Result<()> {
        // Fast path check.
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if self.swap_types[swap_type].state != SwapTypeState::Active {
            return Err(Error::InvalidArgument);
        }

        self.swap_types[swap_type].store_requests += 1;
        self.stats.total_store_requests += 1;

        match self.backend.store(swap_type, offset, data) {
            Ok(()) => {
                self.swap_types[swap_type].store_successes += 1;
                self.swap_types[swap_type].stored_pages += 1;
                self.stats.total_store_successes += 1;
                self.stats.total_stored += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.store_failures += 1;
                Err(e)
            }
        }
    }

    /// Load a page from the frontswap backend.
    ///
    /// Fast path: returns `Err(NotFound)` immediately if the swap
    /// type is not active. On success, `buf` is filled with the
    /// stored page data.
    pub fn load(&mut self, swap_type: usize, offset: u64, buf: &mut [u8]) -> Result<()> {
        // Fast path check.
        if !self.enabled {
            return Err(Error::NotFound);
        }
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if self.swap_types[swap_type].state != SwapTypeState::Active {
            return Err(Error::NotFound);
        }

        self.swap_types[swap_type].load_requests += 1;
        self.stats.total_load_requests += 1;

        match self.backend.load(swap_type, offset, buf) {
            Ok(()) => {
                self.swap_types[swap_type].load_successes += 1;
                self.stats.total_load_successes += 1;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Invalidate a single page in the backend.
    ///
    /// Called when a swap slot is freed. If the page is in the
    /// backend, it is discarded.
    pub fn invalidate_page(&mut self, swap_type: usize, offset: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if self.swap_types[swap_type].state != SwapTypeState::Active {
            return Ok(());
        }

        self.backend.invalidate_page(swap_type, offset)?;
        self.swap_types[swap_type].invalidations += 1;
        self.swap_types[swap_type].stored_pages =
            self.swap_types[swap_type].stored_pages.saturating_sub(1);
        self.stats.total_invalidations += 1;
        self.stats.total_stored = self.stats.total_stored.saturating_sub(1);
        Ok(())
    }

    /// Invalidate all pages belonging to a swap type.
    ///
    /// Called when a swap area is deactivated. Drains all stored
    /// pages and marks the swap type as inactive.
    pub fn invalidate_area(&mut self, swap_type: usize) -> Result<()> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        if self.swap_types[swap_type].state == SwapTypeState::Inactive {
            return Ok(());
        }

        self.swap_types[swap_type].state = SwapTypeState::Draining;
        self.backend.invalidate_area(swap_type)?;

        let freed = self.swap_types[swap_type].stored_pages;
        self.stats.total_stored = self.stats.total_stored.saturating_sub(freed);
        self.stats.total_area_invalidations += 1;
        self.stats.active_swap_types = self.stats.active_swap_types.saturating_sub(1);

        self.swap_types[swap_type] = SwapTypeInfo::new();
        Ok(())
    }

    /// Return per-swap-type tracking information.
    pub fn swap_type_info(&self, swap_type: usize) -> Result<&SwapTypeInfo> {
        if swap_type >= MAX_SWAP_TYPES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.swap_types[swap_type])
    }

    /// Return aggregate frontswap statistics.
    pub fn stats(&self) -> &FrontswapStats {
        &self.stats
    }

    /// Whether frontswap is globally enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of registered backends.
    pub fn backend_count(&self) -> usize {
        self.backend_count
    }

    /// Return the number of active swap types.
    pub fn active_swap_types(&self) -> usize {
        self.stats.active_swap_types as usize
    }

    /// Reset all statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = FrontswapStats::default();
        // Re-derive active counts.
        let mut active = 0u64;
        for info in &self.swap_types {
            if info.state == SwapTypeState::Active {
                active += 1;
            }
        }
        self.stats.active_swap_types = active;
        self.stats.registered_backends = self.backends.iter().filter(|b| b.active).count() as u64;
    }
}

impl Default for FrontswapManager {
    fn default() -> Self {
        Self::new()
    }
}

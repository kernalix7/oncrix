// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Guaranteed allocation memory pool (mempool).
//!
//! Provides a pool of pre-allocated fixed-size elements that guarantees
//! allocation will succeed as long as the pool is not exhausted. This is
//! critical for code paths where allocation failure is not acceptable
//! (e.g., I/O completion, interrupt handlers, swap-out paths).
//!
//! Each [`Mempool`] manages up to [`MAX_ELEMENTS`] elements of a fixed
//! size, with a configurable minimum reserve (`min_nr`). The
//! [`MempoolAllocator`] holds up to [`MAX_POOLS`] named pools.
//!
//! Reference: `.kernelORG/` — `mm/mempool.c`.

use oncrix_lib::{Error, Result};

/// Maximum number of elements per mempool.
const MAX_ELEMENTS: usize = 128;

/// Maximum number of mempools in the allocator.
const MAX_POOLS: usize = 16;

/// Maximum element data size in bytes.
const ELEMENT_DATA_SIZE: usize = 256;

// ── MempoolElementState ──────────────────────────────────────────

/// State of an element within a mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MempoolElementState {
    /// Element is available for allocation.
    #[default]
    Free,
    /// Element has been allocated to a consumer.
    Allocated,
    /// Element is reserved (pre-allocated minimum guarantee).
    Reserved,
}

// ── MempoolElement ───────────────────────────────────────────────

/// A single element managed by a [`Mempool`].
#[derive(Debug, Clone, Copy)]
pub struct MempoolElement {
    /// Element data storage.
    data: [u8; ELEMENT_DATA_SIZE],
    /// Current state of the element.
    state: MempoolElementState,
    /// Owner identifier (0 when free/reserved).
    owner_id: u64,
}

impl Default for MempoolElement {
    fn default() -> Self {
        Self {
            data: [0u8; ELEMENT_DATA_SIZE],
            state: MempoolElementState::Free,
            owner_id: 0,
        }
    }
}

impl MempoolElement {
    /// Immutable access to the element's data buffer.
    pub fn data(&self) -> &[u8; ELEMENT_DATA_SIZE] {
        &self.data
    }

    /// Mutable access to the element's data buffer.
    pub fn data_mut(&mut self) -> &mut [u8; ELEMENT_DATA_SIZE] {
        &mut self.data
    }

    /// Current state of the element.
    pub fn state(&self) -> MempoolElementState {
        self.state
    }

    /// Owner identifier.
    pub fn owner_id(&self) -> u64 {
        self.owner_id
    }
}

// ── MempoolStats ─────────────────────────────────────────────────

/// Snapshot of mempool statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MempoolStats {
    /// Total successful allocations.
    pub alloc_count: u64,
    /// Total successful frees.
    pub free_count: u64,
    /// Total failed allocation attempts.
    pub alloc_fail: u64,
    /// Peak number of simultaneously allocated elements.
    pub high_watermark: usize,
    /// Minimum number of free elements observed.
    pub low_watermark: usize,
}

// ── Mempool ──────────────────────────────────────────────────────

/// A guaranteed allocation pool of fixed-size elements.
///
/// The pool pre-allocates a minimum number of elements (`min_nr`) and
/// guarantees that allocations succeed as long as elements remain.
/// This is modelled after the Linux kernel `mempool_t`.
pub struct Mempool {
    /// Human-readable name stored inline.
    name: [u8; 32],
    /// Valid length of `name`.
    name_len: usize,
    /// Per-element storage.
    elements: [MempoolElement; MAX_ELEMENTS],
    /// Minimum number of elements to keep available.
    min_nr: usize,
    /// Current number of free or reserved elements.
    current_nr: usize,
    /// Size of each element's usable data (up to [`ELEMENT_DATA_SIZE`]).
    element_size: usize,
    /// Cumulative statistics.
    stats: MempoolStats,
    /// Whether this pool is active and usable.
    in_use: bool,
}

impl Mempool {
    /// Create a new mempool.
    ///
    /// `name` is a human-readable label (truncated to 32 bytes),
    /// `min_nr` is the minimum reserve (capped at [`MAX_ELEMENTS`]),
    /// and `element_size` is the usable data size per element
    /// (capped at [`ELEMENT_DATA_SIZE`]).
    ///
    /// All elements start as [`MempoolElementState::Free`] and
    /// `current_nr` is set to [`MAX_ELEMENTS`].
    pub fn new(name: &[u8], min_nr: usize, element_size: usize) -> Result<Self> {
        if element_size == 0 || element_size > ELEMENT_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }

        let capped_min = if min_nr > MAX_ELEMENTS {
            MAX_ELEMENTS
        } else {
            min_nr
        };

        let mut pool_name = [0u8; 32];
        let copy_len = name.len().min(32);
        pool_name[..copy_len].copy_from_slice(&name[..copy_len]);

        Ok(Self {
            name: pool_name,
            name_len: copy_len,
            elements: [MempoolElement::default(); MAX_ELEMENTS],
            min_nr: capped_min,
            current_nr: MAX_ELEMENTS,
            element_size,
            stats: MempoolStats {
                low_watermark: MAX_ELEMENTS,
                ..MempoolStats::default()
            },
            in_use: true,
        })
    }

    /// Allocate an element from the pool.
    ///
    /// Returns the index of the allocated element.
    /// Fails with [`Error::OutOfMemory`] when no free or reserved
    /// elements remain.
    pub fn alloc(&mut self, owner_id: u64) -> Result<u16> {
        // Prefer free elements first, then reserved.
        for target_state in &[MempoolElementState::Free, MempoolElementState::Reserved] {
            let mut i = 0;
            while i < MAX_ELEMENTS {
                if self.elements[i].state == *target_state {
                    self.elements[i].state = MempoolElementState::Allocated;
                    self.elements[i].owner_id = owner_id;
                    self.current_nr = self.current_nr.saturating_sub(1);
                    self.stats.alloc_count += 1;

                    // Update watermarks.
                    let allocated = self.allocated();
                    if allocated > self.stats.high_watermark {
                        self.stats.high_watermark = allocated;
                    }
                    if self.current_nr < self.stats.low_watermark {
                        self.stats.low_watermark = self.current_nr;
                    }

                    return Ok(i as u16);
                }
                i += 1;
            }
        }

        self.stats.alloc_fail += 1;
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated element back to the pool.
    ///
    /// The element at `idx` must be in [`MempoolElementState::Allocated`]
    /// state.
    pub fn free(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_ELEMENTS {
            return Err(Error::InvalidArgument);
        }
        if self.elements[i].state != MempoolElementState::Allocated {
            return Err(Error::InvalidArgument);
        }

        self.elements[i].state = MempoolElementState::Free;
        self.elements[i].owner_id = 0;
        self.current_nr += 1;
        self.stats.free_count += 1;
        Ok(())
    }

    /// Reserve `count` free elements as the minimum guarantee.
    ///
    /// Transitions up to `count` [`MempoolElementState::Free`] elements
    /// to [`MempoolElementState::Reserved`]. Returns
    /// [`Error::OutOfMemory`] if fewer than `count` free elements exist.
    pub fn reserve(&mut self, count: usize) -> Result<()> {
        // Check that enough free elements exist.
        let free = self
            .elements
            .iter()
            .filter(|e| e.state == MempoolElementState::Free)
            .count();

        if free < count {
            return Err(Error::OutOfMemory);
        }

        let mut reserved = 0usize;
        let mut i = 0;
        while i < MAX_ELEMENTS && reserved < count {
            if self.elements[i].state == MempoolElementState::Free {
                self.elements[i].state = MempoolElementState::Reserved;
                reserved += 1;
            }
            i += 1;
        }

        Ok(())
    }

    /// Resize the minimum reserve level.
    ///
    /// `new_min` is capped at [`MAX_ELEMENTS`]. Does not move elements
    /// between states; only updates the `min_nr` threshold.
    pub fn resize(&mut self, new_min: usize) -> Result<()> {
        let capped = if new_min > MAX_ELEMENTS {
            MAX_ELEMENTS
        } else {
            new_min
        };
        self.min_nr = capped;
        Ok(())
    }

    /// Number of free or reserved elements (available for allocation).
    pub fn available(&self) -> usize {
        self.current_nr
    }

    /// Number of currently allocated elements.
    pub fn allocated(&self) -> usize {
        self.elements
            .iter()
            .filter(|e| e.state == MempoolElementState::Allocated)
            .count()
    }

    /// Returns `true` when available elements are below `min_nr`.
    pub fn is_below_min(&self) -> bool {
        self.current_nr < self.min_nr
    }

    /// Replenish the pool by reserving free elements up to `min_nr`.
    ///
    /// Returns the number of elements newly reserved.
    pub fn replenish(&mut self) -> Result<u32> {
        let mut count = 0u32;
        let mut i = 0;
        while i < MAX_ELEMENTS {
            let reserved = self
                .elements
                .iter()
                .filter(|e| e.state == MempoolElementState::Reserved)
                .count();
            let free_and_reserved = reserved + self.available_free_count();

            if free_and_reserved >= self.min_nr {
                break;
            }

            if self.elements[i].state == MempoolElementState::Free {
                self.elements[i].state = MempoolElementState::Reserved;
                count += 1;
            }
            i += 1;
        }

        Ok(count)
    }

    /// Get a reference to the pool's statistics.
    pub fn get_stats(&self) -> &MempoolStats {
        &self.stats
    }

    /// Shrink the pool by releasing reserved elements that exceed
    /// `min_nr` back to free state.
    ///
    /// Returns the number of elements released.
    pub fn shrink(&mut self) -> Result<u32> {
        let reserved = self
            .elements
            .iter()
            .filter(|e| e.state == MempoolElementState::Reserved)
            .count();

        if reserved <= self.min_nr {
            return Ok(0);
        }

        let excess = reserved - self.min_nr;
        let mut released = 0u32;
        let mut i = 0;
        while i < MAX_ELEMENTS && (released as usize) < excess {
            if self.elements[i].state == MempoolElementState::Reserved {
                self.elements[i].state = MempoolElementState::Free;
                released += 1;
            }
            i += 1;
        }

        Ok(released)
    }

    /// Pool name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Element data size for this pool.
    pub fn element_size(&self) -> usize {
        self.element_size
    }

    /// Minimum reserve level.
    pub fn min_nr(&self) -> usize {
        self.min_nr
    }

    /// Whether this pool is active.
    pub fn is_active(&self) -> bool {
        self.in_use
    }

    // ── helpers ────────────────────────────────────────────────────

    /// Count of elements in [`MempoolElementState::Free`] state.
    fn available_free_count(&self) -> usize {
        self.elements
            .iter()
            .filter(|e| e.state == MempoolElementState::Free)
            .count()
    }
}

// ── MempoolAllocator ─────────────────────────────────────────────

/// System-wide mempool allocator managing multiple named pools.
///
/// Holds up to [`MAX_POOLS`] mempools and provides creation,
/// destruction, and per-pool allocation/free operations.
pub struct MempoolAllocator {
    /// Registered pools.
    pools: [Option<Mempool>; MAX_POOLS],
    /// Number of active pools.
    count: usize,
}

impl Default for MempoolAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolAllocator {
    /// Create an empty allocator.
    pub const fn new() -> Self {
        const NONE: Option<Mempool> = None;
        Self {
            pools: [NONE; MAX_POOLS],
            count: 0,
        }
    }

    /// Create a new named mempool and return its slot index.
    ///
    /// `min_nr` is the minimum element reserve, `element_size` is the
    /// usable data size per element.
    pub fn create_pool(&mut self, name: &[u8], min_nr: usize, element_size: usize) -> Result<u16> {
        if self.count >= MAX_POOLS {
            return Err(Error::OutOfMemory);
        }

        let pool = Mempool::new(name, min_nr, element_size)?;

        for (i, slot) in self.pools.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(pool);
                self.count += 1;
                return Ok(i as u16);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a pool at the given index.
    ///
    /// Fails with [`Error::Busy`] if the pool still has allocated
    /// elements, or [`Error::InvalidArgument`] if the index is invalid.
    pub fn destroy_pool(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        let pool = self
            .pools
            .get(i)
            .and_then(|p| p.as_ref())
            .ok_or(Error::InvalidArgument)?;

        if pool.allocated() > 0 {
            return Err(Error::Busy);
        }

        self.pools[i] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Allocate an element from the specified pool.
    ///
    /// Returns the element index within the pool.
    pub fn alloc(&mut self, pool_idx: u16, owner_id: u64) -> Result<u16> {
        let i = pool_idx as usize;
        let pool = self
            .pools
            .get_mut(i)
            .and_then(|p| p.as_mut())
            .ok_or(Error::InvalidArgument)?;
        pool.alloc(owner_id)
    }

    /// Free an element back to the specified pool.
    pub fn free(&mut self, pool_idx: u16, elem_idx: u16) -> Result<()> {
        let i = pool_idx as usize;
        let pool = self
            .pools
            .get_mut(i)
            .and_then(|p| p.as_mut())
            .ok_or(Error::InvalidArgument)?;
        pool.free(elem_idx)
    }

    /// Get an immutable reference to a pool by index.
    pub fn get_pool(&self, idx: u16) -> Option<&Mempool> {
        self.pools.get(idx as usize)?.as_ref()
    }

    /// Shrink all pools, releasing excess reserved elements.
    ///
    /// Returns the total number of elements released across all pools.
    pub fn shrink_all(&mut self) -> Result<u32> {
        let mut total = 0u32;
        for slot in self.pools.iter_mut().flatten() {
            total += slot.shrink()?;
        }
        Ok(total)
    }

    /// Number of active pools.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no pools are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

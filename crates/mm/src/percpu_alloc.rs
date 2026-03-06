// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU memory allocator with chunk-based management.
//!
//! Provides a chunk-based per-CPU data allocation system where each
//! logical CPU maintains its own memory arena divided into fixed-size
//! chunks. This avoids cross-CPU contention on the global allocator
//! for hot-path allocations.
//!
//! # Architecture
//!
//! Each CPU is assigned a [`PerCpuArea`] that is subdivided into
//! [`PerCpuChunk`] regions. Dynamic allocations within a chunk use a
//! bump-pointer strategy. When a chunk fills up, the next chunk in
//! the area is activated.
//!
//! ```text
//! PerCpuAllocator
//!   +--- CPU 0: PerCpuArea
//!   |      +--- Chunk 0 (active, bump ptr @ 1024)
//!   |      +--- Chunk 1 (full)
//!   |      +--- Chunk 2 (empty)
//!   |      ...
//!   +--- CPU 1: PerCpuArea
//!   |      +--- Chunk 0 (active, bump ptr @ 256)
//!   |      ...
//!   +--- CPU N: ...
//! ```
//!
//! # Key types
//!
//! - [`CpuSlot`] -- individual allocation within a chunk
//! - [`PerCpuChunk`] -- fixed-size memory region with bump allocator
//! - [`PerCpuArea`] -- per-CPU arena containing multiple chunks
//! - [`PerCpuAllocator`] -- top-level allocator managing all CPUs
//! - [`PerCpuAllocStats`] -- aggregate allocation statistics
//!
//! # Fast-path design
//!
//! The allocator is designed for O(1) fast-path allocation:
//! 1. Index into the current CPU's area (no locking needed)
//! 2. Bump the active chunk pointer
//! 3. If the chunk is full, advance to the next chunk
//!
//! Freeing is deferred: slots are marked inactive and the chunk is
//! compacted only when all slots are freed or when the area is
//! reclaimed on CPU offline.
//!
//! # CPU hotplug
//!
//! Areas are initialised when a CPU comes online and drained when it
//! goes offline. The allocator tracks CPU lifecycle states.
//!
//! Reference: Linux `mm/percpu.c`, `mm/percpu-vm.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Number of chunks per CPU area.
const CHUNKS_PER_AREA: usize = 16;

/// Size of each chunk in bytes (4 KiB -- one page).
const CHUNK_SIZE: usize = 4096;

/// Minimum allocation granularity (bytes).
const MIN_ALLOC_SIZE: usize = 8;

/// Alignment for all allocations.
const ALLOC_ALIGN: usize = 8;

/// Maximum number of allocation slots per chunk.
const MAX_SLOTS_PER_CHUNK: usize = 128;

/// Total per-CPU area size (chunks * chunk_size).
const AREA_TOTAL_SIZE: usize = CHUNKS_PER_AREA * CHUNK_SIZE;

/// Maximum number of free-list entries for deferred reclamation.
const MAX_FREE_LIST: usize = 64;

// -------------------------------------------------------------------
// CpuLifecycle
// -------------------------------------------------------------------

/// Lifecycle state of a CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuLifecycle {
    /// CPU is offline -- area is not usable.
    Offline,
    /// CPU is being brought online -- area is being initialised.
    Initialising,
    /// CPU is online and area is active.
    Online,
    /// CPU is being taken offline -- area is being drained.
    Draining,
}

// -------------------------------------------------------------------
// CpuSlot
// -------------------------------------------------------------------

/// An individual allocation slot within a [`PerCpuChunk`].
///
/// Tracks the offset and size of a single allocation. Slots are
/// bump-allocated and freed by marking them inactive.
#[derive(Debug, Clone, Copy)]
pub struct CpuSlot {
    /// Offset from the chunk base (in bytes).
    offset: usize,
    /// Size of the allocation (in bytes, rounded up to alignment).
    size: usize,
    /// Whether this slot is currently allocated.
    active: bool,
    /// Generation counter for ABA detection.
    generation: u32,
}

impl CpuSlot {
    /// Creates an empty, inactive slot.
    const fn empty() -> Self {
        Self {
            offset: 0,
            size: 0,
            active: false,
            generation: 0,
        }
    }

    /// Returns the offset of this slot within its chunk.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the allocation size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns whether this slot is currently active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the generation counter.
    pub const fn generation(&self) -> u32 {
        self.generation
    }
}

// -------------------------------------------------------------------
// ChunkState
// -------------------------------------------------------------------

/// State of a per-CPU chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// Chunk is not yet initialised.
    Uninitialised,
    /// Chunk is active and accepting allocations.
    Active,
    /// Chunk is full (bump pointer reached the end).
    Full,
    /// Chunk is being reclaimed (all slots freed).
    Reclaiming,
}

// -------------------------------------------------------------------
// PerCpuChunk
// -------------------------------------------------------------------

/// A fixed-size memory region with a bump-pointer allocator.
///
/// Each chunk is [`CHUNK_SIZE`] bytes and tracks allocations via
/// [`CpuSlot`] entries. The bump pointer advances on allocation;
/// slots are individually freed but the chunk is only fully
/// reclaimed when all slots are inactive.
#[derive(Debug)]
pub struct PerCpuChunk {
    /// Chunk index within the parent area.
    index: usize,
    /// Base address of this chunk (absolute).
    base_addr: u64,
    /// Current bump pointer (offset from base).
    bump_offset: usize,
    /// Allocation slots.
    slots: [CpuSlot; MAX_SLOTS_PER_CHUNK],
    /// Number of active slots.
    active_slots: usize,
    /// Total number of slots ever allocated (including freed).
    total_slots: usize,
    /// Current chunk state.
    state: ChunkState,
    /// Total bytes allocated (including freed slots).
    allocated_bytes: usize,
    /// Total bytes freed.
    freed_bytes: usize,
}

impl PerCpuChunk {
    /// Creates a new uninitialised chunk.
    const fn empty() -> Self {
        Self {
            index: 0,
            base_addr: 0,
            bump_offset: 0,
            slots: [CpuSlot::empty(); MAX_SLOTS_PER_CHUNK],
            active_slots: 0,
            total_slots: 0,
            state: ChunkState::Uninitialised,
            allocated_bytes: 0,
            freed_bytes: 0,
        }
    }

    /// Initialise the chunk with a base address and index.
    fn init(&mut self, index: usize, base_addr: u64) {
        self.index = index;
        self.base_addr = base_addr;
        self.bump_offset = 0;
        self.active_slots = 0;
        self.total_slots = 0;
        self.state = ChunkState::Active;
        self.allocated_bytes = 0;
        self.freed_bytes = 0;
        for slot in &mut self.slots {
            *slot = CpuSlot::empty();
        }
    }

    /// Attempt to allocate `size` bytes from this chunk.
    ///
    /// Returns the slot index on success.
    fn alloc(&mut self, size: usize) -> Result<usize> {
        if self.state != ChunkState::Active {
            return Err(Error::Busy);
        }

        let aligned_size = align_up(size.max(MIN_ALLOC_SIZE), ALLOC_ALIGN);
        let aligned_offset = align_up(self.bump_offset, ALLOC_ALIGN);

        if aligned_offset + aligned_size > CHUNK_SIZE {
            self.state = ChunkState::Full;
            return Err(Error::OutOfMemory);
        }

        // Find a free slot descriptor.
        let slot_idx = self
            .slots
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        self.slots[slot_idx] = CpuSlot {
            offset: aligned_offset,
            size: aligned_size,
            active: true,
            generation: self.slots[slot_idx].generation.wrapping_add(1),
        };

        self.bump_offset = aligned_offset + aligned_size;
        self.active_slots += 1;
        self.total_slots += 1;
        self.allocated_bytes += aligned_size;

        // Check if chunk is now full.
        if self.bump_offset + MIN_ALLOC_SIZE > CHUNK_SIZE
            || self.active_slots >= MAX_SLOTS_PER_CHUNK
        {
            self.state = ChunkState::Full;
        }

        Ok(slot_idx)
    }

    /// Free the slot at `slot_idx`.
    fn free(&mut self, slot_idx: usize) -> Result<usize> {
        if slot_idx >= MAX_SLOTS_PER_CHUNK {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[slot_idx].active {
            return Err(Error::NotFound);
        }

        let freed_size = self.slots[slot_idx].size;
        self.slots[slot_idx].active = false;
        self.active_slots = self.active_slots.saturating_sub(1);
        self.freed_bytes += freed_size;

        // If all slots are freed, the chunk can be reclaimed.
        if self.active_slots == 0 {
            self.reclaim();
        }

        Ok(freed_size)
    }

    /// Free a slot by its offset within the chunk.
    fn free_by_offset(&mut self, offset: usize) -> Result<usize> {
        let slot_idx = self
            .slots
            .iter()
            .position(|s| s.active && s.offset == offset)
            .ok_or(Error::NotFound)?;
        self.free(slot_idx)
    }

    /// Reclaim the chunk, resetting the bump pointer.
    fn reclaim(&mut self) {
        self.state = ChunkState::Reclaiming;
        self.bump_offset = 0;
        self.active_slots = 0;
        self.total_slots = 0;
        self.allocated_bytes = 0;
        self.freed_bytes = 0;
        for slot in &mut self.slots {
            *slot = CpuSlot::empty();
        }
        self.state = ChunkState::Active;
    }

    /// Returns the base address of this chunk.
    pub const fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the chunk index within the parent area.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Returns the current bump offset.
    pub const fn bump_offset(&self) -> usize {
        self.bump_offset
    }

    /// Returns the number of active slots.
    pub const fn active_slots(&self) -> usize {
        self.active_slots
    }

    /// Returns the chunk state.
    pub const fn state(&self) -> ChunkState {
        self.state
    }

    /// Returns the number of free bytes remaining (approximation).
    pub const fn free_bytes(&self) -> usize {
        CHUNK_SIZE.saturating_sub(self.bump_offset)
    }

    /// Returns the total bytes currently allocated.
    pub const fn allocated_bytes(&self) -> usize {
        self.allocated_bytes.saturating_sub(self.freed_bytes)
    }
}

// -------------------------------------------------------------------
// FreeListEntry
// -------------------------------------------------------------------

/// Deferred free-list entry tracking a freed allocation.
#[derive(Debug, Clone, Copy)]
struct FreeListEntry {
    /// Chunk index.
    chunk_idx: usize,
    /// Slot index within the chunk.
    slot_idx: usize,
    /// Whether this entry is valid.
    valid: bool,
}

impl FreeListEntry {
    const fn empty() -> Self {
        Self {
            chunk_idx: 0,
            slot_idx: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// PerCpuArea
// -------------------------------------------------------------------

/// Per-CPU arena containing multiple chunks.
///
/// Each CPU has one area that manages [`CHUNKS_PER_AREA`] chunks.
/// Allocations are served from the current active chunk; when it
/// fills, the next chunk is activated.
pub struct PerCpuArea {
    /// CPU identifier.
    cpu_id: u32,
    /// CPU lifecycle state.
    lifecycle: CpuLifecycle,
    /// Base address of the entire area.
    base_addr: u64,
    /// Chunks in this area.
    chunks: [PerCpuChunk; CHUNKS_PER_AREA],
    /// Index of the current active chunk.
    active_chunk_idx: usize,
    /// Deferred free list.
    free_list: [FreeListEntry; MAX_FREE_LIST],
    /// Number of valid entries in the free list.
    free_list_count: usize,
    /// Total allocations performed on this area.
    alloc_count: u64,
    /// Total frees performed on this area.
    free_count: u64,
    /// Total bytes currently allocated across all chunks.
    total_allocated: usize,
}

impl PerCpuArea {
    /// Creates an empty, offline area.
    const fn empty() -> Self {
        Self {
            cpu_id: 0,
            lifecycle: CpuLifecycle::Offline,
            base_addr: 0,
            chunks: [const { PerCpuChunk::empty() }; CHUNKS_PER_AREA],
            active_chunk_idx: 0,
            free_list: [FreeListEntry::empty(); MAX_FREE_LIST],
            free_list_count: 0,
            alloc_count: 0,
            free_count: 0,
            total_allocated: 0,
        }
    }

    /// Initialise the area for the given CPU.
    fn init(&mut self, cpu_id: u32, base_addr: u64) {
        self.cpu_id = cpu_id;
        self.lifecycle = CpuLifecycle::Online;
        self.base_addr = base_addr;
        self.active_chunk_idx = 0;
        self.alloc_count = 0;
        self.free_count = 0;
        self.total_allocated = 0;
        self.free_list_count = 0;

        for (i, chunk) in self.chunks.iter_mut().enumerate() {
            let chunk_base = base_addr + (i as u64) * (CHUNK_SIZE as u64);
            chunk.init(i, chunk_base);
        }

        for entry in &mut self.free_list {
            *entry = FreeListEntry::empty();
        }
    }

    /// Allocate `size` bytes from this area.
    ///
    /// Returns `(chunk_index, slot_index, absolute_address)`.
    fn alloc(&mut self, size: usize) -> Result<(usize, usize, u64)> {
        if self.lifecycle != CpuLifecycle::Online {
            return Err(Error::PermissionDenied);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        // Try the active chunk first.
        let chunk_idx = self.active_chunk_idx;
        if chunk_idx < CHUNKS_PER_AREA {
            if let Ok(slot_idx) = self.chunks[chunk_idx].alloc(size) {
                let addr = self.chunks[chunk_idx].base_addr
                    + self.chunks[chunk_idx].slots[slot_idx].offset as u64;
                self.alloc_count += 1;
                self.total_allocated += self.chunks[chunk_idx].slots[slot_idx].size;
                return Ok((chunk_idx, slot_idx, addr));
            }
        }

        // Active chunk is full; find the next available chunk.
        for i in 0..CHUNKS_PER_AREA {
            let idx = (self.active_chunk_idx + 1 + i) % CHUNKS_PER_AREA;
            if self.chunks[idx].state == ChunkState::Active {
                self.active_chunk_idx = idx;
                let slot_idx = self.chunks[idx].alloc(size)?;
                let addr =
                    self.chunks[idx].base_addr + self.chunks[idx].slots[slot_idx].offset as u64;
                self.alloc_count += 1;
                self.total_allocated += self.chunks[idx].slots[slot_idx].size;
                return Ok((idx, slot_idx, addr));
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Free an allocation by chunk and slot index.
    fn free(&mut self, chunk_idx: usize, slot_idx: usize) -> Result<()> {
        if chunk_idx >= CHUNKS_PER_AREA {
            return Err(Error::InvalidArgument);
        }
        let freed_size = self.chunks[chunk_idx].free(slot_idx)?;
        self.free_count += 1;
        self.total_allocated = self.total_allocated.saturating_sub(freed_size);
        Ok(())
    }

    /// Free an allocation by absolute address.
    fn free_by_addr(&mut self, addr: u64) -> Result<()> {
        // Determine which chunk contains this address.
        if addr < self.base_addr {
            return Err(Error::InvalidArgument);
        }
        let offset_in_area = (addr - self.base_addr) as usize;
        let chunk_idx = offset_in_area / CHUNK_SIZE;
        if chunk_idx >= CHUNKS_PER_AREA {
            return Err(Error::InvalidArgument);
        }
        let offset_in_chunk = offset_in_area % CHUNK_SIZE;
        let freed_size = self.chunks[chunk_idx].free_by_offset(offset_in_chunk)?;
        self.free_count += 1;
        self.total_allocated = self.total_allocated.saturating_sub(freed_size);
        Ok(())
    }

    /// Enqueue a deferred free.
    fn defer_free(&mut self, chunk_idx: usize, slot_idx: usize) -> Result<()> {
        let entry = self
            .free_list
            .iter_mut()
            .find(|e| !e.valid)
            .ok_or(Error::OutOfMemory)?;

        entry.chunk_idx = chunk_idx;
        entry.slot_idx = slot_idx;
        entry.valid = true;
        self.free_list_count += 1;
        Ok(())
    }

    /// Process all deferred frees.
    ///
    /// Returns the number of frees processed.
    fn process_deferred_frees(&mut self) -> usize {
        let mut processed = 0usize;
        for i in 0..MAX_FREE_LIST {
            if !self.free_list[i].valid {
                continue;
            }
            let chunk_idx = self.free_list[i].chunk_idx;
            let slot_idx = self.free_list[i].slot_idx;
            if self.free(chunk_idx, slot_idx).is_ok() {
                processed += 1;
            }
            self.free_list[i].valid = false;
        }
        self.free_list_count = 0;
        processed
    }

    /// Drain all allocations in this area (CPU going offline).
    fn drain(&mut self) -> usize {
        self.lifecycle = CpuLifecycle::Draining;
        let mut drained = 0usize;

        for chunk in &mut self.chunks {
            drained += chunk.active_slots;
            chunk.reclaim();
        }

        // Clear free list.
        for entry in &mut self.free_list {
            *entry = FreeListEntry::empty();
        }
        self.free_list_count = 0;
        self.total_allocated = 0;
        self.lifecycle = CpuLifecycle::Offline;
        drained
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the lifecycle state.
    pub const fn lifecycle(&self) -> CpuLifecycle {
        self.lifecycle
    }

    /// Returns the base address.
    pub const fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the index of the current active chunk.
    pub const fn active_chunk_idx(&self) -> usize {
        self.active_chunk_idx
    }

    /// Returns total bytes currently allocated.
    pub const fn total_allocated(&self) -> usize {
        self.total_allocated
    }

    /// Returns the total area size.
    pub const fn area_size(&self) -> usize {
        AREA_TOTAL_SIZE
    }

    /// Returns the total free space across all chunks (approximation).
    pub fn total_free(&self) -> usize {
        self.chunks.iter().map(|c| c.free_bytes()).sum()
    }

    /// Returns the allocation count.
    pub const fn alloc_count(&self) -> u64 {
        self.alloc_count
    }

    /// Returns the free count.
    pub const fn free_count(&self) -> u64 {
        self.free_count
    }

    /// Returns a reference to a chunk by index.
    pub fn chunk(&self, idx: usize) -> Option<&PerCpuChunk> {
        if idx < CHUNKS_PER_AREA {
            Some(&self.chunks[idx])
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// AllocationHandle
// -------------------------------------------------------------------

/// Handle returned from a successful allocation.
///
/// Contains the information needed to free the allocation later.
#[derive(Debug, Clone, Copy)]
pub struct AllocationHandle {
    /// CPU that owns this allocation.
    pub cpu_id: u32,
    /// Chunk index within the CPU area.
    pub chunk_idx: usize,
    /// Slot index within the chunk.
    pub slot_idx: usize,
    /// Absolute address of the allocation.
    pub addr: u64,
    /// Size of the allocation.
    pub size: usize,
}

// -------------------------------------------------------------------
// PerCpuAllocStats
// -------------------------------------------------------------------

/// Aggregate allocation statistics across all CPUs.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerCpuAllocStats {
    /// Number of CPUs online.
    pub online_cpus: usize,
    /// Total area bytes across all online CPUs.
    pub total_area_bytes: usize,
    /// Total bytes allocated across all CPUs.
    pub total_allocated_bytes: usize,
    /// Total free bytes across all CPUs.
    pub total_free_bytes: usize,
    /// Total active chunks across all CPUs.
    pub total_active_chunks: usize,
    /// Total full chunks across all CPUs.
    pub total_full_chunks: usize,
    /// Cumulative allocation count.
    pub total_alloc_count: u64,
    /// Cumulative free count.
    pub total_free_count: u64,
    /// Total deferred frees pending.
    pub total_deferred_frees: usize,
}

// -------------------------------------------------------------------
// PerCpuAllocator
// -------------------------------------------------------------------

/// Top-level per-CPU chunk-based memory allocator.
///
/// Manages [`PerCpuArea`] instances for up to [`MAX_CPUS`]
/// processors. Each CPU has its own independent arena of chunks.
///
/// # Usage
///
/// ```ignore
/// let mut alloc = PerCpuAllocator::new();
/// alloc.cpu_online(0, 0x1000_0000)?;
/// let handle = alloc.alloc(0, 64)?;
/// alloc.free_handle(&handle)?;
/// ```
pub struct PerCpuAllocator {
    /// Per-CPU areas.
    areas: [PerCpuArea; MAX_CPUS],
    /// Number of CPUs currently online.
    online_count: usize,
    /// Global allocation counter.
    global_alloc_count: u64,
    /// Global free counter.
    global_free_count: u64,
}

impl Default for PerCpuAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuAllocator {
    /// Creates a new allocator with no CPUs online.
    pub const fn new() -> Self {
        Self {
            areas: [const { PerCpuArea::empty() }; MAX_CPUS],
            online_count: 0,
            global_alloc_count: 0,
            global_free_count: 0,
        }
    }

    // -----------------------------------------------------------
    // CPU lifecycle
    // -----------------------------------------------------------

    /// Bring a CPU online, initialising its per-CPU area.
    ///
    /// `base_addr` is the start of the pre-allocated memory region
    /// for this CPU (must be at least [`AREA_TOTAL_SIZE`] bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::AlreadyExists`] if the CPU is already online.
    pub fn cpu_online(&mut self, cpu_id: u32, base_addr: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.areas[idx].lifecycle == CpuLifecycle::Online {
            return Err(Error::AlreadyExists);
        }

        self.areas[idx].init(cpu_id, base_addr);
        self.online_count += 1;
        Ok(())
    }

    /// Take a CPU offline, draining all allocations.
    ///
    /// Returns the number of slots that were still active.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::NotFound`] if the CPU is not online.
    pub fn cpu_offline(&mut self, cpu_id: u32) -> Result<usize> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.areas[idx].lifecycle != CpuLifecycle::Online {
            return Err(Error::NotFound);
        }

        let drained = self.areas[idx].drain();
        self.online_count = self.online_count.saturating_sub(1);
        Ok(drained)
    }

    /// Check whether a CPU is online.
    pub fn is_cpu_online(&self, cpu_id: u32) -> bool {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return false;
        }
        self.areas[idx].lifecycle == CpuLifecycle::Online
    }

    /// Returns the number of CPUs currently online.
    pub const fn online_count(&self) -> usize {
        self.online_count
    }

    /// Returns the lifecycle state of a CPU.
    pub fn cpu_lifecycle(&self, cpu_id: u32) -> Option<CpuLifecycle> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        Some(self.areas[idx].lifecycle)
    }

    // -----------------------------------------------------------
    // Allocation
    // -----------------------------------------------------------

    /// Allocate `size` bytes on the specified CPU.
    ///
    /// Returns an [`AllocationHandle`] that can be used to free the
    /// allocation later.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range
    /// or `size` is zero.
    /// Returns [`Error::PermissionDenied`] if the CPU is not online.
    /// Returns [`Error::OutOfMemory`] if no chunk can satisfy the
    /// allocation.
    pub fn alloc(&mut self, cpu_id: u32, size: usize) -> Result<AllocationHandle> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        let (chunk_idx, slot_idx, addr) = self.areas[idx].alloc(size)?;
        let alloc_size = self.areas[idx].chunks[chunk_idx].slots[slot_idx].size;

        self.global_alloc_count += 1;

        Ok(AllocationHandle {
            cpu_id,
            chunk_idx,
            slot_idx,
            addr,
            size: alloc_size,
        })
    }

    /// Free an allocation using its handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the handle's CPU or
    /// chunk index is out of range.
    /// Returns [`Error::NotFound`] if the slot is not active.
    pub fn free_handle(&mut self, handle: &AllocationHandle) -> Result<()> {
        let idx = handle.cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[idx].free(handle.chunk_idx, handle.slot_idx)?;
        self.global_free_count += 1;
        Ok(())
    }

    /// Free an allocation by CPU ID and absolute address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range
    /// or the address is outside the CPU's area.
    /// Returns [`Error::NotFound`] if no allocation exists at the
    /// given address.
    pub fn free_by_addr(&mut self, cpu_id: u32, addr: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[idx].free_by_addr(addr)?;
        self.global_free_count += 1;
        Ok(())
    }

    /// Enqueue a deferred free on the given CPU.
    ///
    /// The free will be processed during the next call to
    /// [`process_deferred_frees`](Self::process_deferred_frees).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::OutOfMemory`] if the deferred free list is
    /// full.
    pub fn defer_free(&mut self, cpu_id: u32, chunk_idx: usize, slot_idx: usize) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[idx].defer_free(chunk_idx, slot_idx)
    }

    /// Process all deferred frees for the given CPU.
    ///
    /// Returns the number of frees processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn process_deferred_frees(&mut self, cpu_id: u32) -> Result<usize> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let count = self.areas[idx].process_deferred_frees();
        self.global_free_count += count as u64;
        Ok(count)
    }

    /// Process deferred frees for all online CPUs.
    ///
    /// Returns the total number of frees processed.
    pub fn process_all_deferred_frees(&mut self) -> usize {
        let mut total = 0usize;
        for area in &mut self.areas {
            if area.lifecycle == CpuLifecycle::Online {
                let count = area.process_deferred_frees();
                total += count;
            }
        }
        self.global_free_count += total as u64;
        total
    }

    // -----------------------------------------------------------
    // Queries
    // -----------------------------------------------------------

    /// Returns a reference to the per-CPU area for the given CPU.
    ///
    /// Returns `None` if `cpu_id` is out of range or the CPU is
    /// offline.
    pub fn area(&self, cpu_id: u32) -> Option<&PerCpuArea> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        if self.areas[idx].lifecycle == CpuLifecycle::Offline {
            return None;
        }
        Some(&self.areas[idx])
    }

    /// Returns the base address for a CPU's area.
    pub fn base_addr(&self, cpu_id: u32) -> Option<u64> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        if self.areas[idx].lifecycle == CpuLifecycle::Offline {
            return None;
        }
        Some(self.areas[idx].base_addr)
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> PerCpuAllocStats {
        let mut total_allocated = 0usize;
        let mut total_free = 0usize;
        let mut active_chunks = 0usize;
        let mut full_chunks = 0usize;
        let mut deferred = 0usize;

        for area in &self.areas {
            if area.lifecycle != CpuLifecycle::Online {
                continue;
            }
            total_allocated += area.total_allocated;
            total_free += area.total_free();
            deferred += area.free_list_count;

            for chunk in &area.chunks {
                match chunk.state {
                    ChunkState::Active => active_chunks += 1,
                    ChunkState::Full => full_chunks += 1,
                    _ => {}
                }
            }
        }

        PerCpuAllocStats {
            online_cpus: self.online_count,
            total_area_bytes: self.online_count * AREA_TOTAL_SIZE,
            total_allocated_bytes: total_allocated,
            total_free_bytes: total_free,
            total_active_chunks: active_chunks,
            total_full_chunks: full_chunks,
            total_alloc_count: self.global_alloc_count,
            total_free_count: self.global_free_count,
            total_deferred_frees: deferred,
        }
    }

    /// Returns the global allocation count.
    pub const fn global_alloc_count(&self) -> u64 {
        self.global_alloc_count
    }

    /// Returns the global free count.
    pub const fn global_free_count(&self) -> u64 {
        self.global_free_count
    }
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Round `val` up to the nearest multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(val: usize, align: usize) -> usize {
    let mask = align - 1;
    (val + mask) & !mask
}

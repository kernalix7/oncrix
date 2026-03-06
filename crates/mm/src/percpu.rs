// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU memory allocator.
//!
//! Provides allocation and management of per-CPU data areas — memory
//! regions that are replicated once per logical CPU so each processor
//! can access its own copy without synchronisation.
//!
//! The subsystem manages:
//! - **Static per-CPU variables** — declared at compile time, each CPU
//!   gets its own instance at a fixed offset within the per-CPU area.
//! - **Dynamic per-CPU allocation** — runtime allocation of per-CPU
//!   chunks for kernel subsystems that need per-CPU storage.
//! - **Per-CPU page sets** — small per-CPU freelists to avoid
//!   contention on the global page allocator for hot-path allocations.
//! - **CPU hotplug** — areas are allocated when a CPU comes online
//!   and released when it goes offline.
//!
//! Modeled after Linux `mm/percpu.c` and `include/linux/percpu.h`.
//!
//! Reference: `.kernelORG/` — `mm/percpu.c`, `mm/percpu-vm.c`.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Size of each per-CPU area in bytes (64 KiB).
const PERCPU_AREA_SIZE: usize = 65536;

/// Maximum number of dynamic per-CPU slots per CPU.
const MAX_DYNAMIC_SLOTS: usize = 256;

/// Size of each allocation chunk (minimum allocation unit, 64 bytes).
const CHUNK_MIN_SIZE: usize = 64;

/// Maximum number of per-CPU page set entries.
const PAGE_SET_SIZE: usize = 16;

/// Maximum number of static per-CPU variable registrations.
const MAX_STATIC_VARS: usize = 64;

// ── CpuState ──────────────────────────────────────────────────────

/// Online/offline state of a CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuState {
    /// CPU is offline — per-CPU area is not active.
    Offline,
    /// CPU is coming online — area being initialised.
    Booting,
    /// CPU is fully online — area is active.
    Online,
    /// CPU is going offline — area being drained.
    GoingOffline,
}

// ── PerCpuSlot ────────────────────────────────────────────────────

/// A dynamic allocation slot within a per-CPU area.
///
/// Each slot tracks an offset (relative to the per-CPU area base)
/// and the size of the allocation.
#[derive(Debug, Clone, Copy)]
struct PerCpuSlot {
    /// Offset from the per-CPU area base.
    offset: usize,
    /// Size of the allocation in bytes.
    size: usize,
    /// Whether this slot is in use.
    active: bool,
}

impl PerCpuSlot {
    const fn empty() -> Self {
        Self {
            offset: 0,
            size: 0,
            active: false,
        }
    }
}

// ── StaticVarDescriptor ───────────────────────────────────────────

/// Describes a static per-CPU variable.
///
/// Static variables are registered once and have the same offset
/// in every CPU's area. The offset is assigned during registration
/// from a bump allocator within the static region.
#[derive(Debug, Clone, Copy)]
pub struct StaticVarDescriptor {
    /// Symbolic identifier for this variable (truncated to 31 bytes).
    name: [u8; 32],
    /// Offset from the per-CPU area base.
    offset: usize,
    /// Size of the variable in bytes.
    size: usize,
    /// Alignment requirement in bytes.
    align: usize,
    /// Whether this descriptor is active.
    active: bool,
}

impl StaticVarDescriptor {
    const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            offset: 0,
            size: 0,
            align: 0,
            active: false,
        }
    }

    /// The offset of this variable within the per-CPU area.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The size of this variable in bytes.
    pub const fn size(&self) -> usize {
        self.size
    }
}

// ── PageSetEntry ──────────────────────────────────────────────────

/// An entry in a per-CPU page set (pre-allocated page cache).
///
/// Each CPU maintains a small pool of pre-allocated page frame
/// numbers that can be handed out without locking the global
/// allocator.
#[derive(Debug, Clone, Copy)]
struct PageSetEntry {
    /// Physical frame number of the cached page.
    frame_number: u64,
    /// Whether this entry is valid.
    valid: bool,
}

impl PageSetEntry {
    const fn empty() -> Self {
        Self {
            frame_number: 0,
            valid: false,
        }
    }
}

// ── PerCpuArea ────────────────────────────────────────────────────

/// Per-CPU data area for a single CPU.
///
/// Contains the dynamic allocation table, page set cache, and
/// per-CPU statistics.
struct PerCpuArea {
    /// CPU identifier.
    cpu_id: u32,
    /// Current state of this CPU.
    state: CpuState,
    /// Base address of the per-CPU memory area.
    base_addr: u64,
    /// Dynamic allocation slots.
    slots: [PerCpuSlot; MAX_DYNAMIC_SLOTS],
    /// Number of active dynamic slots.
    slot_count: usize,
    /// Next available offset for dynamic allocation (bump pointer).
    dynamic_offset: usize,
    /// Start offset of the dynamic region (after static vars).
    dynamic_start: usize,
    /// Per-CPU page set — cached pages for fast allocation.
    page_set: [PageSetEntry; PAGE_SET_SIZE],
    /// Number of valid pages in the page set.
    page_set_count: usize,
    /// Total bytes allocated dynamically in this area.
    allocated_bytes: usize,
    /// Total allocation count.
    alloc_count: u64,
    /// Total free count.
    free_count: u64,
}

impl PerCpuArea {
    const fn empty() -> Self {
        Self {
            cpu_id: 0,
            state: CpuState::Offline,
            base_addr: 0,
            slots: [PerCpuSlot::empty(); MAX_DYNAMIC_SLOTS],
            slot_count: 0,
            dynamic_offset: 0,
            dynamic_start: 0,
            page_set: [PageSetEntry::empty(); PAGE_SET_SIZE],
            page_set_count: 0,
            allocated_bytes: 0,
            alloc_count: 0,
            free_count: 0,
        }
    }

    /// Initialise the area for a given CPU.
    fn init(&mut self, cpu_id: u32, base_addr: u64, static_region_end: usize) {
        self.cpu_id = cpu_id;
        self.state = CpuState::Online;
        self.base_addr = base_addr;
        self.dynamic_start = static_region_end;
        self.dynamic_offset = static_region_end;
        self.slot_count = 0;
        self.allocated_bytes = 0;
        self.alloc_count = 0;
        self.free_count = 0;
        self.page_set_count = 0;
    }

    /// Allocate `size` bytes from the dynamic region.
    fn alloc_dynamic(&mut self, size: usize, align: usize) -> Result<usize> {
        if self.state != CpuState::Online {
            return Err(Error::PermissionDenied);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_size = round_up(size, CHUNK_MIN_SIZE);
        let aligned_offset = round_up(self.dynamic_offset, align);

        if aligned_offset + aligned_size > PERCPU_AREA_SIZE {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .slots
            .iter_mut()
            .find(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        slot.offset = aligned_offset;
        slot.size = aligned_size;
        slot.active = true;

        self.dynamic_offset = aligned_offset + aligned_size;
        self.slot_count += 1;
        self.allocated_bytes += aligned_size;
        self.alloc_count += 1;

        Ok(aligned_offset)
    }

    /// Free a dynamic allocation at the given offset.
    fn free_dynamic(&mut self, offset: usize) -> Result<()> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.active && s.offset == offset)
            .ok_or(Error::NotFound)?;

        let freed_size = slot.size;
        slot.active = false;
        slot.offset = 0;
        slot.size = 0;

        self.slot_count = self.slot_count.saturating_sub(1);
        self.allocated_bytes = self.allocated_bytes.saturating_sub(freed_size);
        self.free_count += 1;

        Ok(())
    }

    /// Push a page frame number into the per-CPU page set.
    fn page_set_push(&mut self, frame_number: u64) -> Result<()> {
        let entry = self
            .page_set
            .iter_mut()
            .find(|e| !e.valid)
            .ok_or(Error::OutOfMemory)?;

        entry.frame_number = frame_number;
        entry.valid = true;
        self.page_set_count += 1;
        Ok(())
    }

    /// Pop a page frame number from the per-CPU page set.
    fn page_set_pop(&mut self) -> Option<u64> {
        for entry in self.page_set.iter_mut().rev() {
            if entry.valid {
                entry.valid = false;
                self.page_set_count = self.page_set_count.saturating_sub(1);
                return Some(entry.frame_number);
            }
        }
        None
    }

    /// Drain the page set, returning a count of pages drained.
    fn page_set_drain(&mut self) -> usize {
        let drained = self.page_set_count;
        for entry in self.page_set.iter_mut() {
            entry.valid = false;
            entry.frame_number = 0;
        }
        self.page_set_count = 0;
        drained
    }
}

// ── PerCpuStats ───────────────────────────────────────────────────

/// Statistics for a single per-CPU area.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerCpuStats {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether the CPU is online.
    pub online: bool,
    /// Total bytes of the per-CPU area.
    pub area_size: usize,
    /// Bytes allocated dynamically.
    pub allocated_bytes: usize,
    /// Bytes free in the dynamic region.
    pub free_bytes: usize,
    /// Number of active dynamic slots.
    pub slot_count: usize,
    /// Number of cached pages in the page set.
    pub page_set_count: usize,
    /// Cumulative allocation count.
    pub alloc_count: u64,
    /// Cumulative free count.
    pub free_count: u64,
}

// ── PerCpuAllocator ───────────────────────────────────────────────

/// Per-CPU memory allocator.
///
/// Manages per-CPU areas for up to [`MAX_CPUS`] processors. Handles
/// static variable registration, dynamic allocation, per-CPU page
/// sets, and CPU hotplug events.
pub struct PerCpuAllocator {
    /// Per-CPU areas, one per possible CPU.
    areas: [PerCpuArea; MAX_CPUS],
    /// Static variable descriptors (shared layout for all CPUs).
    static_vars: [StaticVarDescriptor; MAX_STATIC_VARS],
    /// Number of registered static variables.
    static_var_count: usize,
    /// Current end of the static region (bump pointer).
    static_region_end: usize,
    /// Number of CPUs currently online.
    online_count: usize,
    /// Total dynamic allocations across all CPUs.
    total_alloc_count: u64,
    /// Total dynamic frees across all CPUs.
    total_free_count: u64,
}

impl Default for PerCpuAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PerCpuAllocator {
    /// Create a new per-CPU allocator with no CPUs online.
    pub const fn new() -> Self {
        Self {
            areas: [const { PerCpuArea::empty() }; MAX_CPUS],
            static_vars: [StaticVarDescriptor::empty(); MAX_STATIC_VARS],
            static_var_count: 0,
            static_region_end: 0,
            online_count: 0,
            total_alloc_count: 0,
            total_free_count: 0,
        }
    }

    // ── Static variable registration ───────────────────────────

    /// Register a static per-CPU variable.
    ///
    /// Returns the offset within the per-CPU area where the variable
    /// will be located on each CPU. All CPUs share the same offset.
    ///
    /// Must be called before any CPUs are brought online.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero, `align`
    /// is not a power of two, or CPUs are already online.
    /// Returns [`Error::OutOfMemory`] if the static region is full.
    pub fn register_static_var(&mut self, name: &[u8], size: usize, align: usize) -> Result<usize> {
        if size == 0 || align == 0 || !align.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if self.online_count > 0 {
            return Err(Error::InvalidArgument);
        }
        if self.static_var_count >= MAX_STATIC_VARS {
            return Err(Error::OutOfMemory);
        }

        let offset = round_up(self.static_region_end, align);
        if offset + size > PERCPU_AREA_SIZE {
            return Err(Error::OutOfMemory);
        }

        let mut desc = StaticVarDescriptor::empty();
        let copy_len = name.len().min(31);
        let mut i = 0;
        while i < copy_len {
            desc.name[i] = name[i];
            i += 1;
        }
        desc.offset = offset;
        desc.size = size;
        desc.align = align;
        desc.active = true;

        self.static_vars[self.static_var_count] = desc;
        self.static_var_count += 1;
        self.static_region_end = offset + size;

        Ok(offset)
    }

    /// Look up a static variable by name.
    pub fn find_static_var(&self, name: &[u8]) -> Option<&StaticVarDescriptor> {
        for i in 0..self.static_var_count {
            let desc = &self.static_vars[i];
            if !desc.active {
                continue;
            }
            let name_len = desc.name.iter().position(|&b| b == 0).unwrap_or(32);
            if name_len == name.len() && &desc.name[..name_len] == name {
                return Some(desc);
            }
        }
        None
    }

    /// Number of registered static variables.
    pub fn static_var_count(&self) -> usize {
        self.static_var_count
    }

    /// Current end of the static region.
    pub fn static_region_end(&self) -> usize {
        self.static_region_end
    }

    // ── CPU hotplug ────────────────────────────────────────────

    /// Bring a CPU online, allocating its per-CPU area.
    ///
    /// `base_addr` is the physical or virtual base address of the
    /// pre-allocated per-CPU memory region for this CPU.
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
        if self.areas[idx].state == CpuState::Online {
            return Err(Error::AlreadyExists);
        }

        self.areas[idx].init(cpu_id, base_addr, self.static_region_end);
        self.online_count += 1;
        Ok(())
    }

    /// Take a CPU offline, draining its per-CPU resources.
    ///
    /// The page set is drained and dynamic allocations are released.
    /// Returns the number of pages drained from the page set.
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
        if self.areas[idx].state != CpuState::Online {
            return Err(Error::NotFound);
        }

        self.areas[idx].state = CpuState::GoingOffline;
        let drained = self.areas[idx].page_set_drain();

        // Clear dynamic slots.
        for slot in self.areas[idx].slots.iter_mut() {
            slot.active = false;
            slot.offset = 0;
            slot.size = 0;
        }
        self.areas[idx].slot_count = 0;
        self.areas[idx].allocated_bytes = 0;
        self.areas[idx].dynamic_offset = self.areas[idx].dynamic_start;
        self.areas[idx].state = CpuState::Offline;

        self.online_count = self.online_count.saturating_sub(1);
        Ok(drained)
    }

    /// Check whether a CPU is online.
    pub fn is_cpu_online(&self, cpu_id: u32) -> bool {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return false;
        }
        self.areas[idx].state == CpuState::Online
    }

    /// Number of CPUs currently online.
    pub fn online_cpu_count(&self) -> usize {
        self.online_count
    }

    /// Get the state of a CPU.
    pub fn cpu_state(&self, cpu_id: u32) -> Option<CpuState> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        Some(self.areas[idx].state)
    }

    // ── Dynamic allocation ─────────────────────────────────────

    /// Allocate `size` bytes in the per-CPU area of `cpu_id`.
    ///
    /// Returns the offset within the per-CPU area.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range
    /// or `size` is zero.
    /// Returns [`Error::PermissionDenied`] if the CPU is not online.
    /// Returns [`Error::OutOfMemory`] if the area is full.
    pub fn alloc(&mut self, cpu_id: u32, size: usize, align: usize) -> Result<usize> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let real_align = if align == 0 || !align.is_power_of_two() {
            CHUNK_MIN_SIZE
        } else {
            align
        };
        let offset = self.areas[idx].alloc_dynamic(size, real_align)?;
        self.total_alloc_count += 1;
        Ok(offset)
    }

    /// Free a dynamic allocation at `offset` in the per-CPU area
    /// of `cpu_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::NotFound`] if no allocation exists at the
    /// given offset.
    pub fn free(&mut self, cpu_id: u32, offset: usize) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[idx].free_dynamic(offset)?;
        self.total_free_count += 1;
        Ok(())
    }

    /// Allocate the same `size` bytes on all online CPUs.
    ///
    /// Returns the shared offset. All online CPUs will have
    /// allocations at the same offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if any online CPU cannot
    /// satisfy the allocation.
    pub fn alloc_all_cpus(&mut self, size: usize, align: usize) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let real_align = if align == 0 || !align.is_power_of_two() {
            CHUNK_MIN_SIZE
        } else {
            align
        };

        // First pass: determine the offset using the highest
        // dynamic_offset across all online CPUs.
        let mut max_offset = 0usize;
        for area in self.areas.iter() {
            if area.state == CpuState::Online && area.dynamic_offset > max_offset {
                max_offset = area.dynamic_offset;
            }
        }
        let aligned_offset = round_up(max_offset, real_align);
        let aligned_size = round_up(size, CHUNK_MIN_SIZE);

        if aligned_offset + aligned_size > PERCPU_AREA_SIZE {
            return Err(Error::OutOfMemory);
        }

        // Second pass: allocate at the computed offset on each CPU.
        for area in self.areas.iter_mut() {
            if area.state != CpuState::Online {
                continue;
            }
            let slot = area
                .slots
                .iter_mut()
                .find(|s| !s.active)
                .ok_or(Error::OutOfMemory)?;

            slot.offset = aligned_offset;
            slot.size = aligned_size;
            slot.active = true;

            area.slot_count += 1;
            area.allocated_bytes += aligned_size;
            area.alloc_count += 1;

            // Advance bump pointer if needed.
            let new_end = aligned_offset + aligned_size;
            if new_end > area.dynamic_offset {
                area.dynamic_offset = new_end;
            }
        }

        self.total_alloc_count += self.online_count as u64;
        Ok(aligned_offset)
    }

    // ── Per-CPU page set ───────────────────────────────────────

    /// Push a cached page frame into a CPU's page set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::OutOfMemory`] if the page set is full.
    pub fn page_set_push(&mut self, cpu_id: u32, frame_number: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.areas[idx].page_set_push(frame_number)
    }

    /// Pop a cached page frame from a CPU's page set.
    ///
    /// Returns `None` if the page set is empty.
    pub fn page_set_pop(&mut self, cpu_id: u32) -> Option<u64> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        self.areas[idx].page_set_pop()
    }

    /// Number of pages in a CPU's page set.
    pub fn page_set_count(&self, cpu_id: u32) -> usize {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return 0;
        }
        self.areas[idx].page_set_count
    }

    // ── Statistics ─────────────────────────────────────────────

    /// Get per-CPU statistics for a specific CPU.
    ///
    /// Returns `None` if `cpu_id` is out of range.
    pub fn stats(&self, cpu_id: u32) -> Option<PerCpuStats> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        let area = &self.areas[idx];
        Some(PerCpuStats {
            cpu_id: area.cpu_id,
            online: area.state == CpuState::Online,
            area_size: PERCPU_AREA_SIZE,
            allocated_bytes: area.allocated_bytes,
            free_bytes: PERCPU_AREA_SIZE.saturating_sub(area.dynamic_offset),
            slot_count: area.slot_count,
            page_set_count: area.page_set_count,
            alloc_count: area.alloc_count,
            free_count: area.free_count,
        })
    }

    /// Get aggregate statistics across all online CPUs.
    pub fn aggregate_stats(&self) -> AggregatePerCpuStats {
        let mut total_allocated: u64 = 0;
        let mut total_free: u64 = 0;
        let mut total_slots: usize = 0;
        let mut total_pages: usize = 0;

        for area in self.areas.iter() {
            if area.state != CpuState::Online {
                continue;
            }
            total_allocated += area.allocated_bytes as u64;
            total_free += PERCPU_AREA_SIZE.saturating_sub(area.dynamic_offset) as u64;
            total_slots += area.slot_count;
            total_pages += area.page_set_count;
        }

        AggregatePerCpuStats {
            online_cpus: self.online_count,
            total_area_bytes: (self.online_count as u64).saturating_mul(PERCPU_AREA_SIZE as u64),
            total_allocated_bytes: total_allocated,
            total_free_bytes: total_free,
            total_active_slots: total_slots,
            total_cached_pages: total_pages,
            total_alloc_count: self.total_alloc_count,
            total_free_count: self.total_free_count,
            static_var_count: self.static_var_count,
            static_region_bytes: self.static_region_end,
        }
    }

    /// Get the base address of a CPU's per-CPU area.
    pub fn base_addr(&self, cpu_id: u32) -> Option<u64> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return None;
        }
        if self.areas[idx].state == CpuState::Offline {
            return None;
        }
        Some(self.areas[idx].base_addr)
    }
}

// ── AggregatePerCpuStats ──────────────────────────────────────────

/// Aggregate statistics across all per-CPU areas.
#[derive(Debug, Clone, Copy, Default)]
pub struct AggregatePerCpuStats {
    /// Number of online CPUs.
    pub online_cpus: usize,
    /// Total per-CPU area bytes (online CPUs * area size).
    pub total_area_bytes: u64,
    /// Total dynamically allocated bytes across all CPUs.
    pub total_allocated_bytes: u64,
    /// Total free bytes across all CPUs.
    pub total_free_bytes: u64,
    /// Total active dynamic slots across all CPUs.
    pub total_active_slots: usize,
    /// Total cached pages across all CPU page sets.
    pub total_cached_pages: usize,
    /// Cumulative allocation count across all CPUs.
    pub total_alloc_count: u64,
    /// Cumulative free count across all CPUs.
    pub total_free_count: u64,
    /// Number of registered static per-CPU variables.
    pub static_var_count: usize,
    /// Bytes consumed by the static per-CPU variable region.
    pub static_region_bytes: usize,
}

// ── Helpers ───────────────────────────────────────────────────────

/// Round `val` up to the nearest multiple of `align`.
const fn round_up(val: usize, align: usize) -> usize {
    let mask = align - 1;
    (val + mask) & !mask
}

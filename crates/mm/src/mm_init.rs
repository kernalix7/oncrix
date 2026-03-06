// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory management initialisation sequence.
//!
//! During early boot, the kernel transitions through several
//! initialisation phases before full memory management is available:
//!
//! 1. **Early** — firmware-provided memory map is parsed; a simple
//!    bump allocator is used for page tables and per-CPU areas.
//! 2. **Page allocator** — the bitmap / buddy allocator is created
//!    from the remaining free memory regions.
//! 3. **Slab** — the slab (kmem_cache) allocator is bootstrapped on
//!    top of the page allocator.
//! 4. **vmalloc** — the vmalloc subsystem is initialised (kernel
//!    virtual address space management).
//! 5. **Complete** — all subsystems are ready; the early allocator is
//!    retired.
//!
//! This module provides the sequencing logic and the state machine
//! that drives these phases. Architecture-specific details (E820
//! parsing, UEFI memory map) are abstracted behind the
//! [`MemoryRegion`] descriptor.
//!
//! # Key types
//!
//! - [`InitPhase`] — the five boot phases.
//! - [`MemoryRegion`] — a firmware-reported physical memory region.
//! - [`InitConfig`] — configuration parameters for the init sequence.
//! - [`MmInitState`] — the central state machine.
//!
//! Reference: Linux `mm/mm_init.c`, `mm/page_alloc.c`
//! (`mem_init()`), `arch/x86/mm/init.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of firmware memory regions.
const MAX_MEMORY_REGIONS: usize = 64;

/// Maximum number of reserved regions (kernel image, ACPI, initrd).
const MAX_RESERVED_REGIONS: usize = 32;

/// Maximum number of NUMA nodes.
const MAX_NUMA_NODES: usize = 8;

/// Maximum number of memory zones per node.
const MAX_ZONES: usize = 4;

/// Default page allocator watermark (pages).
const DEFAULT_WATERMARK_LOW: u64 = 256;

/// Default page allocator high watermark (pages).
const DEFAULT_WATERMARK_HIGH: u64 = 512;

/// Minimum pages required for the slab allocator bootstrap.
const MIN_SLAB_PAGES: u64 = 64;

/// Minimum pages required for the vmalloc subsystem.
const MIN_VMALLOC_PAGES: u64 = 16;

/// Alignment for zone boundaries (2 MiB / huge page).
const ZONE_ALIGN: u64 = 2 * 1024 * 1024;

/// DMA zone limit (16 MiB).
const DMA_ZONE_LIMIT: u64 = 16 * 1024 * 1024;

/// DMA32 zone limit (4 GiB).
const DMA32_ZONE_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

// ── InitPhase ───────────────────────────────────────────────────────────────

/// Boot-time memory initialisation phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InitPhase {
    /// Not yet started.
    NotStarted,
    /// Early memory map parsed; bump allocator active.
    Early,
    /// Page allocator initialised.
    PageAlloc,
    /// Slab allocator bootstrapped.
    Slab,
    /// vmalloc subsystem initialised.
    Vmalloc,
    /// All subsystems ready; init complete.
    Complete,
}

impl Default for InitPhase {
    fn default() -> Self {
        Self::NotStarted
    }
}

impl InitPhase {
    /// Returns a human-readable label for the phase.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Early => "early",
            Self::PageAlloc => "page-alloc",
            Self::Slab => "slab",
            Self::Vmalloc => "vmalloc",
            Self::Complete => "complete",
        }
    }
}

// ── MemoryRegionType ────────────────────────────────────────────────────────

/// Type of a firmware-reported memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// Usable RAM.
    Usable,
    /// Reserved by firmware (BIOS, UEFI).
    Reserved,
    /// ACPI reclaimable memory.
    AcpiReclaimable,
    /// ACPI NVS (non-volatile storage).
    AcpiNvs,
    /// Bad / defective memory.
    Bad,
    /// Persistent memory (NVDIMM).
    Persistent,
}

impl Default for MemoryRegionType {
    fn default() -> Self {
        Self::Usable
    }
}

// ── MemoryRegion ────────────────────────────────────────────────────────────

/// A single firmware-reported physical memory region.
///
/// Parsed from E820 (BIOS) or UEFI memory map entries.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Base physical address (page-aligned).
    pub base: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Region type.
    pub region_type: MemoryRegionType,
    /// NUMA node this region belongs to (0 if non-NUMA).
    pub numa_node: u8,
    /// Whether this region has been processed by the init sequence.
    pub processed: bool,
}

impl MemoryRegion {
    /// Creates an empty region.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            region_type: MemoryRegionType::Usable,
            numa_node: 0,
            processed: false,
        }
    }

    /// Returns the end address (exclusive) of this region.
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Returns the number of pages in this region.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Returns `true` if the region is usable RAM.
    pub const fn is_usable(&self) -> bool {
        matches!(self.region_type, MemoryRegionType::Usable)
    }
}

// ── ReservedRegion ──────────────────────────────────────────────────────────

/// A reserved physical memory region (kernel image, initrd, etc.).
#[derive(Debug, Clone, Copy)]
pub struct ReservedRegion {
    /// Base physical address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Human-readable label (truncated to 32 bytes).
    pub label: [u8; 32],
    /// Label length.
    pub label_len: usize,
    /// Whether this reservation is active.
    pub active: bool,
}

impl ReservedRegion {
    /// Creates an empty reservation.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            label: [0u8; 32],
            label_len: 0,
            active: false,
        }
    }

    /// Returns the end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }
}

// ── ZoneInfo ────────────────────────────────────────────────────────────────

/// Per-zone metadata computed during initialisation.
#[derive(Debug, Clone, Copy)]
pub struct ZoneInfo {
    /// Zone name index (0 = DMA, 1 = DMA32, 2 = Normal, 3 = HighMem).
    pub zone_index: u8,
    /// Start physical address.
    pub start: u64,
    /// End physical address (exclusive).
    pub end: u64,
    /// Number of usable pages in this zone.
    pub nr_pages: u64,
    /// Number of reserved pages in this zone.
    pub nr_reserved: u64,
    /// Low watermark (pages).
    pub watermark_low: u64,
    /// High watermark (pages).
    pub watermark_high: u64,
    /// Whether this zone is active.
    pub active: bool,
}

impl ZoneInfo {
    /// Creates an empty zone.
    const fn empty() -> Self {
        Self {
            zone_index: 0,
            start: 0,
            end: 0,
            nr_pages: 0,
            nr_reserved: 0,
            watermark_low: 0,
            watermark_high: 0,
            active: false,
        }
    }

    /// Zone name string.
    pub const fn name(&self) -> &'static str {
        match self.zone_index {
            0 => "DMA",
            1 => "DMA32",
            2 => "Normal",
            3 => "HighMem",
            _ => "Unknown",
        }
    }

    /// Returns the number of free pages (usable minus reserved).
    pub const fn free_pages(&self) -> u64 {
        self.nr_pages.saturating_sub(self.nr_reserved)
    }
}

// ── InitConfig ──────────────────────────────────────────────────────────────

/// Configuration parameters for the memory init sequence.
#[derive(Debug, Clone, Copy)]
pub struct InitConfig {
    /// Low watermark for the page allocator (pages).
    pub watermark_low: u64,
    /// High watermark for the page allocator (pages).
    pub watermark_high: u64,
    /// Whether to enable NUMA-aware initialisation.
    pub numa_enabled: bool,
    /// Number of NUMA nodes.
    pub nr_numa_nodes: u8,
    /// Whether to enable early-stage memory debugging (kasan-like).
    pub debug_enabled: bool,
    /// Whether to zero free pages at boot.
    pub zero_pages: bool,
    /// Maximum order for the buddy allocator (log2 of max block size).
    pub max_order: u8,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            watermark_low: DEFAULT_WATERMARK_LOW,
            watermark_high: DEFAULT_WATERMARK_HIGH,
            numa_enabled: false,
            nr_numa_nodes: 1,
            debug_enabled: false,
            zero_pages: false,
            max_order: 11, // 2^11 pages = 8 MiB
        }
    }
}

impl InitConfig {
    /// Validate configuration.
    pub fn validate(&self) -> Result<()> {
        if self.watermark_low == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.watermark_high < self.watermark_low {
            return Err(Error::InvalidArgument);
        }
        if self.nr_numa_nodes == 0 || self.nr_numa_nodes as usize > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        if self.max_order > 20 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── InitStats ───────────────────────────────────────────────────────────────

/// Statistics collected during the init sequence.
#[derive(Debug, Clone, Copy)]
pub struct InitStats {
    /// Total firmware-reported memory in bytes.
    pub total_firmware_bytes: u64,
    /// Total usable memory in bytes.
    pub total_usable_bytes: u64,
    /// Total reserved memory in bytes.
    pub total_reserved_bytes: u64,
    /// Number of firmware regions parsed.
    pub regions_parsed: u32,
    /// Number of reserved regions.
    pub reserved_count: u32,
    /// Pages handed to the page allocator.
    pub page_alloc_pages: u64,
    /// Pages consumed by the slab bootstrap.
    pub slab_bootstrap_pages: u64,
    /// Pages assigned to the vmalloc subsystem.
    pub vmalloc_pages: u64,
    /// Number of zones created.
    pub zones_created: u32,
}

impl InitStats {
    /// Creates zeroed statistics.
    const fn new() -> Self {
        Self {
            total_firmware_bytes: 0,
            total_usable_bytes: 0,
            total_reserved_bytes: 0,
            regions_parsed: 0,
            reserved_count: 0,
            page_alloc_pages: 0,
            slab_bootstrap_pages: 0,
            vmalloc_pages: 0,
            zones_created: 0,
        }
    }
}

// ── MmInitState ─────────────────────────────────────────────────────────────

/// Central state machine for memory management initialisation.
///
/// Drives the boot-time transition from firmware memory map through
/// to a fully functional memory management subsystem.
pub struct MmInitState {
    /// Current init phase.
    phase: InitPhase,
    /// Configuration.
    config: InitConfig,
    /// Firmware memory regions.
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    /// Number of registered regions.
    region_count: usize,
    /// Reserved regions.
    reserved: [ReservedRegion; MAX_RESERVED_REGIONS],
    /// Number of reserved regions.
    reserved_count: usize,
    /// Per-zone metadata.
    zones: [ZoneInfo; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Total usable pages across all regions.
    total_usable_pages: u64,
    /// Total reserved pages.
    total_reserved_pages: u64,
    /// Statistics.
    stats: InitStats,
}

impl MmInitState {
    /// Creates a new uninitialised state machine.
    pub const fn new() -> Self {
        Self {
            phase: InitPhase::NotStarted,
            config: InitConfig {
                watermark_low: DEFAULT_WATERMARK_LOW,
                watermark_high: DEFAULT_WATERMARK_HIGH,
                numa_enabled: false,
                nr_numa_nodes: 1,
                debug_enabled: false,
                zero_pages: false,
                max_order: 11,
            },
            regions: [const { MemoryRegion::empty() }; MAX_MEMORY_REGIONS],
            region_count: 0,
            reserved: [const { ReservedRegion::empty() }; MAX_RESERVED_REGIONS],
            reserved_count: 0,
            zones: [const { ZoneInfo::empty() }; MAX_ZONES],
            zone_count: 0,
            total_usable_pages: 0,
            total_reserved_pages: 0,
            stats: InitStats::new(),
        }
    }

    /// Phase 1: Early initialisation.
    ///
    /// Parses firmware memory regions and sets up the bump allocator.
    /// `regions` — firmware-reported memory map.
    pub fn init_early(&mut self, config: InitConfig, regions: &[MemoryRegion]) -> Result<()> {
        if self.phase != InitPhase::NotStarted {
            return Err(Error::Busy);
        }
        config.validate()?;

        self.config = config;

        // Register firmware regions.
        for region in regions {
            if self.region_count >= MAX_MEMORY_REGIONS {
                break;
            }
            self.regions[self.region_count] = *region;
            self.region_count += 1;

            self.stats.total_firmware_bytes += region.size;
            if region.is_usable() {
                self.stats.total_usable_bytes += region.size;
                self.total_usable_pages += region.page_count();
            }
            self.stats.regions_parsed += 1;
        }

        // Sort regions by base address (simple insertion sort).
        self.sort_regions();

        self.phase = InitPhase::Early;
        Ok(())
    }

    /// Register a reserved region.
    pub fn reserve(&mut self, base: u64, size: u64, label: &[u8]) -> Result<()> {
        if self.phase < InitPhase::Early {
            return Err(Error::InvalidArgument);
        }
        if self.reserved_count >= MAX_RESERVED_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let mut res = ReservedRegion::empty();
        res.base = base;
        res.size = size;
        res.active = true;
        let copy_len = label.len().min(32);
        res.label[..copy_len].copy_from_slice(&label[..copy_len]);
        res.label_len = copy_len;

        self.reserved[self.reserved_count] = res;
        self.reserved_count += 1;

        let reserved_pages = size / PAGE_SIZE;
        self.total_reserved_pages += reserved_pages;
        self.stats.total_reserved_bytes += size;
        self.stats.reserved_count += 1;

        Ok(())
    }

    /// Phase 2: Initialise the page allocator.
    ///
    /// Creates memory zones and hands free pages to the bitmap/buddy
    /// allocator.
    pub fn init_page_alloc(&mut self) -> Result<()> {
        if self.phase != InitPhase::Early {
            return Err(Error::Busy);
        }

        // Build zone metadata.
        self.build_zones()?;

        // Mark all usable regions as processed.
        for r in &mut self.regions[..self.region_count] {
            if r.is_usable() {
                r.processed = true;
            }
        }

        let free_pages = self
            .total_usable_pages
            .saturating_sub(self.total_reserved_pages);
        self.stats.page_alloc_pages = free_pages;

        self.phase = InitPhase::PageAlloc;
        Ok(())
    }

    /// Phase 3: Bootstrap the slab allocator.
    ///
    /// The slab allocator consumes a small number of pages from the
    /// page allocator for its initial caches.
    pub fn init_slab(&mut self) -> Result<()> {
        if self.phase != InitPhase::PageAlloc {
            return Err(Error::Busy);
        }

        let free_pages = self.stats.page_alloc_pages;
        if free_pages < MIN_SLAB_PAGES {
            return Err(Error::OutOfMemory);
        }

        // Reserve pages for initial slab caches (stubbed).
        let slab_pages = MIN_SLAB_PAGES;
        self.stats.slab_bootstrap_pages = slab_pages;
        self.stats.page_alloc_pages -= slab_pages;

        self.phase = InitPhase::Slab;
        Ok(())
    }

    /// Phase 4: Initialise the vmalloc subsystem.
    pub fn init_vmalloc(&mut self) -> Result<()> {
        if self.phase != InitPhase::Slab {
            return Err(Error::Busy);
        }

        if self.stats.page_alloc_pages < MIN_VMALLOC_PAGES {
            return Err(Error::OutOfMemory);
        }

        let vmalloc_pages = MIN_VMALLOC_PAGES;
        self.stats.vmalloc_pages = vmalloc_pages;
        self.stats.page_alloc_pages -= vmalloc_pages;

        self.phase = InitPhase::Vmalloc;
        Ok(())
    }

    /// Phase 5: Mark initialisation as complete.
    ///
    /// After this point, the early allocator is retired and all memory
    /// management subsystems are fully operational.
    pub fn init_complete(&mut self) -> Result<()> {
        if self.phase != InitPhase::Vmalloc {
            return Err(Error::Busy);
        }

        self.phase = InitPhase::Complete;
        Ok(())
    }

    /// Returns the current initialisation phase.
    pub const fn phase(&self) -> InitPhase {
        self.phase
    }

    /// Returns the initialisation configuration.
    pub const fn config(&self) -> &InitConfig {
        &self.config
    }

    /// Returns a snapshot of initialisation statistics.
    pub const fn stats(&self) -> &InitStats {
        &self.stats
    }

    /// Returns the total number of usable pages.
    pub const fn total_usable_pages(&self) -> u64 {
        self.total_usable_pages
    }

    /// Returns the total number of reserved pages.
    pub const fn total_reserved_pages(&self) -> u64 {
        self.total_reserved_pages
    }

    /// Returns the number of firmware regions.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    /// Returns the number of reserved regions.
    pub const fn reserved_count(&self) -> usize {
        self.reserved_count
    }

    /// Returns the number of active zones.
    pub const fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Get zone info by index.
    pub fn zone(&self, index: usize) -> Result<&ZoneInfo> {
        if index >= self.zone_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[index])
    }

    /// Returns `true` if initialisation is complete.
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, InitPhase::Complete)
    }

    /// Returns free pages remaining after all init allocations.
    pub const fn remaining_free_pages(&self) -> u64 {
        self.stats.page_alloc_pages
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Build zone metadata from firmware regions.
    fn build_zones(&mut self) -> Result<()> {
        // Zone 0: DMA (0 .. 16 MiB)
        self.create_zone(0, 0, DMA_ZONE_LIMIT)?;
        // Zone 1: DMA32 (16 MiB .. 4 GiB)
        self.create_zone(1, DMA_ZONE_LIMIT, DMA32_ZONE_LIMIT)?;
        // Zone 2: Normal (4 GiB .. max)
        let max_addr = self.max_usable_address();
        if max_addr > DMA32_ZONE_LIMIT {
            self.create_zone(2, DMA32_ZONE_LIMIT, max_addr)?;
        }

        Ok(())
    }

    /// Create a zone spanning [start, end).
    fn create_zone(&mut self, zone_index: u8, start: u64, end: u64) -> Result<()> {
        if self.zone_count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }

        let aligned_start = align_down(start, ZONE_ALIGN);
        let aligned_end = align_up(end, ZONE_ALIGN);

        // Count usable pages in this zone.
        let mut nr_pages = 0u64;
        let mut nr_reserved = 0u64;
        for r in &self.regions[..self.region_count] {
            let overlap_start = r.base.max(aligned_start);
            let overlap_end = r.end().min(aligned_end);
            if overlap_start < overlap_end {
                let overlap_pages = (overlap_end - overlap_start) / PAGE_SIZE;
                if r.is_usable() {
                    nr_pages += overlap_pages;
                } else {
                    nr_reserved += overlap_pages;
                }
            }
        }

        // Count reserved region overlap.
        for r in &self.reserved[..self.reserved_count] {
            if !r.active {
                continue;
            }
            let overlap_start = r.base.max(aligned_start);
            let overlap_end = r.end().min(aligned_end);
            if overlap_start < overlap_end {
                let overlap_pages = (overlap_end - overlap_start) / PAGE_SIZE;
                nr_reserved += overlap_pages;
            }
        }

        let zone = &mut self.zones[self.zone_count];
        zone.zone_index = zone_index;
        zone.start = aligned_start;
        zone.end = aligned_end;
        zone.nr_pages = nr_pages;
        zone.nr_reserved = nr_reserved;
        zone.watermark_low = self.config.watermark_low;
        zone.watermark_high = self.config.watermark_high;
        zone.active = true;

        self.zone_count += 1;
        self.stats.zones_created += 1;
        Ok(())
    }

    /// Find the highest usable physical address.
    fn max_usable_address(&self) -> u64 {
        let mut max = 0u64;
        for r in &self.regions[..self.region_count] {
            if r.is_usable() && r.end() > max {
                max = r.end();
            }
        }
        max
    }

    /// Sort regions by base address (insertion sort).
    fn sort_regions(&mut self) {
        let n = self.region_count;
        for i in 1..n {
            let mut j = i;
            while j > 0 && self.regions[j].base < self.regions[j - 1].base {
                self.regions.swap(j, j - 1);
                j -= 1;
            }
        }
    }
}

// ── Utility functions ───────────────────────────────────────────────────────

/// Align `addr` down to the nearest multiple of `align`.
const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// Align `addr` up to the nearest multiple of `align`.
const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

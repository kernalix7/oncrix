// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVDIMM (Non-Volatile DIMM) persistent memory driver.
//!
//! Provides access to byte-addressable persistent memory (PMEM) exposed
//! by NVDIMM hardware. Supports region/namespace management and direct
//! memory-mapped I/O for persistent data storage.
//!
//! # Architecture
//!
//! - **NvdimmRegion** — a physical persistent memory region exposed by
//!   firmware (e.g., ACPI NFIT). Regions may be interleaved across
//!   multiple DIMMs.
//! - **NvdimmNamespace** — a logical partition within a region, analogous
//!   to a partition on a disk. Namespaces can operate in raw, sector,
//!   DAX, or filesystem-DAX modes.
//! - **DaxMapping** — a direct-access mapping that bypasses the page cache,
//!   allowing user space to `mmap` persistent memory directly.
//! - **NvdimmSmartData** — SMART-like health attributes: temperature,
//!   remaining life, unsafe shutdown count, media errors.
//! - **NvdimmDevice** — represents a single NVDIMM with its regions,
//!   namespaces, and health/flush capabilities.
//! - **NvdimmSubsystem** — manages up to [`MAX_DEVICES`] devices.
//!
//! # Persistence Primitives
//!
//! Three x86_64 cache-flush instructions are abstracted:
//! - `clflush_line` — invalidate and flush a single cache line (addr).
//! - `clwb_line` — write-back without invalidation (addr), preferred.
//! - `pmem_flush_range` — flush every cache line in `[addr, addr+size)`.
//!
//! Always follow a flush sequence with `sfence` before considering
//! data durable on the persistent medium.
//!
//! # References
//!
//! - ACPI 6.4, §5.2.25 (NVDIMM Firmware Interface Table — NFIT)
//! - UEFI 2.9, §13.6 (Block Translation Table)
//! - Intel Architecture Software Developer's Manual, Vol. 1, §11.12 (CLWB/CLFLUSH)
//! - JEDEC Standard No. 238A: NVDIMM-P (Health status attributes)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NVDIMM devices in the registry.
const MAX_NVDIMMS: usize = 8;

/// Maximum regions per NVDIMM device.
const MAX_REGIONS: usize = 8;

/// Maximum namespaces per NVDIMM device.
const MAX_NAMESPACES: usize = 16;

/// Maximum DAX mappings per device.
const MAX_DAX_MAPPINGS: usize = 16;

/// Label size in bytes.
const LABEL_SIZE: usize = 64;

/// UUID size in bytes.
const UUID_SIZE: usize = 16;

/// x86_64 cache line size in bytes (64 bytes for all current Intel/AMD processors).
pub const CACHE_LINE_SIZE: u64 = 64;

/// Maximum number of namespace resize history entries (informational).
const MAX_NS_EVENTS: usize = 8;

// ---------------------------------------------------------------------------
// NvdimmType
// ---------------------------------------------------------------------------

/// Type of NVDIMM access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvdimmType {
    /// Persistent memory (byte-addressable, load/store access).
    #[default]
    Pmem,
    /// Block-mode access (via BIOS block window).
    Block,
    /// Byte-addressable aperture (control region).
    Byte,
}

// ---------------------------------------------------------------------------
// NvdimmHealth
// ---------------------------------------------------------------------------

/// Health status of an NVDIMM device or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvdimmHealth {
    /// Device is healthy and operating normally.
    #[default]
    Ok,
    /// Device is degraded but still functional.
    Degraded,
    /// Device has failed or is not responding.
    Failed,
    /// Health status is unknown.
    Unknown,
}

// ---------------------------------------------------------------------------
// NamespaceMode
// ---------------------------------------------------------------------------

/// Operating mode of an NVDIMM namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamespaceMode {
    /// Raw mode — no metadata, direct access to persistent memory.
    #[default]
    Raw,
    /// Sector mode — 4 KiB atomic sector writes with BTT.
    Sector,
    /// DAX mode — direct access mapping for `mmap`.
    Dax,
    /// Filesystem-DAX — filesystem with direct access support.
    Fsdax,
}

// ---------------------------------------------------------------------------
// NvdimmSmartData
// ---------------------------------------------------------------------------

/// SMART-like health attributes for an NVDIMM device.
///
/// These fields mirror attributes reported by the NVDIMM firmware
/// via the ACPI DSM (_DSM) Get Smart and Health Info function
/// (DSM function index 0x02 in the NVDIMM root device namespace).
///
/// Values are populated by reading firmware/NFIT data during init.
/// All temperature values are in Celsius (raw), remaining life is
/// 0–100 (percentage of endurance used), counts are monotonically
/// increasing 32-bit counters.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmSmartData {
    /// Current media temperature in tenths of a degree Celsius
    /// (e.g., 250 = 25.0 °C). `u16::MAX` means unavailable.
    pub media_temp: u16,
    /// Controller temperature in tenths of a degree Celsius.
    /// `u16::MAX` means unavailable.
    pub ctrl_temp: u16,
    /// Remaining endurance as a percentage (0 = fully worn out,
    /// 100 = new). `u8::MAX` means unavailable.
    pub remaining_life_pct: u8,
    /// Number of unsafe (unclean) shutdowns since manufacture.
    pub unsafe_shutdowns: u32,
    /// Total number of media error events logged by firmware.
    pub media_errors: u32,
    /// Number of write cycles the device has sustained.
    pub write_cycles: u64,
    /// Health flags bitmask (vendor-specific; 0 = no issues).
    pub health_flags: u32,
    /// Whether health data has been populated from firmware.
    pub valid: bool,
}

impl NvdimmSmartData {
    /// Returns a zeroed, invalid SMART data record.
    pub const fn invalid() -> Self {
        Self {
            media_temp: u16::MAX,
            ctrl_temp: u16::MAX,
            remaining_life_pct: u8::MAX,
            unsafe_shutdowns: 0,
            media_errors: 0,
            write_cycles: 0,
            health_flags: 0,
            valid: false,
        }
    }

    /// Returns `true` if the media temperature reading is available.
    pub const fn has_media_temp(&self) -> bool {
        self.media_temp != u16::MAX
    }

    /// Returns `true` if remaining life data is available.
    pub const fn has_remaining_life(&self) -> bool {
        self.remaining_life_pct != u8::MAX
    }

    /// Returns the media temperature in whole degrees Celsius,
    /// or `None` if the reading is unavailable.
    pub const fn media_temp_celsius(&self) -> Option<i32> {
        if self.media_temp == u16::MAX {
            None
        } else {
            Some(self.media_temp as i32 / 10)
        }
    }

    /// Returns `true` if any critical health flag is set.
    pub const fn is_critical(&self) -> bool {
        self.health_flags != 0
    }
}

// ---------------------------------------------------------------------------
// NamespaceEvent
// ---------------------------------------------------------------------------

/// A recorded namespace lifecycle event (create, delete, resize).
#[derive(Debug, Clone, Copy)]
pub struct NamespaceEvent {
    /// Namespace identifier affected.
    pub ns_id: u32,
    /// Event kind.
    pub kind: NsEventKind,
    /// Size after the event (bytes). For deletion, records the
    /// pre-deletion size.
    pub size_after: u64,
}

/// Kind of namespace lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsEventKind {
    /// Namespace was created.
    Created,
    /// Namespace was deleted.
    Deleted,
    /// Namespace was resized.
    Resized,
    /// Namespace mode was changed.
    ModeChanged,
}

// ---------------------------------------------------------------------------
// NvdimmRegion
// ---------------------------------------------------------------------------

/// A physical persistent memory region.
///
/// Regions are discovered via firmware tables (e.g., ACPI NFIT) and
/// represent contiguous ranges of persistent memory that may span
/// multiple interleaved DIMMs.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmRegion {
    /// Region identifier.
    pub id: u32,
    /// Physical base address of the region.
    pub base_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Access type for this region.
    pub nvdimm_type: NvdimmType,
    /// Number of interleave ways (1 = no interleaving).
    pub interleave_ways: u32,
    /// Health status of this region.
    pub health: NvdimmHealth,
    /// Whether this region is active.
    pub active: bool,
}

impl NvdimmRegion {
    /// Creates a new persistent memory region.
    pub const fn new(id: u32, base_addr: u64, size: u64, nvdimm_type: NvdimmType) -> Self {
        Self {
            id,
            base_addr,
            size,
            nvdimm_type,
            interleave_ways: 1,
            health: NvdimmHealth::Ok,
            active: true,
        }
    }

    /// Returns the end address (exclusive) of this region.
    pub const fn end_addr(&self) -> u64 {
        self.base_addr + self.size
    }

    /// Checks whether an address falls within this region.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base_addr && addr < self.end_addr()
    }

    /// Returns `true` if this region supports DAX-mode namespaces.
    ///
    /// Only PMEM-type regions support byte-addressable DAX access.
    pub const fn supports_dax(&self) -> bool {
        matches!(self.nvdimm_type, NvdimmType::Pmem)
    }
}

// ---------------------------------------------------------------------------
// NvdimmNamespace
// ---------------------------------------------------------------------------

/// A logical namespace within a persistent memory region.
///
/// Namespaces partition a region into independently addressable
/// units, each with its own label, UUID, and operating mode.
/// In DAX or Fsdax mode the namespace's physical address range
/// can be mapped directly into a process's virtual address space,
/// bypassing the page cache entirely.
#[derive(Debug, Clone, Copy)]
pub struct NvdimmNamespace {
    /// Namespace identifier.
    pub id: u32,
    /// Region that contains this namespace.
    pub region_id: u32,
    /// Byte offset within the parent region.
    pub offset: u64,
    /// Size of the namespace in bytes.
    pub size: u64,
    /// Human-readable label (null-padded).
    pub label: [u8; LABEL_SIZE],
    /// Number of valid bytes in [`label`](Self::label).
    pub label_len: usize,
    /// Universally unique identifier.
    pub uuid: [u8; UUID_SIZE],
    /// Operating mode.
    pub mode: NamespaceMode,
    /// Whether this namespace is active.
    pub active: bool,
    /// Whether a DAX mmap is currently outstanding for this namespace.
    pub dax_mapped: bool,
}

impl NvdimmNamespace {
    /// Creates a new namespace within the given region.
    pub const fn new(id: u32, region_id: u32, offset: u64, size: u64) -> Self {
        Self {
            id,
            region_id,
            offset,
            size,
            label: [0u8; LABEL_SIZE],
            label_len: 0,
            uuid: [0u8; UUID_SIZE],
            mode: NamespaceMode::Raw,
            active: true,
            dax_mapped: false,
        }
    }

    /// Sets the label from a byte slice, truncating to [`LABEL_SIZE`].
    pub fn set_label(&mut self, name: &[u8]) {
        let copy_len = name.len().min(LABEL_SIZE);
        self.label[..copy_len].copy_from_slice(&name[..copy_len]);
        if copy_len < LABEL_SIZE {
            self.label[copy_len..].fill(0);
        }
        self.label_len = copy_len;
    }

    /// Sets the UUID.
    pub fn set_uuid(&mut self, uuid: &[u8; UUID_SIZE]) {
        self.uuid = *uuid;
    }

    /// Returns `true` if this namespace supports DAX direct access.
    pub const fn is_dax_capable(&self) -> bool {
        matches!(self.mode, NamespaceMode::Dax | NamespaceMode::Fsdax)
    }

    /// Computes the physical address of the start of this namespace
    /// given the base address of its parent region.
    pub const fn phys_addr(&self, region_base: u64) -> u64 {
        region_base + self.offset
    }

    /// Resizes the namespace to `new_size`.
    ///
    /// Returns [`Error::InvalidArgument`] if the new size is zero or
    /// would overflow a u64.  The caller is responsible for ensuring
    /// the new size fits within the parent region.
    pub fn resize(&mut self, new_size: u64) -> Result<()> {
        if new_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.dax_mapped {
            // Cannot resize while a DAX mapping is active.
            return Err(Error::Busy);
        }
        self.size = new_size;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DaxMapping
// ---------------------------------------------------------------------------

/// A direct-access (DAX) mapping that bypasses the page cache.
///
/// DAX mappings allow user-space processes to `mmap` persistent memory
/// directly, enabling load/store access without any file-system or
/// block-layer overhead.
///
/// # DAX mmap protocol
///
/// 1. Caller requests a DAX mapping via [`NvdimmDevice::create_dax_mapping`].
/// 2. The kernel virtual memory subsystem maps `phys_addr` into the
///    process VA space at `virtual_addr` with no intermediate page cache.
/// 3. On write, stores go directly to NVDIMM media; they become durable
///    only after [`NvdimmDevice::flush`] or [`NvdimmDevice::persist`].
/// 4. Caller removes the mapping via [`NvdimmDevice::remove_dax_mapping`].
#[derive(Debug, Clone, Copy)]
pub struct DaxMapping {
    /// Virtual address of the mapping.
    pub virtual_addr: u64,
    /// Physical address of the backing persistent memory.
    pub phys_addr: u64,
    /// Size of the mapping in bytes.
    pub size: u64,
    /// Namespace identifier this mapping covers.
    pub ns_id: u32,
    /// Whether this mapping is active.
    pub active: bool,
}

impl DaxMapping {
    /// Creates a new DAX mapping.
    pub const fn new(virtual_addr: u64, phys_addr: u64, size: u64, ns_id: u32) -> Self {
        Self {
            virtual_addr,
            phys_addr,
            size,
            ns_id,
            active: true,
        }
    }

    /// Returns the end virtual address (exclusive).
    pub const fn virtual_end(&self) -> u64 {
        self.virtual_addr + self.size
    }

    /// Checks whether a virtual address falls within this mapping.
    pub const fn contains_virtual(&self, addr: u64) -> bool {
        addr >= self.virtual_addr && addr < self.virtual_end()
    }

    /// Translates a virtual address to the corresponding physical address.
    ///
    /// Returns [`None`] if the address is outside this mapping.
    pub const fn translate(&self, vaddr: u64) -> Option<u64> {
        if self.contains_virtual(vaddr) {
            Some(self.phys_addr + (vaddr - self.virtual_addr))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Cache-flush primitives
// ---------------------------------------------------------------------------

/// Flush a single cache line containing `addr` to persistent media using
/// `CLFLUSH` (invalidate + write-back).
///
/// On non-x86_64 targets this is a no-op — callers must provide their
/// own architecture-specific flush primitive.
///
/// # Safety
///
/// `addr` must be a valid virtual address that is currently mapped.
/// The caller must ensure the address is within a persistent memory
/// region before relying on durability.
#[inline]
pub unsafe fn clflush_line(addr: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: CLFLUSH with a valid mapped address. Invalidates and
        // flushes the cache line to memory. The address is passed in
        // via a register operand so no load occurs.
        core::arch::asm!(
            "clflush [{addr}]",
            addr = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = addr;
}

/// Write-back a single cache line containing `addr` without invalidation
/// using `CLWB`.
///
/// Preferred over `CLFLUSH` for NVDIMM workloads — leaves the line
/// in the cache as clean, reducing subsequent read latency.
///
/// # Safety
///
/// `addr` must be a valid virtual address that is currently mapped.
#[inline]
pub unsafe fn clwb_line(addr: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: CLWB writes back the cache line at addr without
        // eviction. CPUID must confirm CLWB support (leaf 7, ECX bit 24)
        // before use; the caller is responsible for that check.
        core::arch::asm!(
            "clwb [{addr}]",
            addr = in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = addr;
}

/// Store fence (`SFENCE`) — orders all preceding stores before
/// subsequent stores or loads.
///
/// Must be issued after a sequence of `clflush_line` / `clwb_line`
/// calls to guarantee that data has reached the persistent medium.
#[inline]
pub fn sfence() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: SFENCE is a serialising store fence with no memory operand.
    // It does not read or write any user-visible memory.
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags));
    }
}

/// Flush every cache line covering the byte range `[addr, addr + size)`.
///
/// Iterates over cache lines at [`CACHE_LINE_SIZE`]-byte intervals,
/// calling [`clwb_line`] for each, then issues a final [`sfence`].
///
/// # Safety
///
/// The entire range `[addr, addr + size)` must be mapped and within
/// a valid persistent memory region. `addr` and `size` must not wrap
/// around the 64-bit address space.
pub unsafe fn pmem_flush_range(addr: u64, size: u64) {
    if size == 0 {
        return;
    }
    let end = addr.saturating_add(size);
    // Align start down to cache-line boundary.
    let start = addr & !(CACHE_LINE_SIZE - 1);
    let mut cur = start;
    while cur < end {
        // SAFETY: caller guarantees [addr, addr+size) is a valid mapped
        // range; `cur` is always within or adjacent to that range.
        unsafe { clwb_line(cur) };
        cur = cur.saturating_add(CACHE_LINE_SIZE);
    }
    sfence();
}

// ---------------------------------------------------------------------------
// NvdimmDevice
// ---------------------------------------------------------------------------

/// An NVDIMM persistent memory device.
///
/// Represents a single NVDIMM with its regions, namespaces, DAX
/// mappings, and health/flush capabilities.
pub struct NvdimmDevice {
    /// Device identifier.
    pub id: u32,
    /// Persistent memory regions.
    regions: [Option<NvdimmRegion>; MAX_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Namespaces.
    namespaces: [Option<NvdimmNamespace>; MAX_NAMESPACES],
    /// Number of active namespaces.
    namespace_count: usize,
    /// DAX mappings.
    dax_mappings: [Option<DaxMapping>; MAX_DAX_MAPPINGS],
    /// Number of active DAX mappings.
    dax_mapping_count: usize,
    /// Overall device health.
    pub health: NvdimmHealth,
    /// SMART health attributes.
    pub smart: NvdimmSmartData,
    /// Namespace event log (ring-buffer, last N events).
    ns_events: [Option<NamespaceEvent>; MAX_NS_EVENTS],
    /// Next write position in the event ring.
    ns_event_head: usize,
    /// Total events recorded (may exceed MAX_NS_EVENTS).
    ns_event_total: usize,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl NvdimmDevice {
    /// Creates a new NVDIMM device.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            regions: [const { None }; MAX_REGIONS],
            region_count: 0,
            namespaces: [const { None }; MAX_NAMESPACES],
            namespace_count: 0,
            dax_mappings: [const { None }; MAX_DAX_MAPPINGS],
            dax_mapping_count: 0,
            health: NvdimmHealth::Ok,
            smart: NvdimmSmartData::invalid(),
            ns_events: [const { None }; MAX_NS_EVENTS],
            ns_event_head: 0,
            ns_event_total: 0,
            initialized: false,
        }
    }

    /// Initializes the NVDIMM device.
    ///
    /// This should be called after regions and namespaces have been
    /// configured from firmware tables.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::Busy);
        }
        self.health = NvdimmHealth::Ok;
        self.initialized = true;
        Ok(())
    }

    /// Returns whether the device is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- Region management -------------------------------------------------

    /// Adds a persistent memory region to this device.
    pub fn add_region(&mut self, region: NvdimmRegion) -> Result<()> {
        // Check for duplicate region ID.
        for slot in &self.regions {
            if let Some(ref r) = *slot {
                if r.id == region.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.regions {
            if slot.is_none() {
                *slot = Some(region);
                self.region_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to the region with the given `id`.
    pub fn get_region(&self, id: u32) -> Option<&NvdimmRegion> {
        self.regions.iter().flatten().find(|r| r.id == id)
    }

    /// Returns the number of active regions.
    pub const fn region_count(&self) -> usize {
        self.region_count
    }

    // -- Namespace management -----------------------------------------------

    /// Adds a namespace to this device.
    ///
    /// The namespace's `region_id` must refer to a region that has
    /// already been added to this device.
    pub fn add_namespace(&mut self, ns: NvdimmNamespace) -> Result<()> {
        // Verify region exists.
        if self.get_region(ns.region_id).is_none() {
            return Err(Error::NotFound);
        }
        // Check for duplicate namespace ID.
        for slot in &self.namespaces {
            if let Some(ref n) = *slot {
                if n.id == ns.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        let free_idx = self.namespaces.iter().position(|s| s.is_none());
        match free_idx {
            Some(idx) => {
                let ns_id = ns.id;
                let ns_size = ns.size;
                self.namespaces[idx] = Some(ns);
                self.namespace_count += 1;
                self.record_ns_event(NamespaceEvent {
                    ns_id,
                    kind: NsEventKind::Created,
                    size_after: ns_size,
                });
                Ok(())
            }
            None => Err(Error::OutOfMemory),
        }
    }

    /// Deletes the namespace with the given `id`.
    ///
    /// Returns [`Error::Busy`] if a DAX mapping is active for the namespace.
    /// Returns [`Error::NotFound`] if no namespace with that id exists.
    pub fn delete_namespace(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.namespaces {
            if let Some(ref ns) = *slot {
                if ns.id == id {
                    if ns.dax_mapped {
                        return Err(Error::Busy);
                    }
                    let old_size = ns.size;
                    *slot = None;
                    self.namespace_count = self.namespace_count.saturating_sub(1);
                    self.record_ns_event(NamespaceEvent {
                        ns_id: id,
                        kind: NsEventKind::Deleted,
                        size_after: old_size,
                    });
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Resizes the namespace with the given `id` to `new_size` bytes.
    ///
    /// The caller must ensure `new_size` fits within the parent region.
    /// Returns [`Error::Busy`] if a DAX mapping is active.
    pub fn resize_namespace(&mut self, id: u32, new_size: u64) -> Result<()> {
        for slot in &mut self.namespaces {
            if let Some(ref mut ns) = *slot {
                if ns.id == id {
                    ns.resize(new_size)?;
                    self.record_ns_event(NamespaceEvent {
                        ns_id: id,
                        kind: NsEventKind::Resized,
                        size_after: new_size,
                    });
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Changes the operating mode of the namespace with the given `id`.
    ///
    /// Returns [`Error::Busy`] if a DAX mapping is active for the namespace.
    pub fn set_namespace_mode(&mut self, id: u32, mode: NamespaceMode) -> Result<()> {
        // Find the namespace index and extract data needed for
        // validation before taking a mutable borrow.
        let idx = self
            .namespaces
            .iter()
            .position(|s| s.as_ref().is_some_and(|n| n.id == id))
            .ok_or(Error::NotFound)?;
        let ns = self.namespaces[idx].as_ref().ok_or(Error::NotFound)?;
        if ns.dax_mapped {
            return Err(Error::Busy);
        }
        let region_id = ns.region_id;
        let ns_size = ns.size;
        // Validate DAX mode requires a PMEM-capable region.
        if matches!(mode, NamespaceMode::Dax | NamespaceMode::Fsdax) {
            let region_ok = self
                .regions
                .iter()
                .flatten()
                .any(|r| r.id == region_id && r.supports_dax());
            if !region_ok {
                return Err(Error::InvalidArgument);
            }
        }
        // Now take the mutable reference and apply changes.
        if let Some(ref mut ns) = self.namespaces[idx] {
            ns.mode = mode;
        }
        self.record_ns_event(NamespaceEvent {
            ns_id: id,
            kind: NsEventKind::ModeChanged,
            size_after: ns_size,
        });
        Ok(())
    }

    /// Returns a reference to the namespace with the given `id`.
    pub fn get_namespace(&self, id: u32) -> Option<&NvdimmNamespace> {
        self.namespaces.iter().flatten().find(|n| n.id == id)
    }

    /// Returns the number of active namespaces.
    pub const fn namespace_count(&self) -> usize {
        self.namespace_count
    }

    // -- DAX mapping management ---------------------------------------------

    /// Creates a DAX mapping for direct access to persistent memory.
    ///
    /// The namespace identified by `mapping.ns_id` must exist, must be
    /// in DAX or Fsdax mode, and must not already have a mapping active.
    /// On success the namespace's `dax_mapped` flag is set.
    pub fn create_dax_mapping(&mut self, mapping: DaxMapping) -> Result<()> {
        // Validate the target namespace (immutable borrow released before
        // the mutable loop below).
        {
            let ns = self
                .namespaces
                .iter()
                .flatten()
                .find(|n| n.id == mapping.ns_id)
                .ok_or(Error::NotFound)?;
            if !ns.is_dax_capable() {
                return Err(Error::InvalidArgument);
            }
            if ns.dax_mapped {
                return Err(Error::AlreadyExists);
            }
        }

        // Find an empty slot.
        for slot in &mut self.dax_mappings {
            if slot.is_none() {
                *slot = Some(mapping);
                self.dax_mapping_count += 1;
                // Mark namespace as mapped.
                for ns_slot in &mut self.namespaces {
                    if let Some(ref mut ns) = *ns_slot {
                        if ns.id == mapping.ns_id {
                            ns.dax_mapped = true;
                            break;
                        }
                    }
                }
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the DAX mapping for namespace `ns_id`.
    ///
    /// Clears the namespace's `dax_mapped` flag on success.
    /// Returns [`Error::NotFound`] if no mapping exists for `ns_id`.
    pub fn remove_dax_mapping(&mut self, ns_id: u32) -> Result<()> {
        let mut found = false;
        for slot in &mut self.dax_mappings {
            if let Some(ref m) = *slot {
                if m.ns_id == ns_id {
                    *slot = None;
                    self.dax_mapping_count = self.dax_mapping_count.saturating_sub(1);
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(Error::NotFound);
        }
        // Clear the namespace mapped flag.
        for ns_slot in &mut self.namespaces {
            if let Some(ref mut ns) = *ns_slot {
                if ns.id == ns_id {
                    ns.dax_mapped = false;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Adds a raw DAX mapping entry (legacy helper, bypasses namespace checks).
    ///
    /// Prefer [`create_dax_mapping`](Self::create_dax_mapping) for new code.
    pub fn add_dax_mapping(&mut self, mapping: DaxMapping) -> Result<()> {
        for slot in &mut self.dax_mappings {
            if slot.is_none() {
                *slot = Some(mapping);
                self.dax_mapping_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the DAX mapping that contains the given virtual address.
    pub fn find_dax_mapping(&self, vaddr: u64) -> Option<&DaxMapping> {
        self.dax_mappings
            .iter()
            .flatten()
            .find(|m| m.active && m.contains_virtual(vaddr))
    }

    /// Returns the number of active DAX mappings.
    pub const fn dax_mapping_count(&self) -> usize {
        self.dax_mapping_count
    }

    // -- Persistence operations ---------------------------------------------

    /// Flushes a cache line range to ensure data reaches persistent media.
    ///
    /// Uses `CLWB` + `SFENCE` on x86_64 for minimal cache disruption.
    /// The address must fall within a known active region.
    pub fn flush(&self, addr: u64, size: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Verify the address falls within a known region.
        let in_region = self
            .regions
            .iter()
            .flatten()
            .any(|r| r.active && r.contains(addr));
        if !in_region {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: addr is confirmed to lie within a valid, active persistent
        // memory region. The range [addr, addr+size) is safe to flush.
        unsafe { pmem_flush_range(addr, size) };
        Ok(())
    }

    /// Persists all outstanding writes to this device.
    ///
    /// Equivalent to flushing the entire address range of all
    /// active regions.
    pub fn persist(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        for region in self.regions.iter().flatten() {
            if region.active && region.size > 0 {
                self.flush(region.base_addr, region.size)?;
            }
        }
        Ok(())
    }

    // -- Health / SMART monitoring ------------------------------------------

    /// Updates the SMART health attributes for this device.
    ///
    /// In a real driver this would call an ACPI DSM or vendor-specific
    /// NVDIMM command to retrieve the latest health counters.
    /// Callers supply the firmware-provided data via `data`.
    pub fn update_smart(&mut self, data: NvdimmSmartData) {
        self.smart = data;
        // Promote device health if critical flags are set.
        if data.valid && data.is_critical() {
            self.health = NvdimmHealth::Degraded;
        }
    }

    /// Returns a reference to the current SMART data.
    pub const fn smart_data(&self) -> &NvdimmSmartData {
        &self.smart
    }

    /// Performs a health check on this NVDIMM device.
    ///
    /// Inspects all regions and the SMART data; returns the worst
    /// health status found.
    pub fn health_check(&mut self) -> NvdimmHealth {
        let mut worst = NvdimmHealth::Ok;
        for region in self.regions.iter().flatten() {
            if !region.active {
                continue;
            }
            match region.health {
                NvdimmHealth::Failed => {
                    worst = NvdimmHealth::Failed;
                    break; // cannot be worse
                }
                NvdimmHealth::Degraded => {
                    worst = NvdimmHealth::Degraded;
                }
                NvdimmHealth::Unknown if worst == NvdimmHealth::Ok => {
                    worst = NvdimmHealth::Unknown;
                }
                _ => {}
            }
        }
        // Also consider SMART data.
        if worst != NvdimmHealth::Failed && self.smart.valid && self.smart.is_critical() {
            worst = NvdimmHealth::Degraded;
        }
        self.health = worst;
        worst
    }

    /// Returns `true` if remaining life is below `threshold_pct` percent.
    ///
    /// Returns `false` if SMART data is unavailable.
    pub fn life_below_threshold(&self, threshold_pct: u8) -> bool {
        if !self.smart.valid || !self.smart.has_remaining_life() {
            return false;
        }
        self.smart.remaining_life_pct < threshold_pct
    }

    /// Returns the total persistent memory size across all active regions.
    pub fn total_persistent_bytes(&self) -> u64 {
        self.regions
            .iter()
            .flatten()
            .filter(|r| r.active)
            .map(|r| r.size)
            .sum()
    }

    // -- Namespace event log ------------------------------------------------

    /// Records a namespace event in the internal ring buffer.
    fn record_ns_event(&mut self, event: NamespaceEvent) {
        self.ns_events[self.ns_event_head] = Some(event);
        self.ns_event_head = (self.ns_event_head + 1) % MAX_NS_EVENTS;
        self.ns_event_total += 1;
    }

    /// Returns the most recent namespace event, if any.
    pub fn last_ns_event(&self) -> Option<&NamespaceEvent> {
        if self.ns_event_total == 0 {
            return None;
        }
        // The previous write position holds the most recent event.
        let last = (self.ns_event_head + MAX_NS_EVENTS - 1) % MAX_NS_EVENTS;
        self.ns_events[last].as_ref()
    }

    /// Returns the total number of namespace events recorded (may exceed
    /// the ring buffer capacity).
    pub const fn ns_event_count(&self) -> usize {
        self.ns_event_total
    }
}

impl core::fmt::Debug for NvdimmDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NvdimmDevice")
            .field("id", &self.id)
            .field("regions", &self.region_count)
            .field("namespaces", &self.namespace_count)
            .field("dax_mappings", &self.dax_mapping_count)
            .field("health", &self.health)
            .field("initialized", &self.initialized)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// NvdimmRegistry
// ---------------------------------------------------------------------------

/// Registry that manages multiple [`NvdimmDevice`] instances.
///
/// Supports up to [`MAX_NVDIMMS`] concurrently registered devices and
/// provides aggregate statistics for total persistent memory.
pub struct NvdimmRegistry {
    /// Registered NVDIMM devices.
    devices: [Option<NvdimmDevice>; MAX_NVDIMMS],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for NvdimmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvdimmRegistry {
    /// Creates a new, empty NVDIMM registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_NVDIMMS],
            count: 0,
        }
    }

    /// Registers an NVDIMM device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, device: NvdimmDevice) -> Result<()> {
        for slot in &self.devices {
            if let Some(ref d) = *slot {
                if d.id == device.id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters the device with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(ref d) = *slot {
                if d.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to the device with the given `id`.
    pub fn find(&self, id: u32) -> Option<&NvdimmDevice> {
        self.devices.iter().flatten().find(|d| d.id == id)
    }

    /// Returns a mutable reference to the device with the given `id`.
    pub fn find_mut(&mut self, id: u32) -> Option<&mut NvdimmDevice> {
        self.devices.iter_mut().flatten().find(|d| d.id == id)
    }

    /// Returns the total persistent memory across all registered devices.
    pub fn total_persistent_bytes(&self) -> u64 {
        self.devices
            .iter()
            .flatten()
            .map(|d| d.total_persistent_bytes())
            .sum()
    }

    /// Returns the number of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

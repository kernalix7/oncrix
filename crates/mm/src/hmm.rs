// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Heterogeneous Memory Management (HMM).
//!
//! HMM provides the infrastructure for unified virtual address space sharing
//! between the CPU and discrete devices (GPUs, FPGAs, accelerators). It allows
//! a device driver to mirror a process's CPU page tables into device-side page
//! tables and to migrate pages between system RAM and device-private memory.
//!
//! # Architecture
//!
//! ```text
//!  Process VAS
//!  ┌──────────┐
//!  │  VMA 1   │──► CPU PTE  ──► DRAM
//!  │  VMA 2   │──► CPU PTE  ──► Device-Private VRAM
//!  │  VMA 3   │──► CPU PTE  ──► DRAM
//!  └──────────┘
//!       │
//!       └─► HmmMirror ──► Device Page Table (driver-managed)
//! ```
//!
//! # Key Types
//!
//! - [`HmmDevice`] — registered heterogeneous device with private memory.
//! - [`HmmMirror`] — per-process mirror associating a VAS with a device.
//! - [`HmmRange`] — a virtual address range under HMM management.
//! - [`HmmPageKind`] — whether a page lives in system RAM or device memory.
//! - [`HmmMigrateDir`] — direction of a page migration.
//! - [`HmmManager`] — global registry of devices and mirrors.
//! - [`HmmStats`] — aggregate HMM statistics.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
pub const HMM_PAGE_SIZE: u64 = 4096;

/// Maximum number of HMM-registered devices.
pub const MAX_HMM_DEVICES: usize = 8;

/// Maximum number of active per-process mirrors.
pub const MAX_HMM_MIRRORS: usize = 16;

/// Maximum number of [`HmmRange`] entries per mirror.
pub const MAX_RANGES_PER_MIRROR: usize = 32;

/// Maximum number of pages in a single migration request.
pub const MAX_MIGRATE_PAGES: usize = 256;

/// Maximum number of device-private page tracking entries.
pub const MAX_DEVICE_PRIVATE_PAGES: usize = 512;

/// Maximum number of pending page-table sync notifications.
pub const MAX_SYNC_NOTIFICATIONS: usize = 64;

/// Sentinel value representing an invalid device identifier.
pub const HMM_INVALID_DEVICE: u32 = u32::MAX;

// -------------------------------------------------------------------
// HmmPageKind
// -------------------------------------------------------------------

/// Describes where a page currently resides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmPageKind {
    /// Page lives in system RAM, accessible by the CPU at normal cost.
    #[default]
    SystemRam,
    /// Page lives in device-private memory (e.g., GPU VRAM).
    DevicePrivate,
    /// Page is currently being migrated and is not accessible.
    Migrating,
    /// Page is not present (demand-paged or swapped).
    NotPresent,
}

// -------------------------------------------------------------------
// HmmMigrateDir
// -------------------------------------------------------------------

/// Direction of a page migration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmMigrateDir {
    /// Move pages from system RAM to device-private memory.
    #[default]
    ToDevice,
    /// Move pages from device-private memory back to system RAM.
    ToCpu,
}

// -------------------------------------------------------------------
// HmmFaultKind
// -------------------------------------------------------------------

/// Type of HMM page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmFaultKind {
    /// CPU-side page fault (device page accessed by CPU).
    #[default]
    Cpu,
    /// Device-side page fault (system RAM page accessed by device).
    Device,
}

// -------------------------------------------------------------------
// HmmPteSyncKind
// -------------------------------------------------------------------

/// Type of CPU page-table change that must be propagated to the
/// device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmPteSyncKind {
    /// A new mapping was established (e.g., page fault resolved).
    #[default]
    Map,
    /// An existing mapping was removed (e.g., munmap).
    Unmap,
    /// Permissions on an existing mapping changed (e.g., mprotect).
    PermChange,
    /// Page was migrated to a different physical location.
    Migrate,
}

// -------------------------------------------------------------------
// HmmPteSyncNotification
// -------------------------------------------------------------------

/// Notification for a single CPU PTE change that the device driver
/// must process.
///
/// These are queued by the MMU notifier path and consumed by the
/// device driver when it synchronises its page tables.
#[derive(Debug, Clone, Copy)]
pub struct HmmPteSyncNotification {
    /// Virtual address affected.
    pub vaddr: u64,
    /// New physical address (0 for unmaps).
    pub new_paddr: u64,
    /// Kind of change.
    pub kind: HmmPteSyncKind,
    /// Whether the new mapping is writable (meaningful only for
    /// `Map` and `PermChange`).
    pub writable: bool,
    /// Device ID this notification targets.
    pub device_id: u32,
    /// Process ID.
    pub pid: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl HmmPteSyncNotification {
    /// An empty, inactive notification slot.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            new_paddr: 0,
            kind: HmmPteSyncKind::Map,
            writable: false,
            device_id: HMM_INVALID_DEVICE,
            pid: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// DevicePrivatePage
// -------------------------------------------------------------------

/// Tracking entry for a page that lives in device-private memory.
///
/// The kernel keeps a shadow entry so it can locate the device page
/// when the CPU attempts to access it (device fault handling).
#[derive(Debug, Clone, Copy)]
pub struct DevicePrivatePage {
    /// Virtual address in the owning process.
    pub vaddr: u64,
    /// Device-side physical address.
    pub device_paddr: u64,
    /// Device that owns this page.
    pub device_id: u32,
    /// Process that owns the virtual mapping.
    pub pid: u32,
    /// Generation counter; incremented on each migration so stale
    /// references can be detected.
    pub generation: u64,
    /// Whether this slot is in use.
    pub active: bool,
}

impl DevicePrivatePage {
    /// An empty, inactive slot.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            device_paddr: 0,
            device_id: HMM_INVALID_DEVICE,
            pid: 0,
            generation: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// HmmBatchMigrateResult
// -------------------------------------------------------------------

/// Summary of a batch migration operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct HmmBatchMigrateResult {
    /// Number of pages successfully migrated.
    pub migrated: u64,
    /// Number of pages that could not be migrated (pinned, etc.).
    pub failed: u64,
}

// -------------------------------------------------------------------
// HmmPageEntry
// -------------------------------------------------------------------

/// State of a single page within an [`HmmRange`].
#[derive(Debug, Clone, Copy)]
pub struct HmmPageEntry {
    /// Virtual address of this page.
    pub vaddr: u64,
    /// Physical address of the page (CPU-side) or device-side physical address.
    pub paddr: u64,
    /// Where the page currently resides.
    pub kind: HmmPageKind,
    /// Whether this page has write permission.
    pub writable: bool,
    /// Whether the device mapping for this page is up-to-date.
    pub device_mapped: bool,
}

impl HmmPageEntry {
    /// Create a new entry for an unmapped page.
    pub const fn unmapped(vaddr: u64) -> Self {
        Self {
            vaddr,
            paddr: 0,
            kind: HmmPageKind::NotPresent,
            writable: false,
            device_mapped: false,
        }
    }
}

// -------------------------------------------------------------------
// HmmRange
// -------------------------------------------------------------------

/// A virtual address range tracked by HMM for a specific device mirror.
///
/// The range covers `[start, end)` in the process virtual address space.
/// HMM maintains a snapshot of page states so the device driver can
/// build its own page tables.
pub struct HmmRange {
    /// Start virtual address (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Device identifier this range is pinned for.
    pub device_id: u32,
    /// Whether this range is currently valid (not invalidated by mmu_notifier).
    pub valid: bool,
    /// Snapshot of page states within this range.
    pages: [HmmPageEntry; MAX_MIGRATE_PAGES],
    /// Number of pages currently tracked.
    page_count: usize,
}

impl HmmRange {
    /// Create a new range covering `[start, end)` for the given device.
    pub fn new(start: u64, end: u64, device_id: u32) -> Result<Self> {
        if end <= start || start % HMM_PAGE_SIZE != 0 || end % HMM_PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let pages = (end - start) / HMM_PAGE_SIZE;
        if pages as usize > MAX_MIGRATE_PAGES {
            return Err(Error::InvalidArgument);
        }
        let mut range = Self {
            start,
            end,
            device_id,
            valid: true,
            pages: [HmmPageEntry::unmapped(0); MAX_MIGRATE_PAGES],
            page_count: pages as usize,
        };
        for i in 0..range.page_count {
            range.pages[i] = HmmPageEntry::unmapped(start + i as u64 * HMM_PAGE_SIZE);
        }
        Ok(range)
    }

    /// Number of pages in this range.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Invalidate this range (called by mmu_notifier on CPU page table changes).
    pub fn invalidate(&mut self) {
        self.valid = false;
        for entry in &mut self.pages[..self.page_count] {
            entry.device_mapped = false;
        }
    }

    /// Update the state of a page within this range.
    ///
    /// `vaddr` must be within `[self.start, self.end)` and page-aligned.
    pub fn update_page(
        &mut self,
        vaddr: u64,
        paddr: u64,
        kind: HmmPageKind,
        writable: bool,
    ) -> Result<()> {
        if vaddr < self.start || vaddr >= self.end || vaddr % HMM_PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = ((vaddr - self.start) / HMM_PAGE_SIZE) as usize;
        self.pages[idx] = HmmPageEntry {
            vaddr,
            paddr,
            kind,
            writable,
            device_mapped: false,
        };
        Ok(())
    }

    /// Mark all pages in the range as device-mapped.
    pub fn mark_device_mapped(&mut self) {
        for entry in &mut self.pages[..self.page_count] {
            entry.device_mapped = true;
        }
    }

    /// Return a slice over the page entries.
    pub fn page_entries(&self) -> &[HmmPageEntry] {
        &self.pages[..self.page_count]
    }

    /// Count pages in system RAM within this range.
    pub fn system_pages(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|e| e.kind == HmmPageKind::SystemRam)
            .count()
    }

    /// Count pages in device-private memory within this range.
    pub fn device_pages(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|e| e.kind == HmmPageKind::DevicePrivate)
            .count()
    }

    /// Count pages currently being migrated within this range.
    pub fn migrating_pages(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|e| e.kind == HmmPageKind::Migrating)
            .count()
    }

    /// Count pages that are not present (demand-paged or swapped).
    pub fn not_present_pages(&self) -> usize {
        self.pages[..self.page_count]
            .iter()
            .filter(|e| e.kind == HmmPageKind::NotPresent)
            .count()
    }

    /// Takes a snapshot of page entries for building a device page
    /// table.
    ///
    /// Copies up to `out.len()` entries into the provided buffer
    /// and returns the number of entries written.
    pub fn snapshot(&self, out: &mut [HmmPageEntry]) -> usize {
        let copy_len = out.len().min(self.page_count);
        out[..copy_len].copy_from_slice(&self.pages[..copy_len]);
        copy_len
    }

    /// Marks the specified range of pages as migrating.
    ///
    /// `start_vaddr` and `end_vaddr` must be within this range
    /// and page-aligned.
    pub fn mark_migrating(&mut self, start_vaddr: u64, end_vaddr: u64) -> Result<usize> {
        if start_vaddr < self.start
            || end_vaddr > self.end
            || start_vaddr >= end_vaddr
            || start_vaddr % HMM_PAGE_SIZE != 0
            || end_vaddr % HMM_PAGE_SIZE != 0
        {
            return Err(Error::InvalidArgument);
        }
        let first = ((start_vaddr - self.start) / HMM_PAGE_SIZE) as usize;
        let last = ((end_vaddr - self.start) / HMM_PAGE_SIZE) as usize;
        let mut count = 0usize;
        for entry in &mut self.pages[first..last] {
            entry.kind = HmmPageKind::Migrating;
            entry.device_mapped = false;
            count += 1;
        }
        Ok(count)
    }
}

// -------------------------------------------------------------------
// HmmDevice
// -------------------------------------------------------------------

/// A heterogeneous device registered with the HMM subsystem.
///
/// Represents a discrete accelerator (GPU, FPGA, etc.) that has its
/// own private physical memory and can share virtual address space
/// with the CPU via HMM.
#[derive(Debug, Clone)]
pub struct HmmDevice {
    /// Unique device identifier assigned by the HMM manager.
    pub id: u32,
    /// Human-readable device name.
    pub name: [u8; 32],
    /// Length of the name string.
    name_len: usize,
    /// Base physical address of device-private memory.
    pub private_mem_base: u64,
    /// Total size of device-private memory in bytes.
    pub private_mem_size: u64,
    /// Amount of free device-private memory in bytes.
    free_device_mem: u64,
    /// Whether this device slot is active.
    pub active: bool,
    /// Number of active mirrors for this device.
    mirror_count: u32,
}

impl HmmDevice {
    /// Create an inactive (placeholder) device.
    const fn inactive() -> Self {
        Self {
            id: HMM_INVALID_DEVICE,
            name: [0u8; 32],
            name_len: 0,
            private_mem_base: 0,
            private_mem_size: 0,
            free_device_mem: 0,
            active: false,
            mirror_count: 0,
        }
    }

    /// Initialise with registration parameters.
    pub fn init(&mut self, id: u32, name: &[u8], private_base: u64, private_size: u64) {
        self.id = id;
        let copy_len = name.len().min(31);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
        self.private_mem_base = private_base;
        self.private_mem_size = private_size;
        self.free_device_mem = private_size;
        self.active = true;
        self.mirror_count = 0;
    }

    /// Allocate `size` bytes from device-private memory.
    ///
    /// Returns the device-side physical address of the allocated region.
    pub fn alloc_private(&mut self, size: u64) -> Result<u64> {
        let aligned = (size + HMM_PAGE_SIZE - 1) & !(HMM_PAGE_SIZE - 1);
        if aligned > self.free_device_mem {
            return Err(Error::OutOfMemory);
        }
        let offset = self.private_mem_size - self.free_device_mem;
        self.free_device_mem -= aligned;
        Ok(self.private_mem_base + offset)
    }

    /// Free `size` bytes back to device-private memory.
    pub fn free_private(&mut self, size: u64) {
        let aligned = (size + HMM_PAGE_SIZE - 1) & !(HMM_PAGE_SIZE - 1);
        self.free_device_mem = (self.free_device_mem + aligned).min(self.private_mem_size);
    }

    /// Free device-private memory in bytes.
    pub fn free_device_mem(&self) -> u64 {
        self.free_device_mem
    }

    /// Return the device name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// -------------------------------------------------------------------
// HmmMirrorState
// -------------------------------------------------------------------

/// State of an [`HmmMirror`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmMirrorState {
    /// Mirror is active and tracking the process VAS.
    #[default]
    Active,
    /// Mirror is being torn down.
    Destroying,
    /// Mirror has been destroyed and may be reused.
    Dead,
}

// -------------------------------------------------------------------
// HmmMirror
// -------------------------------------------------------------------

/// A per-process mirror linking a virtual address space to a device.
///
/// The mirror tracks the set of [`HmmRange`]s that the device driver
/// has expressed interest in. When the CPU page tables change
/// (fork, mprotect, unmap), HMM invalidates the relevant ranges so
/// the driver can update its device-side page tables.
pub struct HmmMirror {
    /// Unique mirror identifier.
    pub id: u32,
    /// Process identifier whose VAS is being mirrored.
    pub pid: u32,
    /// Device this mirror is associated with.
    pub device_id: u32,
    /// Current lifecycle state.
    pub state: HmmMirrorState,
    /// Active ranges under HMM management.
    ranges: [Option<HmmRange>; MAX_RANGES_PER_MIRROR],
    /// Number of active ranges.
    range_count: usize,
    /// Whether this mirror slot is active.
    active: bool,
}

impl HmmMirror {
    /// Create an inactive (placeholder) mirror.
    const fn inactive() -> Self {
        // `Option<HmmRange>` cannot be const-initialized with `Some`, so we
        // use a macro-equivalent expansion.
        Self {
            id: 0,
            pid: 0,
            device_id: HMM_INVALID_DEVICE,
            state: HmmMirrorState::Dead,
            ranges: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            range_count: 0,
            active: false,
        }
    }

    /// Initialise a mirror for process `pid` on device `device_id`.
    pub fn init(&mut self, id: u32, pid: u32, device_id: u32) {
        self.id = id;
        self.pid = pid;
        self.device_id = device_id;
        self.state = HmmMirrorState::Active;
        self.range_count = 0;
        self.active = true;
        for slot in &mut self.ranges {
            *slot = None;
        }
    }

    /// Register a new virtual address range with this mirror.
    pub fn add_range(&mut self, start: u64, end: u64) -> Result<()> {
        if self.range_count >= MAX_RANGES_PER_MIRROR {
            return Err(Error::Busy);
        }
        let range = HmmRange::new(start, end, self.device_id)?;
        // Find the first empty slot.
        for slot in &mut self.ranges {
            if slot.is_none() {
                *slot = Some(range);
                self.range_count += 1;
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Remove the range starting at `start`.
    pub fn remove_range(&mut self, start: u64) -> Result<()> {
        for slot in &mut self.ranges {
            if let Some(r) = slot.as_ref() {
                if r.start == start {
                    *slot = None;
                    self.range_count = self.range_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Invalidate all ranges that overlap with `[start, end)`.
    ///
    /// Called by the mmu_notifier when the CPU page tables change.
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        for slot in &mut self.ranges {
            if let Some(r) = slot.as_mut() {
                // Ranges overlap if r.start < end && r.end > start.
                if r.start < end && r.end > start {
                    r.invalidate();
                }
            }
        }
    }

    /// Update a single page's state within the managed ranges.
    pub fn update_page(
        &mut self,
        vaddr: u64,
        paddr: u64,
        kind: HmmPageKind,
        writable: bool,
    ) -> Result<()> {
        for slot in &mut self.ranges {
            if let Some(r) = slot.as_mut() {
                if vaddr >= r.start && vaddr < r.end {
                    return r.update_page(vaddr, paddr, kind, writable);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Iterate active ranges by calling `f` with a shared reference to each.
    pub fn for_each_range<F>(&self, mut f: F)
    where
        F: FnMut(&HmmRange),
    {
        for slot in &self.ranges {
            if let Some(r) = slot.as_ref() {
                f(r);
            }
        }
    }
}

// -------------------------------------------------------------------
// HmmMigrateRequest
// -------------------------------------------------------------------

/// A request to migrate pages between system RAM and device-private memory.
#[derive(Debug, Clone, Copy)]
pub struct HmmMigrateRequest {
    /// Virtual address range to migrate.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Direction of migration.
    pub direction: HmmMigrateDir,
    /// Device to migrate to/from.
    pub device_id: u32,
    /// Process identifier.
    pub pid: u32,
}

impl HmmMigrateRequest {
    /// Create a new migration request.
    pub fn new(
        start: u64,
        end: u64,
        direction: HmmMigrateDir,
        device_id: u32,
        pid: u32,
    ) -> Result<Self> {
        if end <= start || start % HMM_PAGE_SIZE != 0 || end % HMM_PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            direction,
            device_id,
            pid,
        })
    }

    /// Number of pages covered by this request.
    pub fn page_count(&self) -> u64 {
        (self.end - self.start) / HMM_PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// HmmFaultResult
// -------------------------------------------------------------------

/// Result of handling an HMM page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HmmFaultResult {
    /// Fault was handled successfully.
    #[default]
    Handled,
    /// Page is being migrated; caller should retry.
    Retry,
    /// Fault could not be resolved.
    Error,
}

// -------------------------------------------------------------------
// HmmStats
// -------------------------------------------------------------------

/// Aggregate HMM statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct HmmStats {
    /// Number of registered devices.
    pub device_count: u32,
    /// Number of active mirrors.
    pub mirror_count: u32,
    /// Total number of ranges across all active mirrors.
    pub range_count: u64,
    /// Total pages migrated to device memory since boot.
    pub pages_to_device: u64,
    /// Total pages migrated to system RAM since boot.
    pub pages_to_cpu: u64,
    /// Number of CPU-side HMM faults handled.
    pub cpu_faults: u64,
    /// Number of device-side HMM faults handled.
    pub device_faults: u64,
    /// Number of range invalidations issued.
    pub invalidations: u64,
}

// -------------------------------------------------------------------
// HmmManager
// -------------------------------------------------------------------

/// Global HMM manager.
///
/// Maintains the registry of [`HmmDevice`]s and [`HmmMirror`]s,
/// device-private page tracking, and PTE synchronisation
/// notifications.
///
/// In a real kernel this would be protected by a spinlock; here we
/// rely on the caller to provide appropriate synchronisation.
pub struct HmmManager {
    /// Registered devices.
    devices: [HmmDevice; MAX_HMM_DEVICES],
    /// Active per-process mirrors.
    mirrors: [HmmMirror; MAX_HMM_MIRRORS],
    /// Device-private page tracker.
    private_pages: [DevicePrivatePage; MAX_DEVICE_PRIVATE_PAGES],
    /// Number of active device-private page entries.
    private_page_count: usize,
    /// PTE synchronisation notification queue.
    sync_queue: [HmmPteSyncNotification; MAX_SYNC_NOTIFICATIONS],
    /// Number of pending sync notifications.
    sync_queue_count: usize,
    /// Next device ID to assign.
    next_device_id: u32,
    /// Next mirror ID to assign.
    next_mirror_id: u32,
    /// Generation counter for device-private pages.
    generation: u64,
    /// Aggregate statistics.
    stats: HmmStats,
}

impl HmmManager {
    /// Create a new, empty HMM manager.
    pub const fn new() -> Self {
        Self {
            devices: [
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
                HmmDevice::inactive(),
            ],
            mirrors: [
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
                HmmMirror::inactive(),
            ],
            private_pages: [DevicePrivatePage::empty(); MAX_DEVICE_PRIVATE_PAGES],
            private_page_count: 0,
            sync_queue: [HmmPteSyncNotification::empty(); MAX_SYNC_NOTIFICATIONS],
            sync_queue_count: 0,
            next_device_id: 0,
            next_mirror_id: 0,
            generation: 0,
            stats: HmmStats {
                device_count: 0,
                mirror_count: 0,
                range_count: 0,
                pages_to_device: 0,
                pages_to_cpu: 0,
                cpu_faults: 0,
                device_faults: 0,
                invalidations: 0,
            },
        }
    }

    // ---------------------------------------------------------------
    // Device Registration
    // ---------------------------------------------------------------

    /// Register a new heterogeneous device.
    ///
    /// Returns the assigned device ID on success.
    pub fn register_device(
        &mut self,
        name: &[u8],
        private_base: u64,
        private_size: u64,
    ) -> Result<u32> {
        // Find an empty slot.
        let slot = self
            .devices
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::Busy)?;
        let id = self.next_device_id;
        self.next_device_id += 1;
        self.devices[slot].init(id, name, private_base, private_size);
        self.stats.device_count += 1;
        Ok(id)
    }

    /// Unregister a device.
    ///
    /// Fails if the device still has active mirrors.
    pub fn unregister_device(&mut self, device_id: u32) -> Result<()> {
        let slot = self
            .devices
            .iter()
            .position(|d| d.active && d.id == device_id)
            .ok_or(Error::NotFound)?;
        if self.devices[slot].mirror_count > 0 {
            return Err(Error::Busy);
        }
        self.devices[slot].active = false;
        self.stats.device_count = self.stats.device_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Mirror Management
    // ---------------------------------------------------------------

    /// Create a new mirror for process `pid` on device `device_id`.
    ///
    /// Returns the assigned mirror ID on success.
    pub fn create_mirror(&mut self, pid: u32, device_id: u32) -> Result<u32> {
        // Verify device exists.
        let dev_slot = self
            .devices
            .iter()
            .position(|d| d.active && d.id == device_id)
            .ok_or(Error::NotFound)?;

        // Find empty mirror slot.
        let mir_slot = self
            .mirrors
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::Busy)?;

        let id = self.next_mirror_id;
        self.next_mirror_id += 1;
        self.mirrors[mir_slot].init(id, pid, device_id);
        self.devices[dev_slot].mirror_count += 1;
        self.stats.mirror_count += 1;
        Ok(id)
    }

    /// Destroy an existing mirror.
    pub fn destroy_mirror(&mut self, mirror_id: u32) -> Result<()> {
        let mir_slot = self
            .mirrors
            .iter()
            .position(|m| m.active && m.id == mirror_id)
            .ok_or(Error::NotFound)?;

        let device_id = self.mirrors[mir_slot].device_id;
        self.mirrors[mir_slot].active = false;
        self.mirrors[mir_slot].state = HmmMirrorState::Dead;

        // Decrement device mirror count.
        if let Some(dev_slot) = self
            .devices
            .iter()
            .position(|d| d.active && d.id == device_id)
        {
            self.devices[dev_slot].mirror_count =
                self.devices[dev_slot].mirror_count.saturating_sub(1);
        }
        self.stats.mirror_count = self.stats.mirror_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Range Management
    // ---------------------------------------------------------------

    /// Add a virtual address range to an existing mirror.
    pub fn mirror_add_range(&mut self, mirror_id: u32, start: u64, end: u64) -> Result<()> {
        let slot = self
            .mirrors
            .iter()
            .position(|m| m.active && m.id == mirror_id)
            .ok_or(Error::NotFound)?;
        self.mirrors[slot].add_range(start, end)?;
        self.stats.range_count += 1;
        Ok(())
    }

    /// Remove a virtual address range from a mirror.
    pub fn mirror_remove_range(&mut self, mirror_id: u32, start: u64) -> Result<()> {
        let slot = self
            .mirrors
            .iter()
            .position(|m| m.active && m.id == mirror_id)
            .ok_or(Error::NotFound)?;
        self.mirrors[slot].remove_range(start)?;
        self.stats.range_count = self.stats.range_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // MMU Notifier Integration
    // ---------------------------------------------------------------

    /// Notify HMM that CPU page tables in `[start, end)` have changed.
    ///
    /// Invalidates all mirror ranges that overlap with the given interval.
    /// Call this from the process's mmu_notifier invalidate_range handler.
    pub fn mmu_notifier_invalidate(&mut self, pid: u32, start: u64, end: u64) {
        for mirror in &mut self.mirrors {
            if mirror.active && mirror.pid == pid {
                mirror.invalidate_range(start, end);
                self.stats.invalidations += 1;
            }
        }
    }

    // ---------------------------------------------------------------
    // Page Fault Handling
    // ---------------------------------------------------------------

    /// Handle an HMM page fault.
    ///
    /// Called when a CPU or device-side fault occurs on an HMM-managed page.
    /// Updates the page state within the relevant mirror range.
    ///
    /// In a real implementation this would trigger page table walks and
    /// DMA mappings; here we update internal state and return the result.
    pub fn handle_fault(
        &mut self,
        pid: u32,
        vaddr: u64,
        kind: HmmFaultKind,
        write: bool,
    ) -> HmmFaultResult {
        match kind {
            HmmFaultKind::Cpu => self.stats.cpu_faults += 1,
            HmmFaultKind::Device => self.stats.device_faults += 1,
        }

        // Find the mirror for this process.
        let mir_slot = self.mirrors.iter().position(|m| m.active && m.pid == pid);
        let mir_slot = match mir_slot {
            Some(s) => s,
            None => return HmmFaultResult::Error,
        };

        // Simulate resolving the fault: mark the page present in system RAM.
        let paddr = vaddr; // In reality this would come from the CPU page table walk.
        let page_kind = match kind {
            HmmFaultKind::Cpu => HmmPageKind::SystemRam,
            HmmFaultKind::Device => HmmPageKind::DevicePrivate,
        };
        match self.mirrors[mir_slot].update_page(vaddr, paddr, page_kind, write) {
            Ok(()) => HmmFaultResult::Handled,
            Err(_) => HmmFaultResult::Error,
        }
    }

    // ---------------------------------------------------------------
    // Page Migration
    // ---------------------------------------------------------------

    /// Execute a page migration request.
    ///
    /// Migrates pages in the requested range between system RAM and
    /// device-private memory. Updates mirror page states accordingly.
    ///
    /// Returns the number of pages successfully migrated.
    pub fn migrate(&mut self, request: &HmmMigrateRequest) -> Result<u64> {
        let page_count = request.page_count();
        if page_count == 0 || page_count > MAX_MIGRATE_PAGES as u64 {
            return Err(Error::InvalidArgument);
        }

        // Find device.
        let dev_slot = self
            .devices
            .iter()
            .position(|d| d.active && d.id == request.device_id)
            .ok_or(Error::NotFound)?;

        // For ToDevice: allocate device memory, mark pages as DevicePrivate.
        // For ToCpu: free device memory, mark pages as SystemRam.
        let new_kind = match request.direction {
            HmmMigrateDir::ToDevice => {
                let size = page_count * HMM_PAGE_SIZE;
                self.devices[dev_slot].alloc_private(size)?;
                HmmPageKind::DevicePrivate
            }
            HmmMigrateDir::ToCpu => {
                let size = page_count * HMM_PAGE_SIZE;
                self.devices[dev_slot].free_private(size);
                HmmPageKind::SystemRam
            }
        };

        // Invalidate and update mirrors for this pid/range.
        let mut migrated = 0u64;
        for mirror in &mut self.mirrors {
            if !mirror.active || mirror.pid != request.pid || mirror.device_id != request.device_id
            {
                continue;
            }
            mirror.invalidate_range(request.start, request.end);
            // Update page states page by page.
            let mut vaddr = request.start;
            while vaddr < request.end {
                let paddr = vaddr; // Simulated: real impl walks page tables.
                let _ = mirror.update_page(vaddr, paddr, new_kind, false);
                vaddr += HMM_PAGE_SIZE;
                migrated += 1;
            }
        }

        match request.direction {
            HmmMigrateDir::ToDevice => self.stats.pages_to_device += migrated,
            HmmMigrateDir::ToCpu => self.stats.pages_to_cpu += migrated,
        }
        Ok(migrated)
    }

    // ---------------------------------------------------------------
    // Statistics & Introspection
    // ---------------------------------------------------------------

    /// Return a snapshot of current HMM statistics.
    pub fn stats(&self) -> HmmStats {
        self.stats
    }

    /// Return free device-private memory for a given device (bytes).
    pub fn device_free_mem(&self, device_id: u32) -> Option<u64> {
        self.devices
            .iter()
            .find(|d| d.active && d.id == device_id)
            .map(|d| d.free_device_mem())
    }

    /// Number of active mirrors for a given process.
    pub fn pid_mirror_count(&self, pid: u32) -> usize {
        self.mirrors
            .iter()
            .filter(|m| m.active && m.pid == pid)
            .count()
    }

    // ---------------------------------------------------------------
    // Page Table Synchronisation
    // ---------------------------------------------------------------

    /// Queues a PTE synchronisation notification for device drivers.
    ///
    /// Called from the MMU notifier path whenever a CPU PTE changes
    /// for a range managed by HMM.  The device driver consumes these
    /// via [`drain_sync_notifications`](Self::drain_sync_notifications).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the notification queue is
    /// full.
    pub fn queue_pte_sync(
        &mut self,
        vaddr: u64,
        new_paddr: u64,
        kind: HmmPteSyncKind,
        writable: bool,
        device_id: u32,
        pid: u32,
    ) -> Result<()> {
        if self.sync_queue_count >= MAX_SYNC_NOTIFICATIONS {
            return Err(Error::OutOfMemory);
        }
        self.sync_queue[self.sync_queue_count] = HmmPteSyncNotification {
            vaddr,
            new_paddr,
            kind,
            writable,
            device_id,
            pid,
            active: true,
        };
        self.sync_queue_count += 1;
        Ok(())
    }

    /// Enhanced MMU notifier that also queues PTE sync notifications
    /// for each affected device mirror.
    ///
    /// This replaces direct calls to
    /// [`mmu_notifier_invalidate`](Self::mmu_notifier_invalidate)
    /// when per-PTE notifications are needed.
    pub fn mmu_notifier_sync(&mut self, pid: u32, start: u64, end: u64, kind: HmmPteSyncKind) {
        for i in 0..self.mirrors.len() {
            if !self.mirrors[i].active || self.mirrors[i].pid != pid {
                continue;
            }
            let device_id = self.mirrors[i].device_id;
            self.mirrors[i].invalidate_range(start, end);
            self.stats.invalidations += 1;

            // Queue per-page notifications.
            let mut vaddr = start;
            while vaddr < end {
                let _ = self.queue_pte_sync(vaddr, 0, kind, false, device_id, pid);
                vaddr += HMM_PAGE_SIZE;
            }
        }
    }

    /// Drains pending sync notifications into the caller's buffer.
    ///
    /// Copies up to `out.len()` notifications and removes them from
    /// the internal queue.  Returns the number of notifications
    /// copied.
    pub fn drain_sync_notifications(&mut self, out: &mut [HmmPteSyncNotification]) -> usize {
        let drain = out.len().min(self.sync_queue_count);
        out[..drain].copy_from_slice(&self.sync_queue[..drain]);
        // Shift remaining entries forward.
        let remaining = self.sync_queue_count - drain;
        for i in 0..remaining {
            self.sync_queue[i] = self.sync_queue[drain + i];
        }
        for i in remaining..self.sync_queue_count {
            self.sync_queue[i] = HmmPteSyncNotification::empty();
        }
        self.sync_queue_count = remaining;
        drain
    }

    /// Returns the number of pending sync notifications.
    pub fn pending_sync_count(&self) -> usize {
        self.sync_queue_count
    }

    // ---------------------------------------------------------------
    // Device-Private Page Tracking
    // ---------------------------------------------------------------

    /// Registers a page as living in device-private memory.
    ///
    /// Called after a successful `migrate_to_device` to record
    /// the device-side location so CPU faults can find the page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tracker is full.
    pub fn register_private_page(
        &mut self,
        vaddr: u64,
        device_paddr: u64,
        device_id: u32,
        pid: u32,
    ) -> Result<u64> {
        if self.private_page_count >= MAX_DEVICE_PRIVATE_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.generation += 1;
        let cur_gen = self.generation;
        self.private_pages[self.private_page_count] = DevicePrivatePage {
            vaddr,
            device_paddr,
            device_id,
            pid,
            generation: cur_gen,
            active: true,
        };
        self.private_page_count += 1;
        Ok(cur_gen)
    }

    /// Unregisters a device-private page (e.g., after migrating
    /// back to system RAM).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn unregister_private_page(&mut self, vaddr: u64, device_id: u32, pid: u32) -> Result<()> {
        let pos = (0..self.private_page_count)
            .find(|&i| {
                let p = &self.private_pages[i];
                p.active && p.vaddr == vaddr && p.device_id == device_id && p.pid == pid
            })
            .ok_or(Error::NotFound)?;

        self.private_page_count -= 1;
        if pos < self.private_page_count {
            self.private_pages[pos] = self.private_pages[self.private_page_count];
        }
        self.private_pages[self.private_page_count] = DevicePrivatePage::empty();
        Ok(())
    }

    /// Looks up a device-private page by virtual address and
    /// process.
    ///
    /// Returns `None` if the page is not in device-private memory.
    pub fn find_private_page(&self, vaddr: u64, pid: u32) -> Option<&DevicePrivatePage> {
        self.private_pages[..self.private_page_count]
            .iter()
            .find(|p| p.active && p.vaddr == vaddr && p.pid == pid)
    }

    /// Returns the number of tracked device-private pages.
    pub fn private_page_count(&self) -> usize {
        self.private_page_count
    }

    /// Returns the number of device-private pages for a given
    /// device.
    pub fn device_private_page_count(&self, device_id: u32) -> usize {
        self.private_pages[..self.private_page_count]
            .iter()
            .filter(|p| p.active && p.device_id == device_id)
            .count()
    }

    // ---------------------------------------------------------------
    // Convenience Migration Wrappers
    // ---------------------------------------------------------------

    /// Migrates pages from system RAM to device-private memory.
    ///
    /// A convenience wrapper around [`migrate`](Self::migrate) that
    /// also registers each migrated page in the device-private page
    /// tracker and queues PTE sync notifications.
    ///
    /// Returns the number of pages migrated.
    pub fn migrate_to_device(
        &mut self,
        start: u64,
        end: u64,
        device_id: u32,
        pid: u32,
    ) -> Result<u64> {
        let req = HmmMigrateRequest::new(start, end, HmmMigrateDir::ToDevice, device_id, pid)?;
        let migrated = self.migrate(&req)?;

        // Register each page in the device-private tracker.
        let dev_slot = self
            .devices
            .iter()
            .position(|d| d.active && d.id == device_id);
        let mut vaddr = start;
        while vaddr < end {
            let device_paddr = if let Some(ds) = dev_slot {
                // Estimate: base + offset.
                let offset = self.devices[ds].private_mem_size - self.devices[ds].free_device_mem();
                self.devices[ds].private_mem_base + offset
            } else {
                vaddr // simulated
            };
            let _ = self.register_private_page(vaddr, device_paddr, device_id, pid);
            let _ = self.queue_pte_sync(vaddr, 0, HmmPteSyncKind::Migrate, false, device_id, pid);
            vaddr += HMM_PAGE_SIZE;
        }
        Ok(migrated)
    }

    /// Migrates pages from device-private memory back to system RAM.
    ///
    /// Unregisters each page from the device-private tracker and
    /// queues PTE sync notifications.
    ///
    /// Returns the number of pages migrated.
    pub fn migrate_from_device(
        &mut self,
        start: u64,
        end: u64,
        device_id: u32,
        pid: u32,
    ) -> Result<u64> {
        let req = HmmMigrateRequest::new(start, end, HmmMigrateDir::ToCpu, device_id, pid)?;
        let migrated = self.migrate(&req)?;

        // Unregister each page from the device-private tracker.
        let mut vaddr = start;
        while vaddr < end {
            let _ = self.unregister_private_page(vaddr, device_id, pid);
            let _ = self.queue_pte_sync(
                vaddr,
                vaddr, // simulated CPU paddr
                HmmPteSyncKind::Migrate,
                true,
                device_id,
                pid,
            );
            vaddr += HMM_PAGE_SIZE;
        }
        Ok(migrated)
    }

    // ---------------------------------------------------------------
    // Device Fault Handling
    // ---------------------------------------------------------------

    /// Handles a device-side page fault.
    ///
    /// When a device accesses a virtual address whose page resides
    /// in system RAM (not yet migrated to device-private memory),
    /// the device driver calls this function to migrate the page
    /// to the device.
    ///
    /// If the page is already in device memory, returns
    /// `HmmFaultResult::Handled`.  If the page is currently being
    /// migrated, returns `HmmFaultResult::Retry`.
    pub fn handle_device_fault(
        &mut self,
        pid: u32,
        vaddr: u64,
        device_id: u32,
        write: bool,
    ) -> HmmFaultResult {
        self.stats.device_faults += 1;

        // If the page is already in device-private memory, no
        // migration is needed.
        if self.find_private_page(vaddr, pid).is_some() {
            return HmmFaultResult::Handled;
        }

        // Check if any mirror range has this page marked as
        // Migrating.
        for mirror in &self.mirrors {
            if !mirror.active || mirror.pid != pid || mirror.device_id != device_id {
                continue;
            }
            let mut is_migrating = false;
            mirror.for_each_range(|r| {
                if vaddr >= r.start && vaddr < r.end {
                    for entry in r.page_entries() {
                        if entry.vaddr == vaddr && entry.kind == HmmPageKind::Migrating {
                            is_migrating = true;
                        }
                    }
                }
            });
            if is_migrating {
                return HmmFaultResult::Retry;
            }
        }

        // Attempt to migrate the single page to the device.
        let page_end = vaddr + HMM_PAGE_SIZE;
        match self.migrate_to_device(vaddr, page_end, device_id, pid) {
            Ok(_) => {
                // Also update the mirror's page state.
                let _ = self.handle_fault(pid, vaddr, HmmFaultKind::Device, write);
                HmmFaultResult::Handled
            }
            Err(_) => HmmFaultResult::Error,
        }
    }

    /// Handles a CPU-side fault on a device-private page.
    ///
    /// When the CPU accesses a virtual address whose page has been
    /// migrated to device-private memory, this function migrates
    /// the page back to system RAM so the CPU can access it.
    pub fn handle_cpu_fault(&mut self, pid: u32, vaddr: u64, write: bool) -> HmmFaultResult {
        self.stats.cpu_faults += 1;

        // Look up the device-private page entry.
        let entry = self.find_private_page(vaddr, pid);
        let device_id = match entry {
            Some(e) => e.device_id,
            None => {
                // Page is not in device memory; delegate to normal
                // fault handling.
                return self.handle_fault(pid, vaddr, HmmFaultKind::Cpu, write);
            }
        };

        // Migrate the page back to CPU.
        let page_end = vaddr + HMM_PAGE_SIZE;
        match self.migrate_from_device(vaddr, page_end, device_id, pid) {
            Ok(_) => {
                // Update mirror state.
                let paddr = vaddr; // simulated
                for mirror in &mut self.mirrors {
                    if mirror.active && mirror.pid == pid && mirror.device_id == device_id {
                        let _ = mirror.update_page(vaddr, paddr, HmmPageKind::SystemRam, write);
                    }
                }
                HmmFaultResult::Handled
            }
            Err(_) => HmmFaultResult::Error,
        }
    }

    // ---------------------------------------------------------------
    // Batch Operations
    // ---------------------------------------------------------------

    /// Batch-migrates multiple disjoint ranges to a device.
    ///
    /// Each entry in `ranges` is `(start, end)`.  Returns aggregate
    /// results.
    pub fn batch_migrate_to_device(
        &mut self,
        ranges: &[(u64, u64)],
        device_id: u32,
        pid: u32,
    ) -> HmmBatchMigrateResult {
        let mut result = HmmBatchMigrateResult::default();
        for &(start, end) in ranges {
            match self.migrate_to_device(start, end, device_id, pid) {
                Ok(n) => result.migrated += n,
                Err(_) => {
                    let pages = (end.saturating_sub(start)) / HMM_PAGE_SIZE;
                    result.failed += pages;
                }
            }
        }
        result
    }

    /// Batch-migrates multiple disjoint ranges from a device back
    /// to CPU.
    pub fn batch_migrate_from_device(
        &mut self,
        ranges: &[(u64, u64)],
        device_id: u32,
        pid: u32,
    ) -> HmmBatchMigrateResult {
        let mut result = HmmBatchMigrateResult::default();
        for &(start, end) in ranges {
            match self.migrate_from_device(start, end, device_id, pid) {
                Ok(n) => result.migrated += n,
                Err(_) => {
                    let pages = (end.saturating_sub(start)) / HMM_PAGE_SIZE;
                    result.failed += pages;
                }
            }
        }
        result
    }

    /// Destroys all mirrors and private pages for a device.
    ///
    /// Called during device hot-unplug or driver teardown.  Migrates
    /// all device-private pages back to system RAM first.
    ///
    /// Returns the number of mirrors and private pages cleaned up.
    pub fn teardown_device(&mut self, device_id: u32) -> Result<(usize, usize)> {
        // Migrate all private pages back.
        let mut migrated_pages = 0usize;
        let mut addrs_to_migrate: [(u64, u32); MAX_DEVICE_PRIVATE_PAGES] =
            [(0, 0); MAX_DEVICE_PRIVATE_PAGES];
        let mut addr_count = 0usize;

        for i in 0..self.private_page_count {
            let p = &self.private_pages[i];
            if p.active && p.device_id == device_id {
                addrs_to_migrate[addr_count] = (p.vaddr, p.pid);
                addr_count += 1;
            }
        }

        for i in 0..addr_count {
            let (vaddr, pid) = addrs_to_migrate[i];
            let page_end = vaddr + HMM_PAGE_SIZE;
            if self
                .migrate_from_device(vaddr, page_end, device_id, pid)
                .is_ok()
            {
                migrated_pages += 1;
            }
        }

        // Destroy all mirrors for this device.
        let mut destroyed_mirrors = 0usize;
        let mut mirror_ids = [0u32; MAX_HMM_MIRRORS];
        let mut mid_count = 0usize;
        for mirror in &self.mirrors {
            if mirror.active && mirror.device_id == device_id {
                mirror_ids[mid_count] = mirror.id;
                mid_count += 1;
            }
        }
        for i in 0..mid_count {
            if self.destroy_mirror(mirror_ids[i]).is_ok() {
                destroyed_mirrors += 1;
            }
        }

        Ok((destroyed_mirrors, migrated_pages))
    }
}

impl Default for HmmManager {
    fn default() -> Self {
        Self::new()
    }
}

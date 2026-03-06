// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU Shared Virtual Addressing (SVA) and PASID subsystem.
//!
//! Implements SVA, which allows PCIe devices to share a process
//! address space via PCI Process Address Space IDs (PASIDs). When
//! a device is bound to a process address space, it can issue DMA
//! using process virtual addresses directly, letting the IOMMU
//! translate them using the same page tables as the CPU.
//!
//! # Architecture
//!
//! - **PASID pool** — 20-bit namespace (max 1,048,576 IDs), with a
//!   generation counter per slot to detect stale handles.
//! - **SvaDomain** — logical grouping of SVA bindings for one device.
//! - **IoMmuSvaSubsystem** — top-level registry of domains; provides
//!   IOTLB invalidation, page fault dispatch, and statistics.
//!
//! # Usage
//!
//! ```ignore
//! let mut sva = IoMmuSvaSubsystem::new();
//! let pasid = sva.alloc_pasid()?;
//! sva.bind_device(domain_idx, pasid, device_id, mm_id, 0)?;
//! sva.invalidate_pasid(pasid);
//! sva.free_pasid(pasid)?;
//! ```
//!
//! Reference: PCI Express Base Specification 6.0, §10.5 (PASID);
//!            Intel VT-d Specification, §6.3 (SVA).

use oncrix_lib::{Error, Result};

// ── PASID limits ─────────────────────────────────────────────

/// Number of PASID bits; IDs range 0 .. (2^20 – 1).
const PASID_BITS: u32 = 20;

/// Maximum valid PASID value (inclusive).
pub const PASID_MAX: u32 = (1u32 << PASID_BITS) - 1;

/// PASID 0 is reserved (untranslated / default DMA).
const PASID_RESERVED: u32 = 0;

/// Pool size — the number of PASID slots managed here.
/// We track 1 024 slots; larger systems can increase this.
const PASID_POOL_SIZE: usize = 1024;

// ── Domain and binding limits ─────────────────────────────────

/// Maximum SVA domains in the subsystem.
const MAX_SVA_DOMAINS: usize = 16;

/// Maximum SVA bindings per domain.
const MAX_BINDINGS_PER_DOMAIN: usize = 256;

// ── Fault flag bits ───────────────────────────────────────────

/// Page fault flag: access was a write.
pub const SVA_FAULT_WRITE: u32 = 1 << 0;

/// Page fault flag: access was an instruction fetch.
pub const SVA_FAULT_EXEC: u32 = 1 << 1;

/// Page fault flag: the PASID was not present in the IOTLB.
pub const SVA_FAULT_PASID_MISSING: u32 = 1 << 2;

// ── PASID entry ───────────────────────────────────────────────

/// A single slot in the PASID pool.
///
/// Tracks whether the PASID is allocated and carries a generation
/// counter so callers holding stale handles can be detected.
#[derive(Debug, Clone, Copy)]
pub struct PasidEntry {
    /// The 20-bit PASID value assigned to this slot.
    pub pasid: u32,
    /// Monotonically increasing generation counter.
    /// Incremented each time the slot is freed and reused.
    pub generation: u32,
    /// Whether this slot is currently allocated.
    pub allocated: bool,
}

impl Default for PasidEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl PasidEntry {
    /// Create an empty (unallocated) PASID entry.
    pub const fn new() -> Self {
        Self {
            pasid: 0,
            generation: 0,
            allocated: false,
        }
    }
}

// ── SVA binding ───────────────────────────────────────────────

/// A binding between a device and a process address space.
///
/// When active, the IOMMU translates DMA from `device_id` carrying
/// `pasid` using the page tables of the process identified by
/// `mm_id`.
#[derive(Debug, Clone, Copy)]
pub struct SvaBinding {
    /// Allocated PASID (20-bit value).
    pub pasid: u32,
    /// PCI device identifier (`bus << 8 | devfn`).
    pub device_id: u16,
    /// Process address-space identifier (e.g. task mm cookie).
    pub mm_id: u64,
    /// Binding flags (caller-defined; passed through to hardware).
    pub flags: u32,
    /// Whether this binding slot is occupied.
    pub active: bool,
}

impl Default for SvaBinding {
    fn default() -> Self {
        Self::new()
    }
}

impl SvaBinding {
    /// Create an empty (inactive) binding.
    pub const fn new() -> Self {
        Self {
            pasid: 0,
            device_id: 0,
            mm_id: 0,
            flags: 0,
            active: false,
        }
    }
}

// ── SVA domain ────────────────────────────────────────────────

/// An SVA domain — a logical grouping of SVA bindings for one device.
///
/// A domain owns up to [`MAX_BINDINGS_PER_DOMAIN`] (256) bindings
/// and is associated with a single PCI device. The `fault_handler`
/// flag indicates whether this domain participates in page-fault
/// recovery (PRQ — Page Request Queue).
pub struct SvaDomain {
    /// PCI device identifier that owns this domain.
    pub device_id: u16,
    /// Whether a page-fault handler is registered.
    pub fault_handler: bool,
    /// Active SVA bindings.
    bindings: [SvaBinding; MAX_BINDINGS_PER_DOMAIN],
    /// Number of active bindings.
    binding_count: usize,
    /// Whether this domain slot is in use.
    active: bool,
}

impl Default for SvaDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl SvaDomain {
    /// Create an empty, inactive SVA domain.
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            fault_handler: false,
            bindings: [const { SvaBinding::new() }; MAX_BINDINGS_PER_DOMAIN],
            binding_count: 0,
            active: false,
        }
    }

    /// Find a binding by PASID, returning its slot index.
    fn find_binding(&self, pasid: u32) -> Option<usize> {
        self.bindings[..self.binding_count]
            .iter()
            .position(|b| b.active && b.pasid == pasid)
    }

    /// Return the number of active bindings in this domain.
    pub fn binding_count(&self) -> usize {
        self.binding_count
    }

    /// Return a reference to the binding at `index`.
    pub fn get_binding(&self, index: usize) -> Option<&SvaBinding> {
        if index < self.binding_count {
            Some(&self.bindings[index])
        } else {
            None
        }
    }
}

// ── Page-fault record ─────────────────────────────────────────

/// A recorded SVA page fault from the hardware PRQ.
#[derive(Debug, Clone, Copy)]
pub struct SvaPageFault {
    /// PASID that generated the fault.
    pub pasid: u32,
    /// Faulting virtual address.
    pub addr: u64,
    /// Fault flags (see `SVA_FAULT_*` constants).
    pub flags: u32,
}

// ── Statistics ────────────────────────────────────────────────

/// Operational statistics for the SVA subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SvaStats {
    /// Number of currently active bindings (across all domains).
    pub bindings_active: u64,
    /// Total SVA page faults handled.
    pub faults_handled: u64,
    /// Total IOTLB invalidations issued (PASID-granule + range).
    pub iotlb_invalidations: u64,
    /// Total PASID allocations.
    pub pasid_allocs: u64,
    /// Total PASID frees.
    pub pasid_frees: u64,
}

// ── IOMMU SVA subsystem ───────────────────────────────────────

/// Top-level IOMMU SVA subsystem.
///
/// Manages the PASID pool, SVA domains, and per-event statistics.
/// Supports up to [`MAX_SVA_DOMAINS`] (16) domains and
/// [`PASID_POOL_SIZE`] (1 024) PASID slots.
pub struct IoMmuSvaSubsystem {
    /// PASID allocation pool.
    pool: [PasidEntry; PASID_POOL_SIZE],
    /// Next slot to scan for a free PASID (roving pointer).
    next_free: usize,
    /// Total allocated PASIDs.
    allocated_count: usize,
    /// SVA domains.
    domains: [SvaDomain; MAX_SVA_DOMAINS],
    /// Number of active domains.
    domain_count: usize,
    /// Operational statistics.
    stats: SvaStats,
}

impl IoMmuSvaSubsystem {
    /// Create a new, empty SVA subsystem.
    ///
    /// PASID 0 is marked reserved (pre-allocated) and never
    /// handed out to callers.
    pub fn new() -> Self {
        let mut pool = [const { PasidEntry::new() }; PASID_POOL_SIZE];
        // Assign pasid values and reserve slot 0.
        let mut i = 0usize;
        while i < PASID_POOL_SIZE {
            pool[i].pasid = i as u32;
            i += 1;
        }
        // Reserve PASID 0 — it is the default untranslated context.
        pool[PASID_RESERVED as usize].allocated = true;

        let mut s = Self {
            pool,
            next_free: 1,
            allocated_count: 1,
            domains: [const { SvaDomain::new() }; MAX_SVA_DOMAINS],
            domain_count: 0,
            stats: SvaStats::default(),
        };
        // Give each domain a stable initial state.
        let mut d = 0usize;
        while d < MAX_SVA_DOMAINS {
            s.domains[d] = SvaDomain::new();
            d += 1;
        }
        s
    }

    // ── PASID management ─────────────────────────────────────

    /// Allocate a PASID from the pool.
    ///
    /// Searches the pool starting from the roving pointer for an
    /// unallocated slot. The returned value is a 20-bit PASID
    /// in the range `1 ..= PASID_MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all pool slots are taken.
    pub fn alloc_pasid(&mut self) -> Result<u32> {
        let start = self.next_free;
        let mut idx = start;
        loop {
            if !self.pool[idx].allocated && self.pool[idx].pasid != PASID_RESERVED {
                self.pool[idx].allocated = true;
                self.allocated_count += 1;
                self.next_free = (idx + 1) % PASID_POOL_SIZE;
                self.stats.pasid_allocs += 1;
                return Ok(self.pool[idx].pasid);
            }
            idx = (idx + 1) % PASID_POOL_SIZE;
            if idx == start {
                break;
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated PASID.
    ///
    /// Marks the slot as unallocated and increments its generation
    /// counter. Callers holding old generation values will be able
    /// to detect the reuse.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `pasid` is not currently
    /// allocated, or [`Error::InvalidArgument`] if `pasid` is
    /// the reserved value 0 or exceeds [`PASID_MAX`].
    pub fn free_pasid(&mut self, pasid: u32) -> Result<()> {
        if pasid == PASID_RESERVED || pasid > PASID_MAX {
            return Err(Error::InvalidArgument);
        }
        // Search for the slot owning this PASID.
        let idx = self.pool[..PASID_POOL_SIZE]
            .iter()
            .position(|e| e.pasid == pasid && e.allocated)
            .ok_or(Error::NotFound)?;

        self.pool[idx].allocated = false;
        self.pool[idx].generation = self.pool[idx].generation.wrapping_add(1);
        self.allocated_count = self.allocated_count.saturating_sub(1);
        self.stats.pasid_frees += 1;
        Ok(())
    }

    // ── Domain management ────────────────────────────────────

    /// Create a new SVA domain for `device_id`.
    ///
    /// Returns the domain index (0 .. [`MAX_SVA_DOMAINS`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain table is full.
    pub fn create_domain(&mut self, device_id: u16, fault_handler: bool) -> Result<usize> {
        if self.domain_count >= MAX_SVA_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.domain_count;
        self.domains[idx].device_id = device_id;
        self.domains[idx].fault_handler = fault_handler;
        self.domains[idx].binding_count = 0;
        self.domains[idx].active = true;
        self.domain_count += 1;
        Ok(idx)
    }

    // ── Binding operations ───────────────────────────────────

    /// Bind a device+PASID to a process address space.
    ///
    /// Adds an [`SvaBinding`] record to the domain at `domain_idx`.
    ///
    /// # Arguments
    ///
    /// * `domain_idx` — Index of the target SVA domain.
    /// * `pasid`      — 20-bit PASID (must be allocated).
    /// * `device_id`  — PCI BDF of the device.
    /// * `mm_id`      — Process address-space cookie.
    /// * `flags`      — Caller-defined binding flags.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `domain_idx` is out of range or
    ///   the domain is inactive.
    /// - [`Error::InvalidArgument`] if `pasid` is reserved or > max.
    /// - [`Error::AlreadyExists`] if the PASID is already bound in
    ///   this domain.
    /// - [`Error::OutOfMemory`] if the domain's binding table is full.
    pub fn bind_device(
        &mut self,
        domain_idx: usize,
        pasid: u32,
        device_id: u16,
        mm_id: u64,
        flags: u32,
    ) -> Result<()> {
        if pasid == PASID_RESERVED || pasid > PASID_MAX {
            return Err(Error::InvalidArgument);
        }
        if domain_idx >= self.domain_count || !self.domains[domain_idx].active {
            return Err(Error::NotFound);
        }

        // Guard against duplicate bindings.
        if self.domains[domain_idx].find_binding(pasid).is_some() {
            return Err(Error::AlreadyExists);
        }

        let bc = self.domains[domain_idx].binding_count;
        if bc >= MAX_BINDINGS_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }

        self.domains[domain_idx].bindings[bc] = SvaBinding {
            pasid,
            device_id,
            mm_id,
            flags,
            active: true,
        };
        self.domains[domain_idx].binding_count += 1;
        self.stats.bindings_active += 1;
        Ok(())
    }

    /// Unbind a device+PASID from a domain.
    ///
    /// Removes the binding entry and triggers an IOTLB invalidation
    /// for the freed PASID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `domain_idx` is invalid or no
    ///   binding with `pasid` exists in the domain.
    pub fn unbind(&mut self, domain_idx: usize, pasid: u32) -> Result<()> {
        if domain_idx >= self.domain_count || !self.domains[domain_idx].active {
            return Err(Error::NotFound);
        }
        let pos = self.domains[domain_idx]
            .find_binding(pasid)
            .ok_or(Error::NotFound)?;

        self.domains[domain_idx].bindings[pos].active = false;
        // Compact: swap with last active binding if not already last.
        let last = self.domains[domain_idx].binding_count - 1;
        if pos != last {
            self.domains[domain_idx].bindings[pos] = self.domains[domain_idx].bindings[last];
            self.domains[domain_idx].bindings[last] = SvaBinding::new();
        }
        self.domains[domain_idx].binding_count -= 1;
        self.stats.bindings_active = self.stats.bindings_active.saturating_sub(1);

        // Invalidate the PASID in the IOTLB.
        self.invalidate_pasid(pasid);
        Ok(())
    }

    // ── IOTLB invalidation ───────────────────────────────────

    /// Invalidate all IOTLB entries for a specific PASID.
    ///
    /// This is a logical invalidation — the actual hardware write
    /// must be issued by the platform IOMMU driver once it
    /// processes the invalidation descriptor.
    pub fn invalidate_pasid(&mut self, pasid: u32) {
        // In a full implementation this enqueues an invalidation
        // descriptor into the hardware Invalidation Queue.
        // Here we track the event in statistics.
        let _ = pasid; // consumed by hardware path
        self.stats.iotlb_invalidations += 1;
    }

    /// Invalidate IOTLB entries for a virtual-address range under
    /// a given PASID.
    ///
    /// Useful after unmapping a region in the process page tables
    /// to force the IOMMU to reload translations.
    ///
    /// # Arguments
    ///
    /// * `pasid`      — PASID whose IOTLB entries to flush.
    /// * `start_addr` — Start of virtual address range.
    /// * `end_addr`   — Exclusive end of virtual address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `end_addr <= start_addr`.
    pub fn invalidate_range(&mut self, pasid: u32, start_addr: u64, end_addr: u64) -> Result<()> {
        if end_addr <= start_addr {
            return Err(Error::InvalidArgument);
        }
        let _ = pasid; // consumed by hardware invalidation path
        let _ = start_addr;
        let _ = end_addr;
        self.stats.iotlb_invalidations += 1;
        Ok(())
    }

    // ── Page fault handling ───────────────────────────────────

    /// Handle an SVA page fault reported by the hardware PRQ.
    ///
    /// Looks up the domain associated with the faulting PASID,
    /// checks whether a fault handler is registered, and increments
    /// the fault counter.
    ///
    /// Returns `true` if the fault was dispatched to a handler,
    /// `false` if no domain owns the PASID (hardware should ATS
    /// respond with INVALID).
    ///
    /// # Arguments
    ///
    /// * `pasid` — The PASID reported in the fault record.
    /// * `addr`  — The faulting virtual address.
    /// * `flags` — Fault flags (`SVA_FAULT_*` constants).
    pub fn handle_page_fault(&mut self, pasid: u32, addr: u64, flags: u32) -> bool {
        self.stats.faults_handled += 1;
        // Find a domain that owns a binding for this PASID.
        let mut i = 0usize;
        while i < self.domain_count {
            if self.domains[i].active && self.domains[i].find_binding(pasid).is_some() {
                let _fault = SvaPageFault { pasid, addr, flags };
                // Dispatch to registered handler (platform-specific).
                return self.domains[i].fault_handler;
            }
            i += 1;
        }
        false
    }

    // ── Accessors ────────────────────────────────────────────

    /// Return the current operational statistics.
    pub fn stats(&self) -> &SvaStats {
        &self.stats
    }

    /// Return the number of active SVA domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Return the number of currently allocated PASIDs.
    pub fn allocated_pasid_count(&self) -> usize {
        self.allocated_count
    }

    /// Return a reference to the domain at `index`.
    pub fn get_domain(&self, index: usize) -> Option<&SvaDomain> {
        if index < self.domain_count && self.domains[index].active {
            Some(&self.domains[index])
        } else {
            None
        }
    }

    /// Check whether `pasid` is currently allocated.
    pub fn is_pasid_allocated(&self, pasid: u32) -> bool {
        if pasid as usize >= PASID_POOL_SIZE {
            return false;
        }
        self.pool[pasid as usize].allocated
    }

    /// Return the current generation counter for `pasid`.
    ///
    /// Callers can store this at bind time and compare later to
    /// detect PASID reuse.
    pub fn pasid_generation(&self, pasid: u32) -> u32 {
        if (pasid as usize) < PASID_POOL_SIZE {
            self.pool[pasid as usize].generation
        } else {
            0
        }
    }
}

impl Default for IoMmuSvaSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

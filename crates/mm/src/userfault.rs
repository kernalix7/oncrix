// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd handler for user-space page fault handling.
//!
//! Implements the kernel side of the userfaultfd mechanism, which
//! allows user-space processes to handle page faults for designated
//! virtual memory regions.  This enables:
//! - Live migration of virtual machines (post-copy)
//! - Lazy page population
//! - User-space memory management (e.g., garbage collectors)
//! - Snapshotting and checkpointing
//!
//! The kernel registers memory ranges, intercepts page faults in
//! those ranges, and forwards fault descriptors to user-space via
//! an event queue.  User-space resolves the fault by providing the
//! missing page data (COPY or ZEROPAGE), then the kernel maps the
//! page and resumes the faulting thread.
//!
//! Inspired by Linux `fs/userfaultfd.c` and `include/linux/userfaultfd_k.h`.
//!
//! Key components:
//! - [`UffdFeature`] — supported userfaultfd features
//! - [`UffdFaultType`] — type of intercepted fault
//! - [`UffdEvent`] — event delivered to user-space handler
//! - [`UffdRange`] — registered memory range
//! - [`UffdResolution`] — how user-space resolved a fault
//! - [`UffdDescriptor`] — per-fd userfaultfd state
//! - [`UffdStats`] — aggregate statistics
//! - [`UffdManager`] — top-level userfaultfd manager
//!
//! Reference: Linux `fs/userfaultfd.c`, `include/uapi/linux/userfaultfd.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of userfaultfd descriptors (fd instances).
const MAX_UFFD_DESCRIPTORS: usize = 32;

/// Maximum registered ranges per descriptor.
const MAX_RANGES_PER_FD: usize = 64;

/// Maximum pending events per descriptor.
const MAX_EVENTS_PER_FD: usize = 128;

/// Maximum total fault records retained globally.
const MAX_FAULT_RECORDS: usize = 512;

/// Feature: allow non-cooperative event handling.
const UFFD_FEATURE_EVENT_FORK: u64 = 1 << 0;
/// Feature: remap events.
const UFFD_FEATURE_EVENT_REMAP: u64 = 1 << 1;
/// Feature: madvise(DONTNEED) events.
const UFFD_FEATURE_EVENT_REMOVE: u64 = 1 << 2;
/// Feature: unmap events.
const UFFD_FEATURE_EVENT_UNMAP: u64 = 1 << 3;
/// Feature: minor faults (write-protect).
const UFFD_FEATURE_MINOR_HUGETLBFS: u64 = 1 << 4;
/// Feature: minor faults for shmem.
const UFFD_FEATURE_MINOR_SHMEM: u64 = 1 << 5;
/// Feature: exact address in fault events.
const UFFD_FEATURE_EXACT_ADDRESS: u64 = 1 << 6;
/// Feature: write-protect handling.
const UFFD_FEATURE_WP: u64 = 1 << 7;

/// Maximum time (ns) a fault can be pending before timeout.
const FAULT_TIMEOUT_NS: u64 = 5_000_000_000; // 5 seconds

// -------------------------------------------------------------------
// UffdFeature
// -------------------------------------------------------------------

/// Supported userfaultfd features.
pub struct UffdFeature;

impl UffdFeature {
    /// Fork events.
    pub const EVENT_FORK: u64 = UFFD_FEATURE_EVENT_FORK;
    /// Remap events.
    pub const EVENT_REMAP: u64 = UFFD_FEATURE_EVENT_REMAP;
    /// Remove (madvise DONTNEED) events.
    pub const EVENT_REMOVE: u64 = UFFD_FEATURE_EVENT_REMOVE;
    /// Unmap events.
    pub const EVENT_UNMAP: u64 = UFFD_FEATURE_EVENT_UNMAP;
    /// Minor faults on hugetlbfs.
    pub const MINOR_HUGETLBFS: u64 = UFFD_FEATURE_MINOR_HUGETLBFS;
    /// Minor faults on shmem.
    pub const MINOR_SHMEM: u64 = UFFD_FEATURE_MINOR_SHMEM;
    /// Exact address reporting.
    pub const EXACT_ADDRESS: u64 = UFFD_FEATURE_EXACT_ADDRESS;
    /// Write-protect fault handling.
    pub const WP: u64 = UFFD_FEATURE_WP;
}

// -------------------------------------------------------------------
// UffdFaultType
// -------------------------------------------------------------------

/// Type of page fault intercepted by userfaultfd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdFaultType {
    /// Missing page (first access to unallocated page).
    #[default]
    Missing,
    /// Write-protect fault (CoW or WP tracking).
    WriteProtect,
    /// Minor fault (page present but needs update).
    Minor,
}

// -------------------------------------------------------------------
// UffdEventType
// -------------------------------------------------------------------

/// Type of event in the userfaultfd event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdEventType {
    /// Page fault event.
    #[default]
    Pagefault,
    /// Process fork event.
    Fork,
    /// Memory region remap event.
    Remap,
    /// Memory region remove event.
    Remove,
    /// Memory region unmap event.
    Unmap,
}

// -------------------------------------------------------------------
// UffdEvent
// -------------------------------------------------------------------

/// An event delivered to the user-space fault handler.
#[derive(Debug, Clone, Copy)]
pub struct UffdEvent {
    /// Event type.
    pub event_type: UffdEventType,
    /// Fault type (only for Pagefault events).
    pub fault_type: UffdFaultType,
    /// Faulting virtual address (page-aligned).
    pub address: u64,
    /// Flags associated with the fault.
    pub flags: u64,
    /// PID of the faulting thread.
    pub pid: u32,
    /// Thread ID of the faulting thread.
    pub tid: u32,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Whether this event has been read by user-space.
    pub read: bool,
    /// Whether this event has been resolved.
    pub resolved: bool,
    /// Whether this event slot is occupied.
    active: bool,
}

impl UffdEvent {
    /// Create an empty event.
    const fn empty() -> Self {
        Self {
            event_type: UffdEventType::Pagefault,
            fault_type: UffdFaultType::Missing,
            address: 0,
            flags: 0,
            pid: 0,
            tid: 0,
            timestamp_ns: 0,
            read: false,
            resolved: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// UffdRangeMode
// -------------------------------------------------------------------

/// Mode of a registered userfaultfd range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdRangeMode {
    /// Handle missing page faults.
    #[default]
    Missing,
    /// Handle write-protect faults.
    WriteProtect,
    /// Handle minor faults.
    Minor,
    /// Handle both missing and write-protect faults.
    MissingAndWp,
}

// -------------------------------------------------------------------
// UffdRange
// -------------------------------------------------------------------

/// A registered memory range for userfaultfd handling.
#[derive(Debug, Clone, Copy)]
pub struct UffdRange {
    /// Start address (page-aligned).
    pub start: u64,
    /// Length in bytes (page-aligned).
    pub length: u64,
    /// Handling mode.
    pub mode: UffdRangeMode,
    /// Whether this range is active.
    active: bool,
}

impl UffdRange {
    /// Create an empty range.
    const fn empty() -> Self {
        Self {
            start: 0,
            length: 0,
            mode: UffdRangeMode::Missing,
            active: false,
        }
    }

    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start + self.length
    }

    /// Check if an address falls within this range.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.length
    }
}

// -------------------------------------------------------------------
// UffdResolution
// -------------------------------------------------------------------

/// How user-space resolved a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdResolution {
    /// Copied page data into the faulting address.
    #[default]
    Copy,
    /// Mapped a zero page.
    ZeroPage,
    /// Woke the faulting thread without resolving.
    Wake,
    /// Continued with a minor fault update.
    Continue,
    /// Write-protect resolved.
    WriteProtectResolved,
}

// -------------------------------------------------------------------
// UffdState
// -------------------------------------------------------------------

/// State of a userfaultfd descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdState {
    /// Created but not yet initialised (API handshake pending).
    #[default]
    Created,
    /// Initialised and ready.
    Ready,
    /// Waiting for user-space to handle a fault.
    WaitingHandler,
    /// Closed.
    Closed,
}

// -------------------------------------------------------------------
// UffdDescriptor
// -------------------------------------------------------------------

/// Per-fd userfaultfd state.
#[derive(Debug)]
pub struct UffdDescriptor {
    /// File descriptor number.
    fd: u32,
    /// Owning PID.
    owner_pid: u32,
    /// Current state.
    state: UffdState,
    /// Negotiated features.
    features: u64,
    /// Registered ranges.
    ranges: [UffdRange; MAX_RANGES_PER_FD],
    /// Number of registered ranges.
    range_count: usize,
    /// Event queue.
    events: [UffdEvent; MAX_EVENTS_PER_FD],
    /// Number of pending events.
    event_count: usize,
    /// Event write head.
    event_head: usize,
    /// Total faults intercepted.
    total_faults: u64,
    /// Total faults resolved.
    total_resolved: u64,
    /// Total faults timed out.
    total_timeouts: u64,
    /// Whether this descriptor slot is active.
    active: bool,
}

impl UffdDescriptor {
    /// Create an empty descriptor.
    fn empty() -> Self {
        Self {
            fd: 0,
            owner_pid: 0,
            state: UffdState::Created,
            features: 0,
            ranges: [const { UffdRange::empty() }; MAX_RANGES_PER_FD],
            range_count: 0,
            events: [const { UffdEvent::empty() }; MAX_EVENTS_PER_FD],
            event_count: 0,
            event_head: 0,
            total_faults: 0,
            total_resolved: 0,
            total_timeouts: 0,
            active: false,
        }
    }

    /// Check if a fault address is in any registered range.
    fn covers_address(&self, addr: u64) -> bool {
        self.ranges[..self.range_count]
            .iter()
            .any(|r| r.active && r.contains(addr))
    }

    /// Get the range mode for an address, if covered.
    fn range_mode_for(&self, addr: u64) -> Option<UffdRangeMode> {
        self.ranges[..self.range_count]
            .iter()
            .find(|r| r.active && r.contains(addr))
            .map(|r| r.mode)
    }

    /// Enqueue a fault event.
    fn enqueue_event(&mut self, event: UffdEvent) -> Result<()> {
        if self.event_count >= MAX_EVENTS_PER_FD {
            return Err(Error::Busy);
        }
        let idx = self.event_head;
        self.events[idx] = event;
        self.event_head = (self.event_head + 1) % MAX_EVENTS_PER_FD;
        self.event_count += 1;
        Ok(())
    }
}

// -------------------------------------------------------------------
// UffdFaultRecord
// -------------------------------------------------------------------

/// Global record of a page fault handled via userfaultfd.
#[derive(Debug, Clone, Copy)]
pub struct UffdFaultRecord {
    /// Faulting address.
    pub address: u64,
    /// Descriptor FD.
    pub fd: u32,
    /// PID.
    pub pid: u32,
    /// Fault type.
    pub fault_type: UffdFaultType,
    /// Resolution.
    pub resolution: UffdResolution,
    /// Fault timestamp.
    pub fault_ns: u64,
    /// Resolution timestamp.
    pub resolve_ns: u64,
    /// Latency (resolve_ns - fault_ns).
    pub latency_ns: u64,
    /// Active.
    active: bool,
}

impl UffdFaultRecord {
    const fn empty() -> Self {
        Self {
            address: 0,
            fd: 0,
            pid: 0,
            fault_type: UffdFaultType::Missing,
            resolution: UffdResolution::Copy,
            fault_ns: 0,
            resolve_ns: 0,
            latency_ns: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// UffdStats
// -------------------------------------------------------------------

/// Aggregate userfaultfd statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct UffdStats {
    /// Active descriptors.
    pub active_descriptors: usize,
    /// Total faults intercepted.
    pub total_faults: u64,
    /// Total faults resolved.
    pub total_resolved: u64,
    /// Total faults timed out.
    pub total_timeouts: u64,
    /// Total COPY resolutions.
    pub copy_resolutions: u64,
    /// Total ZEROPAGE resolutions.
    pub zero_resolutions: u64,
    /// Total WAKE resolutions.
    pub wake_resolutions: u64,
    /// Total CONTINUE resolutions.
    pub continue_resolutions: u64,
    /// Total WP resolutions.
    pub wp_resolutions: u64,
    /// Total registered ranges.
    pub total_ranges: usize,
    /// Pending events across all descriptors.
    pub pending_events: usize,
    /// Fault records stored.
    pub fault_records: usize,
}

// -------------------------------------------------------------------
// UffdManager
// -------------------------------------------------------------------

/// Top-level userfaultfd manager.
///
/// Manages userfaultfd descriptors, intercepts page faults,
/// forwards events to user-space, and processes resolutions.
///
/// # Example (conceptual)
///
/// ```ignore
/// let mut mgr = UffdManager::new();
/// let fd = mgr.create_fd(100, 0)?;
/// mgr.api_handshake(fd, UffdFeature::EXACT_ADDRESS)?;
/// mgr.register_range(fd, 0x1000, 0x4000, UffdRangeMode::Missing)?;
/// mgr.handle_fault(0x2000, 100, 1, UffdFaultType::Missing, 1000)?;
/// let event = mgr.read_event(fd)?;
/// mgr.resolve_fault(fd, 0x2000, UffdResolution::Copy, 2000)?;
/// ```
pub struct UffdManager {
    /// Descriptor slots.
    descriptors: [UffdDescriptor; MAX_UFFD_DESCRIPTORS],
    /// Next FD number to assign.
    next_fd: u32,
    /// Global fault records.
    records: [UffdFaultRecord; MAX_FAULT_RECORDS],
    /// Number of fault records.
    record_count: usize,
    /// Aggregate stats.
    stats: UffdStats,
}

impl UffdManager {
    /// Create a new userfaultfd manager.
    pub fn new() -> Self {
        Self {
            descriptors: core::array::from_fn(|_| UffdDescriptor::empty()),
            next_fd: 1,
            records: [const { UffdFaultRecord::empty() }; MAX_FAULT_RECORDS],
            record_count: 0,
            stats: UffdStats::default(),
        }
    }

    // ── descriptor lifecycle ─────────────────────────────────────

    /// Create a new userfaultfd descriptor.
    ///
    /// Returns the assigned FD number.
    pub fn create_fd(&mut self, owner_pid: u32, flags: u64) -> Result<u32> {
        let slot = self
            .descriptors
            .iter_mut()
            .find(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd += 1;
        *slot = UffdDescriptor::empty();
        slot.fd = fd;
        slot.owner_pid = owner_pid;
        slot.features = flags;
        slot.active = true;
        slot.state = UffdState::Created;
        Ok(fd)
    }

    /// Perform the API handshake to initialise a descriptor.
    pub fn api_handshake(&mut self, fd: u32, features: u64) -> Result<u64> {
        let desc = self.find_desc_mut(fd)?;
        if desc.state != UffdState::Created {
            return Err(Error::InvalidArgument);
        }
        // Negotiate features.
        let supported = UFFD_FEATURE_EVENT_FORK
            | UFFD_FEATURE_EVENT_REMAP
            | UFFD_FEATURE_EVENT_REMOVE
            | UFFD_FEATURE_EVENT_UNMAP
            | UFFD_FEATURE_MINOR_HUGETLBFS
            | UFFD_FEATURE_MINOR_SHMEM
            | UFFD_FEATURE_EXACT_ADDRESS
            | UFFD_FEATURE_WP;
        let negotiated = features & supported;
        desc.features = negotiated;
        desc.state = UffdState::Ready;
        Ok(negotiated)
    }

    /// Close a userfaultfd descriptor.
    pub fn close_fd(&mut self, fd: u32) -> Result<()> {
        let desc = self.find_desc_mut(fd)?;
        desc.state = UffdState::Closed;
        desc.active = false;
        Ok(())
    }

    // ── range registration ───────────────────────────────────────

    /// Register a memory range for fault interception.
    pub fn register_range(
        &mut self,
        fd: u32,
        start: u64,
        length: u64,
        mode: UffdRangeMode,
    ) -> Result<()> {
        // Validate alignment.
        if start % PAGE_SIZE != 0 || length % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        let desc = self.find_desc_mut(fd)?;
        if desc.state != UffdState::Ready && desc.state != UffdState::WaitingHandler {
            return Err(Error::InvalidArgument);
        }
        if desc.range_count >= MAX_RANGES_PER_FD {
            return Err(Error::OutOfMemory);
        }
        // Check overlap with existing ranges.
        let end = start + length;
        for r in &desc.ranges[..desc.range_count] {
            if r.active && start < r.end() && end > r.start {
                return Err(Error::AlreadyExists);
            }
        }
        desc.ranges[desc.range_count] = UffdRange {
            start,
            length,
            mode,
            active: true,
        };
        desc.range_count += 1;
        Ok(())
    }

    /// Unregister a memory range.
    pub fn unregister_range(&mut self, fd: u32, start: u64, length: u64) -> Result<()> {
        let desc = self.find_desc_mut(fd)?;
        let pos = (0..desc.range_count)
            .find(|&i| {
                desc.ranges[i].active
                    && desc.ranges[i].start == start
                    && desc.ranges[i].length == length
            })
            .ok_or(Error::NotFound)?;
        desc.ranges[pos].active = false;
        // Compact.
        if pos < desc.range_count - 1 {
            desc.ranges[pos] = desc.ranges[desc.range_count - 1];
            desc.ranges[desc.range_count - 1] = UffdRange::empty();
        }
        desc.range_count -= 1;
        Ok(())
    }

    // ── fault handling ───────────────────────────────────────────

    /// Handle a page fault by routing it to the appropriate
    /// userfaultfd descriptor.
    ///
    /// Returns the FD that will handle this fault.
    pub fn handle_fault(
        &mut self,
        address: u64,
        pid: u32,
        tid: u32,
        fault_type: UffdFaultType,
        now_ns: u64,
    ) -> Result<u32> {
        let aligned_addr = address & !(PAGE_SIZE - 1);

        // Find a descriptor covering this address.
        let desc_idx = self
            .descriptors
            .iter()
            .position(|d| {
                d.active && d.state != UffdState::Closed && d.covers_address(aligned_addr)
            })
            .ok_or(Error::NotFound)?;

        let event = UffdEvent {
            event_type: UffdEventType::Pagefault,
            fault_type,
            address: aligned_addr,
            flags: 0,
            pid,
            tid,
            timestamp_ns: now_ns,
            read: false,
            resolved: false,
            active: true,
        };

        let fd = self.descriptors[desc_idx].fd;
        self.descriptors[desc_idx].enqueue_event(event)?;
        self.descriptors[desc_idx].total_faults += 1;
        self.descriptors[desc_idx].state = UffdState::WaitingHandler;
        self.stats.total_faults += 1;
        Ok(fd)
    }

    /// Read the next pending event from a descriptor.
    pub fn read_event(&mut self, fd: u32) -> Result<UffdEvent> {
        let desc = self.find_desc_mut(fd)?;
        // Find first unread event.
        for event in &mut desc.events {
            if event.active && !event.read {
                event.read = true;
                return Ok(*event);
            }
        }
        Err(Error::WouldBlock)
    }

    /// Resolve a page fault.
    pub fn resolve_fault(
        &mut self,
        fd: u32,
        address: u64,
        resolution: UffdResolution,
        now_ns: u64,
    ) -> Result<()> {
        let aligned_addr = address & !(PAGE_SIZE - 1);
        let desc_idx = self
            .descriptors
            .iter()
            .position(|d| d.active && d.fd == fd)
            .ok_or(Error::NotFound)?;

        // Find the matching event.
        let event_idx = self.descriptors[desc_idx]
            .events
            .iter()
            .position(|e| e.active && e.address == aligned_addr && !e.resolved)
            .ok_or(Error::NotFound)?;

        let fault_ns = self.descriptors[desc_idx].events[event_idx].timestamp_ns;
        let fault_type = self.descriptors[desc_idx].events[event_idx].fault_type;
        let owner_pid = self.descriptors[desc_idx].owner_pid;
        self.descriptors[desc_idx].events[event_idx].resolved = true;
        self.descriptors[desc_idx].events[event_idx].active = false;
        self.descriptors[desc_idx].event_count =
            self.descriptors[desc_idx].event_count.saturating_sub(1);
        self.descriptors[desc_idx].total_resolved += 1;

        // Record.
        self.record_fault(
            aligned_addr,
            fd,
            owner_pid,
            fault_type,
            resolution,
            fault_ns,
            now_ns,
        );

        // Update resolution stats.
        match resolution {
            UffdResolution::Copy => {
                self.stats.copy_resolutions += 1;
            }
            UffdResolution::ZeroPage => {
                self.stats.zero_resolutions += 1;
            }
            UffdResolution::Wake => {
                self.stats.wake_resolutions += 1;
            }
            UffdResolution::Continue => {
                self.stats.continue_resolutions += 1;
            }
            UffdResolution::WriteProtectResolved => {
                self.stats.wp_resolutions += 1;
            }
        }
        self.stats.total_resolved += 1;

        // If no more pending events, transition back to Ready.
        if self.descriptors[desc_idx].event_count == 0 {
            self.descriptors[desc_idx].state = UffdState::Ready;
        }

        Ok(())
    }

    /// Check for timed-out faults and mark them.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut timed_out = 0usize;
        for desc in &mut self.descriptors {
            if !desc.active {
                continue;
            }
            for event in &mut desc.events {
                if event.active
                    && !event.resolved
                    && now_ns.saturating_sub(event.timestamp_ns) > FAULT_TIMEOUT_NS
                {
                    event.resolved = true;
                    event.active = false;
                    desc.event_count = desc.event_count.saturating_sub(1);
                    desc.total_timeouts += 1;
                    timed_out += 1;
                }
            }
        }
        self.stats.total_timeouts += timed_out as u64;
        timed_out
    }

    // ── helpers ──────────────────────────────────────────────────

    /// Find a descriptor by FD (mutable).
    fn find_desc_mut(&mut self, fd: u32) -> Result<&mut UffdDescriptor> {
        self.descriptors
            .iter_mut()
            .find(|d| d.active && d.fd == fd)
            .ok_or(Error::NotFound)
    }

    /// Record a fault in the global log.
    fn record_fault(
        &mut self,
        address: u64,
        fd: u32,
        pid: u32,
        fault_type: UffdFaultType,
        resolution: UffdResolution,
        fault_ns: u64,
        resolve_ns: u64,
    ) {
        if self.record_count >= MAX_FAULT_RECORDS {
            // Shift left.
            for i in 1..MAX_FAULT_RECORDS {
                self.records[i - 1] = self.records[i];
            }
            self.record_count = MAX_FAULT_RECORDS - 1;
        }
        self.records[self.record_count] = UffdFaultRecord {
            address,
            fd,
            pid,
            fault_type,
            resolution,
            fault_ns,
            resolve_ns,
            latency_ns: resolve_ns.saturating_sub(fault_ns),
            active: true,
        };
        self.record_count += 1;
    }

    // ── queries ──────────────────────────────────────────────────

    /// Number of active descriptors.
    pub fn active_fd_count(&self) -> usize {
        self.descriptors.iter().filter(|d| d.active).count()
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> UffdStats {
        let mut s = self.stats;
        s.active_descriptors = self.active_fd_count();
        s.total_ranges = self
            .descriptors
            .iter()
            .filter(|d| d.active)
            .map(|d| d.range_count)
            .sum();
        s.pending_events = self
            .descriptors
            .iter()
            .filter(|d| d.active)
            .map(|d| d.event_count)
            .sum();
        s.fault_records = self.record_count;
        s
    }

    /// Get the state of a descriptor.
    pub fn fd_state(&self, fd: u32) -> Result<UffdState> {
        let desc = self
            .descriptors
            .iter()
            .find(|d| d.active && d.fd == fd)
            .ok_or(Error::NotFound)?;
        Ok(desc.state)
    }

    /// Get recent fault records.
    pub fn fault_records(&self) -> &[UffdFaultRecord] {
        &self.records[..self.record_count]
    }

    /// Reset the manager.
    pub fn reset(&mut self) {
        for desc in &mut self.descriptors {
            *desc = UffdDescriptor::empty();
        }
        for record in &mut self.records {
            *record = UffdFaultRecord::empty();
        }
        self.record_count = 0;
        self.next_fd = 1;
        self.stats = UffdStats::default();
    }
}

impl Default for UffdManager {
    fn default() -> Self {
        Self::new()
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd — user-space page fault handling.
//!
//! Userfaultfd (uffd) allows a user-space process to handle its own page
//! faults. When a fault occurs on a registered virtual memory area (VMA),
//! the kernel pauses the faulting thread and delivers a fault notification
//! to a file descriptor held by the process. The process then resolves the
//! fault (e.g., by copying data into the page with `UFFDIO_COPY`) and
//! wakes the faulting thread.
//!
//! # Applications
//!
//! - Live migration (CRIU): capture page contents on first access
//! - On-demand paging for language runtimes and user-space hypervisors
//! - Lazy page population for large sparse allocations
//!
//! # Key types
//!
//! - [`UffdMode`] — operating mode of the uffd instance
//! - [`UffdRegion`] — a VMA range registered with uffd
//! - [`UffdEvent`] — a fault notification delivered to user space
//! - [`UffdIoCmd`] — an ioctl command from user space to resolve a fault
//! - [`UserfaultFd`] — the kernel-side uffd object
//! - [`UffdStats`] — fault delivery statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMA regions a single uffd can monitor.
pub const UFFD_MAX_REGIONS: usize = 256;

/// Maximum number of pending fault events in the uffd queue.
pub const UFFD_EVENT_QUEUE_SIZE: usize = 512;

/// Feature flag: missing-page faults.
pub const UFFD_FEATURE_MISSING: u64 = 1 << 0;
/// Feature flag: write-protect faults.
pub const UFFD_FEATURE_WP: u64 = 1 << 1;
/// Feature flag: minor faults (page present but needs copy-on-write).
pub const UFFD_FEATURE_MINOR: u64 = 1 << 2;
/// Feature flag: thread ID included in event.
pub const UFFD_FEATURE_THREAD_ID: u64 = 1 << 3;

/// Sentinel value indicating "any address" in some operations.
pub const UFFD_ANY_ADDR: u64 = u64::MAX;

// -------------------------------------------------------------------
// UffdMode
// -------------------------------------------------------------------

/// The operating mode of a userfaultfd instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdMode {
    /// Standard mode: the uffd must be read to consume events.
    #[default]
    Standard,
    /// Non-cooperative mode: faults are handled without pause.
    NonCooperative,
}

// -------------------------------------------------------------------
// UffdFaultKind
// -------------------------------------------------------------------

/// The kind of page fault that triggered a uffd event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdFaultKind {
    /// A missing page was accessed (classic demand-paging fault).
    Missing,
    /// A write to a write-protected page.
    WriteProtect,
    /// A minor fault (page exists but needs to be made writable).
    Minor,
    /// Access tracking: a page in a tracked region was accessed.
    AccessTracked,
}

// -------------------------------------------------------------------
// UffdEventKind
// -------------------------------------------------------------------

/// Top-level kind for a userfaultfd event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdEventKind {
    /// A page fault occurred.
    PageFault,
    /// A fork() was performed (uffd fd was duplicated).
    Fork,
    /// A region was remapped with mremap().
    Remap,
    /// A region was removed with munmap() or madvise(MADV_REMOVE).
    Remove,
    /// A region was unmapped.
    Unmap,
}

// -------------------------------------------------------------------
// UffdRegion
// -------------------------------------------------------------------

/// A virtual memory area registered with a userfaultfd instance.
#[derive(Debug, Clone, Copy)]
pub struct UffdRegion {
    /// Start virtual address of the region (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address of the region (exclusive, page-aligned).
    pub end: u64,
    /// Which fault features are enabled for this region.
    pub features: u64,
    /// Whether write-protect mode is enabled on this region.
    pub write_protect: bool,
}

impl UffdRegion {
    /// Create a new registered region.
    pub const fn new(start: u64, end: u64, features: u64) -> Self {
        Self {
            start,
            end,
            features,
            write_protect: features & UFFD_FEATURE_WP != 0,
        }
    }

    /// Return the size of the region in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Return `true` if `addr` falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// -------------------------------------------------------------------
// UffdEvent
// -------------------------------------------------------------------

/// A page fault event delivered via the uffd file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct UffdEvent {
    /// Event kind.
    pub kind: UffdEventKind,
    /// Fault kind (only meaningful for [`UffdEventKind::PageFault`]).
    pub fault_kind: UffdFaultKind,
    /// Faulting virtual address.
    pub fault_addr: u64,
    /// PID of the faulting thread (if `UFFD_FEATURE_THREAD_ID` enabled).
    pub pid: u32,
    /// Thread ID of the faulting thread.
    pub tid: u32,
    /// For Fork events: the new file descriptor in the child.
    pub arg: u64,
    /// Whether the fault was a write.
    pub write: bool,
}

impl UffdEvent {
    /// Construct a missing-page fault event.
    pub const fn missing(fault_addr: u64, pid: u32, tid: u32, write: bool) -> Self {
        Self {
            kind: UffdEventKind::PageFault,
            fault_kind: UffdFaultKind::Missing,
            fault_addr,
            pid,
            tid,
            arg: 0,
            write,
        }
    }

    /// Construct a write-protect fault event.
    pub const fn write_protect(fault_addr: u64, pid: u32, tid: u32) -> Self {
        Self {
            kind: UffdEventKind::PageFault,
            fault_kind: UffdFaultKind::WriteProtect,
            fault_addr,
            pid,
            tid,
            arg: 0,
            write: true,
        }
    }
}

// -------------------------------------------------------------------
// UffdIoCmd
// -------------------------------------------------------------------

/// An ioctl command issued by user space to resolve a pending fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UffdIoCmd {
    /// Copy `src_addr` user data to `dst_addr` and wake the faulting thread.
    Copy {
        /// Destination virtual address (must be page-aligned).
        dst_addr: u64,
        /// Source virtual address of the data to copy.
        src_addr: u64,
        /// Number of bytes to copy (must be page-aligned).
        len: u64,
        /// Wake the faulting thread after the copy.
        wake: bool,
    },
    /// Zero-fill `dst_addr` and wake the faulting thread.
    ZeroPage {
        /// Destination virtual address (must be page-aligned).
        dst_addr: u64,
        /// Number of bytes to zero (must be page-aligned).
        len: u64,
        /// Wake the faulting thread after zeroing.
        wake: bool,
    },
    /// Wake the faulting thread without resolving the fault.
    Wake {
        /// Virtual address range start.
        addr: u64,
        /// Length of the range to wake.
        len: u64,
    },
    /// Write-protect or unprotect a range.
    WriteProtect {
        /// Start of the range.
        start: u64,
        /// Length of the range.
        len: u64,
        /// If `true`, write-protect; if `false`, remove protection.
        protect: bool,
    },
    /// Continue a minor fault.
    Continue {
        /// Start of the range to continue.
        addr: u64,
        /// Length.
        len: u64,
        /// Wake the faulting thread.
        wake: bool,
    },
}

// -------------------------------------------------------------------
// UffdStats
// -------------------------------------------------------------------

/// Aggregate statistics for a userfaultfd instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct UffdStats {
    /// Total missing-page faults delivered.
    pub missing_faults: u64,
    /// Total write-protect faults delivered.
    pub wp_faults: u64,
    /// Total minor faults delivered.
    pub minor_faults: u64,
    /// Total `UFFDIO_COPY` operations processed.
    pub copy_ops: u64,
    /// Total `UFFDIO_ZEROPAGE` operations processed.
    pub zero_ops: u64,
    /// Total `UFFDIO_WAKE` operations processed.
    pub wake_ops: u64,
    /// Number of faults currently pending in the event queue.
    pub pending_faults: u64,
    /// Faults dropped due to a full event queue.
    pub dropped_faults: u64,
}

// -------------------------------------------------------------------
// UserfaultFd
// -------------------------------------------------------------------

/// Kernel-side state for a userfaultfd instance.
///
/// Each process that opens `/dev/userfaultfd` or calls the `userfaultfd(2)`
/// syscall gets one of these objects. It tracks registered regions and
/// provides the event queue for fault notifications.
#[derive(Debug)]
pub struct UserfaultFd {
    /// Registered VMA regions.
    regions: [Option<UffdRegion>; UFFD_MAX_REGIONS],
    /// Number of registered regions.
    region_count: usize,
    /// Pending fault events.
    event_queue: [Option<UffdEvent>; UFFD_EVENT_QUEUE_SIZE],
    /// Write index for the event queue (circular).
    queue_write: usize,
    /// Read index for the event queue (circular).
    queue_read: usize,
    /// Number of events currently in the queue.
    queue_len: usize,
    /// Negotiated feature flags.
    features: u64,
    /// Operating mode.
    mode: UffdMode,
    /// Whether the uffd is closed/finalized.
    closed: bool,
    /// Aggregate statistics.
    stats: UffdStats,
}

impl UserfaultFd {
    /// Create a new userfaultfd instance with the given features.
    pub const fn new(features: u64, mode: UffdMode) -> Self {
        Self {
            regions: [const { None }; UFFD_MAX_REGIONS],
            region_count: 0,
            event_queue: [const { None }; UFFD_EVENT_QUEUE_SIZE],
            queue_write: 0,
            queue_read: 0,
            queue_len: 0,
            features,
            mode,
            closed: false,
            stats: UffdStats {
                missing_faults: 0,
                wp_faults: 0,
                minor_faults: 0,
                copy_ops: 0,
                zero_ops: 0,
                wake_ops: 0,
                pending_faults: 0,
                dropped_faults: 0,
            },
        }
    }

    /// Register a VMA region to be monitored.
    ///
    /// The region must be page-aligned. Features must be a subset of the
    /// features negotiated at uffd creation.
    pub fn register_region(&mut self, start: u64, end: u64, features: u64) -> Result<()> {
        if self.closed {
            return Err(Error::PermissionDenied);
        }
        if start >= end || start % 4096 != 0 || end % 4096 != 0 {
            return Err(Error::InvalidArgument);
        }
        if features & !self.features != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.region_count >= UFFD_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        // Check for overlap with existing regions.
        for slot in self.regions[..self.region_count].iter().flatten() {
            if slot.start < end && slot.end > start {
                return Err(Error::AlreadyExists);
            }
        }
        self.regions[self.region_count] = Some(UffdRegion::new(start, end, features));
        self.region_count += 1;
        Ok(())
    }

    /// Unregister a region by its start address.
    pub fn unregister_region(&mut self, start: u64) -> Result<()> {
        if self.closed {
            return Err(Error::PermissionDenied);
        }
        for slot in self.regions.iter_mut() {
            if let Some(r) = slot {
                if r.start == start {
                    *slot = None;
                    self.region_count = self.region_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Deliver a page fault event to the queue.
    ///
    /// Called by the page-fault handler when a fault occurs in a registered
    /// region. Returns `Err(WouldBlock)` if the queue is full.
    pub fn deliver_fault(&mut self, event: UffdEvent) -> Result<()> {
        if self.closed {
            return Err(Error::PermissionDenied);
        }
        if !self.fault_addr_registered(event.fault_addr) {
            return Err(Error::NotFound);
        }
        if self.queue_len >= UFFD_EVENT_QUEUE_SIZE {
            self.stats.dropped_faults += 1;
            return Err(Error::WouldBlock);
        }
        self.event_queue[self.queue_write] = Some(event);
        self.queue_write = (self.queue_write + 1) % UFFD_EVENT_QUEUE_SIZE;
        self.queue_len += 1;
        self.stats.pending_faults += 1;

        match event.fault_kind {
            UffdFaultKind::Missing => self.stats.missing_faults += 1,
            UffdFaultKind::WriteProtect => self.stats.wp_faults += 1,
            UffdFaultKind::Minor => self.stats.minor_faults += 1,
            UffdFaultKind::AccessTracked => {}
        }
        Ok(())
    }

    /// Read the next pending fault event from the queue.
    ///
    /// Returns `Err(WouldBlock)` if no events are pending.
    pub fn read_event(&mut self) -> Result<UffdEvent> {
        if self.queue_len == 0 {
            return Err(Error::WouldBlock);
        }
        let event = self.event_queue[self.queue_read]
            .take()
            .ok_or(Error::WouldBlock)?;
        self.queue_read = (self.queue_read + 1) % UFFD_EVENT_QUEUE_SIZE;
        self.queue_len -= 1;
        self.stats.pending_faults = self.stats.pending_faults.saturating_sub(1);
        Ok(event)
    }

    /// Process an ioctl command from user space.
    pub fn ioctl(&mut self, cmd: UffdIoCmd) -> Result<()> {
        if self.closed {
            return Err(Error::PermissionDenied);
        }
        match cmd {
            UffdIoCmd::Copy {
                dst_addr,
                len,
                wake,
                ..
            } => {
                if dst_addr % 4096 != 0 || len % 4096 != 0 {
                    return Err(Error::InvalidArgument);
                }
                self.stats.copy_ops += 1;
                if wake {
                    self.stats.wake_ops += 1;
                }
            }
            UffdIoCmd::ZeroPage {
                dst_addr,
                len,
                wake,
            } => {
                if dst_addr % 4096 != 0 || len % 4096 != 0 {
                    return Err(Error::InvalidArgument);
                }
                self.stats.zero_ops += 1;
                if wake {
                    self.stats.wake_ops += 1;
                }
            }
            UffdIoCmd::Wake { .. } => {
                self.stats.wake_ops += 1;
            }
            UffdIoCmd::WriteProtect { start, len, .. } => {
                if start % 4096 != 0 || len % 4096 != 0 {
                    return Err(Error::InvalidArgument);
                }
            }
            UffdIoCmd::Continue { addr, len, wake } => {
                if addr % 4096 != 0 || len % 4096 != 0 {
                    return Err(Error::InvalidArgument);
                }
                if wake {
                    self.stats.wake_ops += 1;
                }
            }
        }
        Ok(())
    }

    /// Close the userfaultfd; no further events will be delivered.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Return `true` if the address falls in any registered region.
    pub fn fault_addr_registered(&self, addr: u64) -> bool {
        self.regions[..self.region_count]
            .iter()
            .flatten()
            .any(|r| r.contains(addr))
    }

    /// Return a snapshot of statistics.
    pub fn stats(&self) -> &UffdStats {
        &self.stats
    }

    /// Return the number of registered regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Return the number of events pending in the queue.
    pub fn pending_count(&self) -> usize {
        self.queue_len
    }

    /// Return `true` if the uffd has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uffd() -> UserfaultFd {
        UserfaultFd::new(UFFD_FEATURE_MISSING | UFFD_FEATURE_WP, UffdMode::Standard)
    }

    #[test]
    fn test_register_and_fault() {
        let mut uffd = make_uffd();
        uffd.register_region(0x1000_0000, 0x1001_0000, UFFD_FEATURE_MISSING)
            .unwrap();
        assert_eq!(uffd.region_count(), 1);

        let event = UffdEvent::missing(0x1000_1000, 1, 1, false);
        uffd.deliver_fault(event).unwrap();
        assert_eq!(uffd.pending_count(), 1);

        let ev = uffd.read_event().unwrap();
        assert_eq!(ev.fault_addr, 0x1000_1000);
        assert_eq!(uffd.pending_count(), 0);
    }

    #[test]
    fn test_unregistered_fault_rejected() {
        let mut uffd = make_uffd();
        let event = UffdEvent::missing(0xDEAD_0000, 1, 1, false);
        assert!(uffd.deliver_fault(event).is_err());
    }

    #[test]
    fn test_overlap_registration_fails() {
        let mut uffd = make_uffd();
        uffd.register_region(0x1000_0000, 0x1010_0000, UFFD_FEATURE_MISSING)
            .unwrap();
        assert!(
            uffd.register_region(0x1008_0000, 0x1020_0000, UFFD_FEATURE_MISSING)
                .is_err()
        );
    }

    #[test]
    fn test_ioctl_copy() {
        let mut uffd = make_uffd();
        uffd.register_region(0x2000_0000, 0x2010_0000, UFFD_FEATURE_MISSING)
            .unwrap();
        uffd.ioctl(UffdIoCmd::Copy {
            dst_addr: 0x2000_0000,
            src_addr: 0x3000_0000,
            len: 4096,
            wake: true,
        })
        .unwrap();
        assert_eq!(uffd.stats().copy_ops, 1);
        assert_eq!(uffd.stats().wake_ops, 1);
    }
}

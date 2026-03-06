// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KASAN — Kernel Address Sanitizer.
//!
//! A dynamic memory error detector that catches out-of-bounds accesses,
//! use-after-free, and invalid memory accesses. Inspired by the Linux
//! `mm/kasan/` subsystem.
//!
//! KASAN uses a **shadow memory** scheme with a 1:8 mapping ratio: every
//! 8 bytes of kernel memory correspond to 1 shadow byte.  The shadow
//! byte encodes how many of those 8 bytes are validly accessible:
//!
//! | Shadow value | Meaning |
//! |---|---|
//! | `0x00` | All 8 bytes are valid |
//! | `1..=7` | Only the first N bytes are valid |
//! | `0xFE` | Redzone (padding between objects) |
//! | `0xFF` | Freed memory |
//!
//! - [`ShadowMemory`] — shadow map with poison/unpoison operations
//! - [`QuarantineQueue`] — ring-buffer of recently freed objects
//! - [`KasanChecker`] — top-level checker combining shadow and quarantine
//! - [`KasanError`] — detected error descriptors
//! - [`KasanReport`] — detailed error report

use oncrix_lib::Result;

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Ratio of real bytes to one shadow byte.
const SHADOW_SCALE: usize = 8;

/// Shadow value indicating all 8 bytes are accessible.
const SHADOW_ACCESSIBLE: u8 = 0x00;

/// Shadow value indicating freed memory.
const SHADOW_FREED: u8 = 0xFF;

/// Shadow value indicating a redzone.
const SHADOW_REDZONE: u8 = 0xFE;

/// Maximum number of shadow bytes tracked.
///
/// At 1:8 ratio this covers 512 KiB of kernel address space, which
/// is sufficient for a kernel-mode sanitizer on moderate workloads.
const MAX_SHADOW_SIZE: usize = 65536;

/// Maximum number of entries in the quarantine ring buffer.
const QUARANTINE_SIZE: usize = 256;

/// Maximum number of error reports retained.
const MAX_REPORTS: usize = 64;

// -------------------------------------------------------------------
// KasanError
// -------------------------------------------------------------------

/// Describes a memory error detected by KASAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KasanError {
    /// Access went past the allocated region.
    OutOfBounds {
        /// Address of the invalid access.
        addr: u64,
        /// Size of the access in bytes.
        access_size: usize,
        /// Whether the access was a write.
        is_write: bool,
    },
    /// Access to memory that has been freed.
    UseAfterFree {
        /// Address of the invalid access.
        addr: u64,
        /// Size of the access in bytes.
        access_size: usize,
        /// Whether the access was a write.
        is_write: bool,
    },
    /// Access to a region that is not validly accessible.
    InvalidAccess {
        /// Address of the invalid access.
        addr: u64,
        /// Size of the access in bytes.
        access_size: usize,
        /// Whether the access was a write.
        is_write: bool,
    },
    /// Access touched a redzone (padding between objects).
    RedzoneTouched {
        /// Address of the invalid access.
        addr: u64,
        /// Size of the access in bytes.
        access_size: usize,
        /// Whether the access was a write.
        is_write: bool,
    },
}

// -------------------------------------------------------------------
// KasanReport
// -------------------------------------------------------------------

/// Detailed error report produced by the KASAN checker.
#[derive(Debug, Clone, Copy)]
pub struct KasanReport {
    /// The detected error.
    pub error: KasanError,
    /// Shadow byte value at the faulting address.
    pub shadow_value: u8,
    /// Allocation identifier (if available from quarantine).
    pub alloc_id: u64,
    /// Size of the original allocation (if known).
    pub alloc_size: u64,
}

// -------------------------------------------------------------------
// ShadowMemory
// -------------------------------------------------------------------

/// Shadow memory map for KASAN address validation.
///
/// Maps every 8 bytes of kernel address space to a single shadow
/// byte. The base address determines the start of the covered
/// region.
pub struct ShadowMemory {
    /// Shadow byte storage.
    shadow: [u8; MAX_SHADOW_SIZE],
    /// Start of the covered kernel address range.
    base_addr: u64,
    /// Number of shadow bytes currently in use.
    size: usize,
}

impl Default for ShadowMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowMemory {
    /// Creates a new, empty shadow memory region.
    pub const fn new() -> Self {
        Self {
            shadow: [SHADOW_FREED; MAX_SHADOW_SIZE],
            base_addr: 0,
            size: 0,
        }
    }

    /// Initialise the shadow memory to cover the region starting at
    /// `base_addr` for `size` shadow bytes.
    ///
    /// `size` is clamped to [`MAX_SHADOW_SIZE`].
    pub fn init(&mut self, base_addr: u64, size: usize) {
        self.base_addr = base_addr;
        self.size = if size > MAX_SHADOW_SIZE {
            MAX_SHADOW_SIZE
        } else {
            size
        };
        // Mark everything as freed/invalid initially.
        for b in &mut self.shadow[..self.size] {
            *b = SHADOW_FREED;
        }
    }

    /// Returns the base address of the covered region.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the number of shadow bytes in use.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Convert a kernel address to a shadow index.
    ///
    /// Returns `None` if the address is outside the covered range.
    fn addr_to_shadow_index(&self, addr: u64) -> Option<usize> {
        if addr < self.base_addr {
            return None;
        }
        let offset = (addr - self.base_addr) as usize / SHADOW_SCALE;
        if offset < self.size {
            Some(offset)
        } else {
            None
        }
    }

    /// Mark a region as poisoned (inaccessible) with the given shadow
    /// value.
    ///
    /// `value` should be one of [`SHADOW_FREED`] or
    /// [`SHADOW_REDZONE`].  Bytes outside the shadow range are
    /// silently ignored.
    pub fn poison_region(&mut self, addr: u64, size: usize, value: u8) {
        let shadow_bytes = size.div_ceil(SHADOW_SCALE);
        if let Some(start) = self.addr_to_shadow_index(addr) {
            let end = core::cmp::min(start + shadow_bytes, self.size);
            for b in &mut self.shadow[start..end] {
                *b = value;
            }
        }
    }

    /// Mark a region as fully accessible (unpoison).
    ///
    /// Bytes outside the shadow range are silently ignored.
    pub fn unpoison_region(&mut self, addr: u64, size: usize) {
        let full_shadow_bytes = size / SHADOW_SCALE;
        let remaining = size % SHADOW_SCALE;

        if let Some(start) = self.addr_to_shadow_index(addr) {
            let end = core::cmp::min(start + full_shadow_bytes, self.size);
            for b in &mut self.shadow[start..end] {
                *b = SHADOW_ACCESSIBLE;
            }
            // Partial trailing byte: encode how many bytes are valid.
            if remaining > 0 && end < self.size {
                self.shadow[end] = remaining as u8;
            }
        }
    }

    /// Read the shadow byte for the given address.
    pub fn read_shadow(&self, addr: u64) -> Option<u8> {
        self.addr_to_shadow_index(addr).map(|i| self.shadow[i])
    }

    /// Check whether a memory access of `size` bytes at `addr` is
    /// valid.
    ///
    /// Returns `Ok(())` if the access is permitted, or the
    /// appropriate [`KasanError`] if not.
    pub fn check_memory_access(
        &self,
        addr: u64,
        size: usize,
        is_write: bool,
    ) -> core::result::Result<(), KasanError> {
        if size == 0 {
            return Ok(());
        }

        // Check each shadow byte covered by the access.
        let mut cur = addr;
        let end = addr.saturating_add(size as u64);

        while cur < end {
            let shadow = match self.read_shadow(cur) {
                Some(s) => s,
                None => {
                    return Err(KasanError::InvalidAccess {
                        addr,
                        access_size: size,
                        is_write,
                    });
                }
            };

            match shadow {
                SHADOW_ACCESSIBLE => {
                    // All 8 bytes valid — skip ahead.
                }
                SHADOW_FREED => {
                    return Err(KasanError::UseAfterFree {
                        addr,
                        access_size: size,
                        is_write,
                    });
                }
                SHADOW_REDZONE => {
                    return Err(KasanError::RedzoneTouched {
                        addr,
                        access_size: size,
                        is_write,
                    });
                }
                1..=7 => {
                    // Partial: only first `shadow` bytes of this
                    // 8-byte group are valid.
                    let group_offset = (cur - self.base_addr) as usize % SHADOW_SCALE;
                    let valid_in_group = shadow as usize;
                    if group_offset >= valid_in_group {
                        return Err(KasanError::OutOfBounds {
                            addr,
                            access_size: size,
                            is_write,
                        });
                    }
                }
                _ => {
                    return Err(KasanError::InvalidAccess {
                        addr,
                        access_size: size,
                        is_write,
                    });
                }
            }

            // Advance to the next shadow-byte boundary.
            let group_start = cur - (cur - self.base_addr) % SHADOW_SCALE as u64;
            cur = group_start + SHADOW_SCALE as u64;
        }

        Ok(())
    }
}

// -------------------------------------------------------------------
// QuarantineEntry
// -------------------------------------------------------------------

/// A single quarantine entry representing a recently freed object.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuarantineEntry {
    /// Virtual address of the freed object.
    pub addr: u64,
    /// Size of the freed object in bytes.
    pub size: u64,
    /// Allocation identifier for correlation.
    pub alloc_id: u64,
}

// -------------------------------------------------------------------
// QuarantineQueue
// -------------------------------------------------------------------

/// Ring buffer of recently freed objects.
///
/// Objects are held in quarantine for a period before their memory is
/// made available for reuse.  This delays reallocation and increases
/// the chance of catching use-after-free bugs.
pub struct QuarantineQueue {
    /// Fixed-size ring buffer.
    entries: [QuarantineEntry; QUARANTINE_SIZE],
    /// Next write position.
    head: usize,
    /// Number of entries currently in the queue.
    count: usize,
}

impl Default for QuarantineQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl QuarantineQueue {
    /// Creates a new, empty quarantine queue.
    pub const fn new() -> Self {
        const EMPTY: QuarantineEntry = QuarantineEntry {
            addr: 0,
            size: 0,
            alloc_id: 0,
        };
        Self {
            entries: [EMPTY; QUARANTINE_SIZE],
            head: 0,
            count: 0,
        }
    }

    /// Push a freed object into the quarantine.
    ///
    /// If the queue is full the oldest entry is evicted and returned
    /// so the caller can reclaim its backing memory.
    pub fn push(&mut self, entry: QuarantineEntry) -> Option<QuarantineEntry> {
        let evicted = if self.count == QUARANTINE_SIZE {
            Some(self.entries[self.head])
        } else {
            self.count += 1;
            None
        };
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % QUARANTINE_SIZE;
        evicted
    }

    /// Look up an entry by address (for report enrichment).
    pub fn find(&self, addr: u64) -> Option<&QuarantineEntry> {
        self.entries
            .iter()
            .take(self.count)
            .find(|e| e.addr == addr)
    }

    /// Returns the number of entries currently in quarantine.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the quarantine is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Drain the quarantine, returning each evicted entry's address
    /// and size for reclamation.
    pub fn drain(&mut self) -> QuarantineDrain<'_> {
        QuarantineDrain { queue: self }
    }
}

/// Iterator returned by [`QuarantineQueue::drain`].
pub struct QuarantineDrain<'a> {
    queue: &'a mut QuarantineQueue,
}

impl Iterator for QuarantineDrain<'_> {
    type Item = QuarantineEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.queue.count == 0 {
            return None;
        }
        // Pop from the tail (oldest entry).
        let tail = if self.queue.head >= self.queue.count {
            self.queue.head - self.queue.count
        } else {
            QUARANTINE_SIZE + self.queue.head - self.queue.count
        };
        let entry = self.queue.entries[tail];
        self.queue.count -= 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.queue.count, Some(self.queue.count))
    }
}

// -------------------------------------------------------------------
// KasanChecker
// -------------------------------------------------------------------

/// Top-level KASAN checker combining shadow memory, quarantine, and
/// report generation.
pub struct KasanChecker {
    /// Shadow memory map.
    shadow: ShadowMemory,
    /// Quarantine queue for recently freed objects.
    quarantine: QuarantineQueue,
    /// Retained error reports (ring buffer).
    reports: [Option<KasanReport>; MAX_REPORTS],
    /// Next write index in the report ring buffer.
    report_idx: usize,
    /// Whether the checker is enabled.
    enabled: bool,
    /// Monotonically increasing allocation identifier.
    next_alloc_id: u64,
}

impl Default for KasanChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl KasanChecker {
    /// Creates a new, disabled KASAN checker.
    pub const fn new() -> Self {
        const NONE_REPORT: Option<KasanReport> = None;
        Self {
            shadow: ShadowMemory::new(),
            quarantine: QuarantineQueue::new(),
            reports: [NONE_REPORT; MAX_REPORTS],
            report_idx: 0,
            enabled: false,
            next_alloc_id: 1,
        }
    }

    /// Initialise and enable the checker.
    ///
    /// `base_addr` is the start of the kernel region to be covered.
    /// `shadow_size` is the number of shadow bytes (clamped to
    /// [`MAX_SHADOW_SIZE`]).
    pub fn enable(&mut self, base_addr: u64, shadow_size: usize) {
        self.shadow.init(base_addr, shadow_size);
        self.enabled = true;
    }

    /// Disable the checker.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns `true` if the checker is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Notify KASAN that a region has been allocated.
    ///
    /// Unpoisons the object region and poisons a trailing redzone.
    /// Returns the allocation identifier assigned to this object.
    pub fn notify_alloc(&mut self, addr: u64, size: usize, redzone_size: usize) -> Result<u64> {
        if !self.enabled {
            return Err(oncrix_lib::Error::NotImplemented);
        }
        let id = self.next_alloc_id;
        self.next_alloc_id += 1;
        self.shadow.unpoison_region(addr, size);
        if redzone_size > 0 {
            self.shadow
                .poison_region(addr + size as u64, redzone_size, SHADOW_REDZONE);
        }
        Ok(id)
    }

    /// Notify KASAN that a region has been freed.
    ///
    /// Poisons the region with [`SHADOW_FREED`] and pushes the
    /// object into the quarantine queue. If the quarantine evicts
    /// an older entry, its address and size are returned so the
    /// caller can reclaim backing memory.
    pub fn notify_free(
        &mut self,
        addr: u64,
        size: usize,
        alloc_id: u64,
    ) -> Option<QuarantineEntry> {
        if !self.enabled {
            return None;
        }
        self.shadow.poison_region(addr, size, SHADOW_FREED);
        let entry = QuarantineEntry {
            addr,
            size: size as u64,
            alloc_id,
        };
        self.quarantine.push(entry)
    }

    /// Validate a memory access.
    ///
    /// On error a [`KasanReport`] is generated and stored in the
    /// report ring buffer.
    pub fn check_memory_access(
        &mut self,
        addr: u64,
        size: usize,
        is_write: bool,
    ) -> core::result::Result<(), KasanError> {
        if !self.enabled {
            return Ok(());
        }
        let result = self.shadow.check_memory_access(addr, size, is_write);
        if let Err(ref err) = result {
            self.record_report(addr, *err);
        }
        result
    }

    /// Record a report into the ring buffer.
    fn record_report(&mut self, addr: u64, error: KasanError) {
        let shadow_value = self.shadow.read_shadow(addr).unwrap_or(0xFF);
        let (alloc_id, alloc_size) = self
            .quarantine
            .find(addr)
            .map(|e| (e.alloc_id, e.size))
            .unwrap_or((0, 0));
        let report = KasanReport {
            error,
            shadow_value,
            alloc_id,
            alloc_size,
        };
        self.reports[self.report_idx] = Some(report);
        self.report_idx = (self.report_idx + 1) % MAX_REPORTS;
    }

    /// Returns the most recently generated report, if any.
    pub fn last_report(&self) -> Option<&KasanReport> {
        let prev = if self.report_idx == 0 {
            MAX_REPORTS - 1
        } else {
            self.report_idx - 1
        };
        self.reports[prev].as_ref()
    }

    /// Returns the total number of reports recorded.
    pub fn report_count(&self) -> usize {
        self.reports.iter().filter(|r| r.is_some()).count()
    }

    /// Returns an immutable reference to the shadow memory.
    pub fn shadow(&self) -> &ShadowMemory {
        &self.shadow
    }

    /// Returns an immutable reference to the quarantine queue.
    pub fn quarantine(&self) -> &QuarantineQueue {
        &self.quarantine
    }
}

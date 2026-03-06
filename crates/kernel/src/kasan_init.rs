// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KASAN (Kernel Address Sanitizer) runtime initialisation.
//!
//! Sets up the shadow memory mapping (1:8 ratio), provides routines
//! to poison and unpoison page-aligned ranges, manages a quarantine
//! pool for use-after-free detection, and formats KASAN violation
//! reports.
//!
//! # Shadow Memory Layout
//!
//! ```text
//! Kernel address:  addr
//! Shadow address:  (addr >> 3) + SHADOW_OFFSET
//!
//! Shadow byte values:
//!   0x00         all 8 kernel bytes accessible
//!   0x01..0x07   first N bytes accessible
//!   POISON_FREE  freed memory (use-after-free)
//!   POISON_SLAB  slab red-zone
//!   POISON_PAGE  freed page (page allocator)
//!   POISON_STACK stack red-zone
//!   0xFF         completely inaccessible
//! ```
//!
//! # Quarantine
//!
//! Freed objects are placed in a FIFO quarantine pool instead of
//! being immediately returned to the allocator. While an object is
//! in quarantine its shadow bytes are poisoned, so any stale
//! pointer dereference triggers a report. Once the quarantine is
//! full, the oldest entry is evicted and returned to the allocator.
//!
//! # Reference
//!
//! Linux `mm/kasan/kasan_init.c`, `mm/kasan/common.c`,
//! `mm/kasan/quarantine.c`, `mm/kasan/report.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Shadow scale shift: 1 shadow byte per 8 kernel bytes.
const SHADOW_SCALE_SHIFT: usize = 3;

/// Shadow scale (derived from shift).
const _SHADOW_SCALE: usize = 1 << SHADOW_SCALE_SHIFT;

/// Shadow memory region size (for our model: 8 MiB / 8 = 1 MiB
/// of shadow). Expressed as number of shadow bytes.
const SHADOW_SIZE: usize = 4096;

/// Shadow offset. In real hardware this is a large constant
/// (e.g. 0xdffffc0000000000 on x86-64). For our model we use
/// a small sentinel.
const SHADOW_OFFSET: u64 = 0x0010_0000;

/// Poison values.
const POISON_FREE: u8 = 0xFE;
const POISON_SLAB: u8 = 0xFC;
const _POISON_PAGE: u8 = 0xFD;
const _POISON_STACK: u8 = 0xFB;
const POISON_INACCESSIBLE: u8 = 0xFF;

/// Maximum quarantine entries.
const QUARANTINE_SIZE: usize = 256;

/// Maximum number of KASAN reports buffered.
const MAX_REPORTS: usize = 32;

/// Maximum report message length (bytes).
const MAX_REPORT_MSG_LEN: usize = 128;

/// Maximum per-allocation metadata entries.
const MAX_ALLOC_META: usize = 512;

/// Maximum stack frames per allocation metadata.
const MAX_ALLOC_FRAMES: usize = 8;

// ══════════════════════════════════════════════════════════════
// ShadowState
// ══════════════════════════════════════════════════════════════

/// High-level state of the KASAN shadow memory subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ShadowState {
    /// Not yet initialised.
    #[default]
    Uninitialised = 0,
    /// Early shadow (identity mapped zero page).
    EarlyShadow = 1,
    /// Full shadow memory set up.
    FullShadow = 2,
}

// ══════════════════════════════════════════════════════════════
// ViolationType
// ══════════════════════════════════════════════════════════════

/// Kind of memory access violation detected by KASAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    /// Out-of-bounds read.
    OutOfBoundsRead,
    /// Out-of-bounds write.
    OutOfBoundsWrite,
    /// Use-after-free read.
    UseAfterFreeRead,
    /// Use-after-free write.
    UseAfterFreeWrite,
    /// Invalid (wild) free.
    InvalidFree,
    /// Double free.
    DoubleFree,
}

// ══════════════════════════════════════════════════════════════
// KasanReport
// ══════════════════════════════════════════════════════════════

/// A buffered KASAN violation report.
#[derive(Debug, Clone)]
pub struct KasanReport {
    /// Violation kind.
    pub violation: ViolationType,
    /// Faulting kernel virtual address.
    pub fault_addr: u64,
    /// Size of the access that triggered the violation.
    pub access_size: usize,
    /// Whether the access was a write (true) or read (false).
    pub is_write: bool,
    /// Instruction pointer at the time of the violation.
    pub ip: u64,
    /// Shadow byte value at the faulting shadow address.
    pub shadow_value: u8,
    /// Human-readable summary.
    message: [u8; MAX_REPORT_MSG_LEN],
    /// Message length.
    message_len: usize,
    /// Timestamp of detection (nanoseconds since boot).
    pub timestamp_ns: u64,
    /// Slot occupied.
    occupied: bool,
}

impl KasanReport {
    /// Empty report.
    const fn empty() -> Self {
        Self {
            violation: ViolationType::OutOfBoundsRead,
            fault_addr: 0,
            access_size: 0,
            is_write: false,
            ip: 0,
            shadow_value: 0,
            message: [0u8; MAX_REPORT_MSG_LEN],
            message_len: 0,
            timestamp_ns: 0,
            occupied: false,
        }
    }

    /// Return the human-readable message.
    pub fn message(&self) -> &[u8] {
        &self.message[..self.message_len]
    }
}

// ══════════════════════════════════════════════════════════════
// QuarantineEntry
// ══════════════════════════════════════════════════════════════

/// A freed allocation held in quarantine.
#[derive(Debug, Clone, Copy)]
struct QuarantineEntry {
    /// Start address of the freed object.
    addr: u64,
    /// Size of the freed object (bytes).
    size: usize,
    /// Timestamp when the object was quarantined.
    quarantined_at_ns: u64,
    /// Slot occupied.
    active: bool,
}

impl QuarantineEntry {
    const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            quarantined_at_ns: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// AllocMeta — per-allocation metadata
// ══════════════════════════════════════════════════════════════

/// Metadata tracked for each allocation, used in violation
/// reports to attribute allocations to their allocation site.
#[derive(Debug, Clone, Copy)]
struct AllocMeta {
    /// Base kernel address of the allocation.
    addr: u64,
    /// Allocation size (bytes).
    size: usize,
    /// Allocation-site instruction pointers (stack trace).
    alloc_frames: [u64; MAX_ALLOC_FRAMES],
    /// Number of valid frames.
    alloc_frame_count: usize,
    /// Free-site instruction pointers (if freed).
    free_frames: [u64; MAX_ALLOC_FRAMES],
    /// Number of valid free frames.
    free_frame_count: usize,
    /// Whether the allocation is still live.
    live: bool,
    /// Slot occupied.
    active: bool,
}

impl AllocMeta {
    const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            alloc_frames: [0u64; MAX_ALLOC_FRAMES],
            alloc_frame_count: 0,
            free_frames: [0u64; MAX_ALLOC_FRAMES],
            free_frame_count: 0,
            live: false,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KasanStats
// ══════════════════════════════════════════════════════════════

/// Aggregate KASAN statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanStats {
    /// Total ranges poisoned.
    pub poison_ops: u64,
    /// Total ranges unpoisoned.
    pub unpoison_ops: u64,
    /// Shadow check operations performed.
    pub check_ops: u64,
    /// Violations detected.
    pub violations: u64,
    /// Objects currently in quarantine.
    pub quarantine_count: u32,
    /// Objects evicted from quarantine.
    pub quarantine_evictions: u64,
    /// Allocations tracked.
    pub allocs_tracked: u64,
}

// ══════════════════════════════════════════════════════════════
// KasanSubsystem
// ══════════════════════════════════════════════════════════════

/// KASAN runtime initialisation and shadow management.
pub struct KasanSubsystem {
    /// Current shadow state.
    state: ShadowState,
    /// Model shadow memory (real impl would be a large
    /// region; here we use a fixed array for the model).
    shadow: [u8; SHADOW_SIZE],
    /// Shadow offset used for address translation.
    shadow_offset: u64,
    /// Quarantine FIFO pool.
    quarantine: [QuarantineEntry; QUARANTINE_SIZE],
    /// Quarantine head (next to evict).
    quarantine_head: usize,
    /// Quarantine tail (next insert position).
    quarantine_tail: usize,
    /// Quarantine active count.
    quarantine_count: u32,
    /// Violation reports ring.
    reports: [KasanReport; MAX_REPORTS],
    /// Report write index.
    report_write: usize,
    /// Total reports generated.
    report_total: u64,
    /// Per-allocation metadata.
    alloc_meta: [AllocMeta; MAX_ALLOC_META],
    /// Stats.
    stats: KasanStats,
}

impl Default for KasanSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl KasanSubsystem {
    /// Create a new, uninitialised KASAN subsystem.
    pub const fn new() -> Self {
        Self {
            state: ShadowState::Uninitialised,
            shadow: [POISON_INACCESSIBLE; SHADOW_SIZE],
            shadow_offset: SHADOW_OFFSET,
            quarantine: [const { QuarantineEntry::empty() }; QUARANTINE_SIZE],
            quarantine_head: 0,
            quarantine_tail: 0,
            quarantine_count: 0,
            reports: [const { KasanReport::empty() }; MAX_REPORTS],
            report_write: 0,
            report_total: 0,
            alloc_meta: [const { AllocMeta::empty() }; MAX_ALLOC_META],
            stats: KasanStats {
                poison_ops: 0,
                unpoison_ops: 0,
                check_ops: 0,
                violations: 0,
                quarantine_count: 0,
                quarantine_evictions: 0,
                allocs_tracked: 0,
            },
        }
    }

    /// Initialise the early shadow (zero-page identity map).
    pub fn init_early_shadow(&mut self) -> Result<()> {
        if self.state != ShadowState::Uninitialised {
            return Err(Error::AlreadyExists);
        }
        // Zero the shadow (all accessible by default for early boot).
        for b in &mut self.shadow {
            *b = 0x00;
        }
        self.state = ShadowState::EarlyShadow;
        Ok(())
    }

    /// Promote to full shadow (allocate real shadow pages).
    pub fn init_full_shadow(&mut self) -> Result<()> {
        if self.state != ShadowState::EarlyShadow {
            return Err(Error::InvalidArgument);
        }
        self.state = ShadowState::FullShadow;
        Ok(())
    }

    /// Return the current shadow state.
    pub fn shadow_state(&self) -> ShadowState {
        self.state
    }

    /// Poison a range of kernel addresses (mark inaccessible).
    ///
    /// `addr` and `size` should be 8-byte aligned for full
    /// shadow-byte coverage, though partial bytes are handled.
    pub fn poison_range(&mut self, addr: u64, size: usize, poison: u8) -> Result<()> {
        if self.state == ShadowState::Uninitialised {
            return Err(Error::NotImplemented);
        }
        let shadow_start = self.addr_to_shadow(addr);
        let shadow_bytes = (size + 7) >> SHADOW_SCALE_SHIFT;

        for i in 0..shadow_bytes {
            let idx = shadow_start + i;
            if idx < SHADOW_SIZE {
                self.shadow[idx] = poison;
            }
        }
        self.stats.poison_ops += 1;
        Ok(())
    }

    /// Unpoison a range (mark fully accessible).
    pub fn unpoison_range(&mut self, addr: u64, size: usize) -> Result<()> {
        self.poison_range(addr, size, 0x00)?;
        // Correct the counter: poison_range incremented poison_ops,
        // but this is an unpoison. Adjust.
        self.stats.poison_ops -= 1;
        self.stats.unpoison_ops += 1;
        Ok(())
    }

    /// Check whether a memory access at `addr` of `size` bytes
    /// is valid according to the shadow.
    ///
    /// Returns `Ok(())` if accessible, or the shadow byte value
    /// wrapped in an `Err` (via `IoError`) if poisoned.
    pub fn check_access(
        &mut self,
        addr: u64,
        size: usize,
        is_write: bool,
        ip: u64,
        timestamp_ns: u64,
    ) -> Result<()> {
        if self.state == ShadowState::Uninitialised {
            return Err(Error::NotImplemented);
        }

        self.stats.check_ops += 1;

        let shadow_start = self.addr_to_shadow(addr);
        let shadow_end_byte = self.addr_to_shadow(addr + size as u64 - 1);

        for idx in shadow_start..=shadow_end_byte {
            if idx >= SHADOW_SIZE {
                break;
            }
            let sv = self.shadow[idx];
            if sv != 0x00 && sv < 0x08 {
                // Partial accessibility — check offset within
                // the 8-byte granule.
                let offset_in_granule = (addr as usize + (idx - shadow_start) * 8) & 0x07;
                if offset_in_granule < sv as usize {
                    continue;
                }
            }
            if sv != 0x00 {
                let violation = classify_violation(sv, is_write);
                self.record_report(violation, addr, size, is_write, ip, sv, timestamp_ns);
                self.stats.violations += 1;
                return Err(Error::IoError);
            }
        }

        Ok(())
    }

    /// Place a freed object into the quarantine pool.
    ///
    /// Returns `Ok(None)` if the pool had room, or `Ok(Some(evicted))`
    /// with the address/size of the evicted entry if the pool was full.
    pub fn quarantine_put(
        &mut self,
        addr: u64,
        size: usize,
        timestamp_ns: u64,
    ) -> Result<Option<(u64, usize)>> {
        // Poison the freed range.
        self.poison_range(addr, size, POISON_FREE)?;

        let evicted = if self.quarantine_count as usize >= QUARANTINE_SIZE {
            // Evict oldest.
            let head = self.quarantine_head % QUARANTINE_SIZE;
            let old = &self.quarantine[head];
            let ev = if old.active {
                Some((old.addr, old.size))
            } else {
                None
            };
            self.quarantine_head += 1;
            self.quarantine_count -= 1;
            self.stats.quarantine_evictions += 1;
            ev
        } else {
            None
        };

        let tail = self.quarantine_tail % QUARANTINE_SIZE;
        self.quarantine[tail] = QuarantineEntry {
            addr,
            size,
            quarantined_at_ns: timestamp_ns,
            active: true,
        };
        self.quarantine_tail += 1;
        self.quarantine_count += 1;
        self.stats.quarantine_count = self.quarantine_count;

        Ok(evicted)
    }

    /// Register an allocation for metadata tracking.
    pub fn track_alloc(&mut self, addr: u64, size: usize, frames: &[u64]) -> Result<()> {
        let slot = self
            .alloc_meta
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        let meta = &mut self.alloc_meta[slot];
        meta.addr = addr;
        meta.size = size;
        let fcount = frames.len().min(MAX_ALLOC_FRAMES);
        meta.alloc_frames[..fcount].copy_from_slice(&frames[..fcount]);
        meta.alloc_frame_count = fcount;
        meta.free_frame_count = 0;
        meta.live = true;
        meta.active = true;

        self.stats.allocs_tracked += 1;
        Ok(())
    }

    /// Record a free event against a tracked allocation.
    pub fn track_free(&mut self, addr: u64, frames: &[u64]) -> Result<()> {
        let slot = self
            .alloc_meta
            .iter()
            .position(|m| m.active && m.live && m.addr == addr)
            .ok_or(Error::NotFound)?;

        let meta = &mut self.alloc_meta[slot];
        meta.live = false;
        let fcount = frames.len().min(MAX_ALLOC_FRAMES);
        meta.free_frames[..fcount].copy_from_slice(&frames[..fcount]);
        meta.free_frame_count = fcount;

        Ok(())
    }

    /// Return the total number of violation reports generated.
    pub fn total_reports(&self) -> u64 {
        self.report_total
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> &KasanStats {
        &self.stats
    }

    /// Fetch the most recent violation report (if any).
    pub fn last_report(&self) -> Option<&KasanReport> {
        if self.report_total == 0 {
            return None;
        }
        let idx = if self.report_write == 0 {
            MAX_REPORTS - 1
        } else {
            self.report_write - 1
        };
        if self.reports[idx].occupied {
            Some(&self.reports[idx])
        } else {
            None
        }
    }

    // ── internal helpers ─────────────────────────────────────

    /// Translate a kernel virtual address to a shadow array index.
    fn addr_to_shadow(&self, addr: u64) -> usize {
        let raw = (addr >> SHADOW_SCALE_SHIFT).wrapping_add(self.shadow_offset);
        (raw as usize) % SHADOW_SIZE
    }

    /// Record a violation report.
    fn record_report(
        &mut self,
        violation: ViolationType,
        addr: u64,
        size: usize,
        is_write: bool,
        ip: u64,
        shadow_value: u8,
        timestamp_ns: u64,
    ) {
        let idx = self.report_write % MAX_REPORTS;
        let rpt = &mut self.reports[idx];

        rpt.violation = violation;
        rpt.fault_addr = addr;
        rpt.access_size = size;
        rpt.is_write = is_write;
        rpt.ip = ip;
        rpt.shadow_value = shadow_value;
        rpt.timestamp_ns = timestamp_ns;
        rpt.occupied = true;

        // Build a compact message.
        let msg = format_violation_msg(violation, addr, size);
        let mlen = msg.len().min(MAX_REPORT_MSG_LEN);
        rpt.message[..mlen].copy_from_slice(&msg[..mlen]);
        rpt.message_len = mlen;

        self.report_write = idx + 1;
        self.report_total += 1;
    }
}

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

/// Classify a shadow byte value into a violation type.
fn classify_violation(shadow: u8, is_write: bool) -> ViolationType {
    match (shadow, is_write) {
        (POISON_FREE, false) => ViolationType::UseAfterFreeRead,
        (POISON_FREE, true) => ViolationType::UseAfterFreeWrite,
        (POISON_SLAB, false) => ViolationType::OutOfBoundsRead,
        (POISON_SLAB, true) => ViolationType::OutOfBoundsWrite,
        (_, false) => ViolationType::OutOfBoundsRead,
        (_, true) => ViolationType::OutOfBoundsWrite,
    }
}

/// Format a compact violation message into a static buffer.
///
/// Returns a byte slice with the formatted text.
fn format_violation_msg(
    violation: ViolationType,
    addr: u64,
    size: usize,
) -> [u8; MAX_REPORT_MSG_LEN] {
    let mut buf = [0u8; MAX_REPORT_MSG_LEN];
    let tag = match violation {
        ViolationType::OutOfBoundsRead => b"OOB-read" as &[u8],
        ViolationType::OutOfBoundsWrite => b"OOB-write",
        ViolationType::UseAfterFreeRead => b"UAF-read",
        ViolationType::UseAfterFreeWrite => b"UAF-write",
        ViolationType::InvalidFree => b"invalid-free",
        ViolationType::DoubleFree => b"double-free",
    };

    let mut pos = 0usize;
    // Copy tag.
    let tlen = tag.len().min(MAX_REPORT_MSG_LEN);
    buf[..tlen].copy_from_slice(&tag[..tlen]);
    pos += tlen;

    // " at 0x"
    let sep = b" at 0x";
    let slen = sep.len().min(MAX_REPORT_MSG_LEN - pos);
    buf[pos..pos + slen].copy_from_slice(&sep[..slen]);
    pos += slen;

    // Hex-encode the address.
    pos = write_hex(&mut buf, pos, addr);

    // " size "
    let ssz = b" size ";
    let szlen = ssz.len().min(MAX_REPORT_MSG_LEN - pos);
    buf[pos..pos + szlen].copy_from_slice(&ssz[..szlen]);
    pos += szlen;

    // Decimal size.
    let _ = write_decimal(&mut buf, pos, size as u64);

    buf
}

/// Write a u64 as hexadecimal into `buf` starting at `pos`.
fn write_hex(buf: &mut [u8], mut pos: usize, val: u64) -> usize {
    let hex = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut v = val;
    let mut len = 0;

    if v == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            pos += 1;
        }
        return pos;
    }

    while v > 0 && len < 16 {
        tmp[len] = hex[(v & 0xF) as usize];
        v >>= 4;
        len += 1;
    }

    for i in (0..len).rev() {
        if pos < buf.len() {
            buf[pos] = tmp[i];
            pos += 1;
        }
    }
    pos
}

/// Write a u64 as decimal into `buf` starting at `pos`.
fn write_decimal(buf: &mut [u8], mut pos: usize, val: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut v = val;
    let mut len = 0;

    if v == 0 {
        if pos < buf.len() {
            buf[pos] = b'0';
            pos += 1;
        }
        return pos;
    }

    while v > 0 && len < 20 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }

    for i in (0..len).rev() {
        if pos < buf.len() {
            buf[pos] = tmp[i];
            pos += 1;
        }
    }
    pos
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe completion queue management — CQ doorbell, phase bit tracking,
//! and interrupt coalescing.
//!
//! # NVMe Completion Queue Model
//!
//! The NVMe completion queue (CQ) is a circular ring in DMA memory. The
//! controller writes Completion Queue Entries (CQEs) to the ring and toggles
//! a phase bit to signal new entries. Software detects completions by reading
//! the phase bit rather than using a separate in-band flag.
//!
//! ## Phase Tag Protocol
//!
//! - At queue creation the driver sets `expected_phase = true` (phase 1).
//! - The controller writes CQEs with `phase = 1` until the ring wraps, then
//!   switches to `phase = 0`, alternating each lap.
//! - The driver advances the CQ head pointer and rings the CQ head doorbell
//!   after consuming each entry.
//!
//! ## Interrupt Coalescing
//!
//! NVMe supports interrupt coalescing through the `Set Features` admin
//! command (Feature ID 0x08). This module models the coalescing state
//! locally: the driver accumulates completions and defers the CQ head
//! doorbell ring until `coalesce_threshold` entries have been processed
//! or `coalesce_time_us` microseconds have elapsed.
//!
//! ## Multi-Queue
//!
//! [`CqManager`] tracks up to [`MAX_CQS`] completion queues across all
//! I/O queue pairs plus the admin queue (CQ 0).
//!
//! Reference: NVM Express Base Specification 2.0, §4.6 (Completion Queue
//! Management); §5.12.1.5 (Interrupt Coalescing feature).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CQEs per queue.
pub const MAX_CQ_DEPTH: usize = 4096;

/// Default CQ depth for I/O queues.
pub const DEFAULT_CQ_DEPTH: usize = 256;

/// Admin CQ depth.
pub const ADMIN_CQ_DEPTH: usize = 64;

/// Maximum number of completion queues tracked by the manager.
pub const MAX_CQS: usize = 16;

/// Doorbell stride in bytes (2^`CAP.DSTRD`). Default = 4 bytes.
pub const DOORBELL_STRIDE: u64 = 4;

/// CQ head doorbell base offset within controller MMIO space.
/// CQ head doorbell for queue `qid` = `DOORBELL_BASE + (2*qid + 1) * DSTRD`.
pub const DOORBELL_BASE: u64 = 0x1000;

/// NVMe completion status: Successful Completion.
pub const SC_SUCCESS: u16 = 0x0000;

/// Default interrupt coalescing threshold (entries before doorbell flush).
pub const DEFAULT_COALESCE_THRESHOLD: u16 = 8;

/// Default coalescing time window (microseconds, informational).
pub const DEFAULT_COALESCE_TIME_US: u32 = 100;

// ---------------------------------------------------------------------------
// Completion Queue Entry
// ---------------------------------------------------------------------------

/// An NVMe Completion Queue Entry (16 bytes per spec Figure 49).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CqEntry {
    /// DW0: command-specific result.
    pub dw0: u32,
    /// DW1: reserved.
    pub dw1: u32,
    /// DW2\[15:0\] = SQ Head Pointer; DW2\[31:16\] = SQ Identifier.
    pub dw2: u32,
    /// DW3\[0\] = Phase Tag; DW3\[15:1\] = Command Identifier;
    /// DW3\[31:17\] = Status Field (DNR, More, SCT, SC).
    pub dw3: u32,
}

impl CqEntry {
    /// Return the Phase Tag (bit 0 of DW3).
    pub fn phase(&self) -> bool {
        self.dw3 & 1 != 0
    }

    /// Return the Command Identifier (bits 31:16 of DW3).
    pub fn command_id(&self) -> u16 {
        (self.dw3 >> 16) as u16
    }

    /// Return the full 15-bit Status Field (bits 31:17 of DW3).
    pub fn status_field(&self) -> u16 {
        (self.dw3 >> 17) as u16
    }

    /// Return `true` if Status Code Type is Generic (0) and Status Code is 0.
    pub fn is_success(&self) -> bool {
        self.status_field() == SC_SUCCESS
    }

    /// Return the SQ Head Pointer (bits 15:0 of DW2).
    pub fn sq_head(&self) -> u16 {
        (self.dw2 & 0xFFFF) as u16
    }

    /// Return the SQ Identifier (bits 31:16 of DW2).
    pub fn sq_id(&self) -> u16 {
        (self.dw2 >> 16) as u16
    }

    /// Return the Status Code Type (bits 11:9 of DW3).
    pub fn status_code_type(&self) -> u8 {
        ((self.dw3 >> 9) & 0x7) as u8
    }

    /// Return the Status Code (bits 8:1 of DW3).
    pub fn status_code(&self) -> u8 {
        ((self.dw3 >> 1) & 0xFF) as u8
    }
}

// ---------------------------------------------------------------------------
// Coalescing state
// ---------------------------------------------------------------------------

/// Interrupt coalescing control for a single CQ.
#[derive(Debug, Clone, Copy)]
pub struct CoalesceState {
    /// Number of completions to accumulate before ringing the doorbell.
    pub threshold: u16,
    /// Coalescing window in microseconds (informational; no HW timer here).
    pub time_window_us: u32,
    /// Completions accumulated since last doorbell.
    pub pending: u16,
}

impl CoalesceState {
    /// Create a new coalescing state with default settings.
    pub const fn new() -> Self {
        Self {
            threshold: DEFAULT_COALESCE_THRESHOLD,
            time_window_us: DEFAULT_COALESCE_TIME_US,
            pending: 0,
        }
    }

    /// Record one completion and return `true` if the doorbell should ring.
    pub fn record(&mut self) -> bool {
        self.pending = self.pending.saturating_add(1);
        self.pending >= self.threshold
    }

    /// Reset the pending count (called after ringing the doorbell).
    pub fn flush(&mut self) {
        self.pending = 0;
    }
}

impl Default for CoalesceState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CqRing — single completion queue
// ---------------------------------------------------------------------------

/// A single NVMe completion queue ring.
///
/// Stores up to `DEFAULT_CQ_DEPTH` CQEs and tracks the head pointer and
/// expected phase bit.
pub struct CqRing<const DEPTH: usize> {
    /// CQE array (DMA-visible; in a real driver this is allocated from
    /// DMA-coherent memory; here it is embedded for simplicity).
    entries: [CqEntry; DEPTH],
    /// CQ head index (driver advances this as entries are consumed).
    head: u16,
    /// Expected phase bit for the next valid CQE.
    phase: bool,
    /// Queue identifier (0 = admin, 1..N = I/O).
    qid: u16,
    /// Controller MMIO base address.
    ctrl_base: u64,
    /// Interrupt coalescing state.
    coalesce: CoalesceState,
    /// Total CQEs consumed since creation.
    total_consumed: u64,
    /// Whether this queue is active.
    active: bool,
}

impl<const DEPTH: usize> CqRing<DEPTH> {
    /// CQ head doorbell offset for this queue.
    fn doorbell_offset(&self) -> u64 {
        DOORBELL_BASE + (2 * self.qid as u64 + 1) * DOORBELL_STRIDE
    }

    /// Ring the CQ head doorbell to notify the controller.
    fn ring_doorbell(&self) {
        // SAFETY: ctrl_base is a valid controller MMIO base provided at
        // construction; the doorbell offset is derived from the spec formula.
        unsafe {
            core::ptr::write_volatile(
                (self.ctrl_base + self.doorbell_offset()) as *mut u32,
                self.head as u32,
            );
        }
    }

    /// Poll for the next valid CQE.
    ///
    /// Checks the phase bit of the entry at the current head. If it matches
    /// the expected phase, the entry is valid and the head advances.
    ///
    /// Returns `Some(CqEntry)` on success or `None` if the queue is empty.
    pub fn poll(&mut self) -> Option<CqEntry> {
        if !self.active {
            return None;
        }
        // SAFETY: Reading from the DMA-visible CQE array with volatile.
        let entry = unsafe {
            core::ptr::read_volatile(&self.entries[self.head as usize] as *const CqEntry)
        };

        if entry.phase() != self.phase {
            return None;
        }

        let result = entry;
        self.head = self.head.wrapping_add(1) % DEPTH as u16;

        // Flip phase at the ring wrap boundary.
        if self.head == 0 {
            self.phase = !self.phase;
        }

        self.total_consumed += 1;

        // Ring doorbell immediately or defer based on coalescing policy.
        if self.coalesce.record() {
            self.coalesce.flush();
            self.ring_doorbell();
        }

        Some(result)
    }

    /// Drain all available CQEs and ring the doorbell once.
    ///
    /// Returns the number of entries drained.
    pub fn drain(&mut self, out: &mut [CqEntry]) -> usize {
        let mut count = 0;
        for slot in out.iter_mut() {
            match self.poll() {
                Some(entry) => {
                    *slot = entry;
                    count += 1;
                }
                None => break,
            }
        }
        // Force a doorbell flush if there are pending coalesced completions.
        if self.coalesce.pending > 0 {
            self.coalesce.flush();
            self.ring_doorbell();
        }
        count
    }

    /// Force a doorbell update regardless of the coalescing threshold.
    pub fn flush_doorbell(&mut self) {
        self.coalesce.flush();
        self.ring_doorbell();
    }

    /// Return the current CQ head index.
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Return the expected phase bit.
    pub fn expected_phase(&self) -> bool {
        self.phase
    }

    /// Return the total number of CQEs consumed since creation.
    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    /// Return the queue ID.
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// Return the physical address of the CQE array for the Create I/O CQ command.
    pub fn dma_addr(&self) -> u64 {
        self.entries.as_ptr() as u64
    }

    /// Return the queue depth.
    pub fn depth(&self) -> usize {
        DEPTH
    }

    /// Return `true` if the queue is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activate the queue.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the queue.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Configure the interrupt coalescing threshold.
    pub fn set_coalesce_threshold(&mut self, threshold: u16) {
        self.coalesce.threshold = threshold;
    }

    /// Configure the coalescing time window (informational).
    pub fn set_coalesce_time(&mut self, us: u32) {
        self.coalesce.time_window_us = us;
    }
}

// ---------------------------------------------------------------------------
// Concrete CQ types
// ---------------------------------------------------------------------------

/// Admin Completion Queue (64 entries).
pub struct AdminCq {
    pub(crate) inner: CqRing<ADMIN_CQ_DEPTH>,
}

impl AdminCq {
    /// Create a new admin CQ.
    pub const fn new(ctrl_base: u64) -> Self {
        Self {
            inner: CqRing {
                entries: [CqEntry {
                    dw0: 0,
                    dw1: 0,
                    dw2: 0,
                    dw3: 0,
                }; ADMIN_CQ_DEPTH],
                head: 0,
                phase: true,
                qid: 0,
                ctrl_base,
                coalesce: CoalesceState::new(),
                total_consumed: 0,
                active: false,
            },
        }
    }

    /// Activate the admin CQ.
    pub fn init(&mut self) {
        self.inner.activate();
    }

    /// Poll for the next completion.
    pub fn poll(&mut self) -> Option<CqEntry> {
        self.inner.poll()
    }

    /// Return the DMA address of the CQE array.
    pub fn dma_addr(&self) -> u64 {
        self.inner.dma_addr()
    }
}

/// I/O Completion Queue (256 entries).
pub struct IoCq {
    pub(crate) inner: CqRing<DEFAULT_CQ_DEPTH>,
}

impl IoCq {
    /// Create a new I/O CQ with the given queue ID.
    pub const fn new(qid: u16, ctrl_base: u64) -> Self {
        Self {
            inner: CqRing {
                entries: [CqEntry {
                    dw0: 0,
                    dw1: 0,
                    dw2: 0,
                    dw3: 0,
                }; DEFAULT_CQ_DEPTH],
                head: 0,
                phase: true,
                qid,
                ctrl_base,
                coalesce: CoalesceState::new(),
                total_consumed: 0,
                active: false,
            },
        }
    }

    /// Activate the I/O CQ.
    pub fn activate(&mut self) {
        self.inner.activate();
    }

    /// Poll for the next completion.
    pub fn poll(&mut self) -> Option<CqEntry> {
        self.inner.poll()
    }

    /// Drain all pending completions into `out`.
    pub fn drain(&mut self, out: &mut [CqEntry]) -> usize {
        self.inner.drain(out)
    }

    /// Return the DMA address of the CQE array.
    pub fn dma_addr(&self) -> u64 {
        self.inner.dma_addr()
    }

    /// Return the queue ID.
    pub fn qid(&self) -> u16 {
        self.inner.qid()
    }

    /// Return `true` if the queue is active.
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    /// Set interrupt coalescing threshold.
    pub fn set_coalesce_threshold(&mut self, threshold: u16) {
        self.inner.set_coalesce_threshold(threshold);
    }
}

// ---------------------------------------------------------------------------
// CqManager
// ---------------------------------------------------------------------------

/// Slot in the CQ manager table.
#[derive(Clone, Copy)]
struct CqSlot {
    qid: u16,
    ctrl_base: u64,
    active: bool,
}

impl CqSlot {
    const EMPTY: Self = Self {
        qid: 0,
        ctrl_base: 0,
        active: false,
    };
}

/// System-wide NVMe completion queue manager.
///
/// Tracks up to [`MAX_CQS`] I/O completion queues and provides a unified
/// allocation and lookup interface.
pub struct CqManager {
    slots: [CqSlot; MAX_CQS],
    count: usize,
}

impl CqManager {
    /// Create an empty manager.
    pub const fn new() -> Self {
        Self {
            slots: [CqSlot::EMPTY; MAX_CQS],
            count: 0,
        }
    }

    /// Register a new completion queue.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if a CQ with the same `qid` is already registered.
    /// - `OutOfMemory` if the table is full.
    pub fn register(&mut self, qid: u16, ctrl_base: u64) -> Result<usize> {
        for slot in &self.slots[..self.count] {
            if slot.active && slot.qid == qid {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_CQS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.slots[idx] = CqSlot {
            qid,
            ctrl_base,
            active: true,
        };
        self.count += 1;
        Ok(idx)
    }

    /// Look up the registration index for a given `qid`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no CQ with `qid` is registered.
    pub fn find(&self, qid: u16) -> Result<usize> {
        for (i, slot) in self.slots[..self.count].iter().enumerate() {
            if slot.active && slot.qid == qid {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Deregister a CQ by `qid`.
    pub fn deregister(&mut self, qid: u16) {
        let pos = self.slots[..self.count]
            .iter()
            .position(|s| s.active && s.qid == qid);
        if let Some(idx) = pos {
            self.slots[idx].active = false;
            if self.count > 0 {
                self.count -= 1;
                self.slots.swap(idx, self.count);
            }
        }
    }

    /// Return the number of registered CQs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no CQs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for CqManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cqe_phase_and_id() {
        let cqe = CqEntry {
            dw0: 0,
            dw1: 0,
            dw2: 0,
            dw3: 0x0001_0001, // CID=0x0000, Phase=1
        };
        assert!(cqe.phase());
        // CID is bits 31:16.
        assert_eq!(cqe.command_id(), 0x0001);
    }

    #[test]
    fn cqe_success_check() {
        let ok = CqEntry {
            dw0: 0,
            dw1: 0,
            dw2: 0,
            dw3: 0x0000_0001, // status=0, phase=1
        };
        assert!(ok.is_success());

        let err = CqEntry {
            dw0: 0,
            dw1: 0,
            dw2: 0,
            dw3: 0x0000_0003, // status bits set, phase=1
        };
        assert!(!err.is_success());
    }

    #[test]
    fn coalesce_state_threshold() {
        let mut c = CoalesceState::new();
        // Should not flush until threshold.
        for _ in 0..(DEFAULT_COALESCE_THRESHOLD - 1) {
            assert!(!c.record());
        }
        assert!(c.record()); // threshold reached
        c.flush();
        assert_eq!(c.pending, 0);
    }

    #[test]
    fn admin_cq_init() {
        let cq = AdminCq::new(0x1000_0000);
        assert!(!cq.inner.is_active());
    }

    #[test]
    fn io_cq_register_find() {
        let mut mgr = CqManager::new();
        mgr.register(1, 0xFEE0_0000).unwrap();
        mgr.register(2, 0xFEE0_0000).unwrap();
        assert_eq!(mgr.count(), 2);
        assert_eq!(mgr.find(1).unwrap(), 0);
        assert_eq!(mgr.find(2).unwrap(), 1);
    }

    #[test]
    fn io_cq_duplicate_rejected() {
        let mut mgr = CqManager::new();
        mgr.register(1, 0).unwrap();
        assert_eq!(mgr.register(1, 0).unwrap_err(), Error::AlreadyExists);
    }

    #[test]
    fn io_cq_not_found() {
        let mgr = CqManager::new();
        assert_eq!(mgr.find(99).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn io_cq_phase_empty() {
        let mut cq = IoCq::new(1, 0);
        cq.activate();
        // No entries have been written — poll must return None.
        assert!(cq.poll().is_none());
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe submission/completion queue pair management.
//!
//! Provides AdminQueue and IoQueue abstractions for managing NVMe
//! command submission and completion queues. The controller communicates
//! through pairs of circular queues in DMA memory, doorbell registers
//! for flow control, and a completion interrupt mechanism.
//!
//! # Queue Architecture
//!
//! - **Admin Queue** — queue pair 0; used for controller management
//!   (Identify, Create/Delete I/O Queues, Get/Set Features).
//! - **I/O Queue** — queue pairs 1..N; used for NVM read/write commands.
//!
//! # Protocol
//!
//! 1. Software writes a command to the Submission Queue (SQ) tail.
//! 2. Software rings the SQ tail doorbell.
//! 3. Controller picks up the command, executes it.
//! 4. Controller writes a Completion Queue Entry (CQE) to the CQ.
//! 5. Software reads the CQE, checks status, rings the CQ head doorbell.
//!
//! Reference: NVM Express Base Specification 2.0, Section 3 (Queue Model)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Admin queue submission queue depth.
const ADMIN_SQ_DEPTH: usize = 64;
/// Admin queue completion queue depth.
const ADMIN_CQ_DEPTH: usize = 64;
/// I/O queue submission queue depth.
const IO_SQ_DEPTH: usize = 256;
/// I/O queue completion queue depth.
const IO_CQ_DEPTH: usize = 256;
/// Maximum number of I/O queue pairs.
const MAX_IO_QUEUES: usize = 4;

/// NVMe Admin Opcodes.
pub const ADMIN_OP_DELETE_IO_SQ: u8 = 0x00;
pub const ADMIN_OP_CREATE_IO_SQ: u8 = 0x01;
pub const ADMIN_OP_DELETE_IO_CQ: u8 = 0x04;
pub const ADMIN_OP_CREATE_IO_CQ: u8 = 0x05;
pub const ADMIN_OP_IDENTIFY: u8 = 0x06;
pub const ADMIN_OP_SET_FEATURES: u8 = 0x09;
pub const ADMIN_OP_GET_FEATURES: u8 = 0x0A;

/// NVMe I/O Opcodes.
pub const IO_OP_FLUSH: u8 = 0x00;
pub const IO_OP_WRITE: u8 = 0x01;
pub const IO_OP_READ: u8 = 0x02;

/// NVMe Completion Status Code Type: Generic Command Status.
pub const SCT_GENERIC: u8 = 0;
/// NVMe Status Code: Successful Completion.
pub const SC_SUCCESS: u8 = 0x00;
/// NVMe Status Code: Invalid Command Opcode.
pub const SC_INVALID_OPCODE: u8 = 0x01;

/// Doorbell stride shift (default: 4 bytes = shift 2).
const DOORBELL_STRIDE_SHIFT: u32 = 2;

// ── SqEntry ──────────────────────────────────────────────────────────────────

/// NVMe Submission Queue Entry (64 bytes, per NVMe spec Figure 11).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SqEntry {
    /// Command DWORD 0: OPC[7:0], FUSE[9:8], PSDT[15:14], CID[31:16].
    pub cdw0: u32,
    /// Namespace Identifier.
    pub nsid: u32,
    /// CDW2 (reserved or command-specific).
    pub cdw2: u32,
    /// CDW3 (reserved or command-specific).
    pub cdw3: u32,
    /// Metadata Pointer.
    pub mptr: u64,
    /// PRP Entry 1 (first data page address).
    pub prp1: u64,
    /// PRP Entry 2 (second data page or PRP list address).
    pub prp2: u64,
    /// CDW10 — command-specific.
    pub cdw10: u32,
    /// CDW11 — command-specific.
    pub cdw11: u32,
    /// CDW12 — command-specific (LBA high for read/write).
    pub cdw12: u32,
    /// CDW13 — command-specific.
    pub cdw13: u32,
    /// CDW14 — command-specific.
    pub cdw14: u32,
    /// CDW15 — command-specific.
    pub cdw15: u32,
}

impl SqEntry {
    /// Return the opcode (bits 7:0 of CDW0).
    pub fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    /// Return the Command ID (bits 31:16 of CDW0).
    pub fn command_id(&self) -> u16 {
        (self.cdw0 >> 16) as u16
    }

    /// Build a Read command.
    pub fn read(cid: u16, nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: (IO_OP_READ as u32) | ((cid as u32) << 16),
            nsid,
            prp1,
            prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: nlb as u32,
            ..Default::default()
        }
    }

    /// Build a Write command.
    pub fn write(cid: u16, nsid: u32, lba: u64, nlb: u16, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: (IO_OP_WRITE as u32) | ((cid as u32) << 16),
            nsid,
            prp1,
            prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: nlb as u32,
            ..Default::default()
        }
    }

    /// Build a Flush command.
    pub fn flush(cid: u16, nsid: u32) -> Self {
        Self {
            cdw0: (IO_OP_FLUSH as u32) | ((cid as u32) << 16),
            nsid,
            ..Default::default()
        }
    }

    /// Build an Identify command.
    pub fn identify(cid: u16, nsid: u32, cns: u8, prp1: u64) -> Self {
        Self {
            cdw0: (ADMIN_OP_IDENTIFY as u32) | ((cid as u32) << 16),
            nsid,
            prp1,
            cdw10: cns as u32,
            ..Default::default()
        }
    }

    /// Build a Create I/O Completion Queue command.
    pub fn create_io_cq(cid: u16, prp1: u64, qid: u16, qsize: u16, irq: u16) -> Self {
        // CDW10: QID[15:0], QSIZE[31:16]
        // CDW11: PC=1 (physically contiguous), IEN=1, IV
        let cdw10 = (qid as u32) | ((qsize as u32) << 16);
        let cdw11 = 0x0003 | ((irq as u32) << 16); // PC + IEN
        Self {
            cdw0: (ADMIN_OP_CREATE_IO_CQ as u32) | ((cid as u32) << 16),
            prp1,
            cdw10,
            cdw11,
            ..Default::default()
        }
    }

    /// Build a Create I/O Submission Queue command.
    pub fn create_io_sq(cid: u16, prp1: u64, qid: u16, qsize: u16, cqid: u16) -> Self {
        let cdw10 = (qid as u32) | ((qsize as u32) << 16);
        let cdw11 = 0x0001 | ((cqid as u32) << 16); // PC=1
        Self {
            cdw0: (ADMIN_OP_CREATE_IO_SQ as u32) | ((cid as u32) << 16),
            prp1,
            cdw10,
            cdw11,
            ..Default::default()
        }
    }

    /// Build a Delete I/O Submission Queue command.
    pub fn delete_io_sq(cid: u16, qid: u16) -> Self {
        Self {
            cdw0: (ADMIN_OP_DELETE_IO_SQ as u32) | ((cid as u32) << 16),
            cdw10: qid as u32,
            ..Default::default()
        }
    }

    /// Build a Delete I/O Completion Queue command.
    pub fn delete_io_cq(cid: u16, qid: u16) -> Self {
        Self {
            cdw0: (ADMIN_OP_DELETE_IO_CQ as u32) | ((cid as u32) << 16),
            cdw10: qid as u32,
            ..Default::default()
        }
    }
}

// ── CqEntry ──────────────────────────────────────────────────────────────────

/// NVMe Completion Queue Entry (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CqEntry {
    /// Command-specific result DW0.
    pub dw0: u32,
    /// Reserved DW1.
    pub dw1: u32,
    /// SQ Head Pointer [15:0], SQ Identifier [31:16].
    pub dw2: u32,
    /// Command ID [15:0], Phase Tag [16], Status Field [31:17].
    pub dw3: u32,
}

impl CqEntry {
    /// Return the Phase Tag bit (bit 16 of DW3).
    pub fn phase(&self) -> bool {
        self.dw3 & (1 << 16) != 0
    }

    /// Return the Command Identifier (bits 15:0 of DW3).
    pub fn command_id(&self) -> u16 {
        (self.dw3 & 0xFFFF) as u16
    }

    /// Return the SQ Head Pointer (bits 15:0 of DW2).
    pub fn sq_head(&self) -> u16 {
        (self.dw2 & 0xFFFF) as u16
    }

    /// Return the SQ Identifier (bits 31:16 of DW2).
    pub fn sq_id(&self) -> u16 {
        (self.dw2 >> 16) as u16
    }

    /// Return the Status Code Type (bits 27:25 of DW3).
    pub fn status_code_type(&self) -> u8 {
        ((self.dw3 >> 25) & 0x7) as u8
    }

    /// Return the Status Code (bits 24:17 of DW3).
    pub fn status_code(&self) -> u8 {
        ((self.dw3 >> 17) & 0xFF) as u8
    }

    /// Return true if the completion indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code_type() == SCT_GENERIC && self.status_code() == SC_SUCCESS
    }
}

// ── QueuePair ────────────────────────────────────────────────────────────────

/// Maximum CQ drain iterations per call to `poll_completion`.
///
/// Prevents an infinite loop if a malicious / buggy device writes phase-bit-
/// matching entries faster than software can drain them.
const MAX_CQ_DRAIN_ITERS: usize = 1024;

/// An NVMe submission + completion queue pair of fixed depth.
///
/// # In-flight CID tracking
///
/// `SQ_DEPTH` must be in the range `[2, 256]` so that all assigned CIDs fit
/// inside a `u8` index.  `alloc_cid` searches the `in_flight` bitmap for a
/// free slot; `poll_completion` rejects any CID from the device that is not
/// currently marked as in-flight, preventing double-completions and
/// use-after-free of the associated DMA buffer.
pub struct QueuePair<const SQ_DEPTH: usize, const CQ_DEPTH: usize> {
    /// Submission queue entries.
    sq: [SqEntry; SQ_DEPTH],
    /// Completion queue entries.
    cq: [CqEntry; CQ_DEPTH],
    /// Queue ID (0 = admin, 1..N = I/O).
    pub queue_id: u16,
    /// SQ tail (where software writes next).
    sq_tail: u16,
    /// CQ head (where software reads next).
    cq_head: u16,
    /// Expected phase bit for next CQE.
    cq_phase: bool,
    /// In-flight CID occupancy bitmap; bit `i` is set when CID `i` is in use.
    /// Length covers `SQ_DEPTH` bits packed into `u64` words.
    in_flight: [u64; 4],
    /// Controller MMIO base (for doorbell access).
    ctrl_base: u64,
    /// Whether this queue is active.
    active: bool,
}

impl<const SQ_DEPTH: usize, const CQ_DEPTH: usize> QueuePair<SQ_DEPTH, CQ_DEPTH> {
    // Const assertion: SQ_DEPTH must fit in the bitmap (max 256 bits = 4×u64).
    // CQ_DEPTH must be >= 1 to avoid an empty queue.
    //
    // NOTE: these are referenced inside `new()` so they are always
    // monomorphized and the assert is actually evaluated at compile time.
    const _ASSERT_SQ_DEPTH: () = assert!(SQ_DEPTH >= 2 && SQ_DEPTH <= 256);
    const _ASSERT_CQ_DEPTH: () = assert!(CQ_DEPTH >= 1 && CQ_DEPTH <= 256);

    /// SQ tail doorbell register offset.
    fn sq_doorbell_offset(&self) -> u64 {
        0x1000 + (2 * self.queue_id as u64) * (1u64 << DOORBELL_STRIDE_SHIFT)
    }

    /// CQ head doorbell register offset.
    fn cq_doorbell_offset(&self) -> u64 {
        0x1000 + (2 * self.queue_id as u64 + 1) * (1u64 << DOORBELL_STRIDE_SHIFT)
    }

    fn ring_sq_doorbell(&self) {
        // SAFETY: Doorbell MMIO write to controller base.
        unsafe {
            core::ptr::write_volatile(
                (self.ctrl_base + self.sq_doorbell_offset()) as *mut u32,
                self.sq_tail as u32,
            );
        }
    }

    fn ring_cq_doorbell(&self) {
        // SAFETY: Doorbell MMIO write to controller base.
        unsafe {
            core::ptr::write_volatile(
                (self.ctrl_base + self.cq_doorbell_offset()) as *mut u32,
                self.cq_head as u32,
            );
        }
    }

    /// Mark CID `cid` as in-flight.
    fn set_in_flight(&mut self, cid: u16) {
        let idx = cid as usize;
        self.in_flight[idx / 64] |= 1u64 << (idx % 64);
    }

    /// Clear the in-flight bit for `cid`.
    fn clear_in_flight(&mut self, cid: u16) {
        let idx = cid as usize;
        self.in_flight[idx / 64] &= !(1u64 << (idx % 64));
    }

    /// Returns `true` if `cid` is currently marked as in-flight.
    fn is_in_flight(&self, cid: u16) -> bool {
        let idx = cid as usize;
        if idx >= SQ_DEPTH {
            return false; // Device-supplied CID outside our range.
        }
        self.in_flight[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    /// Allocate a free command ID from the in-flight bitmap.
    ///
    /// Scans `[0, SQ_DEPTH)` for the first clear bit.
    /// Returns `None` when all slots are occupied (queue full).
    fn alloc_cid(&mut self) -> Option<u16> {
        for i in 0..SQ_DEPTH {
            if self.in_flight[i / 64] & (1u64 << (i % 64)) == 0 {
                let cid = i as u16;
                self.set_in_flight(cid);
                return Some(cid);
            }
        }
        None
    }

    /// Submit a pre-built SqEntry.
    ///
    /// Assigns a command ID (from the in-flight bitmap), writes to SQ, and
    /// rings the doorbell.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the SQ ring or the CID bitmap is full.
    pub fn submit(&mut self, mut entry: SqEntry) -> Result<u16> {
        // Force evaluation of the const-depth assertions so that invalid
        // const parameters (e.g. SQ_DEPTH == 0) are caught at compile time
        // for every monomorphization that actually calls submit().
        let () = Self::_ASSERT_SQ_DEPTH;
        let () = Self::_ASSERT_CQ_DEPTH;

        if !self.active {
            return Err(Error::NotImplemented);
        }
        // Ring-full check: one-slot-open convention.
        let next_tail = (self.sq_tail as usize + 1) % SQ_DEPTH;
        if next_tail == self.cq_head as usize {
            return Err(Error::Busy);
        }
        let cid = self.alloc_cid().ok_or(Error::Busy)?;
        // Embed CID into CDW0 bits 31:16.
        entry.cdw0 = (entry.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);

        // SAFETY: Writing SQ entry to DMA-visible memory.
        unsafe {
            core::ptr::write_volatile(&mut self.sq[self.sq_tail as usize], entry);
        }
        self.sq_tail = next_tail as u16;
        self.ring_sq_doorbell();
        Ok(cid)
    }

    /// Poll for a completion entry.
    ///
    /// Validates that the CID in the CQE was actually submitted (in-flight
    /// check).  A CQE whose CID is not in-flight is silently dropped and the
    /// head advances — this guards against double-completion and
    /// never-submitted-command scenarios from a malicious device.
    ///
    /// Returns `None` if no valid completion is ready (phase tag mismatch).
    ///
    /// # Destructive drain — single-consumer contract
    ///
    /// This method is a **destructive** drain: every CQE it reads advances the
    /// CQ head and rings the doorbell, consuming the entry permanently.  The
    /// queue has no "peek" operation; once a CQE is consumed it cannot be
    /// recovered.
    ///
    /// Callers that submit multiple commands and then poll for a specific CID
    /// **must not** discard completions for other CIDs — doing so would lose
    /// those completions forever.  The correct pattern is to buffer or dispatch
    /// every returned [`CqEntry`] (matched by `command_id()`) rather than
    /// spinning on this method waiting for a single CID.
    ///
    /// Only one software thread may call `poll_completion` on a given
    /// [`QueuePair`] at a time; no concurrent drain is permitted.
    pub fn poll_completion(&mut self) -> Option<CqEntry> {
        // Guard against an infinite drain loop driven by the device.
        let mut iters = 0usize;
        loop {
            if iters >= MAX_CQ_DRAIN_ITERS {
                return None;
            }
            iters = iters.saturating_add(1);

            // Bounds: cq_head is always kept in [0, CQ_DEPTH) below.
            let head = (self.cq_head as usize).min(CQ_DEPTH - 1);
            // SAFETY: Reading CQE from DMA memory with volatile.
            let cqe = unsafe { core::ptr::read_volatile(&self.cq[head]) };
            if cqe.phase() != self.cq_phase {
                return None; // No new completion.
            }
            // Advance CQ head and flip phase on wrap.
            self.cq_head = (self.cq_head as usize + 1) as u16 % CQ_DEPTH as u16;
            if self.cq_head == 0 {
                self.cq_phase = !self.cq_phase;
            }
            self.ring_cq_doorbell();

            // Reject CID not in our in-flight table (double-completion /
            // never-submitted).
            let cid = cqe.command_id();
            if !self.is_in_flight(cid) {
                // Malicious or stale CQE: drop and continue drain.
                continue;
            }
            self.clear_in_flight(cid);
            return Some(cqe);
        }
    }

    /// Return the physical address of the SQ.
    pub fn sq_addr(&self) -> u64 {
        self.sq.as_ptr() as u64
    }

    /// Return the physical address of the CQ.
    pub fn cq_addr(&self) -> u64 {
        self.cq.as_ptr() as u64
    }

    /// Return whether the queue pair is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activate the queue pair.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the queue pair.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

// ── AdminQueue ────────────────────────────────────────────────────────────────

/// NVMe Admin Queue (queue pair 0).
pub struct AdminQueue {
    inner: QueuePair<ADMIN_SQ_DEPTH, ADMIN_CQ_DEPTH>,
}

impl AdminQueue {
    /// Create a new admin queue.
    pub const fn new(ctrl_base: u64) -> Self {
        Self {
            inner: QueuePair {
                sq: [SqEntry {
                    cdw0: 0,
                    nsid: 0,
                    cdw2: 0,
                    cdw3: 0,
                    mptr: 0,
                    prp1: 0,
                    prp2: 0,
                    cdw10: 0,
                    cdw11: 0,
                    cdw12: 0,
                    cdw13: 0,
                    cdw14: 0,
                    cdw15: 0,
                }; ADMIN_SQ_DEPTH],
                cq: [CqEntry {
                    dw0: 0,
                    dw1: 0,
                    dw2: 0,
                    dw3: 0,
                }; ADMIN_CQ_DEPTH],
                queue_id: 0,
                sq_tail: 0,
                cq_head: 0,
                cq_phase: true,
                in_flight: [0u64; 4],
                ctrl_base,
                active: false,
            },
        }
    }

    /// Initialise the admin queue.
    pub fn init(&mut self) {
        self.inner.activate();
    }

    /// Submit an admin command.
    pub fn submit(&mut self, entry: SqEntry) -> Result<u16> {
        self.inner.submit(entry)
    }

    /// Poll for admin completion.
    pub fn poll(&mut self) -> Option<CqEntry> {
        self.inner.poll_completion()
    }

    /// Return the SQ address for writing to AQA/ASQ registers.
    pub fn sq_addr(&self) -> u64 {
        self.inner.sq_addr()
    }

    /// Return the CQ address for writing to ACQ register.
    pub fn cq_addr(&self) -> u64 {
        self.inner.cq_addr()
    }

    /// Submit an Identify command and poll for result.
    ///
    /// Returns the result DW0, or an error on failure/timeout.
    pub fn identify(&mut self, nsid: u32, cns: u8, prp_addr: u64) -> Result<u32> {
        let entry = SqEntry::identify(0, nsid, cns, prp_addr);
        let cid = self.submit(entry)?;
        // Spin-poll for completion.
        for _ in 0..1_000_000u32 {
            if let Some(cqe) = self.poll() {
                if cqe.command_id() == cid {
                    if !cqe.is_success() {
                        return Err(Error::IoError);
                    }
                    return Ok(cqe.dw0);
                }
            }
        }
        Err(Error::Busy)
    }
}

// ── IoQueue ───────────────────────────────────────────────────────────────────

/// An NVMe I/O Queue pair (queue ID 1..N).
pub struct IoQueue {
    inner: QueuePair<IO_SQ_DEPTH, IO_CQ_DEPTH>,
}

impl IoQueue {
    /// Create a new I/O queue with the given ID.
    pub const fn new(queue_id: u16, ctrl_base: u64) -> Self {
        Self {
            inner: QueuePair {
                sq: [SqEntry {
                    cdw0: 0,
                    nsid: 0,
                    cdw2: 0,
                    cdw3: 0,
                    mptr: 0,
                    prp1: 0,
                    prp2: 0,
                    cdw10: 0,
                    cdw11: 0,
                    cdw12: 0,
                    cdw13: 0,
                    cdw14: 0,
                    cdw15: 0,
                }; IO_SQ_DEPTH],
                cq: [CqEntry {
                    dw0: 0,
                    dw1: 0,
                    dw2: 0,
                    dw3: 0,
                }; IO_CQ_DEPTH],
                queue_id,
                sq_tail: 0,
                cq_head: 0,
                cq_phase: true,
                in_flight: [0u64; 4],
                ctrl_base,
                active: false,
            },
        }
    }

    /// Submit a read command.
    pub fn submit_read(
        &mut self,
        nsid: u32,
        lba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16> {
        let entry = SqEntry::read(0, nsid, lba, nlb, prp1, prp2);
        self.inner.submit(entry)
    }

    /// Submit a write command.
    pub fn submit_write(
        &mut self,
        nsid: u32,
        lba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16> {
        let entry = SqEntry::write(0, nsid, lba, nlb, prp1, prp2);
        self.inner.submit(entry)
    }

    /// Submit a flush command.
    pub fn submit_flush(&mut self, nsid: u32) -> Result<u16> {
        let entry = SqEntry::flush(0, nsid);
        self.inner.submit(entry)
    }

    /// Poll for an I/O completion.
    pub fn poll(&mut self) -> Option<CqEntry> {
        self.inner.poll_completion()
    }

    /// Return the queue ID.
    pub fn queue_id(&self) -> u16 {
        self.inner.queue_id
    }

    /// Return the SQ physical address.
    pub fn sq_addr(&self) -> u64 {
        self.inner.sq_addr()
    }

    /// Return the CQ physical address.
    pub fn cq_addr(&self) -> u64 {
        self.inner.cq_addr()
    }

    /// Activate this queue.
    pub fn activate(&mut self) {
        self.inner.activate();
    }

    /// Deactivate this queue.
    pub fn deactivate(&mut self) {
        self.inner.deactivate();
    }

    /// Return whether this queue is active.
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

// ── NvmeQueueSet ─────────────────────────────────────────────────────────────

/// Complete set of NVMe queues for one controller.
pub struct NvmeQueueSet {
    /// Admin queue (always queue 0).
    pub admin: AdminQueue,
    /// I/O queues.
    pub io_queues: [Option<IoQueue>; MAX_IO_QUEUES],
    /// Number of active I/O queues.
    pub io_queue_count: usize,
}

impl NvmeQueueSet {
    /// Create a new queue set for the given controller MMIO base.
    pub const fn new(ctrl_base: u64) -> Self {
        Self {
            admin: AdminQueue::new(ctrl_base),
            io_queues: [const { None }; MAX_IO_QUEUES],
            io_queue_count: 0,
        }
    }

    /// Add an I/O queue to the set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of I/O queues
    /// has been reached.
    pub fn add_io_queue(&mut self, queue: IoQueue) -> Result<usize> {
        if self.io_queue_count >= MAX_IO_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.io_queue_count;
        self.io_queues[idx] = Some(queue);
        self.io_queue_count += 1;
        Ok(idx)
    }

    /// Return a mutable reference to an I/O queue.
    pub fn io_queue_mut(&mut self, idx: usize) -> Option<&mut IoQueue> {
        self.io_queues.get_mut(idx)?.as_mut()
    }

    /// Return the number of I/O queues.
    pub fn io_queue_count(&self) -> usize {
        self.io_queue_count
    }
}

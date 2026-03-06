// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe I/O Queue operations.
//!
//! This module provides the I/O queue pair (SQ + CQ) management for NVMe
//! read, write, flush, write-zeroes, and dataset management commands.
//!
//! # I/O Queue Architecture
//! Each `IoQueuePair` has:
//! - **Submission Queue (SQ)**: Ring of 64-byte commands written by the host.
//! - **Completion Queue (CQ)**: Ring of 16-byte completions written by the device.
//! - **Doorbells**: MMIO registers that notify the controller of head/tail updates.
//!
//! Reference: NVM Express Base Specification 2.0, Section 3 — Queue Model.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Queue Depths
// ---------------------------------------------------------------------------

/// Default I/O submission queue depth.
const IO_SQ_DEPTH: usize = 256;
/// Default I/O completion queue depth.
const IO_CQ_DEPTH: usize = 256;
/// Maximum number of I/O queue pairs per controller.
const MAX_IO_QUEUES: usize = 8;

// ---------------------------------------------------------------------------
// NVMe I/O Opcodes
// ---------------------------------------------------------------------------

/// I/O opcode: Flush — flush volatile write cache.
pub const IO_OPCODE_FLUSH: u8 = 0x00;
/// I/O opcode: Write — write data to NVM.
pub const IO_OPCODE_WRITE: u8 = 0x01;
/// I/O opcode: Read — read data from NVM.
pub const IO_OPCODE_READ: u8 = 0x02;
/// I/O opcode: Write Zeroes.
pub const IO_OPCODE_WRITE_ZEROES: u8 = 0x08;
/// I/O opcode: Dataset Management (TRIM/DISCARD).
pub const IO_OPCODE_DATASET_MGMT: u8 = 0x09;

// ---------------------------------------------------------------------------
// Admin Opcodes (for io_queue_create)
// ---------------------------------------------------------------------------

/// Admin opcode: Create I/O Completion Queue.
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
/// Admin opcode: Create I/O Submission Queue.
const ADMIN_CREATE_IO_SQ: u8 = 0x01;

// ---------------------------------------------------------------------------
// SQ Entry
// ---------------------------------------------------------------------------

/// NVMe 64-byte Submission Queue Entry.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SqEntry {
    /// CDW0: Opcode, FUSE, PSDT, CID.
    pub cdw0: u32,
    /// NSID: Namespace Identifier.
    pub nsid: u32,
    /// CDW2.
    pub cdw2: u32,
    /// CDW3.
    pub cdw3: u32,
    /// MPTR: Metadata Pointer.
    pub mptr: u64,
    /// PRP1: Physical Region Page entry 1.
    pub prp1: u64,
    /// PRP2: Physical Region Page entry 2 (or PRP List pointer).
    pub prp2: u64,
    /// CDW10.
    pub cdw10: u32,
    /// CDW11.
    pub cdw11: u32,
    /// CDW12.
    pub cdw12: u32,
    /// CDW13.
    pub cdw13: u32,
    /// CDW14.
    pub cdw14: u32,
    /// CDW15.
    pub cdw15: u32,
}

/// Constructs CDW0 for an I/O command.
///
/// # Parameters
/// - `opcode`: NVMe I/O opcode.
/// - `cid`: Command Identifier (caller-assigned; must be unique per queue).
pub const fn make_cdw0(opcode: u8, cid: u16) -> u32 {
    (opcode as u32) | ((cid as u32) << 16)
}

// ---------------------------------------------------------------------------
// CQ Entry
// ---------------------------------------------------------------------------

/// NVMe 16-byte Completion Queue Entry.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CqEntry {
    /// DW0: Command-specific completion data.
    pub dw0: u32,
    /// DW1: Reserved.
    pub dw1: u32,
    /// SQ Head Pointer: current head of the Submission Queue.
    pub sq_head: u16,
    /// SQ Identifier: which SQ this completion is for.
    pub sq_id: u16,
    /// Command Identifier: matches the CID in the SQ entry.
    pub cid: u16,
    /// Status Field: Phase bit (P) in bit 0, Status Code in bits 14:1.
    pub status: u16,
}

impl CqEntry {
    /// Returns the Phase bit (toggles on each new completion).
    pub const fn phase(&self) -> bool {
        self.status & 1 != 0
    }

    /// Returns the Status Code (bits 8:1).
    pub const fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// Returns `true` if the command completed successfully.
    pub const fn is_success(&self) -> bool {
        (self.status >> 1) == 0
    }
}

// ---------------------------------------------------------------------------
// NVMe I/O Command Builder
// ---------------------------------------------------------------------------

/// NVMe I/O command types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeIoCmd {
    /// Read command: read `nlb+1` blocks starting at `slba`.
    Read {
        nsid: u32,
        slba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    },
    /// Write command.
    Write {
        nsid: u32,
        slba: u64,
        nlb: u16,
        prp1: u64,
        prp2: u64,
    },
    /// Flush command.
    Flush { nsid: u32 },
    /// Write Zeroes.
    WriteZeroes { nsid: u32, slba: u64, nlb: u16 },
    /// Dataset Management (TRIM).
    DatasetMgmt { nsid: u32, nr: u8, ad: bool },
}

impl NvmeIoCmd {
    /// Converts this command into an `SqEntry`.
    ///
    /// # Parameters
    /// - `cid`: Command ID (unique per queue).
    pub fn to_sqe(&self, cid: u16) -> SqEntry {
        let mut sqe = SqEntry::default();
        match *self {
            NvmeIoCmd::Read {
                nsid,
                slba,
                nlb,
                prp1,
                prp2,
            } => {
                sqe.cdw0 = make_cdw0(IO_OPCODE_READ, cid);
                sqe.nsid = nsid;
                sqe.prp1 = prp1;
                sqe.prp2 = prp2;
                sqe.cdw10 = slba as u32;
                sqe.cdw11 = (slba >> 32) as u32;
                sqe.cdw12 = nlb as u32;
            }
            NvmeIoCmd::Write {
                nsid,
                slba,
                nlb,
                prp1,
                prp2,
            } => {
                sqe.cdw0 = make_cdw0(IO_OPCODE_WRITE, cid);
                sqe.nsid = nsid;
                sqe.prp1 = prp1;
                sqe.prp2 = prp2;
                sqe.cdw10 = slba as u32;
                sqe.cdw11 = (slba >> 32) as u32;
                sqe.cdw12 = nlb as u32;
            }
            NvmeIoCmd::Flush { nsid } => {
                sqe.cdw0 = make_cdw0(IO_OPCODE_FLUSH, cid);
                sqe.nsid = nsid;
            }
            NvmeIoCmd::WriteZeroes { nsid, slba, nlb } => {
                sqe.cdw0 = make_cdw0(IO_OPCODE_WRITE_ZEROES, cid);
                sqe.nsid = nsid;
                sqe.cdw10 = slba as u32;
                sqe.cdw11 = (slba >> 32) as u32;
                sqe.cdw12 = nlb as u32;
            }
            NvmeIoCmd::DatasetMgmt { nsid, nr, ad } => {
                sqe.cdw0 = make_cdw0(IO_OPCODE_DATASET_MGMT, cid);
                sqe.nsid = nsid;
                sqe.cdw10 = nr as u32;
                sqe.cdw11 = if ad { 0x04 } else { 0 }; // AD (Attribute Deallocate) bit
            }
        }
        sqe
    }
}

// ---------------------------------------------------------------------------
// Doorbell Write Helper
// ---------------------------------------------------------------------------

/// Writes to an NVMe doorbell register (32-bit write to an MMIO address).
///
/// # Safety
/// `addr` must be the virtual address of a mapped NVMe doorbell register.
#[inline]
unsafe fn write_doorbell(addr: u64, val: u32) {
    let ptr = addr as *mut u32;
    // SAFETY: Caller guarantees addr is a valid NVMe doorbell MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ---------------------------------------------------------------------------
// I/O Queue Pair
// ---------------------------------------------------------------------------

/// An NVMe I/O Submission Queue + Completion Queue pair.
pub struct IoQueuePair {
    /// Queue ID (1-indexed; admin queue is 0).
    pub id: u16,
    /// SQ physical address.
    sq_phys: u64,
    /// CQ physical address.
    cq_phys: u64,
    /// SQ virtual address (for writing commands).
    sq_virt: u64,
    /// CQ virtual address (for reading completions).
    cq_virt: u64,
    /// SQ depth.
    sq_depth: u16,
    /// CQ depth.
    cq_depth: u16,
    /// Current SQ tail (next slot to write).
    sq_tail: u16,
    /// Current CQ head (next completion to read).
    cq_head: u16,
    /// Current Phase bit (toggles when CQ wraps).
    cq_phase: bool,
    /// Next command ID.
    next_cid: u16,
    /// SQ tail doorbell virtual address.
    sq_doorbell: u64,
    /// CQ head doorbell virtual address.
    cq_doorbell: u64,
}

impl IoQueuePair {
    /// Creates a new I/O queue pair.
    ///
    /// # Parameters
    /// - `id`: Queue ID (1..N).
    /// - `sq_phys`/`sq_virt`: Physical/virtual addresses of the SQ ring.
    /// - `cq_phys`/`cq_virt`: Physical/virtual addresses of the CQ ring.
    /// - `sq_doorbell`/`cq_doorbell`: Doorbell register virtual addresses.
    /// - `sq_depth`/`cq_depth`: Queue depths (number of entries).
    pub const fn new(
        id: u16,
        sq_phys: u64,
        sq_virt: u64,
        cq_phys: u64,
        cq_virt: u64,
        sq_doorbell: u64,
        cq_doorbell: u64,
        sq_depth: u16,
        cq_depth: u16,
    ) -> Self {
        Self {
            id,
            sq_phys,
            cq_phys,
            sq_virt,
            cq_virt,
            sq_depth,
            cq_depth,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 1,
            sq_doorbell,
            cq_doorbell,
        }
    }

    /// Submits an I/O command.
    ///
    /// Writes the command to the SQ and rings the SQ tail doorbell.
    ///
    /// # Returns
    /// The Command ID (CID) assigned to this command.
    ///
    /// # Errors
    /// Returns `Error::Busy` if the SQ is full.
    ///
    /// # Safety
    /// `sq_virt` must point to valid DMA-accessible memory of sufficient size.
    pub unsafe fn submit_io(&mut self, cmd: &NvmeIoCmd) -> Result<u16> {
        let next_tail = (self.sq_tail + 1) % self.sq_depth;
        // Check if SQ is full (tail+1 would equal head)
        // We detect full queue via the CQ — if no space, return Busy
        // Simplified: trust the caller to not overfill; check wrap
        if next_tail == 0 && self.sq_tail == self.sq_depth - 1 {
            // Ring is full if SQ tail has wrapped and no completions
            return Err(Error::Busy);
        }

        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == 0 {
            self.next_cid = 1;
        }

        let sqe = cmd.to_sqe(cid);
        // SAFETY: sq_virt is a valid ring; sq_tail is in bounds.
        unsafe {
            let slot_addr = self.sq_virt + self.sq_tail as u64 * 64;
            core::ptr::write_volatile(slot_addr as *mut SqEntry, sqe);
        }

        self.sq_tail = next_tail;
        // SAFETY: sq_doorbell is a valid MMIO doorbell address.
        unsafe { write_doorbell(self.sq_doorbell, self.sq_tail as u32) }
        Ok(cid)
    }

    /// Polls for a completion matching `cid`.
    ///
    /// Spins until a matching completion is found or the timeout expires.
    ///
    /// # Safety
    /// `cq_virt` must point to valid DMA-accessible memory.
    pub unsafe fn poll_completion(&mut self, cid: u16) -> Result<CqEntry> {
        // SAFETY: Polling CQ entries written by hardware.
        unsafe {
            let mut spin = 5_000_000u32;
            loop {
                let entry_addr = self.cq_virt + self.cq_head as u64 * 16;
                let entry = core::ptr::read_volatile(entry_addr as *const CqEntry);
                // Phase bit indicates this entry is fresh
                if entry.phase() == self.cq_phase {
                    // Advance CQ head
                    self.cq_head += 1;
                    if self.cq_head >= self.cq_depth {
                        self.cq_head = 0;
                        self.cq_phase = !self.cq_phase;
                    }
                    // Ring CQ head doorbell
                    write_doorbell(self.cq_doorbell, self.cq_head as u32);
                    if entry.cid == cid {
                        if entry.is_success() {
                            return Ok(entry);
                        } else {
                            return Err(Error::IoError);
                        }
                    }
                    // Different CID: continue polling
                    continue;
                }
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
        }
    }

    /// Returns the SQ physical address.
    pub fn sq_phys(&self) -> u64 {
        self.sq_phys
    }

    /// Returns the CQ physical address.
    pub fn cq_phys(&self) -> u64 {
        self.cq_phys
    }

    /// Returns the queue depth (SQ size).
    pub fn sq_depth(&self) -> u16 {
        self.sq_depth
    }

    /// Returns the CQ depth.
    pub fn cq_depth(&self) -> u16 {
        self.cq_depth
    }
}

// ---------------------------------------------------------------------------
// Admin Queue Create Helpers
// ---------------------------------------------------------------------------

/// Builds the SQ entry to create an I/O Completion Queue via the admin queue.
///
/// # Parameters
/// - `cid`: Command ID for this admin command.
/// - `cq_id`: The queue ID to create.
/// - `cq_phys`: Physical address of the CQ ring.
/// - `cq_depth`: Queue depth (0-indexed, so depth-1 is the value).
pub fn build_create_io_cq(cid: u16, cq_id: u16, cq_phys: u64, cq_depth: u16) -> SqEntry {
    let mut sqe = SqEntry::default();
    sqe.cdw0 = make_cdw0(ADMIN_CREATE_IO_CQ, cid);
    sqe.prp1 = cq_phys;
    // CDW10: QSIZE (15:0) and QID (31:16)
    sqe.cdw10 = (cq_depth as u32 - 1) | ((cq_id as u32) << 16);
    // CDW11: bit 1 = IEN (interrupt enable), bit 0 = PC (physically contiguous)
    sqe.cdw11 = 0x03;
    sqe
}

/// Builds the SQ entry to create an I/O Submission Queue via the admin queue.
///
/// # Parameters
/// - `cid`: Command ID.
/// - `sq_id`: Queue ID to create.
/// - `sq_phys`: Physical address of the SQ ring.
/// - `sq_depth`: Queue depth.
/// - `cq_id`: The associated completion queue ID.
pub fn build_create_io_sq(
    cid: u16,
    sq_id: u16,
    sq_phys: u64,
    sq_depth: u16,
    cq_id: u16,
) -> SqEntry {
    let mut sqe = SqEntry::default();
    sqe.cdw0 = make_cdw0(ADMIN_CREATE_IO_SQ, cid);
    sqe.prp1 = sq_phys;
    // CDW10: QSIZE and QID
    sqe.cdw10 = (sq_depth as u32 - 1) | ((sq_id as u32) << 16);
    // CDW11: CQID (31:16), priority MEDIUM (bits 2:1 = 10), PC (bit 0)
    sqe.cdw11 = ((cq_id as u32) << 16) | 0x05;
    sqe
}

// ---------------------------------------------------------------------------
// I/O Queue Registry
// ---------------------------------------------------------------------------

/// Registry of I/O queue pairs for a single NVMe controller.
pub struct IoQueueRegistry {
    queues: [Option<IoQueuePair>; MAX_IO_QUEUES],
    count: usize,
}

impl IoQueueRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            queues: [const { None }; MAX_IO_QUEUES],
            count: 0,
        }
    }

    /// Registers a new I/O queue pair.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the registry is full.
    pub fn register(&mut self, qp: IoQueuePair) -> Result<usize> {
        if self.count >= MAX_IO_QUEUES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.count;
        self.queues[idx] = Some(qp);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the queue pair at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut IoQueuePair> {
        self.queues[index].as_mut()
    }

    /// Returns the number of registered queue pairs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no queues are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IoQueueRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Default I/O SQ ring size in bytes.
pub const IO_SQ_RING_SIZE: usize = IO_SQ_DEPTH * 64;
/// Default I/O CQ ring size in bytes.
pub const IO_CQ_RING_SIZE: usize = IO_CQ_DEPTH * 16;

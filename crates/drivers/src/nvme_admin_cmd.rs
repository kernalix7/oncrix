// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe admin command handling.
//!
//! Implements submission and result parsing for NVMe admin commands:
//! Identify Controller/Namespace, Create/Delete I/O CQ/SQ, Get/Set Features,
//! firmware operations, and namespace management.
//!
//! This module owns the admin submission queue state and provides typed helpers
//! for each admin opcode. It does not perform MMIO directly; instead it
//! constructs submission queue entries ([`AdminSqe`]) that the caller writes
//! to the controller's admin SQ.
//!
//! Reference: NVM Express Base Specification 2.0, Section 5 (Admin Command Set);
//! Linux `drivers/nvme/host/core.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Admin Opcodes
// ---------------------------------------------------------------------------

/// Admin opcode: Delete I/O Submission Queue.
pub const ADMIN_DELETE_IO_SQ: u8 = 0x00;
/// Admin opcode: Create I/O Submission Queue.
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;
/// Admin opcode: Delete I/O Completion Queue.
pub const ADMIN_DELETE_IO_CQ: u8 = 0x04;
/// Admin opcode: Create I/O Completion Queue.
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
/// Admin opcode: Identify.
pub const ADMIN_IDENTIFY: u8 = 0x06;
/// Admin opcode: Abort.
pub const ADMIN_ABORT: u8 = 0x08;
/// Admin opcode: Set Features.
pub const ADMIN_SET_FEATURES: u8 = 0x09;
/// Admin opcode: Get Features.
pub const ADMIN_GET_FEATURES: u8 = 0x0A;
/// Admin opcode: Async Event Request.
pub const ADMIN_ASYNC_EVENT: u8 = 0x0C;
/// Admin opcode: Namespace Management.
pub const ADMIN_NS_MGMT: u8 = 0x0D;
/// Admin opcode: Firmware Activate.
pub const ADMIN_FW_ACTIVATE: u8 = 0x10;
/// Admin opcode: Firmware Image Download.
pub const ADMIN_FW_DOWNLOAD: u8 = 0x11;

// ---------------------------------------------------------------------------
// Feature Identifiers
// ---------------------------------------------------------------------------

/// Feature: Number of Queues.
pub const FEAT_NUM_QUEUES: u8 = 0x07;
/// Feature: Interrupt Coalescing.
pub const FEAT_IRQ_COALESCING: u8 = 0x08;
/// Feature: Write Atomicity Normal.
pub const FEAT_WRITE_ATOMICITY: u8 = 0x0A;
/// Feature: Async Event Configuration.
pub const FEAT_ASYNC_EVENT_CFG: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Identify CNS values
// ---------------------------------------------------------------------------

/// Identify: return Identify Namespace data structure.
pub const IDENTIFY_CNS_NS: u8 = 0x00;
/// Identify: return Identify Controller data structure.
pub const IDENTIFY_CNS_CTRL: u8 = 0x01;
/// Identify: return list of active Namespace IDs.
pub const IDENTIFY_CNS_NS_LIST: u8 = 0x02;

// ---------------------------------------------------------------------------
// Admin SQE (Submission Queue Entry)
// ---------------------------------------------------------------------------

/// NVMe Submission Queue Entry for admin commands (64 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AdminSqe {
    /// Command Dword 0: opcode, fuse, PSDT, CID.
    pub cdw0: u32,
    /// Namespace ID (0xFFFF_FFFF = all namespaces).
    pub nsid: u32,
    /// Reserved Dwords 2–3.
    pub reserved: [u32; 2],
    /// Metadata Pointer.
    pub mptr: u64,
    /// Physical Region Page entry 1 (data pointer lo).
    pub prp1: u64,
    /// Physical Region Page entry 2 (data pointer hi / PRP list).
    pub prp2: u64,
    /// Command-specific Dwords 10–15.
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl AdminSqe {
    /// Set the opcode and command ID in CDW0.
    pub fn set_opcode(&mut self, opcode: u8, cid: u16) {
        self.cdw0 = u32::from(opcode) | (u32::from(cid) << 16);
    }
}

// ---------------------------------------------------------------------------
// Admin CQE (Completion Queue Entry)
// ---------------------------------------------------------------------------

/// NVMe Completion Queue Entry (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AdminCqe {
    /// Command-specific result DW0.
    pub result: u32,
    /// Reserved.
    pub reserved: u32,
    /// SQ Head Pointer.
    pub sq_head: u16,
    /// SQ Identifier.
    pub sq_id: u16,
    /// Command Identifier.
    pub cid: u16,
    /// Status Field (includes Phase Tag in bit 0).
    pub status: u16,
}

impl AdminCqe {
    /// Returns the status code (bits [14:1]).
    pub fn status_code(&self) -> u8 {
        ((self.status >> 1) & 0xFF) as u8
    }

    /// Returns `true` if the command completed successfully.
    pub fn is_success(&self) -> bool {
        self.status_code() == 0
    }

    /// Returns the phase tag (bit 0).
    pub fn phase(&self) -> bool {
        self.status & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// Identify Data Structures (abbreviated)
// ---------------------------------------------------------------------------

/// Abbreviated Identify Controller data structure (relevant fields only).
#[derive(Debug, Clone, Copy)]
pub struct IdentifyController {
    /// PCI Vendor ID.
    pub vid: u16,
    /// PCI Subsystem Vendor ID.
    pub ssvid: u16,
    /// Serial Number (ASCII, 20 bytes).
    pub sn: [u8; 20],
    /// Model Number (ASCII, 40 bytes).
    pub mn: [u8; 40],
    /// Firmware Revision (ASCII, 8 bytes).
    pub fr: [u8; 8],
    /// Maximum Data Transfer Size (MDTS, power of two in pages; 0 = no limit).
    pub mdts: u8,
    /// Number of namespaces (NN).
    pub nn: u32,
}

impl Default for IdentifyController {
    fn default() -> Self {
        Self {
            vid: 0,
            ssvid: 0,
            sn: [0u8; 20],
            mn: [0u8; 40],
            fr: [0u8; 8],
            mdts: 0,
            nn: 0,
        }
    }
}

/// Abbreviated Identify Namespace data structure.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentifyNamespace {
    /// Namespace Size in logical blocks.
    pub nsze: u64,
    /// Namespace Capacity in logical blocks.
    pub ncap: u64,
    /// Namespace Utilization in logical blocks.
    pub nuse: u64,
    /// Formatted LBA Size index.
    pub flbas: u8,
    /// Number of LBA Formats (NLBAF, 0-based).
    pub nlbaf: u8,
}

// ---------------------------------------------------------------------------
// Admin Queue State
// ---------------------------------------------------------------------------

/// Maximum admin queue depth.
const ADMIN_QUEUE_DEPTH: usize = 64;

/// Admin SQ/CQ pair state.
pub struct AdminQueue {
    /// Submission queue entries.
    sq: [AdminSqe; ADMIN_QUEUE_DEPTH],
    /// Completion queue entries.
    cq: [AdminCqe; ADMIN_QUEUE_DEPTH],
    /// SQ tail (next entry to write).
    sq_tail: usize,
    /// CQ head (next entry to read).
    cq_head: usize,
    /// Expected phase tag for CQ entries.
    cq_phase: bool,
    /// Next command ID to assign.
    next_cid: u16,
}

impl AdminQueue {
    /// Create a new admin queue.
    pub const fn new() -> Self {
        Self {
            sq: [const {
                AdminSqe {
                    cdw0: 0,
                    nsid: 0,
                    reserved: [0u32; 2],
                    mptr: 0,
                    prp1: 0,
                    prp2: 0,
                    cdw10: 0,
                    cdw11: 0,
                    cdw12: 0,
                    cdw13: 0,
                    cdw14: 0,
                    cdw15: 0,
                }
            }; ADMIN_QUEUE_DEPTH],
            cq: [const {
                AdminCqe {
                    result: 0,
                    reserved: 0,
                    sq_head: 0,
                    sq_id: 0,
                    cid: 0,
                    status: 0,
                }
            }; ADMIN_QUEUE_DEPTH],
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 1,
        }
    }

    /// Enqueue an admin SQE.
    ///
    /// Returns the slot index and the assigned CID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the queue is full.
    pub fn submit(&mut self, mut sqe: AdminSqe) -> Result<(usize, u16)> {
        let next = (self.sq_tail + 1) % ADMIN_QUEUE_DEPTH;
        if next == self.cq_head {
            return Err(Error::Busy);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1).max(1);
        sqe.set_opcode((sqe.cdw0 & 0xFF) as u8, cid);
        let slot = self.sq_tail;
        self.sq[slot] = sqe;
        self.sq_tail = next;
        Ok((slot, cid))
    }

    /// Consume the next completion entry if phase matches.
    ///
    /// Returns `None` if no completion is available.
    pub fn poll_cq(&mut self) -> Option<AdminCqe> {
        let cqe = self.cq[self.cq_head];
        if cqe.phase() != self.cq_phase {
            return None;
        }
        let entry = cqe;
        self.cq_head = (self.cq_head + 1) % ADMIN_QUEUE_DEPTH;
        if self.cq_head == 0 {
            self.cq_phase = !self.cq_phase;
        }
        Some(entry)
    }

    /// Returns the current SQ tail (doorbell value to write).
    pub fn sq_tail(&self) -> u32 {
        self.sq_tail as u32
    }

    /// Returns the current CQ head (doorbell value to write after consume).
    pub fn cq_head(&self) -> u32 {
        self.cq_head as u32
    }
}

impl Default for AdminQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Admin Command Builder Helpers
// ---------------------------------------------------------------------------

/// Build an Identify Controller SQE.
///
/// `prp1` must point to a 4 KiB DMA-capable buffer that will receive the
/// Identify Controller data structure.
pub fn build_identify_ctrl(prp1: u64) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_IDENTIFY);
    sqe.nsid = 0;
    sqe.prp1 = prp1;
    sqe.cdw10 = u32::from(IDENTIFY_CNS_CTRL);
    sqe
}

/// Build an Identify Namespace SQE.
pub fn build_identify_ns(nsid: u32, prp1: u64) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_IDENTIFY);
    sqe.nsid = nsid;
    sqe.prp1 = prp1;
    sqe.cdw10 = u32::from(IDENTIFY_CNS_NS);
    sqe
}

/// Build a Create I/O Completion Queue SQE.
///
/// `prp1` — physical address of the CQ memory.
/// `qid` — queue identifier (1-based).
/// `qsize` — number of entries minus one (0-based).
/// `irq_vector` — MSI/MSI-X vector for this CQ.
pub fn build_create_io_cq(prp1: u64, qid: u16, qsize: u16, irq_vector: u16) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_CREATE_IO_CQ);
    sqe.prp1 = prp1;
    // CDW10: QID[15:0] | QSIZE[31:16]
    sqe.cdw10 = u32::from(qid) | (u32::from(qsize) << 16);
    // CDW11: PC=1 (physically contiguous), IEN=1, IV=irq_vector
    sqe.cdw11 = 0x0003 | (u32::from(irq_vector) << 16);
    sqe
}

/// Build a Create I/O Submission Queue SQE.
///
/// `prp1` — physical address of the SQ memory.
/// `qid` — queue identifier (1-based).
/// `qsize` — number of entries minus one.
/// `cqid` — associated completion queue identifier.
pub fn build_create_io_sq(prp1: u64, qid: u16, qsize: u16, cqid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_CREATE_IO_SQ);
    sqe.prp1 = prp1;
    sqe.cdw10 = u32::from(qid) | (u32::from(qsize) << 16);
    // CDW11: PC=1, QPRIO=00 (urgent), CQID
    sqe.cdw11 = 0x0001 | (u32::from(cqid) << 16);
    sqe
}

/// Build a Delete I/O Submission Queue SQE.
pub fn build_delete_io_sq(qid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_DELETE_IO_SQ);
    sqe.cdw10 = u32::from(qid);
    sqe
}

/// Build a Delete I/O Completion Queue SQE.
pub fn build_delete_io_cq(qid: u16) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_DELETE_IO_CQ);
    sqe.cdw10 = u32::from(qid);
    sqe
}

/// Build a Get Features SQE.
///
/// `fid` — feature identifier (one of `FEAT_*` constants).
/// `prp1` — optional buffer physical address for features with data.
pub fn build_get_features(fid: u8, prp1: u64) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_GET_FEATURES);
    sqe.prp1 = prp1;
    sqe.cdw10 = u32::from(fid);
    sqe
}

/// Build a Set Features SQE.
///
/// `fid` — feature identifier.
/// `cdw11` — feature-specific value.
pub fn build_set_features(fid: u8, cdw11: u32) -> AdminSqe {
    let mut sqe = AdminSqe::default();
    sqe.cdw0 = u32::from(ADMIN_SET_FEATURES);
    sqe.cdw10 = u32::from(fid);
    sqe.cdw11 = cdw11;
    sqe
}

/// Parse identify controller bytes from a raw 4096-byte buffer.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is shorter than 256 bytes.
pub fn parse_identify_ctrl(buf: &[u8]) -> Result<IdentifyController> {
    if buf.len() < 256 {
        return Err(Error::InvalidArgument);
    }
    let mut ctrl = IdentifyController::default();
    ctrl.vid = u16::from_le_bytes([buf[0], buf[1]]);
    ctrl.ssvid = u16::from_le_bytes([buf[2], buf[3]]);
    ctrl.sn.copy_from_slice(&buf[4..24]);
    ctrl.mn.copy_from_slice(&buf[24..64]);
    ctrl.fr.copy_from_slice(&buf[64..72]);
    ctrl.mdts = buf[77];
    ctrl.nn = u32::from_le_bytes([buf[516 % buf.len()], 0, 0, 0]);
    Ok(ctrl)
}

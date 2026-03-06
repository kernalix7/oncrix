// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe admin queue operations.
//!
//! Implements the NVMe admin command set: Identify, queue creation/deletion,
//! GetFeatures, SetFeatures, firmware management, log pages, and async events.
//!
//! # Admin Queue
//!
//! The admin queue pair (admin SQ + admin CQ) is always queue ID 0.
//! All controller management commands are submitted to the admin SQ.
//! The controller processes them and posts completions to the admin CQ.
//!
//! # Identify Structures
//!
//! The Identify command returns 4096-byte data buffers describing either:
//! - Controller capabilities (`CNS=1`)
//! - Namespace attributes (`CNS=0`)
//!
//! Reference: NVM Express Base Specification 2.0, Section 5 (Admin Commands).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Admin Command Opcodes
// ---------------------------------------------------------------------------

/// Admin opcode: Delete I/O Submission Queue.
pub const ADMIN_DELETE_IO_SQ: u8 = 0x00;

/// Admin opcode: Create I/O Submission Queue.
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;

/// Admin opcode: Get Log Page.
pub const ADMIN_GET_LOG_PAGE: u8 = 0x02;

/// Admin opcode: Delete I/O Completion Queue.
pub const ADMIN_DELETE_IO_CQ: u8 = 0x04;

/// Admin opcode: Create I/O Completion Queue.
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;

/// Admin opcode: Identify.
pub const ADMIN_IDENTIFY: u8 = 0x06;

/// Admin opcode: Abort Command.
pub const ADMIN_ABORT_CMD: u8 = 0x08;

/// Admin opcode: Set Features.
pub const ADMIN_SET_FEATURES: u8 = 0x09;

/// Admin opcode: Get Features.
pub const ADMIN_GET_FEATURES: u8 = 0x0A;

/// Admin opcode: Asynchronous Event Request.
pub const ADMIN_ASYNC_EVENT_REQ: u8 = 0x0C;

/// Admin opcode: Namespace Management.
pub const ADMIN_NS_MGMT: u8 = 0x0D;

/// Admin opcode: Firmware Commit.
pub const ADMIN_FW_COMMIT: u8 = 0x10;

/// Admin opcode: Firmware Image Download.
pub const ADMIN_FW_DOWNLOAD: u8 = 0x11;

// ---------------------------------------------------------------------------
// Identify CNS (Controller or Namespace Structure) values
// ---------------------------------------------------------------------------

/// Identify CNS: Identify Namespace data structure.
pub const CNS_IDENTIFY_NAMESPACE: u8 = 0x00;

/// Identify CNS: Identify Controller data structure.
pub const CNS_IDENTIFY_CONTROLLER: u8 = 0x01;

/// Identify CNS: Active Namespace ID list.
pub const CNS_ACTIVE_NAMESPACE_LIST: u8 = 0x02;

// ---------------------------------------------------------------------------
// Feature IDs
// ---------------------------------------------------------------------------

/// Feature ID: Arbitration.
pub const FEAT_ARBITRATION: u8 = 0x01;

/// Feature ID: Power Management.
pub const FEAT_POWER_MGMT: u8 = 0x02;

/// Feature ID: LBA Range Type.
pub const FEAT_LBA_RANGE: u8 = 0x03;

/// Feature ID: Temperature Threshold.
pub const FEAT_TEMP_THRESHOLD: u8 = 0x04;

/// Feature ID: Error Recovery.
pub const FEAT_ERROR_RECOVERY: u8 = 0x05;

/// Feature ID: Volatile Write Cache.
pub const FEAT_VOLATILE_WR_CACHE: u8 = 0x06;

/// Feature ID: Number of Queues.
pub const FEAT_NUM_QUEUES: u8 = 0x07;

/// Feature ID: Interrupt Coalescing.
pub const FEAT_IRQ_COALESCING: u8 = 0x08;

/// Feature ID: Interrupt Vector Configuration.
pub const FEAT_IRQ_VECTOR_CFG: u8 = 0x09;

/// Feature ID: Write Atomicity.
pub const FEAT_WRITE_ATOMICITY: u8 = 0x0A;

/// Feature ID: Asynchronous Event Configuration.
pub const FEAT_ASYNC_EVENT_CFG: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Log Page IDs
// ---------------------------------------------------------------------------

/// Log page ID: Error Information.
pub const LOG_ERROR_INFO: u8 = 0x01;

/// Log page ID: SMART / Health Information.
pub const LOG_SMART_HEALTH: u8 = 0x02;

/// Log page ID: Firmware Slot Information.
pub const LOG_FW_SLOT: u8 = 0x03;

/// Log page ID: Changed Namespace List.
pub const LOG_CHANGED_NS_LIST: u8 = 0x04;

// ---------------------------------------------------------------------------
// Queue Parameters
// ---------------------------------------------------------------------------

/// Maximum queue depth (entries) for admin queues.
pub const ADMIN_QUEUE_DEPTH: usize = 64;

/// Submission Queue Entry size in bytes.
pub const SQ_ENTRY_SIZE: usize = 64;

/// Completion Queue Entry size in bytes.
pub const CQ_ENTRY_SIZE: usize = 16;

/// Admin SQ doorbell register offset from BAR0.
pub const ADMIN_SQ_DOORBELL: u64 = 0x1000;

/// Admin CQ doorbell register offset from BAR0.
pub const ADMIN_CQ_DOORBELL: u64 = 0x1004;

// ---------------------------------------------------------------------------
// SQE — Submission Queue Entry
// ---------------------------------------------------------------------------

/// NVMe Submission Queue Entry (64 bytes, used for all commands).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NvmeSqe {
    /// CDW0: opcode[7:0], FUSE[9:8], PSDT[15:14], CID[31:16].
    pub cdw0: u32,
    /// NSID: Namespace Identifier.
    pub nsid: u32,
    /// CDW2: reserved.
    pub cdw2: u32,
    /// CDW3: reserved.
    pub cdw3: u32,
    /// MPTR: Metadata Pointer (128-bit: low 64).
    pub mptr_lo: u64,
    /// PRP1 / SGL descriptor 1.
    pub prp1: u64,
    /// PRP2 / SGL descriptor 2.
    pub prp2: u64,
    /// CDW10: command-specific.
    pub cdw10: u32,
    /// CDW11: command-specific.
    pub cdw11: u32,
    /// CDW12: command-specific.
    pub cdw12: u32,
    /// CDW13: command-specific.
    pub cdw13: u32,
    /// CDW14: command-specific.
    pub cdw14: u32,
    /// CDW15: command-specific.
    pub cdw15: u32,
}

impl NvmeSqe {
    /// Creates a zeroed SQE.
    pub const fn zeroed() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr_lo: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Builds a CDW0 value from opcode and command ID.
    pub fn make_cdw0(opcode: u8, cid: u16) -> u32 {
        (opcode as u32) | ((cid as u32) << 16)
    }
}

// ---------------------------------------------------------------------------
// CQE — Completion Queue Entry
// ---------------------------------------------------------------------------

/// NVMe Completion Queue Entry (16 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NvmeCqe {
    /// DW0: Command-specific result.
    pub dw0: u32,
    /// DW1: Reserved.
    pub dw1: u32,
    /// DW2: SQ Head Pointer [15:0], SQ Identifier [31:16].
    pub dw2: u32,
    /// DW3: CID [31:16], Phase Tag [0], Status [15:1].
    pub dw3: u32,
}

impl NvmeCqe {
    /// Returns the command ID from this completion entry.
    pub fn cid(&self) -> u16 {
        (self.dw3 >> 16) as u16
    }

    /// Returns the status code from this completion entry.
    ///
    /// Bits [14:1] of DW3 encode the status field.
    /// Bit [0] is the phase tag.
    pub fn status(&self) -> u16 {
        ((self.dw3 >> 1) & 0x7FFF) as u16
    }

    /// Returns the status code type (bits [9:8] of status field).
    pub fn status_code_type(&self) -> u8 {
        ((self.status() >> 8) & 0x07) as u8
    }

    /// Returns the status code (bits [7:0] of status field).
    pub fn status_code(&self) -> u8 {
        (self.status() & 0xFF) as u8
    }

    /// Returns true if this completion is successful (status == 0).
    pub fn is_success(&self) -> bool {
        self.status() == 0
    }

    /// Returns the phase tag bit.
    pub fn phase(&self) -> bool {
        self.dw3 & 0x01 != 0
    }

    /// Returns the SQ head pointer from this completion.
    pub fn sq_head(&self) -> u16 {
        (self.dw2 & 0xFFFF) as u16
    }
}

// ---------------------------------------------------------------------------
// Admin Queue Pair
// ---------------------------------------------------------------------------

/// An NVMe admin queue pair (submission + completion).
pub struct AdminQueuePair {
    /// Physical address of the submission queue buffer.
    sq_phys: u64,
    /// Physical address of the completion queue buffer.
    cq_phys: u64,
    /// SQ tail (host-owned write pointer).
    sq_tail: u16,
    /// CQ head (host-owned read pointer).
    cq_head: u16,
    /// Expected completion phase tag.
    cq_phase: bool,
    /// Current command ID counter.
    next_cid: u16,
    /// MMIO base address (BAR0).
    mmio_base: u64,
    /// Pending completions ring indexed by CID.
    pending: [bool; ADMIN_QUEUE_DEPTH],
}

impl AdminQueuePair {
    /// Creates a new admin queue pair.
    ///
    /// `sq_phys` and `cq_phys` must be physically contiguous, 4-KiB aligned
    /// DMA buffers of sufficient size.
    pub fn new(sq_phys: u64, cq_phys: u64, mmio_base: u64) -> Self {
        Self {
            sq_phys,
            cq_phys,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 1,
            mmio_base,
            pending: [false; ADMIN_QUEUE_DEPTH],
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

    /// Allocates the next command ID.
    pub fn alloc_cid(&mut self) -> Result<u16> {
        // Search for a free slot.
        for i in 1..ADMIN_QUEUE_DEPTH as u16 {
            let idx = (self.next_cid.wrapping_add(i)) % ADMIN_QUEUE_DEPTH as u16;
            if !self.pending[idx as usize] {
                self.next_cid = idx;
                self.pending[idx as usize] = true;
                return Ok(idx);
            }
        }
        Err(Error::Busy)
    }

    /// Marks a command ID as completed (frees the slot).
    pub fn complete_cid(&mut self, cid: u16) {
        let idx = (cid as usize) % ADMIN_QUEUE_DEPTH;
        self.pending[idx] = false;
    }

    /// Rings the SQ doorbell to notify the controller of new entries.
    pub fn ring_sq_doorbell(&mut self) {
        // SAFETY: mmio_base is a valid NVMe BAR0 MMIO region. The doorbell
        // register at ADMIN_SQ_DOORBELL is a standard NVMe register. Volatile
        // write ensures hardware visibility.
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + ADMIN_SQ_DOORBELL) as *mut u32,
                self.sq_tail as u32,
            );
        }
    }

    /// Rings the CQ doorbell to return processed CQ entries to the controller.
    pub fn ring_cq_doorbell(&mut self) {
        // SAFETY: Same as sq doorbell — valid BAR0 NVMe MMIO region.
        unsafe {
            core::ptr::write_volatile(
                (self.mmio_base + ADMIN_CQ_DOORBELL) as *mut u32,
                self.cq_head as u32,
            );
        }
    }

    /// Returns the current SQ tail index.
    pub fn sq_tail(&self) -> u16 {
        self.sq_tail
    }

    /// Returns the current CQ head index.
    pub fn cq_head(&self) -> u16 {
        self.cq_head
    }

    /// Advances the SQ tail (after writing a new SQE to the queue buffer).
    pub fn advance_sq_tail(&mut self) {
        self.sq_tail = (self.sq_tail + 1) % ADMIN_QUEUE_DEPTH as u16;
    }

    /// Advances the CQ head and toggles phase on wrap.
    pub fn advance_cq_head(&mut self) {
        self.cq_head = (self.cq_head + 1) % ADMIN_QUEUE_DEPTH as u16;
        if self.cq_head == 0 {
            self.cq_phase = !self.cq_phase;
        }
    }

    /// Returns the expected phase tag for new completions.
    pub fn expected_phase(&self) -> bool {
        self.cq_phase
    }
}

// ---------------------------------------------------------------------------
// Admin Command Builders
// ---------------------------------------------------------------------------

/// Builds an Identify Controller SQE.
pub fn build_identify_controller(cid: u16, prp1: u64) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_IDENTIFY, cid);
    sqe.nsid = 0;
    sqe.prp1 = prp1;
    sqe.cdw10 = CNS_IDENTIFY_CONTROLLER as u32;
    sqe
}

/// Builds an Identify Namespace SQE.
pub fn build_identify_namespace(cid: u16, nsid: u32, prp1: u64) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_IDENTIFY, cid);
    sqe.nsid = nsid;
    sqe.prp1 = prp1;
    sqe.cdw10 = CNS_IDENTIFY_NAMESPACE as u32;
    sqe
}

/// Builds a Create I/O Completion Queue SQE.
pub fn build_create_io_cq(cid: u16, qid: u16, qsize: u16, cq_phys: u64, iv: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_CREATE_IO_CQ, cid);
    sqe.prp1 = cq_phys;
    // CDW10: QSIZE[31:16], QID[15:0]  (QSIZE is 0-based, i.e., entries-1).
    sqe.cdw10 = ((qsize as u32 - 1) << 16) | (qid as u32);
    // CDW11: interrupt vector[31:16], IEN[1], PC[0].
    // PC=1 (physically contiguous), IEN=1 (interrupts enabled).
    sqe.cdw11 = ((iv as u32) << 16) | 0x03;
    sqe
}

/// Builds a Create I/O Submission Queue SQE.
pub fn build_create_io_sq(cid: u16, qid: u16, qsize: u16, sq_phys: u64, cq_id: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_CREATE_IO_SQ, cid);
    sqe.prp1 = sq_phys;
    sqe.cdw10 = ((qsize as u32 - 1) << 16) | (qid as u32);
    // CDW11: CQID[31:16], QPRIO[2:1], PC[0].
    // QPRIO=00 (urgent), PC=1.
    sqe.cdw11 = ((cq_id as u32) << 16) | 0x01;
    sqe
}

/// Builds a Delete I/O Submission Queue SQE.
pub fn build_delete_io_sq(cid: u16, qid: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_DELETE_IO_SQ, cid);
    sqe.cdw10 = qid as u32;
    sqe
}

/// Builds a Delete I/O Completion Queue SQE.
pub fn build_delete_io_cq(cid: u16, qid: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_DELETE_IO_CQ, cid);
    sqe.cdw10 = qid as u32;
    sqe
}

/// Builds a Get Features SQE.
pub fn build_get_features(cid: u16, feature_id: u8) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_GET_FEATURES, cid);
    sqe.cdw10 = feature_id as u32;
    sqe
}

/// Builds a Set Features SQE.
pub fn build_set_features(cid: u16, feature_id: u8, cdw11: u32) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_SET_FEATURES, cid);
    sqe.cdw10 = feature_id as u32;
    sqe.cdw11 = cdw11;
    sqe
}

/// Builds a Get Log Page SQE.
pub fn build_get_log_page(cid: u16, log_id: u8, nsid: u32, prp1: u64, num_dwords: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_GET_LOG_PAGE, cid);
    sqe.nsid = nsid;
    sqe.prp1 = prp1;
    // CDW10: NUMD[27:16], LID[7:0]. NUMD is 0-based.
    sqe.cdw10 = (log_id as u32) | (((num_dwords as u32).saturating_sub(1)) << 16);
    sqe
}

/// Builds an Abort Command SQE.
pub fn build_abort(cid: u16, sq_id: u16, cmd_id: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_ABORT_CMD, cid);
    sqe.cdw10 = (sq_id as u32) | ((cmd_id as u32) << 16);
    sqe
}

/// Builds an Asynchronous Event Request SQE.
pub fn build_async_event_req(cid: u16) -> NvmeSqe {
    let mut sqe = NvmeSqe::zeroed();
    sqe.cdw0 = NvmeSqe::make_cdw0(ADMIN_ASYNC_EVENT_REQ, cid);
    sqe
}

// ---------------------------------------------------------------------------
// Identify Controller Data Structure
// ---------------------------------------------------------------------------

/// Size of Identify Controller data.
pub const IDENTIFY_CTRL_SIZE: usize = 4096;

/// NVMe Identify Controller data structure (4096 bytes).
///
/// Only the most-used fields are decoded; the full buffer is stored raw.
#[derive(Clone)]
pub struct IdentifyController {
    /// Raw 4096-byte identify data.
    pub raw: [u8; IDENTIFY_CTRL_SIZE],
}

impl IdentifyController {
    /// Creates a zeroed identify controller structure.
    pub fn new() -> Self {
        Self {
            raw: [0u8; IDENTIFY_CTRL_SIZE],
        }
    }

    /// Vendor ID (bytes 1:0).
    pub fn vendor_id(&self) -> u16 {
        u16::from_le_bytes([self.raw[0], self.raw[1]])
    }

    /// Subsystem Vendor ID (bytes 3:2).
    pub fn subsystem_vendor_id(&self) -> u16 {
        u16::from_le_bytes([self.raw[2], self.raw[3]])
    }

    /// Serial number (bytes 23:4), ASCII, space-padded.
    pub fn serial_number(&self) -> &[u8] {
        &self.raw[4..24]
    }

    /// Model number (bytes 63:24), ASCII, space-padded.
    pub fn model_number(&self) -> &[u8] {
        &self.raw[24..64]
    }

    /// Firmware revision (bytes 71:64), ASCII.
    pub fn firmware_revision(&self) -> &[u8] {
        &self.raw[64..72]
    }

    /// Maximum Data Transfer Size (MDTS) — value of 0 means no limit.
    pub fn mdts(&self) -> u8 {
        self.raw[77]
    }

    /// Controller ID (bytes 79:78).
    pub fn controller_id(&self) -> u16 {
        u16::from_le_bytes([self.raw[78], self.raw[79]])
    }

    /// Version (bytes 83:80): Major[31:16], Minor[15:8], Tertiary[7:0].
    pub fn version(&self) -> u32 {
        u32::from_le_bytes([self.raw[80], self.raw[81], self.raw[82], self.raw[83]])
    }

    /// Number of namespaces (NN) (bytes 519:516).
    pub fn num_namespaces(&self) -> u32 {
        u32::from_le_bytes([self.raw[516], self.raw[517], self.raw[518], self.raw[519]])
    }

    /// Maximum queue entries supported (MQES) from CAP register perspective
    /// — stored separately, not in identify data.
    pub fn max_queue_entries_supported(&self) -> u16 {
        // Not in identify data; returned via CAP register.
        // This accessor is a placeholder.
        ADMIN_QUEUE_DEPTH as u16
    }
}

// ---------------------------------------------------------------------------
// Identify Namespace Data Structure
// ---------------------------------------------------------------------------

/// Size of Identify Namespace data.
pub const IDENTIFY_NS_SIZE: usize = 4096;

/// NVMe Identify Namespace data structure.
#[derive(Clone)]
pub struct IdentifyNamespace {
    /// Raw 4096-byte identify namespace data.
    pub raw: [u8; IDENTIFY_NS_SIZE],
}

impl IdentifyNamespace {
    /// Creates a zeroed identify namespace structure.
    pub fn new() -> Self {
        Self {
            raw: [0u8; IDENTIFY_NS_SIZE],
        }
    }

    /// Namespace Size (NSZE) in logical blocks (bytes 7:0).
    pub fn nsze(&self) -> u64 {
        u64::from_le_bytes([
            self.raw[0],
            self.raw[1],
            self.raw[2],
            self.raw[3],
            self.raw[4],
            self.raw[5],
            self.raw[6],
            self.raw[7],
        ])
    }

    /// Namespace Capacity (NCAP) in logical blocks (bytes 15:8).
    pub fn ncap(&self) -> u64 {
        u64::from_le_bytes([
            self.raw[8],
            self.raw[9],
            self.raw[10],
            self.raw[11],
            self.raw[12],
            self.raw[13],
            self.raw[14],
            self.raw[15],
        ])
    }

    /// Number of LBA Format Data Structures (NLBAF), zero-based (byte 25).
    pub fn nlbaf(&self) -> u8 {
        self.raw[25]
    }

    /// Formatted LBA Size (FLBAS): bits[3:0] = current format index (byte 26).
    pub fn flbas(&self) -> u8 {
        self.raw[26]
    }

    /// Returns the current LBA data size in bytes.
    ///
    /// LBA Format data starts at byte 128. Each entry is 4 bytes.
    pub fn lba_data_size(&self) -> u32 {
        let fmt_idx = (self.flbas() & 0x0F) as usize;
        let lbaf_offset = 128 + fmt_idx * 4;
        if lbaf_offset + 3 >= IDENTIFY_NS_SIZE {
            return 512; // Default to 512 bytes.
        }
        // Bits [19:16] of the LBAF entry encode the data size as 2^n.
        let lbaf = u32::from_le_bytes([
            self.raw[lbaf_offset],
            self.raw[lbaf_offset + 1],
            self.raw[lbaf_offset + 2],
            self.raw[lbaf_offset + 3],
        ]);
        let lbads = ((lbaf >> 16) & 0xFF) as u32;
        if lbads == 0 { 512 } else { 1u32 << lbads }
    }
}

// ---------------------------------------------------------------------------
// Queue Creation Parameters
// ---------------------------------------------------------------------------

/// Parameters for creating an NVMe I/O queue pair.
#[derive(Debug, Clone, Copy)]
pub struct IoQueueParams {
    /// Queue ID (1-based).
    pub qid: u16,
    /// Queue depth (number of entries).
    pub depth: u16,
    /// Physical address of the submission queue buffer.
    pub sq_phys: u64,
    /// Physical address of the completion queue buffer.
    pub cq_phys: u64,
    /// MSI-X interrupt vector for this queue.
    pub interrupt_vector: u16,
}

impl IoQueueParams {
    /// Creates new I/O queue parameters.
    pub const fn new(
        qid: u16,
        depth: u16,
        sq_phys: u64,
        cq_phys: u64,
        interrupt_vector: u16,
    ) -> Self {
        Self {
            qid,
            depth,
            sq_phys,
            cq_phys,
            interrupt_vector,
        }
    }
}

// ---------------------------------------------------------------------------
// Admin Queue Manager
// ---------------------------------------------------------------------------

/// Maximum number of I/O queue pairs managed.
pub const MAX_IO_QUEUE_PAIRS: usize = 8;

/// NVMe admin queue manager: drives admin command submission and completion.
pub struct NvmeAdminManager {
    /// Admin queue pair.
    pub admin_queue: AdminQueuePair,
    /// Identify controller data (populated after Identify command).
    pub identify_ctrl: IdentifyController,
    /// Registered I/O queue parameters.
    io_queues: [Option<IoQueueParams>; MAX_IO_QUEUE_PAIRS],
    /// Number of registered I/O queues.
    io_queue_count: usize,
    /// Total admin commands submitted.
    commands_submitted: u64,
    /// Total admin commands completed.
    commands_completed: u64,
    /// Total admin command errors.
    command_errors: u64,
}

impl NvmeAdminManager {
    /// Creates a new admin queue manager.
    pub fn new(sq_phys: u64, cq_phys: u64, mmio_base: u64) -> Self {
        const EMPTY_IQ: Option<IoQueueParams> = None;
        Self {
            admin_queue: AdminQueuePair::new(sq_phys, cq_phys, mmio_base),
            identify_ctrl: IdentifyController::new(),
            io_queues: [EMPTY_IQ; MAX_IO_QUEUE_PAIRS],
            io_queue_count: 0,
            commands_submitted: 0,
            commands_completed: 0,
            command_errors: 0,
        }
    }

    /// Records a completed admin command, incrementing counters.
    pub fn record_completion(&mut self, cqe: &NvmeCqe) {
        self.admin_queue.complete_cid(cqe.cid());
        self.commands_completed += 1;
        if !cqe.is_success() {
            self.command_errors += 1;
        }
    }

    /// Records a submitted command, incrementing the counter.
    pub fn record_submission(&mut self) {
        self.commands_submitted += 1;
        self.admin_queue.advance_sq_tail();
    }

    /// Registers an I/O queue pair after successful creation.
    pub fn register_io_queue(&mut self, params: IoQueueParams) -> Result<()> {
        if self.io_queue_count >= MAX_IO_QUEUE_PAIRS {
            return Err(Error::OutOfMemory);
        }
        self.io_queues[self.io_queue_count] = Some(params);
        self.io_queue_count += 1;
        Ok(())
    }

    /// Returns the registered I/O queue parameters for the given queue ID.
    pub fn get_io_queue(&self, qid: u16) -> Result<&IoQueueParams> {
        for entry in self.io_queues[..self.io_queue_count].iter() {
            if let Some(q) = entry {
                if q.qid == qid {
                    return Ok(q);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered I/O queues.
    pub fn io_queue_count(&self) -> usize {
        self.io_queue_count
    }

    /// Returns command statistics: (submitted, completed, errors).
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.commands_submitted,
            self.commands_completed,
            self.command_errors,
        )
    }
}

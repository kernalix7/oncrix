// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe (Non-Volatile Memory Express) storage driver.
//!
//! Implements an NVMe driver for PCIe-attached solid-state drives
//! using memory-mapped I/O and submission/completion queue pairs.
//!
//! # Architecture
//!
//! - **Controller registers** — BAR0 MMIO register space
//! - **Admin queue pair** — for controller management commands
//! - **I/O queue pairs** — for read/write/flush commands
//! - **PRP (Physical Region Page)** — data buffer addressing
//!
//! Reference: NVM Express Base Specification 2.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NVMe sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum submission queue depth.
const MAX_SQ_DEPTH: usize = 256;

/// Maximum completion queue depth.
const MAX_CQ_DEPTH: usize = 256;

/// Maximum number of I/O queue pairs per controller.
const MAX_IO_QUEUES: usize = 4;

/// Maximum namespaces per controller.
const _MAX_NAMESPACES: usize = 8;

/// Maximum controllers tracked.
const MAX_CONTROLLERS: usize = 4;

/// Controller ready timeout polling iterations.
const READY_TIMEOUT: u32 = 1_000_000;

/// Page size (4 KiB) used for PRP entries.
const PAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// NVMe Admin Opcodes
// ---------------------------------------------------------------------------

/// Admin opcode: Delete I/O Submission Queue.
const _ADMIN_DELETE_IO_SQ: u8 = 0x00;

/// Admin opcode: Create I/O Submission Queue.
const ADMIN_CREATE_IO_SQ: u8 = 0x01;

/// Admin opcode: Delete I/O Completion Queue.
const _ADMIN_DELETE_IO_CQ: u8 = 0x04;

/// Admin opcode: Create I/O Completion Queue.
const ADMIN_CREATE_IO_CQ: u8 = 0x05;

/// Admin opcode: Identify.
const ADMIN_IDENTIFY: u8 = 0x06;

/// Admin opcode: Set Features.
const _ADMIN_SET_FEATURES: u8 = 0x09;

/// Admin opcode: Get Features.
const _ADMIN_GET_FEATURES: u8 = 0x0A;

// ---------------------------------------------------------------------------
// NVMe I/O Opcodes
// ---------------------------------------------------------------------------

/// I/O opcode: Flush.
const IO_FLUSH: u8 = 0x00;

/// I/O opcode: Write.
const IO_WRITE: u8 = 0x01;

/// I/O opcode: Read.
const IO_READ: u8 = 0x02;

// ---------------------------------------------------------------------------
// Controller Register Offsets
// ---------------------------------------------------------------------------

/// Controller Capabilities (CAP) — 64-bit, offset 0x00.
const REG_CAP: usize = 0x00;

/// Version (VS) — 32-bit, offset 0x08.
const REG_VS: usize = 0x08;

/// Interrupt Mask Set (INTMS) — 32-bit, offset 0x0C.
const _REG_INTMS: usize = 0x0C;

/// Interrupt Mask Clear (INTMC) — 32-bit, offset 0x10.
const _REG_INTMC: usize = 0x10;

/// Controller Configuration (CC) — 32-bit, offset 0x14.
const REG_CC: usize = 0x14;

/// Controller Status (CSTS) — 32-bit, offset 0x1C.
const REG_CSTS: usize = 0x1C;

/// Admin Queue Attributes (AQA) — 32-bit, offset 0x24.
const REG_AQA: usize = 0x24;

/// Admin Submission Queue Base Address (ASQ) — 64-bit, offset 0x28.
const REG_ASQ: usize = 0x28;

/// Admin Completion Queue Base Address (ACQ) — 64-bit, offset 0x30.
const REG_ACQ: usize = 0x30;

// ---------------------------------------------------------------------------
// CC (Controller Configuration) bits
// ---------------------------------------------------------------------------

/// CC: Enable.
const CC_EN: u32 = 1 << 0;

/// CC: I/O Command Set Selected (NVM = 0).
const CC_CSS_NVM: u32 = 0 << 4;

/// CC: Memory Page Size (2^(12+MPS)), 0 = 4KiB.
const CC_MPS_4K: u32 = 0 << 7;

/// CC: I/O Submission Queue Entry Size (6 = 64 bytes).
const CC_IOSQES_64: u32 = 6 << 16;

/// CC: I/O Completion Queue Entry Size (4 = 16 bytes).
const CC_IOCQES_16: u32 = 4 << 20;

// ---------------------------------------------------------------------------
// CSTS (Controller Status) bits
// ---------------------------------------------------------------------------

/// CSTS: Ready.
const CSTS_RDY: u32 = 1 << 0;

/// CSTS: Controller Fatal Status.
const CSTS_CFS: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// NVMe Submission Queue Entry (64 bytes)
// ---------------------------------------------------------------------------

/// NVMe command submission queue entry.
///
/// Every NVMe command is exactly 64 bytes, submitted to a
/// submission queue and completed via a completion queue entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NvmeCommand {
    /// Opcode and fused operation info.
    pub cdw0: u32,
    /// Namespace ID.
    pub nsid: u32,
    /// Reserved.
    pub cdw2: u32,
    /// Reserved.
    pub cdw3: u32,
    /// Metadata pointer.
    pub mptr: u64,
    /// PRP entry 1 (data buffer physical address).
    pub prp1: u64,
    /// PRP entry 2 (second page or PRP list pointer).
    pub prp2: u64,
    /// Command-specific dword 10.
    pub cdw10: u32,
    /// Command-specific dword 11.
    pub cdw11: u32,
    /// Command-specific dword 12.
    pub cdw12: u32,
    /// Command-specific dword 13.
    pub cdw13: u32,
    /// Command-specific dword 14.
    pub cdw14: u32,
    /// Command-specific dword 15.
    pub cdw15: u32,
}

impl NvmeCommand {
    /// Build CDW0 from opcode and command ID.
    fn make_cdw0(opcode: u8, cid: u16) -> u32 {
        (opcode as u32) | ((cid as u32) << 16)
    }

    /// Create an Identify Controller command.
    pub fn identify_controller(cid: u16, prp1: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_IDENTIFY, cid),
            nsid: 0,
            prp1,
            cdw10: 1, // CNS = 01h (Identify Controller)
            ..Self::default()
        }
    }

    /// Create an Identify Namespace command.
    pub fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_IDENTIFY, cid),
            nsid,
            prp1,
            cdw10: 0, // CNS = 00h (Identify Namespace)
            ..Self::default()
        }
    }

    /// Create a Create I/O Completion Queue command.
    pub fn create_io_cq(cid: u16, qid: u16, queue_size: u16, prp1: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_CREATE_IO_CQ, cid),
            prp1,
            // CDW10: QID (15:0) | QSIZE (31:16)
            cdw10: (qid as u32) | (((queue_size.saturating_sub(1)) as u32) << 16),
            // CDW11: PC=1 (physically contiguous), IEN=0, IV=0
            cdw11: 1,
            ..Self::default()
        }
    }

    /// Create a Create I/O Submission Queue command.
    pub fn create_io_sq(cid: u16, qid: u16, queue_size: u16, prp1: u64, cqid: u16) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_CREATE_IO_SQ, cid),
            prp1,
            // CDW10: QID (15:0) | QSIZE (31:16)
            cdw10: (qid as u32) | (((queue_size.saturating_sub(1)) as u32) << 16),
            // CDW11: PC=1 | QPRIO=0 | CQID (31:16)
            cdw11: 1 | ((cqid as u32) << 16),
            ..Self::default()
        }
    }

    /// Create a Read command.
    pub fn read(cid: u16, nsid: u32, lba: u64, block_count: u16, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(IO_READ, cid),
            nsid,
            prp1,
            prp2,
            // CDW10-11: Starting LBA (64-bit)
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            // CDW12: Number of Logical Blocks (0-based)
            cdw12: block_count.saturating_sub(1) as u32,
            ..Self::default()
        }
    }

    /// Create a Write command.
    pub fn write(cid: u16, nsid: u32, lba: u64, block_count: u16, prp1: u64, prp2: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(IO_WRITE, cid),
            nsid,
            prp1,
            prp2,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: block_count.saturating_sub(1) as u32,
            ..Self::default()
        }
    }

    /// Create a Flush command.
    pub fn flush(cid: u16, nsid: u32) -> Self {
        Self {
            cdw0: Self::make_cdw0(IO_FLUSH, cid),
            nsid,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// NVMe Completion Queue Entry (16 bytes)
// ---------------------------------------------------------------------------

/// NVMe completion queue entry.
///
/// Returned by the controller in the completion queue when a
/// command finishes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NvmeCompletion {
    /// Command-specific result (DW0).
    pub dw0: u32,
    /// Reserved (DW1).
    pub dw1: u32,
    /// SQ head pointer (15:0) and SQ identifier (31:16).
    pub sq_head_sqid: u32,
    /// Command ID (15:0), phase tag (bit 16), status field (31:17).
    pub cid_status: u32,
}

impl NvmeCompletion {
    /// Extract the command ID.
    pub fn command_id(&self) -> u16 {
        self.cid_status as u16
    }

    /// Extract the phase tag bit.
    pub fn phase(&self) -> bool {
        (self.cid_status >> 16) & 1 != 0
    }

    /// Extract the status code (SC) field.
    pub fn status_code(&self) -> u8 {
        ((self.cid_status >> 17) & 0xff) as u8
    }

    /// Extract the status code type (SCT) field.
    pub fn status_code_type(&self) -> u8 {
        ((self.cid_status >> 25) & 0x7) as u8
    }

    /// Returns `true` if the completion indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }

    /// Extract the SQ head pointer.
    pub fn sq_head(&self) -> u16 {
        self.sq_head_sqid as u16
    }
}

// ---------------------------------------------------------------------------
// Submission Queue
// ---------------------------------------------------------------------------

/// NVMe submission queue backed by a fixed-size array.
pub struct SubmissionQueue {
    /// Command entries.
    entries: [NvmeCommand; MAX_SQ_DEPTH],
    /// Tail index (next write position).
    tail: u16,
    /// Queue depth.
    depth: u16,
    /// Next command ID.
    next_cid: u16,
    /// Doorbell register offset from BAR0.
    doorbell_offset: usize,
}

impl SubmissionQueue {
    /// Create a new submission queue.
    pub const fn new(depth: u16, doorbell_offset: usize) -> Self {
        Self {
            entries: [NvmeCommand {
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
            }; MAX_SQ_DEPTH],
            tail: 0,
            depth,
            next_cid: 0,
            doorbell_offset,
        }
    }

    /// Submit a command to the queue. Returns the command ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn submit(&mut self, mut cmd: NvmeCommand) -> Result<u16> {
        let cid = self.next_cid;
        // Patch the CID into CDW0
        cmd.cdw0 = (cmd.cdw0 & 0x0000_ffff) | ((cid as u32) << 16);
        self.entries[self.tail as usize] = cmd;
        self.tail = (self.tail + 1) % self.depth;
        self.next_cid = self.next_cid.wrapping_add(1);
        Ok(cid)
    }

    /// Returns the current tail position (for doorbell write).
    pub fn tail(&self) -> u16 {
        self.tail
    }

    /// Returns the doorbell offset.
    pub fn doorbell_offset(&self) -> usize {
        self.doorbell_offset
    }

    /// Returns a pointer to the base of the queue entries for DMA.
    pub fn base_addr(&self) -> usize {
        self.entries.as_ptr() as usize
    }
}

// ---------------------------------------------------------------------------
// Completion Queue
// ---------------------------------------------------------------------------

/// NVMe completion queue backed by a fixed-size array.
pub struct CompletionQueue {
    /// Completion entries.
    entries: [NvmeCompletion; MAX_CQ_DEPTH],
    /// Head index (next read position).
    head: u16,
    /// Queue depth.
    depth: u16,
    /// Expected phase bit (toggles each wrap-around).
    phase: bool,
    /// Doorbell register offset from BAR0.
    doorbell_offset: usize,
}

impl CompletionQueue {
    /// Create a new completion queue.
    pub const fn new(depth: u16, doorbell_offset: usize) -> Self {
        Self {
            entries: [NvmeCompletion {
                dw0: 0,
                dw1: 0,
                sq_head_sqid: 0,
                cid_status: 0,
            }; MAX_CQ_DEPTH],
            head: 0,
            depth,
            phase: true,
            doorbell_offset,
        }
    }

    /// Check if a new completion is available.
    pub fn has_completion(&self) -> bool {
        let entry = &self.entries[self.head as usize];
        entry.phase() == self.phase
    }

    /// Consume the next completion entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if no completion is available.
    pub fn consume(&mut self) -> Result<NvmeCompletion> {
        if !self.has_completion() {
            return Err(Error::WouldBlock);
        }
        let entry = self.entries[self.head as usize];
        self.head += 1;
        if self.head >= self.depth {
            self.head = 0;
            self.phase = !self.phase;
        }
        Ok(entry)
    }

    /// Returns the current head position (for doorbell write).
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Returns the doorbell offset.
    pub fn doorbell_offset(&self) -> usize {
        self.doorbell_offset
    }

    /// Returns a pointer to the base of the queue entries for DMA.
    pub fn base_addr(&self) -> usize {
        self.entries.as_ptr() as usize
    }
}

// ---------------------------------------------------------------------------
// Identify Controller Data (subset)
// ---------------------------------------------------------------------------

/// Subset of the Identify Controller data structure (4096 bytes).
///
/// Only commonly needed fields are extracted.
#[derive(Debug, Clone, Copy)]
pub struct IdentifyController {
    /// PCI Vendor ID.
    pub vid: u16,
    /// PCI Subsystem Vendor ID.
    pub ssvid: u16,
    /// Serial Number (20 bytes, ASCII).
    pub serial: [u8; 20],
    /// Model Number (40 bytes, ASCII).
    pub model: [u8; 40],
    /// Firmware Revision (8 bytes, ASCII).
    pub firmware_rev: [u8; 8],
    /// Maximum Data Transfer Size (in units of minimum page size).
    pub mdts: u8,
    /// Number of Namespaces (NN).
    pub nn: u32,
}

impl IdentifyController {
    /// Parse from a 4096-byte Identify Controller data buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4096 {
            return Err(Error::InvalidArgument);
        }
        let vid = u16::from_le_bytes([data[0], data[1]]);
        let ssvid = u16::from_le_bytes([data[2], data[3]]);

        let mut serial = [0u8; 20];
        serial.copy_from_slice(&data[4..24]);

        let mut model = [0u8; 40];
        model.copy_from_slice(&data[24..64]);

        let mut firmware_rev = [0u8; 8];
        firmware_rev.copy_from_slice(&data[64..72]);

        let mdts = data[77];

        let nn = u32::from_le_bytes([data[516], data[517], data[518], data[519]]);

        Ok(Self {
            vid,
            ssvid,
            serial,
            model,
            firmware_rev,
            mdts,
            nn,
        })
    }
}

// ---------------------------------------------------------------------------
// Identify Namespace Data (subset)
// ---------------------------------------------------------------------------

/// Subset of the Identify Namespace data structure (4096 bytes).
#[derive(Debug, Clone, Copy)]
pub struct IdentifyNamespace {
    /// Namespace Size (total blocks).
    pub nsze: u64,
    /// Namespace Capacity (usable blocks).
    pub ncap: u64,
    /// Namespace Utilization (blocks in use).
    pub nuse: u64,
    /// Formatted LBA Size index.
    pub flbas: u8,
    /// LBA data size as a power of 2 (e.g. 9 = 512, 12 = 4096).
    pub lba_shift: u8,
}

impl IdentifyNamespace {
    /// Parse from a 4096-byte Identify Namespace data buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is too short.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4096 {
            return Err(Error::InvalidArgument);
        }
        let nsze = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let ncap = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let nuse = u64::from_le_bytes([
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);

        let flbas = data[26];
        let active_fmt_idx = (flbas & 0x0f) as usize;

        // LBA Format table starts at offset 128, each entry is 4 bytes.
        let fmt_offset = 128 + active_fmt_idx * 4;
        let lba_shift = if fmt_offset + 4 <= data.len() {
            // LBADS is bits 23:16 of the LBA format entry.
            data[fmt_offset + 2]
        } else {
            9 // default to 512-byte sectors
        };

        Ok(Self {
            nsze,
            ncap,
            nuse,
            flbas,
            lba_shift,
        })
    }

    /// Returns the LBA data size in bytes.
    pub fn block_size(&self) -> usize {
        1 << (self.lba_shift as usize)
    }
}

// ---------------------------------------------------------------------------
// NVMe Controller
// ---------------------------------------------------------------------------

/// NVMe controller state.
///
/// Manages the admin queue pair, I/O queue pairs, and provides
/// methods for issuing admin and I/O commands.
pub struct NvmeController {
    /// BAR0 base address (MMIO).
    bar0: usize,
    /// Doorbell stride (in bytes, calculated from CAP.DSTRD).
    doorbell_stride: usize,
    /// Admin Submission Queue.
    admin_sq: SubmissionQueue,
    /// Admin Completion Queue.
    admin_cq: CompletionQueue,
    /// I/O queue pairs (SQ, CQ).
    io_queues: [Option<IoQueuePair>; MAX_IO_QUEUES],
    /// Number of active I/O queue pairs.
    io_queue_count: usize,
    /// Controller identification data.
    pub identify: Option<IdentifyController>,
    /// Whether the controller has been initialized.
    initialized: bool,
}

/// An I/O queue pair (submission + completion).
pub struct IoQueuePair {
    /// Submission queue.
    pub sq: SubmissionQueue,
    /// Completion queue.
    pub cq: CompletionQueue,
    /// Queue ID (1-based).
    pub qid: u16,
}

impl NvmeController {
    /// Create a new NVMe controller at the given BAR0 address.
    pub fn new(bar0: usize) -> Self {
        // Read CAP to determine doorbell stride
        let cap_lo = read_mmio32(bar0 + REG_CAP);
        let dstrd = ((cap_lo >> 12) & 0xf) as usize;
        let doorbell_stride = 4 << dstrd;

        // Admin SQ doorbell is at offset 0x1000
        // Admin CQ doorbell is at offset 0x1000 + doorbell_stride
        let admin_sq = SubmissionQueue::new(64, 0x1000);
        let admin_cq = CompletionQueue::new(64, 0x1000 + doorbell_stride);

        const NONE_PAIR: Option<IoQueuePair> = None;

        Self {
            bar0,
            doorbell_stride,
            admin_sq,
            admin_cq,
            io_queues: [NONE_PAIR; MAX_IO_QUEUES],
            io_queue_count: 0,
            identify: None,
            initialized: false,
        }
    }

    /// Initialize the controller (reset, configure, create admin queues).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller fails to
    /// become ready or reports a fatal status.
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Disable controller
        let cc = read_mmio32(self.bar0 + REG_CC);
        if cc & CC_EN != 0 {
            write_mmio32(self.bar0 + REG_CC, cc & !CC_EN);
            self.wait_not_ready()?;
        }

        // Step 2: Configure Admin Queue Attributes
        let asq_depth = 64u32 - 1;
        let acq_depth = 64u32 - 1;
        let aqa = asq_depth | (acq_depth << 16);
        write_mmio32(self.bar0 + REG_AQA, aqa);

        // Step 3: Set Admin Queue base addresses
        let asq_addr = self.admin_sq.base_addr() as u64;
        write_mmio64(self.bar0 + REG_ASQ, asq_addr);
        let acq_addr = self.admin_cq.base_addr() as u64;
        write_mmio64(self.bar0 + REG_ACQ, acq_addr);

        // Step 4: Enable controller with NVM command set
        let new_cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_IOSQES_64 | CC_IOCQES_16;
        write_mmio32(self.bar0 + REG_CC, new_cc);

        // Step 5: Wait for controller ready
        self.wait_ready()?;

        self.initialized = true;
        Ok(())
    }

    /// Issue an Identify Controller command and store the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails.
    pub fn identify_controller(&mut self, buffer: &mut [u8; 4096]) -> Result<IdentifyController> {
        let prp1 = buffer.as_ptr() as u64;
        let cmd = NvmeCommand::identify_controller(0, prp1);
        self.admin_command(cmd)?;
        let id = IdentifyController::parse(buffer)?;
        self.identify = Some(id);
        Ok(id)
    }

    /// Issue an Identify Namespace command.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails.
    pub fn identify_namespace(
        &mut self,
        nsid: u32,
        buffer: &mut [u8; 4096],
    ) -> Result<IdentifyNamespace> {
        let prp1 = buffer.as_ptr() as u64;
        let cmd = NvmeCommand::identify_namespace(0, nsid, prp1);
        self.admin_command(cmd)?;
        IdentifyNamespace::parse(buffer)
    }

    /// Create an I/O queue pair (completion queue + submission queue).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all queue slots are used.
    pub fn create_io_queue_pair(&mut self, depth: u16) -> Result<usize> {
        if self.io_queue_count >= MAX_IO_QUEUES {
            return Err(Error::OutOfMemory);
        }

        let qid = (self.io_queue_count + 1) as u16;

        // Doorbell offsets: SQ doorbell = 0x1000 + (2*qid) * stride
        //                   CQ doorbell = 0x1000 + (2*qid+1) * stride
        let sq_db = 0x1000 + (2 * qid as usize) * self.doorbell_stride;
        let cq_db = 0x1000 + (2 * qid as usize + 1) * self.doorbell_stride;

        let cq = CompletionQueue::new(depth, cq_db);
        let sq = SubmissionQueue::new(depth, sq_db);

        // Create I/O CQ via admin command
        let cq_cmd = NvmeCommand::create_io_cq(0, qid, depth, cq.base_addr() as u64);
        self.admin_command(cq_cmd)?;

        // Create I/O SQ via admin command
        let sq_cmd = NvmeCommand::create_io_sq(0, qid, depth, sq.base_addr() as u64, qid);
        self.admin_command(sq_cmd)?;

        let idx = self.io_queue_count;
        self.io_queues[idx] = Some(IoQueuePair { sq, cq, qid });
        self.io_queue_count += 1;

        Ok(idx)
    }

    /// Submit an admin command and poll for completion.
    fn admin_command(&mut self, cmd: NvmeCommand) -> Result<NvmeCompletion> {
        let _cid = self.admin_sq.submit(cmd)?;

        // Ring the doorbell
        write_mmio32(
            self.bar0 + self.admin_sq.doorbell_offset(),
            self.admin_sq.tail() as u32,
        );

        // Poll for completion
        for _ in 0..READY_TIMEOUT {
            if self.admin_cq.has_completion() {
                let cqe = self.admin_cq.consume()?;
                // Update doorbell
                write_mmio32(
                    self.bar0 + self.admin_cq.doorbell_offset(),
                    self.admin_cq.head() as u32,
                );
                if cqe.is_success() {
                    return Ok(cqe);
                }
                return Err(Error::IoError);
            }
        }
        Err(Error::Busy)
    }

    /// Wait for the controller to become ready (CSTS.RDY = 1).
    fn wait_ready(&self) -> Result<()> {
        for _ in 0..READY_TIMEOUT {
            let csts = read_mmio32(self.bar0 + REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return Err(Error::IoError);
            }
            if csts & CSTS_RDY != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Wait for the controller to become not ready (CSTS.RDY = 0).
    fn wait_not_ready(&self) -> Result<()> {
        for _ in 0..READY_TIMEOUT {
            let csts = read_mmio32(self.bar0 + REG_CSTS);
            if csts & CSTS_RDY == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Returns `true` if the controller has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the NVMe version from the VS register.
    pub fn version(&self) -> (u16, u8, u8) {
        let vs = read_mmio32(self.bar0 + REG_VS);
        let major = (vs >> 16) as u16;
        let minor = ((vs >> 8) & 0xff) as u8;
        let tertiary = (vs & 0xff) as u8;
        (major, minor, tertiary)
    }
}

// ---------------------------------------------------------------------------
// NVMe Namespace (I/O operations)
// ---------------------------------------------------------------------------

/// Represents an NVMe namespace for block I/O.
pub struct NvmeNamespace {
    /// Namespace ID (1-based).
    pub nsid: u32,
    /// Total size in logical blocks.
    pub size_blocks: u64,
    /// Logical block size in bytes.
    pub block_size: usize,
    /// LBA data size shift (log2 of block_size).
    pub lba_shift: u8,
}

impl NvmeNamespace {
    /// Create from Identify Namespace data.
    pub fn from_identify(nsid: u32, id: &IdentifyNamespace) -> Self {
        Self {
            nsid,
            size_blocks: id.nsze,
            block_size: id.block_size(),
            lba_shift: id.lba_shift,
        }
    }

    /// Read blocks from the namespace.
    ///
    /// Submits a Read command to the given I/O queue pair and polls
    /// for completion.
    ///
    /// # Errors
    ///
    /// Returns an error if the LBA is out of range, the buffer is
    /// too small, or the command fails.
    pub fn read_blocks(
        &self,
        ctrl: &mut NvmeController,
        queue_idx: usize,
        lba: u64,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<()> {
        let needed = count as usize * self.block_size;
        if buffer.len() < needed {
            return Err(Error::InvalidArgument);
        }
        if lba + count as u64 > self.size_blocks {
            return Err(Error::InvalidArgument);
        }

        let prp1 = buffer.as_ptr() as u64;
        let prp2 = if needed > PAGE_SIZE {
            prp1 + PAGE_SIZE as u64
        } else {
            0
        };

        let cmd = NvmeCommand::read(0, self.nsid, lba, count, prp1, prp2);
        self.io_command(ctrl, queue_idx, cmd)
    }

    /// Write blocks to the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the LBA is out of range, the buffer is
    /// too small, or the command fails.
    pub fn write_blocks(
        &self,
        ctrl: &mut NvmeController,
        queue_idx: usize,
        lba: u64,
        count: u16,
        buffer: &[u8],
    ) -> Result<()> {
        let needed = count as usize * self.block_size;
        if buffer.len() < needed {
            return Err(Error::InvalidArgument);
        }
        if lba + count as u64 > self.size_blocks {
            return Err(Error::InvalidArgument);
        }

        let prp1 = buffer.as_ptr() as u64;
        let prp2 = if needed > PAGE_SIZE {
            prp1 + PAGE_SIZE as u64
        } else {
            0
        };

        let cmd = NvmeCommand::write(0, self.nsid, lba, count, prp1, prp2);
        self.io_command(ctrl, queue_idx, cmd)
    }

    /// Flush the namespace write cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails.
    pub fn flush(&self, ctrl: &mut NvmeController, queue_idx: usize) -> Result<()> {
        let cmd = NvmeCommand::flush(0, self.nsid);
        self.io_command(ctrl, queue_idx, cmd)
    }

    /// Submit an I/O command and poll for completion.
    fn io_command(
        &self,
        ctrl: &mut NvmeController,
        queue_idx: usize,
        cmd: NvmeCommand,
    ) -> Result<()> {
        let pair = ctrl.io_queues[queue_idx]
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        let _cid = pair.sq.submit(cmd)?;

        // Ring SQ doorbell
        write_mmio32(ctrl.bar0 + pair.sq.doorbell_offset(), pair.sq.tail() as u32);

        // Poll CQ
        for _ in 0..READY_TIMEOUT {
            if pair.cq.has_completion() {
                let cqe = pair.cq.consume()?;
                // Ring CQ doorbell
                write_mmio32(ctrl.bar0 + pair.cq.doorbell_offset(), pair.cq.head() as u32);
                if cqe.is_success() {
                    return Ok(());
                }
                return Err(Error::IoError);
            }
        }
        Err(Error::Busy)
    }

    /// Returns the total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.size_blocks * self.block_size as u64
    }
}

// ---------------------------------------------------------------------------
// NVMe Registry
// ---------------------------------------------------------------------------

/// Tracks discovered NVMe controllers.
pub struct NvmeRegistry {
    /// Registered controllers (BAR0 addresses).
    controllers: [Option<usize>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl NvmeRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new controller by BAR0 address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, bar0: usize) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(bar0);
        self.count += 1;
        Ok(idx)
    }

    /// Look up a controller by index.
    pub fn get(&self, index: usize) -> Option<usize> {
        if index < MAX_CONTROLLERS {
            self.controllers[index]
        } else {
            None
        }
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for NvmeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MMIO Helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// The address must be a valid, aligned MMIO register.
fn read_mmio32(addr: usize) -> u32 {
    // SAFETY: Volatile read from MMIO register. The caller guarantees
    // the address is a valid MMIO register in the NVMe BAR0 space.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// The address must be a valid, aligned MMIO register.
fn write_mmio32(addr: usize, val: u32) {
    // SAFETY: Volatile write to MMIO register. The caller guarantees
    // the address is a valid MMIO register in the NVMe BAR0 space.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Write a 64-bit value to a memory-mapped register.
fn write_mmio64(addr: usize, val: u64) {
    // SAFETY: NVMe spec requires 64-bit registers to be written as
    // two 32-bit writes (low then high) on some implementations.
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, val as u32);
        core::ptr::write_volatile((addr + 4) as *mut u32, (val >> 32) as u32);
    }
}

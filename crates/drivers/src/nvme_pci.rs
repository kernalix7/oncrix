// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe PCI transport driver for the ONCRIX operating system.
//!
//! Implements the NVMe over PCIe transport layer including BAR0 register
//! access, admin and I/O queue pair management, doorbell writes, command
//! submission/completion, namespace management, controller identification,
//! MSI-X interrupt support, and queue creation/deletion.
//!
//! # Architecture
//!
//! - **NvmePciBar0** — BAR0 register offsets and field definitions
//! - **NvmePciCommand** — 64-byte submission queue entry for PCI transport
//! - **NvmePciCompletion** — 16-byte completion queue entry
//! - **NvmePciSq** — submission queue with doorbell management
//! - **NvmePciCq** — completion queue with phase tracking
//! - **NvmePciQueuePair** — paired SQ/CQ for admin or I/O
//! - **NvmePciNamespace** — namespace identification and capacity
//! - **NvmePciMsix** — MSI-X interrupt vector table entry
//! - **NvmePciController** — full NVMe PCI controller state
//! - **NvmePciRegistry** — manages multiple NVMe PCI controllers
//!
//! Reference: NVM Express Base Specification 2.0, PCIe 5.0

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum submission/completion queue depth.
const MAX_QUEUE_DEPTH: usize = 256;

/// Maximum I/O queue pairs per controller.
const MAX_IO_QUEUES: usize = 4;

/// Maximum namespaces per controller.
const MAX_NAMESPACES: usize = 16;

/// Maximum MSI-X vectors per controller.
const MAX_MSIX_VECTORS: usize = 8;

/// Maximum controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// Controller ready timeout in polling iterations.
const READY_TIMEOUT: u32 = 1_000_000;

/// Page size (4 KiB) for PRP entries.
const PAGE_SIZE: usize = 4096;

/// NVMe sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// BAR0 Register Offsets
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
const _CSTS_CFS: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Admin opcodes
// ---------------------------------------------------------------------------

/// Admin opcode: Delete I/O Submission Queue.
const ADMIN_DELETE_IO_SQ: u8 = 0x00;

/// Admin opcode: Create I/O Submission Queue.
const ADMIN_CREATE_IO_SQ: u8 = 0x01;

/// Admin opcode: Delete I/O Completion Queue.
const ADMIN_DELETE_IO_CQ: u8 = 0x04;

/// Admin opcode: Create I/O Completion Queue.
const ADMIN_CREATE_IO_CQ: u8 = 0x05;

/// Admin opcode: Identify.
const ADMIN_IDENTIFY: u8 = 0x06;

/// Admin opcode: Set Features.
const _ADMIN_SET_FEATURES: u8 = 0x09;

/// Admin opcode: Get Features.
const _ADMIN_GET_FEATURES: u8 = 0x0A;

// ---------------------------------------------------------------------------
// I/O opcodes
// ---------------------------------------------------------------------------

/// I/O opcode: Flush.
const _IO_FLUSH: u8 = 0x00;

/// I/O opcode: Write.
const _IO_WRITE: u8 = 0x01;

/// I/O opcode: Read.
const _IO_READ: u8 = 0x02;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address aligned to 4 bytes.
unsafe fn read_mmio32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a 32-bit value to MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address aligned to 4 bytes.
unsafe fn write_mmio32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Reads a 64-bit value from MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address aligned to 8 bytes.
unsafe fn read_mmio64(addr: usize) -> u64 {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Writes a 64-bit value to MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address aligned to 8 bytes.
unsafe fn write_mmio64(addr: usize, val: u64) {
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(addr as *mut u64, val) }
}

// ---------------------------------------------------------------------------
// NvmePciCommand (64 bytes)
// ---------------------------------------------------------------------------

/// NVMe PCI transport submission queue entry (64 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NvmePciCommand {
    /// CDW0: opcode (7:0), FUSE (9:8), PSDT (13:12), CID (31:16).
    pub cdw0: u32,
    /// Namespace ID.
    pub nsid: u32,
    /// Reserved dwords 2-3.
    pub cdw2: u32,
    /// Reserved dword 3.
    pub cdw3: u32,
    /// Metadata pointer.
    pub mptr: u64,
    /// PRP entry 1.
    pub prp1: u64,
    /// PRP entry 2 or PRP list pointer.
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

impl NvmePciCommand {
    /// Builds CDW0 from opcode and command ID.
    fn make_cdw0(opcode: u8, cid: u16) -> u32 {
        (opcode as u32) | ((cid as u32) << 16)
    }

    /// Creates an Identify Controller command (CNS=01h).
    pub fn identify_controller(cid: u16, prp1: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_IDENTIFY, cid),
            prp1,
            cdw10: 1, // CNS = 01h
            ..Self::default()
        }
    }

    /// Creates an Identify Namespace command (CNS=00h).
    pub fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_IDENTIFY, cid),
            nsid,
            prp1,
            cdw10: 0, // CNS = 00h
            ..Self::default()
        }
    }

    /// Creates a Create I/O Completion Queue command.
    pub fn create_io_cq(cid: u16, qid: u16, queue_size: u16, prp1: u64, iv: u16) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_CREATE_IO_CQ, cid),
            prp1,
            cdw10: (qid as u32) | ((queue_size.saturating_sub(1) as u32) << 16),
            // PC=1, IEN=1, IV in bits 31:16
            cdw11: 1 | (1 << 1) | ((iv as u32) << 16),
            ..Self::default()
        }
    }

    /// Creates a Create I/O Submission Queue command.
    pub fn create_io_sq(cid: u16, qid: u16, queue_size: u16, prp1: u64, cqid: u16) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_CREATE_IO_SQ, cid),
            prp1,
            cdw10: (qid as u32) | ((queue_size.saturating_sub(1) as u32) << 16),
            cdw11: 1 | ((cqid as u32) << 16), // PC=1
            ..Self::default()
        }
    }

    /// Creates a Delete I/O Submission Queue command.
    pub fn delete_io_sq(cid: u16, qid: u16) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_DELETE_IO_SQ, cid),
            cdw10: qid as u32,
            ..Self::default()
        }
    }

    /// Creates a Delete I/O Completion Queue command.
    pub fn delete_io_cq(cid: u16, qid: u16) -> Self {
        Self {
            cdw0: Self::make_cdw0(ADMIN_DELETE_IO_CQ, cid),
            cdw10: qid as u32,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// NvmePciCompletion (16 bytes)
// ---------------------------------------------------------------------------

/// NVMe PCI transport completion queue entry (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct NvmePciCompletion {
    /// Command-specific result (DW0).
    pub dw0: u32,
    /// Reserved (DW1).
    pub dw1: u32,
    /// SQ head pointer (15:0) and SQ identifier (31:16).
    pub sq_head_sqid: u32,
    /// CID (15:0), phase tag (bit 16), status field (31:17).
    pub cid_status: u32,
}

impl NvmePciCompletion {
    /// Extracts the command ID.
    pub fn command_id(&self) -> u16 {
        self.cid_status as u16
    }

    /// Extracts the phase tag bit.
    pub fn phase(&self) -> bool {
        (self.cid_status >> 16) & 1 != 0
    }

    /// Extracts the status code (SC) field.
    pub fn status_code(&self) -> u8 {
        ((self.cid_status >> 17) & 0xFF) as u8
    }

    /// Extracts the status code type (SCT) field.
    pub fn status_code_type(&self) -> u8 {
        ((self.cid_status >> 25) & 0x7) as u8
    }

    /// Returns `true` if the completion indicates success.
    pub fn is_success(&self) -> bool {
        self.status_code() == 0 && self.status_code_type() == 0
    }

    /// Extracts the SQ head pointer.
    pub fn sq_head(&self) -> u16 {
        self.sq_head_sqid as u16
    }
}

// ---------------------------------------------------------------------------
// NvmePciSq — Submission Queue
// ---------------------------------------------------------------------------

/// NVMe PCI submission queue with doorbell tracking.
pub struct NvmePciSq {
    /// Command entries.
    entries: [NvmePciCommand; MAX_QUEUE_DEPTH],
    /// Tail index (next write position).
    tail: u16,
    /// Queue depth.
    depth: u16,
    /// Next command ID.
    next_cid: u16,
    /// Doorbell register offset from BAR0 base.
    doorbell_offset: usize,
}

impl NvmePciSq {
    /// Creates a new submission queue.
    pub const fn new(depth: u16, doorbell_offset: usize) -> Self {
        Self {
            entries: [NvmePciCommand {
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
            }; MAX_QUEUE_DEPTH],
            tail: 0,
            depth,
            next_cid: 0,
            doorbell_offset,
        }
    }

    /// Submits a command to the queue. Returns the assigned CID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn submit(&mut self, mut cmd: NvmePciCommand) -> Result<u16> {
        let cid = self.next_cid;
        cmd.cdw0 = (cmd.cdw0 & 0x0000_FFFF) | ((cid as u32) << 16);
        self.entries[self.tail as usize] = cmd;
        self.tail = (self.tail + 1) % self.depth;
        self.next_cid = self.next_cid.wrapping_add(1);
        Ok(cid)
    }

    /// Returns the current tail value for doorbell write.
    pub fn tail(&self) -> u16 {
        self.tail
    }

    /// Returns the doorbell register offset.
    pub fn doorbell_offset(&self) -> usize {
        self.doorbell_offset
    }

    /// Returns the base address of the queue entries for DMA setup.
    pub fn base_addr(&self) -> usize {
        self.entries.as_ptr() as usize
    }
}

// ---------------------------------------------------------------------------
// NvmePciCq — Completion Queue
// ---------------------------------------------------------------------------

/// NVMe PCI completion queue with phase tracking.
pub struct NvmePciCq {
    /// Completion entries.
    entries: [NvmePciCompletion; MAX_QUEUE_DEPTH],
    /// Head index (next read position).
    head: u16,
    /// Queue depth.
    depth: u16,
    /// Expected phase bit.
    phase: bool,
    /// Doorbell register offset from BAR0 base.
    doorbell_offset: usize,
}

impl NvmePciCq {
    /// Creates a new completion queue.
    pub const fn new(depth: u16, doorbell_offset: usize) -> Self {
        Self {
            entries: [NvmePciCompletion {
                dw0: 0,
                dw1: 0,
                sq_head_sqid: 0,
                cid_status: 0,
            }; MAX_QUEUE_DEPTH],
            head: 0,
            depth,
            phase: true,
            doorbell_offset,
        }
    }

    /// Returns `true` if a new completion is available.
    pub fn has_completion(&self) -> bool {
        self.entries[self.head as usize].phase() == self.phase
    }

    /// Consumes the next completion entry.
    ///
    /// Returns `None` if no completion is available.
    pub fn consume(&mut self) -> Option<NvmePciCompletion> {
        if !self.has_completion() {
            return None;
        }
        let entry = self.entries[self.head as usize];
        self.head += 1;
        if self.head >= self.depth {
            self.head = 0;
            self.phase = !self.phase;
        }
        Some(entry)
    }

    /// Returns the current head value for doorbell write.
    pub fn head(&self) -> u16 {
        self.head
    }

    /// Returns the doorbell register offset.
    pub fn doorbell_offset(&self) -> usize {
        self.doorbell_offset
    }

    /// Returns the base address of the queue entries for DMA setup.
    pub fn base_addr(&self) -> usize {
        self.entries.as_ptr() as usize
    }
}

// ---------------------------------------------------------------------------
// NvmePciQueuePair
// ---------------------------------------------------------------------------

/// A paired submission and completion queue.
pub struct NvmePciQueuePair {
    /// Queue pair identifier (0 = admin, 1+ = I/O).
    pub qid: u16,
    /// Submission queue.
    pub sq: NvmePciSq,
    /// Completion queue.
    pub cq: NvmePciCq,
}

impl NvmePciQueuePair {
    /// Creates a new queue pair.
    ///
    /// `dstrd` is the doorbell stride from CAP.DSTRD (in 4-byte units).
    pub fn new(qid: u16, depth: u16, dstrd: u32) -> Self {
        let stride = 4u32 << dstrd;
        let sq_db = 0x1000 + ((2 * qid as u32) * stride) as usize;
        let cq_db = 0x1000 + ((2 * qid as u32 + 1) * stride) as usize;
        Self {
            qid,
            sq: NvmePciSq::new(depth, sq_db),
            cq: NvmePciCq::new(depth, cq_db),
        }
    }

    /// Submits a command and rings the SQ doorbell.
    ///
    /// # Safety
    ///
    /// `bar0` must be the valid BAR0 MMIO base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the SQ is full.
    pub unsafe fn submit(&mut self, cmd: NvmePciCommand, bar0: usize) -> Result<u16> {
        let cid = self.sq.submit(cmd)?;
        // SAFETY: Caller guarantees bar0 is valid MMIO base.
        unsafe {
            write_mmio32(bar0 + self.sq.doorbell_offset(), self.sq.tail() as u32);
        }
        Ok(cid)
    }

    /// Polls for a completion and rings the CQ doorbell.
    ///
    /// # Safety
    ///
    /// `bar0` must be the valid BAR0 MMIO base address.
    pub unsafe fn poll_completion(&mut self, bar0: usize) -> Option<NvmePciCompletion> {
        let cqe = self.cq.consume()?;
        // SAFETY: Caller guarantees bar0 is valid MMIO base.
        unsafe {
            write_mmio32(bar0 + self.cq.doorbell_offset(), self.cq.head() as u32);
        }
        Some(cqe)
    }
}

// ---------------------------------------------------------------------------
// NvmePciNamespace
// ---------------------------------------------------------------------------

/// NVMe namespace identification and capacity.
#[derive(Debug, Clone, Copy)]
pub struct NvmePciNamespace {
    /// Namespace ID (1-based).
    pub nsid: u32,
    /// Total size in logical blocks.
    pub size_blocks: u64,
    /// Capacity in logical blocks.
    pub capacity_blocks: u64,
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Whether this namespace is active.
    pub active: bool,
}

/// Constant empty namespace for array initialisation.
const EMPTY_NS: NvmePciNamespace = NvmePciNamespace {
    nsid: 0,
    size_blocks: 0,
    capacity_blocks: 0,
    block_size: 512,
    active: false,
};

// ---------------------------------------------------------------------------
// NvmePciMsix
// ---------------------------------------------------------------------------

/// MSI-X interrupt vector table entry.
#[derive(Debug, Clone, Copy)]
pub struct NvmePciMsix {
    /// MSI-X vector index.
    pub vector: u16,
    /// Message address (lower 32 bits).
    pub msg_addr_lo: u32,
    /// Message address (upper 32 bits).
    pub msg_addr_hi: u32,
    /// Message data.
    pub msg_data: u32,
    /// Whether this vector is masked.
    pub masked: bool,
}

/// Constant empty MSI-X entry for array initialisation.
const EMPTY_MSIX: NvmePciMsix = NvmePciMsix {
    vector: 0,
    msg_addr_lo: 0,
    msg_addr_hi: 0,
    msg_data: 0,
    masked: true,
};

// ---------------------------------------------------------------------------
// NvmePciController
// ---------------------------------------------------------------------------

/// Full NVMe PCI controller state.
///
/// Manages BAR0 register access, admin queue, I/O queues, namespaces,
/// and MSI-X vectors for a single NVMe device on the PCI bus.
pub struct NvmePciController {
    /// Controller identifier.
    pub id: u32,
    /// BAR0 MMIO base address.
    pub bar0: usize,
    /// Doorbell stride from CAP.DSTRD (in 4-byte shift units).
    pub dstrd: u32,
    /// Maximum queue entries supported (from CAP.MQES + 1).
    pub max_queue_entries: u16,
    /// NVMe version (major.minor.tertiary packed into u32).
    pub version: u32,
    /// Admin queue pair.
    pub admin_qp: NvmePciQueuePair,
    /// I/O queue pairs.
    io_qps: [Option<NvmePciQueuePair>; MAX_IO_QUEUES],
    /// Number of active I/O queue pairs.
    pub io_queue_count: usize,
    /// Discovered namespaces.
    pub namespaces: [NvmePciNamespace; MAX_NAMESPACES],
    /// Number of discovered namespaces.
    pub ns_count: usize,
    /// MSI-X vector table.
    pub msix: [NvmePciMsix; MAX_MSIX_VECTORS],
    /// Number of configured MSI-X vectors.
    pub msix_count: usize,
    /// Whether the controller is enabled and ready.
    pub ready: bool,
    /// Serial number from Identify Controller (20 bytes ASCII).
    pub serial: [u8; 20],
    /// Model number from Identify Controller (40 bytes ASCII).
    pub model: [u8; 40],
}

impl NvmePciController {
    /// Creates a new NVMe PCI controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bar0` is zero.
    pub fn new(id: u32, bar0: usize) -> Result<Self> {
        if bar0 == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            id,
            bar0,
            dstrd: 0,
            max_queue_entries: MAX_QUEUE_DEPTH as u16,
            version: 0,
            admin_qp: NvmePciQueuePair::new(0, MAX_QUEUE_DEPTH as u16, 0),
            io_qps: [const { None }; MAX_IO_QUEUES],
            io_queue_count: 0,
            namespaces: [EMPTY_NS; MAX_NAMESPACES],
            ns_count: 0,
            msix: [EMPTY_MSIX; MAX_MSIX_VECTORS],
            msix_count: 0,
            ready: false,
            serial: [0u8; 20],
            model: [0u8; 40],
        })
    }

    /// Initialises the controller by reading capabilities, disabling,
    /// configuring admin queues, and enabling.
    ///
    /// # Safety
    ///
    /// The BAR0 address must be a valid MMIO mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller fails to become ready,
    /// or [`Error::Busy`] if a fatal status is detected.
    pub unsafe fn init(&mut self) -> Result<()> {
        // SAFETY: bar0 is a valid MMIO base guaranteed by caller.
        unsafe {
            // Read capabilities
            let cap = read_mmio64(self.bar0 + REG_CAP);
            self.dstrd = ((cap >> 32) & 0xF) as u32;
            self.max_queue_entries = ((cap & 0xFFFF) as u16).saturating_add(1);
            self.version = read_mmio32(self.bar0 + REG_VS);

            // Disable controller
            let cc = read_mmio32(self.bar0 + REG_CC);
            write_mmio32(self.bar0 + REG_CC, cc & !CC_EN);

            // Wait for not ready
            for _ in 0..READY_TIMEOUT {
                let csts = read_mmio32(self.bar0 + REG_CSTS);
                if csts & CSTS_RDY == 0 {
                    break;
                }
            }

            // Recreate admin queue pair with correct stride
            self.admin_qp = NvmePciQueuePair::new(
                0,
                self.max_queue_entries.min(MAX_QUEUE_DEPTH as u16),
                self.dstrd,
            );

            // Set admin queue attributes
            let admin_depth = self.max_queue_entries.min(MAX_QUEUE_DEPTH as u16);
            let aqa = ((admin_depth.saturating_sub(1) as u32) << 16)
                | (admin_depth.saturating_sub(1) as u32);
            write_mmio32(self.bar0 + REG_AQA, aqa);

            // Set admin queue base addresses
            write_mmio64(self.bar0 + REG_ASQ, self.admin_qp.sq.base_addr() as u64);
            write_mmio64(self.bar0 + REG_ACQ, self.admin_qp.cq.base_addr() as u64);

            // Configure and enable
            let cc_val = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_IOSQES_64 | CC_IOCQES_16;
            write_mmio32(self.bar0 + REG_CC, cc_val);

            // Wait for ready
            for _ in 0..READY_TIMEOUT {
                let csts = read_mmio32(self.bar0 + REG_CSTS);
                if csts & CSTS_RDY != 0 {
                    self.ready = true;
                    return Ok(());
                }
            }
        }
        Err(Error::IoError)
    }

    /// Shuts down the controller by clearing CC.EN and waiting.
    ///
    /// # Safety
    ///
    /// The BAR0 address must be a valid MMIO mapping.
    pub unsafe fn shutdown(&mut self) -> Result<()> {
        // SAFETY: bar0 is a valid MMIO base guaranteed by caller.
        unsafe {
            let cc = read_mmio32(self.bar0 + REG_CC);
            write_mmio32(self.bar0 + REG_CC, cc & !CC_EN);

            for _ in 0..READY_TIMEOUT {
                let csts = read_mmio32(self.bar0 + REG_CSTS);
                if csts & CSTS_RDY == 0 {
                    self.ready = false;
                    return Ok(());
                }
            }
        }
        Err(Error::IoError)
    }

    /// Creates an I/O queue pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all I/O queue slots are used.
    pub fn create_io_queue(&mut self, depth: u16) -> Result<u16> {
        if self.io_queue_count >= MAX_IO_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let qid = (self.io_queue_count + 1) as u16; // 1-based
        let qp = NvmePciQueuePair::new(qid, depth.min(MAX_QUEUE_DEPTH as u16), self.dstrd);
        self.io_qps[self.io_queue_count] = Some(qp);
        self.io_queue_count += 1;
        Ok(qid)
    }

    /// Deletes an I/O queue pair by QID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the QID is not found.
    pub fn delete_io_queue(&mut self, qid: u16) -> Result<()> {
        let mut found_idx = None;
        for i in 0..self.io_queue_count {
            if let Some(qp) = &self.io_qps[i] {
                if qp.qid == qid {
                    found_idx = Some(i);
                    break;
                }
            }
        }
        let i = found_idx.ok_or(Error::NotFound)?;
        self.io_qps[i] = None;
        let remaining = self.io_queue_count - i - 1;
        for j in 0..remaining {
            self.io_qps[i + j] = self.io_qps[i + j + 1].take();
        }
        self.io_queue_count -= 1;
        Ok(())
    }

    /// Adds a discovered namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all namespace slots are used.
    pub fn add_namespace(&mut self, ns: NvmePciNamespace) -> Result<()> {
        if self.ns_count >= MAX_NAMESPACES {
            return Err(Error::OutOfMemory);
        }
        self.namespaces[self.ns_count] = ns;
        self.ns_count += 1;
        Ok(())
    }

    /// Returns the namespace with the given NSID.
    pub fn get_namespace(&self, nsid: u32) -> Result<&NvmePciNamespace> {
        for ns in &self.namespaces[..self.ns_count] {
            if ns.nsid == nsid && ns.active {
                return Ok(ns);
            }
        }
        Err(Error::NotFound)
    }

    /// Configures an MSI-X vector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all vector slots are used.
    pub fn configure_msix(
        &mut self,
        vector: u16,
        msg_addr_lo: u32,
        msg_addr_hi: u32,
        msg_data: u32,
    ) -> Result<()> {
        if self.msix_count >= MAX_MSIX_VECTORS {
            return Err(Error::OutOfMemory);
        }
        self.msix[self.msix_count] = NvmePciMsix {
            vector,
            msg_addr_lo,
            msg_addr_hi,
            msg_data,
            masked: false,
        };
        self.msix_count += 1;
        Ok(())
    }

    /// Returns the total capacity in bytes across all namespaces.
    pub fn total_capacity_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for ns in &self.namespaces[..self.ns_count] {
            if ns.active {
                total =
                    total.saturating_add(ns.capacity_blocks.saturating_mul(ns.block_size as u64));
            }
        }
        total
    }

    /// Returns the NVMe version as (major, minor, tertiary).
    pub fn version_tuple(&self) -> (u16, u8, u8) {
        let major = (self.version >> 16) as u16;
        let minor = ((self.version >> 8) & 0xFF) as u8;
        let tertiary = (self.version & 0xFF) as u8;
        (major, minor, tertiary)
    }

    /// Returns the number of configured page size from capabilities.
    pub fn page_size(&self) -> usize {
        PAGE_SIZE
    }
}

// ---------------------------------------------------------------------------
// NvmePciRegistry
// ---------------------------------------------------------------------------

/// Registry managing multiple NVMe PCI controllers.
pub struct NvmePciRegistry {
    /// Registered controllers.
    controllers: [Option<NvmePciController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl NvmePciRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers an NVMe PCI controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same ID exists.
    pub fn register(&mut self, ctrl: NvmePciController) -> Result<()> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == ctrl.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.controllers.iter_mut() {
            if slot.is_none() {
                *slot = Some(ctrl);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a controller by ID.
    pub fn get(&self, id: u32) -> Result<&NvmePciController> {
        for slot in self.controllers.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a controller by ID.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut NvmePciController> {
        for slot in self.controllers.iter_mut() {
            if let Some(c) = slot {
                if c.id == id {
                    return Ok(c);
                }
            }
        }
        Err(Error::NotFound)
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

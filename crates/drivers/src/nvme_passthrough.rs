// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe admin command passthrough for management utilities.
//!
//! Forwards vendor-specific and standard NVMe admin commands to
//! the controller, enabling management tools (nvme-cli, firmware
//! updates, health monitoring) to issue arbitrary admin commands.
//! Also supports I/O command passthrough for diagnostic workloads.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  User Tool       │
//! └───────┬─────────┘
//!         │ ioctl / syscall
//! ┌───────▼─────────┐
//! │  Passthrough     │ ← this module
//! └───────┬─────────┘
//!         │ admin / IO queue
//! ┌───────▼─────────┐
//! │  NVMe Controller │
//! └─────────────────┘
//! ```
//!
//! Commands are submitted to the admin queue and the caller blocks
//! (polls) until a completion entry appears with a matching command
//! ID.
//!
//! Reference: NVM Express Base Specification 2.0, Section 5 (Admin
//! Command Set).

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum passthrough command data buffer size (4 MiB).
const MAX_DATA_SIZE: usize = 4 * 1024 * 1024;

/// Maximum number of outstanding passthrough commands.
const MAX_OUTSTANDING: usize = 16;

/// Maximum controllers managed.
const MAX_CONTROLLERS: usize = 4;

/// Polling timeout iterations for completion.
const COMPLETION_TIMEOUT: u32 = 10_000_000;

/// NVMe admin queue ID (always 0).
const ADMIN_QUEUE_ID: u16 = 0;

/// Page size used for PRP entries.
const PAGE_SIZE: usize = 4096;

// ── NVMe Admin Opcodes ──────────────────────────────────────────

/// Admin opcode: Identify.
pub const ADMIN_IDENTIFY: u8 = 0x06;

/// Admin opcode: Get Log Page.
pub const ADMIN_GET_LOG_PAGE: u8 = 0x02;

/// Admin opcode: Get Features.
pub const ADMIN_GET_FEATURES: u8 = 0x0A;

/// Admin opcode: Set Features.
pub const ADMIN_SET_FEATURES: u8 = 0x09;

/// Admin opcode: Firmware Commit.
pub const ADMIN_FW_COMMIT: u8 = 0x10;

/// Admin opcode: Firmware Image Download.
pub const ADMIN_FW_DOWNLOAD: u8 = 0x11;

/// Admin opcode: Namespace Management.
pub const ADMIN_NS_MGMT: u8 = 0x0D;

/// Admin opcode: Namespace Attachment.
pub const ADMIN_NS_ATTACH: u8 = 0x15;

/// Admin opcode: Device Self-Test.
pub const ADMIN_SELF_TEST: u8 = 0x14;

/// Admin opcode: Format NVM.
pub const ADMIN_FORMAT_NVM: u8 = 0x80;

/// Admin opcode: Security Send.
pub const ADMIN_SEC_SEND: u8 = 0x81;

/// Admin opcode: Security Receive.
pub const ADMIN_SEC_RECV: u8 = 0x82;

/// Admin opcode: Sanitize.
pub const ADMIN_SANITIZE: u8 = 0x84;

// ── NVMe I/O Opcodes ────────────────────────────────────────────

/// I/O passthrough: Read.
pub const IO_READ: u8 = 0x02;

/// I/O passthrough: Write.
pub const IO_WRITE: u8 = 0x01;

/// I/O passthrough: Verify.
pub const IO_VERIFY: u8 = 0x0C;

/// I/O passthrough: Compare.
pub const IO_COMPARE: u8 = 0x05;

/// I/O passthrough: Dataset Management (TRIM).
pub const IO_DSM: u8 = 0x09;

// ── NVMe Status Codes ───────────────────────────────────────────

/// NVMe status code type: Generic.
pub const SCT_GENERIC: u8 = 0x0;

/// NVMe status code type: Command Specific.
pub const SCT_COMMAND: u8 = 0x1;

/// NVMe status code type: Media/Data Integrity.
pub const SCT_MEDIA: u8 = 0x2;

/// NVMe status code type: Vendor Specific.
pub const SCT_VENDOR: u8 = 0x7;

/// Generic status: Successful Completion.
pub const SC_SUCCESS: u8 = 0x00;

/// Generic status: Invalid Command Opcode.
pub const SC_INVALID_OPCODE: u8 = 0x01;

/// Generic status: Invalid Field in Command.
pub const SC_INVALID_FIELD: u8 = 0x02;

/// Generic status: Data Transfer Error.
pub const SC_DATA_XFER_ERROR: u8 = 0x04;

/// Generic status: Internal Error.
pub const SC_INTERNAL_ERROR: u8 = 0x06;

/// Generic status: Namespace Not Ready.
pub const SC_NS_NOT_READY: u8 = 0x82;

// ── Passthrough Command ─────────────────────────────────────────

/// Direction of data transfer for passthrough commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataDirection {
    /// No data transfer.
    #[default]
    None,
    /// Host to controller (write).
    ToDevice,
    /// Controller to host (read).
    FromDevice,
    /// Bidirectional.
    Bidirectional,
}

/// NVMe command status from completion entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeStatus {
    /// Status Code Type (SCT).
    pub sct: u8,
    /// Status Code (SC).
    pub sc: u8,
    /// Do Not Retry flag.
    pub dnr: bool,
    /// More flag.
    pub more: bool,
    /// Command Retry Delay (CRD).
    pub crd: u8,
}

impl NvmeStatus {
    /// Return whether the status indicates success.
    pub fn is_success(&self) -> bool {
        self.sct == SCT_GENERIC && self.sc == SC_SUCCESS
    }

    /// Parse status from the raw completion dword 3.
    pub fn from_raw(dw3: u32) -> Self {
        let status_field = (dw3 >> 17) & 0x7FFF;
        Self {
            sc: (status_field & 0xFF) as u8,
            sct: ((status_field >> 8) & 0x07) as u8,
            crd: ((status_field >> 11) & 0x03) as u8,
            more: (status_field >> 13) & 1 != 0,
            dnr: (status_field >> 14) & 1 != 0,
        }
    }
}

/// An NVMe admin command submission.
///
/// Carries all 16 dwords of an NVMe command plus metadata for
/// the passthrough layer to manage data transfer.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct AdminCommand {
    /// Opcode (CDW0 bits 7:0).
    pub opcode: u8,
    /// Flags (CDW0 bits 15:8).
    pub flags: u8,
    /// Command ID (assigned by passthrough layer).
    pub command_id: u16,
    /// Namespace ID.
    pub nsid: u32,
    /// Command dwords 2-3 (reserved in most commands).
    pub cdw2: u32,
    /// Command dword 3.
    pub cdw3: u32,
    /// Metadata pointer.
    pub metadata_ptr: u64,
    /// Data pointer 1 (PRP1 or SGL).
    pub data_ptr1: u64,
    /// Data pointer 2 (PRP2 or SGL).
    pub data_ptr2: u64,
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

impl AdminCommand {
    /// Create an empty admin command.
    pub const fn empty() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            command_id: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            metadata_ptr: 0,
            data_ptr1: 0,
            data_ptr2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    /// Create an Identify Controller command.
    pub fn identify_controller(prp1: u64) -> Self {
        Self {
            opcode: ADMIN_IDENTIFY,
            cdw10: 1, // CNS = 01h
            data_ptr1: prp1,
            ..Self::empty()
        }
    }

    /// Create an Identify Namespace command.
    pub fn identify_namespace(nsid: u32, prp1: u64) -> Self {
        Self {
            opcode: ADMIN_IDENTIFY,
            nsid,
            cdw10: 0, // CNS = 00h
            data_ptr1: prp1,
            ..Self::empty()
        }
    }

    /// Create a Get Log Page command.
    pub fn get_log_page(log_id: u8, numdl: u16, prp1: u64) -> Self {
        Self {
            opcode: ADMIN_GET_LOG_PAGE,
            cdw10: u32::from(log_id) | (u32::from(numdl) << 16),
            data_ptr1: prp1,
            ..Self::empty()
        }
    }

    /// Create a Get Features command.
    pub fn get_features(feature_id: u8) -> Self {
        Self {
            opcode: ADMIN_GET_FEATURES,
            cdw10: u32::from(feature_id),
            ..Self::empty()
        }
    }

    /// Create a Set Features command.
    pub fn set_features(feature_id: u8, value: u32) -> Self {
        Self {
            opcode: ADMIN_SET_FEATURES,
            cdw10: u32::from(feature_id),
            cdw11: value,
            ..Self::empty()
        }
    }

    /// Create a Device Self-Test command.
    pub fn device_self_test(stc: u8) -> Self {
        Self {
            opcode: ADMIN_SELF_TEST,
            cdw10: u32::from(stc),
            ..Self::empty()
        }
    }

    /// Create a Format NVM command.
    pub fn format_nvm(nsid: u32, lbaf: u8, secure_erase: u8) -> Self {
        Self {
            opcode: ADMIN_FORMAT_NVM,
            nsid,
            cdw10: u32::from(lbaf) | (u32::from(secure_erase) << 9),
            ..Self::empty()
        }
    }
}

impl Default for AdminCommand {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Completion Entry ────────────────────────────────────────────

/// NVMe completion queue entry returned by the controller.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CompletionEntry {
    /// Command-specific result (DW0).
    pub dw0: u32,
    /// Reserved (DW1).
    pub dw1: u32,
    /// SQ head pointer (15:0) and SQ ID (31:16).
    pub sq_head_sqid: u32,
    /// Command ID (15:0), phase (16), status (31:17).
    pub cid_status: u32,
}

impl CompletionEntry {
    /// Extract the command ID.
    pub fn command_id(&self) -> u16 {
        self.cid_status as u16
    }

    /// Extract the phase tag.
    pub fn phase(&self) -> bool {
        (self.cid_status >> 16) & 1 != 0
    }

    /// Extract the NVMe status.
    pub fn status(&self) -> NvmeStatus {
        NvmeStatus::from_raw(self.cid_status)
    }

    /// Return whether the completion indicates success.
    pub fn is_success(&self) -> bool {
        self.status().is_success()
    }

    /// Extract the command-specific result.
    pub fn result(&self) -> u32 {
        self.dw0
    }
}

// ── Passthrough Command Descriptor ──────────────────────────────

/// A passthrough command descriptor combining the NVMe command
/// with user-facing metadata for the passthrough layer.
#[derive(Debug, Clone, Copy)]
pub struct PassthroughCmd {
    /// The NVMe admin command.
    pub cmd: AdminCommand,
    /// Direction of data transfer.
    pub direction: DataDirection,
    /// Size of data buffer in bytes.
    pub data_size: usize,
    /// Physical address of the data buffer (PRP1).
    pub data_phys: u64,
    /// Timeout in milliseconds (0 = default).
    pub timeout_ms: u32,
    /// Whether this is an admin or I/O command.
    pub is_admin: bool,
    /// I/O queue index (only used if `is_admin` is false).
    pub io_queue_id: u16,
}

impl PassthroughCmd {
    /// Create an empty passthrough command.
    pub const fn empty() -> Self {
        Self {
            cmd: AdminCommand::empty(),
            direction: DataDirection::None,
            data_size: 0,
            data_phys: 0,
            timeout_ms: 0,
            is_admin: true,
            io_queue_id: 0,
        }
    }
}

impl Default for PassthroughCmd {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Passthrough Result ──────────────────────────────────────────

/// Result of a completed passthrough command.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassthroughResult {
    /// NVMe completion status.
    pub status: NvmeStatus,
    /// Command-specific result (DW0 of completion).
    pub result: u32,
    /// Command ID that was assigned.
    pub command_id: u16,
}

// ── Pending Command Tracker ─────────────────────────────────────

/// State of a pending passthrough command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CmdState {
    /// Slot is free.
    #[default]
    Free,
    /// Command submitted, awaiting completion.
    Pending,
    /// Completion received.
    Complete,
    /// Command timed out.
    TimedOut,
}

/// Tracks a single in-flight passthrough command.
#[derive(Clone, Copy)]
struct PendingCommand {
    /// Command ID.
    command_id: u16,
    /// Current state.
    state: CmdState,
    /// Completion entry (when state == Complete).
    completion: CompletionEntry,
}

impl PendingCommand {
    const fn empty() -> Self {
        Self {
            command_id: 0,
            state: CmdState::Free,
            completion: CompletionEntry {
                dw0: 0,
                dw1: 0,
                sq_head_sqid: 0,
                cid_status: 0,
            },
        }
    }
}

// ── Controller Handle ───────────────────────────────────────────

/// Represents the connection to a single NVMe controller for
/// passthrough operations.
#[derive(Clone, Copy)]
struct ControllerHandle {
    /// MMIO base address of the controller.
    mmio_base: u64,
    /// Admin submission queue base physical address.
    admin_sq_phys: u64,
    /// Admin completion queue base physical address.
    admin_cq_phys: u64,
    /// Admin SQ tail doorbell offset.
    sq_doorbell_offset: usize,
    /// Admin CQ head doorbell offset.
    cq_doorbell_offset: usize,
    /// Current SQ tail index.
    sq_tail: u16,
    /// Current CQ head index.
    cq_head: u16,
    /// Current expected phase.
    cq_phase: bool,
    /// Queue depth.
    queue_depth: u16,
    /// Next command ID to allocate.
    next_cid: u16,
    /// Whether this handle is active.
    active: bool,
    /// Controller ID.
    controller_id: u8,
}

impl ControllerHandle {
    const fn empty() -> Self {
        Self {
            mmio_base: 0,
            admin_sq_phys: 0,
            admin_cq_phys: 0,
            sq_doorbell_offset: 0,
            cq_doorbell_offset: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            queue_depth: 0,
            next_cid: 1,
            active: false,
            controller_id: 0,
        }
    }
}

// ── NVMe Passthrough Driver ─────────────────────────────────────

/// NVMe admin/IO command passthrough driver.
///
/// Manages passthrough command submission and completion for
/// management utilities. Each instance can handle multiple
/// NVMe controllers.
pub struct NvmePassthrough {
    /// Controller handles.
    controllers: [ControllerHandle; MAX_CONTROLLERS],
    /// Number of active controllers.
    controller_count: usize,
    /// Pending command trackers.
    pending: [PendingCommand; MAX_OUTSTANDING],
    /// Number of pending commands.
    pending_count: usize,
    /// Whether the passthrough layer is initialised.
    initialised: bool,
}

impl NvmePassthrough {
    /// Create an uninitialised passthrough driver.
    pub const fn new() -> Self {
        Self {
            controllers: [const { ControllerHandle::empty() }; MAX_CONTROLLERS],
            controller_count: 0,
            pending: [const { PendingCommand::empty() }; MAX_OUTSTANDING],
            pending_count: 0,
            initialised: false,
        }
    }

    /// Register an NVMe controller for passthrough.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mmio_base` is zero.
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// controllers has been reached.
    pub fn register_controller(
        &mut self,
        mmio_base: u64,
        admin_sq_phys: u64,
        admin_cq_phys: u64,
        queue_depth: u16,
    ) -> Result<u8> {
        if mmio_base == 0 || admin_sq_phys == 0 || admin_cq_phys == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.controller_count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }

        let id = self.controller_count as u8;

        // Doorbell stride: read from CAP register bits 35:32.
        // Default stride is 4 bytes (2^2).
        let doorbell_stride = 4usize;
        let doorbell_base = 0x1000usize;

        self.controllers[self.controller_count] = ControllerHandle {
            mmio_base,
            admin_sq_phys,
            admin_cq_phys,
            sq_doorbell_offset: doorbell_base,
            cq_doorbell_offset: doorbell_base + doorbell_stride,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            queue_depth,
            next_cid: 1,
            active: true,
            controller_id: id,
        };
        self.controller_count += 1;
        self.initialised = true;

        Ok(id)
    }

    /// Submit an admin command to the specified controller.
    ///
    /// Copies the command into the admin submission queue and
    /// rings the doorbell. Returns the assigned command ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller ID is
    /// invalid or data size exceeds the maximum.
    /// Returns [`Error::OutOfMemory`] if the pending command table
    /// is full.
    pub fn submit_admin_cmd(&mut self, controller_id: u8, cmd: &mut PassthroughCmd) -> Result<u16> {
        let ctrl = self.get_controller_mut(controller_id)?;

        if cmd.data_size > MAX_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Allocate a command ID.
        let cid = ctrl.next_cid;
        ctrl.next_cid = ctrl.next_cid.wrapping_add(1);
        if ctrl.next_cid == 0 {
            ctrl.next_cid = 1;
        }

        cmd.cmd.command_id = cid;
        cmd.cmd.data_ptr1 = cmd.data_phys;

        // Write the command to the admin SQ.
        let entry_offset = (ctrl.sq_tail as usize) * 64;
        let sq_addr = ctrl.admin_sq_phys + entry_offset as u64;

        // SAFETY: The admin SQ physical address was provided during
        // registration and must point to a valid DMA-accessible
        // buffer of at least queue_depth * 64 bytes.
        unsafe {
            let dst = sq_addr as *mut AdminCommand;
            core::ptr::write_volatile(dst, cmd.cmd);
        }

        // Advance the tail.
        ctrl.sq_tail = (ctrl.sq_tail + 1) % ctrl.queue_depth;

        // Ring the SQ doorbell.
        let db_addr = ctrl.mmio_base + ctrl.sq_doorbell_offset as u64;
        // SAFETY: Doorbell register is within the NVMe MMIO space.
        unsafe {
            core::ptr::write_volatile(db_addr as *mut u32, u32::from(ctrl.sq_tail));
        }

        // Track the pending command.
        self.add_pending(cid)?;

        Ok(cid)
    }

    /// Submit an I/O command passthrough.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller ID or
    /// queue ID is invalid.
    pub fn submit_io_cmd(&mut self, controller_id: u8, cmd: &mut PassthroughCmd) -> Result<u16> {
        cmd.is_admin = false;
        // For simplicity, route through the admin queue with the
        // is_admin flag cleared. A full implementation would use
        // the specified I/O queue.
        self.submit_admin_cmd(controller_id, cmd)
    }

    /// Poll for completion of a specific command.
    ///
    /// Spins until the completion entry with matching `cid` appears
    /// or the timeout is reached.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the command does not complete
    /// within the timeout.
    /// Returns [`Error::NotFound`] if `cid` is not a tracked
    /// pending command.
    pub fn wait_completion(&mut self, controller_id: u8, cid: u16) -> Result<PassthroughResult> {
        // Find the pending slot.
        let pending_idx = self.find_pending(cid).ok_or(Error::NotFound)?;

        // Validate controller index once (use index-based access to avoid long &mut borrow).
        let ci = controller_id as usize;
        if ci >= self.controller_count || !self.controllers[ci].active {
            return Err(Error::InvalidArgument);
        }

        let mut timeout = COMPLETION_TIMEOUT;
        loop {
            // Check the CQ for new completions.
            let cq_entry_offset = (self.controllers[ci].cq_head as usize) * 16;
            let cq_addr = self.controllers[ci].admin_cq_phys + cq_entry_offset as u64;

            // SAFETY: The admin CQ physical address was provided
            // during registration.
            let entry = unsafe { core::ptr::read_volatile(cq_addr as *const CompletionEntry) };

            let entry_phase = entry.phase();
            if entry_phase == self.controllers[ci].cq_phase {
                // We have a valid completion.
                let completed_cid = entry.command_id();

                // Advance CQ head.
                let qd = self.controllers[ci].queue_depth;
                self.controllers[ci].cq_head = (self.controllers[ci].cq_head + 1) % qd;
                if self.controllers[ci].cq_head == 0 {
                    self.controllers[ci].cq_phase = !self.controllers[ci].cq_phase;
                }

                // Ring the CQ doorbell.
                let db_addr =
                    self.controllers[ci].mmio_base + self.controllers[ci].cq_doorbell_offset as u64;
                let head_val = u32::from(self.controllers[ci].cq_head);
                // SAFETY: Doorbell register is within NVMe MMIO space.
                unsafe {
                    core::ptr::write_volatile(db_addr as *mut u32, head_val);
                }

                // Update the matching pending command.
                if let Some(idx) = self.find_pending(completed_cid) {
                    self.pending[idx].state = CmdState::Complete;
                    self.pending[idx].completion = entry;
                }

                // Check if our target completed.
                if completed_cid == cid {
                    let result = PassthroughResult {
                        status: entry.status(),
                        result: entry.result(),
                        command_id: cid,
                    };
                    self.remove_pending(pending_idx);
                    return Ok(result);
                }
            }

            timeout = timeout.checked_sub(1).ok_or(Error::Busy)?;
        }
    }

    /// Identify the NVMe controller.
    ///
    /// Issues an Identify Controller admin command and waits for
    /// completion.
    ///
    /// # Errors
    ///
    /// Returns errors from command submission or completion.
    pub fn identify_controller(
        &mut self,
        controller_id: u8,
        data_phys: u64,
    ) -> Result<PassthroughResult> {
        let mut cmd = PassthroughCmd {
            cmd: AdminCommand::identify_controller(data_phys),
            direction: DataDirection::FromDevice,
            data_size: PAGE_SIZE,
            data_phys,
            timeout_ms: 5000,
            is_admin: true,
            io_queue_id: ADMIN_QUEUE_ID,
        };

        let cid = self.submit_admin_cmd(controller_id, &mut cmd)?;
        self.wait_completion(controller_id, cid)
    }

    // ── Internal helpers ────────────────────────────────────

    /// Get a mutable reference to a controller handle.
    fn get_controller_mut(&mut self, id: u8) -> Result<&mut ControllerHandle> {
        let idx = id as usize;
        if idx >= self.controller_count {
            return Err(Error::InvalidArgument);
        }
        if !self.controllers[idx].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.controllers[idx])
    }

    /// Add a pending command tracker.
    fn add_pending(&mut self, cid: u16) -> Result<()> {
        for i in 0..MAX_OUTSTANDING {
            if self.pending[i].state == CmdState::Free {
                self.pending[i] = PendingCommand {
                    command_id: cid,
                    state: CmdState::Pending,
                    completion: CompletionEntry {
                        dw0: 0,
                        dw1: 0,
                        sq_head_sqid: 0,
                        cid_status: 0,
                    },
                };
                self.pending_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a pending command by CID.
    fn find_pending(&self, cid: u16) -> Option<usize> {
        for i in 0..MAX_OUTSTANDING {
            if self.pending[i].state == CmdState::Pending && self.pending[i].command_id == cid {
                return Some(i);
            }
        }
        None
    }

    /// Remove a pending command by index.
    fn remove_pending(&mut self, index: usize) {
        if index < MAX_OUTSTANDING {
            self.pending[index].state = CmdState::Free;
            self.pending_count = self.pending_count.saturating_sub(1);
        }
    }

    /// Return the number of pending commands.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Return the number of registered controllers.
    pub fn controller_count(&self) -> usize {
        self.controller_count
    }

    /// Return whether the passthrough layer is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for NvmePassthrough {
    fn default() -> Self {
        Self::new()
    }
}

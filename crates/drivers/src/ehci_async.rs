// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EHCI Asynchronous Schedule (bulk and control transfers).
//!
//! The EHCI asynchronous schedule is a circular linked list of Queue Heads
//! (QHs). Each QH represents one endpoint (or a control pipe) and contains
//! a linked list of Queue Element Transfer Descriptors (qTDs) describing
//! the actual data to transfer.
//!
//! ```text
//! ASYNCLISTADDR ──▶ QH ──▶ QH ──▶ QH ──▶ (back to first)
//!                   │       │       │
//!                  qTD     qTD     qTD
//!                   │               │
//!                  qTD             qTD (TERMINATE)
//! ```
//!
//! Reference: EHCI Specification 1.0, §4.8 — Asynchronous Schedule.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Hardware Structure Sizes
// ---------------------------------------------------------------------------

/// Size of a Queue Head in bytes (48 bytes, 32-byte aligned).
pub const QH_SIZE: usize = 48;

/// Size of a Queue Element Transfer Descriptor (qTD) in bytes (32 bytes, 32-byte aligned).
pub const QTD_SIZE: usize = 32;

/// Maximum number of qTDs per transfer.
pub const MAX_QTDS_PER_TRANSFER: usize = 8;

/// Maximum payload per qTD (using up to 5 page pointers × 4 KiB = 20 KiB,
/// but first page may be partial, so max contiguous is about 16 KiB).
pub const QTD_MAX_PAYLOAD: u32 = 16 * 1024;

// ---------------------------------------------------------------------------
// qTD Token Bits
// ---------------------------------------------------------------------------

/// qTD Token: Ping State / Err bits 1:0.
pub const QTD_TOKEN_STATUS_ACTIVE: u32 = 1 << 7;
/// qTD Token: Halted.
pub const QTD_TOKEN_STATUS_HALTED: u32 = 1 << 6;
/// qTD Token: Data Buffer Error.
pub const QTD_TOKEN_STATUS_DBUFERR: u32 = 1 << 5;
/// qTD Token: Babble Detected.
pub const QTD_TOKEN_STATUS_BABBLE: u32 = 1 << 4;
/// qTD Token: Transaction Error.
pub const QTD_TOKEN_STATUS_XACTERR: u32 = 1 << 3;
/// qTD Token: Missed Micro-frame.
pub const QTD_TOKEN_STATUS_MISSED_MF: u32 = 1 << 2;
/// qTD Token: Split Transaction State.
pub const QTD_TOKEN_STATUS_SPLITXSTATE: u32 = 1 << 1;
/// qTD Token: Ping State.
pub const QTD_TOKEN_STATUS_PINGSTATE: u32 = 1 << 0;

/// qTD PID codes.
pub const QTD_PID_OUT: u32 = 0x00 << 8;
pub const QTD_PID_IN: u32 = 0x01 << 8;
pub const QTD_PID_SETUP: u32 = 0x02 << 8;

/// qTD Data Toggle bit (bit 31 of token).
pub const QTD_TOKEN_DATA_TOGGLE: u32 = 1 << 31;
/// qTD Interrupt On Complete bit (bit 15 of token).
pub const QTD_TOKEN_IOC: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// QH Characteristics Bits
// ---------------------------------------------------------------------------

/// QH Characteristics: RL (Nak Counter Reload).
pub const QH_CHAR_RL_SHIFT: u32 = 28;
/// QH Characteristics: Control Endpoint Flag (for Full-Speed control).
pub const QH_CHAR_CTRL_EP: u32 = 1 << 27;
/// QH Characteristics: Maximum Packet Size shift.
pub const QH_CHAR_MPS_SHIFT: u32 = 16;
/// QH Characteristics: H (Head of Reclamation List flag).
pub const QH_CHAR_H: u32 = 1 << 15;
/// QH Characteristics: DTC (Data Toggle Control).
pub const QH_CHAR_DTC: u32 = 1 << 14;
/// QH Characteristics: EPS (Endpoint Speed) shift.
pub const QH_CHAR_EPS_SHIFT: u32 = 12;
/// QH Characteristics: EP (Endpoint Number) shift.
pub const QH_CHAR_EP_SHIFT: u32 = 8;
/// QH Characteristics: DevAddr shift.
pub const QH_CHAR_DEVADDR_SHIFT: u32 = 0;

/// Endpoint speed: Full Speed.
pub const EP_SPEED_FULL: u32 = 0;
/// Endpoint speed: Low Speed.
pub const EP_SPEED_LOW: u32 = 1;
/// Endpoint speed: High Speed.
pub const EP_SPEED_HIGH: u32 = 2;

// ---------------------------------------------------------------------------
// Queue Element Transfer Descriptor (qTD)
// ---------------------------------------------------------------------------

/// EHCI Queue Element Transfer Descriptor.
///
/// `#[repr(C, align(32))]` is required by the EHCI specification.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Qtd {
    /// Next qTD physical pointer (bit 0: terminate if 1).
    pub next_qtd: u32,
    /// Alternate Next qTD (for short packet handling).
    pub alt_next_qtd: u32,
    /// Token: status, PID, toggle, length, IOC.
    pub token: u32,
    /// Buffer page pointers (0–4) — 4 KiB aligned physical addresses.
    pub buf_ptr: [u32; 5],
}

/// Physical address termination bit for Next qTD pointer.
pub const QTD_TERMINATE: u32 = 1;

impl Qtd {
    /// Creates a terminated (null) qTD.
    pub const fn terminated() -> Self {
        Self {
            next_qtd: QTD_TERMINATE,
            alt_next_qtd: QTD_TERMINATE,
            token: 0,
            buf_ptr: [0u32; 5],
        }
    }

    /// Returns `true` if the Active bit is set (transfer in progress).
    pub const fn is_active(&self) -> bool {
        self.token & QTD_TOKEN_STATUS_ACTIVE != 0
    }

    /// Returns `true` if the Halted bit is set (transfer error).
    pub const fn is_halted(&self) -> bool {
        self.token & QTD_TOKEN_STATUS_HALTED != 0
    }

    /// Returns the Total Bytes to Transfer (bits 30:16 of token).
    pub const fn total_bytes(&self) -> u16 {
        ((self.token >> 16) & 0x7FFF) as u16
    }

    /// Builds a qTD for a data transfer.
    ///
    /// # Parameters
    /// - `buf_phys`: Physical address of the data buffer (need not be page-aligned).
    /// - `length`: Number of bytes to transfer (max `QTD_MAX_PAYLOAD`).
    /// - `pid`: Transfer direction (`QTD_PID_IN` or `QTD_PID_OUT`).
    /// - `toggle`: Data toggle bit (0 or 1).
    /// - `ioc`: Set Interrupt On Complete.
    pub fn data(buf_phys: u64, length: u32, pid: u32, toggle: bool, ioc: bool) -> Self {
        let mut qtd = Self::terminated();
        let toggle_bit: u32 = if toggle { QTD_TOKEN_DATA_TOGGLE } else { 0 };
        let ioc_bit: u32 = if ioc { QTD_TOKEN_IOC } else { 0 };
        qtd.token =
            QTD_TOKEN_STATUS_ACTIVE | pid | toggle_bit | ioc_bit | ((length as u32 & 0x7FFF) << 16);
        // Set up buffer page pointers (simplified: assume contiguous physical memory).
        qtd.buf_ptr[0] = (buf_phys & 0xFFFF_FFFF) as u32;
        for i in 1..5usize {
            let page_phys = buf_phys + (i as u64 * 4096);
            qtd.buf_ptr[i] = (page_phys & 0xFFFF_F000) as u32;
        }
        qtd
    }
}

// ---------------------------------------------------------------------------
// Queue Head (QH)
// ---------------------------------------------------------------------------

/// EHCI Queue Head.
///
/// `#[repr(C, align(32))]` as required by EHCI spec.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Qh {
    /// Horizontal link pointer: physical address of next QH (bits 4:3 = type 10 = QH).
    pub horizontal_link: u32,
    /// Endpoint Characteristics.
    pub ep_char: u32,
    /// Endpoint Capabilities.
    pub ep_cap: u32,
    /// Current qTD pointer (set by hardware).
    pub current_qtd: u32,
    /// Next qTD pointer (written by software).
    pub next_qtd: u32,
    /// Alternate Next qTD pointer.
    pub alt_qtd: u32,
    /// Overlay token (hardware updates on each transfer).
    pub overlay_token: u32,
    /// Overlay buffer pointers.
    pub overlay_buf: [u32; 5],
}

/// Queue Head type in horizontal link pointer (bits 2:1 = 0b10).
pub const QH_LINK_TYPE_QH: u32 = 0b10 << 1;
/// Terminate bit for link pointers.
pub const QH_LINK_TERMINATE: u32 = 1;

impl Qh {
    /// Creates a new QH for a High-Speed endpoint.
    ///
    /// # Parameters
    /// - `dev_addr`: USB device address (0–127).
    /// - `ep_num`: Endpoint number (0–15).
    /// - `max_packet_size`: Maximum packet size for this endpoint.
    /// - `speed`: Endpoint speed (`EP_SPEED_*`).
    /// - `is_control`: `true` for control endpoints (sets DTC bit).
    /// - `is_head`: `true` if this is the H (head of reclamation list) QH.
    pub fn new_high_speed(
        dev_addr: u8,
        ep_num: u8,
        max_packet_size: u16,
        speed: u32,
        is_control: bool,
        is_head: bool,
    ) -> Self {
        let dtc: u32 = if is_control { QH_CHAR_DTC } else { 0 };
        let head: u32 = if is_head { QH_CHAR_H } else { 0 };
        let ctrl_ep: u32 = if is_control && speed != EP_SPEED_HIGH {
            QH_CHAR_CTRL_EP
        } else {
            0
        };
        let ep_char = ((4u32) << QH_CHAR_RL_SHIFT)
            | ctrl_ep
            | ((max_packet_size as u32) << QH_CHAR_MPS_SHIFT)
            | head
            | dtc
            | (speed << QH_CHAR_EPS_SHIFT)
            | ((ep_num as u32) << QH_CHAR_EP_SHIFT)
            | ((dev_addr as u32) << QH_CHAR_DEVADDR_SHIFT);
        Self {
            horizontal_link: QH_LINK_TERMINATE,
            ep_char,
            ep_cap: 0,
            current_qtd: 0,
            next_qtd: QTD_TERMINATE,
            alt_qtd: QTD_TERMINATE,
            overlay_token: 0,
            overlay_buf: [0u32; 5],
        }
    }

    /// Links this QH to `next_qh_phys` in the async schedule (circular).
    pub fn set_next_qh(&mut self, next_qh_phys: u32) {
        self.horizontal_link = (next_qh_phys & !0x1F) | QH_LINK_TYPE_QH;
    }

    /// Points the overlay to the first qTD.
    pub fn set_next_qtd(&mut self, qtd_phys: u32) {
        self.next_qtd = qtd_phys & !0x1F;
        self.overlay_token = 0; // Clear overlay to let hardware load from qTD.
    }

    /// Returns `true` if the overlay shows the endpoint is halted.
    pub const fn is_halted(&self) -> bool {
        self.overlay_token & QTD_TOKEN_STATUS_HALTED != 0
    }
}

// ---------------------------------------------------------------------------
// EHCI Async Schedule Manager
// ---------------------------------------------------------------------------

/// Maximum number of simultaneous bulk/control transfers.
pub const MAX_ASYNC_TRANSFERS: usize = 16;

/// Manages a set of QHs in the EHCI async schedule.
pub struct AsyncSchedule {
    /// Physical address of the async list head (written to ASYNCLISTADDR).
    head_phys: u64,
    /// Virtual address of the async list head.
    head_virt: u64,
    /// Active transfer count.
    active: usize,
}

impl AsyncSchedule {
    /// Creates a new async schedule with a dummy head QH.
    ///
    /// The head QH is the H=1 sentinel that loops back to itself.
    ///
    /// # Parameters
    /// - `head_phys`: Physical address of a pre-allocated QH for the dummy head.
    /// - `head_virt`: Virtual address of the same QH.
    ///
    /// # Safety
    /// `head_phys`/`head_virt` must point to a valid DMA-accessible QH allocation.
    pub unsafe fn new(head_phys: u64, head_virt: u64) -> Self {
        let mut head_qh = Qh::new_high_speed(0, 0, 64, EP_SPEED_HIGH, false, true);
        // Head QH links to itself (circular).
        head_qh.set_next_qh(head_phys as u32);
        // SAFETY: head_virt is a valid DMA allocation.
        unsafe {
            core::ptr::write_volatile(head_virt as *mut Qh, head_qh);
        }
        Self {
            head_phys,
            head_virt,
            active: 0,
        }
    }

    /// Returns the physical address of the head QH (for ASYNCLISTADDR register).
    pub fn head_phys(&self) -> u64 {
        self.head_phys
    }

    /// Submits a bulk OUT transfer.
    ///
    /// # Parameters
    /// - `qh_phys`/`qh_virt`: Physical/virtual address of the endpoint's QH.
    /// - `qtd_phys`/`qtd_virt`: Physical/virtual address of the first qTD.
    /// - `buf_phys`: Physical buffer address.
    /// - `length`: Transfer length.
    ///
    /// # Errors
    /// Returns `Error::Busy` if too many transfers are active.
    ///
    /// # Safety
    /// All provided addresses must be valid DMA-accessible memory.
    pub unsafe fn submit_bulk_out(
        &mut self,
        qh_phys: u64,
        qh_virt: u64,
        qtd_phys: u64,
        qtd_virt: u64,
        buf_phys: u64,
        length: u32,
    ) -> Result<()> {
        if self.active >= MAX_ASYNC_TRANSFERS {
            return Err(Error::Busy);
        }
        // Build the qTD.
        let qtd = Qtd::data(buf_phys, length, QTD_PID_OUT, false, true);
        // SAFETY: qtd_virt is a valid DMA-accessible qTD slot.
        unsafe {
            core::ptr::write_volatile(qtd_virt as *mut Qtd, qtd);
        }
        // Point the QH at our qTD.
        // SAFETY: qh_virt is a valid DMA-accessible QH slot.
        unsafe {
            let qh = &mut *(qh_virt as *mut Qh);
            qh.set_next_qh(self.head_phys as u32);
            qh.set_next_qtd(qtd_phys as u32);
            // Insert this QH into the circular list after the head.
            let head = &mut *(self.head_virt as *mut Qh);
            qh.horizontal_link = head.horizontal_link;
            head.set_next_qh(qh_phys as u32);
        }
        self.active += 1;
        Ok(())
    }

    /// Polls a QH's overlay to check if the transfer has completed.
    ///
    /// # Safety
    /// `qh_virt` must be a valid, hardware-visible QH.
    pub unsafe fn poll_qh(&mut self, qh_virt: u64) -> Option<bool> {
        // SAFETY: Hardware may update this field; volatile read required.
        let qh = unsafe { core::ptr::read_volatile(qh_virt as *const Qh) };
        let active = qh.overlay_token & QTD_TOKEN_STATUS_ACTIVE != 0;
        let halted = qh.overlay_token & QTD_TOKEN_STATUS_HALTED != 0;
        if !active {
            if self.active > 0 {
                self.active -= 1;
            }
            Some(!halted) // true = success, false = error
        } else {
            None
        }
    }

    /// Returns the number of currently active transfers.
    pub fn active_count(&self) -> usize {
        self.active
    }
}

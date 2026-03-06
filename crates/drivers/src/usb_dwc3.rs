// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DesignWare USB3 (DWC3) controller driver.
//!
//! Implements the Synopsys DesignWare USB 3.0/3.1 Dual-Role Device
//! controller found in many ARM SoCs (Qualcomm, Rockchip, TI, etc.).
//! The driver operates the controller in Host mode and manages
//! endpoint queues via the Event Buffer and Transfer Request Blocks
//! (TRBs).
//!
//! # Hardware Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │          DWC3 Global Registers           │  0x000–0x7FF
//! │  GCTL / GUID / GBUSERRADDR / GPRTBIMAP  │
//! ├─────────────────────────────────────────┤
//! │           DWC3 Device Registers          │  0xC000–0xCFFF
//! │  DCFG / DCTL / DEVTEN / DSTS            │
//! ├─────────────────────────────────────────┤
//! │      Per-endpoint Registers             │  0xC000+N*32
//! │  DEPCFG / DEPXFERCFG / DEPEVTEN        │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Transfer Request Block (TRB)
//!
//! Each TRB describes one buffer segment for a USB transfer.
//! TRBs are chained together in a ring buffer, with the last
//! TRB pointing back to the first (link TRB).
//!
//! # Usage
//!
//! ```ignore
//! let mut dwc3 = Dwc3Controller::new(mmio_base, event_buf_phys, trb_pool_phys);
//! dwc3.init()?;
//! dwc3.start_host_mode()?;
//! ```

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── DWC3 Global Register Offsets ─────────────────────────────

/// GUID register: silicon version.
const DWC3_GSNPSID: u32 = 0x0C120;
/// Global Control register.
const DWC3_GCTL: u32 = 0xC110;
/// Global USB2 PHY configuration register.
const DWC3_GUSB2PHYCFG: u32 = 0xC200;
/// Global USB3 pipe control register.
const DWC3_GUSB3PIPECTL: u32 = 0xC2C0;
/// Global TX FIFO size register (0).
const DWC3_GTXFIFOSIZ0: u32 = 0xC300;
/// Global RX FIFO size register (0).
const DWC3_GRXFIFOSIZ0: u32 = 0xC380;
/// Global Event Buffer size register.
const DWC3_GEVNTSIZ: u32 = 0xC400;
/// Global Event Buffer address (low 32 bits).
const DWC3_GEVNTADRLO: u32 = 0xC408;
/// Global Event Buffer address (high 32 bits).
const DWC3_GEVNTADRHI: u32 = 0xC40C;
/// Global Event Buffer count register.
const DWC3_GEVNTCOUNT: u32 = 0xC404;

// ── DWC3 Device Register Offsets ─────────────────────────────

/// Device configuration register.
const DWC3_DCFG: u32 = 0xC700;
/// Device control register.
const DWC3_DCTL: u32 = 0xC704;
/// Device event enable register.
const DWC3_DEVTEN: u32 = 0xC708;
/// Device status register.
const DWC3_DSTS: u32 = 0xC70C;
/// Device endpoint command register (physical EP 0 out).
const DWC3_DEPCMD0: u32 = 0xC80C;

// ── GCTL Bit Fields ───────────────────────────────────────────

/// Core soft reset bit in GCTL.
const DWC3_GCTL_CORESOFTRESET: u32 = 1 << 11;
/// Port capability direction: host.
const DWC3_GCTL_PRTCAP_HOST: u32 = 1 << 12;
/// Port capability direction mask.
const DWC3_GCTL_PRTCAPDIR_MASK: u32 = 3 << 12;
/// Scale-down mask (bits 19:18).
const DWC3_GCTL_SCALEDOWN_MASK: u32 = 3 << 18;
/// Disable scrambling bit.
const DWC3_GCTL_DISSCRAMBLE: u32 = 1 << 3;

// ── DCTL Bit Fields ───────────────────────────────────────────

/// Run/Stop bit in DCTL (1 = run, 0 = stop).
const DWC3_DCTL_RUN_STOP: u32 = 1 << 31;
/// Core soft reset.
const DWC3_DCTL_CSFTRST: u32 = 1 << 30;

// ── DSTS Bit Fields ───────────────────────────────────────────

/// Device connect status bit in DSTS.
const DWC3_DSTS_CONNECTSPD_MASK: u32 = 0x7;
/// SuperSpeed (USB 3.x) connection speed.
const DWC3_DSTS_SUPERSPEED: u32 = 4;
/// High-speed (USB 2.0) connection speed.
const DWC3_DSTS_HIGHSPEED: u32 = 0;

// ── DCFG Fields ───────────────────────────────────────────────

/// Device number address mask.
const DWC3_DCFG_DEVADDR_MASK: u32 = 0x7F << 3;

// ── Event Buffer ─────────────────────────────────────────────

/// Size of the event buffer in bytes (must be a multiple of 4).
const EVENT_BUF_SIZE: u32 = 4096;

// ── TRB Constants ─────────────────────────────────────────────

/// Number of TRBs per endpoint ring (including link TRB).
const TRB_RING_SIZE: usize = 32;
/// Maximum endpoints supported by this driver.
const MAX_ENDPOINTS: usize = 8;

// ── MMIO Helpers ──────────────────────────────────────────────

/// Read a 32-bit DWC3 register.
///
/// # Safety
///
/// `base + offset` must be a valid DWC3 register address.
#[inline]
unsafe fn read_mmio32(base: u64, offset: u32) -> u32 {
    // SAFETY: caller guarantees the address is a valid DWC3 register.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

/// Write a 32-bit DWC3 register.
///
/// # Safety
///
/// `base + offset` must be a valid DWC3 register address.
#[inline]
unsafe fn write_mmio32(base: u64, offset: u32, val: u32) {
    // SAFETY: caller guarantees the address is a valid DWC3 register.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val) }
}

// ── Transfer Request Block ────────────────────────────────────

/// A DWC3 Transfer Request Block (TRB).
///
/// TRBs are placed in a ring buffer and describe individual USB
/// data or control buffers. The hardware DMA engine reads them
/// in order and sets the `HWO` flag when it owns the TRB.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Trb {
    /// Physical address of the data buffer (low 32 bits).
    pub buf_ptr_lo: u32,
    /// Physical address of the data buffer (high 32 bits).
    pub buf_ptr_hi: u32,
    /// Buffer size and TRB status.
    pub size: u32,
    /// Control flags (type, HWO, LST, CHN, etc.).
    pub ctrl: u32,
}

/// TRB control flag: hardware owns this TRB (must be 0 before software
/// sets it so the device can begin the transfer).
pub const TRB_CTRL_HWO: u32 = 1 << 0;
/// TRB control flag: last TRB in the transfer descriptor.
pub const TRB_CTRL_LST: u32 = 1 << 1;
/// TRB control flag: chain to next TRB.
pub const TRB_CTRL_CHN: u32 = 1 << 4;
/// TRB type: normal data.
pub const TRB_TYPE_NORMAL: u32 = 1 << 10;
/// TRB type: link (ring wrap-around).
pub const TRB_TYPE_LINK: u32 = 6 << 10;

impl Trb {
    /// Create a link TRB pointing to `next_phys`.
    pub const fn link(next_phys: u64) -> Self {
        Self {
            buf_ptr_lo: (next_phys & 0xFFFF_FFFF) as u32,
            buf_ptr_hi: ((next_phys >> 32) & 0xFFFF_FFFF) as u32,
            size: 0,
            ctrl: TRB_TYPE_LINK | TRB_CTRL_HWO,
        }
    }

    /// Create a normal data TRB for the given buffer.
    pub const fn normal(phys: u64, len: u32, last: bool) -> Self {
        let ctrl = TRB_TYPE_NORMAL | TRB_CTRL_HWO | if last { TRB_CTRL_LST } else { TRB_CTRL_CHN };
        Self {
            buf_ptr_lo: (phys & 0xFFFF_FFFF) as u32,
            buf_ptr_hi: ((phys >> 32) & 0xFFFF_FFFF) as u32,
            size: len,
            ctrl,
        }
    }

    /// Return whether the hardware still owns this TRB.
    pub const fn is_hwo(&self) -> bool {
        self.ctrl & TRB_CTRL_HWO != 0
    }
}

// ── Endpoint State ────────────────────────────────────────────

/// Transfer direction for an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EpDirection {
    #[default]
    Out,
    In,
}

/// State of a single DWC3 endpoint.
#[derive(Debug)]
pub struct Endpoint {
    /// Endpoint number (0–max).
    pub ep_num: u8,
    /// Transfer direction.
    pub direction: EpDirection,
    /// Physical base address of this endpoint's TRB ring.
    pub trb_ring_phys: u64,
    /// Enqueue pointer within the ring.
    pub enq: usize,
    /// Dequeue pointer within the ring.
    pub deq: usize,
    /// Whether the endpoint is active.
    pub active: bool,
    /// Transfer bytes completed on this endpoint.
    pub bytes_transferred: u64,
}

impl Endpoint {
    /// Create an inactive endpoint.
    pub const fn new(ep_num: u8, direction: EpDirection) -> Self {
        Self {
            ep_num,
            direction,
            trb_ring_phys: 0,
            enq: 0,
            deq: 0,
            active: false,
            bytes_transferred: 0,
        }
    }
}

// ── DWC3 Controller Stats ─────────────────────────────────────

/// Accumulated DWC3 controller statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dwc3Stats {
    /// Total events processed from the event buffer.
    pub events_processed: u64,
    /// Total USB resets detected.
    pub usb_resets: u64,
    /// Total connection/disconnection events.
    pub connect_events: u64,
    /// Total transfer completions.
    pub transfer_completions: u64,
}

// ── DWC3 Controller ───────────────────────────────────────────

/// Driver for a Synopsys DesignWare USB3 (DWC3) controller.
///
/// Manages global and device-mode registers, the event buffer,
/// and up to [`MAX_ENDPOINTS`] endpoint rings.
pub struct Dwc3Controller {
    /// Physical base address of the DWC3 MMIO register space.
    mmio_base: u64,
    /// Physical base address of the event buffer.
    event_buf_phys: u64,
    /// Physical base address of the TRB pool.
    trb_pool_phys: u64,
    /// Parsed silicon revision from GSNPSID.
    revision: u32,
    /// Whether the controller is running in host mode.
    host_mode: bool,
    /// Whether the controller has been fully initialized.
    initialized: bool,
    /// Endpoint state array.
    endpoints: [Endpoint; MAX_ENDPOINTS],
    /// Current event buffer read pointer (byte offset into event_buf).
    event_read_ptr: u32,
    /// Accumulated statistics.
    stats: Dwc3Stats,
}

impl Dwc3Controller {
    /// Create a new DWC3 controller driver instance.
    ///
    /// # Arguments
    ///
    /// * `mmio_base` — Physical base address of the DWC3 register block.
    /// * `event_buf_phys` — Physical address of the pre-allocated event
    ///   buffer (must be at least [`EVENT_BUF_SIZE`] bytes).
    /// * `trb_pool_phys` — Physical address of the pre-allocated TRB
    ///   pool.
    pub fn new(mmio_base: u64, event_buf_phys: u64, trb_pool_phys: u64) -> Self {
        Self {
            mmio_base,
            event_buf_phys,
            trb_pool_phys,
            revision: 0,
            host_mode: false,
            initialized: false,
            endpoints: [
                Endpoint::new(0, EpDirection::Out),
                Endpoint::new(1, EpDirection::In),
                Endpoint::new(2, EpDirection::Out),
                Endpoint::new(3, EpDirection::In),
                Endpoint::new(4, EpDirection::Out),
                Endpoint::new(5, EpDirection::In),
                Endpoint::new(6, EpDirection::Out),
                Endpoint::new(7, EpDirection::In),
            ],
            event_read_ptr: 0,
            stats: Dwc3Stats::default(),
        }
    }

    /// Initialize the DWC3 controller.
    ///
    /// Performs a soft reset, reads the silicon revision, configures
    /// the event buffer, and sets up the PHY.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `mmio_base` is zero.
    /// - [`Error::IoError`] if the soft reset times out.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Read silicon revision.
        // SAFETY: mmio_base is a valid DWC3 MMIO region.
        self.revision = unsafe { read_mmio32(self.mmio_base, DWC3_GSNPSID) };

        // Perform GCTL soft reset.
        // SAFETY: GCTL is a valid DWC3 global register.
        let gctl = unsafe { read_mmio32(self.mmio_base, DWC3_GCTL) };
        // SAFETY: same.
        unsafe { write_mmio32(self.mmio_base, DWC3_GCTL, gctl | DWC3_GCTL_CORESOFTRESET) };

        // Poll until soft reset clears.
        let mut retries = 1_000u32;
        loop {
            // SAFETY: GCTL is a valid register.
            let v = unsafe { read_mmio32(self.mmio_base, DWC3_GCTL) };
            if v & DWC3_GCTL_CORESOFTRESET == 0 {
                break;
            }
            retries = retries.saturating_sub(1);
            if retries == 0 {
                return Err(Error::IoError);
            }
        }

        // Configure GUSB2PHYCFG: disable suspend and set UTMI clock.
        // SAFETY: GUSB2PHYCFG is a valid DWC3 register.
        let phycfg = unsafe { read_mmio32(self.mmio_base, DWC3_GUSB2PHYCFG) };
        // SAFETY: same.
        unsafe { write_mmio32(self.mmio_base, DWC3_GUSB2PHYCFG, phycfg & !(1 << 6)) };

        // Configure USB3 pipe control.
        // SAFETY: GUSB3PIPECTL is a valid DWC3 register.
        let pipectl = unsafe { read_mmio32(self.mmio_base, DWC3_GUSB3PIPECTL) };
        // SAFETY: same.
        unsafe { write_mmio32(self.mmio_base, DWC3_GUSB3PIPECTL, pipectl & !(1 << 17)) };

        // Set up the event buffer.
        let evt_lo = (self.event_buf_phys & 0xFFFF_FFFF) as u32;
        let evt_hi = ((self.event_buf_phys >> 32) & 0xFFFF_FFFF) as u32;
        // SAFETY: GEVNTADRLO/HI and GEVNTSIZ are valid DWC3 registers.
        unsafe {
            write_mmio32(self.mmio_base, DWC3_GEVNTADRLO, evt_lo);
            write_mmio32(self.mmio_base, DWC3_GEVNTADRHI, evt_hi);
            write_mmio32(self.mmio_base, DWC3_GEVNTSIZ, EVENT_BUF_SIZE);
            // Clear the event count to acknowledge any stale events.
            write_mmio32(self.mmio_base, DWC3_GEVNTCOUNT, 0);
        }

        // Configure GCTL: clear scale-down and scramble-disable, set host.
        let mut new_gctl = unsafe { read_mmio32(self.mmio_base, DWC3_GCTL) };
        new_gctl &= !(DWC3_GCTL_SCALEDOWN_MASK | DWC3_GCTL_DISSCRAMBLE);
        new_gctl &= !DWC3_GCTL_PRTCAPDIR_MASK;
        new_gctl |= DWC3_GCTL_PRTCAP_HOST;
        // SAFETY: GCTL is a valid register.
        unsafe { write_mmio32(self.mmio_base, DWC3_GCTL, new_gctl) };

        self.initialized = true;
        Ok(())
    }

    /// Start the controller in host mode.
    ///
    /// Sets the Run/Stop bit in DCTL after asserting DRIVER_OK.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the controller is not initialized.
    pub fn start_host_mode(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }

        // SAFETY: DCTL is a valid DWC3 register.
        let dctl = unsafe { read_mmio32(self.mmio_base, DWC3_DCTL) };
        // SAFETY: same.
        unsafe { write_mmio32(self.mmio_base, DWC3_DCTL, dctl | DWC3_DCTL_RUN_STOP) };

        self.host_mode = true;
        Ok(())
    }

    /// Stop the controller.
    ///
    /// Clears the Run/Stop bit in DCTL and waits for DSTS.DEVCTRLHLT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the halt times out.
    pub fn stop(&mut self) -> Result<()> {
        // SAFETY: DCTL is a valid register.
        let dctl = unsafe { read_mmio32(self.mmio_base, DWC3_DCTL) };
        // SAFETY: same.
        unsafe { write_mmio32(self.mmio_base, DWC3_DCTL, dctl & !DWC3_DCTL_RUN_STOP) };

        // Poll DSTS for halt complete (bit 22 = DEVCTRLHLT).
        let mut retries = 10_000u32;
        loop {
            // SAFETY: DSTS is a valid register.
            let dsts = unsafe { read_mmio32(self.mmio_base, DWC3_DSTS) };
            if dsts & (1 << 22) != 0 {
                break;
            }
            retries = retries.saturating_sub(1);
            if retries == 0 {
                return Err(Error::IoError);
            }
        }

        self.host_mode = false;
        Ok(())
    }

    /// Enable a specific endpoint.
    ///
    /// Assigns the TRB ring from the pool and marks the endpoint active.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ep_idx` is out of range.
    /// - [`Error::AlreadyExists`] if the endpoint is already active.
    pub fn enable_endpoint(&mut self, ep_idx: usize) -> Result<()> {
        if ep_idx >= MAX_ENDPOINTS {
            return Err(Error::InvalidArgument);
        }
        if self.endpoints[ep_idx].active {
            return Err(Error::AlreadyExists);
        }

        // Assign a slice of the TRB pool to this endpoint.
        let trb_offset = (ep_idx * TRB_RING_SIZE * core::mem::size_of::<Trb>()) as u64;
        self.endpoints[ep_idx].trb_ring_phys = self.trb_pool_phys + trb_offset;
        self.endpoints[ep_idx].enq = 0;
        self.endpoints[ep_idx].deq = 0;
        self.endpoints[ep_idx].active = true;
        Ok(())
    }

    /// Disable an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the endpoint is not active.
    pub fn disable_endpoint(&mut self, ep_idx: usize) -> Result<()> {
        if ep_idx >= MAX_ENDPOINTS || !self.endpoints[ep_idx].active {
            return Err(Error::NotFound);
        }
        self.endpoints[ep_idx].active = false;
        Ok(())
    }

    /// Process pending events from the event buffer.
    ///
    /// Reads all available events, updates statistics, and acknowledges
    /// the events by writing to GEVNTCOUNT.
    ///
    /// Returns the number of events processed.
    pub fn process_events(&mut self) -> u32 {
        // SAFETY: GEVNTCOUNT is a valid DWC3 register.
        let count = unsafe { read_mmio32(self.mmio_base, DWC3_GEVNTCOUNT) };
        let events = count / 4; // Each event is 4 bytes.

        for _ in 0..events {
            self.event_read_ptr = (self.event_read_ptr + 4) % EVENT_BUF_SIZE;
            self.stats.events_processed += 1;
        }

        if events > 0 {
            // Acknowledge by writing the byte count consumed.
            // SAFETY: GEVNTCOUNT is a valid register.
            unsafe { write_mmio32(self.mmio_base, DWC3_GEVNTCOUNT, count) };
        }

        events
    }

    /// Read the current device connection speed from DSTS.
    pub fn connection_speed(&self) -> ConnectionSpeed {
        // SAFETY: DSTS is a valid register.
        let dsts = unsafe { read_mmio32(self.mmio_base, DWC3_DSTS) };
        match dsts & DWC3_DSTS_CONNECTSPD_MASK {
            DWC3_DSTS_SUPERSPEED => ConnectionSpeed::SuperSpeed,
            DWC3_DSTS_HIGHSPEED => ConnectionSpeed::HighSpeed,
            _ => ConnectionSpeed::Unknown,
        }
    }

    /// Return the silicon revision.
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// Return whether the controller is running in host mode.
    pub const fn is_host_mode(&self) -> bool {
        self.host_mode
    }

    /// Return whether the controller has been initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return a reference to an endpoint's state.
    pub fn endpoint(&self, ep_idx: usize) -> Option<&Endpoint> {
        if ep_idx < MAX_ENDPOINTS {
            Some(&self.endpoints[ep_idx])
        } else {
            None
        }
    }

    /// Return accumulated statistics.
    pub const fn stats(&self) -> &Dwc3Stats {
        &self.stats
    }

    /// Return the MMIO base address.
    pub const fn mmio_base(&self) -> u64 {
        self.mmio_base
    }
}

// ── Connection Speed ──────────────────────────────────────────

/// USB connection speed as reported by the DWC3 DSTS register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSpeed {
    /// USB 3.x SuperSpeed.
    SuperSpeed,
    /// USB 2.0 HighSpeed.
    HighSpeed,
    /// Full-speed, low-speed, or unknown.
    Unknown,
}

// ── DWC3 Registry ─────────────────────────────────────────────

/// Maximum DWC3 controllers in the system.
const MAX_DWC3_CONTROLLERS: usize = 4;

/// Registry of DWC3 controller instances.
pub struct Dwc3Registry {
    /// Controller slots.
    controllers: [Option<Dwc3Controller>; MAX_DWC3_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for Dwc3Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Dwc3Registry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a DWC3 controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, ctrl: Dwc3Controller) -> Result<usize> {
        if self.count >= MAX_DWC3_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(ctrl);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a controller by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Dwc3Controller> {
        if index < self.count {
            self.controllers[index].as_mut()
        } else {
            None
        }
    }

    /// Get a shared reference to a controller by index.
    pub fn get(&self, index: usize) -> Option<&Dwc3Controller> {
        if index < self.count {
            self.controllers[index].as_ref()
        } else {
            None
        }
    }

    /// Return the number of registered controllers.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

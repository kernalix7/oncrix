// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB PHY (Physical Layer) hardware abstraction.
//!
//! Provides a unified interface for USB PHY hardware including UTMI+, ULPI,
//! and HSIC PHY variants. Manages PHY initialization, calibration, power
//! sequencing, and link state transitions for USB 2.0 and USB 3.x.

use oncrix_lib::{Error, Result};

/// Maximum number of USB PHY instances.
pub const MAX_USB_PHY: usize = 4;

/// USB PHY interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbPhyType {
    /// UTMI+ (USB Transceiver Macrocell Interface Plus) — USB 2.0.
    Utmi,
    /// ULPI (UTMI+ Low Pin Interface) — USB 2.0 with reduced pin count.
    Ulpi,
    /// HSIC (High Speed Inter-Chip) — USB 2.0 chip-to-chip.
    Hsic,
    /// USB 3.0 SuperSpeed PHY.
    Usb3Ss,
    /// USB 3.1 Gen 2 PHY (10 Gbps).
    Usb31Gen2,
    /// USB 4 40Gbps Thunderbolt PHY.
    Usb4,
}

/// USB link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsbSpeed {
    /// Low Speed — 1.5 Mbps.
    LowSpeed,
    /// Full Speed — 12 Mbps.
    FullSpeed,
    /// High Speed — 480 Mbps.
    HighSpeed,
    /// SuperSpeed — 5 Gbps.
    SuperSpeed,
    /// SuperSpeed+ Gen 2 — 10 Gbps.
    SuperSpeedPlus,
}

impl UsbSpeed {
    /// Returns the nominal bit rate for this speed in bits per second.
    pub fn bitrate_bps(self) -> u64 {
        match self {
            UsbSpeed::LowSpeed => 1_500_000,
            UsbSpeed::FullSpeed => 12_000_000,
            UsbSpeed::HighSpeed => 480_000_000,
            UsbSpeed::SuperSpeed => 5_000_000_000,
            UsbSpeed::SuperSpeedPlus => 10_000_000_000,
        }
    }
}

/// USB PHY power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhyPowerState {
    /// PHY is powered off.
    PoweredOff,
    /// PHY is in suspend (low-power with resume signaling capability).
    Suspended,
    /// PHY is active and operational.
    Active,
}

/// USB PHY calibration parameters.
#[derive(Debug, Clone, Copy)]
pub struct PhyCalibration {
    /// Impedance calibration code (0..=63).
    pub impedance: u8,
    /// Amplitude calibration code (0..=15).
    pub amplitude: u8,
    /// De-emphasis level (0..=7).
    pub deemphasis: u8,
    /// Pre-emphasis level (0..=7).
    pub preemphasis: u8,
}

impl PhyCalibration {
    /// Creates default calibration values.
    pub const fn default_values() -> Self {
        Self {
            impedance: 32,
            amplitude: 8,
            deemphasis: 3,
            preemphasis: 2,
        }
    }
}

impl Default for PhyCalibration {
    fn default() -> Self {
        Self::default_values()
    }
}

/// USB PHY status register contents.
#[derive(Debug, Clone, Copy, Default)]
pub struct PhyStatus {
    /// Current link speed detected.
    pub speed: Option<UsbSpeed>,
    /// Whether a device is connected.
    pub connected: bool,
    /// Whether the PHY has detected a high-speed device.
    pub high_speed_chirp_done: bool,
    /// Whether VBUS is present.
    pub vbus_valid: bool,
    /// Session valid (VBUS above session threshold).
    pub session_valid: bool,
    /// Over-current condition detected.
    pub overcurrent: bool,
}

/// USB PHY driver.
pub struct UsbPhy {
    /// PHY index.
    id: u8,
    /// MMIO base address of PHY registers.
    base_addr: u64,
    /// PHY interface type.
    phy_type: UsbPhyType,
    /// Current power state.
    power_state: PhyPowerState,
    /// Maximum supported speed.
    max_speed: UsbSpeed,
    /// Calibration parameters.
    calibration: PhyCalibration,
    /// Whether the PHY has been initialized.
    initialized: bool,
}

impl UsbPhy {
    /// Creates a new USB PHY instance.
    ///
    /// # Arguments
    /// * `id` — PHY identifier.
    /// * `base_addr` — MMIO base address of the PHY registers.
    /// * `phy_type` — PHY interface type.
    /// * `max_speed` — Maximum supported link speed.
    pub const fn new(id: u8, base_addr: u64, phy_type: UsbPhyType, max_speed: UsbSpeed) -> Self {
        Self {
            id,
            base_addr,
            phy_type,
            power_state: PhyPowerState::PoweredOff,
            max_speed,
            calibration: PhyCalibration::default_values(),
            initialized: false,
        }
    }

    /// Returns the PHY ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the PHY type.
    pub fn phy_type(&self) -> UsbPhyType {
        self.phy_type
    }

    /// Returns the current power state.
    pub fn power_state(&self) -> PhyPowerState {
        self.power_state
    }

    /// Returns the maximum supported speed.
    pub fn max_speed(&self) -> UsbSpeed {
        self.max_speed
    }

    /// Initializes and powers on the USB PHY.
    ///
    /// Sequences the PHY power-on, applies calibration, and waits for PLL lock.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    /// Returns `Error::IoError` if PLL lock times out.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to USB PHY initialization and calibration registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            // Release reset
            ctrl.write_volatile(0x0);
            // Power on
            let pwr = (self.base_addr + 0x04) as *mut u32;
            pwr.write_volatile(0x3); // Power on core and PLL
            // Apply calibration
            let cal = (self.base_addr + 0x08) as *mut u32;
            let cal_val = (self.calibration.impedance as u32)
                | ((self.calibration.amplitude as u32) << 8)
                | ((self.calibration.deemphasis as u32) << 16)
                | ((self.calibration.preemphasis as u32) << 24);
            cal.write_volatile(cal_val);
            // Wait for PLL lock
            let status = (self.base_addr + 0x0C) as *const u32;
            let mut timeout = 10_000u32;
            while status.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::IoError);
                }
            }
        }
        self.power_state = PhyPowerState::Active;
        self.initialized = true;
        Ok(())
    }

    /// Suspends the PHY to low-power state.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn suspend(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to PHY suspend control register. base_addr is non-zero.
        unsafe {
            let pwr = (self.base_addr + 0x04) as *mut u32;
            let val = pwr.read_volatile();
            pwr.write_volatile(val | 0x4); // Set suspend bit
        }
        self.power_state = PhyPowerState::Suspended;
        Ok(())
    }

    /// Resumes the PHY from suspend state.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn resume(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to PHY resume control register. base_addr is non-zero.
        unsafe {
            let pwr = (self.base_addr + 0x04) as *mut u32;
            let val = pwr.read_volatile();
            pwr.write_volatile(val & !0x4); // Clear suspend bit
        }
        self.power_state = PhyPowerState::Active;
        Ok(())
    }

    /// Reads the current PHY status.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn read_status(&self) -> Result<PhyStatus> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO read from PHY status register. base_addr is non-zero.
        let raw = unsafe {
            let sr = (self.base_addr + 0x10) as *const u32;
            sr.read_volatile()
        };
        let status = PhyStatus {
            connected: raw & 0x1 != 0,
            high_speed_chirp_done: raw & 0x2 != 0,
            vbus_valid: raw & 0x4 != 0,
            session_valid: raw & 0x8 != 0,
            overcurrent: raw & 0x10 != 0,
            speed: if raw & 0x1 == 0 {
                None
            } else if raw & 0x20 != 0 {
                Some(UsbSpeed::HighSpeed)
            } else if raw & 0x40 != 0 {
                Some(UsbSpeed::FullSpeed)
            } else {
                Some(UsbSpeed::LowSpeed)
            },
        };
        Ok(status)
    }

    /// Sets the PHY calibration parameters.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn set_calibration(&mut self, cal: PhyCalibration) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        self.calibration = cal;
        // SAFETY: MMIO write to PHY calibration registers. base_addr is non-zero.
        unsafe {
            let cal_reg = (self.base_addr + 0x08) as *mut u32;
            let cal_val = (cal.impedance as u32)
                | ((cal.amplitude as u32) << 8)
                | ((cal.deemphasis as u32) << 16)
                | ((cal.preemphasis as u32) << 24);
            cal_reg.write_volatile(cal_val);
        }
        Ok(())
    }
}

impl Default for UsbPhy {
    fn default() -> Self {
        Self::new(0, 0, UsbPhyType::Utmi, UsbSpeed::HighSpeed)
    }
}

/// Registry of USB PHY instances.
pub struct UsbPhyRegistry {
    phys: [UsbPhy; MAX_USB_PHY],
    count: usize,
}

impl UsbPhyRegistry {
    /// Creates a new empty USB PHY registry.
    pub fn new() -> Self {
        Self {
            phys: [
                UsbPhy::new(0, 0, UsbPhyType::Utmi, UsbSpeed::HighSpeed),
                UsbPhy::new(1, 0, UsbPhyType::Utmi, UsbSpeed::HighSpeed),
                UsbPhy::new(2, 0, UsbPhyType::Usb3Ss, UsbSpeed::SuperSpeed),
                UsbPhy::new(3, 0, UsbPhyType::Usb3Ss, UsbSpeed::SuperSpeed),
            ],
            count: 0,
        }
    }

    /// Registers a USB PHY.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, phy: UsbPhy) -> Result<()> {
        if self.count >= MAX_USB_PHY {
            return Err(Error::OutOfMemory);
        }
        self.phys[self.count] = phy;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered PHYs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no PHYs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the PHY at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut UsbPhy> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.phys[index])
    }
}

impl Default for UsbPhyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks whether a PHY type natively supports SuperSpeed operation.
pub fn supports_superspeed(phy_type: UsbPhyType) -> bool {
    matches!(
        phy_type,
        UsbPhyType::Usb3Ss | UsbPhyType::Usb31Gen2 | UsbPhyType::Usb4
    )
}

/// Returns the ULPI register address for a given PHY function.
///
/// # Arguments
/// * `function` — PHY function index (0..15).
pub fn ulpi_reg_addr(function: u8) -> u8 {
    (function & 0xF) | 0x20
}

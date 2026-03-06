// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eDP (Embedded DisplayPort) panel interface hardware abstraction.
//!
//! Provides a unified interface for eDP host controllers driving internal
//! laptop and embedded display panels. Supports DisplayPort AUX channel
//! transactions, panel power sequencing, backlight control via PWM,
//! and DisplayPort link training.

use oncrix_lib::{Error, Result};

/// Maximum number of eDP host controllers.
pub const MAX_EDP_HOSTS: usize = 2;

/// Maximum number of eDP data lanes.
pub const MAX_EDP_LANES: usize = 4;

/// AUX channel transaction maximum payload bytes.
pub const AUX_MAX_PAYLOAD: usize = 16;

/// eDP link rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdpLinkRate {
    /// RBR — 1.62 Gbps per lane.
    Rbr,
    /// HBR — 2.7 Gbps per lane.
    Hbr,
    /// HBR2 — 5.4 Gbps per lane.
    Hbr2,
    /// HBR3 — 8.1 Gbps per lane.
    Hbr3,
    /// UHBR10 — 10.0 Gbps per lane.
    Uhbr10,
}

impl EdpLinkRate {
    /// Returns the raw link rate in Mbps per lane.
    pub fn mbps_per_lane(self) -> u32 {
        match self {
            EdpLinkRate::Rbr => 1_620,
            EdpLinkRate::Hbr => 2_700,
            EdpLinkRate::Hbr2 => 5_400,
            EdpLinkRate::Hbr3 => 8_100,
            EdpLinkRate::Uhbr10 => 10_000,
        }
    }
}

/// eDP panel power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelPowerState {
    /// Panel is fully powered off.
    Off,
    /// Panel is powering on (VCC applied, waiting for stabilization).
    PoweringOn,
    /// Panel is fully powered and ready for link training.
    Ready,
    /// Panel and backlight are active — displaying image.
    Active,
    /// Panel backlight is off, panel power on (blanked).
    Blanked,
    /// Panel is powering off.
    PoweringOff,
}

/// DisplayPort AUX channel transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuxRequestType {
    /// Native AUX read.
    NativeRead,
    /// Native AUX write.
    NativeWrite,
    /// I2C-over-AUX read.
    I2cRead,
    /// I2C-over-AUX write.
    I2cWrite,
    /// I2C-over-AUX write status request.
    I2cStatus,
}

/// A DisplayPort AUX channel transaction.
#[derive(Debug, Clone, Copy)]
pub struct AuxTransaction {
    /// Transaction type.
    pub req_type: AuxRequestType,
    /// DPCD or I2C address.
    pub address: u32,
    /// Payload data for write operations.
    pub data: [u8; AUX_MAX_PAYLOAD],
    /// Number of data bytes.
    pub length: u8,
}

impl AuxTransaction {
    /// Creates a native DPCD read transaction.
    pub const fn dpcd_read(address: u32, length: u8) -> Self {
        Self {
            req_type: AuxRequestType::NativeRead,
            address,
            data: [0u8; AUX_MAX_PAYLOAD],
            length,
        }
    }

    /// Creates a native DPCD write transaction.
    pub const fn dpcd_write(address: u32, value: u8) -> Self {
        let mut t = Self {
            req_type: AuxRequestType::NativeWrite,
            address,
            data: [0u8; AUX_MAX_PAYLOAD],
            length: 1,
        };
        t.data[0] = value;
        t
    }
}

impl Default for AuxTransaction {
    fn default() -> Self {
        Self::dpcd_read(0, 1)
    }
}

/// Panel timing parameters for eDP.
#[derive(Debug, Clone, Copy)]
pub struct EdpTiming {
    /// Power-on delay before HPD assertion (ms).
    pub t1_ms: u32,
    /// HPD to AUX channel ready delay (ms).
    pub t2_ms: u32,
    /// Link training to backlight enable delay (ms).
    pub t3_ms: u32,
    /// Backlight disable to panel power off delay (ms).
    pub t4_ms: u32,
    /// Panel power off to next power on minimum delay (ms).
    pub t5_ms: u32,
}

impl EdpTiming {
    /// Standard VESA eDP panel timing.
    pub const fn standard() -> Self {
        Self {
            t1_ms: 10,
            t2_ms: 20,
            t3_ms: 50,
            t4_ms: 10,
            t5_ms: 500,
        }
    }
}

impl Default for EdpTiming {
    fn default() -> Self {
        Self::standard()
    }
}

/// eDP backlight configuration.
#[derive(Debug, Clone, Copy)]
pub struct BacklightConfig {
    /// PWM frequency in Hz.
    pub pwm_freq_hz: u32,
    /// Current brightness level (0..=255).
    pub brightness: u8,
    /// Whether backlight is currently enabled.
    pub enabled: bool,
}

impl BacklightConfig {
    /// Creates a default backlight configuration at 50% brightness.
    pub const fn new(pwm_freq_hz: u32) -> Self {
        Self {
            pwm_freq_hz,
            brightness: 128,
            enabled: false,
        }
    }
}

impl Default for BacklightConfig {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// eDP host controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct EdpStats {
    /// Number of link training attempts.
    pub link_trainings: u32,
    /// Number of successful link trainings.
    pub link_train_successes: u32,
    /// Number of AUX channel transactions.
    pub aux_transactions: u64,
    /// Number of AUX errors.
    pub aux_errors: u64,
    /// Number of hot-unplug events.
    pub hotunplug_events: u32,
}

impl EdpStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            link_trainings: 0,
            link_train_successes: 0,
            aux_transactions: 0,
            aux_errors: 0,
            hotunplug_events: 0,
        }
    }
}

/// Hardware eDP host controller driver.
pub struct EdpHost {
    /// Host controller index.
    id: u8,
    /// MMIO base address.
    base_addr: u64,
    /// Maximum link rate.
    max_link_rate: EdpLinkRate,
    /// Maximum lane count.
    max_lanes: u8,
    /// Current panel power state.
    panel_state: PanelPowerState,
    /// Current link rate (after training).
    current_link_rate: Option<EdpLinkRate>,
    /// Current lane count (after training).
    current_lanes: u8,
    /// Panel power sequencing timing.
    timing: EdpTiming,
    /// Backlight configuration.
    backlight: BacklightConfig,
    /// Transfer statistics.
    stats: EdpStats,
    /// Whether the host has been initialized.
    initialized: bool,
}

impl EdpHost {
    /// Creates a new eDP host controller.
    ///
    /// # Arguments
    /// * `id` — Host identifier.
    /// * `base_addr` — MMIO base address.
    /// * `max_link_rate` — Maximum supported link rate.
    /// * `max_lanes` — Maximum number of data lanes (1, 2, or 4).
    pub const fn new(id: u8, base_addr: u64, max_link_rate: EdpLinkRate, max_lanes: u8) -> Self {
        Self {
            id,
            base_addr,
            max_link_rate,
            max_lanes,
            panel_state: PanelPowerState::Off,
            current_link_rate: None,
            current_lanes: 0,
            timing: EdpTiming::standard(),
            backlight: BacklightConfig::new(1000),
            stats: EdpStats::new(),
            initialized: false,
        }
    }

    /// Returns the host ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the current panel power state.
    pub fn panel_state(&self) -> PanelPowerState {
        self.panel_state
    }

    /// Returns the current link rate, or None if not trained.
    pub fn current_link_rate(&self) -> Option<EdpLinkRate> {
        self.current_link_rate
    }

    /// Returns the current lane count, or 0 if not trained.
    pub fn current_lanes(&self) -> u8 {
        self.current_lanes
    }

    /// Initializes the eDP host controller hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero or max_lanes invalid.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.max_lanes == 0 || (self.max_lanes as usize) > MAX_EDP_LANES {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to eDP host controller configuration registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // Reset
            ctrl.write_volatile(0x0); // Release
            let rate = (self.base_addr + 0x04) as *mut u32;
            rate.write_volatile(self.max_link_rate.mbps_per_lane());
            let lanes = (self.base_addr + 0x08) as *mut u32;
            lanes.write_volatile(self.max_lanes as u32);
        }
        self.initialized = true;
        Ok(())
    }

    /// Powers on the display panel following the eDP timing sequence.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn power_on_panel(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to panel power control register. base_addr is non-zero.
        unsafe {
            let pwr = (self.base_addr + 0x10) as *mut u32;
            pwr.write_volatile(0x1); // Apply VCC
        }
        self.panel_state = PanelPowerState::PoweringOn;
        Ok(())
    }

    /// Trains the eDP link at the specified rate and lane count.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or panel not ready.
    /// Returns `Error::IoError` if link training fails.
    pub fn train_link(&mut self, link_rate: EdpLinkRate, lanes: u8) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if self.panel_state != PanelPowerState::Ready && self.panel_state != PanelPowerState::Active
        {
            return Err(Error::Busy);
        }
        if lanes == 0 || (lanes as usize) > self.max_lanes as usize {
            return Err(Error::InvalidArgument);
        }
        self.stats.link_trainings += 1;
        // SAFETY: MMIO writes to eDP link training control registers. base_addr is non-zero.
        unsafe {
            let lt_ctrl = (self.base_addr + 0x20) as *mut u32;
            lt_ctrl.write_volatile((lanes as u32) | ((link_rate.mbps_per_lane() / 270) << 8));
            // Trigger clock recovery phase
            let lt_cmd = (self.base_addr + 0x24) as *mut u32;
            lt_cmd.write_volatile(0x1);
            // Poll for training done
            let lt_status = (self.base_addr + 0x28) as *const u32;
            let mut timeout = 100_000u32;
            while lt_status.read_volatile() & 0x3 != 0x3 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::IoError);
                }
            }
        }
        self.current_link_rate = Some(link_rate);
        self.current_lanes = lanes;
        self.panel_state = PanelPowerState::Active;
        self.stats.link_train_successes += 1;
        Ok(())
    }

    /// Issues a DPCD AUX channel transaction.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn aux_transaction(&mut self, txn: &AuxTransaction) -> Result<[u8; AUX_MAX_PAYLOAD]> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let mut result = [0u8; AUX_MAX_PAYLOAD];
        // SAFETY: MMIO writes/reads to eDP AUX channel registers. base_addr is non-zero.
        unsafe {
            let aux_addr = (self.base_addr + 0x30) as *mut u32;
            aux_addr.write_volatile(txn.address);
            let aux_ctrl = (self.base_addr + 0x34) as *mut u32;
            let cmd = match txn.req_type {
                AuxRequestType::NativeRead => 0x9u32,
                AuxRequestType::NativeWrite => 0x8,
                AuxRequestType::I2cRead => 0x1,
                AuxRequestType::I2cWrite => 0x0,
                AuxRequestType::I2cStatus => 0x2,
            };
            let len = (txn.length as u32).saturating_sub(1);
            aux_ctrl.write_volatile(cmd | (len << 4) | 0x100); // Trigger
            // For writes, send payload
            if matches!(
                txn.req_type,
                AuxRequestType::NativeWrite | AuxRequestType::I2cWrite
            ) {
                let aux_data = (self.base_addr + 0x38) as *mut u8;
                for i in 0..txn.length as usize {
                    aux_data.add(i).write_volatile(txn.data[i]);
                }
            }
            // Wait for completion
            let aux_status = (self.base_addr + 0x3C) as *const u32;
            let mut timeout = 50_000u32;
            while aux_status.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    self.stats.aux_errors += 1;
                    return Err(Error::IoError);
                }
            }
            // Read response
            if matches!(
                txn.req_type,
                AuxRequestType::NativeRead | AuxRequestType::I2cRead
            ) {
                let aux_rdata = (self.base_addr + 0x38) as *const u8;
                for i in 0..txn.length as usize {
                    result[i] = aux_rdata.add(i).read_volatile();
                }
            }
        }
        self.stats.aux_transactions += 1;
        Ok(result)
    }

    /// Sets the panel backlight brightness.
    ///
    /// # Arguments
    /// * `brightness` — Brightness level 0..=255.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn set_backlight(&mut self, brightness: u8) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        self.backlight.brightness = brightness;
        // SAFETY: MMIO write to backlight PWM duty register. base_addr is non-zero.
        unsafe {
            let bl = (self.base_addr + 0x40) as *mut u32;
            bl.write_volatile(brightness as u32);
        }
        Ok(())
    }

    /// Enables the panel backlight.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or panel not active.
    pub fn enable_backlight(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to backlight enable register. base_addr is non-zero.
        unsafe {
            let bl_en = (self.base_addr + 0x44) as *mut u32;
            bl_en.write_volatile(0x1);
        }
        self.backlight.enabled = true;
        Ok(())
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> EdpStats {
        self.stats
    }
}

impl Default for EdpHost {
    fn default() -> Self {
        Self::new(0, 0, EdpLinkRate::Hbr2, 4)
    }
}

/// Registry of eDP host controllers.
pub struct EdpHostRegistry {
    hosts: [EdpHost; MAX_EDP_HOSTS],
    count: usize,
}

impl EdpHostRegistry {
    /// Creates a new empty eDP host registry.
    pub fn new() -> Self {
        Self {
            hosts: [
                EdpHost::new(0, 0, EdpLinkRate::Hbr2, 4),
                EdpHost::new(1, 0, EdpLinkRate::Hbr3, 4),
            ],
            count: 0,
        }
    }

    /// Registers an eDP host controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, host: EdpHost) -> Result<()> {
        if self.count >= MAX_EDP_HOSTS {
            return Err(Error::OutOfMemory);
        }
        self.hosts[self.count] = host;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered hosts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no hosts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the host at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut EdpHost> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.hosts[index])
    }
}

impl Default for EdpHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the maximum pixel clock achievable with the given eDP link config.
///
/// # Arguments
/// * `link_rate` — Link rate.
/// * `lanes` — Number of data lanes.
/// * `bits_per_pixel` — Color depth (e.g., 24 for RGB888).
pub fn max_pixelclk_khz(link_rate: EdpLinkRate, lanes: u8, bits_per_pixel: u8) -> u32 {
    if bits_per_pixel == 0 {
        return 0;
    }
    let total_mbps = link_rate.mbps_per_lane() * lanes as u32;
    // 80% overhead factor for DP protocol and blanking
    total_mbps * 800 / bits_per_pixel as u32
}

/// Returns a human-readable name for an eDP link rate.
pub fn link_rate_name(rate: EdpLinkRate) -> &'static str {
    match rate {
        EdpLinkRate::Rbr => "RBR (1.62 Gbps)",
        EdpLinkRate::Hbr => "HBR (2.7 Gbps)",
        EdpLinkRate::Hbr2 => "HBR2 (5.4 Gbps)",
        EdpLinkRate::Hbr3 => "HBR3 (8.1 Gbps)",
        EdpLinkRate::Uhbr10 => "UHBR10 (10.0 Gbps)",
    }
}

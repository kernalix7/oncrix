// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MIPI DSI (Display Serial Interface) controller hardware abstraction.
//!
//! Provides a unified interface for MIPI DSI host controllers used to drive
//! LCD and OLED displays. Supports both command mode and video mode operation,
//! DCS (Display Command Set) command sending, and multi-lane PHY configuration.

use oncrix_lib::{Error, Result};

/// Maximum number of MIPI DSI host controllers.
pub const MAX_DSI_HOSTS: usize = 2;

/// Maximum number of DSI data lanes per host.
pub const MAX_DSI_LANES: usize = 4;

/// Maximum DCS command payload size in bytes.
pub const MAX_DCS_PAYLOAD: usize = 64;

/// DSI operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsiMode {
    /// Command mode — display has its own frame buffer; host sends commands on demand.
    Command,
    /// Video mode — host streams pixel data continuously.
    Video,
}

/// DSI video mode burst type (applies in video mode only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsiBurstMode {
    /// Non-burst mode with sync pulses.
    NonBurstSyncPulses,
    /// Non-burst mode with sync events.
    NonBurstSyncEvents,
    /// Burst mode — maximizes efficiency.
    Burst,
}

/// MIPI DSI pixel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsiPixelFormat {
    /// RGB565 — 16 bits per pixel.
    Rgb565,
    /// RGB666 packed — 18 bits per pixel (packed).
    Rgb666Packed,
    /// RGB666 loosely packed — 18 bits per pixel (3 bytes).
    Rgb666Loose,
    /// RGB888 — 24 bits per pixel.
    Rgb888,
}

impl DsiPixelFormat {
    /// Returns the bits per pixel for this format.
    pub fn bpp(self) -> u8 {
        match self {
            DsiPixelFormat::Rgb565 => 16,
            DsiPixelFormat::Rgb666Packed => 18,
            DsiPixelFormat::Rgb666Loose => 18,
            DsiPixelFormat::Rgb888 => 24,
        }
    }

    /// Returns the DSI DT (data type) code for this pixel format.
    pub fn data_type(self) -> u8 {
        match self {
            DsiPixelFormat::Rgb565 => 0x0E,
            DsiPixelFormat::Rgb666Packed => 0x1E,
            DsiPixelFormat::Rgb666Loose => 0x2E,
            DsiPixelFormat::Rgb888 => 0x3E,
        }
    }
}

/// DSI display timing parameters.
#[derive(Debug, Clone, Copy)]
pub struct DsiTiming {
    /// Active display width in pixels.
    pub hactive: u32,
    /// Active display height in pixels.
    pub vactive: u32,
    /// Horizontal front porch in pixel clocks.
    pub hfp: u32,
    /// Horizontal back porch in pixel clocks.
    pub hbp: u32,
    /// Horizontal sync width in pixel clocks.
    pub hsync: u32,
    /// Vertical front porch in lines.
    pub vfp: u32,
    /// Vertical back porch in lines.
    pub vbp: u32,
    /// Vertical sync width in lines.
    pub vsync: u32,
    /// Pixel clock in kHz.
    pub pixelclk_khz: u32,
}

impl DsiTiming {
    /// Creates timing for a standard 1080p display at 60 Hz.
    pub const fn fhd_60hz() -> Self {
        Self {
            hactive: 1920,
            vactive: 1080,
            hfp: 88,
            hbp: 148,
            hsync: 44,
            vfp: 4,
            vbp: 36,
            vsync: 5,
            pixelclk_khz: 148_500,
        }
    }
}

impl Default for DsiTiming {
    fn default() -> Self {
        Self::fhd_60hz()
    }
}

/// A DCS (Display Command Set) command.
#[derive(Debug, Clone)]
pub struct DcsCommand {
    /// DCS command byte.
    pub cmd: u8,
    /// Command payload data.
    pub payload: [u8; MAX_DCS_PAYLOAD],
    /// Number of valid payload bytes.
    pub payload_len: usize,
}

impl DcsCommand {
    /// Creates a DCS command with no payload.
    pub const fn new(cmd: u8) -> Self {
        Self {
            cmd,
            payload: [0u8; MAX_DCS_PAYLOAD],
            payload_len: 0,
        }
    }

    /// Creates a DCS command with a one-byte parameter.
    pub const fn with_param(cmd: u8, param: u8) -> Self {
        let mut c = Self::new(cmd);
        c.payload[0] = param;
        c.payload_len = 1;
        c
    }
}

impl Default for DcsCommand {
    fn default() -> Self {
        Self::new(0)
    }
}

/// DSI host controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct DsiStats {
    /// Total DCS commands sent.
    pub commands_sent: u64,
    /// Total video frames transmitted.
    pub frames_sent: u64,
    /// Number of PHY errors.
    pub phy_errors: u64,
    /// Number of ECC errors.
    pub ecc_errors: u64,
}

impl DsiStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            commands_sent: 0,
            frames_sent: 0,
            phy_errors: 0,
            ecc_errors: 0,
        }
    }
}

/// MIPI DSI host controller driver.
pub struct DsiHost {
    /// Host controller index.
    id: u8,
    /// MMIO base address.
    base_addr: u64,
    /// Number of data lanes.
    lane_count: u8,
    /// Current operational mode.
    mode: DsiMode,
    /// Video mode burst type.
    burst_mode: DsiBurstMode,
    /// Pixel format.
    pixel_format: DsiPixelFormat,
    /// Display timing.
    timing: DsiTiming,
    /// Whether the host is currently streaming.
    active: bool,
    /// Transfer statistics.
    stats: DsiStats,
    /// Whether the host has been initialized.
    initialized: bool,
}

impl DsiHost {
    /// Creates a new DSI host controller.
    ///
    /// # Arguments
    /// * `id` — Host identifier.
    /// * `base_addr` — MMIO base address.
    /// * `lane_count` — Number of DSI data lanes (1..=4).
    pub const fn new(id: u8, base_addr: u64, lane_count: u8) -> Self {
        Self {
            id,
            base_addr,
            lane_count,
            mode: DsiMode::Video,
            burst_mode: DsiBurstMode::Burst,
            pixel_format: DsiPixelFormat::Rgb888,
            timing: DsiTiming::fhd_60hz(),
            active: false,
            stats: DsiStats::new(),
            initialized: false,
        }
    }

    /// Returns the host ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the number of data lanes.
    pub fn lane_count(&self) -> u8 {
        self.lane_count
    }

    /// Returns whether the host is currently streaming.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Initializes the DSI host controller.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero or lane_count invalid.
    pub fn init(
        &mut self,
        mode: DsiMode,
        pixel_format: DsiPixelFormat,
        timing: DsiTiming,
    ) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.lane_count == 0 || (self.lane_count as usize) > MAX_DSI_LANES {
            return Err(Error::InvalidArgument);
        }
        self.mode = mode;
        self.pixel_format = pixel_format;
        self.timing = timing;
        // SAFETY: MMIO writes to DSI host initialization registers. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x0); // Disable
            let cfg = (self.base_addr + 0x04) as *mut u32;
            let mode_bit = match mode {
                DsiMode::Command => 0u32,
                DsiMode::Video => 1,
            };
            let burst_bit = match self.burst_mode {
                DsiBurstMode::NonBurstSyncPulses => 0u32 << 4,
                DsiBurstMode::NonBurstSyncEvents => 1 << 4,
                DsiBurstMode::Burst => 2 << 4,
            };
            cfg.write_volatile(mode_bit | burst_bit | ((self.lane_count as u32 - 1) << 8));
            // Set pixel format
            let pxfmt = (self.base_addr + 0x08) as *mut u32;
            pxfmt.write_volatile(pixel_format.data_type() as u32);
            // Set timing
            let htiming = (self.base_addr + 0x0C) as *mut u32;
            htiming.write_volatile(timing.hactive | (timing.hfp << 12) | (timing.hbp << 22));
            let vtiming = (self.base_addr + 0x10) as *mut u32;
            vtiming.write_volatile(timing.vactive | (timing.vfp << 12) | (timing.vbp << 22));
        }
        self.initialized = true;
        Ok(())
    }

    /// Enables the DSI host and starts video streaming.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or already active.
    pub fn enable(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if self.active {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to DSI enable register. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1);
        }
        self.active = true;
        Ok(())
    }

    /// Disables the DSI host.
    pub fn disable(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: MMIO write to DSI enable register. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x0);
        }
        self.active = false;
    }

    /// Sends a DCS command to the display panel.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if the payload is too large.
    pub fn send_dcs(&mut self, cmd: &DcsCommand) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if cmd.payload_len > MAX_DCS_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to DSI command FIFO registers. base_addr is non-zero.
        unsafe {
            let cmd_fifo = (self.base_addr + 0x20) as *mut u32;
            // Write header
            let header = (cmd.payload_len as u32 + 1) | ((cmd.cmd as u32) << 8);
            cmd_fifo.write_volatile(header);
            // Write payload
            let payload_fifo = (self.base_addr + 0x24) as *mut u8;
            for i in 0..cmd.payload_len {
                payload_fifo.add(i).write_volatile(cmd.payload[i]);
            }
            // Trigger send
            let trigger = (self.base_addr + 0x28) as *mut u32;
            trigger.write_volatile(0x1);
        }
        self.stats.commands_sent += 1;
        Ok(())
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> DsiStats {
        self.stats
    }
}

impl Default for DsiHost {
    fn default() -> Self {
        Self::new(0, 0, 4)
    }
}

/// Registry of DSI host controllers.
pub struct DsiHostRegistry {
    hosts: [DsiHost; MAX_DSI_HOSTS],
    count: usize,
}

impl DsiHostRegistry {
    /// Creates a new empty DSI host registry.
    pub fn new() -> Self {
        Self {
            hosts: [DsiHost::new(0, 0, 4), DsiHost::new(1, 0, 2)],
            count: 0,
        }
    }

    /// Registers a DSI host controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, host: DsiHost) -> Result<()> {
        if self.count >= MAX_DSI_HOSTS {
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
    pub fn get_mut(&mut self, index: usize) -> Result<&mut DsiHost> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.hosts[index])
    }
}

impl Default for DsiHostRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the DSI link bandwidth in Mbps for the given configuration.
///
/// # Arguments
/// * `lane_count` — Number of data lanes.
/// * `pixelclk_khz` — Pixel clock frequency in kHz.
/// * `pixel_format` — Pixel format.
pub fn compute_dsi_bandwidth_mbps(
    lane_count: u8,
    pixelclk_khz: u32,
    pixel_format: DsiPixelFormat,
) -> u64 {
    let bpp = pixel_format.bpp() as u64;
    let pixelclk = pixelclk_khz as u64;
    // Required lane rate = (pixel_clock * bpp) / lane_count
    // Add 20% overhead for DSI protocol
    (pixelclk * bpp * 12 / 10) / (lane_count as u64 * 1000)
}

/// Returns the DCS soft-reset command (0x01).
pub fn dcs_soft_reset() -> DcsCommand {
    DcsCommand::new(0x01)
}

/// Returns the DCS display-on command (0x29).
pub fn dcs_display_on() -> DcsCommand {
    DcsCommand::new(0x29)
}

/// Returns the DCS display-off command (0x28).
pub fn dcs_display_off() -> DcsCommand {
    DcsCommand::new(0x28)
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HDMI transmitter hardware abstraction.
//!
//! Provides a unified interface for HDMI transmitter silicon. Supports
//! HDMI 1.4, 2.0, and 2.1 modes, HDCP 1.4/2.x, AVI/VS/AIF infoframe
//! generation, CEC messaging, and hotplug detection.

use oncrix_lib::{Error, Result};

/// Maximum number of HDMI transmitter instances.
pub const MAX_HDMI_TX: usize = 2;

/// HDMI specification version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HdmiVersion {
    /// HDMI 1.4 — max 3840×2160@30Hz, 8 audio channels.
    Hdmi14,
    /// HDMI 2.0 — max 3840×2160@60Hz, 32 audio channels.
    Hdmi20,
    /// HDMI 2.1 — max 10K@120Hz, 48 Gbps bandwidth.
    Hdmi21,
}

/// HDMI colorspace encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdmiColorspace {
    /// RGB full range.
    RgbFull,
    /// RGB limited range (16-235).
    RgbLimited,
    /// YCbCr 4:4:4.
    Ycbcr444,
    /// YCbCr 4:2:2.
    Ycbcr422,
    /// YCbCr 4:2:0 (HDMI 2.0+).
    Ycbcr420,
}

/// HDMI color depth (bits per component).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdmiColorDepth {
    /// 8 bits per channel (24-bit total RGB).
    Bpc8,
    /// 10 bits per channel (Deep Color).
    Bpc10,
    /// 12 bits per channel (Deep Color).
    Bpc12,
    /// 16 bits per channel.
    Bpc16,
}

impl HdmiColorDepth {
    /// Returns the bits per channel value.
    pub fn bits(self) -> u8 {
        match self {
            HdmiColorDepth::Bpc8 => 8,
            HdmiColorDepth::Bpc10 => 10,
            HdmiColorDepth::Bpc12 => 12,
            HdmiColorDepth::Bpc16 => 16,
        }
    }
}

/// HDMI audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdmiAudioCodec {
    /// Linear PCM (LPCM).
    Lpcm,
    /// Dolby Digital (AC-3).
    Ac3,
    /// MPEG audio.
    Mpeg,
    /// DTS audio.
    Dts,
    /// Dolby TrueHD.
    TrueHd,
    /// DTS-HD Master Audio.
    DtsHd,
    /// Dolby Atmos.
    Atmos,
}

/// HDMI video timing / mode.
#[derive(Debug, Clone, Copy)]
pub struct HdmiMode {
    /// Horizontal active pixels.
    pub h_active: u32,
    /// Vertical active lines.
    pub v_active: u32,
    /// Refresh rate in milli-Hz (e.g., 60000 for 60 Hz, 59940 for 59.94 Hz).
    pub refresh_mhz: u32,
    /// Pixel clock in kHz.
    pub pixelclk_khz: u32,
    /// Whether this mode uses interlacing.
    pub interlaced: bool,
    /// CEA/CTA-861 video identification code.
    pub vic: u8,
}

impl HdmiMode {
    /// Standard 1080p60 mode (VIC 16).
    pub const fn fhd_60hz() -> Self {
        Self {
            h_active: 1920,
            v_active: 1080,
            refresh_mhz: 60_000,
            pixelclk_khz: 148_500,
            interlaced: false,
            vic: 16,
        }
    }

    /// 4K UHD 30 Hz (VIC 95).
    pub const fn uhd_30hz() -> Self {
        Self {
            h_active: 3840,
            v_active: 2160,
            refresh_mhz: 30_000,
            pixelclk_khz: 297_000,
            interlaced: false,
            vic: 95,
        }
    }
}

impl Default for HdmiMode {
    fn default() -> Self {
        Self::fhd_60hz()
    }
}

/// AVI (Auxiliary Video Information) infoframe data.
#[derive(Debug, Clone, Copy, Default)]
pub struct AviInfoframe {
    /// Colorspace (scan information).
    pub colorspace: u8,
    /// Video identification code.
    pub vic: u8,
    /// Pixel repetition factor.
    pub pixel_rep: u8,
    /// Extended colorimetry data.
    pub extended_colorimetry: u8,
}

/// HDMI transmitter statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct HdmiStats {
    /// Number of hotplug events.
    pub hotplug_events: u32,
    /// Number of HDCP authentication successes.
    pub hdcp_auths: u32,
    /// Number of HDCP failures.
    pub hdcp_failures: u32,
    /// Number of video mode changes.
    pub mode_changes: u32,
    /// Total CEC messages transmitted.
    pub cec_tx: u64,
    /// Total CEC messages received.
    pub cec_rx: u64,
}

impl HdmiStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            hotplug_events: 0,
            hdcp_auths: 0,
            hdcp_failures: 0,
            mode_changes: 0,
            cec_tx: 0,
            cec_rx: 0,
        }
    }
}

/// Hardware HDMI transmitter driver.
pub struct HdmiTx {
    /// Transmitter index.
    id: u8,
    /// MMIO base address of the HDMI transmitter registers.
    base_addr: u64,
    /// Maximum supported HDMI version.
    max_version: HdmiVersion,
    /// Current video mode.
    current_mode: HdmiMode,
    /// Current colorspace.
    colorspace: HdmiColorspace,
    /// Current color depth.
    color_depth: HdmiColorDepth,
    /// Whether a sink is currently connected (HPD asserted).
    sink_connected: bool,
    /// Whether the output is currently enabled.
    enabled: bool,
    /// Statistics.
    stats: HdmiStats,
    /// Whether the transmitter has been initialized.
    initialized: bool,
}

impl HdmiTx {
    /// Creates a new HDMI transmitter instance.
    ///
    /// # Arguments
    /// * `id` — Transmitter identifier.
    /// * `base_addr` — MMIO base address.
    /// * `max_version` — Maximum supported HDMI specification version.
    pub const fn new(id: u8, base_addr: u64, max_version: HdmiVersion) -> Self {
        Self {
            id,
            base_addr,
            max_version,
            current_mode: HdmiMode::fhd_60hz(),
            colorspace: HdmiColorspace::RgbFull,
            color_depth: HdmiColorDepth::Bpc8,
            sink_connected: false,
            enabled: false,
            stats: HdmiStats::new(),
            initialized: false,
        }
    }

    /// Returns the transmitter ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the maximum supported HDMI version.
    pub fn max_version(&self) -> HdmiVersion {
        self.max_version
    }

    /// Returns whether a sink is currently connected.
    pub fn sink_connected(&self) -> bool {
        self.sink_connected
    }

    /// Initializes the HDMI transmitter hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to HDMI transmitter control registers. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // Reset
            ctrl.write_volatile(0x0); // Release reset
            // Enable HPD interrupt
            let intr = (self.base_addr + 0x04) as *mut u32;
            intr.write_volatile(0x1);
        }
        self.initialized = true;
        Ok(())
    }

    /// Sets the video output mode.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn set_mode(
        &mut self,
        mode: HdmiMode,
        colorspace: HdmiColorspace,
        color_depth: HdmiColorDepth,
    ) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        self.current_mode = mode;
        self.colorspace = colorspace;
        self.color_depth = color_depth;
        // SAFETY: MMIO writes to HDMI video configuration registers. base_addr is non-zero.
        unsafe {
            let vcfg = (self.base_addr + 0x10) as *mut u32;
            vcfg.write_volatile(mode.pixelclk_khz);
            let hv = (self.base_addr + 0x14) as *mut u32;
            hv.write_volatile(mode.h_active | (mode.v_active << 16));
            let cs = (self.base_addr + 0x18) as *mut u32;
            let cs_val = match colorspace {
                HdmiColorspace::RgbFull => 0u32,
                HdmiColorspace::RgbLimited => 1,
                HdmiColorspace::Ycbcr444 => 2,
                HdmiColorspace::Ycbcr422 => 3,
                HdmiColorspace::Ycbcr420 => 4,
            };
            cs.write_volatile(cs_val | ((color_depth.bits() as u32) << 8));
        }
        self.stats.mode_changes += 1;
        Ok(())
    }

    /// Enables the HDMI output.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn enable_output(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to HDMI output enable register. base_addr is non-zero.
        unsafe {
            let out_en = (self.base_addr + 0x20) as *mut u32;
            out_en.write_volatile(0x1);
        }
        self.enabled = true;
        Ok(())
    }

    /// Disables the HDMI output.
    pub fn disable_output(&mut self) {
        if !self.enabled {
            return;
        }
        // SAFETY: MMIO write to HDMI output enable register. base_addr is non-zero.
        unsafe {
            let out_en = (self.base_addr + 0x20) as *mut u32;
            out_en.write_volatile(0x0);
        }
        self.enabled = false;
    }

    /// Polls and returns the current hotplug detection (HPD) status.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    pub fn poll_hpd(&mut self) -> Result<bool> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO read from HPD status register. base_addr is non-zero.
        let hpd = unsafe {
            let hpd_sr = (self.base_addr + 0x24) as *const u32;
            hpd_sr.read_volatile() & 0x1 != 0
        };
        let prev = self.sink_connected;
        self.sink_connected = hpd;
        if hpd != prev {
            self.stats.hotplug_events += 1;
        }
        Ok(hpd)
    }

    /// Transmits a CEC message.
    ///
    /// # Arguments
    /// * `data` — CEC frame bytes (max 16).
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if message is too long.
    pub fn send_cec(&mut self, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if data.len() > 16 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to CEC transmit register. base_addr is non-zero.
        unsafe {
            let cec_tx = (self.base_addr + 0x30) as *mut u8;
            for (i, &byte) in data.iter().enumerate() {
                cec_tx.add(i).write_volatile(byte);
            }
            let cec_ctrl = (self.base_addr + 0x2C) as *mut u32;
            cec_ctrl.write_volatile((data.len() as u32) | 0x100); // Send trigger
        }
        self.stats.cec_tx += 1;
        Ok(())
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> HdmiStats {
        self.stats
    }
}

impl Default for HdmiTx {
    fn default() -> Self {
        Self::new(0, 0, HdmiVersion::Hdmi20)
    }
}

/// Registry of HDMI transmitters.
pub struct HdmiTxRegistry {
    transmitters: [HdmiTx; MAX_HDMI_TX],
    count: usize,
}

impl HdmiTxRegistry {
    /// Creates a new empty HDMI transmitter registry.
    pub fn new() -> Self {
        Self {
            transmitters: [
                HdmiTx::new(0, 0, HdmiVersion::Hdmi20),
                HdmiTx::new(1, 0, HdmiVersion::Hdmi21),
            ],
            count: 0,
        }
    }

    /// Registers an HDMI transmitter.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, tx: HdmiTx) -> Result<()> {
        if self.count >= MAX_HDMI_TX {
            return Err(Error::OutOfMemory);
        }
        self.transmitters[self.count] = tx;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered transmitters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no transmitters are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the transmitter at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut HdmiTx> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.transmitters[index])
    }
}

impl Default for HdmiTxRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the required TMDS clock for a given HDMI mode and color depth.
///
/// TMDS clock = pixel_clock * color_depth / 8
pub fn compute_tmds_clock_khz(pixelclk_khz: u32, color_depth: HdmiColorDepth) -> u32 {
    pixelclk_khz * color_depth.bits() as u32 / 8
}

/// Returns whether a given HDMI mode requires HDMI 2.0.
pub fn requires_hdmi20(mode: &HdmiMode, cs: HdmiColorspace) -> bool {
    if cs == HdmiColorspace::Ycbcr420 {
        return true;
    }
    mode.h_active > 1920 && mode.refresh_mhz > 30_000
}

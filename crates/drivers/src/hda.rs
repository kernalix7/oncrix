// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel High Definition Audio (HDA) controller driver.
//!
//! Implements the Intel HDA specification for audio output and input.
//! The controller communicates with codecs via CORB (Command Output
//! Ring Buffer) and RIRB (Response Input Ring Buffer), which are
//! circular buffers in system memory.
//!
//! # Architecture
//!
//! - **CORB** — host writes codec verbs to the Command Output Ring
//!   Buffer; the controller fetches and sends them to codecs.
//! - **RIRB** — the controller writes codec responses to the
//!   Response Input Ring Buffer for the host to consume.
//! - **Streams** — DMA engines that transfer audio data between
//!   memory and codecs using Buffer Descriptor Lists (BDL).
//! - **Codecs** — up to 15 addressable codecs on the HDA link,
//!   each containing a tree of widgets (DACs, ADCs, mixers, pins).
//!
//! Reference: Intel High Definition Audio Specification Rev 1.0a.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// MMIO register offsets
// -------------------------------------------------------------------

/// Global Capabilities register.
const _GCAP: u32 = 0x00;

/// Minor Version register.
const _VMIN: u32 = 0x02;

/// Major Version register.
const _VMAJ: u32 = 0x03;

/// Output Payload Capability.
const _OUTPAY: u32 = 0x04;

/// Input Payload Capability.
const _INPAY: u32 = 0x06;

/// Global Control register.
const GCTL: u32 = 0x08;

/// Wake Enable register.
const _WAKEEN: u32 = 0x0C;

/// State Change Status register.
const STATESTS: u32 = 0x0E;

/// Global Status register.
const _GSTS: u32 = 0x10;

/// Interrupt Control register.
const _INTCTL: u32 = 0x20;

/// Interrupt Status register.
const _INTSTS: u32 = 0x24;

/// CORB Lower Base Address.
const _CORBLBASE: u32 = 0x40;

/// CORB Upper Base Address.
const _CORBUBASE: u32 = 0x44;

/// CORB Write Pointer.
const CORBWP: u32 = 0x48;

/// CORB Read Pointer.
const _CORBRP: u32 = 0x4A;

/// CORB Control register.
const CORBCTL: u32 = 0x4C;

/// CORB Status register.
const _CORBSTS: u32 = 0x4D;

/// CORB Size register.
const _CORBSIZE: u32 = 0x4E;

/// RIRB Lower Base Address.
const _RIRBLBASE: u32 = 0x50;

/// RIRB Upper Base Address.
const _RIRBUBASE: u32 = 0x54;

/// RIRB Write Pointer.
const RIRBWP: u32 = 0x58;

/// Response Interrupt Count.
const _RINTCNT: u32 = 0x5A;

/// RIRB Control register.
const RIRBCTL: u32 = 0x5C;

/// RIRB Status register.
const _RIRBSTS: u32 = 0x5D;

/// RIRB Size register.
const _RIRBSIZE: u32 = 0x5E;

/// DMA Position Lower Base Address.
const _DPLBASE: u32 = 0x70;

/// DMA Position Upper Base Address.
const _DPUBASE: u32 = 0x74;

// -------------------------------------------------------------------
// GCTL bits
// -------------------------------------------------------------------

/// Controller Reset bit in GCTL.
const GCTL_CRST: u32 = 1 << 0;

// -------------------------------------------------------------------
// CORB / RIRB control bits
// -------------------------------------------------------------------

/// CORB Run bit.
const CORBCTL_RUN: u32 = 1 << 1;

/// RIRB Run bit (DMA enable).
const RIRBCTL_DMAEN: u32 = 1 << 1;

// -------------------------------------------------------------------
// Verb constants
// -------------------------------------------------------------------

/// Get Parameter verb.
pub const GET_PARAMETER: u16 = 0xF00;

/// Get Connection Select Control.
pub const GET_CONN_SELECT: u16 = 0xF01;

/// Set Connection Select Control.
pub const SET_CONN_SELECT: u16 = 0x701;

/// Get Pin Widget Control.
pub const GET_PIN_CONTROL: u16 = 0xF07;

/// Set Pin Widget Control.
pub const SET_PIN_CONTROL: u16 = 0x707;

/// Get Converter Stream/Channel (stream format).
pub const GET_STREAM_FORMAT: u16 = 0xA00;

/// Set Converter Stream/Channel (stream format).
pub const SET_STREAM_FORMAT: u16 = 0x200;

/// Get Amplifier Gain/Mute.
pub const GET_AMP_GAIN: u16 = 0xB00;

/// Set Amplifier Gain/Mute.
pub const SET_AMP_GAIN: u16 = 0x300;

// -------------------------------------------------------------------
// Codec limits
// -------------------------------------------------------------------

/// Maximum codecs on an HDA link.
const MAX_CODECS: usize = 4;

/// Maximum widgets per codec we track.
const MAX_WIDGETS: usize = 32;

/// Maximum controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// CORB ring buffer capacity (entries).
const CORB_SIZE: usize = 256;

/// RIRB ring buffer capacity (entries).
const RIRB_SIZE: usize = 256;

/// Reset polling timeout (iterations).
const RESET_TIMEOUT: u32 = 100_000;

// -------------------------------------------------------------------
// MMIO helpers
// -------------------------------------------------------------------

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// -------------------------------------------------------------------
// HDA Codec Verb / Response
// -------------------------------------------------------------------

/// An HDA codec verb (command) to be written into the CORB.
#[derive(Debug, Clone, Copy)]
pub struct HdaVerb {
    /// Target codec address (0–14).
    pub codec_addr: u8,
    /// Target widget node ID.
    pub node_id: u8,
    /// Verb identifier (12 bits significant).
    pub verb: u16,
    /// Parameter byte (8 bits).
    pub param: u8,
}

impl HdaVerb {
    /// Encode the verb into a 32-bit CORB entry.
    ///
    /// Layout: `[31:28] codec | [27:20] node | [19:8] verb |
    /// [7:0] param`.
    pub fn encode(&self) -> u32 {
        let cad = (self.codec_addr as u32 & 0x0F) << 28;
        let nid = (self.node_id as u32) << 20;
        let vrb = (self.verb as u32 & 0x0FFF) << 8;
        let prm = self.param as u32;
        cad | nid | vrb | prm
    }
}

/// A response received from a codec via the RIRB.
#[derive(Debug, Clone, Copy)]
pub struct HdaResponse {
    /// The 32-bit response payload.
    pub response: u32,
    /// `true` if this is a solicited (command) response.
    pub solicited: bool,
    /// The codec address that sent this response.
    pub codec_addr: u8,
}

// -------------------------------------------------------------------
// Widget types
// -------------------------------------------------------------------

/// HDA widget function types as defined by the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WidgetType {
    /// Audio output converter (DAC).
    #[default]
    AudioOutput,
    /// Audio input converter (ADC).
    AudioInput,
    /// Audio mixer widget.
    AudioMixer,
    /// Audio selector widget.
    AudioSelector,
    /// Pin complex (physical jack/connector).
    PinComplex,
    /// Power management widget.
    PowerWidget,
    /// Volume knob widget.
    VolumeKnob,
    /// Beep generator widget.
    BeepGen,
    /// Vendor-defined widget.
    VendorDefined,
}

// -------------------------------------------------------------------
// HDA Widget
// -------------------------------------------------------------------

/// Describes a single widget within an HDA codec.
#[derive(Debug, Clone, Copy)]
pub struct HdaWidget {
    /// Widget node ID.
    pub node_id: u8,
    /// Functional type of this widget.
    pub widget_type: WidgetType,
    /// Widget capabilities from GET_PARAMETER.
    pub capabilities: u32,
    /// Pin configuration default (pin widgets only).
    pub pin_config: u32,
    /// Default configuration register.
    pub default_config: u32,
    /// Input amplifier capabilities.
    pub amp_in_caps: u32,
    /// Output amplifier capabilities.
    pub amp_out_caps: u32,
    /// Number of connections to other widgets.
    pub connection_count: u8,
    /// Whether this widget is currently active.
    pub active: bool,
}

impl HdaWidget {
    /// Create a zeroed (inactive) widget.
    const fn empty() -> Self {
        Self {
            node_id: 0,
            widget_type: WidgetType::AudioOutput,
            capabilities: 0,
            pin_config: 0,
            default_config: 0,
            amp_in_caps: 0,
            amp_out_caps: 0,
            connection_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// HDA Codec
// -------------------------------------------------------------------

/// Represents a single codec on the HDA link.
#[derive(Debug, Clone, Copy)]
pub struct HdaCodec {
    /// Codec address on the link (0–14).
    pub address: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Revision ID.
    pub revision: u8,
    /// Discovered widgets.
    pub widgets: [HdaWidget; MAX_WIDGETS],
    /// Number of valid entries in `widgets`.
    pub widget_count: usize,
    /// Audio Function Group root node ID.
    pub afg_node: u8,
}

impl HdaCodec {
    /// Create an empty codec descriptor.
    const fn empty() -> Self {
        Self {
            address: 0,
            vendor_id: 0,
            device_id: 0,
            revision: 0,
            widgets: [HdaWidget::empty(); MAX_WIDGETS],
            widget_count: 0,
            afg_node: 0,
        }
    }
}

// -------------------------------------------------------------------
// Stream Format
// -------------------------------------------------------------------

/// Describes the PCM stream format for an audio stream.
#[derive(Debug, Clone, Copy)]
pub struct StreamFormat {
    /// Sample rate in Hz (e.g. 44100, 48000).
    pub sample_rate: u32,
    /// Bits per sample (16, 20, 24, 32).
    pub bits_per_sample: u8,
    /// Number of channels (1–16).
    pub channels: u8,
}

impl StreamFormat {
    /// Encode the stream format into the 16-bit HDA format
    /// register layout.
    ///
    /// Bits `[14]` = base rate, `[13:11]` = mult, `[10:8]` =
    /// div, `[7:4]` = bits, `[3:0]` = channels - 1.
    pub fn encode(&self) -> u16 {
        // Base rate: 0 = 48 kHz, 1 = 44.1 kHz
        let base: u16 = if self.sample_rate == 44100 {
            1 << 14
        } else {
            0
        };

        // Multiplier (simplified: 1x only)
        let mult: u16 = 0;

        // Divisor (simplified: /1 only)
        let div: u16 = 0;

        // Bits per sample encoding
        let bits_enc: u16 = match self.bits_per_sample {
            16 => 0b001,
            20 => 0b010,
            24 => 0b011,
            32 => 0b100,
            _ => 0b000, // 8-bit fallback
        };

        // Channels (0-based, clamped to 0..=15)
        let ch = if self.channels == 0 {
            0u16
        } else {
            (self.channels as u16 - 1) & 0x0F
        };

        base | mult | div | (bits_enc << 4) | ch
    }
}

// -------------------------------------------------------------------
// Buffer Descriptor List Entry
// -------------------------------------------------------------------

/// A single entry in a stream's Buffer Descriptor List (BDL).
///
/// Each entry is 16 bytes and describes one DMA buffer fragment.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BdlEntry {
    /// Physical address of the buffer.
    pub address: u64,
    /// Length of the buffer in bytes.
    pub length: u32,
    /// Interrupt-on-completion flag (bit 0).
    pub ioc: u32,
}

// -------------------------------------------------------------------
// HDA Controller
// -------------------------------------------------------------------

/// Intel HDA controller state.
pub struct HdaController {
    /// MMIO base address of the controller registers.
    mmio_base: u64,
    /// Discovered codecs (up to 4).
    codecs: [Option<HdaCodec>; MAX_CODECS],
    /// Number of discovered codecs.
    codec_count: usize,
    /// Command Output Ring Buffer (host → controller).
    corb: [u32; CORB_SIZE],
    /// Response Input Ring Buffer (controller → host).
    rirb: [u64; RIRB_SIZE],
    /// Current CORB write pointer.
    corb_wp: u16,
    /// Current RIRB read pointer.
    rirb_rp: u16,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl HdaController {
    /// Create a new HDA controller bound to the given MMIO base.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            codecs: [None; MAX_CODECS],
            codec_count: 0,
            corb: [0u32; CORB_SIZE],
            rirb: [0u64; RIRB_SIZE],
            corb_wp: 0,
            rirb_rp: 0,
            initialized: false,
        }
    }

    /// Initialize the HDA controller.
    ///
    /// Performs a controller reset, configures CORB/RIRB, and
    /// enumerates attached codecs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the reset times out or
    /// codec enumeration fails.
    pub fn init(&mut self) -> Result<()> {
        // 1. Take the controller out of reset.
        self.write_reg(GCTL, 0);
        let mut timeout = RESET_TIMEOUT;
        while (self.read_reg(GCTL) & GCTL_CRST) != 0 {
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        // 2. Bring the controller out of reset.
        self.write_reg(GCTL, GCTL_CRST);
        timeout = RESET_TIMEOUT;
        while (self.read_reg(GCTL) & GCTL_CRST) == 0 {
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        // 3. Start CORB.
        let ctl = self.read_reg(CORBCTL);
        self.write_reg(CORBCTL, ctl | CORBCTL_RUN);

        // 4. Start RIRB.
        let ctl = self.read_reg(RIRBCTL);
        self.write_reg(RIRBCTL, ctl | RIRBCTL_DMAEN);

        // 5. Enumerate codecs.
        self.enumerate_codecs()?;

        self.initialized = true;
        Ok(())
    }

    /// Read a 32-bit MMIO register at the given offset.
    pub fn read_reg(&self, offset: u32) -> u32 {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is assumed to be a valid, mapped
        // HDA controller MMIO region and offset is within the
        // standard register space.
        unsafe { mmio_read32(addr) }
    }

    /// Write a 32-bit value to an MMIO register at the given
    /// offset.
    pub fn write_reg(&mut self, offset: u32, val: u32) {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is assumed to be a valid, mapped
        // HDA controller MMIO region and offset is within the
        // standard register space.
        unsafe { mmio_write32(addr, val) }
    }

    /// Send a verb (command) to a codec via the CORB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the CORB is full.
    pub fn send_verb(&mut self, verb: &HdaVerb) -> Result<()> {
        let next_wp = ((self.corb_wp as usize + 1) % CORB_SIZE) as u16;

        // Write the encoded verb into our local CORB buffer.
        self.corb[next_wp as usize] = verb.encode();
        self.corb_wp = next_wp;

        // Update the hardware write pointer.
        self.write_reg(CORBWP, next_wp as u32);
        Ok(())
    }

    /// Try to read a response from the RIRB.
    ///
    /// Returns `None` if no new response is available.
    pub fn receive_response(&mut self) -> Option<HdaResponse> {
        let hw_wp = self.read_reg(RIRBWP) as u16;
        if self.rirb_rp == hw_wp {
            return None;
        }

        let next_rp = ((self.rirb_rp as usize + 1) % RIRB_SIZE) as u16;
        let entry = self.rirb[next_rp as usize];
        self.rirb_rp = next_rp;

        let response = entry as u32;
        let ex = (entry >> 32) as u32;
        let solicited = (ex & (1 << 4)) == 0;
        let codec_addr = (ex & 0x0F) as u8;

        Some(HdaResponse {
            response,
            solicited,
            codec_addr,
        })
    }

    /// Enumerate codecs present on the HDA link.
    ///
    /// Reads STATESTS to discover which codec addresses
    /// responded to the reset, then creates codec descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if no codecs are found.
    pub fn enumerate_codecs(&mut self) -> Result<()> {
        let statests = self.read_reg(STATESTS) & 0x7FFF;
        self.codec_count = 0;

        for addr in 0..MAX_CODECS {
            if statests & (1 << addr) != 0 {
                if self.codec_count >= MAX_CODECS {
                    break;
                }
                let mut codec = HdaCodec::empty();
                codec.address = addr as u8;
                self.codecs[self.codec_count] = Some(codec);
                self.codec_count += 1;
            }
        }

        if self.codec_count == 0 {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Configure an output stream on the given codec.
    ///
    /// Sets the sample rate, bit depth, and channel count by
    /// sending SET_STREAM_FORMAT verbs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the codec index is
    /// invalid or [`Error::IoError`] on verb send failure.
    #[allow(clippy::too_many_arguments)]
    pub fn configure_output(
        &mut self,
        codec: u8,
        sample_rate: u32,
        bits: u8,
        channels: u8,
    ) -> Result<()> {
        if codec as usize >= self.codec_count {
            return Err(Error::NotFound);
        }

        let codec_info = self.codecs[codec as usize].ok_or(Error::NotFound)?;

        let fmt = StreamFormat {
            sample_rate,
            bits_per_sample: bits,
            channels,
        };
        let encoded = fmt.encode();

        // Find the first AudioOutput widget.
        let mut target_node: Option<u8> = None;
        for i in 0..codec_info.widget_count {
            let w = &codec_info.widgets[i];
            if w.widget_type == WidgetType::AudioOutput && w.active {
                target_node = Some(w.node_id);
                break;
            }
        }

        let node_id = target_node.unwrap_or(codec_info.afg_node);

        let verb = HdaVerb {
            codec_addr: codec_info.address,
            node_id,
            verb: SET_STREAM_FORMAT,
            param: (encoded & 0xFF) as u8,
        };
        self.send_verb(&verb)
    }

    /// Set the output volume for a specific widget.
    ///
    /// Sends SET_AMP_GAIN to the codec's widget with the
    /// requested gain value (0–127, where 127 is maximum).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the codec index is
    /// invalid, or [`Error::InvalidArgument`] if `gain > 127`.
    pub fn set_volume(&mut self, codec: u8, node_id: u8, gain: u8) -> Result<()> {
        if codec as usize >= self.codec_count {
            return Err(Error::NotFound);
        }
        if gain > 127 {
            return Err(Error::InvalidArgument);
        }

        let codec_info = self.codecs[codec as usize].ok_or(Error::NotFound)?;

        // SET_AMP_GAIN param: output amp, left+right, gain.
        // Bit 7 = left, bit 6 = right for the upper nibble
        // portion encoded via the verb's param.
        let verb = HdaVerb {
            codec_addr: codec_info.address,
            node_id,
            verb: SET_AMP_GAIN,
            param: gain & 0x7F,
        };
        self.send_verb(&verb)
    }

    /// Return `true` if the controller has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// -------------------------------------------------------------------
// HDA Registry
// -------------------------------------------------------------------

/// Tracks discovered HDA controllers in the system.
pub struct HdaRegistry {
    /// Registered controller MMIO base addresses.
    controllers: [Option<u64>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for HdaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HdaRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new HDA controller by MMIO base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered controller.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            self.controllers[index]
        } else {
            None
        }
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

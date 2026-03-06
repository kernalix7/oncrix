// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel High Definition Audio (HDA) codec driver.
//!
//! Implements the codec node enumeration and widget programming for HD Audio
//! codecs as specified in the Intel High Definition Audio Specification 1.0a.
//! Communicates with the codec via the HDA controller's CORB/RIRB command
//! interface (handled by the HDA controller driver in `hda.rs`).
//!
//! # Architecture
//!
//! An HDA codec is a tree of "widgets" (function group nodes):
//! - **Audio Output (DAC)** — digital-to-analog converter node
//! - **Audio Input (ADC)** — analog-to-digital converter node
//! - **Audio Mixer** — mixes multiple streams
//! - **Audio Selector** — selects one of N inputs
//! - **Pin Complex** — physical jack (HP out, line in, mic, etc.)
//! - **Volume Knob** — hardware volume control
//! - **Power Widget** — power management
//!
//! # Verb/Response Interface
//!
//! Commands (verbs) are 32-bit: [31:28]=codec addr, [27:20]=node ID,
//! [19:8]=verb, [7:0]=payload.
//!
//! Reference: Intel HDA Specification v1.0a, revision 2010.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of HDA codecs on a single HDA bus.
pub const MAX_HDA_CODECS: usize = 16;
/// Maximum number of nodes (widgets) per codec (NID 0..=127).
pub const MAX_CODEC_NODES: usize = 128;
/// Root node ID for codec enumeration.
pub const ROOT_NODE_ID: u8 = 0x00;
/// Default AFG (Audio Function Group) NID (commonly 0x01).
pub const AFG_NID: u8 = 0x01;

// ---------------------------------------------------------------------------
// Verb definitions
// ---------------------------------------------------------------------------

/// Verb: Get Parameter.
pub const VERB_GET_PARAM: u16 = 0xF00;
/// Verb: Get Connection List Entry.
pub const VERB_GET_CONN_LIST_ENTRY: u16 = 0xF02;
/// Verb: Get Connection Select Control.
pub const VERB_GET_CONN_SELECT: u16 = 0xF01;
/// Verb: Set Connection Select Control.
pub const VERB_SET_CONN_SELECT: u16 = 0x701;
/// Verb: Get Amplifier Gain/Mute (output).
pub const VERB_GET_AMP_GAIN_OUT: u16 = 0xB00;
/// Verb: Set Amplifier Gain/Mute (output).
pub const VERB_SET_AMP_GAIN_OUT: u16 = 0x300;
/// Verb: Get Power State.
pub const VERB_GET_POWER_STATE: u16 = 0xF05;
/// Verb: Set Power State.
pub const VERB_SET_POWER_STATE: u16 = 0x705;
/// Verb: Get Stream Format.
pub const VERB_GET_STREAM_FORMAT: u16 = 0xA00;
/// Verb: Set Stream Format.
pub const VERB_SET_STREAM_FORMAT: u16 = 0x200;
/// Verb: Get Pin Widget Control.
pub const VERB_GET_PIN_CTRL: u16 = 0xF07;
/// Verb: Set Pin Widget Control.
pub const VERB_SET_PIN_CTRL: u16 = 0x707;
/// Verb: Get EAPD/BTL Enable.
pub const _VERB_GET_EAPD: u16 = 0xF0C;
/// Verb: Set EAPD/BTL Enable.
pub const VERB_SET_EAPD: u16 = 0x70C;

// ---------------------------------------------------------------------------
// Parameter IDs (for VERB_GET_PARAM)
// ---------------------------------------------------------------------------

/// Vendor/Device ID.
pub const PARAM_VENDOR_ID: u8 = 0x00;
/// Revision ID.
pub const _PARAM_REVISION_ID: u8 = 0x02;
/// Subordinate Node Count.
pub const PARAM_NODE_COUNT: u8 = 0x04;
/// Function Group Type.
pub const PARAM_FG_TYPE: u8 = 0x05;
/// Audio Widget Capabilities.
pub const PARAM_WIDGET_CAP: u8 = 0x09;
/// Supported PCM Sizes and Rates.
pub const PARAM_PCM_RATES: u8 = 0x0A;
/// Supported Stream Formats.
pub const _PARAM_STREAM_FMTS: u8 = 0x0B;
/// Pin Capabilities.
pub const PARAM_PIN_CAP: u8 = 0x0C;
/// Amplifier Capabilities (input/output).
pub const PARAM_AMP_CAP_OUT: u8 = 0x12;
/// Connection List Length.
pub const PARAM_CONN_LIST_LEN: u8 = 0x0E;

// ---------------------------------------------------------------------------
// Widget type codes (from PARAM_WIDGET_CAP [23:20])
// ---------------------------------------------------------------------------

/// Widget type: Audio Output (DAC).
pub const WIDGET_DAC: u8 = 0x0;
/// Widget type: Audio Input (ADC).
pub const WIDGET_ADC: u8 = 0x1;
/// Widget type: Audio Mixer.
pub const WIDGET_MIXER: u8 = 0x2;
/// Widget type: Audio Selector.
pub const WIDGET_SELECTOR: u8 = 0x3;
/// Widget type: Pin Complex.
pub const WIDGET_PIN: u8 = 0x4;
/// Widget type: Power Widget.
pub const WIDGET_POWER: u8 = 0x5;
/// Widget type: Volume Knob.
pub const WIDGET_VOL_KNOB: u8 = 0x6;
/// Widget type: Beep Generator.
pub const WIDGET_BEEP: u8 = 0x7;

// ---------------------------------------------------------------------------
// Power state codes
// ---------------------------------------------------------------------------

/// D0 — fully powered on.
pub const POWER_D0: u8 = 0x00;
/// D3hot — powered off, context retained.
pub const POWER_D3HOT: u8 = 0x03;

// ---------------------------------------------------------------------------
// Pin control bits
// ---------------------------------------------------------------------------

/// Pin Widget Control: Output Enable.
pub const PIN_CTRL_OUT_EN: u8 = 1 << 6;
/// Pin Widget Control: Input Enable.
pub const PIN_CTRL_IN_EN: u8 = 1 << 5;
/// Pin Widget Control: High-Z (tri-state).
pub const _PIN_CTRL_HIZ: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Amplifier gain/mute bits (payload for SET_AMP_GAIN_OUT)
// ---------------------------------------------------------------------------

/// Amp gain: Set output amp.
pub const AMP_OUT: u16 = 1 << 15;
/// Amp gain: Set left channel.
pub const AMP_LEFT: u16 = 1 << 13;
/// Amp gain: Set right channel.
pub const AMP_RIGHT: u16 = 1 << 12;
/// Amp gain: Mute bit.
pub const AMP_MUTE: u16 = 1 << 7;

// ---------------------------------------------------------------------------
// Stream format (16-bit word for SET_STREAM_FORMAT)
// ---------------------------------------------------------------------------

/// Build a stream format word for 48 kHz, 16-bit stereo, PCM.
///
/// - BASE=0 (48 kHz base), MULT=0 (×1), DIV=0 (÷1), BITS=1 (16-bit),
///   CHAN=1 (2 channels = stereo).
pub const STREAM_FMT_48K_16BIT_STEREO: u16 = 0x0011;
/// 44.1 kHz base, 16-bit stereo.
pub const STREAM_FMT_44K_16BIT_STEREO: u16 = 0x4011;

// ---------------------------------------------------------------------------
// Codec node descriptor
// ---------------------------------------------------------------------------

/// Describes a single widget node within a codec.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodecNode {
    /// Node ID (NID).
    pub nid: u8,
    /// Widget type (DAC, ADC, Pin, etc.).
    pub widget_type: u8,
    /// Widget capabilities word.
    pub capabilities: u32,
    /// Connection list length.
    pub conn_list_len: u8,
    /// Whether this node is active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Codec driver
// ---------------------------------------------------------------------------

/// HD Audio codec driver state.
pub struct HdaCodec {
    /// HDA bus address (0..15).
    pub codec_addr: u8,
    /// Vendor ID (upper 16 bits) and Device ID (lower 16 bits).
    pub vendor_device_id: u32,
    /// Audio Function Group starting NID.
    pub afg_start_nid: u8,
    /// Total node count.
    pub total_nodes: u8,
    /// Array of discovered widget nodes.
    pub nodes: [CodecNode; MAX_CODEC_NODES],
    /// Number of discovered nodes.
    pub node_count: usize,
    /// Whether the codec is initialized.
    pub initialized: bool,
}

impl HdaCodec {
    /// Creates a new codec driver for the given codec address.
    pub const fn new(codec_addr: u8) -> Self {
        Self {
            codec_addr,
            vendor_device_id: 0,
            afg_start_nid: 0,
            total_nodes: 0,
            nodes: [CodecNode {
                nid: 0,
                widget_type: 0,
                capabilities: 0,
                conn_list_len: 0,
                active: false,
            }; MAX_CODEC_NODES],
            node_count: 0,
            initialized: false,
        }
    }

    /// Enumerates the codec by reading its function group and widget tree.
    ///
    /// `send_verb` is a closure that sends a verb to the HDA controller and
    /// returns the RIRB response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the controller returns an error.
    pub fn enumerate<F>(&mut self, mut send_verb: F) -> Result<()>
    where
        F: FnMut(u8, u8, u16, u8) -> Result<u32>,
    {
        // Read vendor/device ID from root node.
        self.vendor_device_id = send_verb(
            self.codec_addr,
            ROOT_NODE_ID,
            VERB_GET_PARAM,
            PARAM_VENDOR_ID,
        )?;

        // Read subordinate node count from root.
        let root_node_count = send_verb(
            self.codec_addr,
            ROOT_NODE_ID,
            VERB_GET_PARAM,
            PARAM_NODE_COUNT,
        )?;
        let afg_start = ((root_node_count >> 16) & 0xFF) as u8;
        let _afg_total = (root_node_count & 0xFF) as u8;
        self.afg_start_nid = afg_start;

        // Enumerate widgets under the AFG node.
        let afg_node_count = send_verb(self.codec_addr, AFG_NID, VERB_GET_PARAM, PARAM_NODE_COUNT)?;
        let widget_start = ((afg_node_count >> 16) & 0xFF) as u8;
        let widget_total = (afg_node_count & 0xFF) as u8;
        self.total_nodes = widget_total;

        let end_nid = widget_start.saturating_add(widget_total);
        for nid in widget_start..end_nid {
            if self.node_count >= MAX_CODEC_NODES {
                break;
            }
            let caps = send_verb(self.codec_addr, nid, VERB_GET_PARAM, PARAM_WIDGET_CAP)?;
            let widget_type = ((caps >> 20) & 0xF) as u8;
            let conn_len_resp =
                send_verb(self.codec_addr, nid, VERB_GET_PARAM, PARAM_CONN_LIST_LEN)?;
            let conn_list_len = (conn_len_resp & 0x7F) as u8;

            let idx = self.node_count;
            self.nodes[idx] = CodecNode {
                nid,
                widget_type,
                capabilities: caps,
                conn_list_len,
                active: true,
            };
            self.node_count += 1;
        }

        self.initialized = true;
        Ok(())
    }

    /// Powers up the AFG and all widgets (D0 state).
    ///
    /// # Errors
    ///
    /// Propagates verb send errors.
    pub fn power_up<F>(&self, mut send_verb: F) -> Result<()>
    where
        F: FnMut(u8, u8, u16, u8) -> Result<u32>,
    {
        send_verb(self.codec_addr, AFG_NID, VERB_SET_POWER_STATE, POWER_D0)?;
        for i in 0..self.node_count {
            let nid = self.nodes[i].nid;
            send_verb(self.codec_addr, nid, VERB_SET_POWER_STATE, POWER_D0)?;
        }
        Ok(())
    }

    /// Configures the first DAC node for audio output.
    ///
    /// Enables the first pin complex as output with EAPD, unmutes the DAC,
    /// and sets the stream format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no DAC or pin node is found.
    /// Propagates verb send errors.
    pub fn configure_output<F>(&self, stream_tag: u8, mut send_verb: F) -> Result<()>
    where
        F: FnMut(u8, u8, u16, u8) -> Result<u32>,
    {
        // Find DAC node.
        let dac = self.find_widget(WIDGET_DAC).ok_or(Error::NotFound)?;
        // Find Pin node.
        let pin = self.find_widget(WIDGET_PIN).ok_or(Error::NotFound)?;

        // Set DAC stream format (48 kHz, 16-bit stereo).
        send_verb(
            self.codec_addr,
            dac.nid,
            VERB_SET_STREAM_FORMAT,
            // Payload: stream_tag[7:4] | channel 0[3:0] in the upper byte of format.
            // For simplicity, we encode tag into high nibble (controller sets tag).
            (stream_tag >> 4) as u8,
        )?;
        // Set pin control: output enable.
        send_verb(self.codec_addr, pin.nid, VERB_SET_PIN_CTRL, PIN_CTRL_OUT_EN)?;
        // Enable EAPD (amplifier).
        send_verb(self.codec_addr, pin.nid, VERB_SET_EAPD, 0x02)?;
        // Unmute DAC output amplifier, max gain.
        let amp_payload = AMP_OUT | AMP_LEFT | AMP_RIGHT; // no mute, gain = 0
        send_verb(
            self.codec_addr,
            dac.nid,
            VERB_SET_AMP_GAIN_OUT,
            (amp_payload & 0xFF) as u8,
        )?;
        Ok(())
    }

    /// Returns the vendor ID portion of the vendor/device ID.
    pub fn vendor_id(&self) -> u16 {
        (self.vendor_device_id >> 16) as u16
    }

    /// Returns the device ID portion of the vendor/device ID.
    pub fn device_id(&self) -> u16 {
        (self.vendor_device_id & 0xFFFF) as u16
    }

    /// Returns `true` if the codec is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Finds the first widget of the given type.
    fn find_widget(&self, widget_type: u8) -> Option<&CodecNode> {
        self.nodes[..self.node_count]
            .iter()
            .find(|n| n.active && n.widget_type == widget_type)
    }
}

impl Default for HdaCodec {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Verb encoding helpers
// ---------------------------------------------------------------------------

/// Encodes a 12-bit verb + 8-bit payload into the payload field of an HDA command.
pub const fn encode_verb_payload(verb: u16, payload: u8) -> u32 {
    ((verb as u32) << 8) | payload as u32
}

/// Builds a full 32-bit HDA command word.
///
/// `codec_addr` — codec address (0..15).
/// `nid` — node ID.
/// `verb` — 12-bit verb.
/// `payload` — 8-bit payload.
pub const fn build_hda_command(codec_addr: u8, nid: u8, verb: u16, payload: u8) -> u32 {
    ((codec_addr as u32) << 28) | ((nid as u32) << 20) | ((verb as u32) << 8) | payload as u32
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DisplayPort AUX channel communication and link training.
//!
//! Implements the DisplayPort AUX channel protocol for reading and
//! writing DPCD registers, performing I2C-over-AUX transactions for
//! EDID retrieval, and running the full DP link training sequence.
//!
//! # Architecture
//!
//! - **DpAuxController** — manages up to 4 AUX channels; each
//!   channel provides DPCD register access and I2C passthrough.
//! - **DpLinkConfig** — negotiated link parameters (rate, lanes).
//! - **DpSinkCaps** — capabilities read from the sink DPCD.
//! - Link training phases: clock recovery → channel EQ → trained.
//!
//! # Link Training Summary
//!
//! ```text
//! 1. Clock Recovery (CR):
//!    - Set link rate & lane count in DPCD (0x100, 0x101).
//!    - Write training pattern 1 to TRAINING_PATTERN_SET (0x102).
//!    - Read lane status registers (0x202–0x204); retry w/ voltage
//!      swing adjustments until CR_DONE bits are set.
//! 2. Channel Equalization (CE):
//!    - Write training pattern 2.
//!    - Poll CHANNEL_EQ_DONE and SYMBOL_LOCKED in lane status.
//!    - Once all bits set, write training pattern = 0 (normal).
//! ```
//!
//! Reference: VESA DisplayPort Standard Version 2.1.

use oncrix_lib::{Error, Result};

// ── DPCD Register Addresses ───────────────────────────────────

/// DPCD Revision (0x00000).
const DPCD_REV: u32 = 0x00000;

/// Max Link Rate (0x00001).
const DPCD_MAX_LINK_RATE: u32 = 0x00001;

/// Max Lane Count (0x00002).
const DPCD_MAX_LANE_COUNT: u32 = 0x00002;

/// Link BW Set — negotiated link rate (0x00100).
const DPCD_LINK_BW_SET: u32 = 0x00100;

/// Lane Count Set — negotiated lane count (0x00101).
const DPCD_LANE_COUNT_SET: u32 = 0x00101;

/// Training Pattern Set (0x00102).
const DPCD_TRAINING_PATTERN_SET: u32 = 0x00102;

/// Training Lane 0 Set (0x00103).
const DPCD_TRAINING_LANE0_SET: u32 = 0x00103;

/// Lane 0/1 Status (0x00202).
const DPCD_LANE01_STATUS: u32 = 0x00202;

/// Lane 2/3 Status (0x00203).
const DPCD_LANE23_STATUS: u32 = 0x00203;

/// Lane Align Status Updated (0x00204).
const _DPCD_LANE_ALIGN_STATUS: u32 = 0x00204;

/// Adjust Request Lane 0/1 (0x00206).
const DPCD_ADJUST_REQ_LANE01: u32 = 0x00206;

/// EDP Capability (0x00700).
const DPCD_EDP_CAP: u32 = 0x00700;

/// Sink Count (0x00200).
const _DPCD_SINK_COUNT: u32 = 0x00200;

// ── Lane status bit masks ─────────────────────────────────────

/// Clock Recovery Done for lane 0.
const LANE_STATUS_CR_DONE0: u8 = 1 << 0;
/// Symbol Locked for lane 0.
const LANE_STATUS_SYM_LOCKED0: u8 = 1 << 1;
/// Channel EQ Done for lane 0.
const LANE_STATUS_CEQ_DONE0: u8 = 1 << 2;
/// Clock Recovery Done for lane 1 (upper nibble).
const LANE_STATUS_CR_DONE1: u8 = 1 << 4;
/// Symbol Locked for lane 1.
const LANE_STATUS_SYM_LOCKED1: u8 = 1 << 5;
/// Channel EQ Done for lane 1.
const LANE_STATUS_CEQ_DONE1: u8 = 1 << 6;

// ── Limits ────────────────────────────────────────────────────

/// Maximum AUX channels managed by one controller.
const MAX_AUX_CHANNELS: usize = 4;

/// AUX message maximum data payload (16 bytes).
const AUX_DATA_MAX: usize = 16;

/// Maximum voltage swing adjustment retries during CR phase.
const CR_MAX_RETRIES: u32 = 5;

/// Maximum channel EQ retries.
const CEQ_MAX_RETRIES: u32 = 5;

// ── Link rate ─────────────────────────────────────────────────

/// DisplayPort link rates in Mbps per lane (symbol rate * 8b/10b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpLinkRate {
    /// RBR — Reduced Bit Rate: 1.62 Gbps per lane.
    Rbr,
    /// HBR — High Bit Rate: 2.70 Gbps per lane.
    Hbr,
    /// HBR2 — High Bit Rate 2: 5.40 Gbps per lane.
    Hbr2,
    /// HBR3 — High Bit Rate 3: 8.10 Gbps per lane.
    Hbr3,
}

impl DpLinkRate {
    /// Return the link rate in Mbps (symbol clock * 10).
    pub fn mbps(self) -> u32 {
        match self {
            Self::Rbr => 1620,
            Self::Hbr => 2700,
            Self::Hbr2 => 5400,
            Self::Hbr3 => 8100,
        }
    }

    /// Return the DPCD Link BW byte value.
    pub fn dpcd_bw(self) -> u8 {
        match self {
            Self::Rbr => 0x06,
            Self::Hbr => 0x0A,
            Self::Hbr2 => 0x14,
            Self::Hbr3 => 0x1E,
        }
    }

    /// Decode from a DPCD Max Link Rate byte.
    pub fn from_dpcd(val: u8) -> Self {
        match val {
            0x1E => Self::Hbr3,
            0x14 => Self::Hbr2,
            0x0A => Self::Hbr,
            _ => Self::Rbr,
        }
    }
}

impl Default for DpLinkRate {
    fn default() -> Self {
        Self::Rbr
    }
}

// ── Lane count ────────────────────────────────────────────────

/// DisplayPort lane counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpLaneCount {
    /// Single lane.
    One,
    /// Two lanes.
    Two,
    /// Four lanes.
    Four,
}

impl DpLaneCount {
    /// Return the lane count as a raw integer.
    pub fn count(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    /// Decode from DPCD Max Lane Count (bits 4:0).
    pub fn from_dpcd(val: u8) -> Self {
        match val & 0x1F {
            4 => Self::Four,
            2 => Self::Two,
            _ => Self::One,
        }
    }
}

impl Default for DpLaneCount {
    fn default() -> Self {
        Self::One
    }
}

// ── AUX message ───────────────────────────────────────────────

/// DisplayPort AUX transaction message.
#[derive(Debug, Clone, Copy)]
pub struct DpAuxMessage {
    /// 20-bit DPCD register address or I2C address.
    pub address: u32,
    /// Transaction type (Native read/write, I2C read/write).
    pub request: DpAuxRequest,
    /// Data payload (up to 16 bytes).
    pub data: [u8; AUX_DATA_MAX],
    /// Number of valid bytes in `data`.
    pub size: u8,
}

/// AUX channel transaction type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpAuxRequest {
    /// Native DPCD register read.
    NativeRead,
    /// Native DPCD register write.
    NativeWrite,
    /// I2C-over-AUX read (EDID).
    I2cRead,
    /// I2C-over-AUX write.
    I2cWrite,
}

impl Default for DpAuxMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl DpAuxMessage {
    /// Create an empty AUX message.
    pub const fn new() -> Self {
        Self {
            address: 0,
            request: DpAuxRequest::NativeRead,
            data: [0u8; AUX_DATA_MAX],
            size: 0,
        }
    }
}

// ── Link configuration ────────────────────────────────────────

/// Negotiated DisplayPort link configuration.
#[derive(Debug, Clone, Copy)]
pub struct DpLinkConfig {
    /// Active link rate.
    pub rate: DpLinkRate,
    /// Active lane count.
    pub lanes: DpLaneCount,
    /// Enhanced framing mode enabled.
    pub enhanced_framing: bool,
    /// Spread-spectrum clocking enabled.
    pub spread_spectrum: bool,
}

impl Default for DpLinkConfig {
    fn default() -> Self {
        Self {
            rate: DpLinkRate::Rbr,
            lanes: DpLaneCount::One,
            enhanced_framing: false,
            spread_spectrum: false,
        }
    }
}

// ── Sink capabilities ─────────────────────────────────────────

/// Capabilities read from the sink's DPCD.
#[derive(Debug, Clone, Copy, Default)]
pub struct DpSinkCaps {
    /// DPCD revision byte (0x00 = DPCD 1.0, 0x12 = 1.2, etc.).
    pub dpcd_rev: u8,
    /// Maximum supported link rate.
    pub max_rate: DpLinkRate,
    /// Maximum supported lane count.
    pub max_lanes: DpLaneCount,
    /// Whether the sink is an embedded display panel (eDP).
    pub supports_edp: bool,
    /// Whether Multi-Stream Transport (MST) is supported.
    pub supports_mst: bool,
}

impl DpSinkCaps {
    /// Create default sink caps.
    pub const fn new() -> Self {
        Self {
            dpcd_rev: 0,
            max_rate: DpLinkRate::Rbr,
            max_lanes: DpLaneCount::One,
            supports_edp: false,
            supports_mst: false,
        }
    }
}

// ── Per-channel state ─────────────────────────────────────────

/// Training phase for a DP link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpTrainingState {
    /// Not started.
    #[default]
    Idle,
    /// Clock recovery in progress.
    ClockRecovery,
    /// Channel equalisation in progress.
    ChannelEq,
    /// Link training complete.
    Trained,
    /// Training failed.
    Failed,
}

/// State of one AUX channel.
struct AuxChannel {
    /// Parsed sink capabilities (valid after `read_sink_caps`).
    sink_caps: DpSinkCaps,
    /// Current link configuration.
    link_config: DpLinkConfig,
    /// Link training state.
    training_state: DpTrainingState,
    /// MMIO base address for this AUX channel's registers.
    mmio_base: u64,
    /// Whether this channel slot is in use.
    active: bool,
}

impl AuxChannel {
    const fn new() -> Self {
        Self {
            sink_caps: DpSinkCaps::new(),
            link_config: DpLinkConfig {
                rate: DpLinkRate::Rbr,
                lanes: DpLaneCount::One,
                enhanced_framing: false,
                spread_spectrum: false,
            },
            training_state: DpTrainingState::Idle,
            mmio_base: 0,
            active: false,
        }
    }
}

// ── Statistics ────────────────────────────────────────────────

/// Operational statistics for the DP AUX controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct DpAuxStats {
    /// Total AUX transactions attempted.
    pub transactions: u64,
    /// Transactions that received a NACK reply.
    pub nacks: u64,
    /// Transactions deferred by the sink.
    pub defers: u64,
    /// Transactions that timed out.
    pub timeouts: u64,
}

// ── DP AUX controller ─────────────────────────────────────────

/// DisplayPort AUX channel controller.
///
/// Manages up to [`MAX_AUX_CHANNELS`] (4) AUX channels. Provides
/// DPCD register access, I2C-over-AUX for EDID, and link training.
pub struct DpAuxController {
    /// Per-channel state.
    channels: [AuxChannel; MAX_AUX_CHANNELS],
    /// Number of active channels.
    channel_count: usize,
    /// Operational statistics.
    stats: DpAuxStats,
}

impl Default for DpAuxController {
    fn default() -> Self {
        Self::new()
    }
}

impl DpAuxController {
    /// Create a new DP AUX controller.
    pub fn new() -> Self {
        Self {
            channels: [const { AuxChannel::new() }; MAX_AUX_CHANNELS],
            channel_count: 0,
            stats: DpAuxStats::default(),
        }
    }

    /// Register an AUX channel with the given MMIO base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the channel table is full.
    pub fn add_channel(&mut self, mmio_base: u64) -> Result<usize> {
        if self.channel_count >= MAX_AUX_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.channel_count;
        self.channels[idx].mmio_base = mmio_base;
        self.channels[idx].active = true;
        self.channel_count += 1;
        Ok(idx)
    }

    // ── AUX transaction engine ────────────────────────────────

    /// Perform a single AUX transaction.
    ///
    /// Simulates the AUX channel handshake: sends the request
    /// header and payload, then reads back the reply status.
    /// In a real driver this drives the AUX encoder MMIO registers.
    ///
    /// Returns the number of bytes transferred.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ch` is an invalid channel index.
    /// - [`Error::IoError`] on NACK or unrecoverable error.
    /// - [`Error::Busy`] if the sink deferred the transaction.
    fn aux_transaction(&mut self, ch: usize, msg: &DpAuxMessage) -> Result<usize> {
        if ch >= self.channel_count || !self.channels[ch].active {
            return Err(Error::NotFound);
        }
        self.stats.transactions += 1;
        // In a full implementation, we would write the AUX request
        // to the controller MMIO registers and poll the reply status.
        // The reply codes are: ACK (0x00), NACK (0x01), DEFER (0x02).
        // We model a successful transfer here.
        let _ = msg;
        Ok(msg.size as usize)
    }

    // ── DPCD access ───────────────────────────────────────────

    /// Read `len` bytes from DPCD starting at `reg`.
    ///
    /// Fills `buf[..len]` with the DPCD data.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `len` is 0 or > 16.
    /// - [`Error::NotFound`] if `ch` is invalid.
    /// - [`Error::IoError`] on NACK.
    pub fn read_dpcd(&mut self, ch: usize, reg: u32, buf: &mut [u8], len: usize) -> Result<()> {
        if len == 0 || len > AUX_DATA_MAX || len > buf.len() {
            return Err(Error::InvalidArgument);
        }
        let msg = DpAuxMessage {
            address: reg,
            request: DpAuxRequest::NativeRead,
            data: [0u8; AUX_DATA_MAX],
            size: len as u8,
        };
        let transferred = self.aux_transaction(ch, &msg)?;
        buf[..transferred].copy_from_slice(&msg.data[..transferred]);
        Ok(())
    }

    /// Write `len` bytes to DPCD starting at `reg`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `len` is 0 or > 16.
    /// - [`Error::NotFound`] if `ch` is invalid.
    /// - [`Error::IoError`] on NACK.
    pub fn write_dpcd(&mut self, ch: usize, reg: u32, data: &[u8], len: usize) -> Result<()> {
        if len == 0 || len > AUX_DATA_MAX || len > data.len() {
            return Err(Error::InvalidArgument);
        }
        let mut msg = DpAuxMessage {
            address: reg,
            request: DpAuxRequest::NativeWrite,
            data: [0u8; AUX_DATA_MAX],
            size: len as u8,
        };
        msg.data[..len].copy_from_slice(&data[..len]);
        self.aux_transaction(ch, &msg)?;
        Ok(())
    }

    /// Read a single DPCD register byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] / [`Error::IoError`] on failure.
    pub fn read_dpcd_byte(&mut self, ch: usize, reg: u32) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_dpcd(ch, reg, &mut buf, 1)?;
        Ok(buf[0])
    }

    // ── I2C-over-AUX ─────────────────────────────────────────

    /// Read `len` bytes from I2C address `i2c_addr` (e.g. 0x50 for
    /// EDID), starting at `offset`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `len` > 16.
    /// - [`Error::NotFound`] / [`Error::IoError`] on failure.
    pub fn i2c_read(
        &mut self,
        ch: usize,
        i2c_addr: u8,
        offset: u8,
        buf: &mut [u8],
        len: usize,
    ) -> Result<()> {
        if len == 0 || len > AUX_DATA_MAX || len > buf.len() {
            return Err(Error::InvalidArgument);
        }
        // Set I2C address and offset via write transaction.
        let addr_msg = DpAuxMessage {
            address: u32::from(i2c_addr),
            request: DpAuxRequest::I2cWrite,
            data: [offset, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            size: 1,
        };
        self.aux_transaction(ch, &addr_msg)?;

        // Read the data.
        let read_msg = DpAuxMessage {
            address: u32::from(i2c_addr),
            request: DpAuxRequest::I2cRead,
            data: [0u8; AUX_DATA_MAX],
            size: len as u8,
        };
        let transferred = self.aux_transaction(ch, &read_msg)?;
        buf[..transferred].copy_from_slice(&read_msg.data[..transferred]);
        Ok(())
    }

    /// Write `len` bytes to I2C address `i2c_addr`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `len` > 16.
    /// - [`Error::NotFound`] / [`Error::IoError`] on failure.
    pub fn i2c_write(&mut self, ch: usize, i2c_addr: u8, data: &[u8], len: usize) -> Result<()> {
        if len == 0 || len > AUX_DATA_MAX || len > data.len() {
            return Err(Error::InvalidArgument);
        }
        let mut msg = DpAuxMessage {
            address: u32::from(i2c_addr),
            request: DpAuxRequest::I2cWrite,
            data: [0u8; AUX_DATA_MAX],
            size: len as u8,
        };
        msg.data[..len].copy_from_slice(&data[..len]);
        self.aux_transaction(ch, &msg)?;
        Ok(())
    }

    // ── Sink capability discovery ─────────────────────────────

    /// Read the sink's DPCD capabilities into channel `ch`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] / [`Error::IoError`] on AUX failure.
    pub fn read_sink_caps(&mut self, ch: usize) -> Result<DpSinkCaps> {
        if ch >= self.channel_count || !self.channels[ch].active {
            return Err(Error::NotFound);
        }
        let dpcd_rev = self.read_dpcd_byte(ch, DPCD_REV)?;
        let max_rate_raw = self.read_dpcd_byte(ch, DPCD_MAX_LINK_RATE)?;
        let max_lane_raw = self.read_dpcd_byte(ch, DPCD_MAX_LANE_COUNT)?;
        let edp_cap = self.read_dpcd_byte(ch, DPCD_EDP_CAP).unwrap_or(0);

        let caps = DpSinkCaps {
            dpcd_rev,
            max_rate: DpLinkRate::from_dpcd(max_rate_raw),
            max_lanes: DpLaneCount::from_dpcd(max_lane_raw),
            supports_edp: edp_cap & 0x01 != 0,
            supports_mst: max_lane_raw & 0x80 != 0, // bit 7 = ENHANCED_FRAME_CAP
        };
        self.channels[ch].sink_caps = caps;
        Ok(caps)
    }

    // ── Link training ─────────────────────────────────────────

    /// Clock recovery phase of link training.
    ///
    /// Writes training pattern 1, sets link parameters, and polls
    /// lane status until CR_DONE is set in all active lanes.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ch` is invalid.
    /// - [`Error::IoError`] if CR fails after max retries.
    pub fn clock_recovery_phase(&mut self, ch: usize, cfg: &DpLinkConfig) -> Result<()> {
        if ch >= self.channel_count || !self.channels[ch].active {
            return Err(Error::NotFound);
        }
        // Program link BW and lane count.
        self.write_dpcd(ch, DPCD_LINK_BW_SET, &[cfg.rate.dpcd_bw()], 1)?;
        self.write_dpcd(ch, DPCD_LANE_COUNT_SET, &[cfg.lanes.count()], 1)?;

        // Set training pattern 1.
        self.write_dpcd(ch, DPCD_TRAINING_PATTERN_SET, &[0x01], 1)?;

        // Initial voltage swing: level 0, pre-emphasis 0.
        let sw = [0x00u8; 4];
        self.write_dpcd(ch, DPCD_TRAINING_LANE0_SET, &sw, cfg.lanes.count() as usize)?;

        self.channels[ch].training_state = DpTrainingState::ClockRecovery;

        let mut retries = CR_MAX_RETRIES;
        loop {
            let status01 = self.read_dpcd_byte(ch, DPCD_LANE01_STATUS)?;
            let status23 = self.read_dpcd_byte(ch, DPCD_LANE23_STATUS)?;

            let lanes = cfg.lanes.count();
            let cr_done = match lanes {
                1 => status01 & LANE_STATUS_CR_DONE0 != 0,
                2 => status01 & LANE_STATUS_CR_DONE0 != 0 && status01 & LANE_STATUS_CR_DONE1 != 0,
                4 => {
                    status01 & LANE_STATUS_CR_DONE0 != 0
                        && status01 & LANE_STATUS_CR_DONE1 != 0
                        && status23 & LANE_STATUS_CR_DONE0 != 0
                        && status23 & LANE_STATUS_CR_DONE1 != 0
                }
                _ => false,
            };

            if cr_done {
                return Ok(());
            }

            retries = retries.saturating_sub(1);
            if retries == 0 {
                self.channels[ch].training_state = DpTrainingState::Failed;
                return Err(Error::IoError);
            }

            // Adjust voltage swing from sink's request.
            let adj = self.read_dpcd_byte(ch, DPCD_ADJUST_REQ_LANE01)?;
            let new_sw = [adj & 0x3F; 4];
            self.write_dpcd(ch, DPCD_TRAINING_LANE0_SET, &new_sw, lanes as usize)?;
        }
    }

    /// Channel equalization phase of link training.
    ///
    /// Writes training pattern 2 and polls until CEQ_DONE and
    /// SYMBOL_LOCKED are set in all active lanes.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ch` is invalid.
    /// - [`Error::IoError`] if CE fails after max retries.
    pub fn channel_eq_phase(&mut self, ch: usize, cfg: &DpLinkConfig) -> Result<()> {
        if ch >= self.channel_count || !self.channels[ch].active {
            return Err(Error::NotFound);
        }
        // Set training pattern 2.
        self.write_dpcd(ch, DPCD_TRAINING_PATTERN_SET, &[0x02], 1)?;
        self.channels[ch].training_state = DpTrainingState::ChannelEq;

        let mut retries = CEQ_MAX_RETRIES;
        loop {
            let status01 = self.read_dpcd_byte(ch, DPCD_LANE01_STATUS)?;
            let status23 = self.read_dpcd_byte(ch, DPCD_LANE23_STATUS)?;

            let lanes = cfg.lanes.count();
            let eq_done = match lanes {
                1 => {
                    status01 & LANE_STATUS_CEQ_DONE0 != 0 && status01 & LANE_STATUS_SYM_LOCKED0 != 0
                }
                2 => {
                    status01 & LANE_STATUS_CEQ_DONE0 != 0
                        && status01 & LANE_STATUS_SYM_LOCKED0 != 0
                        && status01 & LANE_STATUS_CEQ_DONE1 != 0
                        && status01 & LANE_STATUS_SYM_LOCKED1 != 0
                }
                4 => {
                    status01 & (LANE_STATUS_CEQ_DONE0 | LANE_STATUS_SYM_LOCKED0) != 0
                        && status01 & (LANE_STATUS_CEQ_DONE1 | LANE_STATUS_SYM_LOCKED1) != 0
                        && status23 & (LANE_STATUS_CEQ_DONE0 | LANE_STATUS_SYM_LOCKED0) != 0
                        && status23 & (LANE_STATUS_CEQ_DONE1 | LANE_STATUS_SYM_LOCKED1) != 0
                }
                _ => false,
            };

            if eq_done {
                // Disable training pattern.
                let _ = self.write_dpcd(ch, DPCD_TRAINING_PATTERN_SET, &[0x00], 1);
                self.channels[ch].training_state = DpTrainingState::Trained;
                self.channels[ch].link_config = *cfg;
                return Ok(());
            }

            retries = retries.saturating_sub(1);
            if retries == 0 {
                self.channels[ch].training_state = DpTrainingState::Failed;
                return Err(Error::IoError);
            }
        }
    }

    /// Run the full DP link training sequence.
    ///
    /// Executes clock recovery then channel equalization. On success
    /// the link is ready for video data.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `ch` is invalid.
    /// - [`Error::IoError`] if either training phase fails.
    pub fn full_link_training(&mut self, ch: usize, cfg: &DpLinkConfig) -> Result<()> {
        self.clock_recovery_phase(ch, cfg)?;
        self.channel_eq_phase(ch, cfg)?;
        Ok(())
    }

    // ── Accessors ─────────────────────────────────────────────

    /// Return the training state of channel `ch`.
    ///
    /// Returns `None` if `ch` is invalid.
    pub fn training_state(&self, ch: usize) -> Option<DpTrainingState> {
        if ch < self.channel_count && self.channels[ch].active {
            Some(self.channels[ch].training_state)
        } else {
            None
        }
    }

    /// Return a copy of the link config for channel `ch`.
    pub fn link_config(&self, ch: usize) -> Option<DpLinkConfig> {
        if ch < self.channel_count && self.channels[ch].active {
            Some(self.channels[ch].link_config)
        } else {
            None
        }
    }

    /// Return a copy of the sink capabilities for channel `ch`.
    pub fn sink_caps(&self, ch: usize) -> Option<DpSinkCaps> {
        if ch < self.channel_count && self.channels[ch].active {
            Some(self.channels[ch].sink_caps)
        } else {
            None
        }
    }

    /// Return the operational statistics.
    pub fn stats(&self) -> &DpAuxStats {
        &self.stats
    }

    /// Return the number of active channels.
    pub fn channel_count(&self) -> usize {
        self.channel_count
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AC97 audio codec interface driver.
//!
//! Implements the AC'97 (Audio Codec '97) interface as defined by Intel's
//! AC'97 Component Specification (Revision 2.3). AC97 splits audio hardware
//! into two components: an AC-Link controller (the "ICH" audio controller,
//! handled separately) and one or more codecs that handle the actual D/A and
//! A/D conversion.
//!
//! # Architecture
//!
//! - **AC-Link** — serial interface between the controller and codecs.
//! - **NAM (Native Audio Mixer)** — codec register space, accessed via the
//!   controller's `NAM_CTRL` / `NAM_DATA` I/O ports (or MMIO registers).
//! - **NABM (Native Audio Bus Master)** — DMA engine registers for PCM streams.
//! - **BDL (Buffer Descriptor List)** — array of `BdlEntry` descriptors that
//!   the controller DMA reads to find PCM buffers.
//!
//! # Codec Registers (NAM space, 16-bit wide)
//!
//! | Offset | Name                    |
//! |--------|-------------------------|
//! | 0x00   | Reset                   |
//! | 0x02   | Master Volume           |
//! | 0x04   | Headphone Volume        |
//! | 0x06   | Master Mono Volume      |
//! | 0x18   | PCM Out Volume          |
//! | 0x1A   | PCM In Volume           |
//! | 0x28   | Audio Interrupt & Paging|
//! | 0x2A   | Power Down Ctrl/Stat    |
//! | 0x2C   | Extended Audio ID       |
//! | 0x2E   | Extended Audio Ctrl     |
//! | 0x7C   | Vendor ID 1             |
//! | 0x7E   | Vendor ID 2             |
//!
//! # NABM Registers (per-stream, see `nabm_offset`)
//!
//! | Offset | Width | Name                          |
//! |--------|-------|-------------------------------|
//! | +0x00  | 32    | BDL Base Address              |
//! | +0x04  | 8     | Current Entry Number          |
//! | +0x05  | 8     | Last Valid Entry              |
//! | +0x06  | 16    | Status                        |
//! | +0x08  | 16    | Position in Current Buffer    |
//! | +0x0A  | 8     | Prefetched Index              |
//! | +0x0B  | 8     | Control Byte                  |
//!
//! Reference: Intel AC'97 Component Specification Rev 2.3a.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Port Definitions
// ---------------------------------------------------------------------------

/// NAM (codec register) base I/O port (ICH standard base).
const NAM_BASE: u16 = 0xD000;

/// NABM (bus-master) base I/O port.
const NABM_BASE: u16 = 0xD100;

// ---------------------------------------------------------------------------
// Codec (NAM) Register Offsets
// ---------------------------------------------------------------------------

/// Codec reset register; write any value to reset.
const NAM_RESET: u16 = 0x00;
/// Master volume (left/right, mute bit 15).
const NAM_MASTER_VOL: u16 = 0x02;
/// Headphone volume.
const _NAM_HP_VOL: u16 = 0x04;
/// Master mono volume.
const _NAM_MASTER_MONO_VOL: u16 = 0x06;
/// PC Beep volume.
const _NAM_PC_BEEP: u16 = 0x0A;
/// Phone volume.
const _NAM_PHONE_VOL: u16 = 0x0C;
/// Mic volume.
const NAM_MIC_VOL: u16 = 0x0E;
/// Line-in volume.
const _NAM_LINE_IN_VOL: u16 = 0x10;
/// CD volume.
const _NAM_CD_VOL: u16 = 0x12;
/// PCM out volume.
const NAM_PCM_OUT_VOL: u16 = 0x18;
/// PCM in volume.
const _NAM_PCM_IN_VOL: u16 = 0x1A;
/// Record select.
const _NAM_REC_SEL: u16 = 0x1A;
/// Record gain.
const _NAM_REC_GAIN: u16 = 0x1C;
/// General purpose register.
const _NAM_GENERAL_PURPOSE: u16 = 0x20;
/// 3D control.
const _NAM_3D_CTRL: u16 = 0x22;
/// Power down control/status.
const NAM_POWERDOWN: u16 = 0x26;
/// Extended Audio ID.
const NAM_EXT_AUDIO_ID: u16 = 0x28;
/// Extended Audio Control/Status.
const NAM_EXT_AUDIO_CTRL: u16 = 0x2A;
/// PCM Front DAC Rate.
const NAM_PCM_FRONT_DAC_RATE: u16 = 0x2C;
/// PCM ADC Rate.
const _NAM_PCM_ADC_RATE: u16 = 0x32;
/// Vendor ID 1.
const NAM_VENDOR_ID1: u16 = 0x7C;
/// Vendor ID 2.
const NAM_VENDOR_ID2: u16 = 0x7E;

// ---------------------------------------------------------------------------
// NABM Register Offsets (from NABM_BASE, per-stream)
// ---------------------------------------------------------------------------

/// PCM in stream base offset.
const NABM_PCM_IN: u16 = 0x00;
/// PCM out stream base offset.
const NABM_PCM_OUT: u16 = 0x10;
/// MIC in stream base offset.
const _NABM_MIC_IN: u16 = 0x20;
/// Global control register offset.
const NABM_GLOBAL_CTRL: u16 = 0x2C;
/// Global status register offset.
const NABM_GLOBAL_STATUS: u16 = 0x30;

// NABM stream sub-register offsets.
/// BDL base address.
const NABM_BDBAR: u16 = 0x00;
/// Current entry number (read-only).
const _NABM_CIV: u16 = 0x04;
/// Last valid entry index (writeable).
const NABM_LVI: u16 = 0x05;
/// Status register.
const NABM_SR: u16 = 0x06;
/// Control byte.
const NABM_CR: u16 = 0x0B;

// ---------------------------------------------------------------------------
// NABM Status Register Bits
// ---------------------------------------------------------------------------

/// SR: FIFO error.
const _NABM_SR_FIFOE: u16 = 1 << 4;
/// SR: Last valid entry interrupt.
const _NABM_SR_LVBCI: u16 = 1 << 2;
/// SR: Buffer completion interrupt.
const _NABM_SR_BCIS: u16 = 1 << 3;
/// SR: DMA controller halted.
const NABM_SR_DCH: u16 = 1 << 0;

// ---------------------------------------------------------------------------
// NABM Control Byte Bits
// ---------------------------------------------------------------------------

/// CR: DMA controller run bit.
const NABM_CR_RPBM: u8 = 1 << 0;
/// CR: Reset pipeline.
const NABM_CR_RR: u8 = 1 << 1;
/// CR: Last valid entry interrupt enable.
const _NABM_CR_LVBIE: u8 = 1 << 2;
/// CR: FIFO error interrupt enable.
const _NABM_CR_FEIE: u8 = 1 << 3;
/// CR: Buffer completion interrupt enable.
const _NABM_CR_IOCE: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// Global Control Bits
// ---------------------------------------------------------------------------

/// Global Control: Global Interrupt Enable.
const NABM_GC_GIE: u32 = 1 << 0;
/// Global Control: Cold reset.
const NABM_GC_COLD_RESET: u32 = 1 << 1;
/// Global Control: Warm reset.
const _NABM_GC_WARM_RESET: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Extended Audio ID / Ctrl Bits
// ---------------------------------------------------------------------------

/// Extended Audio ID: Variable rate supported.
const EXT_AUDIO_ID_VRA: u16 = 1 << 0;
/// Extended Audio Control: Enable variable rate.
const EXT_AUDIO_CTRL_VRA: u16 = 1 << 0;

// ---------------------------------------------------------------------------
// Volume encoding
// ---------------------------------------------------------------------------

/// Mute bit in volume registers.
const VOL_MUTE: u16 = 1 << 15;
/// Maximum attenuation value per channel (0x3F = fully attenuated).
pub const VOL_MAX_ATT: u8 = 0x3F;

// ---------------------------------------------------------------------------
// Buffer Descriptor List
// ---------------------------------------------------------------------------

/// Maximum BDL entries per stream (hardware limit: 32).
pub const BDL_ENTRIES: usize = 32;

/// Buffer descriptor entry for AC97 DMA.
///
/// The controller reads the BDL to find PCM buffer addresses and sizes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BdlEntry {
    /// Physical address of the PCM buffer.
    pub phys_addr: u32,
    /// Number of samples in the buffer (16-bit samples count).
    pub samples: u16,
    /// Flags: bit 15 = generate interrupt, bit 14 = last entry in list (BUP).
    pub flags: u16,
}

/// BDL entry flag: generate an interrupt when this buffer completes.
pub const BDL_FLAG_IOC: u16 = 1 << 15;
/// BDL entry flag: buffer underrun policy (0=silence, 1=repeat).
pub const BDL_FLAG_BUP: u16 = 1 << 14;

// ---------------------------------------------------------------------------
// Sample rate limits
// ---------------------------------------------------------------------------

/// Minimum supported sample rate (Hz).
pub const RATE_MIN: u32 = 7_350;
/// Maximum supported sample rate for VRA (Hz).
pub const RATE_MAX: u32 = 48_000;
/// Fixed sample rate when VRA is not supported (Hz).
pub const RATE_FIXED: u32 = 48_000;

// ---------------------------------------------------------------------------
// Codec Vendor IDs (for identification)
// ---------------------------------------------------------------------------

/// AC97 codec vendor identification.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodecVendorId {
    /// Vendor ID word 1 (NAM 0x7C).
    pub id1: u16,
    /// Vendor ID word 2 (NAM 0x7E).
    pub id2: u16,
}

impl CodecVendorId {
    /// Decodes the 32-bit concatenated vendor string into 4 ASCII bytes.
    pub fn vendor_chars(&self) -> [u8; 4] {
        [
            (self.id1 >> 8) as u8,
            (self.id1 & 0xFF) as u8,
            (self.id2 >> 8) as u8,
            (self.id2 & 0xFF) as u8,
        ]
    }
}

// ---------------------------------------------------------------------------
// Ac97Codec driver
// ---------------------------------------------------------------------------

/// Driver for an AC97 audio codec accessed through an ICH-style controller.
pub struct Ac97Codec {
    /// Base I/O port for NAM (codec registers).
    nam_base: u16,
    /// Base I/O port for NABM (bus master DMA).
    nabm_base: u16,
    /// Whether the driver has been initialised.
    initialized: bool,
    /// Whether the codec supports variable rate audio (VRA).
    vra_supported: bool,
    /// Current PCM front DAC sample rate.
    sample_rate: u32,
    /// Codec vendor ID.
    vendor_id: CodecVendorId,
    /// PCM output BDL.
    pcm_out_bdl: [BdlEntry; BDL_ENTRIES],
    /// Current fill index into the PCM out BDL.
    pcm_out_lvi: u8,
}

impl Ac97Codec {
    /// Creates a new (uninitialised) AC97 codec driver.
    ///
    /// `nam_base` and `nabm_base` are the I/O port base addresses as read
    /// from the PCI BAR configuration.
    pub const fn new(nam_base: u16, nabm_base: u16) -> Self {
        Self {
            nam_base,
            nabm_base,
            initialized: false,
            vra_supported: false,
            sample_rate: RATE_FIXED,
            vendor_id: CodecVendorId { id1: 0, id2: 0 },
            pcm_out_bdl: [BdlEntry {
                phys_addr: 0,
                samples: 0,
                flags: 0,
            }; BDL_ENTRIES],
            pcm_out_lvi: 0,
        }
    }

    /// Initialises the AC97 codec.
    ///
    /// Performs a cold reset, waits for codec power-up, reads the vendor ID,
    /// detects VRA, and configures default volumes.
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Cold reset via global control.
        let gc = self.read_nabm32(NABM_GLOBAL_CTRL);
        self.write_nabm32(NABM_GLOBAL_CTRL, gc | NABM_GC_COLD_RESET);

        // Step 2: Reset codec registers.
        self.write_nam16(NAM_RESET, 1);

        // Step 3: Wait for codec ready (power-down register should clear).
        self.wait_powerup()?;

        // Step 4: Read vendor ID.
        self.vendor_id = CodecVendorId {
            id1: self.read_nam16(NAM_VENDOR_ID1),
            id2: self.read_nam16(NAM_VENDOR_ID2),
        };

        // Step 5: Enable global interrupt.
        self.write_nabm32(NABM_GLOBAL_CTRL, NABM_GC_GIE | NABM_GC_COLD_RESET);

        // Step 6: Detect VRA support.
        let ext_id = self.read_nam16(NAM_EXT_AUDIO_ID);
        if ext_id & EXT_AUDIO_ID_VRA != 0 {
            self.vra_supported = true;
            // Enable VRA.
            let ctrl = self.read_nam16(NAM_EXT_AUDIO_CTRL);
            self.write_nam16(NAM_EXT_AUDIO_CTRL, ctrl | EXT_AUDIO_CTRL_VRA);
        }

        // Step 7: Set default sample rate.
        self.set_sample_rate(RATE_FIXED)?;

        // Step 8: Default volumes — unmuted, moderate attenuation.
        self.set_master_volume(false, 0x08, 0x08)?;
        self.set_pcm_out_volume(false, 0x08, 0x08)?;
        self.set_mic_volume(false, 0x08)?;

        self.initialized = true;
        Ok(())
    }

    /// Returns the codec vendor ID.
    pub fn vendor_id(&self) -> &CodecVendorId {
        &self.vendor_id
    }

    /// Returns `true` if variable-rate audio (VRA) is supported.
    pub fn has_vra(&self) -> bool {
        self.vra_supported
    }

    /// Returns the current PCM front DAC sample rate.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Sets the PCM output sample rate.
    ///
    /// If VRA is not supported, only 48000 Hz is accepted.
    pub fn set_sample_rate(&mut self, rate: u32) -> Result<()> {
        if !self.initialized && rate != RATE_FIXED {
            // Allow setting during init.
        }
        if !self.vra_supported && rate != RATE_FIXED {
            return Err(Error::InvalidArgument);
        }
        if rate < RATE_MIN || rate > RATE_MAX {
            return Err(Error::InvalidArgument);
        }
        self.write_nam16(NAM_PCM_FRONT_DAC_RATE, rate as u16);
        // Verify the codec accepted the rate.
        let actual = self.read_nam16(NAM_PCM_FRONT_DAC_RATE) as u32;
        if actual == 0 {
            return Err(Error::IoError);
        }
        self.sample_rate = actual;
        Ok(())
    }

    /// Sets the master volume.
    ///
    /// `mute` — if true, sets the mute bit.
    /// `left_att`, `right_att` — attenuation (0 = max volume, 0x3F = silent).
    pub fn set_master_volume(&self, mute: bool, left_att: u8, right_att: u8) -> Result<()> {
        let vol = encode_stereo_vol(mute, left_att, right_att);
        self.write_nam16(NAM_MASTER_VOL, vol);
        Ok(())
    }

    /// Sets the PCM output volume.
    pub fn set_pcm_out_volume(&self, mute: bool, left_att: u8, right_att: u8) -> Result<()> {
        let vol = encode_stereo_vol(mute, left_att, right_att);
        self.write_nam16(NAM_PCM_OUT_VOL, vol);
        Ok(())
    }

    /// Sets the microphone input volume.
    pub fn set_mic_volume(&self, mute: bool, gain: u8) -> Result<()> {
        let gain_clipped = gain.min(VOL_MAX_ATT);
        let val = if mute {
            VOL_MUTE | gain_clipped as u16
        } else {
            gain_clipped as u16
        };
        self.write_nam16(NAM_MIC_VOL, val);
        Ok(())
    }

    /// Adds a PCM output buffer to the BDL.
    ///
    /// `phys_addr` — physical address of the PCM sample buffer.
    /// `samples` — number of 16-bit samples in the buffer.
    /// `last` — if true, marks this as the last valid entry.
    pub fn add_pcm_out_buffer(&mut self, phys_addr: u32, samples: u16, last: bool) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let idx = self.pcm_out_lvi as usize;
        let mut flags = BDL_FLAG_IOC;
        if last {
            flags |= BDL_FLAG_BUP;
        }
        self.pcm_out_bdl[idx] = BdlEntry {
            phys_addr,
            samples,
            flags,
        };
        self.pcm_out_lvi = ((self.pcm_out_lvi as usize + 1) % BDL_ENTRIES) as u8;
        Ok(())
    }

    /// Submits the BDL to the hardware and starts PCM output DMA.
    ///
    /// `bdl_phys` — physical address of the `pcm_out_bdl` array.
    pub fn start_pcm_out(&self, bdl_phys: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        // Reset the PCM out channel.
        self.write_nabm8(NABM_PCM_OUT + NABM_CR, NABM_CR_RR);
        // Wait for reset to complete.
        for _ in 0..1_000_000u32 {
            let cr = self.read_nabm8(NABM_PCM_OUT + NABM_CR);
            if cr & NABM_CR_RR == 0 {
                break;
            }
        }
        // Program BDL base address.
        self.write_nabm32(NABM_PCM_OUT + NABM_BDBAR, bdl_phys);
        // Set last valid entry.
        let lvi = if self.pcm_out_lvi == 0 {
            (BDL_ENTRIES - 1) as u8
        } else {
            self.pcm_out_lvi - 1
        };
        self.write_nabm8(NABM_PCM_OUT + NABM_LVI, lvi);
        // Start DMA.
        self.write_nabm8(NABM_PCM_OUT + NABM_CR, NABM_CR_RPBM);
        Ok(())
    }

    /// Stops PCM output DMA.
    pub fn stop_pcm_out(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        // Clear RPBM to stop.
        let cr = self.read_nabm8(NABM_PCM_OUT + NABM_CR);
        self.write_nabm8(NABM_PCM_OUT + NABM_CR, cr & !NABM_CR_RPBM);
        Ok(())
    }

    /// Returns `true` if PCM output DMA is running.
    pub fn pcm_out_running(&self) -> bool {
        let sr = self.read_nabm16(NABM_PCM_OUT + NABM_SR);
        sr & NABM_SR_DCH == 0
    }

    /// Handles an interrupt for the PCM output stream.
    ///
    /// Clears interrupt flags by writing them back (RWC). Returns the
    /// raw status value for the caller to inspect.
    pub fn handle_pcm_out_irq(&self) -> u16 {
        let sr = self.read_nabm16(NABM_PCM_OUT + NABM_SR);
        // Clear by writing back.
        self.write_nabm16(NABM_PCM_OUT + NABM_SR, sr);
        sr
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Polls the power-down register until the codec reports "ready".
    fn wait_powerup(&self) -> Result<()> {
        for _ in 0..1_000_000u32 {
            let pd = self.read_nam16(NAM_POWERDOWN);
            // Bits 15:8 are power status flags; 0 = all powered up.
            if pd & 0xFF00 == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    // -----------------------------------------------------------------------
    // Private: port I/O
    // -----------------------------------------------------------------------

    fn read_nam16(&self, reg: u16) -> u16 {
        port_inw(self.nam_base + reg)
    }

    fn write_nam16(&self, reg: u16, value: u16) {
        port_outw(self.nam_base + reg, value)
    }

    fn read_nabm8(&self, reg: u16) -> u8 {
        port_inb(self.nabm_base + reg)
    }

    fn write_nabm8(&self, reg: u16, value: u8) {
        port_outb(self.nabm_base + reg, value)
    }

    fn read_nabm16(&self, reg: u16) -> u16 {
        port_inw(self.nabm_base + reg)
    }

    fn write_nabm16(&self, reg: u16, value: u16) {
        port_outw(self.nabm_base + reg, value)
    }

    fn read_nabm32(&self, reg: u16) -> u32 {
        port_ind(self.nabm_base + reg)
    }

    fn write_nabm32(&self, reg: u16, value: u32) {
        port_outd(self.nabm_base + reg, value)
    }
}

// ---------------------------------------------------------------------------
// Volume encoding helper
// ---------------------------------------------------------------------------

/// Encodes a stereo volume register value from attenuation and mute.
fn encode_stereo_vol(mute: bool, left_att: u8, right_att: u8) -> u16 {
    let l = (left_att.min(VOL_MAX_ATT) as u16) << 8;
    let r = right_att.min(VOL_MAX_ATT) as u16;
    let m = if mute { VOL_MUTE } else { 0 };
    m | l | r
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

fn port_inb(port: u16) -> u8 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Reads from NABM I/O ports assigned by PCI BAR configuration.
        let v: u8;
        core::arch::asm!("in al, dx", in("dx") port, out("al") v,
            options(nomem, nostack, preserves_flags));
        v
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = port;
        0
    }
}

fn port_outb(port: u16, value: u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Writes to NABM I/O ports assigned by PCI BAR configuration.
        core::arch::asm!("out dx, al", in("dx") port, in("al") value,
            options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (port, value);
    }
}

fn port_inw(port: u16) -> u16 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Reads from NAM or NABM I/O ports assigned by PCI BARs.
        let v: u16;
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") v,
            options(nomem, nostack, preserves_flags));
        v
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = port;
        0
    }
}

fn port_outw(port: u16, value: u16) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Writes to NAM or NABM I/O ports assigned by PCI BARs.
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value,
            options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (port, value);
    }
}

fn port_ind(port: u16) -> u32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Reads a 32-bit NABM register from an I/O port.
        let v: u32;
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") v,
            options(nomem, nostack, preserves_flags));
        v
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = port;
        0
    }
}

fn port_outd(port: u16, value: u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: Writes a 32-bit value to a NABM register via I/O port.
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value,
            options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (port, value);
    }
}

// ---------------------------------------------------------------------------
// Global device registry
// ---------------------------------------------------------------------------

/// Maximum number of AC97 codec devices tracked.
const MAX_AC97_DEVICES: usize = 4;

/// Registry of AC97 codec drivers.
pub struct Ac97Registry {
    devices: [Ac97Codec; MAX_AC97_DEVICES],
    count: usize,
}

impl Ac97Registry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { Ac97Codec::new(NAM_BASE, NABM_BASE) }; MAX_AC97_DEVICES],
            count: 0,
        }
    }

    /// Registers an AC97 device with the given I/O port bases.
    ///
    /// Calls `init()` and returns the assigned index.
    pub fn register(&mut self, nam_base: u16, nabm_base: u16) -> Result<usize> {
        if self.count >= MAX_AC97_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let mut dev = Ac97Codec::new(nam_base, nabm_base);
        dev.init()?;
        let idx = self.count;
        self.devices[idx] = dev;
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the device at `index`.
    pub fn get(&self, index: usize) -> Option<&Ac97Codec> {
        if index < self.count {
            Some(&self.devices[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Ac97Codec> {
        if index < self.count {
            Some(&mut self.devices[index])
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for Ac97Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_stereo_vol_unmuted() {
        let v = encode_stereo_vol(false, 0x08, 0x08);
        assert_eq!(v, 0x0808);
    }

    #[test]
    fn encode_stereo_vol_muted() {
        let v = encode_stereo_vol(true, 0x00, 0x00);
        assert_eq!(v, VOL_MUTE);
    }

    #[test]
    fn encode_stereo_vol_clamps_attenuation() {
        let v = encode_stereo_vol(false, 0xFF, 0xFF);
        assert_eq!(v, encode_stereo_vol(false, VOL_MAX_ATT, VOL_MAX_ATT));
    }

    #[test]
    fn bdl_entry_size() {
        assert_eq!(core::mem::size_of::<BdlEntry>(), 8);
    }

    #[test]
    fn registry_empty() {
        let reg = Ac97Registry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn codec_initial_state() {
        let c = Ac97Codec::new(0xD000, 0xD100);
        assert!(!c.initialized);
        assert!(!c.has_vra());
        assert_eq!(c.sample_rate(), RATE_FIXED);
    }
}

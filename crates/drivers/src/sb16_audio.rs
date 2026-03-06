// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sound Blaster 16 (ISA audio) driver.
//!
//! The Sound Blaster 16 is the classic ISA-bus audio card widely supported
//! by legacy software and emulators (QEMU, DOSBox). It provides:
//!
//! - 8-bit and 16-bit PCM playback/capture via DMA
//! - FM synthesis via OPL2/OPL3 at I/O ports 0x388/0x389
//! - Mixer chip for volume/sample rate control
//! - DSP (Digital Signal Processor) command interface
//!
//! This driver implements the SB16 DSP command interface and mixer.
//!
//! Reference: Creative Labs Sound Blaster 16 Programmer's Reference.

use oncrix_lib::{Error, Result};

// ── SB16 I/O Ports (base = 0x220) ─────────────────────────────────────────

/// Default SB16 I/O base address.
pub const SB16_BASE: u16 = 0x220;

/// DSP Reset port (base + 6).
pub const DSP_RESET: u16 = 6;
/// DSP Read Data port (base + 0xA).
pub const DSP_READ: u16 = 0xA;
/// DSP Write Command/Data port (base + 0xC).
pub const DSP_WRITE: u16 = 0xC;
/// DSP Write Status port (read, base + 0xC).
pub const DSP_WRITE_STATUS: u16 = 0xC;
/// DSP Read Status port (base + 0xE).
pub const DSP_READ_STATUS: u16 = 0xE;
/// Mixer address port (base + 4).
pub const MIXER_ADDR: u16 = 4;
/// Mixer data port (base + 5).
pub const MIXER_DATA: u16 = 5;

// ── DSP Commands ───────────────────────────────────────────────────────────

pub mod dsp_cmd {
    /// DSP version query.
    pub const VERSION: u8 = 0xE1;
    /// 16-bit DMA output (auto-init).
    pub const DMA16_OUT_AUTO: u8 = 0xB6;
    /// 16-bit DMA input (auto-init).
    pub const DMA16_IN_AUTO: u8 = 0xBE;
    /// 8-bit DMA output (auto-init).
    pub const DMA8_OUT_AUTO: u8 = 0xC6;
    /// Set sample rate (output).
    pub const SET_OUTPUT_RATE: u8 = 0x41;
    /// Set sample rate (input).
    pub const SET_INPUT_RATE: u8 = 0x42;
    /// Exit auto-init DMA.
    pub const EXIT_DMA: u8 = 0xDA;
    /// Pause DMA.
    pub const PAUSE_DMA: u8 = 0xD0;
    /// Continue DMA.
    pub const CONTINUE_DMA: u8 = 0xD4;
    /// Speaker on.
    pub const SPEAKER_ON: u8 = 0xD1;
    /// Speaker off.
    pub const SPEAKER_OFF: u8 = 0xD3;
}

// ── Mixer Register Addresses ───────────────────────────────────────────────

pub mod mixer_reg {
    /// Reset mixer to defaults.
    pub const RESET: u8 = 0x00;
    /// Master volume (left/right).
    pub const MASTER_VOL: u8 = 0x22;
    /// DAC volume.
    pub const DAC_VOL: u8 = 0x04;
    /// Line-in volume.
    pub const LINE_VOL: u8 = 0x2E;
    /// Microphone volume.
    pub const MIC_VOL: u8 = 0x0A;
    /// Output gain.
    pub const OUT_GAIN: u8 = 0x3C;
    /// IRQ select.
    pub const IRQ_SEL: u8 = 0x80;
    /// DMA channel select.
    pub const DMA_SEL: u8 = 0x81;
}

// ── PCM Format ─────────────────────────────────────────────────────────────

/// PCM audio format for DMA transfer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PcmFormat {
    /// 8-bit unsigned PCM.
    Unsigned8,
    /// 16-bit signed PCM.
    Signed16,
}

// ── I/O Port Helpers ───────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod io {
    #[inline]
    pub unsafe fn outb(port: u16, val: u8) {
        // SAFETY: caller guarantees port is valid SB16 I/O.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nostack, nomem, preserves_flags),
            );
        }
    }

    #[inline]
    pub unsafe fn inb(port: u16) -> u8 {
        let val: u8;
        // SAFETY: caller guarantees port is valid SB16 I/O.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") val,
                options(nostack, nomem, preserves_flags),
            );
        }
        val
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod io {
    pub unsafe fn outb(_port: u16, _val: u8) {}
    pub unsafe fn inb(_port: u16) -> u8 {
        0
    }
}

// ── SB16 Driver ────────────────────────────────────────────────────────────

/// Sound Blaster 16 driver.
pub struct Sb16 {
    /// I/O base address (default 0x220).
    base: u16,
    /// IRQ number.
    irq: u8,
    /// 8-bit DMA channel.
    dma8: u8,
    /// 16-bit DMA channel.
    dma16: u8,
    /// DSP version (major.minor).
    dsp_version: (u8, u8),
    /// Initialized flag.
    initialized: bool,
}

impl Sb16 {
    /// Create an SB16 driver with the given base, IRQ, and DMA channels.
    pub fn new(base: u16, irq: u8, dma8: u8, dma16: u8) -> Self {
        Self {
            base,
            irq,
            dma8,
            dma16,
            dsp_version: (0, 0),
            initialized: false,
        }
    }

    /// Read an I/O port relative to base.
    fn inb(&self, offset: u16) -> u8 {
        // SAFETY: base + offset is a valid SB16 I/O port.
        unsafe { io::inb(self.base + offset) }
    }

    /// Write an I/O port relative to base.
    fn outb(&self, offset: u16, val: u8) {
        // SAFETY: base + offset is a valid SB16 I/O port.
        unsafe { io::outb(self.base + offset, val) }
    }

    /// Reset the DSP.
    fn dsp_reset(&self) -> Result<()> {
        self.outb(DSP_RESET, 1);
        // Short delay (in real hardware, >= 3 µs).
        for _ in 0..100 {
            let _ = self.inb(DSP_READ_STATUS);
        }
        self.outb(DSP_RESET, 0);
        // Wait for ready byte (0xAA).
        for _ in 0..1000 {
            if self.inb(DSP_READ_STATUS) & 0x80 != 0 {
                let b = self.inb(DSP_READ);
                if b == 0xAA {
                    return Ok(());
                }
            }
        }
        Err(Error::IoError)
    }

    /// Write a byte to the DSP command port (polls busy).
    fn dsp_write(&self, val: u8) -> Result<()> {
        for _ in 0..10_000 {
            if self.inb(DSP_WRITE_STATUS) & 0x80 == 0 {
                self.outb(DSP_WRITE, val);
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Read a byte from the DSP (polls data available).
    fn dsp_read(&self) -> Result<u8> {
        for _ in 0..10_000 {
            if self.inb(DSP_READ_STATUS) & 0x80 != 0 {
                return Ok(self.inb(DSP_READ));
            }
        }
        Err(Error::Busy)
    }

    /// Write a mixer register.
    fn mixer_write(&self, reg: u8, val: u8) {
        self.outb(MIXER_ADDR, reg);
        self.outb(MIXER_DATA, val);
    }

    /// Read a mixer register.
    fn mixer_read(&self, reg: u8) -> u8 {
        self.outb(MIXER_ADDR, reg);
        self.inb(MIXER_DATA)
    }

    /// Initialize the SB16 card.
    pub fn init(&mut self) -> Result<()> {
        self.dsp_reset()?;

        // Read DSP version.
        self.dsp_write(dsp_cmd::VERSION)?;
        let major = self.dsp_read()?;
        let minor = self.dsp_read()?;
        self.dsp_version = (major, minor);

        // SB16 has DSP version >= 4.x.
        if major < 4 {
            return Err(Error::NotFound);
        }

        // Configure mixer: set IRQ and DMA.
        let irq_bit = match self.irq {
            2 => 0x01,
            5 => 0x02,
            7 => 0x04,
            10 => 0x08,
            _ => return Err(Error::InvalidArgument),
        };
        self.mixer_write(mixer_reg::IRQ_SEL, irq_bit);

        let dma8_bit = 1u8 << self.dma8;
        let dma16_bit = 1u8 << (self.dma16 - 4); // 16-bit channels 5-7
        self.mixer_write(mixer_reg::DMA_SEL, dma8_bit | (dma16_bit << 4));

        // Set default volumes.
        self.mixer_write(mixer_reg::MASTER_VOL, 0xCC); // ~80%
        self.mixer_write(mixer_reg::DAC_VOL, 0xCC);

        // Speaker on.
        self.dsp_write(dsp_cmd::SPEAKER_ON)?;

        self.initialized = true;
        Ok(())
    }

    /// Set the playback sample rate.
    pub fn set_sample_rate(&self, rate: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.dsp_write(dsp_cmd::SET_OUTPUT_RATE)?;
        self.dsp_write((rate >> 8) as u8)?;
        self.dsp_write(rate as u8)?;
        Ok(())
    }

    /// Start 16-bit auto-init DMA playback.
    pub fn start_playback16(&self, len_samples: u16) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.dsp_write(dsp_cmd::DMA16_OUT_AUTO)?;
        // Mode byte: stereo, signed 16-bit.
        self.dsp_write(0x30)?;
        let count = len_samples.saturating_sub(1);
        self.dsp_write(count as u8)?;
        self.dsp_write((count >> 8) as u8)?;
        Ok(())
    }

    /// Pause DMA transfer.
    pub fn pause(&self) -> Result<()> {
        self.dsp_write(dsp_cmd::PAUSE_DMA)
    }

    /// Resume DMA transfer.
    pub fn resume(&self) -> Result<()> {
        self.dsp_write(dsp_cmd::CONTINUE_DMA)
    }

    /// Stop DMA transfer.
    pub fn stop(&self) -> Result<()> {
        self.dsp_write(dsp_cmd::EXIT_DMA)
    }

    /// Set master volume (0-255 maps to 0-100%).
    pub fn set_master_volume(&self, vol: u8) {
        let v = (vol & 0xF0) | ((vol & 0xF0) >> 4);
        self.mixer_write(mixer_reg::MASTER_VOL, v);
    }

    /// Return the DSP version as (major, minor).
    pub fn dsp_version(&self) -> (u8, u8) {
        self.dsp_version
    }

    /// Read the current IRQ selector from the mixer.
    pub fn irq_select(&self) -> u8 {
        self.mixer_read(mixer_reg::IRQ_SEL)
    }
}

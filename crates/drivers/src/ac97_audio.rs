// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AC'97 audio controller driver.
//!
//! Implements the Intel ICH AC'97 (Audio Codec '97) audio specification used
//! in PCI audio devices from the late 1990s through mid-2000s. Supports PCM
//! playback and recording via DMA buffer descriptors, and AC'97 codec register
//! access via the native audio mixer interface.

use oncrix_lib::{Error, Result};

/// PCI vendor/device IDs for common AC'97 controllers.
pub const AC97_VENDOR_INTEL: u16 = 0x8086;
pub const AC97_DEVICE_ICH: u16 = 0x2415; // ICH / 82801AA
pub const AC97_DEVICE_ICH0: u16 = 0x2425; // ICH0 / 82801AB
pub const AC97_DEVICE_ICH2: u16 = 0x2445; // ICH2
pub const AC97_DEVICE_ICH3: u16 = 0x2485; // ICH3
pub const AC97_DEVICE_ICH4: u16 = 0x24C5; // ICH4
pub const AC97_DEVICE_ICH5: u16 = 0x24D5; // ICH5
pub const AC97_DEVICE_ICH6: u16 = 0x266E; // ICH6
pub const AC97_DEVICE_ICH7: u16 = 0x27DE; // ICH7

/// Native Audio Mixer (NAM) register offsets — accessed via BAR0.
const NAM_RESET: u16 = 0x00;
const NAM_MASTER_VOL: u16 = 0x02;
const NAM_HEADPHONE_VOL: u16 = 0x04;
const NAM_MONO_VOL: u16 = 0x06;
const NAM_PCM_OUT_VOL: u16 = 0x18;
const NAM_RECORD_SEL: u16 = 0x1A;
const NAM_RECORD_GAIN: u16 = 0x1C;
const NAM_SAMPLE_RATE_PCM_OUT: u16 = 0x2C;
const NAM_SAMPLE_RATE_PCM_IN: u16 = 0x32;
const NAM_EXTENDED_AUDIO_ID: u16 = 0x28;
const NAM_EXTENDED_AUDIO_CTRL: u16 = 0x2A;

/// Native Audio Bus Master (NABM) register offsets — accessed via BAR1.
/// PCM-out channel uses base offset 0x10, PCM-in 0x00.
const NABM_PCM_IN_BDBAR: u16 = 0x00; // Buffer Descriptor Base Address
const NABM_PCM_IN_CIV: u16 = 0x04; // Current Index Value
const NABM_PCM_IN_LVI: u16 = 0x05; // Last Valid Index
const NABM_PCM_IN_SR: u16 = 0x06; // Status Register
const NABM_PCM_IN_PICB: u16 = 0x08; // Position in Current Buffer
const NABM_PCM_IN_PIV: u16 = 0x0A; // Prefetched Index Value
const NABM_PCM_IN_CR: u16 = 0x0B; // Control Register

const NABM_PCM_OUT_BDBAR: u16 = 0x10;
const NABM_PCM_OUT_CIV: u16 = 0x14;
const NABM_PCM_OUT_LVI: u16 = 0x15;
const NABM_PCM_OUT_SR: u16 = 0x16;
const NABM_PCM_OUT_PICB: u16 = 0x18;
const NABM_PCM_OUT_PIV: u16 = 0x1A;
const NABM_PCM_OUT_CR: u16 = 0x1B;

const NABM_GLOB_CNT: u16 = 0x2C; // Global Control
const NABM_GLOB_STA: u16 = 0x30; // Global Status

/// Control Register bits.
const CR_DMA_EN: u8 = 1 << 0; // DMA engine run
const CR_RESET: u8 = 1 << 1; // Reset channel
const CR_LVBIE: u8 = 1 << 2; // Last valid buffer interrupt enable
const CR_FEIE: u8 = 1 << 3; // FIFO error interrupt enable
const CR_IOCE: u8 = 1 << 4; // Interrupt on completion enable

/// Status Register bits.
const SR_DCH: u16 = 1 << 0; // DMA controller halted
const SR_CELV: u16 = 1 << 1; // Current equals last valid
const SR_LVBCI: u16 = 1 << 2; // Last valid buffer completion interrupt
const SR_BCIS: u16 = 1 << 3; // Buffer completion interrupt status
const SR_FIFOE: u16 = 1 << 4; // FIFO error

/// Global Control bits.
const GCNT_GIE: u32 = 1 << 0; // GPI interrupt enable
const GCNT_COLD_RST: u32 = 1 << 1; // Cold reset (0 = in reset, 1 = running)
const GCNT_WARM_RST: u32 = 1 << 2; // Warm reset

/// Extended Audio ID bits (VRA = Variable Rate Audio).
const EAID_VRA: u16 = 1 << 0;

/// Maximum number of Buffer Descriptor List (BDL) entries.
const BDL_ENTRIES: usize = 32;

/// Buffer Descriptor List entry in `#[repr(C)]` for DMA.
#[repr(C)]
pub struct BdlEntry {
    /// Physical address of the audio buffer.
    pub buf_addr: u32,
    /// Number of samples in the buffer (lower 16 bits).
    pub buf_len: u16,
    /// Control flags.
    pub flags: u16,
}

/// BDL entry flag: interrupt on completion of this buffer.
const BDL_FLAG_IOC: u16 = 1 << 15;
/// BDL entry flag: end-of-list (last valid buffer).
const BDL_FLAG_EOL: u16 = 1 << 14;

impl BdlEntry {
    /// Create a zeroed BDL entry.
    pub const fn new() -> Self {
        Self {
            buf_addr: 0,
            buf_len: 0,
            flags: 0,
        }
    }
}

impl Default for BdlEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Audio sample rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleRate {
    /// 8000 Hz (telephone quality).
    Hz8000 = 8000,
    /// 11025 Hz (quarter CD quality).
    Hz11025 = 11025,
    /// 22050 Hz (half CD quality).
    Hz22050 = 22050,
    /// 44100 Hz (CD quality).
    Hz44100 = 44100,
    /// 48000 Hz (DAT quality; AC'97 native rate).
    Hz48000 = 48000,
}

/// AC'97 driver state.
pub struct Ac97Audio {
    /// Base I/O port for the NAM (mixer) registers (BAR0).
    nam_base: u16,
    /// Base I/O port for the NABM (bus master) registers (BAR1).
    nabm_base: u16,
    /// Current playback sample rate.
    playback_rate: SampleRate,
    /// Variable Rate Audio is supported by the codec.
    vra_capable: bool,
    /// DMA is running on the PCM-out channel.
    playback_running: bool,
}

impl Ac97Audio {
    /// Create a new AC'97 driver.
    ///
    /// # Arguments
    /// - `nam_base`: I/O base port for the NAM mixer registers (PCI BAR0)
    /// - `nabm_base`: I/O base port for the NABM bus master registers (PCI BAR1)
    pub fn new(nam_base: u16, nabm_base: u16) -> Self {
        Self {
            nam_base,
            nabm_base,
            playback_rate: SampleRate::Hz48000,
            vra_capable: false,
            playback_running: false,
        }
    }

    /// Initialize the AC'97 controller.
    pub fn init(&mut self) -> Result<()> {
        self.global_reset()?;
        self.codec_ready()?;
        self.reset_codec()?;
        self.detect_vra();
        self.set_master_volume(0)?;
        self.set_pcm_volume(0)?;
        Ok(())
    }

    /// Perform a cold reset via the Global Control register.
    fn global_reset(&mut self) -> Result<()> {
        // Clear COLD_RST to assert cold reset.
        self.write_nabm32(NABM_GLOB_CNT, 0);
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
        // Release reset and wait for codec ready.
        self.write_nabm32(NABM_GLOB_CNT, GCNT_COLD_RST);
        Ok(())
    }

    /// Wait until the codec is ready (bit 8 in GLOB_STA).
    fn codec_ready(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            let sta = self.read_nabm32(NABM_GLOB_STA);
            if (sta & 0x0000_0100) != 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 200_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Reset the codec by writing to NAM reset register.
    fn reset_codec(&mut self) -> Result<()> {
        self.write_nam16(NAM_RESET, 0);
        Ok(())
    }

    /// Detect Variable Rate Audio capability and enable it if present.
    fn detect_vra(&mut self) {
        let eaid = self.read_nam16(NAM_EXTENDED_AUDIO_ID);
        if (eaid & EAID_VRA) != 0 {
            self.vra_capable = true;
            // Enable VRA in the extended audio control register.
            let ctrl = self.read_nam16(NAM_EXTENDED_AUDIO_CTRL);
            self.write_nam16(NAM_EXTENDED_AUDIO_CTRL, ctrl | EAID_VRA);
        }
    }

    /// Set master output volume (0 = max, 63 = min/mute).
    pub fn set_master_volume(&mut self, attenuation: u8) -> Result<()> {
        let vol = ((attenuation as u16 & 0x3F) << 8) | (attenuation as u16 & 0x3F);
        self.write_nam16(NAM_MASTER_VOL, vol);
        Ok(())
    }

    /// Set PCM output volume (0 = max, 31 = min/mute).
    pub fn set_pcm_volume(&mut self, attenuation: u8) -> Result<()> {
        let vol = ((attenuation as u16 & 0x1F) << 8) | (attenuation as u16 & 0x1F);
        self.write_nam16(NAM_PCM_OUT_VOL, vol);
        Ok(())
    }

    /// Set the PCM output sample rate.
    pub fn set_sample_rate(&mut self, rate: SampleRate) -> Result<()> {
        if !self.vra_capable && rate != SampleRate::Hz48000 {
            return Err(Error::NotImplemented);
        }
        self.write_nam16(NAM_SAMPLE_RATE_PCM_OUT, rate as u16);
        self.playback_rate = rate;
        Ok(())
    }

    /// Start PCM-out DMA playback on the previously configured BDL.
    pub fn start_playback(&mut self) -> Result<()> {
        if self.playback_running {
            return Err(Error::Busy);
        }
        let cr = self.read_nabm8(NABM_PCM_OUT_CR);
        self.write_nabm8(NABM_PCM_OUT_CR, cr | CR_DMA_EN | CR_IOCE | CR_LVBIE);
        self.playback_running = true;
        Ok(())
    }

    /// Stop PCM-out DMA playback.
    pub fn stop_playback(&mut self) -> Result<()> {
        let cr = self.read_nabm8(NABM_PCM_OUT_CR);
        self.write_nabm8(NABM_PCM_OUT_CR, cr & !CR_DMA_EN);
        self.playback_running = false;
        Ok(())
    }

    /// Read the current index in the PCM-out BDL.
    pub fn current_buffer_index(&self) -> u8 {
        self.read_nabm8(NABM_PCM_OUT_CIV)
    }

    /// Handle a PCM-out interrupt; returns the status register.
    pub fn handle_pcm_out_interrupt(&mut self) -> u16 {
        let sr = self.read_nabm16(NABM_PCM_OUT_SR);
        // Write 1 to clear interrupt bits.
        self.write_nabm16(NABM_PCM_OUT_SR, sr & (SR_LVBCI | SR_BCIS | SR_FIFOE));
        sr
    }

    // --- NAM I/O port helpers ---

    fn read_nam16(&self, offset: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u16;
            // SAFETY: nam_base is a valid PCI BAR0 I/O port for AC'97 NAM;
            // offset selects a 16-bit aligned register within the NAM space.
            unsafe {
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") self.nam_base + offset,
                    out("ax") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write_nam16(&mut self, offset: u16, val: u16) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: nam_base is a valid PCI BAR0 I/O port; volatile PIO write to hardware.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.nam_base + offset,
                in("ax") val,
                options(nomem, nostack)
            );
        }
    }

    // --- NABM I/O port helpers ---

    fn read_nabm8(&self, offset: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: nabm_base is a valid PCI BAR1 I/O port for AC'97 NABM.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") self.nabm_base + offset,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn read_nabm16(&self, offset: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u16;
            // SAFETY: nabm_base is a valid PCI BAR1 NABM port.
            unsafe {
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") self.nabm_base + offset,
                    out("ax") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn read_nabm32(&self, offset: u16) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u32;
            // SAFETY: nabm_base is a valid PCI BAR1 NABM port.
            unsafe {
                core::arch::asm!(
                    "in eax, dx",
                    in("dx") self.nabm_base + offset,
                    out("eax") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write_nabm8(&mut self, offset: u16, val: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: nabm_base is a valid PCI BAR1 NABM port; volatile PIO write.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.nabm_base + offset,
                in("al") val,
                options(nomem, nostack)
            );
        }
    }

    fn write_nabm16(&mut self, offset: u16, val: u16) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: nabm_base is a valid PCI BAR1 NABM port; volatile PIO write.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.nabm_base + offset,
                in("ax") val,
                options(nomem, nostack)
            );
        }
    }

    fn write_nabm32(&mut self, offset: u16, val: u32) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: nabm_base is a valid PCI BAR1 NABM port; volatile PIO write.
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") self.nabm_base + offset,
                in("eax") val,
                options(nomem, nostack)
            );
        }
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AMD GPU core driver framework.
//!
//! Provides the foundational abstractions for AMD Radeon graphics controllers
//! (GCN architecture and later). Handles MMIO register access, command
//! processor ring buffer management, and basic display output configuration.

use oncrix_lib::{Error, Result};

/// PCI vendor ID for AMD.
pub const AMD_VENDOR_ID: u16 = 0x1002;

/// Common AMD GPU device IDs (Polaris/Vega/RDNA).
pub const DEVICE_RX470: u16 = 0x67DF;
pub const DEVICE_RX480: u16 = 0x67DF;
pub const DEVICE_VEGA10: u16 = 0x6860;
pub const DEVICE_NAVI10: u16 = 0x731F;

/// MMIO register offsets (GCN architecture, relative to BAR5 or MMIO base).
const REG_GRBM_STATUS: u32 = 0x8010;
const REG_CP_ME_CNTL: u32 = 0xC200;
const REG_CP_RB0_BASE: u32 = 0xC100;
const REG_CP_RB0_RPTR_ADDR: u32 = 0xC10C;
const REG_CP_RB0_WPTR: u32 = 0xC114;
const REG_CP_RB0_CNTL: u32 = 0xC104;
const REG_IH_RB_BASE: u32 = 0x3B04;
const REG_IH_RB_WPTR: u32 = 0x3B0C;
const REG_IH_RB_RPTR: u32 = 0x3B08;
const REG_IH_DOORBELL_RPTR: u32 = 0x3B10;
const REG_IH_CNTL: u32 = 0x3B00;
const REG_SDMA0_F32_CNTL: u32 = 0xD800;
const REG_SDMA0_RB_BASE: u32 = 0xD804;
const REG_SDMA0_RB_RPTR: u32 = 0xD808;
const REG_SDMA0_RB_WPTR: u32 = 0xD80C;
const REG_SDMA0_RB_CNTL: u32 = 0xD800;

/// GRBM status bits.
const GRBM_GUI_ACTIVE: u32 = 1 << 31;

/// CP (Command Processor) ME control.
const CP_ME_HALT: u32 = 1 << 28;
const CP_PFP_HALT: u32 = 1 << 26;

/// Ring buffer control: ring_size = 2^(RB_BUFSZ) DWORDs.
const RB_BUFSZ_64K: u32 = 14; // 2^14 = 16384 DWORDs = 64 KiB

/// Interrupt handler ring control.
const IH_RB_ENABLE: u32 = 1 << 0;
const IH_MC_SWAP_NONE: u32 = 0 << 1;

/// Maximum command ring sizes.
const GFX_RING_SIZE: usize = 64 * 1024; // 64 KiB
const SDMA_RING_SIZE: usize = 4 * 1024; // 4 KiB

/// Command packet header for AMDGPU PKT3 packets.
pub const fn pkt3_header(opcode: u8, count: u16, shdr_en: bool) -> u32 {
    let shdr = if shdr_en { 1u32 << 28 } else { 0 };
    0xC000_0000 | shdr | ((opcode as u32) << 8) | (count as u32 & 0x3FFF)
}

/// Common PM4 opcodes.
pub mod pm4_opcode {
    pub const NOP: u8 = 0x10;
    pub const SET_CONTEXT_REG: u8 = 0x69;
    pub const SET_CONFIG_REG: u8 = 0x68;
    pub const WRITE_DATA: u8 = 0x37;
    pub const WAIT_REG_MEM: u8 = 0x3C;
    pub const EVENT_WRITE: u8 = 0x46;
    pub const DMA_DATA: u8 = 0x50;
    pub const RELEASE_MEM: u8 = 0x49;
}

/// Frame buffer descriptor.
#[derive(Clone, Copy, Debug)]
pub struct AmdFramebuffer {
    /// GPU virtual address of the framebuffer.
    pub gpu_addr: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pitch (bytes per row).
    pub pitch: u32,
    /// Bits per pixel.
    pub bpp: u8,
}

/// AMD GPU driver state.
pub struct AmdgpuCore {
    /// Virtual address of the MMIO register region (BAR5 on GCN).
    mmio_base: usize,
    /// Virtual address of the PCI aperture (VRAM CPU-visible window, BAR0).
    vram_base: usize,
    /// Size of VRAM in bytes.
    vram_size: u64,
    /// GFX ring write pointer.
    gfx_ring_wptr: usize,
    /// GFX ring read pointer (from hardware).
    gfx_ring_rptr: usize,
    /// Current framebuffer configuration.
    fb: Option<AmdFramebuffer>,
    /// Hardware is initialized.
    initialized: bool,
}

impl AmdgpuCore {
    /// Create a new AMD GPU driver.
    ///
    /// # Arguments
    /// - `mmio_base`: virtual address of the MMIO register region (BAR5)
    /// - `vram_base`: virtual address of the VRAM aperture (BAR0)
    /// - `vram_size`: size of VRAM in bytes
    pub fn new(mmio_base: usize, vram_base: usize, vram_size: u64) -> Self {
        Self {
            mmio_base,
            vram_base,
            vram_size,
            gfx_ring_wptr: 0,
            gfx_ring_rptr: 0,
            fb: None,
            initialized: false,
        }
    }

    /// Initialize the GPU.
    pub fn init(&mut self) -> Result<()> {
        self.halt_cp();
        self.setup_gfx_ring()?;
        self.resume_cp();
        self.initialized = true;
        Ok(())
    }

    /// Halt the Command Processor.
    fn halt_cp(&mut self) {
        let cntl = self.read32(REG_CP_ME_CNTL);
        self.write32(REG_CP_ME_CNTL, cntl | CP_ME_HALT | CP_PFP_HALT);
    }

    /// Resume the Command Processor.
    fn resume_cp(&mut self) {
        let cntl = self.read32(REG_CP_ME_CNTL);
        self.write32(REG_CP_ME_CNTL, cntl & !(CP_ME_HALT | CP_PFP_HALT));
    }

    /// Configure the GFX ring buffer.
    fn setup_gfx_ring(&mut self) -> Result<()> {
        // In a real driver, the ring buffer is a DMA-coherent allocation.
        // Here we configure placeholder values.
        self.write32(REG_CP_RB0_BASE, 0); // Physical address / 4 bytes.
        self.write32(REG_CP_RB0_RPTR_ADDR, 0); // Read-ptr writeback address.
        self.write32(REG_CP_RB0_WPTR, 0);
        self.write32(REG_CP_RB0_CNTL, RB_BUFSZ_64K);
        self.gfx_ring_wptr = 0;
        self.gfx_ring_rptr = 0;
        Ok(())
    }

    /// Submit a NOP packet to the GFX ring (basic test).
    pub fn submit_nop(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let hdr = pkt3_header(pm4_opcode::NOP, 0, false);
        self.ring_emit(hdr)?;
        self.ring_commit();
        Ok(())
    }

    /// Write a dword to the GFX ring buffer.
    fn ring_emit(&mut self, _dword: u32) -> Result<()> {
        let next = (self.gfx_ring_wptr + 4) % GFX_RING_SIZE;
        if next == self.gfx_ring_rptr {
            return Err(Error::Busy);
        }
        // In a real driver, write to mapped ring buffer memory here.
        self.gfx_ring_wptr = next;
        Ok(())
    }

    /// Advance the HW write pointer to trigger execution.
    fn ring_commit(&mut self) {
        self.write32(REG_CP_RB0_WPTR, (self.gfx_ring_wptr >> 2) as u32);
    }

    /// Check whether the GPU engine is busy.
    pub fn is_busy(&self) -> bool {
        (self.read32(REG_GRBM_STATUS) & GRBM_GUI_ACTIVE) != 0
    }

    /// Configure the primary scanout framebuffer.
    pub fn set_framebuffer(&mut self, fb: AmdFramebuffer) -> Result<()> {
        if fb.width == 0 || fb.height == 0 {
            return Err(Error::InvalidArgument);
        }
        self.fb = Some(fb);
        Ok(())
    }

    /// Return the current framebuffer.
    pub fn framebuffer(&self) -> Option<AmdFramebuffer> {
        self.fb
    }

    /// Return the VRAM size.
    pub fn vram_size(&self) -> u64 {
        self.vram_size
    }

    // --- MMIO helpers ---

    fn read32(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as usize) as *const u32;
        // SAFETY: mmio_base is a valid AMD GPU MMIO region (BAR5); offsets
        // are 4-byte aligned registers within the GCN register space.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Volatile write to a hardware register in the AMD GPU MMIO space.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

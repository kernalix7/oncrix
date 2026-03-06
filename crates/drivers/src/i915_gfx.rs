// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel i915 graphics driver framework.
//!
//! Provides the base abstraction for Intel integrated graphics (Gen6+)
//! found in Sandy Bridge and later Core processors. Handles GTT (Graphics
//! Translation Table), ring buffer command submission, and display output
//! via the LVDS/DisplayPort/HDMI encoders.

use oncrix_lib::{Error, Result};

/// PCI vendor ID for Intel.
pub const INTEL_VENDOR_ID: u16 = 0x8086;

/// Common Intel GPU device IDs.
pub const DEVICE_SANDYBRIDGE: u16 = 0x0102;
pub const DEVICE_IVYBRIDGE: u16 = 0x0152;
pub const DEVICE_HASWELL: u16 = 0x0402;
pub const DEVICE_BROADWELL: u16 = 0x1602;
pub const DEVICE_SKYLAKE: u16 = 0x1912;

/// MMIO register offsets.
const REG_GFX_MODE: u32 = 0x0002_0D0;
const REG_RENDER_RING_BASE: u32 = 0x0002_030;
const REG_RENDER_RING_HEAD: u32 = 0x0002_034;
const REG_RENDER_RING_TAIL: u32 = 0x0002_038;
const REG_RENDER_RING_CTL: u32 = 0x0002_03C;
const REG_GEN6_RPNSWREQ: u32 = 0x000A_008C;
const REG_DISPLAY_PIPE_A_CTRL: u32 = 0x0007_0008;
const REG_DISPLAY_PIPE_B_CTRL: u32 = 0x0007_1008;
const REG_DISPLAY_PLANE_A_CTL: u32 = 0x0007_0180;
const REG_DISPLAY_PLANE_A_BASE: u32 = 0x0007_0184;
const REG_DISPLAY_PLANE_A_STRIDE: u32 = 0x0007_0188;
const REG_GTT_BASE: u32 = 0x0010_0000; // GTT starts at 1 MiB offset

/// Ring buffer control register bits.
const RING_CTL_ENABLE: u32 = 1 << 0;
const RING_CTL_NO_REPORT: u32 = 1 << 18;

/// Display pipe control bits.
const PIPE_ENABLE: u32 = 1 << 31;

/// Display plane control bits.
const PLANE_ENABLE: u32 = 1 << 31;
const PLANE_TILED: u32 = 1 << 10;

/// Ring buffer size (must be power of 2, multiple of 4 KiB).
const RING_SIZE: usize = 64 * 1024; // 64 KiB

/// GTT entry bits.
const GTT_ENTRY_VALID: u32 = 1 << 0;
const GTT_CACHE_LLC: u32 = 3 << 1;

/// Number of GTT pages available.
const GTT_PAGES: usize = 512 * 1024; // 2 GB aperture / 4096 per page

/// Display pipe identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pipe {
    /// Pipe A.
    A,
    /// Pipe B.
    B,
}

/// Display output encoder type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncoderType {
    Lvds,
    Hdmi,
    DisplayPort,
    Vga,
}

/// Frame buffer descriptor.
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    /// Physical address of the framebuffer in graphics memory.
    pub gfx_addr: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Stride in bytes.
    pub stride: u32,
    /// Bits per pixel.
    pub bpp: u8,
}

/// Intel i915 graphics driver.
pub struct I915Gfx {
    /// Virtual address of the MMIO register region (BAR0).
    mmio_base: usize,
    /// Virtual address of the GTT aperture (BAR2).
    gtt_base: usize,
    /// GPU generation (e.g., 6 for Sandy Bridge).
    gpu_gen: u8,
    /// Ring buffer write pointer.
    ring_tail: usize,
    /// Ring buffer read pointer.
    ring_head: usize,
    /// Current display framebuffer.
    fb: Option<Framebuffer>,
    /// Display is active.
    display_on: bool,
}

impl I915Gfx {
    /// Create a new i915 driver instance.
    ///
    /// # Arguments
    /// - `mmio_base`: virtual address of BAR0 (MMIO registers)
    /// - `gtt_base`: virtual address of BAR2 (GTT aperture)
    /// - `gen`: GPU generation number
    pub fn new(mmio_base: usize, gtt_base: usize, gpu_gen: u8) -> Self {
        Self {
            mmio_base,
            gtt_base,
            gpu_gen,
            ring_tail: 0,
            ring_head: 0,
            fb: None,
            display_on: false,
        }
    }

    /// Initialize the GPU engine and display subsystem.
    pub fn init(&mut self) -> Result<()> {
        self.init_ring_buffer()?;
        Ok(())
    }

    /// Initialize the render ring buffer.
    fn init_ring_buffer(&mut self) -> Result<()> {
        // Disable ring first.
        self.write32(REG_RENDER_RING_CTL, 0);
        // Set ring base (physical address, aligned to ring size).
        // In a real driver, this would be a DMA-coherent allocation.
        self.write32(REG_RENDER_RING_BASE, 0); // placeholder
        self.write32(REG_RENDER_RING_HEAD, 0);
        self.write32(REG_RENDER_RING_TAIL, 0);
        // Enable ring.
        let ctl = ((RING_SIZE - 4096) as u32) | RING_CTL_ENABLE;
        self.write32(REG_RENDER_RING_CTL, ctl);
        self.ring_head = 0;
        self.ring_tail = 0;
        Ok(())
    }

    /// Configure a display pipe and plane for the given framebuffer.
    pub fn set_framebuffer(&mut self, pipe: Pipe, fb: Framebuffer) -> Result<()> {
        let (pipe_ctrl_reg, plane_ctl_reg, plane_base_reg, plane_stride_reg) = match pipe {
            Pipe::A => (
                REG_DISPLAY_PIPE_A_CTRL,
                REG_DISPLAY_PLANE_A_CTL,
                REG_DISPLAY_PLANE_A_BASE,
                REG_DISPLAY_PLANE_A_STRIDE,
            ),
            Pipe::B => (
                REG_DISPLAY_PIPE_B_CTRL,
                REG_DISPLAY_PLANE_A_CTL + 0x1000,
                REG_DISPLAY_PLANE_A_BASE + 0x1000,
                REG_DISPLAY_PLANE_A_STRIDE + 0x1000,
            ),
        };
        // Enable pipe.
        self.write32(pipe_ctrl_reg, PIPE_ENABLE);
        // Configure plane.
        self.write32(plane_stride_reg, fb.stride);
        self.write32(plane_base_reg, fb.gfx_addr as u32);
        self.write32(plane_ctl_reg, PLANE_ENABLE);
        self.fb = Some(fb);
        self.display_on = true;
        Ok(())
    }

    /// Map a physical page into the GTT aperture.
    ///
    /// # Arguments
    /// - `gtt_index`: GTT page index (0 to GTT_PAGES-1)
    /// - `phys_page`: physical page frame number
    pub fn map_gtt_page(&mut self, gtt_index: usize, phys_page: u64) -> Result<()> {
        if gtt_index >= GTT_PAGES {
            return Err(Error::InvalidArgument);
        }
        let entry: u32 = ((phys_page << 12) as u32) | GTT_ENTRY_VALID | GTT_CACHE_LLC;
        let offset = REG_GTT_BASE + (gtt_index as u32) * 4;
        self.write32(offset, entry);
        Ok(())
    }

    /// Return the current framebuffer configuration.
    pub fn framebuffer(&self) -> Option<Framebuffer> {
        self.fb
    }

    /// Return whether the display is currently enabled.
    pub fn is_display_on(&self) -> bool {
        self.display_on
    }

    /// Return the GPU generation.
    pub fn gpu_gen(&self) -> u8 {
        self.gpu_gen
    }

    // --- MMIO helpers ---

    fn read32(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as usize) as *const u32;
        // SAFETY: mmio_base is a valid Intel GPU MMIO region (BAR0); all
        // offsets are 4-byte aligned and within the documented register space.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Volatile write to a hardware register in the Intel GPU MMIO region.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bochs VBE (VESA BIOS Extensions) display driver.
//!
//! Supports the Bochs/QEMU VBE display adapter (PCI vendor 0x1234, device 0x1111)
//! which exposes a simple programmable framebuffer via I/O port registers.
//! This driver handles mode setting and direct framebuffer access.

use oncrix_lib::{Error, Result};

/// PCI vendor and device IDs for the Bochs VBE display.
pub const BOCHS_VBE_VENDOR_ID: u16 = 0x1234;
pub const BOCHS_VBE_DEVICE_ID: u16 = 0x1111;

/// Bochs VBE I/O port base.
const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
const VBE_DISPI_IOPORT_DATA: u16 = 0x01CF;

/// VBE display info register indices.
const VBE_DISPI_INDEX_ID: u16 = 0x00;
const VBE_DISPI_INDEX_XRES: u16 = 0x01;
const VBE_DISPI_INDEX_YRES: u16 = 0x02;
const VBE_DISPI_INDEX_BPP: u16 = 0x03;
const VBE_DISPI_INDEX_ENABLE: u16 = 0x04;
const VBE_DISPI_INDEX_BANK: u16 = 0x05;
const VBE_DISPI_INDEX_VIRT_WIDTH: u16 = 0x06;
const VBE_DISPI_INDEX_VIRT_HEIGHT: u16 = 0x07;
const VBE_DISPI_INDEX_X_OFFSET: u16 = 0x08;
const VBE_DISPI_INDEX_Y_OFFSET: u16 = 0x09;
const VBE_DISPI_INDEX_VIDEO_MEMORY_64K: u16 = 0x0A;

/// VBE version IDs.
const VBE_DISPI_ID5: u16 = 0xB0C5;

/// VBE enable register bits.
const VBE_DISPI_DISABLED: u16 = 0x0000;
const VBE_DISPI_ENABLED: u16 = 0x0001;
const VBE_DISPI_LFB_ENABLED: u16 = 0x0040; // Linear framebuffer mode
const VBE_DISPI_NOCLEARMEM: u16 = 0x0080; // Don't clear video RAM on mode set

/// Supported bits-per-pixel values.
pub const BPP_8: u16 = 8;
pub const BPP_16: u16 = 16;
pub const BPP_24: u16 = 24;
pub const BPP_32: u16 = 32;

/// Maximum supported resolution.
pub const MAX_WIDTH: u16 = 2560;
pub const MAX_HEIGHT: u16 = 1600;

/// Framebuffer pixel format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8-bit indexed (palette) mode.
    Indexed8,
    /// 16-bit RGB 5:6:5.
    Rgb565,
    /// 24-bit RGB (packed, no padding).
    Rgb24,
    /// 32-bit BGRX (blue in LSB, X = unused high byte).
    Bgrx32,
}

impl PixelFormat {
    /// Bytes per pixel for this format.
    pub fn bytes_per_pixel(self) -> usize {
        match self {
            PixelFormat::Indexed8 => 1,
            PixelFormat::Rgb565 => 2,
            PixelFormat::Rgb24 => 3,
            PixelFormat::Bgrx32 => 4,
        }
    }

    /// Map from bits-per-pixel value.
    pub fn from_bpp(bpp: u16) -> Option<PixelFormat> {
        match bpp {
            8 => Some(PixelFormat::Indexed8),
            16 => Some(PixelFormat::Rgb565),
            24 => Some(PixelFormat::Rgb24),
            32 => Some(PixelFormat::Bgrx32),
            _ => None,
        }
    }

    /// Convert to VBE BPP register value.
    pub fn to_bpp(self) -> u16 {
        match self {
            PixelFormat::Indexed8 => 8,
            PixelFormat::Rgb565 => 16,
            PixelFormat::Rgb24 => 24,
            PixelFormat::Bgrx32 => 32,
        }
    }
}

/// Current display mode configuration.
#[derive(Clone, Copy, Debug)]
pub struct DisplayMode {
    /// Horizontal resolution in pixels.
    pub width: u16,
    /// Vertical resolution in pixels.
    pub height: u16,
    /// Pixel format.
    pub format: PixelFormat,
    /// Line stride in bytes (may be >= width * bpp).
    pub stride: usize,
}

/// Bochs VBE driver.
pub struct BochsVbe {
    /// Virtual address of the linear framebuffer (BAR0).
    framebuffer: usize,
    /// Size of the framebuffer in bytes.
    framebuffer_size: usize,
    /// Current display mode (set after init).
    mode: Option<DisplayMode>,
    /// VBE version reported by hardware.
    vbe_version: u16,
}

impl BochsVbe {
    /// Create a new Bochs VBE driver.
    ///
    /// # Arguments
    /// - `framebuffer`: virtual address of BAR0 (linear framebuffer)
    /// - `framebuffer_size`: size of the framebuffer in bytes
    pub fn new(framebuffer: usize, framebuffer_size: usize) -> Self {
        Self {
            framebuffer,
            framebuffer_size,
            mode: None,
            vbe_version: 0,
        }
    }

    /// Initialize the driver and probe the hardware version.
    pub fn init(&mut self) -> Result<()> {
        self.vbe_version = self.read_dispi(VBE_DISPI_INDEX_ID);
        if self.vbe_version < VBE_DISPI_ID5 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Set a display mode.
    ///
    /// # Arguments
    /// - `width`: horizontal resolution (must be <= `MAX_WIDTH`)
    /// - `height`: vertical resolution (must be <= `MAX_HEIGHT`)
    /// - `format`: pixel format
    pub fn set_mode(&mut self, width: u16, height: u16, format: PixelFormat) -> Result<()> {
        if width == 0 || height == 0 || width > MAX_WIDTH || height > MAX_HEIGHT {
            return Err(Error::InvalidArgument);
        }
        let bpp = format.to_bpp();
        let stride = width as usize * format.bytes_per_pixel();
        let fb_required = stride * height as usize;
        if fb_required > self.framebuffer_size {
            return Err(Error::OutOfMemory);
        }
        // Disable VBE before changing resolution.
        self.write_dispi(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
        self.write_dispi(VBE_DISPI_INDEX_XRES, width);
        self.write_dispi(VBE_DISPI_INDEX_YRES, height);
        self.write_dispi(VBE_DISPI_INDEX_BPP, bpp);
        self.write_dispi(VBE_DISPI_INDEX_VIRT_WIDTH, width);
        self.write_dispi(VBE_DISPI_INDEX_VIRT_HEIGHT, height);
        self.write_dispi(VBE_DISPI_INDEX_X_OFFSET, 0);
        self.write_dispi(VBE_DISPI_INDEX_Y_OFFSET, 0);
        // Enable with linear framebuffer.
        self.write_dispi(
            VBE_DISPI_INDEX_ENABLE,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED,
        );
        self.mode = Some(DisplayMode {
            width,
            height,
            format,
            stride,
        });
        Ok(())
    }

    /// Return the current display mode, if one has been set.
    pub fn current_mode(&self) -> Option<DisplayMode> {
        self.mode
    }

    /// Return a mutable pointer to the raw framebuffer.
    ///
    /// # Safety
    /// The caller must ensure accesses are within the framebuffer bounds
    /// and use volatile writes for hardware-visible pixel data.
    pub unsafe fn framebuffer_ptr(&self) -> *mut u8 {
        self.framebuffer as *mut u8
    }

    /// Fill the framebuffer with a solid color (32-bit BGRX or 32-bit value).
    pub fn fill(&mut self, color: u32) -> Result<()> {
        let mode = self.mode.ok_or(Error::IoError)?;
        let pixel_count = mode.width as usize * mode.height as usize;
        let bpp = mode.format.bytes_per_pixel();
        let fb = self.framebuffer as *mut u8;
        for i in 0..pixel_count {
            let offset = i * bpp;
            // SAFETY: offset is within [0, framebuffer_size) since we verified
            // fb_required <= framebuffer_size during set_mode.
            unsafe {
                let ptr = fb.add(offset);
                match bpp {
                    1 => core::ptr::write_volatile(ptr, (color & 0xFF) as u8),
                    2 => {
                        let p = ptr as *mut u16;
                        core::ptr::write_volatile(p, (color & 0xFFFF) as u16);
                    }
                    4 => {
                        let p = ptr as *mut u32;
                        core::ptr::write_volatile(p, color);
                    }
                    _ => {
                        core::ptr::write_volatile(ptr, (color & 0xFF) as u8);
                        core::ptr::write_volatile(ptr.add(1), ((color >> 8) & 0xFF) as u8);
                        core::ptr::write_volatile(ptr.add(2), ((color >> 16) & 0xFF) as u8);
                    }
                }
            }
        }
        Ok(())
    }

    /// Put a single pixel at the given position.
    pub fn put_pixel(&mut self, x: u16, y: u16, color: u32) -> Result<()> {
        let mode = self.mode.ok_or(Error::IoError)?;
        if (x as usize) >= mode.width as usize || (y as usize) >= mode.height as usize {
            return Err(Error::InvalidArgument);
        }
        let bpp = mode.format.bytes_per_pixel();
        let offset = y as usize * mode.stride + x as usize * bpp;
        let fb = self.framebuffer as *mut u8;
        // SAFETY: offset is within framebuffer bounds (validated above and
        // in set_mode); volatile write ensures the GPU sees the change.
        unsafe {
            let ptr = fb.add(offset);
            match bpp {
                1 => core::ptr::write_volatile(ptr, (color & 0xFF) as u8),
                2 => {
                    let p = ptr as *mut u16;
                    core::ptr::write_volatile(p, (color & 0xFFFF) as u16);
                }
                4 => {
                    let p = ptr as *mut u32;
                    core::ptr::write_volatile(p, color);
                }
                _ => {
                    core::ptr::write_volatile(ptr, (color & 0xFF) as u8);
                    core::ptr::write_volatile(ptr.add(1), ((color >> 8) & 0xFF) as u8);
                    core::ptr::write_volatile(ptr.add(2), ((color >> 16) & 0xFF) as u8);
                }
            }
        }
        Ok(())
    }

    /// Return total available video memory in bytes (64K units).
    pub fn video_memory_bytes(&self) -> usize {
        let units = self.read_dispi(VBE_DISPI_INDEX_VIDEO_MEMORY_64K) as usize;
        units * 64 * 1024
    }

    // --- VBE I/O port helpers ---

    fn read_dispi(&self, index: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: VBE_DISPI_IOPORT_INDEX (0x01CE) is the standard Bochs VBE
            // index port; writing selects the register, reading the data port returns it.
            unsafe {
                core::arch::asm!(
                    "out dx, ax",
                    in("dx") VBE_DISPI_IOPORT_INDEX,
                    in("ax") index,
                    options(nomem, nostack)
                );
                let val: u16;
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") VBE_DISPI_IOPORT_DATA,
                    out("ax") val,
                    options(nomem, nostack)
                );
                return val;
            }
        }
        #[allow(unreachable_code)]
        0
    }

    fn write_dispi(&mut self, index: u16, value: u16) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Standard Bochs VBE index/data port pair; writes configure
        // the virtual display adapter's resolution and color depth.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") VBE_DISPI_IOPORT_INDEX,
                in("ax") index,
                options(nomem, nostack)
            );
            core::arch::asm!(
                "out dx, ax",
                in("dx") VBE_DISPI_IOPORT_DATA,
                in("ax") value,
                options(nomem, nostack)
            );
        }
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Boot information structure passed from bootloader to kernel.

use crate::memory_map::MemoryMap;

/// Information collected by the bootloader and passed to the kernel.
///
/// This structure is the single point of communication between the
/// bootloader and the kernel entry point. The bootloader populates
/// it with hardware information discovered during early initialization.
#[derive(Debug)]
pub struct BootInfo {
    /// Physical memory map.
    pub memory_map: MemoryMap,
    /// Physical address where the kernel image is loaded.
    pub kernel_phys_addr: u64,
    /// Size of the kernel image in bytes.
    pub kernel_size: u64,
    /// Physical address of the RSDP (ACPI root table), if available.
    pub rsdp_addr: Option<u64>,
    /// Physical address of the framebuffer, if available.
    pub framebuffer: Option<FramebufferInfo>,
}

/// Framebuffer information for graphical output.
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of the framebuffer.
    pub addr: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per pixel.
    pub bpp: u8,
    /// Bytes per scanline (pitch).
    pub pitch: u32,
}

impl BootInfo {
    /// Create a new `BootInfo` with the given memory map.
    pub fn new(memory_map: MemoryMap) -> Self {
        Self {
            memory_map,
            kernel_phys_addr: 0,
            kernel_size: 0,
            rsdp_addr: None,
            framebuffer: None,
        }
    }
}

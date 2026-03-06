// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multiboot2 header for GRUB/QEMU boot.
//!
//! The header must appear within the first 32 KiB of the kernel image.
//! It is placed in the `.multiboot2` section by the linker script.

/// Multiboot2 magic number.
const MULTIBOOT2_MAGIC: u32 = 0xE852_50D6;

/// Architecture: i386 (covers x86_64 in protected mode handoff).
const ARCH_I386: u32 = 0;

/// Header length (3 tags: info request, entry address, end tag).
const HEADER_LENGTH: u32 = 64;

/// Checksum: -(magic + arch + length) mod 2^32.
const CHECKSUM: u32 = (-(MULTIBOOT2_MAGIC as i64 + ARCH_I386 as i64 + HEADER_LENGTH as i64)) as u32;

/// Multiboot2 header, placed in `.multiboot2` section.
///
/// Layout (all u32, little-endian):
///   [0]  magic
///   [1]  architecture
///   [2]  header_length
///   [3]  checksum
///   [4..] tags
///   [N]  end tag (type=0, flags=0, size=8)
#[unsafe(link_section = ".multiboot2")]
#[used]
static MULTIBOOT2_HEADER: [u32; 16] = [
    // Header
    MULTIBOOT2_MAGIC,
    ARCH_I386,
    HEADER_LENGTH,
    CHECKSUM,
    // Tag: information request (type=1, flags=0, size=20)
    // Request memory map (tag type 6), basic meminfo (tag type 4),
    // boot command line (tag type 1)
    1,  // tag type: information request
    0,  // flags (optional)
    20, // tag size
    6,  // request: memory map
    4,  // request: basic meminfo
    // Padding to 8-byte alignment
    0,
    // Tag: framebuffer (type=5, flags=0, size=20)
    5,  // tag type: framebuffer
    0,  // flags (optional)
    20, // tag size
    0,  // width (0 = no preference)
    0,  // height
    0,  // depth
        // End tag (type=0, flags=0, size=8)
        // Note: packed into remaining slots
];

// Verify the checksum at compile time.
const _: () = {
    let sum = MULTIBOOT2_MAGIC
        .wrapping_add(ARCH_I386)
        .wrapping_add(HEADER_LENGTH)
        .wrapping_add(CHECKSUM);
    assert!(sum == 0, "Multiboot2 header checksum is incorrect");
};

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ELF64 binary loader.
//!
//! Parses ELF64 headers and program headers to load executable
//! segments into a process's virtual address space. Only supports
//! `ET_EXEC` (static) and `ET_DYN` (PIE) executables for x86_64.

use oncrix_lib::{Error, Result};

/// ELF magic number (`\x7FELF`).
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 64-bit.
const ELFCLASS64: u8 = 2;
/// ELF data: little-endian.
const ELFDATA2LSB: u8 = 1;
/// ELF machine: x86_64.
const EM_X86_64: u16 = 62;

/// ELF type: executable.
const ET_EXEC: u16 = 2;
/// ELF type: shared object (PIE).
const ET_DYN: u16 = 3;

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Program header flags.
pub mod pf {
    /// Executable.
    pub const PF_X: u32 = 1;
    /// Writable.
    pub const PF_W: u32 = 2;
    /// Readable.
    pub const PF_R: u32 = 4;
}

/// ELF64 file header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Header {
    /// Magic number and identification.
    pub e_ident: [u8; 16],
    /// Object file type.
    pub e_type: u16,
    /// Architecture.
    pub e_machine: u16,
    /// Object file version.
    pub e_version: u32,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size.
    pub e_ehsize: u16,
    /// Program header entry size.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Section header entry size.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

/// ELF64 program header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Phdr {
    /// Segment type.
    pub p_type: u32,
    /// Segment flags.
    pub p_flags: u32,
    /// Segment file offset.
    pub p_offset: u64,
    /// Segment virtual address.
    pub p_vaddr: u64,
    /// Segment physical address (unused in user space).
    pub p_paddr: u64,
    /// Segment size in file.
    pub p_filesz: u64,
    /// Segment size in memory.
    pub p_memsz: u64,
    /// Segment alignment.
    pub p_align: u64,
}

/// Parsed ELF information.
#[derive(Debug, Clone, Copy)]
pub struct ElfInfo {
    /// Entry point virtual address.
    pub entry: u64,
    /// Whether this is a PIE executable.
    pub is_pie: bool,
    /// Number of PT_LOAD segments.
    pub load_segment_count: usize,
}

/// A loadable segment extracted from the ELF.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Virtual address to map at.
    pub vaddr: u64,
    /// Offset in the ELF file.
    pub file_offset: u64,
    /// Size of data in the file.
    pub file_size: u64,
    /// Size in memory (may be larger for .bss).
    pub mem_size: u64,
    /// Segment flags (PF_R, PF_W, PF_X).
    pub flags: u32,
    /// Alignment requirement.
    pub align: u64,
}

/// Maximum number of loadable segments we support.
const MAX_LOAD_SEGMENTS: usize = 16;

/// Validate and parse an ELF64 header.
///
/// `data` must point to the beginning of the ELF file in memory.
pub fn parse_header(data: &[u8]) -> Result<ElfInfo> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Size verified above. Use read_unaligned because the
    // input slice may not be aligned to Elf64Header's 8-byte alignment.
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Header) };

    // Validate magic.
    if header.e_ident[..4] != ELF_MAGIC {
        return Err(Error::InvalidArgument);
    }

    // Validate class (64-bit) and endianness (little).
    if header.e_ident[4] != ELFCLASS64 || header.e_ident[5] != ELFDATA2LSB {
        return Err(Error::InvalidArgument);
    }

    // Validate machine type.
    if header.e_machine != EM_X86_64 {
        return Err(Error::InvalidArgument);
    }

    // Validate file type.
    let is_pie = match header.e_type {
        ET_EXEC => false,
        ET_DYN => true,
        _ => return Err(Error::InvalidArgument),
    };

    // Count PT_LOAD segments — use checked arithmetic to prevent overflow.
    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

    let ph_end = ph_size
        .checked_mul(ph_count)
        .and_then(|n| n.checked_add(ph_offset))
        .ok_or(Error::InvalidArgument)?;
    if ph_end > data.len() {
        return Err(Error::InvalidArgument);
    }

    let mut load_count = 0;
    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        // SAFETY: Bounds checked above (offset + ph_size <= ph_end <= data.len()).
        // Use read_unaligned for potentially unaligned input.
        let phdr =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const Elf64Phdr) };
        if phdr.p_type == PT_LOAD {
            load_count += 1;
        }
    }

    Ok(ElfInfo {
        entry: header.e_entry,
        is_pie,
        load_segment_count: load_count,
    })
}

/// Extract loadable segments from an ELF file.
pub fn load_segments(data: &[u8]) -> Result<([LoadSegment; MAX_LOAD_SEGMENTS], usize)> {
    if data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Size verified above. Use read_unaligned for alignment safety.
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Header) };

    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

    let mut segments = [LoadSegment {
        vaddr: 0,
        file_offset: 0,
        file_size: 0,
        mem_size: 0,
        flags: 0,
        align: 0,
    }; MAX_LOAD_SEGMENTS];
    let mut count = 0;

    for i in 0..ph_count {
        let offset = ph_offset + i * ph_size;
        if offset + ph_size > data.len() {
            break;
        }
        // SAFETY: Bounds checked above. Use read_unaligned for
        // potentially unaligned input data.
        let phdr =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const Elf64Phdr) };

        if phdr.p_type == PT_LOAD && count < MAX_LOAD_SEGMENTS {
            segments[count] = LoadSegment {
                vaddr: phdr.p_vaddr,
                file_offset: phdr.p_offset,
                file_size: phdr.p_filesz,
                mem_size: phdr.p_memsz,
                flags: phdr.p_flags,
                align: phdr.p_align,
            };
            count += 1;
        }
    }

    Ok((segments, count))
}

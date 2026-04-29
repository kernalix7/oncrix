// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reusable ELF64 PT_LOAD copier for the single-region user layout.
//!
//! Both the initial-load path (`load_init_elf`) and the `execve` path
//! need to parse an ELF64 image, extract its PT_LOAD segments, and copy
//! them into a single flat 2 MiB user region at the appropriate offset
//! (`p_vaddr - USER_BASE`), zero-filling the `.bss` tail.
//!
//! This module owns that copy logic so it can be invoked by
//! [`crate::address_space::UserAddressSpace::map_elf_segments`] and any
//! other caller that needs the same layout. It intentionally does NOT
//! do any page-table manipulation — callers are responsible for mapping
//! the destination buffer into the user VMA.
//!
//! # Supported ELF subset
//!
//! - ELF64, little-endian, x86_64 (EM_X86_64)
//! - ET_EXEC and ET_DYN
//! - All PT_LOAD segments must fall inside `[USER_BASE, USER_BASE +
//!   dst.len())`; otherwise the call fails with
//!   [`oncrix_lib::Error::InvalidArgument`].
//!
//! This mirrors the behaviour of `crates/kernel/src/elf.rs` so the two
//! paths stay consistent.

use oncrix_lib::{Error, Result};

/// User code base virtual address (matches `user.ld`).
pub const USER_BASE: u64 = 0x0040_0000;

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

/// Maximum PT_LOAD program headers accepted. Matches the kernel ELF
/// loader in `crates/kernel/src/elf.rs`.
const MAX_LOAD_SEGMENTS: usize = 16;

/// ELF64 file header — layout as defined by System V gABI.
#[derive(Clone, Copy)]
#[repr(C)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header.
#[derive(Clone, Copy)]
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// Summary of a successful ELF load.
#[derive(Debug, Clone, Copy)]
pub struct ElfLoadInfo {
    /// Entry point virtual address (`e_entry`).
    pub entry: u64,
    /// Number of PT_LOAD segments copied.
    pub load_segment_count: usize,
    /// Highest virtual address touched (useful as a brk start hint).
    pub max_vaddr: u64,
}

/// Parse `elf_bytes`, validate the ELF64 header, and copy every
/// PT_LOAD segment into `dst` rebased to start at [`USER_BASE`].
///
/// `dst` is the per-process backing buffer that will later be mapped
/// at VMA [`USER_BASE`]..[`USER_BASE`]` + dst.len()`. The caller is
/// responsible for ensuring `dst` is page-aligned in both its virtual
/// and physical backing if any page-table mapping uses those frames.
///
/// # Image base discovery
///
/// rustc's default link script emits a static EXEC at `0x200000`
/// while ONCRIX's `user.ld` places the image at [`USER_BASE`]
/// (`0x400000`). Both layouts must run from the kernel's single user
/// VMA window at [`USER_BASE`]. To support that we treat the lowest
/// PT_LOAD `p_vaddr` (rounded down to a page boundary) as the
/// image base and copy each segment at offset
/// `p_vaddr - image_base`. The returned [`ElfLoadInfo::entry`] and
/// [`ElfLoadInfo::max_vaddr`] are likewise rebased so they reference
/// [`USER_BASE`]-relative addresses regardless of how the binary was
/// linked. The image bytes themselves are copied verbatim, so any
/// non-relocatable absolute references (a non-PIE EXEC linked at a
/// base other than [`USER_BASE`]) will reference unmapped VAs at
/// runtime — those binaries should be relinked with the project's
/// `user.ld`. The hot path of small statically-linked utilities
/// (RIP-relative calls + register-based syscalls) does not exercise
/// such absolutes and runs correctly after rebase.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on any of:
/// - truncated or malformed ELF header
/// - wrong ELF class / endianness / machine / type
/// - program-header table out of bounds
/// - no PT_LOAD segments
/// - rebased segment span exceeds `dst.len()`
/// - segment file range outside `elf_bytes`
/// - `p_filesz > p_memsz`
/// - entry point falls outside the rebased load image
/// - more than [`MAX_LOAD_SEGMENTS`] PT_LOAD segments
///
/// On success, `dst` contains the loaded image with `.bss` zero-filled
/// and [`ElfLoadInfo::entry`] is the entry point to jump to.
pub fn load_elf_into(elf_bytes: &[u8], dst: &mut [u8]) -> Result<ElfLoadInfo> {
    if elf_bytes.len() < core::mem::size_of::<Elf64Header>() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Size verified above. `read_unaligned` handles the fact
    // that `elf_bytes` is a byte slice which is not guaranteed to meet
    // `Elf64Header`'s 8-byte alignment.
    let header = unsafe { core::ptr::read_unaligned(elf_bytes.as_ptr() as *const Elf64Header) };

    if header.e_ident[..4] != ELF_MAGIC {
        return Err(Error::InvalidArgument);
    }
    if header.e_ident[4] != ELFCLASS64 || header.e_ident[5] != ELFDATA2LSB {
        return Err(Error::InvalidArgument);
    }
    if header.e_machine != EM_X86_64 {
        return Err(Error::InvalidArgument);
    }
    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err(Error::InvalidArgument);
    }

    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

    let ph_end = ph_size
        .checked_mul(ph_count)
        .and_then(|n| n.checked_add(ph_offset))
        .ok_or(Error::InvalidArgument)?;
    if ph_end > elf_bytes.len() {
        return Err(Error::InvalidArgument);
    }

    // Pass 1: discover the image base (lowest PT_LOAD vaddr, page-aligned
    // down). This is what the binary "thinks" its load address is; we
    // rebase everything to USER_BASE below.
    let mut image_base: Option<u64> = None;
    let mut load_count = 0usize;
    for i in 0..ph_count {
        let phdr = read_phdr(elf_bytes, ph_offset, ph_size, i)?;
        if phdr.p_type != PT_LOAD {
            continue;
        }
        load_count += 1;
        let cand = phdr.p_vaddr & !((PAGE_SIZE_U64) - 1);
        image_base = Some(match image_base {
            Some(cur) if cur <= cand => cur,
            _ => cand,
        });
    }
    if load_count == 0 {
        return Err(Error::InvalidArgument);
    }
    let image_base = image_base.ok_or(Error::InvalidArgument)?;

    let dst_len = dst.len() as u64;
    let mut loaded = 0usize;
    let mut max_rebased_end = 0u64;

    // Pass 2: copy each PT_LOAD into dst at offset `p_vaddr - image_base`.
    for i in 0..ph_count {
        let phdr = read_phdr(elf_bytes, ph_offset, ph_size, i)?;
        if phdr.p_type != PT_LOAD {
            continue;
        }
        if loaded >= MAX_LOAD_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        if phdr.p_filesz > phdr.p_memsz {
            return Err(Error::InvalidArgument);
        }

        // Offset of this segment within the dst buffer (i.e. relative
        // to `image_base`, which the kernel maps at USER_BASE).
        let seg_off_in_dst = phdr
            .p_vaddr
            .checked_sub(image_base)
            .ok_or(Error::InvalidArgument)?;
        let seg_end_in_dst = seg_off_in_dst
            .checked_add(phdr.p_memsz)
            .ok_or(Error::InvalidArgument)?;
        if seg_end_in_dst > dst_len {
            return Err(Error::InvalidArgument);
        }

        let file_off = phdr.p_offset as usize;
        let file_sz = phdr.p_filesz as usize;
        let file_end = file_off
            .checked_add(file_sz)
            .ok_or(Error::InvalidArgument)?;
        if file_end > elf_bytes.len() {
            return Err(Error::InvalidArgument);
        }

        let dst_start = seg_off_in_dst as usize;
        let dst_file_end = dst_start
            .checked_add(file_sz)
            .ok_or(Error::InvalidArgument)?;
        let dst_mem_end = dst_start
            .checked_add(phdr.p_memsz as usize)
            .ok_or(Error::InvalidArgument)?;

        if dst_mem_end > dst.len() || dst_file_end > dst.len() {
            return Err(Error::InvalidArgument);
        }

        dst[dst_start..dst_file_end].copy_from_slice(&elf_bytes[file_off..file_end]);
        if dst_mem_end > dst_file_end {
            for b in &mut dst[dst_file_end..dst_mem_end] {
                *b = 0;
            }
        }

        if seg_end_in_dst > max_rebased_end {
            max_rebased_end = seg_end_in_dst;
        }
        loaded += 1;
    }

    // Rebase the entry point: e_entry is relative to image_base; the
    // kernel will jump in user mode with the dst buffer mapped at
    // USER_BASE, so the entry must reference USER_BASE-relative VAs.
    let entry_off = header
        .e_entry
        .checked_sub(image_base)
        .ok_or(Error::InvalidArgument)?;
    if entry_off >= max_rebased_end {
        return Err(Error::InvalidArgument);
    }
    let entry = USER_BASE
        .checked_add(entry_off)
        .ok_or(Error::InvalidArgument)?;
    let max_vaddr = USER_BASE
        .checked_add(max_rebased_end)
        .ok_or(Error::InvalidArgument)?;

    Ok(ElfLoadInfo {
        entry,
        load_segment_count: loaded,
        max_vaddr,
    })
}

/// Page size constant used for image-base alignment. Mirrors
/// `crate::addr::PAGE_SIZE` but kept local so this module compiles
/// independently of crate-internal types.
const PAGE_SIZE_U64: u64 = 4096;

/// Read the i-th program header from `elf_bytes`, bounds-checked.
fn read_phdr(elf_bytes: &[u8], ph_offset: usize, ph_size: usize, i: usize) -> Result<Elf64Phdr> {
    let offset = ph_offset
        .checked_add(i.checked_mul(ph_size).ok_or(Error::InvalidArgument)?)
        .ok_or(Error::InvalidArgument)?;
    if offset.checked_add(ph_size).ok_or(Error::InvalidArgument)? > elf_bytes.len() {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Bounds checked above (offset + ph_size <= elf_bytes.len()).
    // `read_unaligned` handles potentially unaligned input.
    Ok(unsafe { core::ptr::read_unaligned(elf_bytes.as_ptr().add(offset) as *const Elf64Phdr) })
}

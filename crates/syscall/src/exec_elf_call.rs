// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ELF binary loading helpers for `execve` / `execveat`.
//!
//! Provides ELF64 program header parsing, segment mapping classification,
//! and `PT_INTERP` handling (dynamic linker discovery).  Used by the
//! execution path to determine how to map the binary into the new address
//! space.
//!
//! # References
//!
//! - Linux: `fs/binfmt_elf.c`
//! - System V ABI AMD64 Supplement
//! - ELF specification (TIS Committee 1995 + extensions)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ELF64 constants
// ---------------------------------------------------------------------------

/// Program header type: loadable segment.
pub const PT_LOAD: u32 = 1;
/// Program header type: dynamic linking info.
pub const PT_DYNAMIC: u32 = 2;
/// Program header type: interpreter path.
pub const PT_INTERP: u32 = 3;
/// Program header type: note (auxiliary info).
pub const PT_NOTE: u32 = 4;
/// Program header type: TLS template.
pub const PT_TLS: u32 = 7;
/// Program header type: GNU stack (noexec flag).
pub const PT_GNU_STACK: u32 = 0x6474e551;
/// Program header type: GNU relro (read-only after reloc).
pub const PT_GNU_RELRO: u32 = 0x6474e552;
/// Program header type: GNU property.
pub const PT_GNU_PROPERTY: u32 = 0x6474e553;

/// Segment flag: execute.
pub const PF_X: u32 = 0x1;
/// Segment flag: write.
pub const PF_W: u32 = 0x2;
/// Segment flag: read.
pub const PF_R: u32 = 0x4;

/// Maximum interpreter path length.
pub const INTERP_PATH_MAX: usize = 256;
/// Maximum number of program headers.
pub const MAX_PHDRS: usize = 64;
/// Default page size.
pub const PAGE_SIZE: u64 = 4096;
/// Page mask.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);
/// Upper bound on a PT_LOAD segment's virtual memory size (128 TiB on x86-64).
///
/// Segments larger than this are almost certainly decompression-bomb attacks.
/// The value is identical to Linux's `TASK_SIZE_MAX` for x86-64.
pub const TASK_SIZE_MAX: u64 = 0x0000_7FFF_FFFF_F000;

// ---------------------------------------------------------------------------
// Elf64Phdr — ELF64 program header
// ---------------------------------------------------------------------------

/// ELF64 program header entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64Phdr {
    /// Segment type.
    pub p_type: u32,
    /// Segment-dependent flags.
    pub p_flags: u32,
    /// File offset of segment data.
    pub p_offset: u64,
    /// Virtual address at which the segment should be mapped.
    pub p_vaddr: u64,
    /// Physical address (often same as vaddr on x86-64).
    pub p_paddr: u64,
    /// Number of bytes in the file image.
    pub p_filesz: u64,
    /// Number of bytes in memory.
    pub p_memsz: u64,
    /// Alignment constraint (must be power of two).
    pub p_align: u64,
}

impl Elf64Phdr {
    /// Return `true` if this is a loadable segment.
    pub const fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    /// Return `true` if the segment is executable.
    pub const fn is_exec(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// Return `true` if the segment is writable.
    pub const fn is_write(&self) -> bool {
        self.p_flags & PF_W != 0
    }

    /// Return `true` if the segment has a BSS area (memsz > filesz).
    pub const fn has_bss(&self) -> bool {
        self.p_memsz > self.p_filesz
    }

    /// Page-aligned load address.
    pub const fn load_addr(&self) -> u64 {
        self.p_vaddr & PAGE_MASK
    }

    /// Validate basic constraints for a PT_LOAD segment.
    ///
    /// `file_len` is the total byte length of the ELF image on disk; it is
    /// used to ensure `p_offset + p_filesz` does not exceed the file, which
    /// would otherwise allow an out-of-bounds read when the loader copies file
    /// data into the mapped segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any constraint is violated.
    pub fn validate(&self, file_len: usize) -> Result<()> {
        if self.p_type != PT_LOAD {
            return Ok(()); // Non-LOAD segments have relaxed constraints.
        }
        if self.p_align > 1 && self.p_align & (self.p_align - 1) != 0 {
            return Err(Error::InvalidArgument); // Not a power of two.
        }
        if self.p_filesz > self.p_memsz {
            return Err(Error::InvalidArgument);
        }
        // Reject both u64 wrap-around and any end address that exceeds the
        // user virtual address space limit.  Checking only p_memsz is
        // insufficient: p_vaddr = TASK_SIZE_MAX with p_memsz = 1 passes a
        // bare size check yet places the segment end in kernel virtual space.
        // Using strict > allows a segment whose end equals TASK_SIZE_MAX.
        let seg_end = self
            .p_vaddr
            .checked_add(self.p_memsz)
            .ok_or(Error::InvalidArgument)?;
        if seg_end > TASK_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        // Ensure p_offset + p_filesz is within the file image.
        let file_off = self.p_offset as usize;
        let file_sz = self.p_filesz as usize;
        let file_end = file_off
            .checked_add(file_sz)
            .ok_or(Error::InvalidArgument)?;
        if file_end > file_len {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoadSegment — classified load segment
// ---------------------------------------------------------------------------

/// Classification of a loadable ELF segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// Text (read + execute, no write).
    Text,
    /// Data (read + write, no execute).
    Data,
    /// Read-only data.
    Rodata,
    /// Read + write + execute (unusual).
    Rwx,
}

/// Mapped ELF segment descriptor.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Segment kind.
    pub kind: SegmentKind,
    /// Virtual address (page-aligned start).
    pub vaddr: u64,
    /// Length to map from file.
    pub filesz: u64,
    /// Total memory size (including BSS).
    pub memsz: u64,
    /// File offset.
    pub offset: u64,
}

impl LoadSegment {
    /// Construct from a validated `PT_LOAD` program header.
    pub fn from_phdr(phdr: &Elf64Phdr) -> Self {
        let kind = match (
            phdr.p_flags & PF_R != 0,
            phdr.p_flags & PF_W != 0,
            phdr.p_flags & PF_X != 0,
        ) {
            (true, false, true) => SegmentKind::Text,
            (true, true, false) => SegmentKind::Data,
            (true, false, false) => SegmentKind::Rodata,
            _ => SegmentKind::Rwx,
        };
        Self {
            kind,
            vaddr: phdr.load_addr(),
            filesz: phdr.p_filesz,
            memsz: phdr.p_memsz,
            offset: phdr.p_offset & PAGE_MASK,
        }
    }
}

// ---------------------------------------------------------------------------
// ElfParseResult — result of parsing the program header table
// ---------------------------------------------------------------------------

/// Result of parsing an ELF64 binary's program headers.
#[derive(Debug)]
pub struct ElfParseResult {
    /// Loadable segments to map.
    pub segments: [Option<LoadSegment>; MAX_PHDRS],
    /// Number of loadable segments.
    pub segment_count: usize,
    /// Interpreter path (from PT_INTERP), if present.
    pub interp_path: [u8; INTERP_PATH_MAX],
    /// Length of interpreter path (0 = none).
    pub interp_len: usize,
    /// Entry point from the ELF header.
    pub entry_point: u64,
    /// Whether the GNU stack header marks the stack non-executable.
    pub noexec_stack: bool,
}

impl ElfParseResult {
    /// Create an empty result.
    pub fn new(entry_point: u64) -> Self {
        Self {
            segments: [const { None }; MAX_PHDRS],
            segment_count: 0,
            interp_path: [0; INTERP_PATH_MAX],
            interp_len: 0,
            entry_point,
            noexec_stack: true,
        }
    }

    /// Return `true` if this is a dynamically linked binary.
    pub const fn is_dynamic(&self) -> bool {
        self.interp_len > 0
    }

    /// Return the interpreter path as a byte slice.
    pub fn interp_path_str(&self) -> &[u8] {
        &self.interp_path[..self.interp_len]
    }
}

// ---------------------------------------------------------------------------
// parse_program_headers — parse and classify ELF phdrs
// ---------------------------------------------------------------------------

/// Parse and validate a program header table.
///
/// # Arguments
///
/// * `phdrs`       — Slice of program headers.
/// * `entry_point` — ELF entry point from the ELF header.
/// * `interp_data` — Optional data from the PT_INTERP segment.
/// * `file_len`    — Total byte length of the ELF image; used to bounds-check
///                   `PT_LOAD` segment file offsets.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for invalid program headers.
pub fn parse_program_headers(
    phdrs: &[Elf64Phdr],
    entry_point: u64,
    interp_data: Option<&[u8]>,
    file_len: usize,
) -> Result<ElfParseResult> {
    if phdrs.len() > MAX_PHDRS {
        return Err(Error::InvalidArgument);
    }

    let mut result = ElfParseResult::new(entry_point);

    for phdr in phdrs {
        phdr.validate(file_len)?;

        match phdr.p_type {
            PT_LOAD => {
                if result.segment_count >= MAX_PHDRS {
                    return Err(Error::InvalidArgument);
                }
                result.segments[result.segment_count] = Some(LoadSegment::from_phdr(phdr));
                result.segment_count += 1;
            }
            PT_INTERP => {
                if let Some(data) = interp_data {
                    let len = data.len().min(INTERP_PATH_MAX - 1);
                    result.interp_path[..len].copy_from_slice(&data[..len]);
                    result.interp_len = len;
                }
            }
            PT_GNU_STACK => {
                result.noexec_stack = phdr.p_flags & PF_X == 0;
            }
            _ => {}
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn text_phdr() -> Elf64Phdr {
        Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: 0x40_0000,
            p_paddr: 0x40_0000,
            p_filesz: 4096,
            p_memsz: 4096,
            p_align: PAGE_SIZE,
        }
    }

    fn data_phdr() -> Elf64Phdr {
        Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_W,
            p_offset: 4096,
            p_vaddr: 0x60_0000,
            p_paddr: 0x60_0000,
            p_filesz: 512,
            p_memsz: 1024, // BSS
            p_align: PAGE_SIZE,
        }
    }

    #[test]
    fn parse_basic_binary() {
        let phdrs = [text_phdr(), data_phdr()];
        // file_len must cover the highest offset + filesz used in the test
        // phdrs: text at offset 0 size 4096, data at offset 4096 size 512 → 4608
        let r = parse_program_headers(&phdrs, 0x40_1000, None, 8192).unwrap();
        assert_eq!(r.segment_count, 2);
        assert!(!r.is_dynamic());
    }

    #[test]
    fn segment_classification() {
        let text = LoadSegment::from_phdr(&text_phdr());
        assert_eq!(text.kind, SegmentKind::Text);
        let data = LoadSegment::from_phdr(&data_phdr());
        assert_eq!(data.kind, SegmentKind::Data);
        assert!(data_phdr().has_bss());
    }

    #[test]
    fn interp_path() {
        let interp_phdr = Elf64Phdr {
            p_type: PT_INTERP,
            p_flags: PF_R,
            p_offset: 256,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 20,
            p_memsz: 20,
            p_align: 1,
        };
        let phdrs = [text_phdr(), interp_phdr];
        // file_len must cover text segment (offset 0, size 4096) = 4096
        let r = parse_program_headers(&phdrs, 0, Some(b"/lib/ld-linux.so.2"), 4096).unwrap();
        assert!(r.is_dynamic());
        assert_eq!(&r.interp_path_str(), b"/lib/ld-linux.so.2");
    }

    #[test]
    fn gnu_stack_noexec() {
        let stack = Elf64Phdr {
            p_type: PT_GNU_STACK,
            p_flags: PF_R | PF_W, // no X
            ..Default::default()
        };
        // GNU_STACK is not PT_LOAD so file_len is irrelevant; use 0.
        let r = parse_program_headers(&[stack], 0, None, 0).unwrap();
        assert!(r.noexec_stack);
    }

    #[test]
    fn filesz_gt_memsz_rejected() {
        let mut bad = text_phdr();
        bad.p_filesz = 8192;
        bad.p_memsz = 4096;
        // file_len is irrelevant here because filesz > memsz is caught first.
        assert_eq!(bad.validate(65536), Err(Error::InvalidArgument));
    }

    #[test]
    fn too_many_phdrs() {
        let phdrs = [const { Elf64Phdr::default() }; 65];
        assert_eq!(
            parse_program_headers(&phdrs, 0, None, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vaddr_memsz_overflow_rejected() {
        // p_vaddr near usize::MAX: p_vaddr + p_memsz wraps.
        let bad = Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: u64::MAX - 1,
            p_paddr: u64::MAX - 1,
            p_filesz: 1,
            p_memsz: 4096,
            p_align: PAGE_SIZE,
        };
        assert_eq!(bad.validate(65536), Err(Error::InvalidArgument));
    }

    #[test]
    fn memsz_exceeds_task_size_rejected() {
        let bad = Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: 0x40_0000,
            p_paddr: 0x40_0000,
            p_filesz: 0,
            p_memsz: TASK_SIZE_MAX + 1,
            p_align: PAGE_SIZE,
        };
        assert_eq!(bad.validate(65536), Err(Error::InvalidArgument));
    }

    #[test]
    fn high_vaddr_small_memsz_end_exceeds_task_size_rejected() {
        // p_vaddr = TASK_SIZE_MAX, p_memsz = 1: end address overflows into
        // kernel virtual space even though p_memsz alone is tiny.  This was
        // the specific attack vector fixed by checking seg_end > TASK_SIZE_MAX
        // instead of p_memsz > TASK_SIZE_MAX.
        let bad = Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: TASK_SIZE_MAX,
            p_paddr: TASK_SIZE_MAX,
            p_filesz: 0,
            p_memsz: 1,
            p_align: PAGE_SIZE,
        };
        assert_eq!(bad.validate(65536), Err(Error::InvalidArgument));
    }

    #[test]
    fn seg_end_exactly_task_size_accepted() {
        // A segment whose end address equals TASK_SIZE_MAX exactly is valid
        // (strict > comparison).
        let ok = Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: TASK_SIZE_MAX - 4096,
            p_paddr: TASK_SIZE_MAX - 4096,
            p_filesz: 0,
            p_memsz: 4096,
            p_align: PAGE_SIZE,
        };
        assert!(ok.validate(65536).is_ok());
    }

    #[test]
    fn segment_beyond_file_rejected() {
        // p_offset + p_filesz > file_len
        let bad = Elf64Phdr {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: 0x40_0000,
            p_paddr: 0x40_0000,
            p_filesz: 8192,
            p_memsz: 8192,
            p_align: PAGE_SIZE,
        };
        // file_len is only 4096 — segment extends beyond file.
        assert_eq!(bad.validate(4096), Err(Error::InvalidArgument));
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Common types and helpers shared by `execve` and `execveat` call handlers.
//!
//! Provides ELF header validation, argument/environment string accumulation,
//! auxiliary vector construction, and initial stack layout computation.
//!
//! These routines are used by both `execve_call` and `execveat_call` to
//! avoid duplication.
//!
//! # References
//!
//! - POSIX.1-2024: `exec()`
//! - System V ABI: AMD64 Supplement (initial process stack layout)
//! - Linux: `fs/binfmt_elf.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ELF64 header field constants
// ---------------------------------------------------------------------------

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// 64-bit ELF class.
pub const ELFCLASS64: u8 = 2;
/// Little-endian data encoding.
pub const ELFDATA2LSB: u8 = 1;
/// Executable file type.
pub const ET_EXEC: u16 = 2;
/// Shared object / PIE file type.
pub const ET_DYN: u16 = 3;
/// x86-64 machine type.
pub const EM_X86_64: u16 = 62;
/// Minimum ELF64 header size in bytes.
pub const ELF64_EHDR_MIN: usize = 64;

// ---------------------------------------------------------------------------
// Argument limits
// ---------------------------------------------------------------------------

/// Maximum length of all argv+envp string data combined.
pub const MAX_ARG_STRLEN: usize = 2 * 1024 * 1024 + 4096;
/// Maximum individual argument/environment count.
pub const MAX_ARG_COUNT: usize = 0x7FFF_FFFF;

// ---------------------------------------------------------------------------
// ElfIdent — first 16 bytes of every ELF file
// ---------------------------------------------------------------------------

/// Decoded ELF identification header (first 16 bytes).
#[derive(Debug, Clone, Copy)]
pub struct ElfIdent {
    /// ELF class (32 or 64 bit).
    pub class: u8,
    /// Data encoding (LSB or MSB).
    pub data: u8,
    /// ELF version (must be 1).
    pub version: u8,
    /// OS/ABI identifier.
    pub osabi: u8,
}

impl ElfIdent {
    /// Parse and validate an ELF ident block.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if the magic, class, encoding, or version
    /// are not acceptable for a 64-bit little-endian ELF.
    pub fn parse(ident: &[u8; 16]) -> Result<Self> {
        if &ident[0..4] != &ELF_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let class = ident[4];
        if class != ELFCLASS64 {
            return Err(Error::InvalidArgument);
        }
        let data = ident[5];
        if data != ELFDATA2LSB {
            return Err(Error::InvalidArgument);
        }
        let version = ident[6];
        if version != 1 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            class,
            data,
            version,
            osabi: ident[7],
        })
    }
}

// ---------------------------------------------------------------------------
// ElfHeader64 — minimal parsed ELF header
// ---------------------------------------------------------------------------

/// Minimal parsed ELF64 header (type, machine, entry point, phoff, phnum).
#[derive(Debug, Clone, Copy)]
pub struct ElfHeader64 {
    /// File type (`ET_EXEC` or `ET_DYN`).
    pub e_type: u16,
    /// Target machine.
    pub e_machine: u16,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table offset.
    pub e_phoff: u64,
    /// Number of program header entries.
    pub e_phnum: u16,
}

impl ElfHeader64 {
    /// Validate the parsed header fields.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if the type or machine are not supported.
    pub fn validate(&self) -> Result<()> {
        if self.e_type != ET_EXEC && self.e_type != ET_DYN {
            return Err(Error::InvalidArgument);
        }
        if self.e_machine != EM_X86_64 {
            return Err(Error::InvalidArgument);
        }
        if self.e_entry == 0 && self.e_type == ET_EXEC {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArgEnvAccumulator — collects argv/envp data
// ---------------------------------------------------------------------------

/// Accumulates argument and environment strings prior to exec.
///
/// Enforces the POSIX/Linux limits on total string data and argument count.
pub struct ArgEnvAccumulator {
    /// Total accumulated byte count.
    total_bytes: usize,
    /// Number of strings accumulated.
    count: usize,
}

impl ArgEnvAccumulator {
    /// Create an empty accumulator.
    pub const fn new() -> Self {
        Self {
            total_bytes: 0,
            count: 0,
        }
    }

    /// Accumulate one argument or environment string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if limits would be exceeded.
    pub fn push(&mut self, s: &[u8]) -> Result<()> {
        if self.count >= MAX_ARG_COUNT {
            return Err(Error::InvalidArgument);
        }
        let new_total = self
            .total_bytes
            .checked_add(s.len())
            .ok_or(Error::InvalidArgument)?;
        if new_total > MAX_ARG_STRLEN {
            return Err(Error::InvalidArgument);
        }
        self.total_bytes = new_total;
        self.count += 1;
        Ok(())
    }

    /// Return the total byte count.
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Return the number of strings accumulated.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for ArgEnvAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AuxVector — auxiliary vector entries
// ---------------------------------------------------------------------------

/// Auxiliary vector tag/value pair.
///
/// Laid out on the initial stack below the environment pointers.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuxPair {
    /// Auxiliary vector tag.
    pub a_type: u64,
    /// Auxiliary vector value.
    pub a_val: u64,
}

/// AT_NULL — end of auxiliary vector.
pub const AT_NULL: u64 = 0;
/// AT_PHDR — address of program headers.
pub const AT_PHDR: u64 = 3;
/// AT_PHENT — size of one program header entry.
pub const AT_PHENT: u64 = 4;
/// AT_PHNUM — number of program headers.
pub const AT_PHNUM: u64 = 5;
/// AT_PAGESZ — system page size.
pub const AT_PAGESZ: u64 = 6;
/// AT_ENTRY — entry point.
pub const AT_ENTRY: u64 = 9;
/// AT_RANDOM — address of 16 random bytes.
pub const AT_RANDOM: u64 = 25;

/// Maximum number of auxiliary vector entries (including `AT_NULL`).
const MAX_AUXV_ENTRIES: usize = 32;

/// Auxiliary vector builder.
pub struct AuxVector {
    pairs: [AuxPair; MAX_AUXV_ENTRIES],
    len: usize,
}

impl AuxVector {
    /// Create an empty auxiliary vector.
    pub const fn new() -> Self {
        Self {
            pairs: [const {
                AuxPair {
                    a_type: AT_NULL,
                    a_val: 0,
                }
            }; MAX_AUXV_ENTRIES],
            len: 0,
        }
    }

    /// Append a tag/value pair.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the vector is full.
    pub fn push(&mut self, a_type: u64, a_val: u64) -> Result<()> {
        if self.len >= MAX_AUXV_ENTRIES - 1 {
            return Err(Error::OutOfMemory);
        }
        self.pairs[self.len] = AuxPair { a_type, a_val };
        self.len += 1;
        Ok(())
    }

    /// Terminate the vector with `AT_NULL` and return the valid slice.
    pub fn finish(&mut self) -> &[AuxPair] {
        self.pairs[self.len] = AuxPair {
            a_type: AT_NULL,
            a_val: 0,
        };
        &self.pairs[..=self.len]
    }

    /// Return the number of non-null entries.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the vector is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for AuxVector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// build_standard_auxv — construct a standard auxiliary vector
// ---------------------------------------------------------------------------

/// Construct a standard auxiliary vector for a newly exec'd process.
///
/// # Arguments
///
/// * `phdr_vaddr` — Virtual address of the ELF program header table.
/// * `phent`      — Size of one program header entry.
/// * `phnum`      — Number of program headers.
/// * `entry`      — Process entry point virtual address.
/// * `random_ptr` — Virtual address of 16 random bytes on the stack.
pub fn build_standard_auxv(
    phdr_vaddr: u64,
    phent: u64,
    phnum: u64,
    entry: u64,
    random_ptr: u64,
) -> Result<AuxVector> {
    let mut v = AuxVector::new();
    v.push(AT_PHDR, phdr_vaddr)?;
    v.push(AT_PHENT, phent)?;
    v.push(AT_PHNUM, phnum)?;
    v.push(AT_PAGESZ, 4096)?;
    v.push(AT_ENTRY, entry)?;
    v.push(AT_RANDOM, random_ptr)?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_ident_valid() {
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&ELF_MAGIC);
        raw[4] = ELFCLASS64;
        raw[5] = ELFDATA2LSB;
        raw[6] = 1;
        let ident = ElfIdent::parse(&raw).unwrap();
        assert_eq!(ident.class, ELFCLASS64);
    }

    #[test]
    fn elf_ident_bad_magic() {
        let raw = [0u8; 16];
        assert_eq!(ElfIdent::parse(&raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn elf_ident_32bit_rejected() {
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&ELF_MAGIC);
        raw[4] = 1; // ELFCLASS32
        raw[5] = ELFDATA2LSB;
        raw[6] = 1;
        assert_eq!(ElfIdent::parse(&raw), Err(Error::InvalidArgument));
    }

    #[test]
    fn elf_header_valid_exec() {
        let h = ElfHeader64 {
            e_type: ET_EXEC,
            e_machine: EM_X86_64,
            e_entry: 0x401000,
            e_phoff: 64,
            e_phnum: 3,
        };
        assert!(h.validate().is_ok());
    }

    #[test]
    fn elf_header_bad_machine() {
        let h = ElfHeader64 {
            e_type: ET_EXEC,
            e_machine: 40, // ARM
            e_entry: 0x401000,
            e_phoff: 64,
            e_phnum: 3,
        };
        assert_eq!(h.validate(), Err(Error::InvalidArgument));
    }

    #[test]
    fn accumulator_limits() {
        let mut acc = ArgEnvAccumulator::new();
        acc.push(b"hello").unwrap();
        acc.push(b"world").unwrap();
        assert_eq!(acc.count(), 2);
        assert_eq!(acc.total_bytes(), 10);
    }

    #[test]
    fn auxv_build() {
        let mut v = build_standard_auxv(0x400000, 56, 3, 0x401000, 0x7FFF_0000).unwrap();
        let pairs = v.finish();
        // Should end with AT_NULL.
        let last = pairs.last().unwrap();
        assert_eq!(last.a_type, AT_NULL);
    }

    #[test]
    fn auxv_full() {
        let mut v = AuxVector::new();
        for i in 0..31 {
            v.push(i as u64, 0).unwrap();
        }
        assert_eq!(v.push(99, 0), Err(Error::OutOfMemory));
    }
}

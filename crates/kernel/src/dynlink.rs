// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ELF dynamic linker basics.
//!
//! Provides structures and functions for parsing ELF dynamic sections,
//! symbol tables, and applying relocations. This module handles the
//! kernel-side preparation for dynamically linked executables,
//! including PT_DYNAMIC parsing, PT_INTERP extraction, and
//! relocation processing for x86_64.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ELF dynamic section tag constants (from ELF spec)
// ---------------------------------------------------------------------------

/// Marks end of dynamic section.
pub const DT_NULL: i64 = 0;
/// Name of needed library (string table offset).
pub const DT_NEEDED: i64 = 1;
/// Size in bytes of PLT relocation entries.
pub const DT_PLTRELSZ: i64 = 2;
/// Address of PLT and/or GOT.
pub const DT_PLTGOT: i64 = 3;
/// Address of symbol hash table.
pub const DT_HASH: i64 = 4;
/// Address of string table.
pub const DT_STRTAB: i64 = 5;
/// Address of symbol table.
pub const DT_SYMTAB: i64 = 6;
/// Address of Rela relocation table.
pub const DT_RELA: i64 = 7;
/// Size in bytes of the Rela relocation table.
pub const DT_RELASZ: i64 = 8;
/// Size of each Rela relocation entry.
pub const DT_RELAENT: i64 = 9;
/// Size of the string table in bytes.
pub const DT_STRSZ: i64 = 10;
/// Size of each symbol table entry.
pub const DT_SYMENT: i64 = 11;
/// Address of the initialization function.
pub const DT_INIT: i64 = 12;
/// Address of the finalization function.
pub const DT_FINI: i64 = 13;
/// Name of shared object (string table offset).
pub const DT_SONAME: i64 = 14;
/// Library search path (string table offset).
pub const DT_RPATH: i64 = 15;
/// Address of PLT relocation entries.
pub const DT_JMPREL: i64 = 23;
/// All relocations must be processed before execution.
pub const DT_BIND_NOW: i64 = 24;

// ---------------------------------------------------------------------------
// x86_64 relocation types
// ---------------------------------------------------------------------------

/// No relocation.
pub const R_X86_64_NONE: u32 = 0;
/// Direct 64-bit: S + A.
pub const R_X86_64_64: u32 = 1;
/// Create GOT entry: S.
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// Set GOT entry to PLT address: S.
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// Adjust by base: B + A.
pub const R_X86_64_RELATIVE: u32 = 8;

// ---------------------------------------------------------------------------
// ELF64 Dynamic entry
// ---------------------------------------------------------------------------

/// ELF64 dynamic section entry.
///
/// Each entry in the `.dynamic` section describes a property of the
/// dynamically linked binary (e.g., string table address, needed
/// libraries, relocation tables).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Dyn {
    /// Dynamic entry tag (one of the `DT_*` constants).
    pub d_tag: i64,
    /// Tag-dependent value (address or integer).
    pub d_val: u64,
}

// ---------------------------------------------------------------------------
// ELF64 Symbol table entry
// ---------------------------------------------------------------------------

/// ELF64 symbol table entry.
///
/// Represents a single symbol in the `.dynsym` section.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Sym {
    /// Symbol name (index into string table).
    pub st_name: u32,
    /// Symbol type and binding attributes.
    pub st_info: u8,
    /// Symbol visibility.
    pub st_other: u8,
    /// Section index this symbol is defined in.
    pub st_shndx: u16,
    /// Symbol value (address).
    pub st_value: u64,
    /// Symbol size in bytes.
    pub st_size: u64,
}

impl Elf64Sym {
    /// Returns the symbol binding (upper 4 bits of `st_info`).
    pub fn bind(&self) -> u8 {
        self.st_info >> 4
    }

    /// Returns the symbol type (lower 4 bits of `st_info`).
    pub fn sym_type(&self) -> u8 {
        self.st_info & 0xf
    }

    /// Returns `true` if the symbol is undefined (section index 0).
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == 0
    }
}

// ---------------------------------------------------------------------------
// ELF64 Rela relocation entry
// ---------------------------------------------------------------------------

/// ELF64 relocation entry with explicit addend.
///
/// Used in `.rela.dyn` and `.rela.plt` sections.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Elf64Rela {
    /// Address where the relocation must be applied.
    pub r_offset: u64,
    /// Relocation type and symbol index.
    pub r_info: u64,
    /// Constant addend for computing the relocation value.
    pub r_addend: i64,
}

impl Elf64Rela {
    /// Returns the symbol table index (upper 32 bits of `r_info`).
    pub fn sym_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    /// Returns the relocation type (lower 32 bits of `r_info`).
    pub fn rela_type(&self) -> u32 {
        (self.r_info & 0xffff_ffff) as u32
    }
}

// ---------------------------------------------------------------------------
// DynamicInfo — parsed PT_DYNAMIC content
// ---------------------------------------------------------------------------

/// Parsed information from a PT_DYNAMIC segment.
///
/// Collects the addresses and sizes of the string table, symbol
/// table, relocation tables, and other dynamic linking metadata
/// extracted from the array of `Elf64Dyn` entries.
#[derive(Debug, Clone, Copy)]
pub struct DynamicInfo {
    /// File offset (or load address) of the string table.
    pub strtab_offset: u64,
    /// Size of the string table in bytes.
    pub strtab_size: u64,
    /// File offset (or load address) of the symbol table.
    pub symtab_offset: u64,
    /// Size of each symbol table entry.
    pub syment_size: u64,
    /// File offset (or load address) of the Rela table.
    pub rela_offset: u64,
    /// Total size of the Rela table in bytes.
    pub rela_size: u64,
    /// Size of each Rela entry.
    pub relaent_size: u64,
    /// File offset (or load address) of PLT relocations.
    pub jmprel_offset: u64,
    /// Total size of PLT relocation entries.
    pub pltrelsz: u64,
    /// Address of the initialization function (0 if absent).
    pub init_addr: u64,
    /// Address of the finalization function (0 if absent).
    pub fini_addr: u64,
    /// Address of the PLT/GOT.
    pub pltgot_addr: u64,
    /// Whether `DT_BIND_NOW` is set (eager binding).
    pub bind_now: bool,
}

impl DynamicInfo {
    /// Parses an array of `Elf64Dyn` entries (from PT_DYNAMIC)
    /// into a [`DynamicInfo`] struct.
    ///
    /// Iteration stops at the first `DT_NULL` entry. Returns
    /// `Err(Error::InvalidArgument)` if the slice is empty or
    /// no `DT_NULL` terminator is found.
    pub fn parse_dynamic(dyn_entries: &[Elf64Dyn]) -> Result<DynamicInfo> {
        if dyn_entries.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let mut info = DynamicInfo {
            strtab_offset: 0,
            strtab_size: 0,
            symtab_offset: 0,
            syment_size: 0,
            rela_offset: 0,
            rela_size: 0,
            relaent_size: 0,
            jmprel_offset: 0,
            pltrelsz: 0,
            init_addr: 0,
            fini_addr: 0,
            pltgot_addr: 0,
            bind_now: false,
        };

        let mut found_null = false;

        for entry in dyn_entries {
            match entry.d_tag {
                DT_NULL => {
                    found_null = true;
                    break;
                }
                DT_STRTAB => info.strtab_offset = entry.d_val,
                DT_STRSZ => info.strtab_size = entry.d_val,
                DT_SYMTAB => info.symtab_offset = entry.d_val,
                DT_SYMENT => info.syment_size = entry.d_val,
                DT_RELA => info.rela_offset = entry.d_val,
                DT_RELASZ => info.rela_size = entry.d_val,
                DT_RELAENT => info.relaent_size = entry.d_val,
                DT_JMPREL => info.jmprel_offset = entry.d_val,
                DT_PLTRELSZ => info.pltrelsz = entry.d_val,
                DT_INIT => info.init_addr = entry.d_val,
                DT_FINI => info.fini_addr = entry.d_val,
                DT_PLTGOT => info.pltgot_addr = entry.d_val,
                DT_BIND_NOW => info.bind_now = true,
                _ => { /* ignore unknown tags */ }
            }
        }

        if !found_null {
            return Err(Error::InvalidArgument);
        }

        Ok(info)
    }
}

// ---------------------------------------------------------------------------
// SymbolTable — fixed-capacity exported symbol registry
// ---------------------------------------------------------------------------

/// Maximum number of symbols the table can hold.
const MAX_SYMBOLS: usize = 256;

/// A fixed-capacity symbol table for exported symbols.
///
/// Stores up to 256 `(address, name_offset)` pairs. This is used
/// during dynamic linking to resolve symbols by index.
#[derive(Debug, Clone, Copy)]
pub struct SymbolTable {
    /// Array of (address, name_offset) pairs.
    symbols: [(u64, u32); MAX_SYMBOLS],
    /// Number of valid entries in the table.
    count: usize,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    /// Creates an empty symbol table.
    pub fn new() -> Self {
        Self {
            symbols: [(0, 0); MAX_SYMBOLS],
            count: 0,
        }
    }

    /// Adds a symbol to the table.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the table is full.
    pub fn add_symbol(&mut self, addr: u64, name_offset: u32) -> Result<()> {
        if self.count >= MAX_SYMBOLS {
            return Err(Error::OutOfMemory);
        }
        self.symbols[self.count] = (addr, name_offset);
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Looks up a symbol by index.
    ///
    /// Returns `(address, name_offset)` or
    /// `Err(Error::InvalidArgument)` if the index is out of range.
    pub fn lookup_by_index(&self, idx: usize) -> Result<(u64, u32)> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.symbols[idx])
    }

    /// Returns the number of symbols in the table.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table contains no symbols.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Relocation processing
// ---------------------------------------------------------------------------

/// Applies relocations from a Rela table.
///
/// This is a **simulation** — actual memory writes would go through
/// the mm subsystem. The function validates each relocation entry
/// and counts how many would be applied.
///
/// # Arguments
///
/// * `base_addr` — Base load address of the shared object.
/// * `rela_entries` — Slice of `Elf64Rela` entries to process.
/// * `rela_count` — Number of entries to process from the slice.
/// * `symtab` — Symbol table for resolving symbol references.
/// * `_got_base` — Base address of the GOT (reserved for future
///   use when actual writes are implemented).
///
/// # Returns
///
/// The number of relocations successfully processed, or an error
/// if an entry cannot be validated.
pub fn apply_relocations(
    base_addr: u64,
    rela_entries: &[Elf64Rela],
    rela_count: usize,
    symtab: &SymbolTable,
    _got_base: u64,
) -> Result<usize> {
    let effective_count = if rela_count < rela_entries.len() {
        rela_count
    } else {
        rela_entries.len()
    };

    let mut applied: usize = 0;

    for rela in rela_entries.iter().take(effective_count) {
        let rtype = rela.rela_type();
        let sym_idx = rela.sym_index() as usize;

        match rtype {
            R_X86_64_NONE => {
                // No-op relocation; skip.
            }
            R_X86_64_RELATIVE => {
                // B + A: base address plus addend.
                let _value = base_addr
                    .checked_add(rela.r_addend as u64)
                    .ok_or(Error::InvalidArgument)?;
                // Validate target offset is representable.
                let _target = base_addr
                    .checked_add(rela.r_offset)
                    .ok_or(Error::InvalidArgument)?;
                applied = applied.saturating_add(1);
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                // Resolve symbol and write its address.
                let (sym_addr, _name_off) = symtab.lookup_by_index(sym_idx)?;
                let _target = base_addr
                    .checked_add(rela.r_offset)
                    .ok_or(Error::InvalidArgument)?;
                // Value to write is the resolved symbol address.
                let _value = sym_addr;
                applied = applied.saturating_add(1);
            }
            R_X86_64_64 => {
                // S + A: symbol value plus addend.
                let (sym_addr, _name_off) = symtab.lookup_by_index(sym_idx)?;
                let _value = sym_addr
                    .checked_add(rela.r_addend as u64)
                    .ok_or(Error::InvalidArgument)?;
                let _target = base_addr
                    .checked_add(rela.r_offset)
                    .ok_or(Error::InvalidArgument)?;
                applied = applied.saturating_add(1);
            }
            _ => {
                // Unknown relocation type.
                return Err(Error::NotImplemented);
            }
        }
    }

    Ok(applied)
}

// ---------------------------------------------------------------------------
// InterpreterInfo — PT_INTERP content
// ---------------------------------------------------------------------------

/// Maximum length of the interpreter path.
const MAX_INTERP_PATH: usize = 256;

/// Interpreter path extracted from a PT_INTERP segment.
///
/// Stores the path to the dynamic linker (e.g., `/lib/ld-linux.so.2`)
/// as a fixed-size byte array.
#[derive(Debug, Clone, Copy)]
pub struct InterpreterInfo {
    /// Interpreter path bytes (NUL-terminated or truncated).
    pub path: [u8; MAX_INTERP_PATH],
    /// Number of valid bytes in `path` (excluding any NUL).
    pub path_len: usize,
}

impl InterpreterInfo {
    /// Returns the interpreter path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// Parses interpreter path data from a PT_INTERP segment.
///
/// The input `interp_data` is typically a NUL-terminated string.
/// The NUL terminator (if present) is stripped from the stored
/// path. Returns `Err(Error::InvalidArgument)` if the data is
/// empty or exceeds the maximum path length.
pub fn parse_interp(interp_data: &[u8]) -> Result<InterpreterInfo> {
    if interp_data.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Strip trailing NUL if present.
    let data = if interp_data.last() == Some(&0) {
        &interp_data[..interp_data.len() - 1]
    } else {
        interp_data
    };

    if data.is_empty() {
        return Err(Error::InvalidArgument);
    }

    if data.len() > MAX_INTERP_PATH {
        return Err(Error::InvalidArgument);
    }

    let mut info = InterpreterInfo {
        path: [0u8; MAX_INTERP_PATH],
        path_len: data.len(),
    };

    let dest = &mut info.path[..data.len()];
    dest.copy_from_slice(data);

    Ok(info)
}

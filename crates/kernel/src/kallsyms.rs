// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel symbol table lookup (`kallsyms`).
//!
//! Provides a static symbol table that maps kernel symbol names to their
//! virtual addresses and type information. Used by:
//! - Stack trace symbolication
//! - kprobes for attaching probes by name
//! - BPF programs resolving helper addresses
//! - Module loader for kernel symbol resolution
//!
//! # Architecture
//!
//! | Component         | Purpose                                           |
//! |-------------------|---------------------------------------------------|
//! | [`SymbolType`]    | Symbol type (function, data, bss, …)              |
//! | [`KernelSymbol`]  | A single symbol entry (name + address + type)     |
//! | [`KallsymsTable`] | The searchable symbol table                       |
//!
//! # Lookup Modes
//!
//! - **By name**: exact string match, O(n).
//! - **By address**: find the symbol whose address is ≤ `addr` and is the
//!   closest match (symbol + offset), O(n).
//!
//! In a production kernel the table is sorted by address for binary search;
//! ONCRIX uses a linear scan for simplicity at this stage.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum symbol name length (bytes, including NUL terminator).
pub const MAX_SYM_NAME_LEN: usize = 128;

/// Maximum number of symbols in the static table.
pub const MAX_SYMBOLS: usize = 4096;

// ---------------------------------------------------------------------------
// Symbol type
// ---------------------------------------------------------------------------

/// Symbol type, following nm(1) convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymbolType {
    /// Absolute symbol.
    Absolute,
    /// BSS (uninitialized data).
    Bss,
    /// Data section symbol.
    Data,
    /// Read-only data section.
    ReadOnlyData,
    /// Text (code) symbol (function).
    #[default]
    Text,
    /// Weak symbol.
    Weak,
    /// Unknown / other.
    Unknown,
}

impl SymbolType {
    /// Single-character nm(1)-style type code.
    pub fn code(self) -> char {
        match self {
            Self::Absolute => 'A',
            Self::Bss => 'B',
            Self::Data => 'D',
            Self::ReadOnlyData => 'R',
            Self::Text => 'T',
            Self::Weak => 'W',
            Self::Unknown => '?',
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel symbol
// ---------------------------------------------------------------------------

/// A single kernel symbol entry.
#[derive(Clone, Copy)]
pub struct KernelSymbol {
    /// Symbol name (NUL-terminated).
    name: [u8; MAX_SYM_NAME_LEN],
    /// Length of the name string (excluding NUL).
    name_len: u8,
    /// Virtual address of the symbol.
    pub address: u64,
    /// Size of the symbol in bytes (0 if unknown).
    pub size: u32,
    /// Symbol type.
    pub sym_type: SymbolType,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl KernelSymbol {
    /// Create a new kernel symbol entry.
    pub fn new(name: &[u8], address: u64, size: u32, sym_type: SymbolType) -> Self {
        let len = name.len().min(MAX_SYM_NAME_LEN - 1);
        let mut buf = [0u8; MAX_SYM_NAME_LEN];
        buf[..len].copy_from_slice(&name[..len]);
        Self {
            name: buf,
            name_len: len as u8,
            address,
            size,
            sym_type,
            occupied: true,
        }
    }

    /// Return the symbol name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns true if the given address falls within this symbol's range.
    pub fn contains_address(&self, addr: u64) -> bool {
        if addr < self.address {
            return false;
        }
        if self.size == 0 {
            return addr == self.address;
        }
        addr < self.address + self.size as u64
    }
}

impl Default for KernelSymbol {
    fn default() -> Self {
        Self {
            name: [0u8; MAX_SYM_NAME_LEN],
            name_len: 0,
            address: 0,
            size: 0,
            sym_type: SymbolType::Unknown,
            occupied: false,
        }
    }
}

impl core::fmt::Debug for KernelSymbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelSymbol")
            .field("name", &core::str::from_utf8(self.name()).unwrap_or("?"))
            .field("address", &self.address)
            .field("size", &self.size)
            .field("type", &self.sym_type)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Address lookup result
// ---------------------------------------------------------------------------

/// Result of an address-to-symbol lookup.
#[derive(Debug, Clone, Copy)]
pub struct AddrLookup<'a> {
    /// The matched symbol.
    pub symbol: &'a KernelSymbol,
    /// Byte offset from the symbol's base address.
    pub offset: u64,
}

// ---------------------------------------------------------------------------
// Kallsyms table
// ---------------------------------------------------------------------------

/// The kernel symbol table.
pub struct KallsymsTable {
    symbols: [KernelSymbol; MAX_SYMBOLS],
    count: usize,
}

impl KallsymsTable {
    /// Create an empty symbol table.
    pub const fn new() -> Self {
        Self {
            symbols: [KernelSymbol {
                name: [0u8; MAX_SYM_NAME_LEN],
                name_len: 0,
                address: 0,
                size: 0,
                sym_type: SymbolType::Unknown,
                occupied: false,
            }; MAX_SYMBOLS],
            count: 0,
        }
    }

    /// Add a symbol to the table.
    pub fn add(&mut self, sym: KernelSymbol) -> Result<()> {
        if self.count >= MAX_SYMBOLS {
            return Err(Error::OutOfMemory);
        }
        self.symbols[self.count] = sym;
        self.count += 1;
        Ok(())
    }

    /// Add a symbol from components.
    pub fn add_symbol(
        &mut self,
        name: &[u8],
        address: u64,
        size: u32,
        sym_type: SymbolType,
    ) -> Result<()> {
        self.add(KernelSymbol::new(name, address, size, sym_type))
    }

    /// Look up a symbol by exact name.
    pub fn lookup_by_name(&self, name: &[u8]) -> Option<&KernelSymbol> {
        self.symbols[..self.count]
            .iter()
            .find(|s| s.occupied && s.name() == name)
    }

    /// Look up the address of a symbol by name.
    pub fn address_of(&self, name: &[u8]) -> Option<u64> {
        self.lookup_by_name(name).map(|s| s.address)
    }

    /// Look up the symbol closest to the given address (address ≤ addr).
    ///
    /// Returns the symbol and the offset within it.
    pub fn lookup_by_address(&self, addr: u64) -> Option<AddrLookup<'_>> {
        let mut best: Option<&KernelSymbol> = None;
        for sym in self.symbols[..self.count].iter() {
            if !sym.occupied || sym.address > addr {
                continue;
            }
            let is_better = best.map_or(true, |b| sym.address > b.address);
            if is_better {
                best = Some(sym);
            }
        }
        best.map(|sym| AddrLookup {
            symbol: sym,
            offset: addr - sym.address,
        })
    }

    /// Return all symbols of a given type.
    ///
    /// Writes matching symbols into `out` and returns the count.
    pub fn by_type<'a>(&'a self, sym_type: SymbolType, out: &mut [&'a KernelSymbol]) -> usize {
        let mut n = 0;
        for sym in self.symbols[..self.count].iter() {
            if n >= out.len() {
                break;
            }
            if sym.occupied && sym.sym_type == sym_type {
                out[n] = sym;
                n += 1;
            }
        }
        n
    }

    /// Remove a symbol by name.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.symbols[..self.count]
            .iter()
            .position(|s| s.occupied && s.name() == name)
            .ok_or(Error::NotFound)?;
        self.symbols[pos].occupied = false;
        // Compact: shift left.
        for i in pos..self.count - 1 {
            self.symbols[i] = self.symbols[i + 1];
        }
        self.symbols[self.count - 1] = KernelSymbol::default();
        self.count -= 1;
        Ok(())
    }

    /// Number of symbols in the table.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for KallsymsTable {
    fn default() -> Self {
        Self::new()
    }
}

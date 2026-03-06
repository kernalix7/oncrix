// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel module binary loader with symbol resolution.
//!
//! Extends the module registry (`kmod`) with the low-level
//! machinery for loading module binaries: ELF section parsing,
//! relocation processing, symbol table management, and PLT/GOT
//! fixups. While `kmod` tracks module lifecycle and dependencies
//! at a high level, this module handles the actual binary image
//! loading pipeline.
//!
//! # Architecture
//!
//! ```text
//! load_image(bytes)
//!   ├── parse_header()        → validate ELF magic, arch, type
//!   ├── load_sections()       → copy .text, .data, .rodata, .bss
//!   ├── process_relocations() → apply R_X86_64_* fixups
//!   └── resolve_symbols()     → link undefined symbols to kernel
//!
//! SymbolTable
//!   ├── export_symbol(name, addr)   → add to kernel symbol namespace
//!   ├── resolve(name)               → lookup by name
//!   └── symbol_count()              → number of exported symbols
//! ```
//!
//! # Symbol Resolution
//!
//! When a module references an undefined symbol, the loader
//! searches the global kernel symbol table. If found, the
//! relocation is patched with the symbol's address. Unresolved
//! symbols cause the load to fail.
//!
//! Reference: Linux `kernel/module/main.c`,
//! `kernel/module/kallsyms.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of exported kernel symbols.
const MAX_SYMBOLS: usize = 512;

/// Maximum symbol name length in bytes.
const MAX_SYMBOL_NAME: usize = 64;

/// Maximum number of ELF sections tracked per module.
const MAX_SECTIONS: usize = 32;

/// Maximum section name length in bytes.
const MAX_SECTION_NAME: usize = 32;

/// Maximum number of relocations per module.
const MAX_RELOCATIONS: usize = 256;

/// Maximum number of modules being loaded concurrently.
const MAX_LOADING: usize = 8;

/// ELF magic: 0x7F 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class for 64-bit objects.
const _ELFCLASS64: u8 = 2;

/// ELF data encoding: little-endian.
const _ELFDATA2LSB: u8 = 1;

/// ELF machine type: x86_64.
const _EM_X86_64: u16 = 62;

/// ELF type: relocatable object.
const _ET_REL: u16 = 1;

// ── RelocationType ─────────────────────────────────────────────

/// x86_64 ELF relocation types supported by the module loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelocationType {
    /// R_X86_64_NONE (0) — no relocation.
    #[default]
    None,
    /// R_X86_64_64 (1) — direct 64-bit.
    Direct64,
    /// R_X86_64_PC32 (2) — PC-relative 32-bit.
    Pc32,
    /// R_X86_64_GOT32 (3) — 32-bit GOT entry.
    Got32,
    /// R_X86_64_PLT32 (4) — 32-bit PLT entry.
    Plt32,
    /// R_X86_64_32 (10) — direct 32-bit zero-extended.
    Direct32,
    /// R_X86_64_32S (11) — direct 32-bit sign-extended.
    Direct32S,
}

impl RelocationType {
    /// Convert from an ELF relocation type number.
    pub const fn from_elf(r_type: u32) -> Option<Self> {
        match r_type {
            0 => Some(Self::None),
            1 => Some(Self::Direct64),
            2 => Some(Self::Pc32),
            3 => Some(Self::Got32),
            4 => Some(Self::Plt32),
            10 => Some(Self::Direct32),
            11 => Some(Self::Direct32S),
            _ => None,
        }
    }
}

// ── SymbolKind ─────────────────────────────────────────────────

/// Kind of exported kernel symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymbolKind {
    /// Function symbol (STT_FUNC).
    #[default]
    Function,
    /// Data object symbol (STT_OBJECT).
    Object,
    /// Section symbol (STT_SECTION).
    Section,
    /// Other / unknown.
    Other,
}

// ── SymbolBinding ──────────────────────────────────────────────

/// ELF symbol binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymbolBinding {
    /// Local scope (STB_LOCAL).
    Local,
    /// Global scope (STB_GLOBAL).
    #[default]
    Global,
    /// Weak binding (STB_WEAK).
    Weak,
}

// ── KernelSymbol ───────────────────────────────────────────────

/// An exported kernel symbol in the global symbol table.
#[derive(Clone, Copy)]
pub struct KernelSymbol {
    /// Symbol name (fixed-size, zero-padded).
    name: [u8; MAX_SYMBOL_NAME],
    /// Valid length of `name`.
    name_len: usize,
    /// Virtual address of the symbol.
    pub addr: u64,
    /// Kind of symbol (function, data, etc.).
    pub kind: SymbolKind,
    /// Binding (local, global, weak).
    pub binding: SymbolBinding,
    /// Module ID that owns this symbol (0 = built-in kernel).
    pub owner_module: u64,
    /// Whether this symbol slot is in use.
    pub active: bool,
}

impl Default for KernelSymbol {
    fn default() -> Self {
        Self::empty()
    }
}

impl KernelSymbol {
    /// Create an empty (unused) symbol entry.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_SYMBOL_NAME],
            name_len: 0,
            addr: 0,
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            owner_module: 0,
            active: false,
        }
    }

    /// Return the symbol name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

impl core::fmt::Debug for KernelSymbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelSymbol")
            .field(
                "name",
                &core::str::from_utf8(self.name_bytes()).unwrap_or("<invalid>"),
            )
            .field("addr", &self.addr)
            .field("kind", &self.kind)
            .field("binding", &self.binding)
            .field("owner", &self.owner_module)
            .finish()
    }
}

// ── SymbolTable ────────────────────────────────────────────────

/// Global kernel symbol table.
///
/// Stores all exported symbols from the kernel core and loaded
/// modules. The module loader queries this table to resolve
/// undefined symbol references during relocation processing.
pub struct SymbolTable {
    /// Symbol storage.
    symbols: [KernelSymbol; MAX_SYMBOLS],
    /// Number of active symbols.
    count: usize,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolTable {
    /// Create an empty symbol table.
    pub const fn new() -> Self {
        Self {
            symbols: [KernelSymbol::empty(); MAX_SYMBOLS],
            count: 0,
        }
    }

    /// Export a symbol to the global namespace.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if a symbol with the same
    ///   name already exists.
    /// - [`Error::InvalidArgument`] if the name is empty or
    ///   too long.
    pub fn export_symbol(
        &mut self,
        name: &[u8],
        addr: u64,
        kind: SymbolKind,
        binding: SymbolBinding,
        owner: u64,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_SYMBOL_NAME {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate.
        if self.resolve(name).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .symbols
            .iter_mut()
            .find(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        slot.name = [0u8; MAX_SYMBOL_NAME];
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.addr = addr;
        slot.kind = kind;
        slot.binding = binding;
        slot.owner_module = owner;
        slot.active = true;
        self.count += 1;
        Ok(())
    }

    /// Resolve a symbol by name.
    ///
    /// Returns the symbol if found, `None` otherwise. Weak
    /// symbols are returned only if no global symbol with the
    /// same name exists (global symbols take precedence).
    pub fn resolve(&self, name: &[u8]) -> Option<&KernelSymbol> {
        let mut weak_match: Option<&KernelSymbol> = None;

        for sym in &self.symbols {
            if !sym.active {
                continue;
            }
            if sym.name_bytes() != name {
                continue;
            }
            if sym.binding == SymbolBinding::Global {
                return Some(sym);
            }
            if sym.binding == SymbolBinding::Weak && weak_match.is_none() {
                weak_match = Some(sym);
            }
        }

        weak_match
    }

    /// Remove all symbols owned by a specific module.
    ///
    /// Returns the number of symbols removed.
    pub fn remove_module_symbols(&mut self, module_id: u64) -> usize {
        let mut removed = 0;
        for sym in &mut self.symbols {
            if sym.active && sym.owner_module == module_id {
                sym.active = false;
                removed += 1;
            }
        }
        self.count = self.count.saturating_sub(removed);
        removed
    }

    /// Return the number of active symbols.
    pub fn symbol_count(&self) -> usize {
        self.count
    }

    /// Return `true` if the symbol table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── SectionInfo ────────────────────────────────────────────────

/// Describes a single ELF section in a loaded module.
#[derive(Debug, Clone, Copy)]
pub struct SectionInfo {
    /// Section name (fixed buffer, zero-padded).
    pub name: [u8; MAX_SECTION_NAME],
    /// Valid length of `name`.
    pub name_len: usize,
    /// Virtual address where the section is loaded.
    pub vaddr: u64,
    /// Size of the section in bytes.
    pub size: u64,
    /// Section flags (SHF_ALLOC, SHF_WRITE, SHF_EXECINSTR).
    pub flags: u32,
    /// Section type (SHT_PROGBITS, SHT_NOBITS, etc.).
    pub sh_type: u32,
    /// Alignment requirement.
    pub alignment: u64,
    /// Whether this section slot is in use.
    pub active: bool,
}

impl Default for SectionInfo {
    fn default() -> Self {
        Self::empty()
    }
}

impl SectionInfo {
    /// Create an empty section descriptor.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_SECTION_NAME],
            name_len: 0,
            vaddr: 0,
            size: 0,
            flags: 0,
            sh_type: 0,
            alignment: 0,
            active: false,
        }
    }

    /// Return the section name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Whether this section is executable.
    pub const fn is_executable(&self) -> bool {
        self.flags & 0x4 != 0 // SHF_EXECINSTR
    }

    /// Whether this section is writable.
    pub const fn is_writable(&self) -> bool {
        self.flags & 0x1 != 0 // SHF_WRITE
    }
}

// ── RelocationEntry ────────────────────────────────────────────

/// A single relocation to be applied during module loading.
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    /// Offset within the section where the fixup is applied.
    pub offset: u64,
    /// Index of the section containing the fixup site.
    pub section_idx: u16,
    /// Relocation type.
    pub rel_type: RelocationType,
    /// Name of the referenced symbol.
    pub symbol_name: [u8; MAX_SYMBOL_NAME],
    /// Valid length of `symbol_name`.
    pub symbol_name_len: usize,
    /// Addend (for RELA relocations).
    pub addend: i64,
    /// Whether this relocation has been resolved.
    pub resolved: bool,
    /// Resolved target address (valid only when `resolved`).
    pub target_addr: u64,
    /// Whether this relocation slot is in use.
    pub active: bool,
}

impl Default for RelocationEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl RelocationEntry {
    /// Create an empty relocation entry.
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            section_idx: 0,
            rel_type: RelocationType::None,
            symbol_name: [0u8; MAX_SYMBOL_NAME],
            symbol_name_len: 0,
            addend: 0,
            resolved: false,
            target_addr: 0,
            active: false,
        }
    }

    /// Return the symbol name as a byte slice.
    pub fn symbol_bytes(&self) -> &[u8] {
        &self.symbol_name[..self.symbol_name_len]
    }
}

// ── LoadState ──────────────────────────────────────────────────

/// State of a module currently being loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadState {
    /// Slot is free.
    #[default]
    Idle,
    /// ELF header parsed, sections being loaded.
    Parsing,
    /// Sections loaded, relocations being processed.
    Relocating,
    /// Relocations applied, module ready for init.
    Ready,
    /// Load failed.
    Failed,
}

// ── LoadContext ─────────────────────────────────────────────────

/// Tracks the state of a module that is in the process of being
/// loaded.
pub struct LoadContext {
    /// Module ID (assigned by the higher-level module registry).
    pub module_id: u64,
    /// Current loading state.
    pub state: LoadState,
    /// Parsed ELF sections.
    pub sections: [SectionInfo; MAX_SECTIONS],
    /// Number of active section entries.
    pub section_count: usize,
    /// Relocations to process.
    pub relocations: [RelocationEntry; MAX_RELOCATIONS],
    /// Number of active relocation entries.
    pub relocation_count: usize,
    /// Base address where the module image is mapped.
    pub load_base: u64,
    /// Total size of the loaded image.
    pub load_size: u64,
    /// Entry point address (after relocation).
    pub entry_point: u64,
    /// Whether this context slot is in use.
    pub active: bool,
}

impl Default for LoadContext {
    fn default() -> Self {
        Self::empty()
    }
}

impl LoadContext {
    /// Create an empty (unused) load context.
    #[allow(clippy::large_stack_frames)]
    pub fn empty() -> Self {
        Self {
            module_id: 0,
            state: LoadState::Idle,
            sections: [SectionInfo::empty(); MAX_SECTIONS],
            section_count: 0,
            relocations: [RelocationEntry::empty(); MAX_RELOCATIONS],
            relocation_count: 0,
            load_base: 0,
            load_size: 0,
            entry_point: 0,
            active: false,
        }
    }

    /// Register a section for the module being loaded.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the section table is full.
    /// - [`Error::InvalidArgument`] if the name is too long.
    pub fn add_section(
        &mut self,
        name: &[u8],
        vaddr: u64,
        size: u64,
        flags: u32,
        sh_type: u32,
        alignment: u64,
    ) -> Result<usize> {
        if name.len() > MAX_SECTION_NAME {
            return Err(Error::InvalidArgument);
        }
        if self.section_count >= MAX_SECTIONS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.section_count;
        let sec = &mut self.sections[idx];

        sec.name = [0u8; MAX_SECTION_NAME];
        let copy_len = name.len().min(MAX_SECTION_NAME);
        sec.name[..copy_len].copy_from_slice(&name[..copy_len]);
        sec.name_len = copy_len;
        sec.vaddr = vaddr;
        sec.size = size;
        sec.flags = flags;
        sec.sh_type = sh_type;
        sec.alignment = alignment;
        sec.active = true;

        self.section_count += 1;
        Ok(idx)
    }

    /// Register a relocation for the module being loaded.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the relocation table is full.
    /// - [`Error::InvalidArgument`] if the symbol name is too
    ///   long or the relocation type is unsupported.
    pub fn add_relocation(
        &mut self,
        offset: u64,
        section_idx: u16,
        rel_type: u32,
        symbol_name: &[u8],
        addend: i64,
    ) -> Result<usize> {
        if symbol_name.len() > MAX_SYMBOL_NAME {
            return Err(Error::InvalidArgument);
        }
        let rtype = RelocationType::from_elf(rel_type).ok_or(Error::InvalidArgument)?;
        if self.relocation_count >= MAX_RELOCATIONS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.relocation_count;
        let rel = &mut self.relocations[idx];

        rel.offset = offset;
        rel.section_idx = section_idx;
        rel.rel_type = rtype;
        rel.symbol_name = [0u8; MAX_SYMBOL_NAME];
        let copy_len = symbol_name.len().min(MAX_SYMBOL_NAME);
        rel.symbol_name[..copy_len].copy_from_slice(&symbol_name[..copy_len]);
        rel.symbol_name_len = copy_len;
        rel.addend = addend;
        rel.resolved = false;
        rel.target_addr = 0;
        rel.active = true;

        self.relocation_count += 1;
        Ok(idx)
    }

    /// Attempt to resolve all relocations against the symbol
    /// table.
    ///
    /// Returns `Ok(count)` with the number of successfully
    /// resolved relocations. Unresolved relocations remain
    /// in the table with `resolved == false`.
    pub fn resolve_all(&mut self, symtab: &SymbolTable) -> Result<usize> {
        let mut resolved = 0usize;

        for rel in &mut self.relocations[..self.relocation_count] {
            if !rel.active || rel.resolved {
                continue;
            }
            if let Some(sym) = symtab.resolve(rel.symbol_bytes()) {
                rel.target_addr = sym.addr;
                rel.resolved = true;
                resolved += 1;
            }
        }

        Ok(resolved)
    }

    /// Check whether all relocations are resolved.
    pub fn all_resolved(&self) -> bool {
        self.relocations[..self.relocation_count]
            .iter()
            .filter(|r| r.active)
            .all(|r| r.resolved)
    }

    /// Count unresolved relocations.
    pub fn unresolved_count(&self) -> usize {
        self.relocations[..self.relocation_count]
            .iter()
            .filter(|r| r.active && !r.resolved)
            .count()
    }

    /// Find a section by name.
    pub fn find_section(&self, name: &[u8]) -> Option<&SectionInfo> {
        self.sections[..self.section_count]
            .iter()
            .find(|s| s.active && s.name_bytes() == name)
    }
}

// ── ModuleLoader ───────────────────────────────────────────────

/// Top-level module loader that manages concurrent load
/// operations and the global symbol table.
pub struct ModuleLoader {
    /// Global symbol table shared across all modules.
    pub symtab: SymbolTable,
    /// Active load contexts (one per module being loaded).
    contexts: [LoadContext; MAX_LOADING],
    /// Number of active load operations.
    active_loads: usize,
    /// Total number of modules successfully loaded.
    total_loaded: u64,
    /// Total number of load failures.
    total_failures: u64,
}

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleLoader {
    /// Create a new module loader with an empty symbol table.
    #[allow(clippy::large_stack_frames)]
    pub fn new() -> Self {
        const EMPTY_CTX: LoadContext = LoadContext {
            module_id: 0,
            state: LoadState::Idle,
            sections: [SectionInfo::empty(); MAX_SECTIONS],
            section_count: 0,
            relocations: [RelocationEntry::empty(); MAX_RELOCATIONS],
            relocation_count: 0,
            load_base: 0,
            load_size: 0,
            entry_point: 0,
            active: false,
        };
        Self {
            symtab: SymbolTable::new(),
            contexts: [EMPTY_CTX; MAX_LOADING],
            active_loads: 0,
            total_loaded: 0,
            total_failures: 0,
        }
    }

    /// Begin loading a module, returning a context index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all load slots are busy.
    pub fn begin_load(&mut self, module_id: u64) -> Result<usize> {
        let idx = self
            .contexts
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        self.contexts[idx] = LoadContext::empty();
        self.contexts[idx].module_id = module_id;
        self.contexts[idx].state = LoadState::Parsing;
        self.contexts[idx].active = true;
        self.active_loads += 1;
        Ok(idx)
    }

    /// Validate an ELF header from the first bytes of a module
    /// image.
    ///
    /// Checks the ELF magic number. Returns `Ok(())` if valid.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the header is too short
    ///   or has incorrect magic.
    pub fn validate_elf_header(&self, header: &[u8]) -> Result<()> {
        if header.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        if header[..4] != ELF_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Get a mutable reference to a load context.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the index is out of range or
    ///   the slot is inactive.
    pub fn context_mut(&mut self, idx: usize) -> Result<&mut LoadContext> {
        if idx >= MAX_LOADING {
            return Err(Error::NotFound);
        }
        if !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.contexts[idx])
    }

    /// Get a shared reference to a load context.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the index is out of range or
    ///   the slot is inactive.
    pub fn context(&self, idx: usize) -> Result<&LoadContext> {
        if idx >= MAX_LOADING {
            return Err(Error::NotFound);
        }
        if !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.contexts[idx])
    }

    /// Resolve all relocations for a load context against the
    /// global symbol table.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the context index is invalid.
    /// - [`Error::IoError`] if unresolved symbols remain after
    ///   resolution.
    pub fn resolve_relocations(&mut self, idx: usize) -> Result<usize> {
        if idx >= MAX_LOADING || !self.contexts[idx].active {
            return Err(Error::NotFound);
        }

        // Hoist immutable borrow data before mutable borrow.
        let resolved = self.contexts[idx].resolve_all(&self.symtab)?;

        if !self.contexts[idx].all_resolved() {
            self.contexts[idx].state = LoadState::Failed;
            return Err(Error::IoError);
        }

        self.contexts[idx].state = LoadState::Ready;
        Ok(resolved)
    }

    /// Finalise a successful load, releasing the load context.
    ///
    /// The caller is responsible for running the module's init
    /// function after this returns.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the context index is invalid.
    /// - [`Error::InvalidArgument`] if the context is not in
    ///   the `Ready` state.
    pub fn finish_load(&mut self, idx: usize) -> Result<u64> {
        if idx >= MAX_LOADING || !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        if self.contexts[idx].state != LoadState::Ready {
            return Err(Error::InvalidArgument);
        }

        let module_id = self.contexts[idx].module_id;
        self.contexts[idx].active = false;
        self.contexts[idx].state = LoadState::Idle;
        self.active_loads = self.active_loads.saturating_sub(1);
        self.total_loaded = self.total_loaded.saturating_add(1);
        Ok(module_id)
    }

    /// Abort a load, releasing the load context and recording
    /// the failure.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the context index is invalid.
    pub fn abort_load(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_LOADING || !self.contexts[idx].active {
            return Err(Error::NotFound);
        }

        // Remove any symbols exported by this module.
        let mod_id = self.contexts[idx].module_id;
        self.symtab.remove_module_symbols(mod_id);

        self.contexts[idx].active = false;
        self.contexts[idx].state = LoadState::Idle;
        self.active_loads = self.active_loads.saturating_sub(1);
        self.total_failures = self.total_failures.saturating_add(1);
        Ok(())
    }

    /// Return the number of active load operations.
    pub fn active_loads(&self) -> usize {
        self.active_loads
    }

    /// Return the total number of successfully loaded modules.
    pub fn total_loaded(&self) -> u64 {
        self.total_loaded
    }

    /// Return the total number of failed load attempts.
    pub fn total_failures(&self) -> u64 {
        self.total_failures
    }
}

impl core::fmt::Debug for ModuleLoader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleLoader")
            .field("symbols", &self.symtab.symbol_count())
            .field("active_loads", &self.active_loads)
            .field("total_loaded", &self.total_loaded)
            .field("total_failures", &self.total_failures)
            .finish()
    }
}

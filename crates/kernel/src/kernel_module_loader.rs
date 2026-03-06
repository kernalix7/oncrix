// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel module loading framework.
//!
//! Provides the infrastructure for loading, unloading, and managing
//! kernel modules at runtime.  Key responsibilities:
//!
//! - **Dependency resolution**: modules declare their requirements;
//!   the loader ensures all dependencies are satisfied before
//!   initialisation.
//! - **Symbol export/import**: modules export named symbols that
//!   other modules can import; the loader maintains a global
//!   symbol table.
//! - **Lifecycle management**: load, init, live, unloading, unloaded
//!   state machine with reference counting to prevent unloading a
//!   module that other modules depend on.
//!
//! # Architecture
//!
//! ```text
//! ModuleLoader
//!  +-- modules: [KernelModule; MAX_MODULES]
//!  |    +-- KernelModule
//!  |    |    +-- id, name, state, ref_count
//!  |    |    +-- deps: [ModuleDep; MAX_DEPS_PER_MOD]
//!  |    |    +-- exports: [SymbolExport; MAX_EXPORTS_PER_MOD]
//!  |    +-- ...
//!  +-- symbol_table: [GlobalSymbol; MAX_GLOBAL_SYMBOLS]
//!  +-- ModuleLoaderStats
//! ```
//!
//! Reference: Linux `kernel/module/main.c`,
//! `include/linux/module.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum loaded modules.
const MAX_MODULES: usize = 128;

/// Maximum dependencies per module.
const MAX_DEPS_PER_MOD: usize = 16;

/// Maximum symbol exports per module.
const MAX_EXPORTS_PER_MOD: usize = 32;

/// Maximum symbols in the global symbol table.
const MAX_GLOBAL_SYMBOLS: usize = 1024;

/// Name buffer length.
const MAX_NAME_LEN: usize = 64;

/// Symbol name length.
const MAX_SYM_NAME_LEN: usize = 64;

/// Version string length.
const MAX_VERSION_LEN: usize = 32;

// ── ModuleState ────────────────────────────────────────────────────

/// Lifecycle state of a kernel module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    /// Slot is free.
    Free,
    /// Module image is loaded, dependencies not yet resolved.
    Loaded,
    /// Dependencies resolved, ready for initialisation.
    Resolved,
    /// Module init function is executing.
    Initialising,
    /// Module is fully initialised and live.
    Live,
    /// Module is being unloaded.
    Unloading,
    /// Module has been unloaded and slot is reclaimable.
    Unloaded,
}

// ── SymbolVisibility ───────────────────────────────────────────────

/// Visibility of an exported symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolVisibility {
    /// Symbol is visible to all modules.
    Public,
    /// Symbol is visible only to modules declaring a
    /// compatible license (GPL-like).
    GplOnly,
}

// ── SymbolExport ───────────────────────────────────────────────────

/// A symbol exported by a module.
#[derive(Clone, Copy)]
pub struct SymbolExport {
    /// Symbol name.
    name: [u8; MAX_SYM_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Address / token of the symbol.
    address: u64,
    /// Visibility.
    visibility: SymbolVisibility,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl SymbolExport {
    /// Creates an empty symbol slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_SYM_NAME_LEN],
            name_len: 0,
            address: 0,
            visibility: SymbolVisibility::Public,
            occupied: false,
        }
    }

    /// Returns the symbol name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the symbol address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Returns the visibility.
    pub const fn visibility(&self) -> SymbolVisibility {
        self.visibility
    }
}

// ── GlobalSymbol ───────────────────────────────────────────────────

/// Entry in the global symbol table.
#[derive(Clone, Copy)]
pub struct GlobalSymbol {
    /// Symbol name.
    name: [u8; MAX_SYM_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Resolved address.
    address: u64,
    /// Module id that owns this symbol.
    owner_id: u64,
    /// Visibility.
    visibility: SymbolVisibility,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl GlobalSymbol {
    /// Creates an empty global symbol slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_SYM_NAME_LEN],
            name_len: 0,
            address: 0,
            owner_id: 0,
            visibility: SymbolVisibility::Public,
            occupied: false,
        }
    }

    /// Returns the symbol name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the owning module id.
    pub const fn owner_id(&self) -> u64 {
        self.owner_id
    }
}

// ── ModuleDep ──────────────────────────────────────────────────────

/// A declared dependency on another module.
#[derive(Clone, Copy)]
pub struct ModuleDep {
    /// Name of the required module.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Minimum version (encoded as major*10000 + minor*100 + patch).
    min_version: u32,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Whether this dependency has been resolved.
    resolved: bool,
    /// Module id of the resolved dependency (0 if unresolved).
    resolved_id: u64,
}

impl ModuleDep {
    /// Creates an empty dependency slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            min_version: 0,
            occupied: false,
            resolved: false,
            resolved_id: 0,
        }
    }
}

// ── KernelModule ───────────────────────────────────────────────────

/// A single loaded kernel module.
pub struct KernelModule {
    /// Unique module identifier.
    mod_id: u64,
    /// Module name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Version string.
    version: [u8; MAX_VERSION_LEN],
    /// Version length.
    version_len: usize,
    /// Encoded version for comparison.
    version_code: u32,
    /// Lifecycle state.
    state: ModuleState,
    /// Reference count (modules depending on this one).
    ref_count: u32,
    /// Dependencies.
    deps: [ModuleDep; MAX_DEPS_PER_MOD],
    /// Number of declared dependencies.
    nr_deps: usize,
    /// Exported symbols.
    exports: [SymbolExport; MAX_EXPORTS_PER_MOD],
    /// Number of exports.
    nr_exports: usize,
    /// Load address (base of the module image).
    load_addr: u64,
    /// Size of the module image in bytes.
    image_size: u64,
    /// Load timestamp (ticks).
    loaded_at: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl KernelModule {
    /// Creates an empty module slot.
    pub const fn new() -> Self {
        Self {
            mod_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            version: [0u8; MAX_VERSION_LEN],
            version_len: 0,
            version_code: 0,
            state: ModuleState::Free,
            ref_count: 0,
            deps: [const { ModuleDep::new() }; MAX_DEPS_PER_MOD],
            nr_deps: 0,
            exports: [const { SymbolExport::new() }; MAX_EXPORTS_PER_MOD],
            nr_exports: 0,
            load_addr: 0,
            image_size: 0,
            loaded_at: 0,
            occupied: false,
        }
    }

    /// Returns the module identifier.
    pub const fn mod_id(&self) -> u64 {
        self.mod_id
    }

    /// Returns the module name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the state.
    pub const fn state(&self) -> ModuleState {
        self.state
    }

    /// Returns the reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns the number of dependencies.
    pub const fn nr_deps(&self) -> usize {
        self.nr_deps
    }

    /// Returns the number of exports.
    pub const fn nr_exports(&self) -> usize {
        self.nr_exports
    }

    /// Returns the load address.
    pub const fn load_addr(&self) -> u64 {
        self.load_addr
    }

    /// Returns the image size.
    pub const fn image_size(&self) -> u64 {
        self.image_size
    }
}

// ── ModuleLoaderStats ──────────────────────────────────────────────

/// Statistics for the module loader.
#[derive(Clone, Copy)]
pub struct ModuleLoaderStats {
    /// Total modules loaded.
    pub loads: u64,
    /// Total modules unloaded.
    pub unloads: u64,
    /// Total dependency resolutions.
    pub dep_resolves: u64,
    /// Total symbol lookups.
    pub sym_lookups: u64,
    /// Total failed loads.
    pub load_failures: u64,
}

impl ModuleLoaderStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            loads: 0,
            unloads: 0,
            dep_resolves: 0,
            sym_lookups: 0,
            load_failures: 0,
        }
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ── ModuleLoader ───────────────────────────────────────────────────

/// System-wide kernel module loader.
pub struct ModuleLoader {
    /// Module table.
    modules: [KernelModule; MAX_MODULES],
    /// Global symbol table.
    symbols: [GlobalSymbol; MAX_GLOBAL_SYMBOLS],
    /// Number of loaded modules.
    nr_modules: usize,
    /// Number of global symbols.
    nr_symbols: usize,
    /// Next module identifier.
    next_mod_id: u64,
    /// Statistics.
    stats: ModuleLoaderStats,
}

impl ModuleLoader {
    /// Creates a new module loader.
    pub const fn new() -> Self {
        Self {
            modules: [const { KernelModule::new() }; MAX_MODULES],
            symbols: [const { GlobalSymbol::new() }; MAX_GLOBAL_SYMBOLS],
            nr_modules: 0,
            nr_symbols: 0,
            next_mod_id: 1,
            stats: ModuleLoaderStats::new(),
        }
    }

    /// Loads a module image (transitions to Loaded state).
    pub fn load(
        &mut self,
        name: &[u8],
        version: &[u8],
        version_code: u32,
        load_addr: u64,
        image_size: u64,
        now: u64,
    ) -> Result<u64> {
        // Check for duplicate.
        if self.find_module_by_name(name).is_ok() {
            self.stats.load_failures += 1;
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .modules
            .iter()
            .position(|m| !m.occupied)
            .ok_or(Error::OutOfMemory)?;

        let mod_id = self.next_mod_id;
        self.next_mod_id += 1;

        let m = &mut self.modules[slot];
        m.mod_id = mod_id;
        let nlen = name.len().min(MAX_NAME_LEN);
        m.name[..nlen].copy_from_slice(&name[..nlen]);
        m.name_len = nlen;
        let vlen = version.len().min(MAX_VERSION_LEN);
        m.version[..vlen].copy_from_slice(&version[..vlen]);
        m.version_len = vlen;
        m.version_code = version_code;
        m.state = ModuleState::Loaded;
        m.ref_count = 0;
        m.nr_deps = 0;
        m.nr_exports = 0;
        m.load_addr = load_addr;
        m.image_size = image_size;
        m.loaded_at = now;
        m.occupied = true;

        self.nr_modules += 1;
        self.stats.loads += 1;
        Ok(mod_id)
    }

    /// Declares a dependency for a loaded module.
    pub fn add_dependency(&mut self, mod_id: u64, dep_name: &[u8], min_version: u32) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        let m = &self.modules[idx];
        if m.state != ModuleState::Loaded {
            return Err(Error::InvalidArgument);
        }
        if m.nr_deps >= MAX_DEPS_PER_MOD {
            return Err(Error::OutOfMemory);
        }
        let didx = m.nr_deps;
        let dep = &mut self.modules[idx].deps[didx];
        let len = dep_name.len().min(MAX_NAME_LEN);
        dep.name[..len].copy_from_slice(&dep_name[..len]);
        dep.name_len = len;
        dep.min_version = min_version;
        dep.occupied = true;
        dep.resolved = false;
        self.modules[idx].nr_deps += 1;
        Ok(())
    }

    /// Declares a symbol export for a module.
    pub fn add_export(
        &mut self,
        mod_id: u64,
        sym_name: &[u8],
        address: u64,
        visibility: SymbolVisibility,
    ) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        let m = &self.modules[idx];
        if m.state != ModuleState::Loaded && m.state != ModuleState::Resolved {
            return Err(Error::InvalidArgument);
        }
        if m.nr_exports >= MAX_EXPORTS_PER_MOD {
            return Err(Error::OutOfMemory);
        }
        let eidx = m.nr_exports;
        let exp = &mut self.modules[idx].exports[eidx];
        let len = sym_name.len().min(MAX_SYM_NAME_LEN);
        exp.name[..len].copy_from_slice(&sym_name[..len]);
        exp.name_len = len;
        exp.address = address;
        exp.visibility = visibility;
        exp.occupied = true;
        self.modules[idx].nr_exports += 1;
        Ok(())
    }

    /// Resolves all dependencies of a module.
    pub fn resolve_deps(&mut self, mod_id: u64) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        if self.modules[idx].state != ModuleState::Loaded {
            return Err(Error::InvalidArgument);
        }

        // Check each dependency.
        let nr_deps = self.modules[idx].nr_deps;
        for d in 0..nr_deps {
            let dep = &self.modules[idx].deps[d];
            if !dep.occupied || dep.resolved {
                continue;
            }
            let dep_name = &dep.name[..dep.name_len];
            let min_ver = dep.min_version;

            // Search for a live module matching the name.
            let found = self.modules.iter().position(|m| {
                m.occupied
                    && m.state == ModuleState::Live
                    && m.name_len == dep_name.len()
                    && m.name[..m.name_len] == *dep_name
                    && m.version_code >= min_ver
            });

            match found {
                Some(dep_idx) => {
                    let dep_mod_id = self.modules[dep_idx].mod_id;
                    self.modules[idx].deps[d].resolved = true;
                    self.modules[idx].deps[d].resolved_id = dep_mod_id;
                    self.modules[dep_idx].ref_count += 1;
                    self.stats.dep_resolves += 1;
                }
                None => {
                    return Err(Error::NotFound);
                }
            }
        }

        self.modules[idx].state = ModuleState::Resolved;
        Ok(())
    }

    /// Initialises a resolved module (Resolved -> Live).
    pub fn init_module(&mut self, mod_id: u64) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        if self.modules[idx].state != ModuleState::Resolved {
            return Err(Error::InvalidArgument);
        }

        self.modules[idx].state = ModuleState::Initialising;

        // Register exports in the global symbol table.
        let nr_exports = self.modules[idx].nr_exports;
        for e in 0..nr_exports {
            let exp = self.modules[idx].exports[e];
            if !exp.occupied {
                continue;
            }
            let name_copy: [u8; MAX_SYM_NAME_LEN] = exp.name;
            self.register_global_symbol(
                &name_copy[..exp.name_len],
                exp.address,
                mod_id,
                exp.visibility,
            )?;
        }

        self.modules[idx].state = ModuleState::Live;
        Ok(())
    }

    /// Begins unloading a live module.
    pub fn begin_unload(&mut self, mod_id: u64) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        if self.modules[idx].state != ModuleState::Live {
            return Err(Error::InvalidArgument);
        }
        if self.modules[idx].ref_count > 0 {
            return Err(Error::Busy);
        }

        self.modules[idx].state = ModuleState::Unloading;
        Ok(())
    }

    /// Completes unloading: removes symbols and releases deps.
    pub fn finish_unload(&mut self, mod_id: u64) -> Result<()> {
        let idx = self.find_module(mod_id)?;
        if self.modules[idx].state != ModuleState::Unloading {
            return Err(Error::InvalidArgument);
        }

        // Remove global symbols owned by this module.
        for sym in &mut self.symbols {
            if sym.occupied && sym.owner_id == mod_id {
                sym.occupied = false;
                self.nr_symbols = self.nr_symbols.saturating_sub(1);
            }
        }

        // Release dependency references.
        let nr_deps = self.modules[idx].nr_deps;
        for d in 0..nr_deps {
            let dep = &self.modules[idx].deps[d];
            if dep.occupied && dep.resolved {
                let dep_id = dep.resolved_id;
                if let Some(didx) = self
                    .modules
                    .iter()
                    .position(|m| m.occupied && m.mod_id == dep_id)
                {
                    self.modules[didx].ref_count = self.modules[didx].ref_count.saturating_sub(1);
                }
            }
        }

        // Clear the module slot.
        self.modules[idx] = KernelModule::new();
        self.nr_modules = self.nr_modules.saturating_sub(1);
        self.stats.unloads += 1;
        Ok(())
    }

    /// Looks up a global symbol by name.
    pub fn lookup_symbol(&mut self, name: &[u8]) -> Result<u64> {
        self.stats.sym_lookups += 1;
        self.symbols
            .iter()
            .find(|s| s.occupied && s.name_len == name.len() && s.name[..s.name_len] == *name)
            .map(|s| s.address)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of loaded modules.
    pub const fn nr_modules(&self) -> usize {
        self.nr_modules
    }

    /// Returns the number of global symbols.
    pub const fn nr_symbols(&self) -> usize {
        self.nr_symbols
    }

    /// Returns a read-only reference to the statistics.
    pub const fn stats(&self) -> &ModuleLoaderStats {
        &self.stats
    }

    /// Lists module ids of all live modules.
    pub fn live_modules(&self, buf: &mut [u64]) -> usize {
        let mut count = 0usize;
        for m in &self.modules {
            if m.occupied && m.state == ModuleState::Live {
                if count < buf.len() {
                    buf[count] = m.mod_id;
                }
                count += 1;
            }
        }
        count.min(buf.len())
    }

    /// Returns the state of a module by id.
    pub fn module_state(&self, mod_id: u64) -> Result<ModuleState> {
        let idx = self.find_module(mod_id)?;
        Ok(self.modules[idx].state)
    }

    // ── internal helpers ───────────────────────────────────────────

    fn find_module(&self, mod_id: u64) -> Result<usize> {
        self.modules
            .iter()
            .position(|m| m.occupied && m.mod_id == mod_id)
            .ok_or(Error::NotFound)
    }

    fn find_module_by_name(&self, name: &[u8]) -> Result<usize> {
        self.modules
            .iter()
            .position(|m| m.occupied && m.name_len == name.len() && m.name[..m.name_len] == *name)
            .ok_or(Error::NotFound)
    }

    fn register_global_symbol(
        &mut self,
        name: &[u8],
        address: u64,
        owner_id: u64,
        visibility: SymbolVisibility,
    ) -> Result<()> {
        // Check for duplicate.
        if self
            .symbols
            .iter()
            .any(|s| s.occupied && s.name_len == name.len() && s.name[..s.name_len] == *name)
        {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .symbols
            .iter()
            .position(|s| !s.occupied)
            .ok_or(Error::OutOfMemory)?;

        let sym = &mut self.symbols[slot];
        let len = name.len().min(MAX_SYM_NAME_LEN);
        sym.name[..len].copy_from_slice(&name[..len]);
        sym.name_len = len;
        sym.address = address;
        sym.owner_id = owner_id;
        sym.visibility = visibility;
        sym.occupied = true;
        self.nr_symbols += 1;
        Ok(())
    }
}

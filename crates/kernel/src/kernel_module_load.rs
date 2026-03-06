// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel module loading framework.
//!
//! Provides the full lifecycle for loadable kernel modules: a
//! [`ModuleDescriptor`] carries metadata (name, init/cleanup
//! function pointers, dependencies), the [`ModuleRegistry`]
//! manages load/unload operations and dependency resolution, and
//! a [`SymbolExportTable`] tracks symbols exported by modules.
//!
//! # Module State Machine
//!
//! ```text
//! Loading ──init()──→ Live ──cleanup()──→ Unloading ──→ Gone
//!   │                                        ↑
//!   └── init fails → Unloading ──────────────┘
//! ```
//!
//! # Architecture
//!
//! ```text
//! ModuleRegistry
//! ├── descriptors: [ModuleDescriptor; MAX_MODULES]
//! │   ├── name, version, state
//! │   ├── init_fn, cleanup_fn (addresses)
//! │   ├── dependencies: [dep indices]
//! │   └── ref_count
//! ├── symbols: SymbolExportTable
//! │   └── entries: [SymbolEntry; MAX_SYMBOLS]
//! └── stats: RegistryStats
//! ```
//!
//! # Dependency Resolution
//!
//! Before loading a module the registry verifies that every
//! declared dependency is in `Live` state. Cyclic dependencies
//! are rejected. Unloading checks that no other live module
//! depends on the target.
//!
//! Reference: Linux `kernel/module/main.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of registered modules.
const MAX_MODULES: usize = 128;

/// Maximum module name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Maximum version string length in bytes.
const MAX_VERSION_LEN: usize = 32;

/// Maximum dependencies per module.
const MAX_DEPS: usize = 16;

/// Maximum exported symbols across all modules.
const MAX_SYMBOLS: usize = 512;

/// Maximum symbol name length in bytes.
const MAX_SYM_NAME: usize = 64;

/// Maximum depth for dependency cycle detection.
const _MAX_DEP_DEPTH: usize = 16;

// ── ModuleState ────────────────────────────────────────────────

/// Lifecycle state of a kernel module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModuleState {
    /// Module slot is empty.
    #[default]
    Gone,
    /// Module is being loaded (init pending).
    Loading,
    /// Module is fully operational.
    Live,
    /// Module is being unloaded (cleanup pending).
    Unloading,
}

impl ModuleState {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Gone => "gone",
            Self::Loading => "loading",
            Self::Live => "live",
            Self::Unloading => "unloading",
        }
    }
}

// ── ModuleDescriptor ───────────────────────────────────────────

/// Metadata and state for a single kernel module.
#[derive(Clone, Copy)]
pub struct ModuleDescriptor {
    /// Module name (NUL-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Module version string (NUL-padded).
    pub version: [u8; MAX_VERSION_LEN],
    /// Current lifecycle state.
    pub state: ModuleState,
    /// Virtual address of the module init function.
    pub init_fn: u64,
    /// Virtual address of the module cleanup function.
    pub cleanup_fn: u64,
    /// Indices into the registry of required dependencies.
    pub deps: [u16; MAX_DEPS],
    /// Number of valid entries in `deps`.
    pub dep_count: u16,
    /// Reference count (other modules depending on this one).
    pub ref_count: u32,
    /// Module load order sequence number.
    pub load_seq: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl ModuleDescriptor {
    /// Creates an empty descriptor.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            version: [0u8; MAX_VERSION_LEN],
            state: ModuleState::Gone,
            init_fn: 0,
            cleanup_fn: 0,
            deps: [0u16; MAX_DEPS],
            dep_count: 0,
            ref_count: 0,
            load_seq: 0,
            active: false,
        }
    }
}

// ── SymbolEntry ────────────────────────────────────────────────

/// An exported kernel symbol.
#[derive(Clone, Copy)]
pub struct SymbolEntry {
    /// Symbol name (NUL-padded).
    pub name: [u8; MAX_SYM_NAME],
    /// Virtual address of the symbol.
    pub addr: u64,
    /// Index of the owning module in the registry.
    pub owner: u16,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl SymbolEntry {
    /// Creates an empty symbol entry.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_SYM_NAME],
            addr: 0,
            owner: 0,
            active: false,
        }
    }
}

// ── SymbolExportTable ──────────────────────────────────────────

/// Global table of symbols exported by loaded modules.
pub struct SymbolExportTable {
    /// Symbol entries.
    entries: [SymbolEntry; MAX_SYMBOLS],
    /// Number of active entries.
    count: usize,
}

impl SymbolExportTable {
    /// Creates an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { SymbolEntry::new() }; MAX_SYMBOLS],
            count: 0,
        }
    }

    /// Exports a symbol. Returns its index.
    pub fn export(&mut self, name: &[u8], addr: u64, owner: u16) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_SYM_NAME {
            return Err(Error::InvalidArgument);
        }
        let pos = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        let entry = &mut self.entries[pos];
        let len = name.len().min(MAX_SYM_NAME);
        entry.name[..len].copy_from_slice(&name[..len]);
        entry.addr = addr;
        entry.owner = owner;
        entry.active = true;
        self.count += 1;
        Ok(pos)
    }

    /// Looks up a symbol by name.
    pub fn resolve(&self, name: &[u8]) -> Result<u64> {
        let len = name.len().min(MAX_SYM_NAME);
        self.entries
            .iter()
            .find(|e| e.active && e.name[..len] == name[..len])
            .map(|e| e.addr)
            .ok_or(Error::NotFound)
    }

    /// Removes all symbols owned by the given module.
    pub fn remove_by_owner(&mut self, owner: u16) {
        for entry in &mut self.entries {
            if entry.active && entry.owner == owner {
                *entry = SymbolEntry::new();
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Returns the number of active symbols.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ── RegistryStats ──────────────────────────────────────────────

/// Statistics for module registry operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryStats {
    /// Total modules loaded (including unloaded).
    pub loads: u64,
    /// Total modules unloaded.
    pub unloads: u64,
    /// Load failures.
    pub failures: u64,
    /// Dependency resolution failures.
    pub dep_errors: u64,
}

// ── ModuleRegistry ─────────────────────────────────────────────

/// Central registry for all kernel modules.
pub struct ModuleRegistry {
    /// Module descriptors.
    descriptors: [ModuleDescriptor; MAX_MODULES],
    /// Global symbol export table.
    symbols: SymbolExportTable,
    /// Next load sequence number.
    next_seq: u64,
    /// Operational statistics.
    stats: RegistryStats,
}

impl ModuleRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            descriptors: [const { ModuleDescriptor::new() }; MAX_MODULES],
            symbols: SymbolExportTable::new(),
            next_seq: 1,
            stats: RegistryStats {
                loads: 0,
                unloads: 0,
                failures: 0,
                dep_errors: 0,
            },
        }
    }

    /// Registers a module in `Loading` state after resolving
    /// dependencies. Returns the module index.
    pub fn load(
        &mut self,
        name: &[u8],
        version: &[u8],
        init_fn: u64,
        cleanup_fn: u64,
        deps: &[u16],
    ) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if deps.len() > MAX_DEPS {
            return Err(Error::InvalidArgument);
        }
        // Check all dependencies are live.
        for &dep_idx in deps {
            let di = dep_idx as usize;
            if di >= MAX_MODULES {
                self.stats.dep_errors += 1;
                return Err(Error::InvalidArgument);
            }
            let dep = &self.descriptors[di];
            if !dep.active || dep.state != ModuleState::Live {
                self.stats.dep_errors += 1;
                return Err(Error::NotFound);
            }
        }
        // Allocate a slot.
        let pos = self
            .descriptors
            .iter()
            .position(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        let desc = &mut self.descriptors[pos];
        let nlen = name.len().min(MAX_NAME_LEN);
        desc.name[..nlen].copy_from_slice(&name[..nlen]);
        let vlen = version.len().min(MAX_VERSION_LEN);
        desc.version[..vlen].copy_from_slice(&version[..vlen]);
        desc.init_fn = init_fn;
        desc.cleanup_fn = cleanup_fn;
        desc.dep_count = deps.len() as u16;
        for (i, &d) in deps.iter().enumerate() {
            desc.deps[i] = d;
        }
        desc.state = ModuleState::Loading;
        desc.load_seq = self.next_seq;
        desc.active = true;
        self.next_seq += 1;
        // Increment ref counts on dependencies.
        for &dep_idx in deps {
            self.descriptors[dep_idx as usize].ref_count += 1;
        }
        self.stats.loads += 1;
        Ok(pos)
    }

    /// Transitions a module from `Loading` to `Live` after
    /// its init function succeeds.
    pub fn activate(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MODULES {
            return Err(Error::InvalidArgument);
        }
        let desc = &mut self.descriptors[idx];
        if !desc.active || desc.state != ModuleState::Loading {
            return Err(Error::InvalidArgument);
        }
        desc.state = ModuleState::Live;
        Ok(())
    }

    /// Begins unloading a module (Live → Unloading).
    /// Fails if other live modules depend on it.
    pub fn begin_unload(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MODULES {
            return Err(Error::InvalidArgument);
        }
        let desc = &self.descriptors[idx];
        if !desc.active || desc.state != ModuleState::Live {
            return Err(Error::InvalidArgument);
        }
        if desc.ref_count > 0 {
            return Err(Error::Busy);
        }
        self.descriptors[idx].state = ModuleState::Unloading;
        Ok(())
    }

    /// Finalises unload: transitions to Gone and frees the slot.
    pub fn finish_unload(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MODULES {
            return Err(Error::InvalidArgument);
        }
        let desc = &self.descriptors[idx];
        if !desc.active || desc.state != ModuleState::Unloading {
            return Err(Error::InvalidArgument);
        }
        // Decrement dependency ref counts.
        let dep_count = desc.dep_count as usize;
        let mut dep_indices = [0u16; MAX_DEPS];
        dep_indices[..dep_count].copy_from_slice(&desc.deps[..dep_count]);
        self.symbols.remove_by_owner(idx as u16);
        self.descriptors[idx] = ModuleDescriptor::new();
        for &di in &dep_indices[..dep_count] {
            let target = &mut self.descriptors[di as usize];
            target.ref_count = target.ref_count.saturating_sub(1);
        }
        self.stats.unloads += 1;
        Ok(())
    }

    /// Returns a reference to a module descriptor.
    pub fn get(&self, idx: usize) -> Result<&ModuleDescriptor> {
        if idx >= MAX_MODULES {
            return Err(Error::InvalidArgument);
        }
        let desc = &self.descriptors[idx];
        if !desc.active {
            return Err(Error::NotFound);
        }
        Ok(desc)
    }

    /// Exports a symbol from the given module.
    pub fn export_symbol(&mut self, owner: usize, name: &[u8], addr: u64) -> Result<usize> {
        if owner >= MAX_MODULES || !self.descriptors[owner].active {
            return Err(Error::InvalidArgument);
        }
        self.symbols.export(name, addr, owner as u16)
    }

    /// Resolves a symbol name to an address.
    pub fn resolve_symbol(&self, name: &[u8]) -> Result<u64> {
        self.symbols.resolve(name)
    }

    /// Returns the registry statistics.
    pub fn stats(&self) -> &RegistryStats {
        &self.stats
    }

    /// Returns the number of modules currently loaded (active).
    pub fn loaded_count(&self) -> usize {
        self.descriptors.iter().filter(|d| d.active).count()
    }
}

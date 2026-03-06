// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Module unloading — safe removal of loaded kernel modules.
//!
//! Handles the safe tear-down of kernel modules including reference
//! counting, dependency checking, and cleanup callback invocation.
//! A module can only be unloaded when its reference count reaches
//! zero and no other modules depend on it.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   ModuleUnloader                             │
//! │                                                              │
//! │  UnloadEntry[0..MAX_MODULES]  (per-module unload state)      │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  module_id: u64                                        │  │
//! │  │  ref_count: u32                                        │  │
//! │  │  dep_count: u32                                        │  │
//! │  │  state: UnloadState                                    │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/module/main.c`, `include/linux/module.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum tracked modules.
const MAX_MODULES: usize = 256;

/// Maximum dependencies per module.
const MAX_DEPS_PER_MODULE: usize = 16;

/// Maximum name length.
const MAX_NAME_LEN: usize = 56;

// ══════════════════════════════════════════════════════════════
// UnloadState
// ══════════════════════════════════════════════════════════════

/// State of a module with respect to unloading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnloadState {
    /// Slot is free.
    Free = 0,
    /// Module is live (normally loaded and in use).
    Live = 1,
    /// Module is going (unload initiated but cleanup pending).
    Going = 2,
    /// Module cleanup is complete, ready to free.
    Gone = 3,
}

// ══════════════════════════════════════════════════════════════
// UnloadPolicy
// ══════════════════════════════════════════════════════════════

/// Policy for handling modules with non-zero reference counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnloadPolicy {
    /// Wait until ref_count reaches zero.
    Wait = 0,
    /// Force unload regardless of ref_count.
    Force = 1,
    /// Fail immediately if ref_count is non-zero.
    Strict = 2,
}

// ══════════════════════════════════════════════════════════════
// UnloadEntry
// ══════════════════════════════════════════════════════════════

/// Per-module unload tracking entry.
#[derive(Debug, Clone, Copy)]
pub struct UnloadEntry {
    /// Module identifier.
    pub module_id: u64,
    /// Module name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Reference count.
    pub ref_count: u32,
    /// Number of modules that depend on this one.
    pub dep_count: u32,
    /// IDs of modules that depend on this one.
    pub dependents: [u64; MAX_DEPS_PER_MODULE],
    /// Current unload state.
    pub state: UnloadState,
    /// Whether the module supports live-patching teardown.
    pub live_patch: bool,
}

impl UnloadEntry {
    /// Create a free entry.
    const fn empty() -> Self {
        Self {
            module_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            ref_count: 0,
            dep_count: 0,
            dependents: [0u64; MAX_DEPS_PER_MODULE],
            state: UnloadState::Free,
            live_patch: false,
        }
    }

    /// Returns `true` if the slot is in use.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, UnloadState::Free)
    }

    /// Returns `true` if the module can be safely unloaded.
    pub const fn can_unload(&self) -> bool {
        self.ref_count == 0 && self.dep_count == 0
    }
}

// ══════════════════════════════════════════════════════════════
// ModuleUnloadStats
// ══════════════════════════════════════════════════════════════

/// Statistics for module unloading.
#[derive(Debug, Clone, Copy)]
pub struct ModuleUnloadStats {
    /// Total unload attempts.
    pub total_attempts: u64,
    /// Successful unloads.
    pub total_success: u64,
    /// Failed unloads (busy, dependencies).
    pub total_failures: u64,
    /// Forced unloads.
    pub total_forced: u64,
}

impl ModuleUnloadStats {
    const fn new() -> Self {
        Self {
            total_attempts: 0,
            total_success: 0,
            total_failures: 0,
            total_forced: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ModuleUnloader
// ══════════════════════════════════════════════════════════════

/// Top-level module unload subsystem.
pub struct ModuleUnloader {
    /// Per-module entries.
    entries: [UnloadEntry; MAX_MODULES],
    /// Statistics.
    stats: ModuleUnloadStats,
    /// Global unload policy.
    policy: UnloadPolicy,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for ModuleUnloader {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleUnloader {
    /// Create a new module unloader.
    pub const fn new() -> Self {
        Self {
            entries: [const { UnloadEntry::empty() }; MAX_MODULES],
            stats: ModuleUnloadStats::new(),
            policy: UnloadPolicy::Strict,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Set the global unload policy.
    pub fn set_policy(&mut self, policy: UnloadPolicy) {
        self.policy = policy;
    }

    // ── Module tracking ──────────────────────────────────────

    /// Track a loaded module for unload management.
    pub fn track(&mut self, module_id: u64, name: &[u8]) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .entries
            .iter()
            .position(|e| matches!(e.state, UnloadState::Free))
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot] = UnloadEntry::empty();
        self.entries[slot].module_id = module_id;
        self.entries[slot].name[..name.len()].copy_from_slice(name);
        self.entries[slot].name_len = name.len();
        self.entries[slot].state = UnloadState::Live;
        Ok(slot)
    }

    /// Increment the reference count of a module.
    pub fn get_ref(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_MODULES || !self.entries[slot].is_active() {
            return Err(Error::NotFound);
        }
        self.entries[slot].ref_count += 1;
        Ok(())
    }

    /// Decrement the reference count of a module.
    pub fn put_ref(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_MODULES || !self.entries[slot].is_active() {
            return Err(Error::NotFound);
        }
        if self.entries[slot].ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[slot].ref_count -= 1;
        Ok(())
    }

    /// Add a dependency (module at `dep_slot` depends on `slot`).
    pub fn add_dependent(&mut self, slot: usize, dep_module_id: u64) -> Result<()> {
        if slot >= MAX_MODULES || !self.entries[slot].is_active() {
            return Err(Error::NotFound);
        }
        let idx = self.entries[slot].dep_count as usize;
        if idx >= MAX_DEPS_PER_MODULE {
            return Err(Error::OutOfMemory);
        }
        self.entries[slot].dependents[idx] = dep_module_id;
        self.entries[slot].dep_count += 1;
        Ok(())
    }

    // ── Unload ───────────────────────────────────────────────

    /// Initiate unloading of a module.
    ///
    /// # Errors
    ///
    /// - `Busy` if the module has references or dependents (strict mode).
    /// - `NotFound` if the module is not tracked.
    pub fn unload(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_MODULES || !self.entries[slot].is_active() {
            return Err(Error::NotFound);
        }

        self.stats.total_attempts += 1;

        if !self.entries[slot].can_unload() {
            match self.policy {
                UnloadPolicy::Strict => {
                    self.stats.total_failures += 1;
                    return Err(Error::Busy);
                }
                UnloadPolicy::Force => {
                    self.stats.total_forced += 1;
                    // Fall through to force unload.
                }
                UnloadPolicy::Wait => {
                    return Err(Error::WouldBlock);
                }
            }
        }

        self.entries[slot].state = UnloadState::Going;
        // Cleanup would happen here in a real kernel.
        self.entries[slot].state = UnloadState::Gone;
        self.entries[slot] = UnloadEntry::empty();

        self.stats.total_success += 1;
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return an entry.
    pub fn entry(&self, slot: usize) -> Result<&UnloadEntry> {
        if slot >= MAX_MODULES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[slot])
    }

    /// Find a module by ID.
    pub fn find_by_id(&self, module_id: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_active() && e.module_id == module_id)
    }

    /// Return statistics.
    pub fn stats(&self) -> ModuleUnloadStats {
        self.stats
    }

    /// Return the number of tracked modules.
    pub fn tracked_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_active()).count()
    }

    /// Return the current unload policy.
    pub fn policy(&self) -> UnloadPolicy {
        self.policy
    }
}

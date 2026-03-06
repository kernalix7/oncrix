// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Static key / jump label infrastructure.
//!
//! Replaces conditional branches with NOPs or unconditional jumps
//! that can be patched at runtime, enabling near-zero-cost runtime
//! feature toggles. Modeled after Linux's `kernel/jump_label.c`
//! and `include/linux/jump_label.h`.
//!
//! # How It Works
//!
//! A [`StaticKey`] represents a boolean toggle. At each usage site
//! a [`JumpEntry`] records the address of a branch instruction
//! and the target to jump to when the key is enabled.
//!
//! ```text
//!   StaticKey (disabled)         StaticKey (enabled)
//!   ─────────────────────        ─────────────────────
//!   site: NOP (5 bytes)    →     site: JMP target
//!   fall-through path             jump-to path
//! ```
//!
//! When a key state changes, all associated [`PatchSite`] entries
//! are patched in-place via code modification. On x86_64 this
//! replaces 5-byte NOP instructions with relative JMP
//! instructions (or vice versa).
//!
//! # Usage
//!
//! ```ignore
//! let mut mgr = JumpLabelManager::new();
//! let key_id = mgr.register_key("tracing_enabled")?;
//! let site = mgr.register_site(key_id, 0x1000, 0x2000)?;
//! mgr.enable_key(key_id)?;  // patches all sites for this key
//! ```
//!
//! # Safety
//!
//! Patching code at runtime requires careful synchronization.
//! The real implementation must ensure all CPUs see a consistent
//! instruction stream (e.g. via IPI + serializing instructions).
//! This module models the logic without performing actual memory
//! writes.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of static keys.
const MAX_KEYS: usize = 128;

/// Maximum number of patch sites (across all keys).
const MAX_SITES: usize = 512;

/// Maximum key name length in bytes.
const MAX_KEY_NAME_LEN: usize = 32;

/// Size of a NOP instruction on x86_64 (5-byte NOP).
const _NOP_SIZE: usize = 5;

/// Size of a JMP rel32 instruction on x86_64.
const _JMP_SIZE: usize = 5;

// ── KeyState ─────────────────────────────────────────────────

/// State of a static key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyState {
    /// Key is disabled — branch sites contain NOPs.
    #[default]
    Disabled,
    /// Key is enabled — branch sites contain JMPs.
    Enabled,
}

// ── StaticKey ────────────────────────────────────────────────

/// A static key that controls one or more jump label sites.
///
/// Each key has a unique ID, a human-readable name, a current
/// state (enabled/disabled), and a reference count of
/// associated patch sites.
#[derive(Debug, Clone, Copy)]
pub struct StaticKey {
    /// Unique key identifier.
    pub id: u32,
    /// Human-readable name.
    name: [u8; MAX_KEY_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Current state.
    pub state: KeyState,
    /// Number of associated patch sites.
    pub site_count: u32,
    /// Enable reference count (supports nested enable calls).
    pub ref_count: u32,
    /// Whether this key was initially configured as "likely".
    pub initially_true: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl StaticKey {
    /// Create an empty key for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_KEY_NAME_LEN],
            name_len: 0,
            state: KeyState::Disabled,
            site_count: 0,
            ref_count: 0,
            initially_true: false,
            active: false,
        }
    }

    /// Return the key name as a string slice.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_KEY_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Return `true` if the key is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.state == KeyState::Enabled
    }

    /// Evaluate the static branch outcome.
    ///
    /// When `likely` is `true`, the branch is predicted taken
    /// when the key is enabled. When `likely` is `false`, the
    /// branch is predicted taken when the key is disabled.
    pub fn branch_likely(&self, likely: bool) -> bool {
        if likely {
            self.state == KeyState::Enabled
        } else {
            self.state == KeyState::Disabled
        }
    }
}

impl Default for StaticKey {
    fn default() -> Self {
        Self::empty()
    }
}

// ── PatchSite ────────────────────────────────────────────────

/// A code location that is patched when a key state changes.
///
/// Records the address of the instruction to patch, the jump
/// target address, and the key this site is associated with.
#[derive(Debug, Clone, Copy)]
pub struct PatchSite {
    /// Unique site identifier.
    pub id: u32,
    /// Key ID this site is associated with.
    pub key_id: u32,
    /// Address of the instruction to patch (NOP or JMP).
    pub code_addr: u64,
    /// Target address for the JMP instruction.
    pub target_addr: u64,
    /// Current instruction at this site.
    pub current: SiteInstruction,
    /// Whether this slot is active.
    pub active: bool,
}

impl PatchSite {
    /// Create an empty patch site for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            key_id: 0,
            code_addr: 0,
            target_addr: 0,
            current: SiteInstruction::Nop,
            active: false,
        }
    }
}

impl Default for PatchSite {
    fn default() -> Self {
        Self::empty()
    }
}

// ── SiteInstruction ──────────────────────────────────────────

/// The instruction currently at a patch site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SiteInstruction {
    /// 5-byte NOP (branch not taken).
    #[default]
    Nop,
    /// 5-byte JMP rel32 to the target address.
    Jump,
}

// ── JumpEntry ────────────────────────────────────────────────

/// A jump table entry linking a static key to its patch sites.
///
/// In the real kernel this lives in a special ELF section
/// (`__jump_table`). Here we model it as a runtime structure.
#[derive(Debug, Clone, Copy)]
pub struct JumpEntry {
    /// Address of the code site.
    pub code: u64,
    /// Address of the jump target.
    pub target: u64,
    /// Pointer to the static key (modeled as key ID).
    pub key_id: u32,
}

impl JumpEntry {
    /// Create a new jump entry.
    pub const fn new(code: u64, target: u64, key_id: u32) -> Self {
        Self {
            code,
            target,
            key_id,
        }
    }
}

// ── PatchStats ───────────────────────────────────────────────

/// Statistics for the jump label subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PatchStats {
    /// Total number of sites patched.
    pub total_patches: u64,
    /// Number of NOP-to-JMP patches.
    pub nop_to_jmp: u64,
    /// Number of JMP-to-NOP patches.
    pub jmp_to_nop: u64,
    /// Number of enable_key calls.
    pub enable_calls: u64,
    /// Number of disable_key calls.
    pub disable_calls: u64,
}

impl PatchStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_patches: 0,
            nop_to_jmp: 0,
            jmp_to_nop: 0,
            enable_calls: 0,
            disable_calls: 0,
        }
    }
}

// ── JumpLabelManager ─────────────────────────────────────────

/// Central manager for static keys and jump label sites.
///
/// Provides the kernel-facing API for registering keys and
/// sites, enabling/disabling keys, and performing the text
/// patching.
pub struct JumpLabelManager {
    /// Registered static keys.
    keys: [StaticKey; MAX_KEYS],
    /// Registered patch sites.
    sites: [PatchSite; MAX_SITES],
    /// Number of active keys.
    key_count: usize,
    /// Number of active sites.
    site_count: usize,
    /// Next key ID.
    next_key_id: u32,
    /// Next site ID.
    next_site_id: u32,
    /// Patching statistics.
    stats: PatchStats,
}

impl JumpLabelManager {
    /// Create a new, empty jump label manager.
    pub const fn new() -> Self {
        Self {
            keys: [StaticKey::empty(); MAX_KEYS],
            sites: [PatchSite::empty(); MAX_SITES],
            key_count: 0,
            site_count: 0,
            next_key_id: 1,
            next_site_id: 1,
            stats: PatchStats::new(),
        }
    }

    /// Register a new static key.
    ///
    /// Returns the key ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the key table is full.
    pub fn register_key(&mut self, name: &str) -> Result<u32> {
        let slot = self
            .keys
            .iter()
            .position(|k| !k.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_key_id;
        self.next_key_id = self.next_key_id.wrapping_add(1);

        let mut name_buf = [0u8; MAX_KEY_NAME_LEN];
        let copy_len = name.len().min(MAX_KEY_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        self.keys[slot] = StaticKey {
            id,
            name: name_buf,
            name_len: copy_len,
            state: KeyState::Disabled,
            site_count: 0,
            ref_count: 0,
            initially_true: false,
            active: true,
        };
        self.key_count += 1;
        Ok(id)
    }

    /// Register a new static key configured as initially
    /// enabled ("likely true").
    ///
    /// Returns the key ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the key table is full.
    pub fn register_key_true(&mut self, name: &str) -> Result<u32> {
        let id = self.register_key(name)?;
        // Find the key we just registered and mark it.
        if let Some(key) = self.keys.iter_mut().find(|k| k.active && k.id == id) {
            key.initially_true = true;
            key.state = KeyState::Enabled;
            key.ref_count = 1;
        }
        Ok(id)
    }

    /// Unregister a static key and all its associated sites.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given ID
    /// exists.
    pub fn unregister_key(&mut self, key_id: u32) -> Result<()> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;
        key.active = false;
        self.key_count = self.key_count.saturating_sub(1);

        // Remove all sites for this key.
        for site in &mut self.sites {
            if site.active && site.key_id == key_id {
                site.active = false;
                self.site_count = self.site_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Register a patch site for a static key.
    ///
    /// Returns the site ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the site table is full.
    /// Returns [`Error::NotFound`] if the key does not exist.
    pub fn register_site(&mut self, key_id: u32, code_addr: u64, target_addr: u64) -> Result<u32> {
        // Verify key exists.
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        let slot = self
            .sites
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_site_id;
        self.next_site_id = self.next_site_id.wrapping_add(1);

        // Determine initial instruction based on key state.
        let key_state = self.keys[key_pos].state;
        let instruction = if key_state == KeyState::Enabled {
            SiteInstruction::Jump
        } else {
            SiteInstruction::Nop
        };

        self.sites[slot] = PatchSite {
            id,
            key_id,
            code_addr,
            target_addr,
            current: instruction,
            active: true,
        };
        self.site_count += 1;
        self.keys[key_pos].site_count = self.keys[key_pos].site_count.wrapping_add(1);
        Ok(id)
    }

    /// Enable a static key.
    ///
    /// Patches all associated sites from NOP to JMP. Uses
    /// reference counting: the key is only disabled when
    /// `ref_count` reaches zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given ID
    /// exists.
    pub fn enable_key(&mut self, key_id: u32) -> Result<usize> {
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        self.keys[key_pos].ref_count = self.keys[key_pos].ref_count.wrapping_add(1);
        self.stats.enable_calls += 1;

        // Only patch if transitioning from disabled to enabled.
        if self.keys[key_pos].state == KeyState::Enabled {
            return Ok(0);
        }

        self.keys[key_pos].state = KeyState::Enabled;
        let patched = self.patch_sites(key_id, SiteInstruction::Jump);
        Ok(patched)
    }

    /// Disable a static key.
    ///
    /// Decrements the reference count. When it reaches zero,
    /// patches all associated sites from JMP to NOP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given ID
    /// exists.
    pub fn disable_key(&mut self, key_id: u32) -> Result<usize> {
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        self.stats.disable_calls += 1;

        if self.keys[key_pos].ref_count > 0 {
            self.keys[key_pos].ref_count -= 1;
        }

        // Only patch if ref_count reaches zero.
        if self.keys[key_pos].ref_count > 0 {
            return Ok(0);
        }

        if self.keys[key_pos].state == KeyState::Disabled {
            return Ok(0);
        }

        self.keys[key_pos].state = KeyState::Disabled;
        let patched = self.patch_sites(key_id, SiteInstruction::Nop);
        Ok(patched)
    }

    /// Evaluate a static branch likely outcome.
    ///
    /// Returns `true` if the branch should be taken (key is
    /// enabled and `likely` is `true`, or key is disabled and
    /// `likely` is `false`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given ID
    /// exists.
    pub fn static_branch_likely(&self, key_id: u32, likely: bool) -> Result<bool> {
        let key = self
            .keys
            .iter()
            .find(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;
        Ok(key.branch_likely(likely))
    }

    /// Look up a static key by name.
    ///
    /// Returns the key ID, or `None` if not found.
    pub fn find_key_by_name(&self, name: &str) -> Option<u32> {
        self.keys
            .iter()
            .find(|k| k.active && k.name_str() == name)
            .map(|k| k.id)
    }

    /// Return a reference to a key by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no key with the given ID
    /// exists.
    pub fn get_key(&self, key_id: u32) -> Result<&StaticKey> {
        self.keys
            .iter()
            .find(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)
    }

    /// Return the number of active keys.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Return the number of active sites.
    pub fn site_count(&self) -> usize {
        self.site_count
    }

    /// Return the patching statistics.
    pub fn stats(&self) -> &PatchStats {
        &self.stats
    }

    // ── internal helpers ─────────────────────────────────────

    /// Patch all sites associated with a key to the given
    /// instruction. Returns the number of sites patched.
    fn patch_sites(&mut self, key_id: u32, instruction: SiteInstruction) -> usize {
        let mut patched = 0usize;
        for site in &mut self.sites {
            if site.active && site.key_id == key_id && site.current != instruction {
                // In a real kernel we would:
                // 1. Stop all CPUs via IPI
                // 2. Write the new instruction bytes
                // 3. Execute a serializing instruction
                // 4. Resume all CPUs
                // Here we just update the model.
                let was_nop = site.current == SiteInstruction::Nop;
                site.current = instruction;
                patched += 1;
                self.stats.total_patches += 1;
                if was_nop {
                    self.stats.nop_to_jmp += 1;
                } else {
                    self.stats.jmp_to_nop += 1;
                }
            }
        }
        patched
    }
}

impl Default for JumpLabelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for JumpLabelManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JumpLabelManager")
            .field("key_count", &self.key_count)
            .field("site_count", &self.site_count)
            .field("stats", &self.stats)
            .finish()
    }
}

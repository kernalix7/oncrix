// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Static call site infrastructure.
//!
//! Static calls replace indirect function calls (via function
//! pointers) with direct calls that can be patched at runtime.
//! This eliminates the branch-prediction and speculative-execution
//! penalties of indirect calls while retaining the ability to
//! change the target at runtime.
//!
//! # How It Works
//!
//! ```text
//! Without static_call:    With static_call:
//!   mov rax, [ptr]          call <target>     ← patched in place
//!   call rax                NOP sled (padding)
//!   (indirect, spectre)     (direct, no spectre)
//! ```
//!
//! Each [`StaticCallKey`] represents a call target. When the
//! target changes, all [`StaticCallSite`] entries associated with
//! that key are patched to call the new function directly.
//!
//! # Usage
//!
//! ```ignore
//! let mut mgr = StaticCallManager::new();
//! let key = mgr.register_key("sched_tick", initial_fn)?;
//! let site = mgr.register_site(key, 0x1000)?;
//! mgr.update_key(key, new_fn)?;   // patches all sites
//! ```
//!
//! # Reference
//!
//! Linux `kernel/static_call.c`,
//! `include/linux/static_call.h`,
//! `arch/x86/kernel/static_call.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of static call keys.
const MAX_KEYS: usize = 128;

/// Maximum number of call sites (across all keys).
const MAX_SITES: usize = 512;

/// Maximum key name length.
const MAX_NAME_LEN: usize = 32;

/// Size of a direct call instruction on x86_64.
const _CALL_INSN_SIZE: usize = 5;

/// NOP opcode for x86_64 (5-byte NOP).
const _NOP5_OPCODE: u8 = 0x0F;

// ── StaticCallFn ────────────────────────────────────────────

/// Function type for static call targets.
pub type StaticCallFn = fn(u64) -> u64;

// ── SiteState ───────────────────────────────────────────────

/// Current state of a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SiteState {
    /// Site contains a direct call to the current target.
    #[default]
    Active,
    /// Site is patched to a NOP (function is a no-op).
    Nop,
    /// Site is disabled and will not be patched.
    Disabled,
}

// ── StaticCallKey ───────────────────────────────────────────

/// A static call key representing a patchable function pointer.
///
/// All sites referencing this key call the same function. When
/// the function changes, all sites are atomically updated.
#[derive(Clone, Copy)]
pub struct StaticCallKey {
    /// Unique key identifier.
    id: u32,
    /// Key name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Current target function.
    func: Option<StaticCallFn>,
    /// Number of associated sites.
    site_count: u32,
    /// Number of times this key has been updated.
    update_count: u64,
    /// Whether this key is active.
    active: bool,
}

impl core::fmt::Debug for StaticCallKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticCallKey")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("site_count", &self.site_count)
            .field("update_count", &self.update_count)
            .field("active", &self.active)
            .finish()
    }
}

impl StaticCallKey {
    /// Create an empty key.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            func: None,
            site_count: 0,
            update_count: 0,
            active: false,
        }
    }

    /// Key ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Key name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Number of associated sites.
    pub fn site_count(&self) -> u32 {
        self.site_count
    }

    /// Number of updates.
    pub fn update_count(&self) -> u64 {
        self.update_count
    }

    /// Whether the key has a function set.
    pub fn has_func(&self) -> bool {
        self.func.is_some()
    }

    /// Invoke the current function (for testing).
    pub fn invoke(&self, arg: u64) -> Option<u64> {
        self.func.map(|f| f(arg))
    }
}

// ── StaticCallSite ──────────────────────────────────────────

/// A code location where a static call is made.
#[derive(Debug, Clone, Copy)]
pub struct StaticCallSite {
    /// Unique site identifier.
    id: u32,
    /// Key ID this site is associated with.
    key_id: u32,
    /// Address of the call instruction.
    code_addr: u64,
    /// Current state.
    state: SiteState,
    /// Number of times this site has been patched.
    patch_count: u64,
    /// Whether this slot is active.
    active: bool,
}

impl StaticCallSite {
    /// Create an empty site.
    const fn empty() -> Self {
        Self {
            id: 0,
            key_id: 0,
            code_addr: 0,
            state: SiteState::Active,
            patch_count: 0,
            active: false,
        }
    }

    /// Site ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Code address.
    pub fn code_addr(&self) -> u64 {
        self.code_addr
    }

    /// Site state.
    pub fn state(&self) -> SiteState {
        self.state
    }
}

// ── PatchStats ──────────────────────────────────────────────

/// Statistics for the static call subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticCallStats {
    /// Total keys registered.
    pub keys_registered: u64,
    /// Total sites registered.
    pub sites_registered: u64,
    /// Total key updates.
    pub key_updates: u64,
    /// Total sites patched.
    pub sites_patched: u64,
    /// Total NOP patches applied.
    pub nop_patches: u64,
}

impl StaticCallStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            keys_registered: 0,
            sites_registered: 0,
            key_updates: 0,
            sites_patched: 0,
            nop_patches: 0,
        }
    }
}

// ── StaticCallManager ───────────────────────────────────────

/// Central manager for static call keys and sites.
pub struct StaticCallManager {
    /// Registered keys.
    keys: [StaticCallKey; MAX_KEYS],
    /// Registered sites.
    sites: [StaticCallSite; MAX_SITES],
    /// Number of active keys.
    key_count: usize,
    /// Number of active sites.
    site_count: usize,
    /// Next key ID.
    next_key_id: u32,
    /// Next site ID.
    next_site_id: u32,
    /// Statistics.
    stats: StaticCallStats,
}

impl StaticCallManager {
    /// Create a new static call manager.
    pub const fn new() -> Self {
        Self {
            keys: [StaticCallKey::empty(); MAX_KEYS],
            sites: [StaticCallSite::empty(); MAX_SITES],
            key_count: 0,
            site_count: 0,
            next_key_id: 1,
            next_site_id: 1,
            stats: StaticCallStats::new(),
        }
    }

    /// Register a new static call key. Returns the key ID.
    pub fn register_key(&mut self, name: &str, func: StaticCallFn) -> Result<u32> {
        let slot = self
            .keys
            .iter()
            .position(|k| !k.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_key_id;
        self.next_key_id = self.next_key_id.wrapping_add(1);

        let mut name_buf = [0u8; MAX_NAME_LEN];
        let copy_len = name.len().min(MAX_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        self.keys[slot] = StaticCallKey {
            id,
            name: name_buf,
            name_len: copy_len,
            func: Some(func),
            site_count: 0,
            update_count: 0,
            active: true,
        };
        self.key_count += 1;
        self.stats.keys_registered += 1;
        Ok(id)
    }

    /// Unregister a key and all its sites.
    pub fn unregister_key(&mut self, key_id: u32) -> Result<()> {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;
        key.active = false;
        self.key_count = self.key_count.saturating_sub(1);

        // Remove associated sites.
        for site in &mut self.sites {
            if site.active && site.key_id == key_id {
                site.active = false;
                self.site_count = self.site_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Register a call site for a key. Returns the site ID.
    pub fn register_site(&mut self, key_id: u32, code_addr: u64) -> Result<u32> {
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

        self.sites[slot] = StaticCallSite {
            id,
            key_id,
            code_addr,
            state: SiteState::Active,
            patch_count: 0,
            active: true,
        };
        self.site_count += 1;
        self.keys[key_pos].site_count += 1;
        self.stats.sites_registered += 1;
        Ok(id)
    }

    /// Update a key's target function.
    ///
    /// All associated sites are patched to call the new function.
    /// Returns the number of sites patched.
    pub fn update_key(&mut self, key_id: u32, new_func: StaticCallFn) -> Result<usize> {
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        self.keys[key_pos].func = Some(new_func);
        self.keys[key_pos].update_count += 1;
        self.stats.key_updates += 1;

        // Patch all sites.
        let mut patched = 0usize;
        for site in &mut self.sites {
            if site.active && site.key_id == key_id && site.state == SiteState::Active {
                // In real kernel: text_poke the call instruction.
                site.patch_count += 1;
                patched += 1;
                self.stats.sites_patched += 1;
            }
        }
        Ok(patched)
    }

    /// Set a key to NOP (all sites become no-ops).
    pub fn set_nop(&mut self, key_id: u32) -> Result<usize> {
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        self.keys[key_pos].func = None;
        self.keys[key_pos].update_count += 1;

        let mut patched = 0usize;
        for site in &mut self.sites {
            if site.active && site.key_id == key_id {
                site.state = SiteState::Nop;
                site.patch_count += 1;
                patched += 1;
                self.stats.nop_patches += 1;
            }
        }
        Ok(patched)
    }

    /// Restore a key from NOP to active with a function.
    pub fn restore_from_nop(&mut self, key_id: u32, func: StaticCallFn) -> Result<usize> {
        let key_pos = self
            .keys
            .iter()
            .position(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)?;

        self.keys[key_pos].func = Some(func);
        self.keys[key_pos].update_count += 1;

        let mut patched = 0usize;
        for site in &mut self.sites {
            if site.active && site.key_id == key_id && site.state == SiteState::Nop {
                site.state = SiteState::Active;
                site.patch_count += 1;
                patched += 1;
                self.stats.sites_patched += 1;
            }
        }
        Ok(patched)
    }

    /// Look up a key by name.
    pub fn find_key_by_name(&self, name: &str) -> Option<u32> {
        self.keys
            .iter()
            .find(|k| k.active && k.name_str() == name)
            .map(|k| k.id)
    }

    /// Get a key by ID.
    pub fn get_key(&self, key_id: u32) -> Result<&StaticCallKey> {
        self.keys
            .iter()
            .find(|k| k.active && k.id == key_id)
            .ok_or(Error::NotFound)
    }

    /// Get a site by ID.
    pub fn get_site(&self, site_id: u32) -> Result<&StaticCallSite> {
        self.sites
            .iter()
            .find(|s| s.active && s.id == site_id)
            .ok_or(Error::NotFound)
    }

    /// Number of active keys.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Number of active sites.
    pub fn site_count(&self) -> usize {
        self.site_count
    }

    /// Statistics.
    pub fn stats(&self) -> &StaticCallStats {
        &self.stats
    }
}

impl Default for StaticCallManager {
    fn default() -> Self {
        Self::new()
    }
}

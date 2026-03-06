// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Static key / branch optimization framework.
//!
//! Static keys allow the kernel to optimize frequently-evaluated boolean
//! conditions by patching jump instructions at runtime. When a static
//! key is disabled, the code path is a NOP (fall through); when enabled,
//! it becomes a JMP to the target. This eliminates branch prediction
//! overhead for configurations that rarely change.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    StaticKeySubsystem                             │
//! │                                                                  │
//! │  static_keys:  [StaticKey; MAX_STATIC_KEYS]                      │
//! │     ┌──────────────────────────────────────┐                     │
//! │     │  StaticKey                            │                    │
//! │     │    enabled: bool                      │                    │
//! │     │    ref_count: [u32; MAX_CPUS]         │                    │
//! │     │    entries: jump_entry_start..end      │                    │
//! │     └──────────────────────────────────────┘                     │
//! │                                                                  │
//! │  jump_entries: [JumpEntry; MAX_JUMP_ENTRIES]                      │
//! │     ┌──────────────────────────────────────┐                     │
//! │     │  JumpEntry                            │                    │
//! │     │    code_addr — instruction to patch    │                    │
//! │     │    target_addr — JMP destination        │                    │
//! │     │    key_index — back-reference to key    │                    │
//! │     │    patch_type — NOP/JMP5               │                    │
//! │     └──────────────────────────────────────┘                     │
//! │                                                                  │
//! │  Patching: NOP (0x0F 0x1F ..) ←→ JMP rel32 (0xE9 ..)           │
//! │                                                                  │
//! │  Batch update: stop_machine() + patch all entries for a key      │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Define a static key (initially disabled)
//! let key_id = subsystem.create_key("tracing_enabled", false)?;
//!
//! // Register jump sites
//! subsystem.add_jump_entry(key_id, code_addr, target_addr)?;
//!
//! // Hot path: check with zero branch overhead
//! if subsystem.evaluate(key_id) {
//!     // tracing code (normally NOP'd out)
//! }
//!
//! // Enable when configuration changes (patches all sites)
//! subsystem.enable_key(key_id)?;
//! ```
//!
//! # Reference
//!
//! Linux `kernel/jump_label.c`, `include/linux/jump_label.h`,
//! `arch/x86/kernel/jump_label.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of static keys in the system.
const MAX_STATIC_KEYS: usize = 256;

/// Maximum number of jump entries (patch sites) across all keys.
const MAX_JUMP_ENTRIES: usize = 4096;

/// Maximum CPUs for per-CPU reference counting.
const MAX_CPUS: usize = 64;

/// Maximum length of a key name.
const MAX_NAME_LEN: usize = 32;

/// Maximum jump entries per single key.
const MAX_ENTRIES_PER_KEY: usize = 128;

/// Maximum keys in a single batch update.
const MAX_BATCH_SIZE: usize = 32;

/// x86_64 NOP instruction (5-byte: 0F 1F 44 00 00).
const X86_NOP5: [u8; 5] = [0x0f, 0x1f, 0x44, 0x00, 0x00];

/// x86_64 JMP rel32 opcode byte.
const X86_JMP_OPCODE: u8 = 0xe9;

/// Size of a patch site (5 bytes: NOP5 or JMP rel32).
const PATCH_SIZE: usize = 5;

// ── Patch Type ──────────────────────────────────────────────────────────────

/// The type of instruction currently at a patch site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchType {
    /// 5-byte NOP (key disabled / likely-false path).
    Nop,
    /// 5-byte JMP rel32 (key enabled / branch taken).
    Jump,
}

/// Direction hint for static branch evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchHint {
    /// The key is expected to be false most of the time.
    Likely,
    /// The key is expected to be true most of the time.
    Unlikely,
}

/// State of the static key subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemState {
    /// Not yet initialized.
    Uninitialized,
    /// Ready for use.
    Ready,
    /// Currently patching (all CPUs stopped).
    Patching,
}

// ── Jump Entry ──────────────────────────────────────────────────────────────

/// A single jump/patch site in kernel code.
///
/// Each entry records the address of the instruction to patch, the
/// target address for the JMP, and a back-reference to the controlling
/// static key.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JumpEntry {
    /// Whether this entry slot is in use.
    pub active: bool,
    /// Address of the instruction to patch (NOP or JMP site).
    pub code_addr: u64,
    /// Target address for the JMP instruction.
    pub target_addr: u64,
    /// Index of the controlling static key.
    pub key_index: u16,
    /// Current instruction type at this site.
    pub current_patch: PatchType,
    /// Branch direction hint.
    pub hint: BranchHint,
    /// The original bytes before patching (for rollback).
    pub original_bytes: [u8; PATCH_SIZE],
    /// The current patched bytes.
    pub patched_bytes: [u8; PATCH_SIZE],
}

impl JumpEntry {
    /// Create an empty (inactive) jump entry.
    pub const fn new() -> Self {
        Self {
            active: false,
            code_addr: 0,
            target_addr: 0,
            key_index: 0,
            current_patch: PatchType::Nop,
            hint: BranchHint::Unlikely,
            original_bytes: [0u8; PATCH_SIZE],
            patched_bytes: [0u8; PATCH_SIZE],
        }
    }

    /// Compute the JMP rel32 instruction bytes for this entry.
    ///
    /// The relative offset is `target_addr - (code_addr + 5)`.
    pub fn compute_jmp_bytes(&self) -> Result<[u8; PATCH_SIZE]> {
        let next_ip = self.code_addr.wrapping_add(PATCH_SIZE as u64);
        let offset = self.target_addr.wrapping_sub(next_ip);
        // Check that offset fits in i32
        let offset_i64 = offset as i64;
        if offset_i64 > i32::MAX as i64 || offset_i64 < i32::MIN as i64 {
            return Err(Error::InvalidArgument);
        }
        let rel32 = (offset as i32).to_le_bytes();
        Ok([X86_JMP_OPCODE, rel32[0], rel32[1], rel32[2], rel32[3]])
    }

    /// Get the NOP instruction bytes.
    pub fn nop_bytes() -> [u8; PATCH_SIZE] {
        X86_NOP5
    }
}

// ── Static Key ──────────────────────────────────────────────────────────────

/// A static key controlling one or more jump/patch sites.
#[derive(Debug)]
pub struct StaticKey {
    /// Whether this key slot is in use.
    active: bool,
    /// Key name for debugging/diagnostics.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Current enabled state.
    enabled: bool,
    /// Default state (initial value).
    default_enabled: bool,
    /// Per-CPU reference counts for concurrent enable/disable.
    ref_counts: [u32; MAX_CPUS],
    /// Total reference count (sum of per-CPU counts).
    total_ref_count: u64,
    /// Index of the first jump entry for this key.
    entry_start: usize,
    /// Number of jump entries for this key.
    entry_count: usize,
    /// Number of times this key has been toggled.
    toggle_count: u64,
    /// Whether this key is locked (cannot be toggled).
    locked: bool,
}

impl StaticKey {
    /// Create a new static key.
    pub const fn new() -> Self {
        Self {
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            enabled: false,
            default_enabled: false,
            ref_counts: [0u32; MAX_CPUS],
            total_ref_count: 0,
            entry_start: 0,
            entry_count: 0,
            toggle_count: 0,
            locked: false,
        }
    }

    /// Whether the key is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether the key is locked.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Get the total reference count.
    pub fn total_ref_count(&self) -> u64 {
        self.total_ref_count
    }

    /// Get the number of times this key has been toggled.
    pub fn toggle_count(&self) -> u64 {
        self.toggle_count
    }

    /// Get the number of jump entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Get the per-CPU reference count.
    pub fn cpu_ref_count(&self, cpu: usize) -> u32 {
        if cpu < MAX_CPUS {
            self.ref_counts[cpu]
        } else {
            0
        }
    }

    /// Increment the reference count for a CPU.
    ///
    /// Returns `true` if this was the first reference (0→1 transition).
    pub fn inc_ref(&mut self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let was_zero = self.total_ref_count == 0;
        self.ref_counts[cpu] = self.ref_counts[cpu]
            .checked_add(1)
            .ok_or(Error::InvalidArgument)?;
        self.total_ref_count += 1;
        Ok(was_zero)
    }

    /// Decrement the reference count for a CPU.
    ///
    /// Returns `true` if this was the last reference (1→0 transition).
    pub fn dec_ref(&mut self, cpu: usize) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.ref_counts[cpu] == 0 {
            return Err(Error::InvalidArgument);
        }
        self.ref_counts[cpu] -= 1;
        self.total_ref_count = self.total_ref_count.saturating_sub(1);
        Ok(self.total_ref_count == 0)
    }

    /// Lock the key to prevent further toggling.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the key.
    pub fn unlock(&mut self) {
        self.locked = false;
    }
}

// ── Batch Update ────────────────────────────────────────────────────────────

/// A pending key state change for batch processing.
#[derive(Debug, Clone, Copy)]
pub struct PendingUpdate {
    /// Whether this slot is in use.
    pub active: bool,
    /// Key index to update.
    pub key_index: u16,
    /// New enabled state.
    pub new_state: bool,
}

impl PendingUpdate {
    /// Create an empty pending update.
    pub const fn new() -> Self {
        Self {
            active: false,
            key_index: 0,
            new_state: false,
        }
    }
}

// ── Static Key Subsystem ────────────────────────────────────────────────────

/// Subsystem-wide statistics.
#[derive(Debug, Clone, Copy)]
pub struct StaticKeyStats {
    /// Number of active keys.
    pub active_keys: u32,
    /// Number of active jump entries.
    pub active_entries: u32,
    /// Total key toggles performed.
    pub total_toggles: u64,
    /// Total instructions patched.
    pub total_patches: u64,
    /// Total batch updates executed.
    pub total_batches: u64,
}

/// The global static key subsystem.
///
/// Manages all static keys, their jump entries, and coordinates
/// patching of instruction sites when keys are toggled.
pub struct StaticKeySubsystem {
    /// Subsystem state.
    state: SubsystemState,
    /// All static keys.
    keys: [StaticKey; MAX_STATIC_KEYS],
    /// Number of active keys.
    key_count: usize,
    /// All jump entries.
    entries: [JumpEntry; MAX_JUMP_ENTRIES],
    /// Number of active jump entries.
    entry_count: usize,
    /// Pending batch updates.
    pending: [PendingUpdate; MAX_BATCH_SIZE],
    /// Number of pending updates.
    pending_count: usize,
    /// Total patches applied.
    total_patches: u64,
    /// Total batch updates.
    total_batches: u64,
}

impl StaticKeySubsystem {
    /// Create a new static key subsystem.
    pub const fn new() -> Self {
        Self {
            state: SubsystemState::Uninitialized,
            keys: [const { StaticKey::new() }; MAX_STATIC_KEYS],
            key_count: 0,
            entries: [const { JumpEntry::new() }; MAX_JUMP_ENTRIES],
            entry_count: 0,
            pending: [const { PendingUpdate::new() }; MAX_BATCH_SIZE],
            pending_count: 0,
            total_patches: 0,
            total_batches: 0,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.state != SubsystemState::Uninitialized {
            return Err(Error::AlreadyExists);
        }
        self.state = SubsystemState::Ready;
        Ok(())
    }

    /// Get the subsystem state.
    pub fn state(&self) -> SubsystemState {
        self.state
    }

    /// Create a new static key.
    ///
    /// Returns the key index.
    pub fn create_key(&mut self, name: &[u8], default_enabled: bool) -> Result<u16> {
        if self.state != SubsystemState::Ready {
            return Err(Error::InvalidArgument);
        }
        if self.key_count >= MAX_STATIC_KEYS {
            return Err(Error::OutOfMemory);
        }
        let slot = (0..MAX_STATIC_KEYS)
            .find(|&i| !self.keys[i].active)
            .ok_or(Error::OutOfMemory)?;
        let key = &mut self.keys[slot];
        key.active = true;
        key.enabled = default_enabled;
        key.default_enabled = default_enabled;
        key.entry_start = 0;
        key.entry_count = 0;
        key.toggle_count = 0;
        key.locked = false;
        key.total_ref_count = 0;
        key.ref_counts = [0u32; MAX_CPUS];
        if name.len() < MAX_NAME_LEN {
            key.name[..name.len()].copy_from_slice(name);
            key.name_len = name.len();
        }
        self.key_count += 1;
        Ok(slot as u16)
    }

    /// Destroy a static key and all its jump entries.
    pub fn destroy_key(&mut self, key_index: u16) -> Result<()> {
        let idx = key_index as usize;
        if idx >= MAX_STATIC_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        // Deactivate all entries for this key
        for entry in &mut self.entries {
            if entry.active && entry.key_index == key_index {
                entry.active = false;
                self.entry_count = self.entry_count.saturating_sub(1);
            }
        }
        self.keys[idx].active = false;
        self.key_count = self.key_count.saturating_sub(1);
        Ok(())
    }

    /// Add a jump entry (patch site) for a key.
    pub fn add_jump_entry(
        &mut self,
        key_index: u16,
        code_addr: u64,
        target_addr: u64,
        hint: BranchHint,
    ) -> Result<usize> {
        let kidx = key_index as usize;
        if kidx >= MAX_STATIC_KEYS || !self.keys[kidx].active {
            return Err(Error::NotFound);
        }
        if self.keys[kidx].entry_count >= MAX_ENTRIES_PER_KEY {
            return Err(Error::OutOfMemory);
        }
        if self.entry_count >= MAX_JUMP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = (0..MAX_JUMP_ENTRIES)
            .find(|&i| !self.entries[i].active)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.entries[slot];
        entry.active = true;
        entry.code_addr = code_addr;
        entry.target_addr = target_addr;
        entry.key_index = key_index;
        entry.hint = hint;
        // Initial patch: if key enabled, JMP; else NOP
        if self.keys[kidx].enabled {
            let jmp = entry.compute_jmp_bytes()?;
            entry.current_patch = PatchType::Jump;
            entry.patched_bytes = jmp;
        } else {
            entry.current_patch = PatchType::Nop;
            entry.patched_bytes = JumpEntry::nop_bytes();
        }
        entry.original_bytes = JumpEntry::nop_bytes();

        if self.keys[kidx].entry_count == 0 {
            self.keys[kidx].entry_start = slot;
        }
        self.keys[kidx].entry_count += 1;
        self.entry_count += 1;
        Ok(slot)
    }

    /// Remove a jump entry.
    pub fn remove_jump_entry(&mut self, entry_index: usize) -> Result<()> {
        if entry_index >= MAX_JUMP_ENTRIES || !self.entries[entry_index].active {
            return Err(Error::NotFound);
        }
        let key_idx = self.entries[entry_index].key_index as usize;
        self.entries[entry_index].active = false;
        self.entry_count = self.entry_count.saturating_sub(1);
        if key_idx < MAX_STATIC_KEYS && self.keys[key_idx].active {
            self.keys[key_idx].entry_count = self.keys[key_idx].entry_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Evaluate a static key (fast path).
    ///
    /// Returns the current enabled state of the key.
    pub fn evaluate(&self, key_index: u16) -> bool {
        let idx = key_index as usize;
        if idx < MAX_STATIC_KEYS && self.keys[idx].active {
            self.keys[idx].enabled
        } else {
            false
        }
    }

    /// Evaluate a static key with branch hint.
    ///
    /// `static_branch_likely` — expect the key to be true.
    /// `static_branch_unlikely` — expect the key to be false.
    pub fn evaluate_with_hint(&self, key_index: u16, hint: BranchHint) -> bool {
        let val = self.evaluate(key_index);
        match hint {
            BranchHint::Likely => val,
            BranchHint::Unlikely => val,
        }
    }

    /// Enable a static key, patching all its jump sites.
    pub fn enable_key(&mut self, key_index: u16) -> Result<usize> {
        let idx = key_index as usize;
        if idx >= MAX_STATIC_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        if self.keys[idx].locked {
            return Err(Error::PermissionDenied);
        }
        if self.keys[idx].enabled {
            return Ok(0); // Already enabled
        }
        self.keys[idx].enabled = true;
        self.keys[idx].toggle_count += 1;
        let patched = self.patch_entries_for_key(key_index, PatchType::Jump)?;
        Ok(patched)
    }

    /// Disable a static key, patching all its jump sites to NOP.
    pub fn disable_key(&mut self, key_index: u16) -> Result<usize> {
        let idx = key_index as usize;
        if idx >= MAX_STATIC_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        if self.keys[idx].locked {
            return Err(Error::PermissionDenied);
        }
        if !self.keys[idx].enabled {
            return Ok(0); // Already disabled
        }
        self.keys[idx].enabled = false;
        self.keys[idx].toggle_count += 1;
        let patched = self.patch_entries_for_key(key_index, PatchType::Nop)?;
        Ok(patched)
    }

    /// Toggle a static key via reference counting (per-CPU).
    ///
    /// Increments the ref count for the given CPU. When transitioning
    /// from 0→1 total refs, the key is enabled.
    pub fn ref_enable(&mut self, key_index: u16, cpu: usize) -> Result<bool> {
        let idx = key_index as usize;
        if idx >= MAX_STATIC_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        let was_zero = self.keys[idx].inc_ref(cpu)?;
        if was_zero && !self.keys[idx].enabled {
            self.enable_key(key_index)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Decrement the ref count for a CPU. When transitioning
    /// from 1→0 total refs, the key is disabled.
    pub fn ref_disable(&mut self, key_index: u16, cpu: usize) -> Result<bool> {
        let idx = key_index as usize;
        if idx >= MAX_STATIC_KEYS || !self.keys[idx].active {
            return Err(Error::NotFound);
        }
        let is_zero = self.keys[idx].dec_ref(cpu)?;
        if is_zero && self.keys[idx].enabled {
            self.disable_key(key_index)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Queue a key update for batch processing.
    pub fn queue_update(&mut self, key_index: u16, new_state: bool) -> Result<()> {
        if self.pending_count >= MAX_BATCH_SIZE {
            return Err(Error::OutOfMemory);
        }
        let slot = (0..MAX_BATCH_SIZE)
            .find(|&i| !self.pending[i].active)
            .ok_or(Error::OutOfMemory)?;
        self.pending[slot].active = true;
        self.pending[slot].key_index = key_index;
        self.pending[slot].new_state = new_state;
        self.pending_count += 1;
        Ok(())
    }

    /// Execute all queued batch updates.
    ///
    /// Returns the total number of entries patched.
    pub fn execute_batch(&mut self) -> Result<usize> {
        if self.pending_count == 0 {
            return Ok(0);
        }
        self.state = SubsystemState::Patching;
        let mut total_patched = 0;

        // Collect pending updates (copy to avoid borrow issues)
        let mut updates = [(0u16, false); MAX_BATCH_SIZE];
        let mut count = 0;
        for i in 0..MAX_BATCH_SIZE {
            if self.pending[i].active {
                updates[count] = (self.pending[i].key_index, self.pending[i].new_state);
                self.pending[i].active = false;
                count += 1;
            }
        }
        self.pending_count = 0;

        for &(key_index, new_state) in &updates[..count] {
            let result = if new_state {
                self.enable_key(key_index)
            } else {
                self.disable_key(key_index)
            };
            if let Ok(n) = result {
                total_patched += n;
            }
        }

        self.total_batches += 1;
        self.state = SubsystemState::Ready;
        Ok(total_patched)
    }

    /// Patch all jump entries for a key to the given patch type.
    ///
    /// Returns the number of entries patched.
    fn patch_entries_for_key(&mut self, key_index: u16, patch_type: PatchType) -> Result<usize> {
        let mut patched = 0;
        for i in 0..MAX_JUMP_ENTRIES {
            if !self.entries[i].active || self.entries[i].key_index != key_index {
                continue;
            }
            if self.entries[i].current_patch == patch_type {
                continue; // Already in desired state
            }
            match patch_type {
                PatchType::Jump => {
                    let jmp = self.entries[i].compute_jmp_bytes()?;
                    self.entries[i].patched_bytes = jmp;
                    self.entries[i].current_patch = PatchType::Jump;
                }
                PatchType::Nop => {
                    self.entries[i].patched_bytes = JumpEntry::nop_bytes();
                    self.entries[i].current_patch = PatchType::Nop;
                }
            }
            patched += 1;
            self.total_patches += 1;
        }
        Ok(patched)
    }

    /// Get the number of active keys.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    /// Get the number of active jump entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Get a reference to a static key by index.
    pub fn get_key(&self, key_index: u16) -> Option<&StaticKey> {
        let idx = key_index as usize;
        if idx < MAX_STATIC_KEYS && self.keys[idx].active {
            Some(&self.keys[idx])
        } else {
            None
        }
    }

    /// Get a reference to a jump entry by index.
    pub fn get_entry(&self, entry_index: usize) -> Option<&JumpEntry> {
        if entry_index < MAX_JUMP_ENTRIES && self.entries[entry_index].active {
            Some(&self.entries[entry_index])
        } else {
            None
        }
    }

    /// Get subsystem statistics.
    pub fn stats(&self) -> StaticKeyStats {
        let mut total_toggles = 0u64;
        for key in &self.keys {
            if key.active {
                total_toggles += key.toggle_count;
            }
        }
        StaticKeyStats {
            active_keys: self.key_count as u32,
            active_entries: self.entry_count as u32,
            total_toggles,
            total_patches: self.total_patches,
            total_batches: self.total_batches,
        }
    }

    /// Reset the subsystem (for testing).
    pub fn reset(&mut self) {
        for key in &mut self.keys {
            key.active = false;
        }
        for entry in &mut self.entries {
            entry.active = false;
        }
        for pending in &mut self.pending {
            pending.active = false;
        }
        self.key_count = 0;
        self.entry_count = 0;
        self.pending_count = 0;
        self.total_patches = 0;
        self.total_batches = 0;
        self.state = SubsystemState::Ready;
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel module loader framework.
//!
//! Provides runtime-loadable kernel extensions with lifecycle
//! management, dependency tracking, and reference counting.
//! Modules are registered in a [`ModuleRegistry`] which supports
//! up to 64 concurrently loaded modules.
//!
//! # Lifecycle
//!
//! ```text
//! Unloaded ──► Loading ──► Live ──► Unloading ──► Gone
//! ```
//!
//! # Usage
//!
//! 1. Call [`ModuleRegistry::load_module`] to register a module.
//! 2. The module transitions through `Loading` to `Live`.
//! 3. Add inter-module dependencies with [`ModuleRegistry::add_dependency`].
//! 4. When done, call [`ModuleRegistry::unload_module`] (ref_count must
//!    be zero and no other modules may depend on it).

use oncrix_lib::{Error, Result};

/// Maximum number of modules in the registry.
const MAX_MODULES: usize = 64;

/// Maximum number of dependency entries.
const MAX_DEPS: usize = 128;

/// Maximum number of parameters per module.
const MAX_PARAMS: usize = 8;

/// Module name buffer length.
const MODULE_NAME_LEN: usize = 64;

/// Module version buffer length.
const MODULE_VERSION_LEN: usize = 16;

/// Parameter name buffer length.
const PARAM_NAME_LEN: usize = 32;

// ======================================================================
// ModuleState
// ======================================================================

/// Lifecycle state of a kernel module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModuleState {
    /// Module slot is unused or has been fully unloaded.
    #[default]
    Unloaded,
    /// Module binary is being loaded into memory.
    Loading,
    /// Module is fully initialised and running.
    Live,
    /// Module is in the process of shutting down.
    Unloading,
    /// Module has been removed and its slot is reclaimable.
    Gone,
}

// ======================================================================
// ParamType
// ======================================================================

/// Type tag for a module parameter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParamType {
    /// Boolean parameter (0 = false, non-zero = true).
    Bool,
    /// Signed integer parameter.
    #[default]
    Int,
    /// Unsigned integer parameter.
    UInt,
    /// String parameter (encoded in the value field).
    String,
}

// ======================================================================
// ModuleParam
// ======================================================================

/// A single key-value parameter for a kernel module.
#[derive(Debug, Clone, Copy)]
pub struct ModuleParam {
    /// Parameter name (fixed buffer, zero-padded).
    pub name: [u8; PARAM_NAME_LEN],
    /// Valid length of `name` in bytes.
    pub name_len: usize,
    /// Parameter value (interpretation depends on `param_type`).
    pub value: u64,
    /// Type of this parameter.
    pub param_type: ParamType,
}

impl ModuleParam {
    /// Creates an empty parameter with default values.
    const fn empty() -> Self {
        Self {
            name: [0u8; PARAM_NAME_LEN],
            name_len: 0,
            value: 0,
            param_type: ParamType::Int,
        }
    }

    /// Returns the parameter name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        let len = self.name_len.min(PARAM_NAME_LEN);
        &self.name[..len]
    }
}

impl Default for ModuleParam {
    fn default() -> Self {
        Self::empty()
    }
}

// ======================================================================
// ModuleDep
// ======================================================================

/// A dependency relationship between two kernel modules.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleDep {
    /// ID of the module that has the dependency.
    pub mod_id: u64,
    /// ID of the module that is depended upon.
    pub dep_id: u64,
    /// Whether this dependency entry is active.
    pub in_use: bool,
}

// ======================================================================
// KernelModule
// ======================================================================

/// A single registered kernel module.
///
/// Tracks the module's identity, memory layout, lifecycle state,
/// parameters, and reference count. Stored in fixed-size slots
/// within the [`ModuleRegistry`].
pub struct KernelModule {
    /// Unique module identifier (assigned by the registry).
    pub id: u64,
    /// Human-readable name (fixed buffer, zero-padded).
    pub name: [u8; MODULE_NAME_LEN],
    /// Valid length of `name` in bytes.
    pub name_len: usize,
    /// Current lifecycle state.
    pub state: ModuleState,
    /// Version string (fixed buffer, zero-padded).
    pub version: [u8; MODULE_VERSION_LEN],
    /// Valid length of `version` in bytes.
    pub ver_len: usize,
    /// Address of the module initialisation function.
    pub init_fn: u64,
    /// Address of the module cleanup/exit function.
    pub exit_fn: u64,
    /// Base virtual address of the module's text (code) section.
    pub text_base: u64,
    /// Size of the text section in bytes.
    pub text_size: u64,
    /// Base virtual address of the module's data section.
    pub data_base: u64,
    /// Size of the data section in bytes.
    pub data_size: u64,
    /// Module parameters (up to [`MAX_PARAMS`]).
    pub params: [ModuleParam; MAX_PARAMS],
    /// Number of valid entries in `params`.
    pub param_count: usize,
    /// Number of active references to this module.
    pub ref_count: u32,
    /// Whether this slot is occupied in the registry.
    pub in_use: bool,
}

impl KernelModule {
    /// Creates an empty (inactive) module for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MODULE_NAME_LEN],
            name_len: 0,
            state: ModuleState::Unloaded,
            version: [0u8; MODULE_VERSION_LEN],
            ver_len: 0,
            init_fn: 0,
            exit_fn: 0,
            text_base: 0,
            text_size: 0,
            data_base: 0,
            data_size: 0,
            params: [ModuleParam::empty(); MAX_PARAMS],
            param_count: 0,
            ref_count: 0,
            in_use: false,
        }
    }

    /// Invoke the module's init function (state transition).
    ///
    /// Transitions from [`ModuleState::Loading`] to [`ModuleState::Live`].
    /// In a full implementation this would call the function at `init_fn`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the module is not in
    /// the `Loading` state.
    pub fn init(&mut self) -> Result<()> {
        if self.state != ModuleState::Loading {
            return Err(Error::InvalidArgument);
        }
        self.state = ModuleState::Live;
        Ok(())
    }

    /// Invoke the module's exit function (state transition).
    ///
    /// Transitions from [`ModuleState::Live`] to [`ModuleState::Unloading`].
    /// In a full implementation this would call the function at `exit_fn`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the module is not in
    /// the `Live` state.
    pub fn exit(&mut self) -> Result<()> {
        if self.state != ModuleState::Live {
            return Err(Error::InvalidArgument);
        }
        self.state = ModuleState::Unloading;
        Ok(())
    }

    /// Returns a reference to a parameter by name, or `None` if
    /// no parameter with that name exists.
    pub fn get_param(&self, name: &[u8]) -> Option<&ModuleParam> {
        self.params[..self.param_count]
            .iter()
            .find(|p| p.name_bytes() == name)
    }

    /// Sets the value of a parameter by name.
    ///
    /// If the parameter exists, its value is updated. If it does
    /// not exist and there is room, a new parameter is created.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or
    /// exceeds the buffer size.
    /// Returns [`Error::OutOfMemory`] if the parameter table is full.
    pub fn set_param(&mut self, name: &[u8], value: u64) -> Result<()> {
        if name.is_empty() || name.len() > PARAM_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Update existing parameter if found.
        for p in &mut self.params[..self.param_count] {
            if p.name_bytes() == name {
                p.value = value;
                return Ok(());
            }
        }

        // Add new parameter.
        if self.param_count >= MAX_PARAMS {
            return Err(Error::OutOfMemory);
        }

        let mut name_buf = [0u8; PARAM_NAME_LEN];
        let copy_len = name.len().min(PARAM_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        self.params[self.param_count] = ModuleParam {
            name: name_buf,
            name_len: copy_len,
            value,
            param_type: ParamType::Int,
        };
        self.param_count = self.param_count.saturating_add(1);
        Ok(())
    }

    /// Returns the total memory footprint (text + data) of this module.
    pub fn total_size(&self) -> u64 {
        self.text_size.saturating_add(self.data_size)
    }

    /// Returns the module name as a `&str`.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MODULE_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

impl Default for KernelModule {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for KernelModule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelModule")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("state", &self.state)
            .field("ref_count", &self.ref_count)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ======================================================================
// ModuleRegistry
// ======================================================================

/// Global registry of kernel modules.
///
/// Manages up to [`MAX_MODULES`] kernel modules with dependency
/// tracking and reference counting. All storage is fixed-size
/// arrays, suitable for `#![no_std]` kernel environments.
pub struct ModuleRegistry {
    /// Module slots.
    modules: [KernelModule; MAX_MODULES],
    /// Number of active (in-use) modules.
    count: usize,
    /// Dependency table.
    deps: [ModuleDep; MAX_DEPS],
    /// Number of active dependency entries.
    dep_count: usize,
    /// Monotonically increasing module ID counter.
    next_id: u64,
}

impl ModuleRegistry {
    /// Creates a new, empty module registry.
    #[allow(clippy::large_stack_frames)]
    pub fn new() -> Self {
        const EMPTY_MOD: KernelModule = KernelModule::empty();
        const EMPTY_DEP: ModuleDep = ModuleDep {
            mod_id: 0,
            dep_id: 0,
            in_use: false,
        };
        Self {
            modules: [EMPTY_MOD; MAX_MODULES],
            count: 0,
            deps: [EMPTY_DEP; MAX_DEPS],
            dep_count: 0,
            next_id: 1,
        }
    }

    /// Allocates the next module ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Loads a new kernel module into the registry.
    ///
    /// The module starts in [`ModuleState::Loading`] and is
    /// automatically transitioned to [`ModuleState::Live`] upon
    /// successful registration.
    ///
    /// Returns the assigned module ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    /// Returns [`Error::AlreadyExists`] if a module with the same
    /// name is already loaded.
    pub fn load_module(
        &mut self,
        name: &str,
        init_fn: u64,
        exit_fn: u64,
        text_base: u64,
        text_size: u64,
    ) -> Result<u64> {
        // Reject duplicate names.
        if self.find_by_name(name).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .modules
            .iter()
            .position(|m| !m.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.alloc_id();

        let mut name_buf = [0u8; MODULE_NAME_LEN];
        let copy_len = name.len().min(MODULE_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        let m = &mut self.modules[slot];
        m.id = id;
        m.name = name_buf;
        m.name_len = copy_len;
        m.state = ModuleState::Live;
        m.init_fn = init_fn;
        m.exit_fn = exit_fn;
        m.text_base = text_base;
        m.text_size = text_size;
        m.data_base = 0;
        m.data_size = 0;
        m.params = [ModuleParam::empty(); MAX_PARAMS];
        m.param_count = 0;
        m.ref_count = 0;
        m.in_use = true;

        self.count = self.count.saturating_add(1);
        Ok(id)
    }

    /// Unloads a kernel module by ID.
    ///
    /// The module must have a zero reference count and no other
    /// module may depend on it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no module with the given ID exists.
    /// Returns [`Error::Busy`] if the module's reference count is
    /// non-zero or other modules depend on it.
    pub fn unload_module(&mut self, id: u64) -> Result<()> {
        let slot = self
            .modules
            .iter()
            .position(|m| m.in_use && m.id == id)
            .ok_or(Error::NotFound)?;

        if self.modules[slot].ref_count != 0 {
            return Err(Error::Busy);
        }

        // Check that no other module depends on this one.
        if self.has_dependents(id) {
            return Err(Error::Busy);
        }

        // Remove all dependency entries involving this module.
        for dep in &mut self.deps {
            if dep.in_use && (dep.mod_id == id || dep.dep_id == id) {
                dep.in_use = false;
                self.dep_count = self.dep_count.saturating_sub(1);
            }
        }

        self.modules[slot].state = ModuleState::Gone;
        self.modules[slot].in_use = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Adds a dependency: module `mod_id` depends on `dep_id`.
    ///
    /// Both IDs must refer to active modules. Self-dependency is
    /// rejected. Duplicate dependencies are silently accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if either module does not exist.
    /// Returns [`Error::InvalidArgument`] if `mod_id == dep_id`.
    /// Returns [`Error::OutOfMemory`] if the dependency table is full.
    pub fn add_dependency(&mut self, mod_id: u64, dep_id: u64) -> Result<()> {
        if mod_id == dep_id {
            return Err(Error::InvalidArgument);
        }

        // Verify both modules exist.
        if self.get(mod_id).is_err() || self.get(dep_id).is_err() {
            return Err(Error::NotFound);
        }

        // Avoid duplicate dependency entries.
        let already_exists = self
            .deps
            .iter()
            .any(|d| d.in_use && d.mod_id == mod_id && d.dep_id == dep_id);
        if already_exists {
            return Ok(());
        }

        let slot = self
            .deps
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.deps[slot] = ModuleDep {
            mod_id,
            dep_id,
            in_use: true,
        };
        self.dep_count = self.dep_count.saturating_add(1);
        Ok(())
    }

    /// Returns a shared reference to a module by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no in-use module with the
    /// given ID exists.
    pub fn get(&self, id: u64) -> Result<&KernelModule> {
        self.modules
            .iter()
            .find(|m| m.in_use && m.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a module by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no in-use module with the
    /// given ID exists.
    pub fn get_mut(&mut self, id: u64) -> Result<&mut KernelModule> {
        self.modules
            .iter_mut()
            .find(|m| m.in_use && m.id == id)
            .ok_or(Error::NotFound)
    }

    /// Finds a module by name, returning its ID.
    pub fn find_by_name(&self, name: &str) -> Option<u64> {
        let name_bytes = name.as_bytes();
        self.modules.iter().find_map(|m| {
            if m.in_use {
                let len = m.name_len.min(MODULE_NAME_LEN);
                if &m.name[..len] == name_bytes {
                    return Some(m.id);
                }
            }
            None
        })
    }

    /// Increments the reference count of a module.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the module does not exist.
    /// Returns [`Error::InvalidArgument`] on overflow.
    pub fn inc_ref(&mut self, id: u64) -> Result<()> {
        let m = self.get_mut(id)?;
        m.ref_count = m.ref_count.checked_add(1).ok_or(Error::InvalidArgument)?;
        Ok(())
    }

    /// Decrements the reference count of a module.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the module does not exist.
    /// Returns [`Error::InvalidArgument`] if the count is already zero.
    pub fn dec_ref(&mut self, id: u64) -> Result<()> {
        let m = self.get_mut(id)?;
        if m.ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        m.ref_count = m.ref_count.saturating_sub(1);
        Ok(())
    }

    /// Returns a slice of all module slots (including inactive ones).
    ///
    /// Callers should filter by `in_use` or `state` to find loaded
    /// modules.
    pub fn list_loaded(&self) -> &[KernelModule] {
        &self.modules[..MAX_MODULES]
    }

    /// Returns the number of active (in-use) modules.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the registry has no active modules.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── private helpers ─────────────────────────────────────────

    /// Checks whether any active module depends on `id`.
    fn has_dependents(&self, id: u64) -> bool {
        self.deps.iter().any(|d| d.in_use && d.dep_id == id)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ModuleRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleRegistry")
            .field("count", &self.count)
            .field("dep_count", &self.dep_count)
            .field("capacity", &MAX_MODULES)
            .field("next_id", &self.next_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_find() {
        let mut reg = ModuleRegistry::new();
        let id = reg
            .load_module("test_mod", 0xDEAD, 0xBEEF, 0x1000, 4096)
            .ok();
        assert!(id.is_some());
        assert_eq!(reg.find_by_name("test_mod"), id);
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn unload_success() {
        let mut reg = ModuleRegistry::new();
        let id = reg.load_module("mod_a", 0x1, 0x2, 0x2000, 8192).ok();
        assert!(id.is_some());
        let id = id.unwrap_or(0);
        assert!(reg.unload_module(id).is_ok());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn unload_busy_ref_count() {
        let mut reg = ModuleRegistry::new();
        let id = reg
            .load_module("mod_b", 0x1, 0x2, 0x3000, 4096)
            .ok()
            .unwrap_or(0);
        assert!(reg.inc_ref(id).is_ok());
        assert_eq!(reg.unload_module(id), Err(Error::Busy));
        assert!(reg.dec_ref(id).is_ok());
        assert!(reg.unload_module(id).is_ok());
    }

    #[test]
    fn unload_blocked_by_dependent() {
        let mut reg = ModuleRegistry::new();
        let a = reg
            .load_module("base", 0x1, 0x2, 0x4000, 4096)
            .ok()
            .unwrap_or(0);
        let b = reg
            .load_module("child", 0x3, 0x4, 0x5000, 4096)
            .ok()
            .unwrap_or(0);
        assert!(reg.add_dependency(b, a).is_ok());
        assert_eq!(reg.unload_module(a), Err(Error::Busy));
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut reg = ModuleRegistry::new();
        assert!(reg.load_module("dup", 0x1, 0x2, 0x7000, 4096).is_ok());
        assert_eq!(
            reg.load_module("dup", 0x3, 0x4, 0x8000, 4096),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn module_params() {
        let mut reg = ModuleRegistry::new();
        let id = reg
            .load_module("param_mod", 0x1, 0x2, 0x9000, 4096)
            .ok()
            .unwrap_or(0);
        let m = reg.get_mut(id);
        assert!(m.is_ok());
        if let Ok(m) = m {
            assert!(m.set_param(b"debug", 1).is_ok());
            assert!(m.set_param(b"level", 42).is_ok());
            assert!(m.get_param(b"debug").is_some());
            assert_eq!(m.get_param(b"debug").map(|p| p.value), Some(1));
            // Overwrite
            assert!(m.set_param(b"debug", 0).is_ok());
            assert_eq!(m.get_param(b"debug").map(|p| p.value), Some(0));
            assert!(m.get_param(b"missing").is_none());
        }
    }

    #[test]
    fn total_size_calculation() {
        let mut m = KernelModule::empty();
        m.text_size = 4096;
        m.data_size = 2048;
        assert_eq!(m.total_size(), 6144);
    }

    #[test]
    fn ref_count_overflow_checked() {
        let mut reg = ModuleRegistry::new();
        let id = reg
            .load_module("rc", 0x1, 0x2, 0xA000, 4096)
            .ok()
            .unwrap_or(0);
        if let Ok(m) = reg.get_mut(id) {
            m.ref_count = u32::MAX;
        }
        assert_eq!(reg.inc_ref(id), Err(Error::InvalidArgument));
    }

    #[test]
    fn list_loaded_returns_all_slots() {
        let reg = ModuleRegistry::new();
        assert_eq!(reg.list_loaded().len(), MAX_MODULES);
    }

    #[test]
    fn self_dependency_rejected() {
        let mut reg = ModuleRegistry::new();
        let id = reg
            .load_module("self_dep", 0x1, 0x2, 0xB000, 4096)
            .ok()
            .unwrap_or(0);
        assert_eq!(reg.add_dependency(id, id), Err(Error::InvalidArgument));
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Loadable kernel module support.
//!
//! Manages the lifecycle of kernel modules: loading, initialisation,
//! dependency tracking, and unloading. Each module has a state
//! machine (Coming → Live → Going) and may declare dependencies on
//! other modules.
//!
//! # Module State Machine
//!
//! ```text
//! Coming ──init()──→ Live ──exit()──→ Going ──cleanup──→ (removed)
//!   │                                   ↑
//!   └── init fails → Going ─────────────┘
//! ```
//!
//! # Architecture
//!
//! ```text
//! ModuleSubsystem
//! ├── modules: [ModuleInfo; MAX_MODULES]
//! │   ├── name, version, state
//! │   ├── init_fn, exit_fn (function pointers)
//! │   ├── dependencies: [dep_ids]
//! │   └── ref_count
//! └── stats: ModuleStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/module/main.c`, `include/linux/module.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of modules.
const MAX_MODULES: usize = 128;

/// Maximum module name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum version string length.
const MAX_VERSION_LEN: usize = 32;

/// Maximum dependencies per module.
const MAX_DEPS: usize = 16;

/// Maximum parameters per module.
const MAX_PARAMS: usize = 16;

/// Maximum parameter name length.
const MAX_PARAM_NAME_LEN: usize = 32;

// ── ModuleState ─────────────────────────────────────────────

/// State of a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModuleState {
    /// Module is being initialised.
    #[default]
    Coming,
    /// Module is live and operational.
    Live,
    /// Module is being removed.
    Going,
}

impl ModuleState {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Coming => "coming",
            Self::Live => "live",
            Self::Going => "going",
        }
    }
}

// ── ModuleInitFn / ModuleExitFn ─────────────────────────────

/// Module init function. Returns Ok(()) on success.
pub type ModuleInitFn = fn() -> Result<()>;

/// Module exit (cleanup) function.
pub type ModuleExitFn = fn();

// ── ModuleParam ─────────────────────────────────────────────

/// A module parameter.
#[derive(Debug, Clone, Copy)]
pub struct ModuleParam {
    /// Parameter name.
    name: [u8; MAX_PARAM_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Parameter value (integer representation).
    value: u64,
    /// Whether this param slot is used.
    active: bool,
}

impl ModuleParam {
    /// Create an empty param.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_PARAM_NAME_LEN],
            name_len: 0,
            value: 0,
            active: false,
        }
    }

    /// Parameter name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_PARAM_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Parameter value.
    pub fn value(&self) -> u64 {
        self.value
    }
}

// ── ModuleInfo ──────────────────────────────────────────────

/// Information about a loaded kernel module.
#[derive(Clone, Copy)]
pub struct ModuleInfo {
    /// Unique module ID.
    id: u32,
    /// Module name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Version string.
    version: [u8; MAX_VERSION_LEN],
    /// Version length.
    version_len: usize,
    /// Current state.
    state: ModuleState,
    /// Initialisation function.
    init_fn: Option<ModuleInitFn>,
    /// Exit (cleanup) function.
    exit_fn: Option<ModuleExitFn>,
    /// IDs of modules this one depends on.
    deps: [u32; MAX_DEPS],
    /// Number of dependencies.
    dep_count: usize,
    /// Reference count (how many others depend on this).
    ref_count: u32,
    /// Module parameters.
    params: [ModuleParam; MAX_PARAMS],
    /// Number of parameters.
    param_count: usize,
    /// Size of the module's code/data in bytes.
    size_bytes: u64,
    /// Load timestamp (ns since boot).
    load_time_ns: u64,
    /// Whether this slot is active.
    active: bool,
}

impl core::fmt::Debug for ModuleInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleInfo")
            .field("id", &self.id)
            .field("name", &self.name_str())
            .field("state", &self.state)
            .field("ref_count", &self.ref_count)
            .field("dep_count", &self.dep_count)
            .finish()
    }
}

impl ModuleInfo {
    /// Create an empty module.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            version: [0u8; MAX_VERSION_LEN],
            version_len: 0,
            state: ModuleState::Coming,
            init_fn: None,
            exit_fn: None,
            deps: [0; MAX_DEPS],
            dep_count: 0,
            ref_count: 0,
            params: [ModuleParam::empty(); MAX_PARAMS],
            param_count: 0,
            size_bytes: 0,
            load_time_ns: 0,
            active: false,
        }
    }

    /// Module ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Module name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Version string.
    pub fn version_str(&self) -> &str {
        let len = self.version_len.min(MAX_VERSION_LEN);
        core::str::from_utf8(&self.version[..len]).unwrap_or("0.0.0")
    }

    /// Current state.
    pub fn state(&self) -> ModuleState {
        self.state
    }

    /// Reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Number of dependencies.
    pub fn dep_count(&self) -> usize {
        self.dep_count
    }

    /// Module size.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Get a parameter by name.
    pub fn get_param(&self, name: &str) -> Option<u64> {
        self.params
            .iter()
            .find(|p| p.active && p.name_str() == name)
            .map(|p| p.value)
    }
}

// ── ModuleStats ─────────────────────────────────────────────

/// Module subsystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleStats {
    /// Total modules loaded.
    pub loaded: u64,
    /// Total modules unloaded.
    pub unloaded: u64,
    /// Total init failures.
    pub init_failures: u64,
    /// Total module lookups.
    pub lookups: u64,
    /// Current active module count.
    pub active_count: u32,
}

// ── ModuleSubsystem ─────────────────────────────────────────

/// Kernel module management subsystem.
pub struct ModuleSubsystem {
    /// Loaded modules.
    modules: [ModuleInfo; MAX_MODULES],
    /// Number of active modules.
    module_count: usize,
    /// Next module ID.
    next_id: u32,
    /// Statistics.
    stats: ModuleStats,
    /// Whether initialized.
    initialized: bool,
}

impl ModuleSubsystem {
    /// Create a new module subsystem.
    pub const fn new() -> Self {
        Self {
            modules: [ModuleInfo::empty(); MAX_MODULES],
            module_count: 0,
            next_id: 1,
            stats: ModuleStats {
                loaded: 0,
                unloaded: 0,
                init_failures: 0,
                lookups: 0,
                active_count: 0,
            },
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Load a module. Returns the module ID.
    ///
    /// The module starts in `Coming` state. Call `init_module` to
    /// run its init function and transition to `Live`.
    pub fn load_module(
        &mut self,
        name: &str,
        version: &str,
        init_fn: Option<ModuleInitFn>,
        exit_fn: Option<ModuleExitFn>,
        size_bytes: u64,
        now_ns: u64,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate name.
        if self.find_by_name(name).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .modules
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.modules[slot] = ModuleInfo::empty();
        self.modules[slot].id = id;
        self.modules[slot].state = ModuleState::Coming;
        self.modules[slot].init_fn = init_fn;
        self.modules[slot].exit_fn = exit_fn;
        self.modules[slot].size_bytes = size_bytes;
        self.modules[slot].load_time_ns = now_ns;
        self.modules[slot].active = true;

        let name_len = name.len().min(MAX_NAME_LEN);
        self.modules[slot].name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        self.modules[slot].name_len = name_len;

        let ver_len = version.len().min(MAX_VERSION_LEN);
        self.modules[slot].version[..ver_len].copy_from_slice(&version.as_bytes()[..ver_len]);
        self.modules[slot].version_len = ver_len;

        self.module_count += 1;
        self.stats.loaded += 1;
        self.stats.active_count = self.module_count as u32;
        Ok(id)
    }

    /// Run a module's init function, transitioning to Live state.
    pub fn init_module(&mut self, module_id: u32) -> Result<()> {
        let module = self
            .modules
            .iter_mut()
            .find(|m| m.active && m.id == module_id)
            .ok_or(Error::NotFound)?;

        if module.state != ModuleState::Coming {
            return Err(Error::InvalidArgument);
        }

        if let Some(init) = module.init_fn {
            match init() {
                Ok(()) => {
                    module.state = ModuleState::Live;
                    Ok(())
                }
                Err(e) => {
                    module.state = ModuleState::Going;
                    self.stats.init_failures += 1;
                    Err(e)
                }
            }
        } else {
            // No init function — go straight to Live.
            module.state = ModuleState::Live;
            Ok(())
        }
    }

    /// Unload a module.
    ///
    /// The module must be in Live state with zero references.
    pub fn unload_module(&mut self, module_id: u32) -> Result<()> {
        let module = self
            .modules
            .iter_mut()
            .find(|m| m.active && m.id == module_id)
            .ok_or(Error::NotFound)?;

        if module.state != ModuleState::Live {
            return Err(Error::InvalidArgument);
        }
        if module.ref_count > 0 {
            return Err(Error::Busy);
        }

        module.state = ModuleState::Going;

        // Run exit function.
        if let Some(exit) = module.exit_fn {
            exit();
        }

        module.active = false;
        self.module_count = self.module_count.saturating_sub(1);
        self.stats.unloaded += 1;
        self.stats.active_count = self.module_count as u32;

        // Decrement ref counts on dependencies.
        let deps = module.deps;
        let dep_count = module.dep_count;
        for &dep_id in &deps[..dep_count] {
            if let Some(dep) = self.modules.iter_mut().find(|m| m.active && m.id == dep_id) {
                dep.ref_count = dep.ref_count.saturating_sub(1);
            }
        }

        Ok(())
    }

    /// Add a dependency: `module_id` depends on `dep_id`.
    pub fn add_dependency(&mut self, module_id: u32, dep_id: u32) -> Result<()> {
        // Verify dependency exists and is live.
        let dep_exists = self
            .modules
            .iter()
            .any(|m| m.active && m.id == dep_id && m.state == ModuleState::Live);
        if !dep_exists {
            return Err(Error::NotFound);
        }

        let module = self
            .modules
            .iter_mut()
            .find(|m| m.active && m.id == module_id)
            .ok_or(Error::NotFound)?;

        if module.dep_count >= MAX_DEPS {
            return Err(Error::OutOfMemory);
        }
        module.deps[module.dep_count] = dep_id;
        module.dep_count += 1;

        // Increment ref count on the dependency.
        if let Some(dep) = self.modules.iter_mut().find(|m| m.active && m.id == dep_id) {
            dep.ref_count = dep.ref_count.saturating_add(1);
        }

        Ok(())
    }

    /// Set a module parameter.
    pub fn set_param(&mut self, module_id: u32, name: &str, value: u64) -> Result<()> {
        let module = self
            .modules
            .iter_mut()
            .find(|m| m.active && m.id == module_id)
            .ok_or(Error::NotFound)?;

        // Check if param already exists.
        for param in &mut module.params {
            if param.active && param.name_str() == name {
                param.value = value;
                return Ok(());
            }
        }

        // Add new param.
        if module.param_count >= MAX_PARAMS {
            return Err(Error::OutOfMemory);
        }
        let idx = module.param_count;
        let name_len = name.len().min(MAX_PARAM_NAME_LEN);
        module.params[idx].name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);
        module.params[idx].name_len = name_len;
        module.params[idx].value = value;
        module.params[idx].active = true;
        module.param_count += 1;
        Ok(())
    }

    /// Find a module by name.
    pub fn find_by_name(&self, name: &str) -> Option<u32> {
        self.stats_inc_lookups();
        self.modules
            .iter()
            .find(|m| m.active && m.name_str() == name)
            .map(|m| m.id)
    }

    /// Get a module by ID.
    pub fn get(&self, module_id: u32) -> Result<&ModuleInfo> {
        self.modules
            .iter()
            .find(|m| m.active && m.id == module_id)
            .ok_or(Error::NotFound)
    }

    /// List all live modules (writes IDs into out).
    pub fn list_live(&self, out: &mut [u32]) -> usize {
        let mut count = 0;
        for m in &self.modules {
            if m.active && m.state == ModuleState::Live {
                if count < out.len() {
                    out[count] = m.id;
                }
                count += 1;
            }
        }
        count.min(out.len())
    }

    /// Number of active modules.
    pub fn module_count(&self) -> usize {
        self.module_count
    }

    /// Statistics.
    pub fn stats(&self) -> &ModuleStats {
        &self.stats
    }

    /// Increment lookup counter (interior pattern).
    fn stats_inc_lookups(&self) {
        // In a real implementation this would be atomic.
        // Omitted here since we don't have &mut self.
    }
}

impl Default for ModuleSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

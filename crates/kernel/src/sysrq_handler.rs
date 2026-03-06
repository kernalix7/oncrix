// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SysRq key handler dispatch.
//!
//! Manages registration and dispatch of SysRq key handlers.
//! Each key code maps to a specific handler that performs an
//! emergency kernel operation (sync, reboot, OOM kill, etc.).
//! Handlers can be registered dynamically by subsystems.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of registered handlers.
const MAX_HANDLERS: usize = 64;

/// Number of possible key codes (ASCII printable range).
const KEY_CODE_COUNT: usize = 128;

/// SysRq enable mask bits.
const SYSRQ_ENABLE_LOG: u32 = 1 << 0;
const SYSRQ_ENABLE_KEYBOARD: u32 = 1 << 1;
const SYSRQ_ENABLE_DUMP: u32 = 1 << 2;
const SYSRQ_ENABLE_SYNC: u32 = 1 << 3;
const SYSRQ_ENABLE_REBOOT: u32 = 1 << 4;
const SYSRQ_ENABLE_SIGNAL: u32 = 1 << 5;
const _SYSRQ_ENABLE_ALL: u32 = 0xFFFF;

// ── Types ────────────────────────────────────────────────────────────

/// Category of SysRq operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysRqCategory {
    /// Logging and debugging.
    Logging,
    /// Keyboard control.
    Keyboard,
    /// Memory/register dump.
    Dump,
    /// Filesystem sync.
    Sync,
    /// System reboot.
    Reboot,
    /// Signal delivery (OOM kill, etc.).
    Signal,
    /// Other/custom category.
    Other,
}

impl Default for SysRqCategory {
    fn default() -> Self {
        Self::Other
    }
}

/// A registered SysRq handler.
#[derive(Debug, Clone)]
pub struct SysRqHandlerEntry {
    /// Handler identifier.
    handler_id: u64,
    /// Key code that triggers this handler (ASCII value).
    key_code: u8,
    /// Category of this handler.
    category: SysRqCategory,
    /// Handler description.
    description: [u8; 64],
    /// Description length.
    desc_len: usize,
    /// Whether this handler is enabled.
    enabled: bool,
    /// Number of times invoked.
    invocation_count: u64,
    /// Required enable mask bit.
    required_mask: u32,
}

impl SysRqHandlerEntry {
    /// Creates a new handler entry.
    pub const fn new(handler_id: u64, key_code: u8, category: SysRqCategory) -> Self {
        let required_mask = match category {
            SysRqCategory::Logging => SYSRQ_ENABLE_LOG,
            SysRqCategory::Keyboard => SYSRQ_ENABLE_KEYBOARD,
            SysRqCategory::Dump => SYSRQ_ENABLE_DUMP,
            SysRqCategory::Sync => SYSRQ_ENABLE_SYNC,
            SysRqCategory::Reboot => SYSRQ_ENABLE_REBOOT,
            SysRqCategory::Signal => SYSRQ_ENABLE_SIGNAL,
            SysRqCategory::Other => 0,
        };
        Self {
            handler_id,
            key_code,
            category,
            description: [0u8; 64],
            desc_len: 0,
            enabled: true,
            invocation_count: 0,
            required_mask,
        }
    }

    /// Returns the key code.
    pub const fn key_code(&self) -> u8 {
        self.key_code
    }

    /// Returns the handler category.
    pub const fn category(&self) -> SysRqCategory {
        self.category
    }

    /// Returns the invocation count.
    pub const fn invocation_count(&self) -> u64 {
        self.invocation_count
    }
}

/// Key-to-handler mapping table.
#[derive(Debug)]
pub struct KeyMap {
    /// Handler identifier for each key code (None = unregistered).
    map: [Option<u64>; KEY_CODE_COUNT],
}

impl KeyMap {
    /// Creates an empty key map.
    pub const fn new() -> Self {
        Self {
            map: [None; KEY_CODE_COUNT],
        }
    }
}

impl Default for KeyMap {
    fn default() -> Self {
        Self::new()
    }
}

/// SysRq dispatch statistics.
#[derive(Debug, Clone)]
pub struct SysRqStats {
    /// Total dispatch attempts.
    pub total_dispatches: u64,
    /// Successful handler invocations.
    pub successful: u64,
    /// Rejected by enable mask.
    pub rejected_mask: u64,
    /// No handler registered for key.
    pub unhandled: u64,
    /// Number of registered handlers.
    pub handler_count: u32,
}

impl Default for SysRqStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SysRqStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_dispatches: 0,
            successful: 0,
            rejected_mask: 0,
            unhandled: 0,
            handler_count: 0,
        }
    }
}

/// Central SysRq handler dispatcher.
#[derive(Debug)]
pub struct SysRqDispatcher {
    /// Registered handlers.
    handlers: [Option<SysRqHandlerEntry>; MAX_HANDLERS],
    /// Key-to-handler mapping.
    key_map: KeyMap,
    /// Number of registered handlers.
    handler_count: usize,
    /// Next handler identifier.
    next_id: u64,
    /// Enable mask controlling which categories are active.
    enable_mask: u32,
    /// Whether SysRq is globally enabled.
    enabled: bool,
    /// Total dispatches.
    total_dispatches: u64,
    /// Successful dispatches.
    successful: u64,
    /// Rejected by mask.
    rejected_mask: u64,
    /// Unhandled keys.
    unhandled: u64,
}

impl Default for SysRqDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SysRqDispatcher {
    /// Creates a new SysRq dispatcher.
    pub const fn new() -> Self {
        Self {
            handlers: [const { None }; MAX_HANDLERS],
            key_map: KeyMap::new(),
            handler_count: 0,
            next_id: 1,
            enable_mask: 0xFFFF,
            enabled: true,
            total_dispatches: 0,
            successful: 0,
            rejected_mask: 0,
            unhandled: 0,
        }
    }

    /// Registers a handler for a key code.
    pub fn register_handler(&mut self, key_code: u8, category: SysRqCategory) -> Result<u64> {
        if (key_code as usize) >= KEY_CODE_COUNT {
            return Err(Error::InvalidArgument);
        }
        if self.key_map.map[key_code as usize].is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.handler_count >= MAX_HANDLERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        let entry = SysRqHandlerEntry::new(id, key_code, category);
        let slot_idx = self
            .handlers
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.handlers[slot_idx] = Some(entry);
        self.key_map.map[key_code as usize] = Some(id);
        self.handler_count += 1;
        Ok(id)
    }

    /// Dispatches a SysRq key press.
    pub fn dispatch(&mut self, key_code: u8) -> Result<()> {
        self.total_dispatches += 1;
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if (key_code as usize) >= KEY_CODE_COUNT {
            return Err(Error::InvalidArgument);
        }
        let handler_id = self.key_map.map[key_code as usize].ok_or_else(|| {
            self.unhandled += 1;
            Error::NotFound
        })?;
        let handler = self
            .handlers
            .iter_mut()
            .flatten()
            .find(|h| h.handler_id == handler_id)
            .ok_or(Error::NotFound)?;
        if !handler.enabled {
            return Err(Error::PermissionDenied);
        }
        if handler.required_mask != 0 && self.enable_mask & handler.required_mask == 0 {
            self.rejected_mask += 1;
            return Err(Error::PermissionDenied);
        }
        handler.invocation_count += 1;
        self.successful += 1;
        Ok(())
    }

    /// Unregisters a handler.
    pub fn unregister_handler(&mut self, handler_id: u64) -> Result<()> {
        let slot_idx = self
            .handlers
            .iter()
            .position(|s| s.as_ref().map_or(false, |h| h.handler_id == handler_id))
            .ok_or(Error::NotFound)?;
        if let Some(h) = &self.handlers[slot_idx] {
            let kc = h.key_code as usize;
            if kc < KEY_CODE_COUNT {
                self.key_map.map[kc] = None;
            }
        }
        self.handlers[slot_idx] = None;
        self.handler_count -= 1;
        Ok(())
    }

    /// Sets the SysRq enable mask.
    pub fn set_enable_mask(&mut self, mask: u32) {
        self.enable_mask = mask;
    }

    /// Enables or disables SysRq globally.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns dispatch statistics.
    pub fn stats(&self) -> SysRqStats {
        SysRqStats {
            total_dispatches: self.total_dispatches,
            successful: self.successful,
            rejected_mask: self.rejected_mask,
            unhandled: self.unhandled,
            handler_count: self.handler_count as u32,
        }
    }

    /// Returns the number of registered handlers.
    pub const fn handler_count(&self) -> usize {
        self.handler_count
    }
}

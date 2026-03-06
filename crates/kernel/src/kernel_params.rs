// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel command-line parameter parsing and typed access.
//!
//! Builds on top of the raw `cmdline` parser to provide a structured,
//! typed parameter registry. Boot-time subsystems register parameters
//! with expected types (bool, integer, string), and the registry
//! validates and stores parsed values for later retrieval.
//!
//! # Architecture
//!
//! ```text
//!  Bootloader cmdline string
//!        │
//!        ▼
//!  KernelParamRegistry::parse_cmdline()
//!        │  ┌──────────────────────────────────┐
//!        ├─►│ ParamEntry { key, type, value }   │ × MAX_PARAMS
//!        │  └──────────────────────────────────┘
//!        ▼
//!  Subsystem queries: get_bool("debug"), get_u64("maxcpus"), ...
//! ```
//!
//! # Parameter Types
//!
//! | Type | Format | Example |
//! |------|--------|---------|
//! | Bool | bare key or `key=1`/`key=0` | `debug`, `nosmp=1` |
//! | U64 | `key=decimal` | `maxcpus=4`, `loglevel=7` |
//! | String | `key=value` | `root=/dev/sda1` |
//! | Size | `key=NNN[KMG]` | `mem=512M` |
//!
//! All storage is stack-allocated (no heap) for use during early boot.
//!
//! Reference: Linux `kernel/params.c`, `include/linux/moduleparam.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of registered kernel parameters.
const MAX_PARAMS: usize = 64;

/// Maximum key length in bytes.
const MAX_KEY_LEN: usize = 64;

/// Maximum string value length in bytes.
const MAX_STRING_LEN: usize = 128;

/// Maximum raw command line length.
const MAX_CMDLINE_LEN: usize = 1024;

/// Maximum number of early-boot parameter callbacks.
const MAX_EARLY_PARAMS: usize = 16;

/// Maximum number of parameter change listeners.
const MAX_LISTENERS: usize = 16;

/// Maximum length of a listener name.
const MAX_LISTENER_NAME_LEN: usize = 32;

// -------------------------------------------------------------------
// ParamType
// -------------------------------------------------------------------

/// The type of a kernel parameter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// Boolean flag (presence or `=1`/`=0`/`=y`/`=n`).
    Bool,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 64-bit integer.
    I64,
    /// Byte string (up to `MAX_STRING_LEN`).
    String,
    /// Size with optional K/M/G suffix.
    Size,
}

// -------------------------------------------------------------------
// ParamValue
// -------------------------------------------------------------------

/// A parsed parameter value.
#[derive(Debug, Clone, Copy)]
pub enum ParamValue {
    /// Boolean value.
    Bool(bool),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 64-bit integer.
    I64(i64),
    /// Byte string stored inline.
    String(ParamString),
    /// Size in bytes (suffix already expanded).
    Size(u64),
    /// No value parsed yet.
    None,
}

impl ParamValue {
    /// Return the boolean value, or `None` if this is not a bool.
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            ParamValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the u64 value, or `None` if this is not a u64.
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            ParamValue::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the i64 value, or `None` if this is not an i64.
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            ParamValue::I64(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the size in bytes, or `None` if this is not a size.
    pub const fn as_size(&self) -> Option<u64> {
        match self {
            ParamValue::Size(v) => Some(*v),
            _ => None,
        }
    }
}

// -------------------------------------------------------------------
// ParamString — inline byte buffer
// -------------------------------------------------------------------

/// Inline byte buffer for string parameter values.
#[derive(Clone, Copy)]
pub struct ParamString {
    /// Raw bytes.
    buf: [u8; MAX_STRING_LEN],
    /// Number of valid bytes.
    len: usize,
}

impl ParamString {
    /// Create an empty param string.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_STRING_LEN],
            len: 0,
        }
    }

    /// Create a param string from a byte slice.
    ///
    /// Truncates silently if `data` exceeds `MAX_STRING_LEN`.
    pub fn from_bytes(data: &[u8]) -> Self {
        let copy_len = if data.len() > MAX_STRING_LEN {
            MAX_STRING_LEN
        } else {
            data.len()
        };
        let mut s = Self::new();
        s.buf[..copy_len].copy_from_slice(&data[..copy_len]);
        s.len = copy_len;
        s
    }

    /// Return the stored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the length in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the string is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ParamString {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ParamString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ParamString({} bytes)", self.len)
    }
}

// -------------------------------------------------------------------
// ParamAccess — permission control
// -------------------------------------------------------------------

/// Access mode for a kernel parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamAccess {
    /// Read-only — can be set at boot but not changed at runtime.
    ReadOnly,
    /// Read-write — can be changed at runtime via sysfs/sysctl.
    ReadWrite,
    /// Write-once — can be set once (at boot or first write), then
    /// becomes read-only.
    WriteOnce,
}

// -------------------------------------------------------------------
// ParamEntry
// -------------------------------------------------------------------

/// A single registered kernel parameter.
#[derive(Debug, Clone, Copy)]
pub struct ParamEntry {
    /// Parameter key (null-terminated byte string).
    key: [u8; MAX_KEY_LEN],
    /// Length of the key.
    key_len: usize,
    /// Expected type.
    param_type: ParamType,
    /// Current value.
    value: ParamValue,
    /// Default value (used if not provided on cmdline).
    default_value: ParamValue,
    /// Access mode.
    access: ParamAccess,
    /// Whether this entry is occupied.
    active: bool,
    /// Whether the value was explicitly set (vs. using default).
    was_set: bool,
    /// Owner subsystem identifier.
    owner_id: u64,
}

impl ParamEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            param_type: ParamType::Bool,
            value: ParamValue::None,
            default_value: ParamValue::None,
            access: ParamAccess::ReadOnly,
            active: false,
            was_set: false,
            owner_id: 0,
        }
    }

    /// Return the key as a byte slice.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Return the current value.
    pub const fn value(&self) -> &ParamValue {
        &self.value
    }

    /// Return the parameter type.
    pub const fn param_type(&self) -> ParamType {
        self.param_type
    }

    /// Return whether this parameter was explicitly set.
    pub const fn was_set(&self) -> bool {
        self.was_set
    }

    /// Return the access mode.
    pub const fn access(&self) -> ParamAccess {
        self.access
    }
}

// -------------------------------------------------------------------
// EarlyParam — boot-time parameter callback
// -------------------------------------------------------------------

/// Callback type for early boot parameters.
///
/// Receives the raw value bytes (or empty slice for bare flags).
/// Returns `Ok(())` on success.
pub type EarlyParamFn = fn(&[u8]) -> Result<()>;

/// An early-boot parameter callback registration.
#[derive(Clone, Copy)]
struct EarlyParam {
    /// Parameter key to match.
    key: [u8; MAX_KEY_LEN],
    /// Length of the key.
    key_len: usize,
    /// Callback to invoke when this key is found.
    callback: EarlyParamFn,
    /// Whether this slot is in use.
    active: bool,
}

impl EarlyParam {
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            callback: |_| Ok(()),
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// ParamListener — runtime change notification
// -------------------------------------------------------------------

/// Callback for parameter change notifications.
pub type ParamListenerFn = fn(key: &[u8], old: &ParamValue, new: &ParamValue);

/// A listener that receives parameter change notifications.
#[derive(Clone, Copy)]
struct ParamListener {
    /// Listener name for debugging.
    name: [u8; MAX_LISTENER_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Key pattern to match (empty = all parameters).
    key_filter: [u8; MAX_KEY_LEN],
    /// Filter key length (0 = match all).
    filter_len: usize,
    /// Callback function.
    callback: ParamListenerFn,
    /// Whether this slot is active.
    active: bool,
}

impl ParamListener {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_LISTENER_NAME_LEN],
            name_len: 0,
            key_filter: [0u8; MAX_KEY_LEN],
            filter_len: 0,
            callback: |_, _, _| {},
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// ParseStats
// -------------------------------------------------------------------

/// Statistics about the last command-line parse.
#[derive(Debug, Clone, Copy)]
pub struct ParseStats {
    /// Total tokens found on the command line.
    pub total_tokens: usize,
    /// Tokens successfully matched to registered params.
    pub matched_tokens: usize,
    /// Tokens that matched an early-boot callback.
    pub early_tokens: usize,
    /// Tokens that could not be matched.
    pub unknown_tokens: usize,
    /// Tokens with parse errors (type mismatch, overflow, etc.).
    pub error_tokens: usize,
}

impl ParseStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_tokens: 0,
            matched_tokens: 0,
            early_tokens: 0,
            unknown_tokens: 0,
            error_tokens: 0,
        }
    }
}

// -------------------------------------------------------------------
// KernelParamRegistry
// -------------------------------------------------------------------

/// Central registry for kernel command-line parameters.
///
/// Subsystems register their expected parameters (with type and
/// default value) before the command line is parsed. After parsing,
/// each subsystem queries its parameters by key.
pub struct KernelParamRegistry {
    /// Registered parameter entries.
    params: [ParamEntry; MAX_PARAMS],
    /// Number of active parameters.
    count: usize,
    /// Raw command line buffer (preserved for /proc/cmdline).
    raw_cmdline: [u8; MAX_CMDLINE_LEN],
    /// Length of the raw command line.
    raw_len: usize,
    /// Early-boot parameter callbacks.
    early_params: [EarlyParam; MAX_EARLY_PARAMS],
    /// Number of registered early params.
    early_count: usize,
    /// Parameter change listeners.
    listeners: [ParamListener; MAX_LISTENERS],
    /// Number of active listeners.
    listener_count: usize,
    /// Statistics from the last parse.
    stats: ParseStats,
    /// Whether the cmdline has been parsed.
    parsed: bool,
}

impl Default for KernelParamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelParamRegistry {
    /// Create an empty parameter registry.
    pub const fn new() -> Self {
        Self {
            params: [const { ParamEntry::empty() }; MAX_PARAMS],
            count: 0,
            raw_cmdline: [0u8; MAX_CMDLINE_LEN],
            raw_len: 0,
            early_params: [const { EarlyParam::empty() }; MAX_EARLY_PARAMS],
            early_count: 0,
            listeners: [const { ParamListener::empty() }; MAX_LISTENERS],
            listener_count: 0,
            stats: ParseStats::new(),
            parsed: false,
        }
    }

    /// Register a boolean parameter with a default value.
    pub fn register_bool(
        &mut self,
        key: &[u8],
        default: bool,
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        self.register_param(
            key,
            ParamType::Bool,
            ParamValue::Bool(default),
            access,
            owner_id,
        )
    }

    /// Register a u64 parameter with a default value.
    pub fn register_u64(
        &mut self,
        key: &[u8],
        default: u64,
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        self.register_param(
            key,
            ParamType::U64,
            ParamValue::U64(default),
            access,
            owner_id,
        )
    }

    /// Register an i64 parameter with a default value.
    pub fn register_i64(
        &mut self,
        key: &[u8],
        default: i64,
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        self.register_param(
            key,
            ParamType::I64,
            ParamValue::I64(default),
            access,
            owner_id,
        )
    }

    /// Register a string parameter with a default value.
    pub fn register_string(
        &mut self,
        key: &[u8],
        default: &[u8],
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        self.register_param(
            key,
            ParamType::String,
            ParamValue::String(ParamString::from_bytes(default)),
            access,
            owner_id,
        )
    }

    /// Register a size parameter (with K/M/G suffix support).
    pub fn register_size(
        &mut self,
        key: &[u8],
        default_bytes: u64,
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        self.register_param(
            key,
            ParamType::Size,
            ParamValue::Size(default_bytes),
            access,
            owner_id,
        )
    }

    /// Internal parameter registration.
    fn register_param(
        &mut self,
        key: &[u8],
        param_type: ParamType,
        default: ParamValue,
        access: ParamAccess,
        owner_id: u64,
    ) -> Result<()> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicates.
        for i in 0..self.count {
            if self.params[i].active
                && self.params[i].key_len == key.len()
                && self.params[i].key[..key.len()] == *key
            {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_PARAMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.params[idx].key[..key.len()].copy_from_slice(key);
        self.params[idx].key_len = key.len();
        self.params[idx].param_type = param_type;
        self.params[idx].value = default;
        self.params[idx].default_value = default;
        self.params[idx].access = access;
        self.params[idx].active = true;
        self.params[idx].was_set = false;
        self.params[idx].owner_id = owner_id;
        self.count += 1;
        Ok(())
    }

    /// Register an early-boot parameter callback.
    ///
    /// Early params are processed before the main parse and are used
    /// for things that must be configured very early (e.g., memory
    /// layout, console setup).
    pub fn register_early_param(&mut self, key: &[u8], callback: EarlyParamFn) -> Result<()> {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.early_count >= MAX_EARLY_PARAMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.early_count;
        self.early_params[idx].key[..key.len()].copy_from_slice(key);
        self.early_params[idx].key_len = key.len();
        self.early_params[idx].callback = callback;
        self.early_params[idx].active = true;
        self.early_count += 1;
        Ok(())
    }

    /// Register a parameter change listener.
    ///
    /// If `key_filter` is empty, the listener receives all changes.
    pub fn register_listener(
        &mut self,
        name: &[u8],
        key_filter: &[u8],
        callback: ParamListenerFn,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_LISTENER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if key_filter.len() > MAX_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.listener_count >= MAX_LISTENERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.listener_count;
        self.listeners[idx].name[..name.len()].copy_from_slice(name);
        self.listeners[idx].name_len = name.len();
        if !key_filter.is_empty() {
            self.listeners[idx].key_filter[..key_filter.len()].copy_from_slice(key_filter);
        }
        self.listeners[idx].filter_len = key_filter.len();
        self.listeners[idx].callback = callback;
        self.listeners[idx].active = true;
        self.listener_count += 1;
        Ok(())
    }

    /// Parse a boot command-line string.
    ///
    /// Splits the string on whitespace, matches each token to
    /// registered parameters, and parses the value according to
    /// the expected type. Unknown tokens are counted but silently
    /// ignored (they may be intended for user-space init).
    pub fn parse_cmdline(&mut self, cmdline: &[u8]) -> Result<ParseStats> {
        // Preserve raw cmdline.
        let copy_len = if cmdline.len() > MAX_CMDLINE_LEN {
            MAX_CMDLINE_LEN
        } else {
            cmdline.len()
        };
        self.raw_cmdline[..copy_len].copy_from_slice(&cmdline[..copy_len]);
        self.raw_len = copy_len;

        let mut stats = ParseStats::new();
        let mut pos = 0;

        while pos < copy_len {
            // Skip leading whitespace.
            while pos < copy_len && cmdline[pos] == b' ' {
                pos += 1;
            }
            if pos >= copy_len {
                break;
            }

            // Find the end of this token.
            let token_start = pos;
            while pos < copy_len && cmdline[pos] != b' ' {
                pos += 1;
            }
            let token = &cmdline[token_start..pos];
            stats.total_tokens += 1;

            // Split on '=' if present.
            let (key, value) = split_key_value(token);

            // Try early params first.
            if self.try_early_param(key, value) {
                stats.early_tokens += 1;
                continue;
            }

            // Find matching registered param.
            match self.find_param_index(key) {
                Some(idx) => match self.parse_and_set(idx, value) {
                    Ok(()) => stats.matched_tokens += 1,
                    Err(_) => stats.error_tokens += 1,
                },
                None => stats.unknown_tokens += 1,
            }
        }

        self.stats = stats;
        self.parsed = true;
        Ok(stats)
    }

    /// Try to match and invoke an early-boot parameter callback.
    fn try_early_param(&self, key: &[u8], value: &[u8]) -> bool {
        for i in 0..self.early_count {
            if !self.early_params[i].active {
                continue;
            }
            let ep_key = &self.early_params[i].key[..self.early_params[i].key_len];
            if ep_key == key {
                let _ = (self.early_params[i].callback)(value);
                return true;
            }
        }
        false
    }

    /// Find the index of a parameter by key.
    fn find_param_index(&self, key: &[u8]) -> Option<usize> {
        for i in 0..self.count {
            if !self.params[i].active {
                continue;
            }
            if self.params[i].key_len == key.len() && self.params[i].key[..key.len()] == *key {
                return Some(i);
            }
        }
        None
    }

    /// Parse a value string and set it on the parameter at `idx`.
    fn parse_and_set(&mut self, idx: usize, value: &[u8]) -> Result<()> {
        let parsed = match self.params[idx].param_type {
            ParamType::Bool => parse_bool_value(value)?,
            ParamType::U64 => parse_u64_value(value)?,
            ParamType::I64 => parse_i64_value(value)?,
            ParamType::String => ParamValue::String(ParamString::from_bytes(value)),
            ParamType::Size => parse_size_value(value)?,
        };
        self.params[idx].value = parsed;
        self.params[idx].was_set = true;
        Ok(())
    }

    /// Look up a parameter by key and return its value.
    pub fn get(&self, key: &[u8]) -> Option<&ParamValue> {
        self.find_param_index(key)
            .map(|idx| &self.params[idx].value)
    }

    /// Get a boolean parameter value.
    pub fn get_bool(&self, key: &[u8]) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    /// Get a u64 parameter value.
    pub fn get_u64(&self, key: &[u8]) -> Option<u64> {
        self.get(key).and_then(|v| v.as_u64())
    }

    /// Get a size parameter value (in bytes).
    pub fn get_size(&self, key: &[u8]) -> Option<u64> {
        self.get(key).and_then(|v| v.as_size())
    }

    /// Get a string parameter value as bytes.
    pub fn get_string(&self, key: &[u8]) -> Option<&[u8]> {
        match self.get(key) {
            Some(ParamValue::String(s)) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Set a parameter value at runtime.
    ///
    /// Respects access modes: ReadOnly params cannot be changed,
    /// WriteOnce params can only be changed if not previously set.
    pub fn set(&mut self, key: &[u8], value: ParamValue) -> Result<()> {
        let idx = self.find_param_index(key).ok_or(Error::NotFound)?;

        match self.params[idx].access {
            ParamAccess::ReadOnly => {
                return Err(Error::PermissionDenied);
            }
            ParamAccess::WriteOnce if self.params[idx].was_set => {
                return Err(Error::PermissionDenied);
            }
            _ => {}
        }

        let old_value = self.params[idx].value;
        self.params[idx].value = value;
        self.params[idx].was_set = true;

        // Notify listeners.
        self.notify_listeners(key, &old_value, &value);
        Ok(())
    }

    /// Notify matching listeners about a parameter change.
    fn notify_listeners(&self, key: &[u8], old: &ParamValue, new: &ParamValue) {
        for i in 0..self.listener_count {
            if !self.listeners[i].active {
                continue;
            }
            let filter = &self.listeners[i].key_filter[..self.listeners[i].filter_len];
            // Empty filter matches all keys.
            if filter.is_empty() || filter == key {
                (self.listeners[i].callback)(key, old, new);
            }
        }
    }

    /// Reset a parameter to its default value.
    pub fn reset_to_default(&mut self, key: &[u8]) -> Result<()> {
        let idx = self.find_param_index(key).ok_or(Error::NotFound)?;
        if self.params[idx].access == ParamAccess::ReadOnly {
            return Err(Error::PermissionDenied);
        }
        self.params[idx].value = self.params[idx].default_value;
        self.params[idx].was_set = false;
        Ok(())
    }

    /// Return the raw command-line bytes.
    pub fn raw_cmdline(&self) -> &[u8] {
        &self.raw_cmdline[..self.raw_len]
    }

    /// Return parse statistics.
    pub const fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Return whether the cmdline has been parsed.
    pub const fn is_parsed(&self) -> bool {
        self.parsed
    }

    /// Return the number of registered parameters.
    pub const fn param_count(&self) -> usize {
        self.count
    }

    /// Return a reference to a parameter entry by index.
    pub fn param_at(&self, index: usize) -> Option<&ParamEntry> {
        if index < self.count && self.params[index].active {
            Some(&self.params[index])
        } else {
            None
        }
    }

    /// Iterate over all active parameters and write to a buffer.
    ///
    /// Format: `key=value\n` for each set parameter, `key\n` for
    /// bool flags. Returns the number of bytes written.
    pub fn dump_params(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for i in 0..self.count {
            if !self.params[i].active || !self.params[i].was_set {
                continue;
            }
            let key = &self.params[i].key[..self.params[i].key_len];

            // Write key.
            let key_end = offset + key.len();
            if key_end >= buf.len() {
                break;
            }
            buf[offset..key_end].copy_from_slice(key);
            offset = key_end;

            // Write value representation.
            match &self.params[i].value {
                ParamValue::Bool(v) => {
                    let s = if *v { b"=1" } else { b"=0" };
                    let end = offset + s.len();
                    if end >= buf.len() {
                        break;
                    }
                    buf[offset..end].copy_from_slice(s);
                    offset = end;
                }
                ParamValue::U64(v) => {
                    offset = write_u64_to_buf(buf, offset, *v);
                }
                ParamValue::I64(v) => {
                    offset = write_i64_to_buf(buf, offset, *v);
                }
                ParamValue::Size(v) => {
                    offset = write_u64_to_buf(buf, offset, *v);
                }
                ParamValue::String(s) => {
                    let end = offset + 1 + s.len();
                    if end >= buf.len() {
                        break;
                    }
                    buf[offset] = b'=';
                    offset += 1;
                    buf[offset..offset + s.len()].copy_from_slice(s.as_bytes());
                    offset += s.len();
                }
                ParamValue::None => {}
            }

            // Newline.
            if offset < buf.len() {
                buf[offset] = b'\n';
                offset += 1;
            }
        }
        offset
    }

    /// Unregister a parameter by key.
    pub fn unregister(&mut self, key: &[u8]) -> Result<()> {
        let idx = self.find_param_index(key).ok_or(Error::NotFound)?;
        self.params[idx].active = false;
        Ok(())
    }

    /// Remove a listener by name.
    pub fn remove_listener(&mut self, name: &[u8]) -> Result<()> {
        for i in 0..self.listener_count {
            if !self.listeners[i].active {
                continue;
            }
            let ln = &self.listeners[i].name[..self.listeners[i].name_len];
            if ln == name {
                self.listeners[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

// -------------------------------------------------------------------
// Parsing helpers
// -------------------------------------------------------------------

/// Split a token at the first `=` into (key, value).
///
/// If no `=` is present, returns (token, &[]).
fn split_key_value(token: &[u8]) -> (&[u8], &[u8]) {
    for (i, &b) in token.iter().enumerate() {
        if b == b'=' {
            return (&token[..i], &token[i + 1..]);
        }
    }
    (token, &[])
}

/// Parse a boolean value from command-line format.
///
/// Accepted: empty (bare flag → true), `1`/`0`, `y`/`n`,
/// `yes`/`no`, `on`/`off`.
fn parse_bool_value(value: &[u8]) -> Result<ParamValue> {
    if value.is_empty() {
        return Ok(ParamValue::Bool(true));
    }
    match value {
        b"1" | b"y" | b"yes" | b"on" | b"true" => Ok(ParamValue::Bool(true)),
        b"0" | b"n" | b"no" | b"off" | b"false" => Ok(ParamValue::Bool(false)),
        _ => Err(Error::InvalidArgument),
    }
}

/// Parse a u64 value from decimal ASCII.
fn parse_u64_value(value: &[u8]) -> Result<ParamValue> {
    let v = parse_decimal_u64(value)?;
    Ok(ParamValue::U64(v))
}

/// Parse an i64 value from optional-sign decimal ASCII.
fn parse_i64_value(value: &[u8]) -> Result<ParamValue> {
    if value.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let (negative, digits) = if value[0] == b'-' {
        (true, &value[1..])
    } else if value[0] == b'+' {
        (false, &value[1..])
    } else {
        (false, value)
    };
    let abs = parse_decimal_u64(digits)?;
    if negative {
        if abs > (i64::MAX as u64) + 1 {
            return Err(Error::InvalidArgument);
        }
        // Two's complement negation.
        Ok(ParamValue::I64(-(abs as i64)))
    } else {
        if abs > i64::MAX as u64 {
            return Err(Error::InvalidArgument);
        }
        Ok(ParamValue::I64(abs as i64))
    }
}

/// Parse a size value with optional K/M/G suffix.
///
/// `512M` → 512 * 1024 * 1024 = 536870912
fn parse_size_value(value: &[u8]) -> Result<ParamValue> {
    if value.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let last = value[value.len() - 1];
    let (digits, multiplier) = match last {
        b'K' | b'k' => (&value[..value.len() - 1], 1024u64),
        b'M' | b'm' => (&value[..value.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&value[..value.len() - 1], 1024 * 1024 * 1024),
        _ => (value, 1u64),
    };
    let base = parse_decimal_u64(digits)?;
    base.checked_mul(multiplier)
        .map(ParamValue::Size)
        .ok_or(Error::InvalidArgument)
}

/// Parse decimal ASCII digits to u64.
fn parse_decimal_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut result: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(Error::InvalidArgument);
        }
        let digit = (b - b'0') as u64;
        result = result
            .checked_mul(10)
            .and_then(|r| r.checked_add(digit))
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

/// Write `=<u64>` into a buffer at the given offset.
/// Returns the new offset.
fn write_u64_to_buf(buf: &mut [u8], offset: usize, val: u64) -> usize {
    let mut tmp = [0u8; 21]; // max u64 is 20 digits + '='
    tmp[0] = b'=';
    let digits = format_u64(&mut tmp[1..], val);
    let total = 1 + digits;
    let end = offset + total;
    if end > buf.len() {
        return offset;
    }
    buf[offset..end].copy_from_slice(&tmp[..total]);
    end
}

/// Write `=<i64>` into a buffer at the given offset.
/// Returns the new offset.
fn write_i64_to_buf(buf: &mut [u8], offset: usize, val: i64) -> usize {
    if val < 0 {
        // Write '=-' then the absolute value.
        if offset + 2 > buf.len() {
            return offset;
        }
        buf[offset] = b'=';
        buf[offset + 1] = b'-';
        let abs = if val == i64::MIN {
            (i64::MAX as u64) + 1
        } else {
            (-val) as u64
        };
        let mut tmp = [0u8; 20];
        let digits = format_u64(&mut tmp, abs);
        let end = offset + 2 + digits;
        if end > buf.len() {
            return offset;
        }
        buf[offset + 2..end].copy_from_slice(&tmp[..digits]);
        end
    } else {
        write_u64_to_buf(buf, offset, val as u64)
    }
}

/// Format a u64 into a byte buffer, returning the number of digits.
fn format_u64(buf: &mut [u8], val: u64) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    // Write digits in reverse.
    let mut tmp = [0u8; 20];
    let mut n = val;
    let mut count = 0;
    while n > 0 {
        tmp[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    // Reverse into output buffer.
    let write_len = if count > buf.len() { buf.len() } else { count };
    for i in 0..write_len {
        buf[i] = tmp[count - 1 - i];
    }
    write_len
}

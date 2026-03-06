// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kobject uevent notification system.
//!
//! Implements the kernel object (kobject) uevent mechanism that
//! notifies user-space about device and subsystem events. This is
//! the kernel-side counterpart to udev/systemd-udevd:
//!
//! - Device add/remove/change/move/online/offline
//! - Attribute changes
//! - Driver binding/unbinding
//!
//! # Architecture
//!
//! ```text
//!  Driver / subsystem
//!    │ kobject_uevent(kobj, action)
//!    ▼
//!  UeventManager
//!    ├── Filter events (suppress, seqnum, etc.)
//!    ├── Build environment variables (ACTION, DEVPATH, ...)
//!    ├── Queue to netlink broadcast buffer
//!    └── Optionally call uevent_helper (e.g., /sbin/hotplug)
//!
//!  User-space
//!    ├── udevd (listens on NETLINK_KOBJECT_UEVENT)
//!    └── reads /sys/... for device attributes
//! ```
//!
//! # Environment Variables
//!
//! Each uevent carries a set of key=value environment variables:
//! - `ACTION` — add, remove, change, move, online, offline, bind, unbind
//! - `DEVPATH` — sysfs device path
//! - `SUBSYSTEM` — subsystem name (e.g., "block", "net", "usb")
//! - `SEQNUM` — monotonic sequence number
//! - Optional: `DEVNAME`, `DEVTYPE`, `DRIVER`, `MAJOR`, `MINOR`, etc.
//!
//! Reference: Linux `lib/kobject_uevent.c`,
//! `include/linux/kobject.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of kobjects that can be registered.
const MAX_KOBJECTS: usize = 128;

/// Maximum length of a kobject name.
const MAX_KOBJ_NAME_LEN: usize = 64;

/// Maximum length of a device path.
const MAX_DEVPATH_LEN: usize = 256;

/// Maximum length of a subsystem name.
const MAX_SUBSYSTEM_LEN: usize = 32;

/// Maximum number of environment variables per uevent.
const MAX_ENV_VARS: usize = 16;

/// Maximum length of an env var key.
const MAX_ENV_KEY_LEN: usize = 32;

/// Maximum length of an env var value.
const MAX_ENV_VAL_LEN: usize = 128;

/// Maximum number of pending uevents in the queue.
const MAX_UEVENT_QUEUE: usize = 256;

/// Maximum number of uevent listeners.
const MAX_LISTENERS: usize = 16;

/// Maximum number of uevent filters (suppress rules).
const MAX_FILTERS: usize = 16;

/// Maximum length of a filter pattern.
const MAX_FILTER_PATTERN_LEN: usize = 64;

/// Maximum uevent helper path length.
const MAX_HELPER_PATH_LEN: usize = 128;

// -------------------------------------------------------------------
// UeventAction
// -------------------------------------------------------------------

/// Uevent action type.
///
/// Maps to the `ACTION=` environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UeventAction {
    /// Device or object added.
    Add,
    /// Device or object removed.
    Remove,
    /// Device state changed.
    Change,
    /// Device moved (renamed).
    Move,
    /// Device online.
    Online,
    /// Device offline.
    Offline,
    /// Driver bound to device.
    Bind,
    /// Driver unbound from device.
    Unbind,
}

impl UeventAction {
    /// Return the action string for the `ACTION=` env var.
    pub const fn as_str(&self) -> &'static [u8] {
        match self {
            Self::Add => b"add",
            Self::Remove => b"remove",
            Self::Change => b"change",
            Self::Move => b"move",
            Self::Online => b"online",
            Self::Offline => b"offline",
            Self::Bind => b"bind",
            Self::Unbind => b"unbind",
        }
    }
}

// -------------------------------------------------------------------
// KobjType — object classification
// -------------------------------------------------------------------

/// Kobject type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KobjType {
    /// A device (block, char, net, etc.).
    Device,
    /// A subsystem.
    Subsystem,
    /// A driver.
    Driver,
    /// A bus.
    Bus,
    /// A class.
    Class,
    /// A firmware object.
    Firmware,
    /// A module.
    Module,
    /// Generic kobject.
    Generic,
}

// -------------------------------------------------------------------
// EnvVar — uevent environment variable
// -------------------------------------------------------------------

/// A single key=value environment variable.
#[derive(Clone, Copy)]
pub struct EnvVar {
    /// Key bytes.
    key: [u8; MAX_ENV_KEY_LEN],
    /// Key length.
    key_len: usize,
    /// Value bytes.
    value: [u8; MAX_ENV_VAL_LEN],
    /// Value length.
    value_len: usize,
    /// Whether this slot is in use.
    active: bool,
}

impl EnvVar {
    /// Create an empty env var.
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_ENV_KEY_LEN],
            key_len: 0,
            value: [0u8; MAX_ENV_VAL_LEN],
            value_len: 0,
            active: false,
        }
    }

    /// Create an env var from key and value byte slices.
    pub fn from_kv(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.is_empty() || key.len() > MAX_ENV_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        if value.len() > MAX_ENV_VAL_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut ev = Self::empty();
        ev.key[..key.len()].copy_from_slice(key);
        ev.key_len = key.len();
        ev.value[..value.len()].copy_from_slice(value);
        ev.value_len = value.len();
        ev.active = true;
        Ok(ev)
    }

    /// Return the key bytes.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Return the value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

impl core::fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EnvVar({} bytes)", self.key_len + self.value_len)
    }
}

// -------------------------------------------------------------------
// UeventEnv — environment variable set
// -------------------------------------------------------------------

/// A set of environment variables for a uevent.
#[derive(Clone, Copy)]
pub struct UeventEnv {
    /// Variables.
    vars: [EnvVar; MAX_ENV_VARS],
    /// Number of active variables.
    count: usize,
}

impl UeventEnv {
    /// Create an empty environment.
    const fn new() -> Self {
        Self {
            vars: [const { EnvVar::empty() }; MAX_ENV_VARS],
            count: 0,
        }
    }

    /// Add a key=value pair.
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if self.count >= MAX_ENV_VARS {
            return Err(Error::OutOfMemory);
        }
        self.vars[self.count] = EnvVar::from_kv(key, value)?;
        self.count += 1;
        Ok(())
    }

    /// Find a variable by key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        for i in 0..self.count {
            if self.vars[i].active
                && self.vars[i].key_len == key.len()
                && self.vars[i].key[..key.len()] == *key
            {
                return Some(self.vars[i].value());
            }
        }
        None
    }

    /// Return the number of variables.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return a variable by index.
    pub fn var_at(&self, index: usize) -> Option<&EnvVar> {
        if index < self.count && self.vars[index].active {
            Some(&self.vars[index])
        } else {
            None
        }
    }

    /// Serialize all variables into a buffer as "KEY=VALUE\0" pairs.
    ///
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for i in 0..self.count {
            if !self.vars[i].active {
                continue;
            }
            let key = self.vars[i].key();
            let val = self.vars[i].value();
            // KEY=VALUE\0
            let needed = key.len() + 1 + val.len() + 1;
            if offset + needed > buf.len() {
                break;
            }
            buf[offset..offset + key.len()].copy_from_slice(key);
            offset += key.len();
            buf[offset] = b'=';
            offset += 1;
            buf[offset..offset + val.len()].copy_from_slice(val);
            offset += val.len();
            buf[offset] = 0;
            offset += 1;
        }
        offset
    }
}

impl Default for UeventEnv {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Kobject
// -------------------------------------------------------------------

/// A kernel object that can generate uevents.
#[derive(Clone, Copy)]
pub struct Kobject {
    /// Object name.
    name: [u8; MAX_KOBJ_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Device path in sysfs.
    devpath: [u8; MAX_DEVPATH_LEN],
    /// Devpath length.
    devpath_len: usize,
    /// Subsystem name.
    subsystem: [u8; MAX_SUBSYSTEM_LEN],
    /// Subsystem name length.
    subsystem_len: usize,
    /// Object type.
    kobj_type: KobjType,
    /// Unique kobject ID.
    kobj_id: u64,
    /// Parent kobject ID (0 = root).
    parent_id: u64,
    /// Whether uevents are suppressed for this object.
    uevent_suppress: bool,
    /// Whether this slot is active.
    active: bool,
    /// Reference count.
    ref_count: u32,
}

impl Kobject {
    /// Create an empty, inactive kobject.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_KOBJ_NAME_LEN],
            name_len: 0,
            devpath: [0u8; MAX_DEVPATH_LEN],
            devpath_len: 0,
            subsystem: [0u8; MAX_SUBSYSTEM_LEN],
            subsystem_len: 0,
            kobj_type: KobjType::Generic,
            kobj_id: 0,
            parent_id: 0,
            uevent_suppress: false,
            active: false,
            ref_count: 0,
        }
    }

    /// Return the name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the device path.
    pub fn devpath(&self) -> &[u8] {
        &self.devpath[..self.devpath_len]
    }

    /// Return the subsystem name.
    pub fn subsystem(&self) -> &[u8] {
        &self.subsystem[..self.subsystem_len]
    }

    /// Return the kobject type.
    pub const fn kobj_type(&self) -> KobjType {
        self.kobj_type
    }

    /// Return the kobject ID.
    pub const fn kobj_id(&self) -> u64 {
        self.kobj_id
    }

    /// Return the parent ID.
    pub const fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Return whether uevents are suppressed.
    pub const fn is_suppressed(&self) -> bool {
        self.uevent_suppress
    }

    /// Return the reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }
}

impl core::fmt::Debug for Kobject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kobject")
            .field("id", &self.kobj_id)
            .field("type", &self.kobj_type)
            .field("ref_count", &self.ref_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// UeventEntry — queued uevent
// -------------------------------------------------------------------

/// A queued uevent waiting to be dispatched.
#[derive(Clone, Copy)]
struct UeventEntry {
    /// Kobject ID that generated this event.
    kobj_id: u64,
    /// Action type.
    action: UeventAction,
    /// Sequence number.
    seqnum: u64,
    /// Environment variables.
    env: UeventEnv,
    /// Whether this slot is occupied.
    active: bool,
}

impl UeventEntry {
    const fn empty() -> Self {
        Self {
            kobj_id: 0,
            action: UeventAction::Add,
            seqnum: 0,
            env: UeventEnv::new(),
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// UeventFilter — suppress rules
// -------------------------------------------------------------------

/// A filter rule to suppress certain uevents.
#[derive(Clone, Copy)]
struct UeventFilter {
    /// Subsystem pattern to match (empty = match all).
    subsystem: [u8; MAX_FILTER_PATTERN_LEN],
    /// Subsystem pattern length.
    subsystem_len: usize,
    /// Action to filter (None = match all actions).
    action: Option<UeventAction>,
    /// Whether this filter is active.
    active: bool,
}

impl UeventFilter {
    const fn empty() -> Self {
        Self {
            subsystem: [0u8; MAX_FILTER_PATTERN_LEN],
            subsystem_len: 0,
            action: None,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// UeventListener callback
// -------------------------------------------------------------------

/// Callback type for uevent listeners.
///
/// Receives the action, kobject reference, and environment vars.
pub type UeventListenerFn = fn(UeventAction, &Kobject, &UeventEnv);

/// A registered uevent listener.
#[derive(Clone, Copy)]
struct UeventListener {
    /// Listener name.
    name: [u8; MAX_KOBJ_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Callback.
    callback: UeventListenerFn,
    /// Subsystem filter (empty = all).
    subsystem_filter: [u8; MAX_SUBSYSTEM_LEN],
    /// Filter length.
    filter_len: usize,
    /// Active flag.
    active: bool,
}

/// Default listener callback.
fn default_listener(_action: UeventAction, _kobj: &Kobject, _env: &UeventEnv) {}

impl UeventListener {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_KOBJ_NAME_LEN],
            name_len: 0,
            callback: default_listener,
            subsystem_filter: [0u8; MAX_SUBSYSTEM_LEN],
            filter_len: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// UeventStats
// -------------------------------------------------------------------

/// Statistics about uevent processing.
#[derive(Debug, Clone, Copy)]
pub struct UeventStats {
    /// Total uevents generated.
    pub total_generated: u64,
    /// Uevents suppressed by filters.
    pub total_suppressed: u64,
    /// Uevents delivered to listeners.
    pub total_delivered: u64,
    /// Uevents dropped (queue full).
    pub total_dropped: u64,
    /// Current queue depth.
    pub queue_depth: usize,
}

impl UeventStats {
    const fn new() -> Self {
        Self {
            total_generated: 0,
            total_suppressed: 0,
            total_delivered: 0,
            total_dropped: 0,
            queue_depth: 0,
        }
    }
}

// -------------------------------------------------------------------
// UeventManager
// -------------------------------------------------------------------

/// Central manager for kobject uevent notifications.
pub struct UeventManager {
    /// Registered kobjects.
    kobjects: [Kobject; MAX_KOBJECTS],
    /// Number of active kobjects.
    kobj_count: usize,
    /// Next kobject ID.
    next_kobj_id: u64,
    /// Uevent queue (ring buffer).
    queue: [UeventEntry; MAX_UEVENT_QUEUE],
    /// Queue head (next entry to dequeue).
    queue_head: usize,
    /// Queue tail (next slot to enqueue).
    queue_tail: usize,
    /// Current queue count.
    queue_count: usize,
    /// Global sequence number counter.
    seqnum: u64,
    /// Uevent listeners.
    listeners: [UeventListener; MAX_LISTENERS],
    /// Listener count.
    listener_count: usize,
    /// Suppress filters.
    filters: [UeventFilter; MAX_FILTERS],
    /// Filter count.
    filter_count: usize,
    /// Path to uevent helper binary.
    helper_path: [u8; MAX_HELPER_PATH_LEN],
    /// Helper path length (0 = disabled).
    helper_path_len: usize,
    /// Statistics.
    stats: UeventStats,
}

impl Default for UeventManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UeventManager {
    /// Create a new uevent manager.
    pub const fn new() -> Self {
        Self {
            kobjects: [const { Kobject::empty() }; MAX_KOBJECTS],
            kobj_count: 0,
            next_kobj_id: 1,
            queue: [const { UeventEntry::empty() }; MAX_UEVENT_QUEUE],
            queue_head: 0,
            queue_tail: 0,
            queue_count: 0,
            seqnum: 0,
            listeners: [const { UeventListener::empty() }; MAX_LISTENERS],
            listener_count: 0,
            filters: [const { UeventFilter::empty() }; MAX_FILTERS],
            filter_count: 0,
            helper_path: [0u8; MAX_HELPER_PATH_LEN],
            helper_path_len: 0,
            stats: UeventStats::new(),
        }
    }

    /// Register a new kobject.
    ///
    /// Returns the kobject ID.
    pub fn register_kobject(
        &mut self,
        name: &[u8],
        devpath: &[u8],
        subsystem: &[u8],
        kobj_type: KobjType,
        parent_id: u64,
    ) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_KOBJ_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if devpath.len() > MAX_DEVPATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if subsystem.len() > MAX_SUBSYSTEM_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_kobj_slot()?;
        let id = self.next_kobj_id;
        self.next_kobj_id += 1;

        self.kobjects[slot].name[..name.len()].copy_from_slice(name);
        self.kobjects[slot].name_len = name.len();
        if !devpath.is_empty() {
            self.kobjects[slot].devpath[..devpath.len()].copy_from_slice(devpath);
        }
        self.kobjects[slot].devpath_len = devpath.len();
        if !subsystem.is_empty() {
            self.kobjects[slot].subsystem[..subsystem.len()].copy_from_slice(subsystem);
        }
        self.kobjects[slot].subsystem_len = subsystem.len();
        self.kobjects[slot].kobj_type = kobj_type;
        self.kobjects[slot].kobj_id = id;
        self.kobjects[slot].parent_id = parent_id;
        self.kobjects[slot].uevent_suppress = false;
        self.kobjects[slot].active = true;
        self.kobjects[slot].ref_count = 1;
        self.kobj_count += 1;
        Ok(id)
    }

    /// Find a free kobject slot.
    fn find_free_kobj_slot(&self) -> Result<usize> {
        for i in 0..MAX_KOBJECTS {
            if !self.kobjects[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a kobject by ID.
    fn find_kobj_index(&self, kobj_id: u64) -> Option<usize> {
        (0..MAX_KOBJECTS).find(|&i| self.kobjects[i].active && self.kobjects[i].kobj_id == kobj_id)
    }

    /// Unregister a kobject.
    pub fn unregister_kobject(&mut self, kobj_id: u64) -> Result<()> {
        let idx = self.find_kobj_index(kobj_id).ok_or(Error::NotFound)?;
        self.kobjects[idx].active = false;
        self.kobj_count -= 1;
        Ok(())
    }

    /// Get a reference to a kobject by ID.
    pub fn kobject(&self, kobj_id: u64) -> Option<&Kobject> {
        self.find_kobj_index(kobj_id).map(|idx| &self.kobjects[idx])
    }

    /// Increment a kobject's reference count.
    pub fn kobj_get(&mut self, kobj_id: u64) -> Result<u32> {
        let idx = self.find_kobj_index(kobj_id).ok_or(Error::NotFound)?;
        self.kobjects[idx].ref_count += 1;
        Ok(self.kobjects[idx].ref_count)
    }

    /// Decrement a kobject's reference count.
    ///
    /// Returns the new count. If it reaches zero, the kobject is
    /// deactivated.
    pub fn kobj_put(&mut self, kobj_id: u64) -> Result<u32> {
        let idx = self.find_kobj_index(kobj_id).ok_or(Error::NotFound)?;
        if self.kobjects[idx].ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.kobjects[idx].ref_count -= 1;
        let count = self.kobjects[idx].ref_count;
        if count == 0 {
            self.kobjects[idx].active = false;
            self.kobj_count -= 1;
        }
        Ok(count)
    }

    /// Suppress or unsuppress uevents for a kobject.
    pub fn set_uevent_suppress(&mut self, kobj_id: u64, suppress: bool) -> Result<()> {
        let idx = self.find_kobj_index(kobj_id).ok_or(Error::NotFound)?;
        self.kobjects[idx].uevent_suppress = suppress;
        Ok(())
    }

    /// Generate a uevent for a kobject.
    ///
    /// This is the primary entry point. It builds the standard
    /// environment variables, checks filters, and queues the event.
    pub fn kobject_uevent(&mut self, kobj_id: u64, action: UeventAction) -> Result<u64> {
        self.kobject_uevent_env(kobj_id, action, &UeventEnv::new())
    }

    /// Generate a uevent with additional environment variables.
    pub fn kobject_uevent_env(
        &mut self,
        kobj_id: u64,
        action: UeventAction,
        extra_env: &UeventEnv,
    ) -> Result<u64> {
        let idx = self.find_kobj_index(kobj_id).ok_or(Error::NotFound)?;

        self.stats.total_generated += 1;

        // Check suppression.
        if self.kobjects[idx].uevent_suppress {
            self.stats.total_suppressed += 1;
            return Ok(0);
        }

        // Check filters.
        let subsystem = &self.kobjects[idx].subsystem[..self.kobjects[idx].subsystem_len];
        if self.is_filtered(subsystem, action) {
            self.stats.total_suppressed += 1;
            return Ok(0);
        }

        // Assign sequence number.
        self.seqnum += 1;
        let seqnum = self.seqnum;

        // Build environment.
        let mut env = UeventEnv::new();
        let _ = env.add(b"ACTION", action.as_str());
        let devpath = &self.kobjects[idx].devpath[..self.kobjects[idx].devpath_len];
        if !devpath.is_empty() {
            let _ = env.add(b"DEVPATH", devpath);
        }
        if !subsystem.is_empty() {
            let _ = env.add(b"SUBSYSTEM", subsystem);
        }

        // Add SEQNUM.
        let mut seqnum_buf = [0u8; 20];
        let seqnum_len = format_u64(&mut seqnum_buf, seqnum);
        let _ = env.add(b"SEQNUM", &seqnum_buf[..seqnum_len]);

        // Add extra env vars.
        for i in 0..extra_env.count() {
            if let Some(var) = extra_env.var_at(i) {
                let _ = env.add(var.key(), var.value());
            }
        }

        // Enqueue.
        self.enqueue_uevent(kobj_id, action, seqnum, env)?;

        Ok(seqnum)
    }

    /// Enqueue a uevent in the ring buffer.
    fn enqueue_uevent(
        &mut self,
        kobj_id: u64,
        action: UeventAction,
        seqnum: u64,
        env: UeventEnv,
    ) -> Result<()> {
        if self.queue_count >= MAX_UEVENT_QUEUE {
            self.stats.total_dropped += 1;
            return Err(Error::OutOfMemory);
        }
        let tail = self.queue_tail;
        self.queue[tail].kobj_id = kobj_id;
        self.queue[tail].action = action;
        self.queue[tail].seqnum = seqnum;
        self.queue[tail].env = env;
        self.queue[tail].active = true;
        self.queue_tail = (tail + 1) % MAX_UEVENT_QUEUE;
        self.queue_count += 1;
        self.stats.queue_depth = self.queue_count;
        Ok(())
    }

    /// Dequeue and dispatch the next pending uevent.
    ///
    /// Calls all matching listeners. Returns `Ok(true)` if an
    /// event was dispatched, `Ok(false)` if the queue is empty.
    pub fn dispatch_next(&mut self) -> Result<bool> {
        if self.queue_count == 0 {
            return Ok(false);
        }

        let head = self.queue_head;
        if !self.queue[head].active {
            return Ok(false);
        }

        let kobj_id = self.queue[head].kobj_id;
        let action = self.queue[head].action;
        let env = self.queue[head].env;

        self.queue[head].active = false;
        self.queue_head = (head + 1) % MAX_UEVENT_QUEUE;
        self.queue_count -= 1;
        self.stats.queue_depth = self.queue_count;

        // Find the kobject for listeners.
        if let Some(idx) = self.find_kobj_index(kobj_id) {
            let kobj = self.kobjects[idx];
            self.dispatch_to_listeners(action, &kobj, &env);
        }

        Ok(true)
    }

    /// Dispatch all pending uevents.
    pub fn dispatch_all(&mut self) -> usize {
        let mut dispatched = 0;
        while let Ok(true) = self.dispatch_next() {
            dispatched += 1;
        }
        dispatched
    }

    /// Dispatch an event to all matching listeners.
    fn dispatch_to_listeners(&mut self, action: UeventAction, kobj: &Kobject, env: &UeventEnv) {
        let subsystem = kobj.subsystem();
        for i in 0..self.listener_count {
            if !self.listeners[i].active {
                continue;
            }
            // Check subsystem filter.
            let filter = &self.listeners[i].subsystem_filter[..self.listeners[i].filter_len];
            if !filter.is_empty() && filter != subsystem {
                continue;
            }
            (self.listeners[i].callback)(action, kobj, env);
            self.stats.total_delivered += 1;
        }
    }

    /// Register a uevent listener.
    pub fn register_listener(
        &mut self,
        name: &[u8],
        subsystem_filter: &[u8],
        callback: UeventListenerFn,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_KOBJ_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if subsystem_filter.len() > MAX_SUBSYSTEM_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.listener_count >= MAX_LISTENERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.listener_count;
        self.listeners[idx].name[..name.len()].copy_from_slice(name);
        self.listeners[idx].name_len = name.len();
        if !subsystem_filter.is_empty() {
            self.listeners[idx].subsystem_filter[..subsystem_filter.len()]
                .copy_from_slice(subsystem_filter);
        }
        self.listeners[idx].filter_len = subsystem_filter.len();
        self.listeners[idx].callback = callback;
        self.listeners[idx].active = true;
        self.listener_count += 1;
        Ok(())
    }

    /// Unregister a uevent listener by name.
    pub fn unregister_listener(&mut self, name: &[u8]) -> Result<()> {
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

    /// Add a uevent suppress filter.
    pub fn add_filter(&mut self, subsystem: &[u8], action: Option<UeventAction>) -> Result<()> {
        if subsystem.len() > MAX_FILTER_PATTERN_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.filter_count >= MAX_FILTERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.filter_count;
        if !subsystem.is_empty() {
            self.filters[idx].subsystem[..subsystem.len()].copy_from_slice(subsystem);
        }
        self.filters[idx].subsystem_len = subsystem.len();
        self.filters[idx].action = action;
        self.filters[idx].active = true;
        self.filter_count += 1;
        Ok(())
    }

    /// Check whether an event matches any suppress filter.
    fn is_filtered(&self, subsystem: &[u8], action: UeventAction) -> bool {
        for i in 0..self.filter_count {
            if !self.filters[i].active {
                continue;
            }
            let pat = &self.filters[i].subsystem[..self.filters[i].subsystem_len];
            let subsys_match = pat.is_empty() || pat == subsystem;
            let action_match = self.filters[i].action.is_none_or(|a| a == action);
            if subsys_match && action_match {
                return true;
            }
        }
        false
    }

    /// Set the uevent helper path (e.g., "/sbin/hotplug").
    pub fn set_helper_path(&mut self, path: &[u8]) -> Result<()> {
        if path.len() > MAX_HELPER_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if !path.is_empty() {
            self.helper_path[..path.len()].copy_from_slice(path);
        }
        self.helper_path_len = path.len();
        Ok(())
    }

    /// Return the helper path.
    pub fn helper_path(&self) -> &[u8] {
        &self.helper_path[..self.helper_path_len]
    }

    /// Return statistics.
    pub const fn stats(&self) -> &UeventStats {
        &self.stats
    }

    /// Return the current sequence number.
    pub const fn seqnum(&self) -> u64 {
        self.seqnum
    }

    /// Return the number of registered kobjects.
    pub const fn kobj_count(&self) -> usize {
        self.kobj_count
    }

    /// Return the queue depth.
    pub const fn queue_depth(&self) -> usize {
        self.queue_count
    }

    /// Clear all suppress filters.
    pub fn clear_filters(&mut self) {
        for i in 0..self.filter_count {
            self.filters[i].active = false;
        }
        self.filter_count = 0;
    }
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Format a u64 into a byte buffer, returning number of bytes written.
fn format_u64(buf: &mut [u8], val: u64) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = val;
    let mut count = 0;
    while n > 0 {
        tmp[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    let write_len = if count > buf.len() { buf.len() } else { count };
    for i in 0..write_len {
        buf[i] = tmp[count - 1 - i];
    }
    write_len
}

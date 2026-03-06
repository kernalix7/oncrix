// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kobject uevent notification over netlink — generate and
//! broadcast device lifecycle events to user-space.
//!
//! When a device or subsystem changes state (added, removed,
//! brought online/offline, etc.) the kernel generates a uevent
//! containing a set of `KEY=VALUE` environment variables and
//! broadcasts it over a netlink socket. User-space daemons
//! (udevd, systemd-udevd) listen for these events and take
//! appropriate action (creating device nodes, loading firmware,
//! etc.).
//!
//! # Architecture
//!
//! ```text
//! UeventBroadcaster
//!  ├── pending_queue[MAX_PENDING]
//!  │    └── UeventMessage
//!  │         ├── action, devpath, subsystem
//!  │         ├── env_vars[MAX_ENV_VARS]
//!  │         └── seqnum
//!  ├── listeners[MAX_LISTENERS]
//!  │    └── UeventListener (netlink socket abstraction)
//!  ├── seqnum_counter
//!  ├── filter_table[MAX_FILTERS]
//!  └── stats: UeventStats
//! ```
//!
//! # Environment Variables
//!
//! Each uevent carries mandatory variables:
//! - `ACTION=` — add, remove, change, move, online, offline
//! - `DEVPATH=` — sysfs device path
//! - `SUBSYSTEM=` — subsystem name
//! - `SEQNUM=` — monotonic sequence number
//!
//! And optional variables:
//! - `DEVNAME=`, `DEVTYPE=`, `DRIVER=`, `MAJOR=`, `MINOR=`
//!
//! Reference: Linux `lib/kobject_uevent.c`,
//! `include/linux/kobject.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum pending uevent messages in the queue.
const MAX_PENDING: usize = 256;

/// Maximum environment variables per uevent.
const MAX_ENV_VARS: usize = 16;

/// Maximum key length for an env var (bytes).
const MAX_KEY_LEN: usize = 32;

/// Maximum value length for an env var (bytes).
const MAX_VALUE_LEN: usize = 128;

/// Maximum devpath length (bytes).
const MAX_DEVPATH_LEN: usize = 256;

/// Maximum subsystem name length (bytes).
const MAX_SUBSYSTEM_LEN: usize = 32;

/// Maximum registered listeners.
const MAX_LISTENERS: usize = 32;

/// Maximum uevent suppression filters.
const MAX_FILTERS: usize = 16;

/// Maximum serialized uevent message length (bytes).
const MAX_SERIALIZED_LEN: usize = 2048;

// ══════════════════════════════════════════════════════════════
// UeventAction
// ══════════════════════════════════════════════════════════════

/// Uevent action types — what happened to the kobject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UeventAction {
    /// Device / kobject added to the system.
    Add = 0,
    /// Device / kobject removed from the system.
    Remove = 1,
    /// Device attribute changed.
    Change = 2,
    /// Device moved (renamed or reparented).
    Move = 3,
    /// Device brought online.
    Online = 4,
    /// Device taken offline.
    Offline = 5,
    /// Driver bound to device.
    Bind = 6,
    /// Driver unbound from device.
    Unbind = 7,
}

impl UeventAction {
    /// Return the action as an ASCII string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Change => "change",
            Self::Move => "move",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }

    /// Parse from ASCII bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        match b {
            b"add" => Ok(Self::Add),
            b"remove" => Ok(Self::Remove),
            b"change" => Ok(Self::Change),
            b"move" => Ok(Self::Move),
            b"online" => Ok(Self::Online),
            b"offline" => Ok(Self::Offline),
            b"bind" => Ok(Self::Bind),
            b"unbind" => Ok(Self::Unbind),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ══════════════════════════════════════════════════════════════
// EnvVar — key=value pair
// ══════════════════════════════════════════════════════════════

/// A single `KEY=VALUE` environment variable in a uevent.
#[derive(Debug, Clone)]
pub struct EnvVar {
    /// Key bytes.
    key: [u8; MAX_KEY_LEN],
    /// Key length.
    key_len: usize,
    /// Value bytes.
    value: [u8; MAX_VALUE_LEN],
    /// Value length.
    value_len: usize,
    /// Whether this slot is in use.
    active: bool,
}

impl EnvVar {
    /// Create an empty env var slot.
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            value: [0u8; MAX_VALUE_LEN],
            value_len: 0,
            active: false,
        }
    }

    /// Return the key as a byte slice.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Return the value as a byte slice.
    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

// ══════════════════════════════════════════════════════════════
// UeventMessage — one queued uevent
// ══════════════════════════════════════════════════════════════

/// A single uevent message queued for broadcast.
pub struct UeventMessage {
    /// Monotonic sequence number.
    pub seqnum: u64,
    /// Event action.
    pub action: UeventAction,
    /// Device sysfs path.
    devpath: [u8; MAX_DEVPATH_LEN],
    /// Devpath length.
    devpath_len: usize,
    /// Subsystem name.
    subsystem: [u8; MAX_SUBSYSTEM_LEN],
    /// Subsystem name length.
    subsystem_len: usize,
    /// Environment variables.
    env_vars: [EnvVar; MAX_ENV_VARS],
    /// Number of active env vars.
    env_count: usize,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl UeventMessage {
    /// Create an empty uevent message.
    const fn empty() -> Self {
        Self {
            seqnum: 0,
            action: UeventAction::Add,
            devpath: [0u8; MAX_DEVPATH_LEN],
            devpath_len: 0,
            subsystem: [0u8; MAX_SUBSYSTEM_LEN],
            subsystem_len: 0,
            env_vars: [const { EnvVar::empty() }; MAX_ENV_VARS],
            env_count: 0,
            timestamp_ns: 0,
            occupied: false,
        }
    }

    /// Return the devpath as a byte slice.
    pub fn devpath(&self) -> &[u8] {
        &self.devpath[..self.devpath_len]
    }

    /// Return the subsystem name as a byte slice.
    pub fn subsystem(&self) -> &[u8] {
        &self.subsystem[..self.subsystem_len]
    }

    /// Return the environment variables as a slice.
    pub fn env_vars(&self) -> &[EnvVar] {
        &self.env_vars[..self.env_count]
    }

    /// Add an environment variable to this message.
    fn add_env(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if self.env_count >= MAX_ENV_VARS {
            return Err(Error::OutOfMemory);
        }

        let slot = &mut self.env_vars[self.env_count];
        let klen = key.len().min(MAX_KEY_LEN);
        slot.key[..klen].copy_from_slice(&key[..klen]);
        slot.key_len = klen;

        let vlen = value.len().min(MAX_VALUE_LEN);
        slot.value[..vlen].copy_from_slice(&value[..vlen]);
        slot.value_len = vlen;

        slot.active = true;
        self.env_count += 1;
        Ok(())
    }

    /// Serialize the uevent into a `KEY=VALUE\0` netlink message
    /// format. Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < MAX_SERIALIZED_LEN {
            return Err(Error::InvalidArgument);
        }

        let mut pos = 0;

        // ACTION=<action>\0
        pos = write_kv(buf, pos, b"ACTION", self.action.as_str().as_bytes())?;

        // DEVPATH=<devpath>\0
        pos = write_kv(buf, pos, b"DEVPATH", self.devpath())?;

        // SUBSYSTEM=<subsystem>\0
        pos = write_kv(buf, pos, b"SUBSYSTEM", self.subsystem())?;

        // SEQNUM=<decimal>\0
        let mut numbuf = [0u8; 20];
        let numlen = format_u64(self.seqnum, &mut numbuf);
        pos = write_kv(buf, pos, b"SEQNUM", &numbuf[..numlen])?;

        // Additional env vars.
        for var in &self.env_vars[..self.env_count] {
            if var.active {
                pos = write_kv(buf, pos, var.key(), var.value())?;
            }
        }

        Ok(pos)
    }
}

// ══════════════════════════════════════════════════════════════
// UeventListener — netlink socket abstraction
// ══════════════════════════════════════════════════════════════

/// A registered uevent listener (abstraction over a netlink
/// socket that receives uevent broadcasts).
#[derive(Debug, Clone, Copy)]
pub struct UeventListener {
    /// Listener ID.
    pub listener_id: u32,
    /// Owning process PID.
    pub pid: u64,
    /// Whether this listener is active.
    active: bool,
    /// Number of events delivered to this listener.
    pub delivered: u64,
    /// Number of events dropped (listener buffer full).
    pub dropped: u64,
}

impl UeventListener {
    /// Create an empty listener slot.
    const fn empty() -> Self {
        Self {
            listener_id: 0,
            pid: 0,
            active: false,
            delivered: 0,
            dropped: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// UeventFilter — suppression filter
// ══════════════════════════════════════════════════════════════

/// A uevent suppression filter. Matching events are not
/// broadcast.
pub struct UeventFilter {
    /// Subsystem to match (empty = match all).
    subsystem: [u8; MAX_SUBSYSTEM_LEN],
    /// Subsystem match length.
    subsystem_len: usize,
    /// Action to suppress (None = all actions).
    pub action: Option<UeventAction>,
    /// Whether this filter is active.
    active: bool,
}

impl UeventFilter {
    /// Create an empty filter slot.
    const fn empty() -> Self {
        Self {
            subsystem: [0u8; MAX_SUBSYSTEM_LEN],
            subsystem_len: 0,
            action: None,
            active: false,
        }
    }

    /// Return the subsystem pattern.
    pub fn subsystem(&self) -> &[u8] {
        &self.subsystem[..self.subsystem_len]
    }
}

// ══════════════════════════════════════════════════════════════
// UeventStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the uevent broadcaster.
#[derive(Debug, Clone, Copy, Default)]
pub struct UeventStats {
    /// Total events generated.
    pub total_generated: u64,
    /// Total events broadcast.
    pub total_broadcast: u64,
    /// Total events filtered (suppressed).
    pub total_filtered: u64,
    /// Total listener registrations.
    pub total_listeners: u32,
    /// Current pending queue depth.
    pub pending_count: u32,
}

// ══════════════════════════════════════════════════════════════
// UeventBroadcaster — the main subsystem
// ══════════════════════════════════════════════════════════════

/// Generates and broadcasts kobject uevent notifications to
/// user-space via netlink.
pub struct UeventBroadcaster {
    /// Pending event queue.
    pending: [UeventMessage; MAX_PENDING],
    /// Write index into the pending queue.
    write_idx: usize,
    /// Read index into the pending queue.
    read_idx: usize,
    /// Global monotonic sequence counter.
    seqnum: u64,
    /// Registered listeners.
    listeners: [UeventListener; MAX_LISTENERS],
    /// Next listener ID.
    next_listener_id: u32,
    /// Suppression filters.
    filters: [UeventFilter; MAX_FILTERS],
    /// Statistics.
    stats: UeventStats,
}

impl Default for UeventBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl UeventBroadcaster {
    /// Create a new uevent broadcaster.
    pub const fn new() -> Self {
        Self {
            pending: [const { UeventMessage::empty() }; MAX_PENDING],
            write_idx: 0,
            read_idx: 0,
            seqnum: 1,
            listeners: [const { UeventListener::empty() }; MAX_LISTENERS],
            next_listener_id: 1,
            filters: [const { UeventFilter::empty() }; MAX_FILTERS],
            stats: UeventStats {
                total_generated: 0,
                total_broadcast: 0,
                total_filtered: 0,
                total_listeners: 0,
                pending_count: 0,
            },
        }
    }

    /// Return uevent statistics.
    pub fn stats(&self) -> &UeventStats {
        &self.stats
    }

    /// Check whether an event should be suppressed by filters.
    fn is_filtered(&self, action: UeventAction, subsystem: &[u8]) -> bool {
        for filter in &self.filters {
            if !filter.active {
                continue;
            }
            // Match subsystem.
            let sub_match = filter.subsystem_len == 0 || filter.subsystem() == subsystem;
            // Match action.
            let act_match = filter.action.is_none() || filter.action == Some(action);

            if sub_match && act_match {
                return true;
            }
        }
        false
    }

    /// Generate and queue a uevent.
    ///
    /// The event is assigned a sequence number, the mandatory
    /// environment variables are populated, and the message is
    /// placed in the pending queue for broadcast.
    pub fn generate_event(
        &mut self,
        action: UeventAction,
        devpath: &[u8],
        subsystem: &[u8],
        extra_env: &[(&[u8], &[u8])],
        timestamp_ns: u64,
    ) -> Result<u64> {
        if devpath.is_empty() || subsystem.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check suppression filters.
        if self.is_filtered(action, subsystem) {
            self.stats.total_filtered += 1;
            return Err(Error::WouldBlock);
        }

        // Check queue space.
        let next_write = (self.write_idx + 1) % MAX_PENDING;
        if next_write == self.read_idx {
            return Err(Error::OutOfMemory);
        }

        let seq = self.seqnum;
        self.seqnum += 1;

        let msg = &mut self.pending[self.write_idx];
        msg.seqnum = seq;
        msg.action = action;
        msg.timestamp_ns = timestamp_ns;
        msg.occupied = true;
        msg.env_count = 0;

        let dlen = devpath.len().min(MAX_DEVPATH_LEN);
        msg.devpath[..dlen].copy_from_slice(&devpath[..dlen]);
        msg.devpath_len = dlen;

        let slen = subsystem.len().min(MAX_SUBSYSTEM_LEN);
        msg.subsystem[..slen].copy_from_slice(&subsystem[..slen]);
        msg.subsystem_len = slen;

        // Add extra environment variables.
        for &(key, value) in extra_env {
            if msg.add_env(key, value).is_err() {
                break; // env_vars full, ignore rest
            }
        }

        self.write_idx = next_write;
        self.stats.total_generated += 1;
        self.stats.pending_count += 1;

        Ok(seq)
    }

    /// Dequeue the next pending event for broadcast.
    ///
    /// Returns a reference to the message. The caller should
    /// serialize it and send to all listeners.
    pub fn dequeue_next(&mut self) -> Result<&UeventMessage> {
        if self.read_idx == self.write_idx {
            return Err(Error::WouldBlock);
        }

        let msg = &self.pending[self.read_idx];
        if !msg.occupied {
            return Err(Error::NotFound);
        }

        self.read_idx = (self.read_idx + 1) % MAX_PENDING;
        self.stats.pending_count = self.stats.pending_count.saturating_sub(1);
        self.stats.total_broadcast += 1;

        Ok(msg)
    }

    // ── Listener management ─────────────────────────────────

    /// Register a new uevent listener. Returns the listener ID.
    pub fn register_listener(&mut self, pid: u64) -> Result<u32> {
        let pos = self
            .listeners
            .iter()
            .position(|l| !l.active)
            .ok_or(Error::OutOfMemory)?;

        let lid = self.next_listener_id;
        self.next_listener_id += 1;

        let listener = &mut self.listeners[pos];
        listener.listener_id = lid;
        listener.pid = pid;
        listener.active = true;
        listener.delivered = 0;
        listener.dropped = 0;

        self.stats.total_listeners += 1;
        Ok(lid)
    }

    /// Unregister a listener by ID.
    pub fn unregister_listener(&mut self, listener_id: u32) -> Result<()> {
        let pos = self
            .listeners
            .iter()
            .position(|l| l.active && l.listener_id == listener_id)
            .ok_or(Error::NotFound)?;

        self.listeners[pos].active = false;
        self.stats.total_listeners = self.stats.total_listeners.saturating_sub(1);
        Ok(())
    }

    /// Record that an event was delivered to a listener.
    pub fn record_delivery(&mut self, listener_id: u32) -> Result<()> {
        let pos = self
            .listeners
            .iter()
            .position(|l| l.active && l.listener_id == listener_id)
            .ok_or(Error::NotFound)?;

        self.listeners[pos].delivered += 1;
        Ok(())
    }

    /// Record that an event was dropped for a listener.
    pub fn record_drop(&mut self, listener_id: u32) -> Result<()> {
        let pos = self
            .listeners
            .iter()
            .position(|l| l.active && l.listener_id == listener_id)
            .ok_or(Error::NotFound)?;

        self.listeners[pos].dropped += 1;
        Ok(())
    }

    /// Return the number of active listeners.
    pub fn listener_count(&self) -> u32 {
        self.listeners.iter().filter(|l| l.active).count() as u32
    }

    // ── Filter management ───────────────────────────────────

    /// Add a suppression filter. Events matching the filter
    /// criteria are not broadcast.
    pub fn add_filter(&mut self, subsystem: &[u8], action: Option<UeventAction>) -> Result<usize> {
        let pos = self
            .filters
            .iter()
            .position(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;

        let filter = &mut self.filters[pos];
        let slen = subsystem.len().min(MAX_SUBSYSTEM_LEN);
        filter.subsystem[..slen].copy_from_slice(&subsystem[..slen]);
        filter.subsystem_len = slen;
        filter.action = action;
        filter.active = true;

        Ok(pos)
    }

    /// Remove a suppression filter by index.
    pub fn remove_filter(&mut self, index: usize) -> Result<()> {
        if index >= MAX_FILTERS {
            return Err(Error::InvalidArgument);
        }
        if !self.filters[index].active {
            return Err(Error::NotFound);
        }
        self.filters[index].active = false;
        self.filters[index].subsystem_len = 0;
        Ok(())
    }

    /// Return the number of pending events in the queue.
    pub fn pending_count(&self) -> u32 {
        self.stats.pending_count
    }

    /// Return the current sequence number.
    pub fn current_seqnum(&self) -> u64 {
        self.seqnum
    }
}

// ══════════════════════════════════════════════════════════════
// Helper functions
// ══════════════════════════════════════════════════════════════

/// Write `KEY=VALUE\0` to `buf` at `pos`. Returns the new
/// position after the null terminator.
fn write_kv(buf: &mut [u8], pos: usize, key: &[u8], value: &[u8]) -> Result<usize> {
    // key + '=' + value + '\0'
    let total = key.len() + 1 + value.len() + 1;
    if pos + total > buf.len() {
        return Err(Error::OutOfMemory);
    }

    let mut p = pos;
    buf[p..p + key.len()].copy_from_slice(key);
    p += key.len();
    buf[p] = b'=';
    p += 1;
    buf[p..p + value.len()].copy_from_slice(value);
    p += value.len();
    buf[p] = 0;
    p += 1;

    Ok(p)
}

/// Format a u64 as decimal ASCII into `buf`. Returns the number
/// of bytes written.
fn format_u64(mut val: u64, buf: &mut [u8; 20]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut tmp = [0u8; 20];
    let mut len = 0;

    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }

    // Reverse into output buffer.
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }

    len
}

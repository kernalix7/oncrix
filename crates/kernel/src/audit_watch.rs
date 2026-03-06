// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Audit filesystem watches.
//!
//! Allows the audit subsystem to place watches on filesystem paths.
//! When a watched path is accessed, modified, or has its attributes
//! changed, an audit record is generated. This is the kernel-side
//! counterpart of the `-w` flag in `auditctl(8)`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    AuditWatchSubsystem                            │
//! │                                                                  │
//! │  [AuditWatch; MAX_WATCHES]  — active watches                     │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  AuditWatch                                                │  │
//! │  │    path[MAX_PATH_LEN]  — watched filesystem path           │  │
//! │  │    WatchPermFilter     — permission bitmask (r/w/x/a)      │  │
//! │  │    inode, dev          — resolved inode for fast lookup     │  │
//! │  │    WatchState          — lifecycle                          │  │
//! │  │    trigger_count       — number of audit events fired      │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  [AuditWatchEvent; MAX_EVENTS]  — ring buffer of recent events  │
//! │  [AuditWatchRule; MAX_RULES]    — rules linking watches→keys    │
//! │  AuditWatchStats                — global counters               │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Watch Resolution
//!
//! 1. A watch is added on a path (e.g. `/etc/passwd`).
//! 2. The path is resolved to `(dev, inode)`.
//! 3. On each filesystem operation, the audit hook checks the
//!    `(dev, inode)` against registered watches.
//! 4. If matched, a `WatchPermFilter` test determines if the
//!    operation type (read/write/execute/attr) is relevant.
//! 5. If relevant, an `AuditWatchEvent` is emitted.
//!
//! # Reference
//!
//! Linux `kernel/audit_watch.c`, `kernel/audit_tree.c`,
//! `include/linux/audit.h`,
//! `Documentation/ABI/testing/sysfs-fs-audit`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of active watches.
const MAX_WATCHES: usize = 256;

/// Maximum watched path length.
const MAX_PATH_LEN: usize = 256;

/// Maximum audit key length.
const MAX_KEY_LEN: usize = 64;

/// Maximum number of audit watch rules.
const MAX_RULES: usize = 128;

/// Maximum number of recent events in the ring buffer.
const MAX_EVENTS: usize = 512;

/// Maximum watch trees (parent directory watch groups).
const MAX_TREES: usize = 32;

/// Maximum children per watch tree.
const MAX_TREE_CHILDREN: usize = 16;

// ── Permission filter bits ──────────────────────────────────────────────────

/// Read permission bit.
pub const PERM_READ: u8 = 1 << 0;

/// Write permission bit.
pub const PERM_WRITE: u8 = 1 << 1;

/// Execute permission bit.
pub const PERM_EXEC: u8 = 1 << 2;

/// Attribute change permission bit.
pub const PERM_ATTR: u8 = 1 << 3;

/// All permission bits combined.
const PERM_ALL: u8 = PERM_READ | PERM_WRITE | PERM_EXEC | PERM_ATTR;

// ── WatchPermFilter ─────────────────────────────────────────────────────────

/// Permission filter for an audit watch.
///
/// Specifies which types of filesystem operations trigger the watch.
/// Uses the `auditctl -p` semantics: r=read, w=write, x=execute,
/// a=attribute change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchPermFilter(pub u8);

impl WatchPermFilter {
    /// Watch all operations.
    pub const ALL: Self = Self(PERM_ALL);

    /// Watch read + attribute (typical for config files).
    pub const READ_ATTR: Self = Self(PERM_READ | PERM_ATTR);

    /// Watch write + attribute (typical for integrity monitoring).
    pub const WRITE_ATTR: Self = Self(PERM_WRITE | PERM_ATTR);

    /// Check whether a specific permission is included.
    pub fn matches(self, perm: u8) -> bool {
        self.0 & perm != 0
    }

    /// Check whether the filter is empty (no permissions).
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Count the number of permission bits set.
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }
}

impl Default for WatchPermFilter {
    fn default() -> Self {
        Self::ALL
    }
}

// ── WatchState ──────────────────────────────────────────────────────────────

/// Lifecycle state of an audit watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchState {
    /// Slot is free.
    Free,
    /// Watch is registered and active.
    Active,
    /// Watch is temporarily suspended.
    Suspended,
    /// Path could not be resolved (orphan watch).
    Orphan,
    /// Watch has been removed.
    Removed,
}

impl Default for WatchState {
    fn default() -> Self {
        Self::Free
    }
}

// ── AuditWatch ──────────────────────────────────────────────────────────────

/// A single filesystem audit watch.
#[derive(Debug, Clone, Copy)]
pub struct AuditWatch {
    /// Unique watch identifier.
    id: u64,
    /// Watched path.
    path: [u8; MAX_PATH_LEN],
    /// Path length.
    path_len: usize,
    /// Permission filter.
    perm_filter: WatchPermFilter,
    /// Current state.
    state: WatchState,
    /// Resolved inode number (0 if orphan).
    inode: u64,
    /// Resolved device number.
    dev: u64,
    /// PID of the process that added this watch.
    creator_pid: u64,
    /// UID of the creator.
    creator_uid: u32,
    /// Creation timestamp.
    created_ns: u64,
    /// Number of times this watch has triggered.
    trigger_count: u64,
    /// Last trigger timestamp.
    last_trigger_ns: u64,
    /// Associated audit key (for filtering in auditd).
    key: [u8; MAX_KEY_LEN],
    /// Key length.
    key_len: usize,
    /// Tree index (0 = not in a tree).
    tree_idx: usize,
}

impl AuditWatch {
    /// Create an empty watch slot.
    const fn new() -> Self {
        Self {
            id: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            perm_filter: WatchPermFilter(PERM_ALL),
            state: WatchState::Free,
            inode: 0,
            dev: 0,
            creator_pid: 0,
            creator_uid: 0,
            created_ns: 0,
            trigger_count: 0,
            last_trigger_ns: 0,
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            tree_idx: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, WatchState::Free | WatchState::Removed)
    }

    /// Get the watch ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the watched path.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Get the permission filter.
    pub fn perm_filter(&self) -> WatchPermFilter {
        self.perm_filter
    }

    /// Get the trigger count.
    pub fn trigger_count(&self) -> u64 {
        self.trigger_count
    }

    /// Get the resolved inode.
    pub fn inode(&self) -> u64 {
        self.inode
    }

    /// Get the audit key.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }
}

// ── EventType ───────────────────────────────────────────────────────────────

/// Type of filesystem event that triggered a watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// File was opened for reading.
    Read,
    /// File was written to.
    Write,
    /// File was executed.
    Execute,
    /// File attributes were changed.
    AttrChange,
    /// File was created.
    Create,
    /// File was deleted.
    Delete,
    /// File was renamed.
    Rename,
    /// File link count changed.
    Link,
}

impl EventType {
    /// Get the corresponding permission bit.
    pub const fn perm_bit(self) -> u8 {
        match self {
            Self::Read => PERM_READ,
            Self::Write | Self::Create | Self::Delete | Self::Rename | Self::Link => PERM_WRITE,
            Self::Execute => PERM_EXEC,
            Self::AttrChange => PERM_ATTR,
        }
    }
}

// ── AuditWatchEvent ─────────────────────────────────────────────────────────

/// An audit event generated by a watch trigger.
#[derive(Debug, Clone, Copy)]
pub struct AuditWatchEvent {
    /// Timestamp.
    timestamp_ns: u64,
    /// Watch ID that triggered.
    watch_id: u64,
    /// Type of event.
    event_type: EventType,
    /// PID of the process that caused the event.
    pid: u64,
    /// UID of the process.
    uid: u32,
    /// Inode accessed.
    inode: u64,
    /// Device number.
    dev: u64,
    /// Operation result (0 = success, errno on failure).
    result: i32,
    /// Whether the event was successfully delivered to auditd.
    delivered: bool,
}

impl AuditWatchEvent {
    /// Create an empty event.
    const fn new() -> Self {
        Self {
            timestamp_ns: 0,
            watch_id: 0,
            event_type: EventType::Read,
            pid: 0,
            uid: 0,
            inode: 0,
            dev: 0,
            result: 0,
            delivered: false,
        }
    }

    /// Get the watch ID.
    pub fn watch_id(&self) -> u64 {
        self.watch_id
    }

    /// Get the event type.
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Get the PID.
    pub fn pid(&self) -> u64 {
        self.pid
    }
}

// ── AuditWatchRule ──────────────────────────────────────────────────────────

/// A rule binding a watch to an audit filter key and additional
/// conditions.
#[derive(Debug, Clone, Copy)]
pub struct AuditWatchRule {
    /// Whether this rule slot is active.
    active: bool,
    /// Watch index this rule references.
    watch_idx: usize,
    /// Audit filter key.
    key: [u8; MAX_KEY_LEN],
    /// Key length.
    key_len: usize,
    /// Minimum UID filter (-1 = any).
    uid_min: i64,
    /// Maximum UID filter (-1 = any).
    uid_max: i64,
    /// Whether to log successes.
    log_success: bool,
    /// Whether to log failures.
    log_failure: bool,
}

impl AuditWatchRule {
    /// Create an empty rule.
    const fn new() -> Self {
        Self {
            active: false,
            watch_idx: 0,
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            uid_min: -1,
            uid_max: -1,
            log_success: true,
            log_failure: true,
        }
    }

    /// Check whether a UID matches this rule's filter.
    fn uid_matches(&self, uid: u32) -> bool {
        if self.uid_min < 0 {
            return true;
        }
        let uid_i64 = uid as i64;
        uid_i64 >= self.uid_min && uid_i64 <= self.uid_max
    }
}

// ── WatchTree ───────────────────────────────────────────────────────────────

/// A watch tree groups watches on files under a common parent
/// directory so that renames/moves can be tracked.
#[derive(Debug, Clone, Copy)]
pub struct WatchTree {
    /// Whether this tree slot is active.
    active: bool,
    /// Parent directory inode.
    parent_inode: u64,
    /// Parent directory device.
    parent_dev: u64,
    /// Watch indices for children.
    children: [usize; MAX_TREE_CHILDREN],
    /// Number of children.
    child_count: usize,
}

impl WatchTree {
    /// Create an empty tree.
    const fn new() -> Self {
        Self {
            active: false,
            parent_inode: 0,
            parent_dev: 0,
            children: [0usize; MAX_TREE_CHILDREN],
            child_count: 0,
        }
    }
}

// ── AuditWatchStats ─────────────────────────────────────────────────────────

/// Global statistics for the audit watch subsystem.
#[derive(Debug, Clone, Copy)]
pub struct AuditWatchStats {
    /// Total watches added.
    pub watches_added: u64,
    /// Total watches removed.
    pub watches_removed: u64,
    /// Total events generated.
    pub events_generated: u64,
    /// Events delivered to auditd.
    pub events_delivered: u64,
    /// Events dropped (buffer full).
    pub events_dropped: u64,
    /// Orphan watches (path unresolved).
    pub orphan_watches: u64,
    /// Rules added.
    pub rules_added: u64,
    /// Lookup hits.
    pub lookup_hits: u64,
    /// Lookup misses.
    pub lookup_misses: u64,
}

impl AuditWatchStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            watches_added: 0,
            watches_removed: 0,
            events_generated: 0,
            events_delivered: 0,
            events_dropped: 0,
            orphan_watches: 0,
            rules_added: 0,
            lookup_hits: 0,
            lookup_misses: 0,
        }
    }
}

// ── AuditWatchSubsystem ─────────────────────────────────────────────────────

/// Top-level audit watch subsystem.
///
/// Manages filesystem watches, event generation, and integration with
/// the audit framework. Watches can be added via `auditctl -w` or
/// programmatically through `add_watch()`.
pub struct AuditWatchSubsystem {
    /// Watch table.
    watches: [AuditWatch; MAX_WATCHES],
    /// Next watch ID.
    next_watch_id: u64,
    /// Event ring buffer.
    events: [AuditWatchEvent; MAX_EVENTS],
    /// Event ring head.
    event_head: usize,
    /// Total events.
    event_total: u64,
    /// Watch rules.
    rules: [AuditWatchRule; MAX_RULES],
    /// Watch trees.
    trees: [WatchTree; MAX_TREES],
    /// Global statistics.
    stats: AuditWatchStats,
    /// Whether the subsystem is enabled.
    enabled: bool,
    /// Current time.
    now_ns: u64,
}

impl AuditWatchSubsystem {
    /// Create a new audit watch subsystem.
    pub const fn new() -> Self {
        Self {
            watches: [const { AuditWatch::new() }; MAX_WATCHES],
            next_watch_id: 1,
            events: [const { AuditWatchEvent::new() }; MAX_EVENTS],
            event_head: 0,
            event_total: 0,
            rules: [const { AuditWatchRule::new() }; MAX_RULES],
            trees: [const { WatchTree::new() }; MAX_TREES],
            stats: AuditWatchStats::new(),
            enabled: true,
            now_ns: 0,
        }
    }

    /// Update the internal time.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Enable or disable the subsystem.
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Check whether the subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get global statistics.
    pub fn stats(&self) -> &AuditWatchStats {
        &self.stats
    }

    // ── Watch management ────────────────────────────────────────────

    /// Add a filesystem watch.
    ///
    /// The path is stored and resolved to `(dev, inode)`. If
    /// resolution fails, the watch enters `Orphan` state and will
    /// be retried on the next relevant mount event.
    pub fn add_watch(
        &mut self,
        path: &[u8],
        perm: WatchPermFilter,
        inode: u64,
        dev: u64,
        pid: u64,
        uid: u32,
    ) -> Result<usize> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if perm.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate path.
        for w in &self.watches {
            if !w.is_free() && w.path_len == path.len() && w.path[..w.path_len] == path[..] {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = self
            .watches
            .iter()
            .position(|w| w.is_free())
            .ok_or(Error::OutOfMemory)?;

        let watch = &mut self.watches[idx];
        watch.id = self.next_watch_id;
        self.next_watch_id += 1;
        watch.path[..path.len()].copy_from_slice(path);
        watch.path_len = path.len();
        watch.perm_filter = perm;
        watch.creator_pid = pid;
        watch.creator_uid = uid;
        watch.created_ns = self.now_ns;
        watch.trigger_count = 0;
        watch.last_trigger_ns = 0;
        watch.key = [0u8; MAX_KEY_LEN];
        watch.key_len = 0;

        if inode == 0 {
            watch.state = WatchState::Orphan;
            watch.inode = 0;
            watch.dev = 0;
            self.stats.orphan_watches += 1;
        } else {
            watch.state = WatchState::Active;
            watch.inode = inode;
            watch.dev = dev;
        }

        self.stats.watches_added += 1;
        Ok(idx)
    }

    /// Remove a watch by index.
    pub fn remove_watch(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        if self.watches[idx].is_free() {
            return Err(Error::NotFound);
        }
        self.watches[idx].state = WatchState::Removed;

        // Deactivate associated rules.
        for rule in &mut self.rules {
            if rule.active && rule.watch_idx == idx {
                rule.active = false;
            }
        }

        // Remove from tree.
        let tree_idx = self.watches[idx].tree_idx;
        if tree_idx > 0 {
            self.remove_from_tree(tree_idx - 1, idx);
        }

        self.stats.watches_removed += 1;
        Ok(())
    }

    /// Remove a watch by path.
    pub fn remove_watch_by_path(&mut self, path: &[u8]) -> Result<()> {
        let idx = self
            .watches
            .iter()
            .position(|w| {
                !w.is_free() && w.path_len == path.len() && w.path[..w.path_len] == path[..]
            })
            .ok_or(Error::NotFound)?;
        self.remove_watch(idx)
    }

    /// Suspend a watch (stop triggering without removing).
    pub fn suspend_watch(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        match self.watches[idx].state {
            WatchState::Active => {
                self.watches[idx].state = WatchState::Suspended;
                Ok(())
            }
            WatchState::Free | WatchState::Removed => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Resume a suspended watch.
    pub fn resume_watch(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        match self.watches[idx].state {
            WatchState::Suspended => {
                self.watches[idx].state = WatchState::Active;
                Ok(())
            }
            WatchState::Free | WatchState::Removed => Err(Error::NotFound),
            _ => Err(Error::Busy),
        }
    }

    /// Resolve an orphan watch to an inode/dev pair.
    pub fn resolve_orphan(&mut self, idx: usize, inode: u64, dev: u64) -> Result<()> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.watches[idx].state, WatchState::Orphan) {
            return Err(Error::InvalidArgument);
        }
        if inode == 0 {
            return Err(Error::InvalidArgument);
        }
        self.watches[idx].inode = inode;
        self.watches[idx].dev = dev;
        self.watches[idx].state = WatchState::Active;
        self.stats.orphan_watches = self.stats.orphan_watches.saturating_sub(1);
        Ok(())
    }

    /// Set an audit key on a watch.
    pub fn set_watch_key(&mut self, idx: usize, key: &[u8]) -> Result<()> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        if self.watches[idx].is_free() {
            return Err(Error::NotFound);
        }
        if key.len() > MAX_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        let w = &mut self.watches[idx];
        w.key[..key.len()].copy_from_slice(key);
        w.key_len = key.len();
        Ok(())
    }

    // ── Event triggering ────────────────────────────────────────────

    /// Check a filesystem operation against all watches.
    ///
    /// Called from VFS hooks. If a watch matches, an event is generated.
    /// Returns the number of events generated.
    pub fn check_operation(
        &mut self,
        inode: u64,
        dev: u64,
        event_type: EventType,
        pid: u64,
        uid: u32,
        result: i32,
    ) -> u32 {
        if !self.enabled {
            return 0;
        }

        let perm_bit = event_type.perm_bit();
        let mut count = 0u32;

        for i in 0..MAX_WATCHES {
            let w = &self.watches[i];
            if !matches!(w.state, WatchState::Active) {
                continue;
            }
            if w.inode != inode || w.dev != dev {
                continue;
            }
            if !w.perm_filter.matches(perm_bit) {
                continue;
            }

            // Check rules.
            if !self.check_rules(i, uid, result) {
                continue;
            }

            self.stats.lookup_hits += 1;

            // Generate event.
            self.emit_event(i, event_type, pid, uid, inode, dev, result);
            self.watches[i].trigger_count += 1;
            self.watches[i].last_trigger_ns = self.now_ns;
            count += 1;
        }

        if count == 0 {
            self.stats.lookup_misses += 1;
        }

        count
    }

    /// Check whether any rule on the given watch passes.
    fn check_rules(&self, watch_idx: usize, uid: u32, result: i32) -> bool {
        // If no rules reference this watch, it triggers unconditionally.
        let has_rules = self
            .rules
            .iter()
            .any(|r| r.active && r.watch_idx == watch_idx);
        if !has_rules {
            return true;
        }

        for rule in &self.rules {
            if !rule.active || rule.watch_idx != watch_idx {
                continue;
            }
            if !rule.uid_matches(uid) {
                continue;
            }
            // Check success/failure logging preference.
            if result == 0 && !rule.log_success {
                continue;
            }
            if result != 0 && !rule.log_failure {
                continue;
            }
            return true;
        }
        false
    }

    /// Emit an audit watch event into the ring buffer.
    fn emit_event(
        &mut self,
        watch_idx: usize,
        event_type: EventType,
        pid: u64,
        uid: u32,
        inode: u64,
        dev: u64,
        result: i32,
    ) {
        let event = &mut self.events[self.event_head];
        event.timestamp_ns = self.now_ns;
        event.watch_id = self.watches[watch_idx].id;
        event.event_type = event_type;
        event.pid = pid;
        event.uid = uid;
        event.inode = inode;
        event.dev = dev;
        event.result = result;
        event.delivered = false;

        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        self.event_total += 1;
        self.stats.events_generated += 1;
    }

    // ── Rule management ─────────────────────────────────────────────

    /// Add a watch rule.
    pub fn add_rule(
        &mut self,
        watch_idx: usize,
        key: &[u8],
        uid_min: i64,
        uid_max: i64,
        log_success: bool,
        log_failure: bool,
    ) -> Result<usize> {
        if watch_idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        if self.watches[watch_idx].is_free() {
            return Err(Error::NotFound);
        }
        if key.len() > MAX_KEY_LEN {
            return Err(Error::InvalidArgument);
        }

        let idx = self
            .rules
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let rule = &mut self.rules[idx];
        rule.active = true;
        rule.watch_idx = watch_idx;
        rule.key[..key.len()].copy_from_slice(key);
        rule.key_len = key.len();
        rule.uid_min = uid_min;
        rule.uid_max = uid_max;
        rule.log_success = log_success;
        rule.log_failure = log_failure;

        self.stats.rules_added += 1;
        Ok(idx)
    }

    /// Remove a rule by index.
    pub fn remove_rule(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_RULES {
            return Err(Error::InvalidArgument);
        }
        if !self.rules[idx].active {
            return Err(Error::NotFound);
        }
        self.rules[idx].active = false;
        Ok(())
    }

    // ── Watch tree management ───────────────────────────────────────

    /// Create a watch tree for a parent directory.
    pub fn create_tree(&mut self, parent_inode: u64, parent_dev: u64) -> Result<usize> {
        let idx = self
            .trees
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        self.trees[idx] = WatchTree {
            active: true,
            parent_inode,
            parent_dev,
            children: [0usize; MAX_TREE_CHILDREN],
            child_count: 0,
        };
        Ok(idx)
    }

    /// Add a watch to a tree.
    pub fn add_to_tree(&mut self, tree_idx: usize, watch_idx: usize) -> Result<()> {
        if tree_idx >= MAX_TREES {
            return Err(Error::InvalidArgument);
        }
        if watch_idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        let tree = &mut self.trees[tree_idx];
        if !tree.active {
            return Err(Error::NotFound);
        }
        if tree.child_count >= MAX_TREE_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        tree.children[tree.child_count] = watch_idx;
        tree.child_count += 1;
        // tree_idx is 1-based in the watch to distinguish from 0=none.
        self.watches[watch_idx].tree_idx = tree_idx + 1;
        Ok(())
    }

    /// Remove a watch from a tree.
    fn remove_from_tree(&mut self, tree_idx: usize, watch_idx: usize) {
        if tree_idx >= MAX_TREES {
            return;
        }
        let tree = &mut self.trees[tree_idx];
        if let Some(pos) = tree.children[..tree.child_count]
            .iter()
            .position(|&c| c == watch_idx)
        {
            for i in pos..tree.child_count.saturating_sub(1) {
                tree.children[i] = tree.children[i + 1];
            }
            if tree.child_count > 0 {
                tree.children[tree.child_count - 1] = 0;
            }
            tree.child_count = tree.child_count.saturating_sub(1);
            if tree.child_count == 0 {
                tree.active = false;
            }
        }
    }

    // ── Query ───────────────────────────────────────────────────────

    /// Get a watch by index.
    pub fn watch(&self, idx: usize) -> Result<&AuditWatch> {
        if idx >= MAX_WATCHES {
            return Err(Error::InvalidArgument);
        }
        if self.watches[idx].is_free() {
            return Err(Error::NotFound);
        }
        Ok(&self.watches[idx])
    }

    /// Find a watch by inode/dev.
    pub fn find_watch_by_inode(&self, inode: u64, dev: u64) -> Option<usize> {
        self.watches
            .iter()
            .position(|w| matches!(w.state, WatchState::Active) && w.inode == inode && w.dev == dev)
    }

    /// Count active watches.
    pub fn active_watch_count(&self) -> usize {
        self.watches
            .iter()
            .filter(|w| matches!(w.state, WatchState::Active))
            .count()
    }

    /// Count orphan watches.
    pub fn orphan_watch_count(&self) -> usize {
        self.watches
            .iter()
            .filter(|w| matches!(w.state, WatchState::Orphan))
            .count()
    }

    /// Read an event from the ring buffer.
    pub fn read_event(&self, index: usize) -> Result<&AuditWatchEvent> {
        if self.event_total == 0 {
            return Err(Error::NotFound);
        }
        let available = (self.event_total as usize).min(MAX_EVENTS);
        if index >= available {
            return Err(Error::InvalidArgument);
        }
        let start = if self.event_total as usize > MAX_EVENTS {
            self.event_head
        } else {
            0
        };
        let real = (start + index) % MAX_EVENTS;
        Ok(&self.events[real])
    }

    /// Get total event count.
    pub fn event_total(&self) -> u64 {
        self.event_total
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_trigger() {
        let mut sys = AuditWatchSubsystem::new();
        let idx = sys
            .add_watch(b"/etc/passwd", WatchPermFilter::ALL, 100, 1, 42, 0)
            .unwrap();
        assert_eq!(sys.active_watch_count(), 1);

        let triggered = sys.check_operation(100, 1, EventType::Write, 42, 0, 0);
        assert_eq!(triggered, 1);
        assert_eq!(sys.watch(idx).unwrap().trigger_count(), 1);
    }

    #[test]
    fn test_perm_filter() {
        let mut sys = AuditWatchSubsystem::new();
        sys.add_watch(
            b"/etc/shadow",
            WatchPermFilter(PERM_WRITE | PERM_ATTR),
            200,
            1,
            0,
            0,
        )
        .unwrap();

        // Read should not trigger.
        let t = sys.check_operation(200, 1, EventType::Read, 1, 0, 0);
        assert_eq!(t, 0);

        // Write should trigger.
        let t = sys.check_operation(200, 1, EventType::Write, 1, 0, 0);
        assert_eq!(t, 1);
    }

    #[test]
    fn test_orphan_resolution() {
        let mut sys = AuditWatchSubsystem::new();
        let idx = sys
            .add_watch(b"/mnt/data/file", WatchPermFilter::ALL, 0, 0, 1, 0)
            .unwrap();
        assert_eq!(sys.orphan_watch_count(), 1);

        sys.resolve_orphan(idx, 500, 2).unwrap();
        assert_eq!(sys.orphan_watch_count(), 0);
        assert_eq!(sys.active_watch_count(), 1);
    }

    #[test]
    fn test_rule_uid_filter() {
        let mut sys = AuditWatchSubsystem::new();
        let w = sys
            .add_watch(b"/var/log/auth.log", WatchPermFilter::ALL, 300, 1, 0, 0)
            .unwrap();
        // Only trigger for UID 1000-2000.
        sys.add_rule(w, b"auth-key", 1000, 2000, true, true)
            .unwrap();

        // UID 500 should not trigger.
        let t = sys.check_operation(300, 1, EventType::Read, 1, 500, 0);
        assert_eq!(t, 0);

        // UID 1500 should trigger.
        let t = sys.check_operation(300, 1, EventType::Read, 1, 1500, 0);
        assert_eq!(t, 1);
    }

    #[test]
    fn test_remove_watch() {
        let mut sys = AuditWatchSubsystem::new();
        let idx = sys
            .add_watch(b"/tmp/test", WatchPermFilter::ALL, 400, 1, 0, 0)
            .unwrap();
        sys.remove_watch(idx).unwrap();
        assert_eq!(sys.active_watch_count(), 0);
    }
}

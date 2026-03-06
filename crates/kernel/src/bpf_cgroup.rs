// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF cgroup program attachment and management.
//!
//! Provides the infrastructure for attaching eBPF programs to cgroups,
//! implementing cgroup-level network and resource control hooks. This
//! mirrors Linux's `kernel/bpf/cgroup.c` functionality.
//!
//! # Hook Points
//!
//! | Hook              | Direction | Description                     |
//! |-------------------|-----------|---------------------------------|
//! | Ingress           | Inbound   | Filter incoming packets         |
//! | Egress            | Outbound  | Filter outgoing packets         |
//! | SockCreate        | —         | Socket creation control         |
//! | SockOps           | —         | TCP socket event hooks          |
//! | DeviceCgroup      | —         | Device access control           |
//! | SockAddr          | —         | Socket address rewrite          |
//! | Sysctl            | —         | Sysctl read/write filtering     |
//! | Getsockopt        | —         | getsockopt interposition        |
//! | Setsockopt        | —         | setsockopt interposition        |
//!
//! # Effective Program Ordering
//!
//! Programs are evaluated in order of cgroup hierarchy depth: root
//! cgroup first, then child, then grandchild, etc. Within the same
//! cgroup, programs run in attachment order. A program returning
//! `DENY` short-circuits evaluation — remaining programs are skipped.
//!
//! # Attach Flags
//!
//! - `NONE`: append to the list; only one program of this type allowed
//! - `MULTI`: allow multiple programs of the same type
//! - `REPLACE`: replace an existing program (requires `replace_prog_id`)
//! - `OVERRIDE`: effective programs override parent cgroup programs
//!
//! Reference: Linux `kernel/bpf/cgroup.c`, `include/linux/bpf-cgroup.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of cgroups that can have BPF programs attached.
const MAX_CGROUPS: usize = 64;

/// Maximum BPF programs per cgroup per hook type.
const MAX_PROGS_PER_HOOK: usize = 16;

/// Maximum number of hook types.
const MAX_HOOK_TYPES: usize = 10;

/// Maximum cgroup hierarchy depth for effective program computation.
const MAX_HIERARCHY_DEPTH: usize = 8;

/// Maximum total effective programs across the hierarchy.
const MAX_EFFECTIVE_PROGS: usize = 64;

/// Maximum cgroup name length in bytes.
const MAX_NAME_LEN: usize = 64;

// ── BPF Cgroup Hook Type ───────────────────────────────────────────

/// Hook points where BPF programs can be attached to a cgroup.
///
/// Each hook type corresponds to a specific kernel subsystem event
/// that BPF programs can intercept for the processes within a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfCgroupHookType {
    /// Ingress packet filter (before socket delivery).
    Ingress = 0,
    /// Egress packet filter (before transmission).
    Egress = 1,
    /// Socket creation hook (AF_INET/AF_INET6).
    SockCreate = 2,
    /// TCP socket operations (connect, sendmsg, etc.).
    SockOps = 3,
    /// Device cgroup access control.
    DeviceCgroup = 4,
    /// Socket address bind/connect rewriting.
    SockAddr = 5,
    /// Sysctl read/write interception.
    Sysctl = 6,
    /// getsockopt interposition.
    Getsockopt = 7,
    /// setsockopt interposition.
    Setsockopt = 8,
    /// Socket release notification.
    SockRelease = 9,
}

impl BpfCgroupHookType {
    /// Convert a raw u32 to a hook type.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Ingress),
            1 => Some(Self::Egress),
            2 => Some(Self::SockCreate),
            3 => Some(Self::SockOps),
            4 => Some(Self::DeviceCgroup),
            5 => Some(Self::SockAddr),
            6 => Some(Self::Sysctl),
            7 => Some(Self::Getsockopt),
            8 => Some(Self::Setsockopt),
            9 => Some(Self::SockRelease),
            _ => None,
        }
    }

    /// Return the index of this hook type for array indexing.
    fn index(self) -> usize {
        self as usize
    }
}

// ── Attach Flags ───────────────────────────────────────────────────

/// Flags controlling how a BPF program is attached to a cgroup hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfCgroupAttachFlags {
    /// Default: single program per hook type (replace if exists).
    #[default]
    None,
    /// Allow multiple programs of the same hook type.
    Multi,
    /// Replace a specific existing program (by `replace_prog_id`).
    Replace,
    /// Override parent cgroup effective programs.
    Override,
}

// ── BPF Cgroup Verdict ─────────────────────────────────────────────

/// Result of running a BPF cgroup program.
///
/// The verdict determines whether the operation proceeds or is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfCgroupVerdict {
    /// Allow the operation to proceed.
    #[default]
    Allow,
    /// Deny the operation; short-circuits further evaluation.
    Deny,
}

// ── Attached Program Entry ─────────────────────────────────────────

/// A single BPF program attached to a cgroup hook.
///
/// Records the program identity, ordering, and attachment metadata.
#[derive(Debug, Clone, Copy)]
pub struct BpfCgroupProgEntry {
    /// BPF program ID (from the BPF program registry).
    pub prog_id: u64,
    /// Hook type this program is attached to.
    pub hook_type: BpfCgroupHookType,
    /// Attachment order within this hook (lower = earlier).
    pub order: u32,
    /// Whether this entry is active.
    pub active: bool,
    /// Attachment flags used when attaching this program.
    pub flags: BpfCgroupAttachFlags,
    /// Timestamp (ticks) when the program was attached.
    pub attach_time: u64,
}

impl BpfCgroupProgEntry {
    /// Create an empty (inactive) entry.
    const fn empty() -> Self {
        Self {
            prog_id: 0,
            hook_type: BpfCgroupHookType::Ingress,
            order: 0,
            active: false,
            flags: BpfCgroupAttachFlags::None,
            attach_time: 0,
        }
    }
}

// ── Per-Hook Program List ──────────────────────────────────────────

/// Programs attached to a single hook type within a cgroup.
///
/// Maintains an ordered list of BPF programs for a given hook point.
/// Programs are executed in order of their `order` field.
struct HookProgList {
    /// Attached programs for this hook.
    progs: [BpfCgroupProgEntry; MAX_PROGS_PER_HOOK],
    /// Number of active programs.
    count: usize,
    /// Whether multi-attach is enabled for this hook.
    multi_enabled: bool,
    /// Whether this hook overrides parent effective programs.
    override_enabled: bool,
}

impl HookProgList {
    /// Create an empty hook program list.
    const fn new() -> Self {
        Self {
            progs: [BpfCgroupProgEntry::empty(); MAX_PROGS_PER_HOOK],
            count: 0,
            multi_enabled: false,
            override_enabled: false,
        }
    }

    /// Attach a program to this hook.
    fn attach(
        &mut self,
        prog_id: u64,
        hook_type: BpfCgroupHookType,
        flags: BpfCgroupAttachFlags,
        now: u64,
    ) -> Result<()> {
        match flags {
            BpfCgroupAttachFlags::None => {
                // Single program mode: replace any existing program
                if self.count > 0 {
                    self.progs[0] = BpfCgroupProgEntry {
                        prog_id,
                        hook_type,
                        order: 0,
                        active: true,
                        flags,
                        attach_time: now,
                    };
                } else {
                    self.progs[0] = BpfCgroupProgEntry {
                        prog_id,
                        hook_type,
                        order: 0,
                        active: true,
                        flags,
                        attach_time: now,
                    };
                    self.count = 1;
                }
                self.multi_enabled = false;
            }
            BpfCgroupAttachFlags::Multi => {
                if self.count >= MAX_PROGS_PER_HOOK {
                    return Err(Error::OutOfMemory);
                }
                let order = self.count as u32;
                self.progs[self.count] = BpfCgroupProgEntry {
                    prog_id,
                    hook_type,
                    order,
                    active: true,
                    flags,
                    attach_time: now,
                };
                self.count += 1;
                self.multi_enabled = true;
            }
            BpfCgroupAttachFlags::Replace => {
                // Find and replace by scanning for an existing entry
                // Caller must ensure at least one program exists
                if self.count == 0 {
                    return Err(Error::NotFound);
                }
                // Replace the first active program
                let slot = self.progs[..self.count].iter().position(|p| p.active);
                match slot {
                    Some(idx) => {
                        self.progs[idx] = BpfCgroupProgEntry {
                            prog_id,
                            hook_type,
                            order: self.progs[idx].order,
                            active: true,
                            flags,
                            attach_time: now,
                        };
                    }
                    None => return Err(Error::NotFound),
                }
            }
            BpfCgroupAttachFlags::Override => {
                if self.count >= MAX_PROGS_PER_HOOK {
                    return Err(Error::OutOfMemory);
                }
                let order = self.count as u32;
                self.progs[self.count] = BpfCgroupProgEntry {
                    prog_id,
                    hook_type,
                    order,
                    active: true,
                    flags,
                    attach_time: now,
                };
                self.count += 1;
                self.override_enabled = true;
            }
        }
        Ok(())
    }

    /// Detach a program by its ID.
    fn detach(&mut self, prog_id: u64) -> Result<()> {
        let slot = self.progs[..self.count]
            .iter()
            .position(|p| p.active && p.prog_id == prog_id);
        match slot {
            Some(idx) => {
                self.progs[idx].active = false;
                // Compact the list
                self.compact();
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Compact the list by removing inactive entries and reordering.
    fn compact(&mut self) {
        let mut write_idx = 0;
        for read_idx in 0..self.count {
            if self.progs[read_idx].active {
                if write_idx != read_idx {
                    self.progs[write_idx] = self.progs[read_idx];
                }
                self.progs[write_idx].order = write_idx as u32;
                write_idx += 1;
            }
        }
        // Clear remaining slots
        for idx in write_idx..self.count {
            self.progs[idx] = BpfCgroupProgEntry::empty();
        }
        self.count = write_idx;
    }
}

// ── Per-Cgroup BPF State ───────────────────────────────────────────

/// BPF programs attached to a single cgroup.
///
/// Tracks programs across all hook types for one cgroup. Also stores
/// cgroup metadata needed for effective program computation (parent
/// index and hierarchy depth).
pub struct BpfCgroupState {
    /// Cgroup ID (unique, matches the cgroup subsystem).
    cgroup_id: u64,
    /// Human-readable name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
    /// Index of the parent cgroup in the registry (u64::MAX = root).
    parent_idx: u64,
    /// Depth in the cgroup hierarchy (0 = root).
    depth: u32,
    /// Per-hook-type program lists.
    hooks: [HookProgList; MAX_HOOK_TYPES],
    /// Whether this slot is in use.
    active: bool,
}

impl BpfCgroupState {
    /// Create an empty (inactive) cgroup BPF state.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_idx: u64::MAX,
            depth: 0,
            hooks: [
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
                HookProgList::new(),
            ],
            active: false,
        }
    }
}

// ── Effective Program Entry ────────────────────────────────────────

/// An entry in the effective program list for a hook type.
///
/// Effective programs are the flattened, ordered list of all BPF
/// programs that apply to a cgroup, considering the full hierarchy.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveProgEntry {
    /// BPF program ID.
    pub prog_id: u64,
    /// Cgroup that owns this program.
    pub cgroup_id: u64,
    /// Depth of the owning cgroup in the hierarchy.
    pub depth: u32,
    /// Order within the cgroup's hook list.
    pub order: u32,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl EffectiveProgEntry {
    /// Create an empty effective program entry.
    const fn empty() -> Self {
        Self {
            prog_id: 0,
            cgroup_id: 0,
            depth: 0,
            order: 0,
            valid: false,
        }
    }
}

/// Result of computing effective programs for a hook.
pub struct EffectiveProgList {
    /// Ordered list of effective programs.
    pub entries: [EffectiveProgEntry; MAX_EFFECTIVE_PROGS],
    /// Number of valid entries.
    pub count: usize,
}

impl EffectiveProgList {
    /// Create an empty effective program list.
    const fn new() -> Self {
        Self {
            entries: [EffectiveProgEntry::empty(); MAX_EFFECTIVE_PROGS],
            count: 0,
        }
    }

    /// Add an entry to the effective list.
    fn push(&mut self, entry: EffectiveProgEntry) -> Result<()> {
        if self.count >= MAX_EFFECTIVE_PROGS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }
}

// ── Run Context ────────────────────────────────────────────────────

/// Context passed to BPF cgroup programs during execution.
///
/// Contains information about the event being filtered and metadata
/// for the program to make allow/deny decisions.
#[derive(Debug, Clone, Copy)]
pub struct BpfCgroupRunCtx {
    /// Hook type being executed.
    pub hook_type: BpfCgroupHookType,
    /// Process ID of the task triggering the hook.
    pub pid: u64,
    /// Cgroup ID of the task's cgroup.
    pub cgroup_id: u64,
    /// Socket family (AF_INET=2, AF_INET6=10), for socket hooks.
    pub sock_family: u16,
    /// Socket type (SOCK_STREAM=1, SOCK_DGRAM=2), for socket hooks.
    pub sock_type: u16,
    /// Protocol number, for socket hooks.
    pub protocol: u16,
    /// Source/destination port, for address hooks.
    pub port: u16,
    /// Source/destination IPv4 address, for address hooks.
    pub addr_v4: u32,
    /// Packet length in bytes, for skb hooks.
    pub pkt_len: u32,
    /// Sysctl name hash, for sysctl hooks.
    pub sysctl_name_hash: u32,
    /// Sysctl value (first 8 bytes), for sysctl hooks.
    pub sysctl_val: u64,
}

impl BpfCgroupRunCtx {
    /// Create a minimal run context for a given hook and cgroup.
    pub const fn new(hook_type: BpfCgroupHookType, cgroup_id: u64) -> Self {
        Self {
            hook_type,
            pid: 0,
            cgroup_id,
            sock_family: 0,
            sock_type: 0,
            protocol: 0,
            port: 0,
            addr_v4: 0,
            pkt_len: 0,
            sysctl_name_hash: 0,
            sysctl_val: 0,
        }
    }
}

// ── Run Result ─────────────────────────────────────────────────────

/// Result of running BPF cgroup programs for a hook.
#[derive(Debug, Clone, Copy)]
pub struct BpfCgroupRunResult {
    /// Final verdict after running all applicable programs.
    pub verdict: BpfCgroupVerdict,
    /// Number of programs that were executed.
    pub progs_run: u32,
    /// ID of the program that issued DENY (0 if allowed).
    pub deny_prog_id: u64,
}

// ── Statistics ─────────────────────────────────────────────────────

/// Per-hook-type statistics for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct BpfCgroupHookStats {
    /// Total number of times this hook was invoked.
    pub run_count: u64,
    /// Total number of DENY verdicts.
    pub deny_count: u64,
    /// Total programs executed across all invocations.
    pub total_progs_run: u64,
}

impl BpfCgroupHookStats {
    /// Create zeroed hook stats.
    const fn new() -> Self {
        Self {
            run_count: 0,
            deny_count: 0,
            total_progs_run: 0,
        }
    }
}

/// Aggregate statistics for the BPF cgroup subsystem.
#[derive(Debug, Clone, Copy)]
pub struct BpfCgroupStats {
    /// Per-hook-type statistics.
    pub per_hook: [BpfCgroupHookStats; MAX_HOOK_TYPES],
    /// Total programs currently attached across all cgroups.
    pub total_attached: u64,
    /// Total attach operations performed.
    pub attach_ops: u64,
    /// Total detach operations performed.
    pub detach_ops: u64,
}

impl BpfCgroupStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            per_hook: [
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
                BpfCgroupHookStats::new(),
            ],
            total_attached: 0,
            attach_ops: 0,
            detach_ops: 0,
        }
    }
}

// ── Registry ───────────────────────────────────────────────────────

/// System-wide registry of BPF cgroup program attachments.
///
/// Manages BPF programs attached to cgroups across the entire system.
/// Provides attach, detach, effective program computation, and
/// simulated program execution (verdict evaluation).
///
/// # Effective Program Computation
///
/// When evaluating a hook for a process, the effective programs are
/// the union of all programs attached to the process's cgroup and
/// all ancestor cgroups, ordered by:
/// 1. Hierarchy depth (root first, deepest last)
/// 2. Attachment order within each cgroup
///
/// A cgroup with `override_enabled` replaces all ancestor programs
/// for that hook.
pub struct BpfCgroupRegistry {
    /// Per-cgroup BPF state.
    cgroups: [BpfCgroupState; MAX_CGROUPS],
    /// Number of active cgroups.
    active_count: usize,
    /// Global statistics.
    stats: BpfCgroupStats,
    /// Next cgroup slot to try on allocation.
    next_slot: usize,
}

impl BpfCgroupRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            cgroups: [
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
                BpfCgroupState::empty(),
            ],
            active_count: 0,
            stats: BpfCgroupStats::new(),
            next_slot: 0,
        }
    }

    /// Register a cgroup for BPF program attachment.
    ///
    /// The cgroup must have a unique `cgroup_id`. The `parent_idx` is
    /// the index of the parent cgroup in this registry, or `u64::MAX`
    /// for the root cgroup.
    pub fn register_cgroup(
        &mut self,
        cgroup_id: u64,
        name: &[u8],
        parent_idx: u64,
        depth: u32,
    ) -> Result<usize> {
        if self.active_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate
        if self.find_cgroup(cgroup_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        // Find a free slot
        let slot = self.find_free_slot()?;
        let cg = &mut self.cgroups[slot];
        cg.cgroup_id = cgroup_id;
        let copy_len = name.len().min(MAX_NAME_LEN);
        cg.name[..copy_len].copy_from_slice(&name[..copy_len]);
        cg.name_len = copy_len;
        cg.parent_idx = parent_idx;
        cg.depth = depth;
        cg.active = true;
        self.active_count += 1;
        Ok(slot)
    }

    /// Unregister a cgroup, detaching all BPF programs.
    pub fn unregister_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        // Count programs being removed
        let mut removed = 0u64;
        for hook in &self.cgroups[idx].hooks {
            removed += hook.count as u64;
        }
        self.cgroups[idx] = BpfCgroupState::empty();
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.total_attached = self.stats.total_attached.saturating_sub(removed);
        Ok(())
    }

    /// Attach a BPF program to a cgroup hook.
    ///
    /// # Arguments
    /// * `cgroup_id` — target cgroup
    /// * `hook_type` — which hook to attach to
    /// * `prog_id` — BPF program ID
    /// * `flags` — attachment flags (single/multi/replace/override)
    /// * `now` — current timestamp in ticks
    pub fn attach_prog(
        &mut self,
        cgroup_id: u64,
        hook_type: BpfCgroupHookType,
        prog_id: u64,
        flags: BpfCgroupAttachFlags,
        now: u64,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let hook_idx = hook_type.index();
        self.cgroups[idx].hooks[hook_idx].attach(prog_id, hook_type, flags, now)?;
        self.stats.total_attached += 1;
        self.stats.attach_ops += 1;
        Ok(())
    }

    /// Detach a BPF program from a cgroup hook.
    pub fn detach_prog(
        &mut self,
        cgroup_id: u64,
        hook_type: BpfCgroupHookType,
        prog_id: u64,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let hook_idx = hook_type.index();
        self.cgroups[idx].hooks[hook_idx].detach(prog_id)?;
        self.stats.total_attached = self.stats.total_attached.saturating_sub(1);
        self.stats.detach_ops += 1;
        Ok(())
    }

    /// Replace a specific program in a cgroup hook.
    ///
    /// Finds the program with `old_prog_id` and replaces it with
    /// `new_prog_id`, preserving the attachment order.
    pub fn replace_prog(
        &mut self,
        cgroup_id: u64,
        hook_type: BpfCgroupHookType,
        old_prog_id: u64,
        new_prog_id: u64,
        now: u64,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let hook_idx = hook_type.index();
        let hook = &mut self.cgroups[idx].hooks[hook_idx];
        let slot = hook.progs[..hook.count]
            .iter()
            .position(|p| p.active && p.prog_id == old_prog_id)
            .ok_or(Error::NotFound)?;
        hook.progs[slot].prog_id = new_prog_id;
        hook.progs[slot].attach_time = now;
        Ok(())
    }

    /// Compute the effective program list for a cgroup and hook type.
    ///
    /// Walks the cgroup hierarchy from root to the target cgroup,
    /// collecting all attached programs in order. A cgroup with
    /// `override_enabled` discards ancestor programs.
    pub fn compute_effective(
        &self,
        cgroup_id: u64,
        hook_type: BpfCgroupHookType,
    ) -> Result<EffectiveProgList> {
        let mut result = EffectiveProgList::new();
        let hook_idx = hook_type.index();

        // Collect ancestor chain (from target up to root)
        let mut chain = [0usize; MAX_HIERARCHY_DEPTH];
        let mut chain_len = 0usize;
        let mut current_id = cgroup_id;

        loop {
            let idx = self.find_cgroup(current_id).ok_or(Error::NotFound)?;
            if chain_len >= MAX_HIERARCHY_DEPTH {
                break;
            }
            chain[chain_len] = idx;
            chain_len += 1;
            let parent = self.cgroups[idx].parent_idx;
            if parent == u64::MAX {
                break;
            }
            current_id = self.cgroups[parent as usize].cgroup_id;
        }

        // Walk from root (last in chain) to target (first in chain)
        // Check if any cgroup has override, in which case we start
        // from the deepest override.
        let mut start = 0usize;
        for i in 0..chain_len {
            let ci = chain[i];
            if self.cgroups[ci].hooks[hook_idx].override_enabled {
                start = i;
                break;
            }
        }

        // Iterate from root towards target (reversed chain)
        let mut i = if chain_len > 0 { chain_len - 1 } else { 0 };
        loop {
            if i < start {
                if i == 0 {
                    break;
                }
                i -= 1;
                continue;
            }
            let ci = chain[i];
            let cg = &self.cgroups[ci];
            let hook = &cg.hooks[hook_idx];
            for p_idx in 0..hook.count {
                let prog = &hook.progs[p_idx];
                if prog.active {
                    result.push(EffectiveProgEntry {
                        prog_id: prog.prog_id,
                        cgroup_id: cg.cgroup_id,
                        depth: cg.depth,
                        order: prog.order,
                        valid: true,
                    })?;
                }
            }
            if i == 0 {
                break;
            }
            i -= 1;
        }

        Ok(result)
    }

    /// Run BPF cgroup programs for a hook event.
    ///
    /// Computes the effective programs and simulates execution. Each
    /// program's verdict is determined by a hash-based decision:
    /// programs with even IDs allow, odd IDs deny. In a real system
    /// the BPF VM would execute the program bytecode.
    ///
    /// Returns the aggregate verdict — `Deny` if any program denies,
    /// `Allow` otherwise (short-circuit on first deny).
    pub fn run_progs(&mut self, ctx: &BpfCgroupRunCtx) -> Result<BpfCgroupRunResult> {
        let effective = self.compute_effective(ctx.cgroup_id, ctx.hook_type)?;

        let hook_idx = ctx.hook_type.index();
        self.stats.per_hook[hook_idx].run_count += 1;

        let mut progs_run = 0u32;
        let mut verdict = BpfCgroupVerdict::Allow;
        let mut deny_prog_id = 0u64;

        for i in 0..effective.count {
            let entry = &effective.entries[i];
            if !entry.valid {
                continue;
            }
            progs_run += 1;

            // Simulate BPF program execution. In a real kernel, the
            // BPF VM would run the program bytecode here.
            let prog_verdict = self.simulate_prog_verdict(entry.prog_id, ctx);
            if prog_verdict == BpfCgroupVerdict::Deny {
                verdict = BpfCgroupVerdict::Deny;
                deny_prog_id = entry.prog_id;
                break; // Short-circuit on deny
            }
        }

        self.stats.per_hook[hook_idx].total_progs_run += progs_run as u64;
        if verdict == BpfCgroupVerdict::Deny {
            self.stats.per_hook[hook_idx].deny_count += 1;
        }

        Ok(BpfCgroupRunResult {
            verdict,
            progs_run,
            deny_prog_id,
        })
    }

    /// Query the number of programs attached to a cgroup hook.
    pub fn prog_count(&self, cgroup_id: u64, hook_type: BpfCgroupHookType) -> Result<usize> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.cgroups[idx].hooks[hook_type.index()].count)
    }

    /// List program IDs attached to a cgroup hook.
    ///
    /// Returns up to `buf.len()` program IDs and the total count.
    pub fn list_progs(
        &self,
        cgroup_id: u64,
        hook_type: BpfCgroupHookType,
        buf: &mut [u64],
    ) -> Result<usize> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let hook = &self.cgroups[idx].hooks[hook_type.index()];
        let mut written = 0;
        for i in 0..hook.count {
            if hook.progs[i].active {
                if written < buf.len() {
                    buf[written] = hook.progs[i].prog_id;
                }
                written += 1;
            }
        }
        Ok(written)
    }

    /// Get global BPF cgroup statistics.
    pub fn statistics(&self) -> &BpfCgroupStats {
        &self.stats
    }

    /// Return the number of active cgroups in the registry.
    pub fn active_cgroup_count(&self) -> usize {
        self.active_count
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Find the index of a cgroup by its ID.
    fn find_cgroup(&self, cgroup_id: u64) -> Option<usize> {
        self.cgroups
            .iter()
            .position(|cg| cg.active && cg.cgroup_id == cgroup_id)
    }

    /// Find a free slot in the cgroup array.
    fn find_free_slot(&mut self) -> Result<usize> {
        for i in 0..MAX_CGROUPS {
            let idx = (self.next_slot + i) % MAX_CGROUPS;
            if !self.cgroups[idx].active {
                self.next_slot = (idx + 1) % MAX_CGROUPS;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Simulate a BPF program verdict based on program ID and context.
    ///
    /// In a real kernel, this would invoke the BPF VM. Here we use a
    /// deterministic hash to produce a verdict for testing.
    fn simulate_prog_verdict(&self, prog_id: u64, ctx: &BpfCgroupRunCtx) -> BpfCgroupVerdict {
        // Simple deterministic: programs with ID ending in 0xFF deny
        let combined = prog_id ^ ctx.cgroup_id ^ (ctx.pid << 3);
        if combined & 0xFF == 0xFF {
            BpfCgroupVerdict::Deny
        } else {
            BpfCgroupVerdict::Allow
        }
    }
}

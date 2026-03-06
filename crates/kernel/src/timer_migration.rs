// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Timer migration between CPUs.
//!
//! When a CPU goes idle, its pending timers must still fire on time.
//! Timer migration groups organize CPUs into a hierarchy
//! (core → package → system) so that an idle CPU's timers are
//! handled by a still-active CPU in the same group.
//!
//! # Hierarchy
//!
//! ```text
//!   System Group (level 2)
//!   ├── Package Group 0 (level 1)
//!   │   ├── Core Group 0 (level 0)
//!   │   │   ├── CPU 0  (next_expiry = 1000)
//!   │   │   └── CPU 1  (idle, timers migrated)
//!   │   └── Core Group 1 (level 0)
//!   │       ├── CPU 2  (next_expiry = 2000)
//!   │       └── CPU 3  (idle)
//!   └── Package Group 1 (level 1)
//!       └── ...
//! ```
//!
//! # Expiry Propagation
//!
//! Each group tracks the earliest timer expiry across all its
//! members. When a CPU's earliest expiry changes, the group
//! propagates this up the hierarchy.
//!
//! # Reference
//!
//! Linux `kernel/time/timer_migration.c`,
//! `include/linux/timer_migration.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of CPUs.
const MAX_CPUS: usize = 64;

/// Maximum hierarchy depth (core, package, system).
const MAX_LEVELS: usize = 3;

/// Maximum number of groups per level.
const MAX_GROUPS_PER_LEVEL: usize = 32;

/// Maximum CPUs per core group.
const MAX_CPUS_PER_GROUP: usize = 8;

/// Sentinel value meaning "no timer pending".
const EXPIRY_NONE: u64 = u64::MAX;

/// Group level names.
const _LEVEL_NAMES: [&str; MAX_LEVELS] = ["core", "package", "system"];

// ======================================================================
// Group level
// ======================================================================

/// Hierarchy level for a timer migration group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupLevel {
    /// Core level (SMT siblings).
    Core = 0,
    /// Package level (cores in a socket).
    Package = 1,
    /// System level (all packages).
    System = 2,
}

impl GroupLevel {
    /// Converts from a numeric index.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(Self::Core),
            1 => Ok(Self::Package),
            2 => Ok(Self::System),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns the numeric index.
    pub fn index(self) -> usize {
        self as usize
    }
}

// ======================================================================
// Per-CPU timer state
// ======================================================================

/// Timer migration state for a single CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpuTimerState {
    /// CPU index.
    cpu: u32,
    /// Earliest local timer expiry (nanoseconds).
    next_expiry: u64,
    /// Whether this CPU is idle.
    idle: bool,
    /// Whether this CPU is online.
    online: bool,
    /// Group index at level 0 (core group).
    core_group: u8,
    /// Group index at level 1 (package group).
    package_group: u8,
    /// Number of pending timers.
    nr_pending: u32,
}

impl CpuTimerState {
    /// Creates a new CPU timer state.
    pub const fn new() -> Self {
        Self {
            cpu: 0,
            next_expiry: EXPIRY_NONE,
            idle: false,
            online: false,
            core_group: 0,
            package_group: 0,
            nr_pending: 0,
        }
    }

    /// Returns the CPU index.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns the next expiry time.
    pub fn next_expiry(&self) -> u64 {
        self.next_expiry
    }

    /// Returns whether this CPU is idle.
    pub fn is_idle(&self) -> bool {
        self.idle
    }

    /// Returns whether this CPU is online.
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Returns the number of pending timers.
    pub fn nr_pending(&self) -> u32 {
        self.nr_pending
    }
}

// ======================================================================
// Timer migration group
// ======================================================================

/// A group of CPUs at a given hierarchy level.
pub struct TimerMigrationGroup {
    /// Group ID.
    group_id: u16,
    /// Hierarchy level.
    level: GroupLevel,
    /// Member CPU indices (for core-level groups).
    members: [u32; MAX_CPUS_PER_GROUP],
    /// Number of members.
    nr_members: usize,
    /// Number of active (non-idle) members.
    nr_active: u32,
    /// Earliest timer expiry across all members.
    next_expiry: u64,
    /// CPU designated to handle migrated timers.
    migrator_cpu: u32,
    /// Whether this group is active (has at least one active CPU).
    active: bool,
    /// Parent group index (at next level up).
    parent_group: u16,
    /// Whether this group slot is in use.
    in_use: bool,
    /// Child group indices (for package/system levels).
    children: [u16; MAX_CPUS_PER_GROUP],
    /// Number of child groups.
    nr_children: usize,
}

impl TimerMigrationGroup {
    /// Creates an empty group.
    pub const fn new() -> Self {
        Self {
            group_id: 0,
            level: GroupLevel::Core,
            members: [0; MAX_CPUS_PER_GROUP],
            nr_members: 0,
            nr_active: 0,
            next_expiry: EXPIRY_NONE,
            migrator_cpu: 0,
            active: false,
            parent_group: 0,
            in_use: false,
            children: [0; MAX_CPUS_PER_GROUP],
            nr_children: 0,
        }
    }

    /// Returns the group ID.
    pub fn group_id(&self) -> u16 {
        self.group_id
    }

    /// Returns the hierarchy level.
    pub fn level(&self) -> GroupLevel {
        self.level
    }

    /// Returns the number of members.
    pub fn nr_members(&self) -> usize {
        self.nr_members
    }

    /// Returns the number of active members.
    pub fn nr_active(&self) -> u32 {
        self.nr_active
    }

    /// Returns the earliest expiry.
    pub fn next_expiry(&self) -> u64 {
        self.next_expiry
    }

    /// Returns the migrator CPU.
    pub fn migrator_cpu(&self) -> u32 {
        self.migrator_cpu
    }

    /// Returns whether the group is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Adds a CPU member.
    pub fn add_member(&mut self, cpu: u32) -> Result<()> {
        if self.nr_members >= MAX_CPUS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.members[self.nr_members] = cpu;
        self.nr_members += 1;
        Ok(())
    }

    /// Adds a child group.
    pub fn add_child(&mut self, child_id: u16) -> Result<()> {
        if self.nr_children >= MAX_CPUS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.children[self.nr_children] = child_id;
        self.nr_children += 1;
        Ok(())
    }

    /// Recalculates the earliest expiry from member states.
    pub fn recalc_expiry(&mut self, cpu_states: &[CpuTimerState; MAX_CPUS]) {
        let mut earliest = EXPIRY_NONE;
        for i in 0..self.nr_members {
            let cpu = self.members[i] as usize;
            if cpu < MAX_CPUS && cpu_states[cpu].online {
                earliest = earliest.min(cpu_states[cpu].next_expiry);
            }
        }
        self.next_expiry = earliest;
    }

    /// Selects the migrator CPU (first non-idle, online member).
    pub fn select_migrator(&mut self, cpu_states: &[CpuTimerState; MAX_CPUS]) {
        for i in 0..self.nr_members {
            let cpu = self.members[i] as usize;
            if cpu < MAX_CPUS && cpu_states[cpu].online && !cpu_states[cpu].idle {
                self.migrator_cpu = self.members[i];
                self.active = true;
                return;
            }
        }
        // All members idle — pick first online as fallback.
        for i in 0..self.nr_members {
            let cpu = self.members[i] as usize;
            if cpu < MAX_CPUS && cpu_states[cpu].online {
                self.migrator_cpu = self.members[i];
                self.active = false;
                return;
            }
        }
    }
}

// ======================================================================
// Timer migration hierarchy
// ======================================================================

/// Manages the timer migration group hierarchy.
pub struct TimerMigrationHierarchy {
    /// Per-CPU timer states.
    cpu_states: [CpuTimerState; MAX_CPUS],
    /// Groups at each level.
    groups: [[TimerMigrationGroup; MAX_GROUPS_PER_LEVEL]; MAX_LEVELS],
    /// Number of groups at each level.
    nr_groups: [usize; MAX_LEVELS],
    /// Number of online CPUs.
    nr_online: u32,
    /// Global earliest timer expiry.
    global_next_expiry: u64,
}

impl TimerMigrationHierarchy {
    /// Creates a new timer migration hierarchy.
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { CpuTimerState::new() }; MAX_CPUS],
            groups: [const { [const { TimerMigrationGroup::new() }; MAX_GROUPS_PER_LEVEL] };
                MAX_LEVELS],
            nr_groups: [0; MAX_LEVELS],
            nr_online: 0,
            global_next_expiry: EXPIRY_NONE,
        }
    }

    /// Returns the number of online CPUs.
    pub fn nr_online(&self) -> u32 {
        self.nr_online
    }

    /// Returns the global earliest expiry.
    pub fn global_next_expiry(&self) -> u64 {
        self.global_next_expiry
    }

    /// Returns a reference to a CPU's timer state.
    pub fn cpu_state(&self, cpu: u32) -> Result<&CpuTimerState> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpu_states[cpu as usize])
    }

    /// Initializes a CPU.
    pub fn init_cpu(&mut self, cpu: u32, core_group: u8, package_group: u8) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = cpu as usize;
        self.cpu_states[idx].cpu = cpu;
        self.cpu_states[idx].online = true;
        self.cpu_states[idx].idle = false;
        self.cpu_states[idx].next_expiry = EXPIRY_NONE;
        self.cpu_states[idx].core_group = core_group;
        self.cpu_states[idx].package_group = package_group;
        self.nr_online += 1;
        Ok(())
    }

    /// Creates a group at a given level.
    pub fn create_group(&mut self, level: GroupLevel, parent: u16) -> Result<u16> {
        let lvl = level.index();
        if self.nr_groups[lvl] >= MAX_GROUPS_PER_LEVEL {
            return Err(Error::OutOfMemory);
        }
        let gid = self.nr_groups[lvl] as u16;
        self.groups[lvl][gid as usize].group_id = gid;
        self.groups[lvl][gid as usize].level = level;
        self.groups[lvl][gid as usize].parent_group = parent;
        self.groups[lvl][gid as usize].in_use = true;
        self.nr_groups[lvl] += 1;
        Ok(gid)
    }

    /// Adds a CPU to a core-level group.
    pub fn add_cpu_to_group(&mut self, cpu: u32, group_id: u16) -> Result<()> {
        if group_id as usize >= MAX_GROUPS_PER_LEVEL {
            return Err(Error::InvalidArgument);
        }
        self.groups[0][group_id as usize].add_member(cpu)
    }

    /// Updates a CPU's timer expiry and propagates up.
    pub fn update_expiry(&mut self, cpu: u32, next_expiry: u64, nr_pending: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = cpu as usize;
        self.cpu_states[idx].next_expiry = next_expiry;
        self.cpu_states[idx].nr_pending = nr_pending;
        // Propagate through hierarchy.
        self.propagate_expiry(cpu)
    }

    /// Marks a CPU as going idle and migrates its timers.
    pub fn cpu_going_idle(&mut self, cpu: u32) -> Result<u32> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_states[cpu as usize].idle = true;
        // Find the core group and select a new migrator.
        let cg = self.cpu_states[cpu as usize].core_group;
        if (cg as usize) < MAX_GROUPS_PER_LEVEL && self.groups[0][cg as usize].in_use {
            self.groups[0][cg as usize].select_migrator(&self.cpu_states);
            self.groups[0][cg as usize].recalc_expiry(&self.cpu_states);
            return Ok(self.groups[0][cg as usize].migrator_cpu);
        }
        Err(Error::NotFound)
    }

    /// Marks a CPU as waking from idle.
    pub fn cpu_waking(&mut self, cpu: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_states[cpu as usize].idle = false;
        let cg = self.cpu_states[cpu as usize].core_group;
        if (cg as usize) < MAX_GROUPS_PER_LEVEL && self.groups[0][cg as usize].in_use {
            self.groups[0][cg as usize].select_migrator(&self.cpu_states);
        }
        Ok(())
    }

    /// Takes a CPU offline.
    pub fn cpu_offline(&mut self, cpu: u32) -> Result<()> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_states[cpu as usize].online = false;
        self.cpu_states[cpu as usize].idle = true;
        self.nr_online = self.nr_online.saturating_sub(1);
        self.propagate_expiry(cpu)
    }

    /// Propagates expiry changes up the hierarchy.
    fn propagate_expiry(&mut self, cpu: u32) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        // Update core group.
        let cg = self.cpu_states[idx].core_group as usize;
        if cg < MAX_GROUPS_PER_LEVEL && self.groups[0][cg].in_use {
            self.groups[0][cg].recalc_expiry(&self.cpu_states);
        }
        // Recalculate global.
        self.global_next_expiry = EXPIRY_NONE;
        for i in 0..self.nr_groups[0] {
            if self.groups[0][i].in_use {
                self.global_next_expiry =
                    self.global_next_expiry.min(self.groups[0][i].next_expiry);
            }
        }
        Ok(())
    }

    /// Returns the number of groups at a given level.
    pub fn nr_groups_at_level(&self, level: GroupLevel) -> usize {
        self.nr_groups[level.index()]
    }

    /// Returns a reference to a group.
    pub fn group(&self, level: GroupLevel, index: usize) -> Result<&TimerMigrationGroup> {
        let lvl = level.index();
        if index >= MAX_GROUPS_PER_LEVEL {
            return Err(Error::InvalidArgument);
        }
        if !self.groups[lvl][index].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.groups[lvl][index])
    }
}

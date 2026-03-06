// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Advanced memory hotplug subsystem with ACPI integration and
//! firmware-assisted hot-add/remove.
//!
//! Builds on top of the core [`hotplug`] module to provide:
//!
//! - [`HotplugPolicy`] — policy-based decisions for auto-online
//!   and zone selection
//! - [`MemorySection`] — fine-grained section tracking within blocks
//! - [`HotplugMigrationContext`] — coordinated page migration during
//!   offline operations
//! - [`AcpiMemoryDevice`] — ACPI memory device descriptor for
//!   firmware-initiated hot-add
//! - [`HotplugManager`] — orchestrates the full hotplug lifecycle
//!   with policy enforcement, migration, and ACPI integration
//! - [`HotplugEventLog`] — persistent event log for diagnostics
//!
//! Reference: Linux `mm/memory_hotplug.c`, `drivers/acpi/acpi_memhotplug.c`,
//! `admin-guide/mm/memory-hotplug.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Memory section size (128 MiB), matching Linux's `SECTION_SIZE_BITS = 27`.
const SECTION_SIZE: u64 = 128 * 1024 * 1024;

/// Maximum number of memory sections tracked.
const MAX_SECTIONS: usize = 256;

/// Maximum number of ACPI memory device descriptors.
const MAX_ACPI_DEVICES: usize = 32;

/// Maximum number of hotplug event log entries.
const MAX_EVENT_LOG: usize = 128;

/// Maximum number of migration retry attempts during offline.
const MAX_MIGRATION_RETRIES: u32 = 5;

/// Maximum number of pages tracked per migration context.
const MAX_MIGRATE_PAGES: usize = 64;

/// Maximum number of policy rules.
const MAX_POLICY_RULES: usize = 16;

/// Maximum number of node affinity overrides.
const MAX_NODE_OVERRIDES: usize = 8;

// -------------------------------------------------------------------
// HotplugPolicy
// -------------------------------------------------------------------

/// Policy controlling automatic onlining behaviour and zone selection.
///
/// When firmware or the administrator adds new memory, the policy
/// determines whether it should be automatically brought online and
/// which zone it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoOnlinePolicy {
    /// Do not auto-online; wait for explicit request.
    #[default]
    Manual,
    /// Auto-online to the Normal zone.
    OnlineNormal,
    /// Auto-online to the Movable zone (preferred for hotplug memory).
    OnlineMovable,
    /// Auto-online using a kernel heuristic based on existing layout.
    OnlineKernel,
}

/// Zone assignment preference for newly onlined memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZonePreference {
    /// Let the kernel decide based on existing zone layout.
    #[default]
    Auto,
    /// Force assignment to the Normal zone.
    ForceNormal,
    /// Force assignment to the Movable zone.
    ForceMovable,
    /// Force assignment to the DMA32 zone.
    ForceDma32,
}

/// A single policy rule that matches an address range.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyRule {
    /// Start of the physical address range this rule matches.
    pub range_start: u64,
    /// End of the physical address range (exclusive).
    pub range_end: u64,
    /// Auto-online policy for matching memory.
    pub auto_online: AutoOnlinePolicy,
    /// Zone preference for matching memory.
    pub zone_pref: ZonePreference,
    /// Whether this rule slot is active.
    pub active: bool,
}

/// Node-specific affinity override for hotplugged memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeAffinityOverride {
    /// NUMA node ID this override applies to.
    pub node_id: u32,
    /// Preferred zone for memory on this node.
    pub zone_pref: ZonePreference,
    /// Whether auto-online is enabled for this node.
    pub auto_online: bool,
    /// Whether this override slot is active.
    pub active: bool,
}

/// Hotplug policy engine.
#[derive(Debug)]
pub struct HotplugPolicy {
    /// Default auto-online policy when no rule matches.
    pub default_auto_online: AutoOnlinePolicy,
    /// Default zone preference when no rule matches.
    pub default_zone: ZonePreference,
    /// Address-range-based policy rules.
    rules: [PolicyRule; MAX_POLICY_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// Per-node affinity overrides.
    node_overrides: [NodeAffinityOverride; MAX_NODE_OVERRIDES],
    /// Number of active node overrides.
    node_override_count: usize,
}

impl Default for HotplugPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugPolicy {
    /// Creates a new policy with defaults (manual online, auto zone).
    pub const fn new() -> Self {
        Self {
            default_auto_online: AutoOnlinePolicy::Manual,
            default_zone: ZonePreference::Auto,
            rules: [PolicyRule {
                range_start: 0,
                range_end: 0,
                auto_online: AutoOnlinePolicy::Manual,
                zone_pref: ZonePreference::Auto,
                active: false,
            }; MAX_POLICY_RULES],
            rule_count: 0,
            node_overrides: [NodeAffinityOverride {
                node_id: 0,
                zone_pref: ZonePreference::Auto,
                auto_online: false,
                active: false,
            }; MAX_NODE_OVERRIDES],
            node_override_count: 0,
        }
    }

    /// Adds a policy rule for an address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the rule table is full.
    /// Returns [`Error::InvalidArgument`] if `range_start >= range_end`.
    pub fn add_rule(
        &mut self,
        range_start: u64,
        range_end: u64,
        auto_online: AutoOnlinePolicy,
        zone_pref: ZonePreference,
    ) -> Result<()> {
        if range_start >= range_end {
            return Err(Error::InvalidArgument);
        }
        if self.rule_count >= MAX_POLICY_RULES {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .rules
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = PolicyRule {
            range_start,
            range_end,
            auto_online,
            zone_pref,
            active: true,
        };
        self.rule_count += 1;
        Ok(())
    }

    /// Removes a policy rule matching the given address range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching rule exists.
    pub fn remove_rule(&mut self, range_start: u64, range_end: u64) -> Result<()> {
        let slot = self
            .rules
            .iter_mut()
            .find(|r| r.active && r.range_start == range_start && r.range_end == range_end)
            .ok_or(Error::NotFound)?;
        slot.active = false;
        self.rule_count = self.rule_count.saturating_sub(1);
        Ok(())
    }

    /// Adds a per-node affinity override.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the override table is full.
    pub fn add_node_override(
        &mut self,
        node_id: u32,
        zone_pref: ZonePreference,
        auto_online: bool,
    ) -> Result<()> {
        if self.node_override_count >= MAX_NODE_OVERRIDES {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .node_overrides
            .iter_mut()
            .find(|o| !o.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = NodeAffinityOverride {
            node_id,
            zone_pref,
            auto_online,
            active: true,
        };
        self.node_override_count += 1;
        Ok(())
    }

    /// Evaluates the policy for a given physical address and NUMA node.
    ///
    /// Returns the auto-online policy and zone preference.
    pub fn evaluate(&self, phys_addr: u64, node_id: u32) -> (AutoOnlinePolicy, ZonePreference) {
        // Check address-range rules first (most specific).
        for i in 0..MAX_POLICY_RULES {
            let r = &self.rules[i];
            if r.active && phys_addr >= r.range_start && phys_addr < r.range_end {
                return (r.auto_online, r.zone_pref);
            }
        }
        // Check per-node overrides.
        for i in 0..MAX_NODE_OVERRIDES {
            let o = &self.node_overrides[i];
            if o.active && o.node_id == node_id {
                let ao = if o.auto_online {
                    AutoOnlinePolicy::OnlineMovable
                } else {
                    AutoOnlinePolicy::Manual
                };
                return (ao, o.zone_pref);
            }
        }
        (self.default_auto_online, self.default_zone)
    }
}

// -------------------------------------------------------------------
// MemorySectionState
// -------------------------------------------------------------------

/// State of a memory section within a hotplug block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SectionState {
    /// Section is not present (no physical memory backing).
    #[default]
    NotPresent,
    /// Section is present but offline.
    Offline,
    /// Section is online and available for allocation.
    Online,
    /// Section is being migrated (pages being moved out).
    Migrating,
    /// Section encountered a hardware error.
    HwError,
}

// -------------------------------------------------------------------
// MemorySection
// -------------------------------------------------------------------

/// Fine-grained tracking of a 128 MiB memory section.
///
/// Memory blocks are divided into sections for finer granularity in
/// online/offline operations and error tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemorySection {
    /// Section index (unique within the system).
    pub section_id: u32,
    /// Base physical address of this section.
    pub phys_start: u64,
    /// Size in bytes (normally [`SECTION_SIZE`]).
    pub size_bytes: u64,
    /// Current state of this section.
    pub state: SectionState,
    /// NUMA node this section belongs to.
    pub node_id: u32,
    /// Number of allocated pages in this section.
    pub allocated_pages: u32,
    /// Number of free pages in this section.
    pub free_pages: u32,
    /// Whether pages in this section can be migrated.
    pub migratable: bool,
    /// Number of hardware errors detected.
    pub error_count: u32,
}

impl MemorySection {
    /// Creates a new section descriptor.
    pub const fn new(section_id: u32, phys_start: u64, node_id: u32) -> Self {
        let total_pages = (SECTION_SIZE / PAGE_SIZE) as u32;
        Self {
            section_id,
            phys_start,
            size_bytes: SECTION_SIZE,
            state: SectionState::Offline,
            node_id,
            allocated_pages: 0,
            free_pages: total_pages,
            migratable: true,
            error_count: 0,
        }
    }

    /// Returns the number of total pages in this section.
    pub fn total_pages(&self) -> u32 {
        (self.size_bytes / PAGE_SIZE) as u32
    }

    /// Returns the utilisation ratio (0..=100).
    pub fn utilisation_pct(&self) -> u32 {
        let total = self.total_pages();
        if total == 0 {
            return 0;
        }
        (self.allocated_pages as u64 * 100 / total as u64) as u32
    }
}

// -------------------------------------------------------------------
// AcpiMemoryDevice
// -------------------------------------------------------------------

/// ACPI memory device descriptor (_HID PNP0C80).
///
/// Represents a memory device reported by ACPI firmware. The OS uses
/// these descriptors to discover hotplug-capable memory regions.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiMemoryDevice {
    /// ACPI handle identifier.
    pub handle: u64,
    /// Base physical address reported by firmware.
    pub phys_start: u64,
    /// Size in bytes.
    pub size_bytes: u64,
    /// NUMA proximity domain from SRAT.
    pub proximity_domain: u32,
    /// Whether this device is currently enabled.
    pub enabled: bool,
    /// Whether online was requested by firmware (_STA).
    pub online_requested: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

// -------------------------------------------------------------------
// HotplugMigrationContext
// -------------------------------------------------------------------

/// Tracks pages being migrated during an offline operation.
///
/// Before a section can be taken offline, all allocated pages must
/// be moved to another online section. This context coordinates
/// that migration.
#[derive(Debug, Clone, Copy)]
pub struct MigrationPage {
    /// Source physical address.
    pub src_phys: u64,
    /// Destination physical address (0 = not yet assigned).
    pub dst_phys: u64,
    /// Process ID that maps this page (0 = kernel page).
    pub owner_pid: u64,
    /// Whether migration completed for this page.
    pub migrated: bool,
    /// Whether this page is pinned (unmovable).
    pub pinned: bool,
}

impl Default for MigrationPage {
    fn default() -> Self {
        Self {
            src_phys: 0,
            dst_phys: 0,
            owner_pid: 0,
            migrated: false,
            pinned: false,
        }
    }
}

/// Migration context for a section offline operation.
#[derive(Debug)]
pub struct HotplugMigrationContext {
    /// Section being offlined.
    pub section_id: u32,
    /// Pages being migrated.
    pages: [MigrationPage; MAX_MIGRATE_PAGES],
    /// Number of pages to migrate.
    page_count: usize,
    /// Number of pages successfully migrated.
    migrated_count: usize,
    /// Number of pinned (unmovable) pages encountered.
    pinned_count: usize,
    /// Current retry attempt.
    retry: u32,
    /// Whether migration is complete (success or exhausted retries).
    complete: bool,
}

impl Default for HotplugMigrationContext {
    fn default() -> Self {
        Self::new(0)
    }
}

impl HotplugMigrationContext {
    /// Creates a new migration context for the given section.
    pub const fn new(section_id: u32) -> Self {
        Self {
            section_id,
            pages: [MigrationPage {
                src_phys: 0,
                dst_phys: 0,
                owner_pid: 0,
                migrated: false,
                pinned: false,
            }; MAX_MIGRATE_PAGES],
            page_count: 0,
            migrated_count: 0,
            pinned_count: 0,
            retry: 0,
            complete: false,
        }
    }

    /// Adds a page to the migration list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the migration page list is full.
    pub fn add_page(&mut self, src_phys: u64, owner_pid: u64, pinned: bool) -> Result<()> {
        if self.page_count >= MAX_MIGRATE_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.page_count] = MigrationPage {
            src_phys,
            dst_phys: 0,
            owner_pid,
            migrated: false,
            pinned,
        };
        if pinned {
            self.pinned_count += 1;
        }
        self.page_count += 1;
        Ok(())
    }

    /// Assigns a destination address for a source page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `src_phys` is not in the list.
    pub fn assign_destination(&mut self, src_phys: u64, dst_phys: u64) -> Result<()> {
        for i in 0..self.page_count {
            if self.pages[i].src_phys == src_phys && !self.pages[i].pinned {
                self.pages[i].dst_phys = dst_phys;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Marks a page as successfully migrated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `src_phys` is not in the list.
    pub fn mark_migrated(&mut self, src_phys: u64) -> Result<()> {
        for i in 0..self.page_count {
            if self.pages[i].src_phys == src_phys && !self.pages[i].migrated {
                self.pages[i].migrated = true;
                self.migrated_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Runs one migration step, attempting to migrate all un-migrated,
    /// non-pinned pages. Returns the number of pages migrated in this
    /// step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if pinned pages prevent completion and
    /// retries are exhausted.
    pub fn run_step(&mut self) -> Result<usize> {
        if self.complete {
            return Ok(0);
        }

        let mut migrated_this_step = 0_usize;

        for i in 0..self.page_count {
            if self.pages[i].migrated || self.pages[i].pinned {
                continue;
            }
            if self.pages[i].dst_phys == 0 {
                continue;
            }
            // Simulate successful migration.
            self.pages[i].migrated = true;
            self.migrated_count += 1;
            migrated_this_step += 1;
        }

        // Check completion.
        let movable = self.page_count - self.pinned_count;
        if self.migrated_count >= movable {
            self.complete = true;
        } else {
            self.retry += 1;
            if self.retry >= MAX_MIGRATION_RETRIES {
                self.complete = true;
                if self.pinned_count > 0 {
                    return Err(Error::Busy);
                }
            }
        }

        Ok(migrated_this_step)
    }

    /// Returns `true` if migration is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Returns the number of pages successfully migrated.
    pub fn migrated_count(&self) -> usize {
        self.migrated_count
    }

    /// Returns the number of pinned pages that could not be migrated.
    pub fn pinned_count(&self) -> usize {
        self.pinned_count
    }

    /// Returns the total number of pages in the migration context.
    pub fn total_pages(&self) -> usize {
        self.page_count
    }
}

// -------------------------------------------------------------------
// HotplugEventType / HotplugEventEntry
// -------------------------------------------------------------------

/// Type of hotplug event recorded in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugEventType {
    /// Memory added (ACPI or manual).
    #[default]
    Add,
    /// Memory removed.
    Remove,
    /// Section brought online.
    Online,
    /// Section taken offline.
    Offline,
    /// Migration started for offline.
    MigrationStart,
    /// Migration completed.
    MigrationDone,
    /// Migration failed (pinned pages).
    MigrationFailed,
    /// Hardware error detected on section.
    HwError,
    /// Policy rule change.
    PolicyChange,
}

/// A single hotplug event log entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct HotplugEventEntry {
    /// Monotonic timestamp (tick count or similar).
    pub timestamp: u64,
    /// Event type.
    pub event_type: HotplugEventType,
    /// Section or block identifier related to the event.
    pub section_id: u32,
    /// Physical address associated with the event.
    pub phys_addr: u64,
    /// Additional context (e.g. node ID, error code).
    pub detail: u64,
    /// Whether this log slot is in use.
    pub in_use: bool,
}

/// Ring-buffer event log for hotplug diagnostics.
#[derive(Debug)]
pub struct HotplugEventLog {
    /// Log entries in ring-buffer order.
    entries: [HotplugEventEntry; MAX_EVENT_LOG],
    /// Write cursor (wraps around).
    write_pos: usize,
    /// Total number of events recorded (may exceed buffer size).
    total_events: u64,
}

impl Default for HotplugEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugEventLog {
    /// Creates an empty event log.
    pub const fn new() -> Self {
        Self {
            entries: [HotplugEventEntry {
                timestamp: 0,
                event_type: HotplugEventType::Add,
                section_id: 0,
                phys_addr: 0,
                detail: 0,
                in_use: false,
            }; MAX_EVENT_LOG],
            write_pos: 0,
            total_events: 0,
        }
    }

    /// Records an event in the ring buffer.
    pub fn record(
        &mut self,
        timestamp: u64,
        event_type: HotplugEventType,
        section_id: u32,
        phys_addr: u64,
        detail: u64,
    ) {
        self.entries[self.write_pos] = HotplugEventEntry {
            timestamp,
            event_type,
            section_id,
            phys_addr,
            detail,
            in_use: true,
        };
        self.write_pos = (self.write_pos + 1) % MAX_EVENT_LOG;
        self.total_events += 1;
    }

    /// Returns the most recent `count` events (newest first).
    ///
    /// The returned slice length is `min(count, total_events, MAX_EVENT_LOG)`.
    pub fn recent(&self, count: usize) -> &[HotplugEventEntry] {
        let available = core::cmp::min(
            count,
            core::cmp::min(self.total_events as usize, MAX_EVENT_LOG),
        );
        if available == 0 {
            return &[];
        }
        // Return a contiguous slice from the most recent entries.
        let start = if self.write_pos >= available {
            self.write_pos - available
        } else {
            0
        };
        let end = core::cmp::min(start + available, MAX_EVENT_LOG);
        &self.entries[start..end]
    }

    /// Total number of events recorded (including overwritten).
    pub fn total_events(&self) -> u64 {
        self.total_events
    }
}

// -------------------------------------------------------------------
// HotplugStats
// -------------------------------------------------------------------

/// Aggregate hotplug statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HotplugStats {
    /// Total sections currently online.
    pub sections_online: u32,
    /// Total sections currently offline.
    pub sections_offline: u32,
    /// Total bytes of online memory.
    pub online_bytes: u64,
    /// Total bytes of offline memory.
    pub offline_bytes: u64,
    /// Number of successful online operations.
    pub online_ops: u64,
    /// Number of successful offline operations.
    pub offline_ops: u64,
    /// Number of failed offline operations.
    pub offline_failures: u64,
    /// Total pages migrated during offline operations.
    pub pages_migrated: u64,
    /// Number of ACPI hot-add events.
    pub acpi_add_events: u64,
    /// Number of ACPI hot-remove events.
    pub acpi_remove_events: u64,
}

// -------------------------------------------------------------------
// HotplugManager
// -------------------------------------------------------------------

/// Advanced memory hotplug manager with ACPI integration.
///
/// Coordinates the full lifecycle of hotplugged memory: firmware
/// discovery via ACPI, section-granularity online/offline, policy
/// enforcement, and coordinated page migration for safe removal.
pub struct HotplugManager {
    /// Memory sections tracked by the manager.
    sections: [MemorySection; MAX_SECTIONS],
    /// Number of registered sections.
    section_count: usize,
    /// Next section ID to assign.
    next_section_id: u32,
    /// ACPI memory device descriptors.
    acpi_devices: [AcpiMemoryDevice; MAX_ACPI_DEVICES],
    /// Number of registered ACPI devices.
    acpi_count: usize,
    /// Hotplug policy engine.
    policy: HotplugPolicy,
    /// Active migration context (one at a time).
    migration: HotplugMigrationContext,
    /// Whether a migration is in progress.
    migration_active: bool,
    /// Event log.
    event_log: HotplugEventLog,
    /// Aggregate statistics.
    stats: HotplugStats,
    /// Monotonic timestamp counter.
    tick: u64,
}

impl Default for HotplugManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugManager {
    /// Creates a new hotplug manager with empty state.
    pub const fn new() -> Self {
        Self {
            sections: [MemorySection {
                section_id: 0,
                phys_start: 0,
                size_bytes: 0,
                state: SectionState::NotPresent,
                node_id: 0,
                allocated_pages: 0,
                free_pages: 0,
                migratable: true,
                error_count: 0,
            }; MAX_SECTIONS],
            section_count: 0,
            next_section_id: 1,
            acpi_devices: [AcpiMemoryDevice {
                handle: 0,
                phys_start: 0,
                size_bytes: 0,
                proximity_domain: 0,
                enabled: false,
                online_requested: false,
                in_use: false,
            }; MAX_ACPI_DEVICES],
            acpi_count: 0,
            policy: HotplugPolicy::new(),
            migration: HotplugMigrationContext::new(0),
            migration_active: false,
            event_log: HotplugEventLog::new(),
            stats: HotplugStats {
                sections_online: 0,
                sections_offline: 0,
                online_bytes: 0,
                offline_bytes: 0,
                online_ops: 0,
                offline_ops: 0,
                offline_failures: 0,
                pages_migrated: 0,
                acpi_add_events: 0,
                acpi_remove_events: 0,
            },
            tick: 0,
        }
    }

    /// Advances the internal tick counter and returns the new value.
    fn advance_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Registers an ACPI memory device discovered by firmware.
    ///
    /// If the device's address range falls under an auto-online policy,
    /// sections are created and optionally brought online automatically.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the ACPI device table or
    /// section table is full.
    /// Returns [`Error::InvalidArgument`] if `size_bytes` is zero.
    pub fn acpi_add_device(
        &mut self,
        handle: u64,
        phys_start: u64,
        size_bytes: u64,
        proximity_domain: u32,
    ) -> Result<u32> {
        if size_bytes == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.acpi_count >= MAX_ACPI_DEVICES {
            return Err(Error::OutOfMemory);
        }

        // Register ACPI device.
        let slot = self
            .acpi_devices
            .iter_mut()
            .find(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;
        *slot = AcpiMemoryDevice {
            handle,
            phys_start,
            size_bytes,
            proximity_domain,
            enabled: true,
            online_requested: false,
            in_use: true,
        };
        self.acpi_count += 1;
        self.stats.acpi_add_events += 1;

        // Create sections for this device.
        let section_count = ((size_bytes + SECTION_SIZE - 1) / SECTION_SIZE) as u32;
        let mut first_id = 0_u32;

        for i in 0..section_count {
            let addr = phys_start + (i as u64) * SECTION_SIZE;
            let id = self.add_section(addr, proximity_domain)?;
            if i == 0 {
                first_id = id;
            }

            // Check auto-online policy.
            let (auto_policy, _zone_pref) = self.policy.evaluate(addr, proximity_domain);
            if auto_policy != AutoOnlinePolicy::Manual {
                let _ = self.online_section(id);
            }
        }

        let ts = self.advance_tick();
        self.event_log
            .record(ts, HotplugEventType::Add, first_id, phys_start, size_bytes);

        Ok(first_id)
    }

    /// Removes an ACPI memory device and its associated sections.
    ///
    /// All sections must be offline before removal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not registered.
    /// Returns [`Error::Busy`] if any section is still online.
    pub fn acpi_remove_device(&mut self, handle: u64) -> Result<()> {
        let device_idx = self
            .acpi_devices
            .iter()
            .position(|d| d.in_use && d.handle == handle)
            .ok_or(Error::NotFound)?;

        let phys_start = self.acpi_devices[device_idx].phys_start;
        let size_bytes = self.acpi_devices[device_idx].size_bytes;
        let end = phys_start.saturating_add(size_bytes);

        // Verify all sections in this range are offline.
        for i in 0..MAX_SECTIONS {
            let s = &self.sections[i];
            if s.state != SectionState::NotPresent
                && s.phys_start >= phys_start
                && s.phys_start < end
                && s.state == SectionState::Online
            {
                return Err(Error::Busy);
            }
        }

        // Remove sections in this range.
        for i in 0..MAX_SECTIONS {
            let s = &self.sections[i];
            if s.state != SectionState::NotPresent
                && s.phys_start >= phys_start
                && s.phys_start < end
            {
                let size = self.sections[i].size_bytes;
                self.sections[i] = MemorySection::default();
                self.sections[i].state = SectionState::NotPresent;
                self.section_count = self.section_count.saturating_sub(1);
                self.stats.sections_offline = self.stats.sections_offline.saturating_sub(1);
                self.stats.offline_bytes = self.stats.offline_bytes.saturating_sub(size);
            }
        }

        // Remove ACPI device.
        self.acpi_devices[device_idx] = AcpiMemoryDevice::default();
        self.acpi_count = self.acpi_count.saturating_sub(1);
        self.stats.acpi_remove_events += 1;

        let ts = self.advance_tick();
        self.event_log
            .record(ts, HotplugEventType::Remove, 0, phys_start, size_bytes);

        Ok(())
    }

    /// Adds a memory section.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the section table is full.
    pub fn add_section(&mut self, phys_start: u64, node_id: u32) -> Result<u32> {
        if self.section_count >= MAX_SECTIONS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_section_id;
        let section = MemorySection::new(id, phys_start, node_id);

        let slot = self
            .sections
            .iter_mut()
            .find(|s| s.state == SectionState::NotPresent && s.section_id == 0)
            .ok_or(Error::OutOfMemory)?;
        *slot = section;

        self.section_count += 1;
        self.next_section_id = self.next_section_id.wrapping_add(1);
        self.stats.sections_offline += 1;
        self.stats.offline_bytes = self.stats.offline_bytes.saturating_add(SECTION_SIZE);
        Ok(id)
    }

    /// Brings a section online.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the section does not exist.
    /// Returns [`Error::InvalidArgument`] if the section is not offline.
    pub fn online_section(&mut self, section_id: u32) -> Result<()> {
        let section = self
            .sections
            .iter_mut()
            .find(|s| s.section_id == section_id && s.state != SectionState::NotPresent)
            .ok_or(Error::NotFound)?;

        if section.state != SectionState::Offline {
            return Err(Error::InvalidArgument);
        }

        let size = section.size_bytes;
        section.state = SectionState::Online;

        self.stats.sections_online += 1;
        self.stats.sections_offline = self.stats.sections_offline.saturating_sub(1);
        self.stats.online_bytes = self.stats.online_bytes.saturating_add(size);
        self.stats.offline_bytes = self.stats.offline_bytes.saturating_sub(size);
        self.stats.online_ops += 1;

        let ts = self.advance_tick();
        self.event_log
            .record(ts, HotplugEventType::Online, section_id, 0, size);

        Ok(())
    }

    /// Initiates an offline operation for a section.
    ///
    /// If the section has allocated pages, a migration context is
    /// created. The caller must drive the migration with
    /// [`drive_migration`](Self::drive_migration) before the section
    /// can fully go offline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the section does not exist.
    /// Returns [`Error::InvalidArgument`] if not online.
    /// Returns [`Error::Busy`] if another migration is already active.
    pub fn offline_section(&mut self, section_id: u32) -> Result<bool> {
        if self.migration_active {
            return Err(Error::Busy);
        }

        let idx = self
            .sections
            .iter()
            .position(|s| s.section_id == section_id && s.state != SectionState::NotPresent)
            .ok_or(Error::NotFound)?;

        if self.sections[idx].state != SectionState::Online {
            return Err(Error::InvalidArgument);
        }

        if self.sections[idx].allocated_pages > 0 {
            // Need migration first.
            self.sections[idx].state = SectionState::Migrating;
            self.migration = HotplugMigrationContext::new(section_id);
            self.migration_active = true;

            let ts = self.advance_tick();
            self.event_log.record(
                ts,
                HotplugEventType::MigrationStart,
                section_id,
                self.sections[idx].phys_start,
                self.sections[idx].allocated_pages as u64,
            );

            return Ok(false); // Not yet offline; migration needed.
        }

        // No allocated pages — go directly offline.
        self.complete_offline(idx);
        Ok(true)
    }

    /// Drives the active migration context forward by one step.
    ///
    /// Returns the number of pages migrated in this step. When
    /// migration completes, the section transitions to Offline.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no migration is active.
    /// Returns [`Error::Busy`] if pinned pages prevent completion.
    pub fn drive_migration(&mut self) -> Result<usize> {
        if !self.migration_active {
            return Err(Error::InvalidArgument);
        }

        let result = self.migration.run_step();

        if self.migration.is_complete() {
            let section_id = self.migration.section_id;
            let migrated = self.migration.migrated_count();
            self.stats.pages_migrated += migrated as u64;

            let idx = self
                .sections
                .iter()
                .position(|s| s.section_id == section_id);

            if let Some(idx) = idx {
                if self.migration.pinned_count() > 0 {
                    // Failed — revert to online.
                    self.sections[idx].state = SectionState::Online;
                    self.stats.offline_failures += 1;

                    let ts = self.advance_tick();
                    self.event_log.record(
                        ts,
                        HotplugEventType::MigrationFailed,
                        section_id,
                        0,
                        self.migration.pinned_count() as u64,
                    );
                } else {
                    // Success — complete offline.
                    self.complete_offline(idx);

                    let ts = self.advance_tick();
                    self.event_log.record(
                        ts,
                        HotplugEventType::MigrationDone,
                        section_id,
                        0,
                        migrated as u64,
                    );
                }
            }

            self.migration_active = false;
        }

        result
    }

    /// Completes the offline transition for a section at the given
    /// index.
    fn complete_offline(&mut self, idx: usize) {
        let size = self.sections[idx].size_bytes;
        let section_id = self.sections[idx].section_id;
        self.sections[idx].state = SectionState::Offline;
        self.sections[idx].allocated_pages = 0;

        self.stats.sections_online = self.stats.sections_online.saturating_sub(1);
        self.stats.sections_offline += 1;
        self.stats.online_bytes = self.stats.online_bytes.saturating_sub(size);
        self.stats.offline_bytes = self.stats.offline_bytes.saturating_add(size);
        self.stats.offline_ops += 1;

        let ts = self.advance_tick();
        self.event_log
            .record(ts, HotplugEventType::Offline, section_id, 0, size);
    }

    /// Reports a hardware error on a section.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the section does not exist.
    pub fn report_hw_error(&mut self, section_id: u32) -> Result<()> {
        let idx = self
            .sections
            .iter()
            .position(|s| s.section_id == section_id && s.state != SectionState::NotPresent)
            .ok_or(Error::NotFound)?;

        self.sections[idx].error_count += 1;
        self.sections[idx].state = SectionState::HwError;
        let phys = self.sections[idx].phys_start;
        let err_count = self.sections[idx].error_count as u64;

        let ts = self.advance_tick();
        self.event_log
            .record(ts, HotplugEventType::HwError, section_id, phys, err_count);

        Ok(())
    }

    /// Updates the page allocation count for a section.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the section does not exist.
    /// Returns [`Error::InvalidArgument`] if `count` exceeds total.
    pub fn set_allocated_pages(&mut self, section_id: u32, count: u32) -> Result<()> {
        let section = self
            .sections
            .iter_mut()
            .find(|s| s.section_id == section_id && s.state != SectionState::NotPresent)
            .ok_or(Error::NotFound)?;

        let total = section.total_pages();
        if count > total {
            return Err(Error::InvalidArgument);
        }
        section.allocated_pages = count;
        section.free_pages = total - count;
        Ok(())
    }

    /// Looks up a section by its identifier.
    pub fn get_section(&self, section_id: u32) -> Option<&MemorySection> {
        self.sections
            .iter()
            .find(|s| s.section_id == section_id && s.state != SectionState::NotPresent)
    }

    /// Returns a mutable reference to the policy engine.
    pub fn policy_mut(&mut self) -> &mut HotplugPolicy {
        &mut self.policy
    }

    /// Returns a reference to the policy engine.
    pub fn policy(&self) -> &HotplugPolicy {
        &self.policy
    }

    /// Returns a reference to the event log.
    pub fn event_log(&self) -> &HotplugEventLog {
        &self.event_log
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &HotplugStats {
        &self.stats
    }

    /// Returns a reference to the active migration context.
    ///
    /// Returns `None` if no migration is in progress.
    pub fn migration_context(&self) -> Option<&HotplugMigrationContext> {
        if self.migration_active {
            Some(&self.migration)
        } else {
            None
        }
    }

    /// Number of registered sections.
    pub fn section_count(&self) -> usize {
        self.section_count
    }

    /// Returns `true` if no sections are registered.
    pub fn is_empty(&self) -> bool {
        self.section_count == 0
    }
}

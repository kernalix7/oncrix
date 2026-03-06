// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory hotplug (online/offline) subsystem.
//!
//! Provides runtime addition and removal of physical memory blocks. A
//! memory block is the granule at which hotplug operates — typically 128 MiB
//! on x86_64, though configurable here via [`BLOCK_SIZE_BYTES`].
//!
//! # Lifecycle
//!
//! Memory blocks move through the following states:
//!
//! ```text
//!                       add_memory()
//!  [absent] ──────────────────────────► [offline]
//!              online_memory()                     remove_memory()
//!  [offline] ◄─────────────────────── [online] ◄─────────── [absent]
//!                                        │
//!                     GoingOffline / GoingOnline transient states
//! ```
//!
//! Registered notifiers are called at each state transition, allowing
//! subsystems (NUMA, slab, scheduler) to adjust their per-node data
//! structures accordingly.
//!
//! # Types
//!
//! - [`HotplugState`] — block lifecycle state
//! - [`HotplugZone`] — zone for the block when onlined
//! - [`HotplugNotifyEvent`] — event passed to notifier callbacks
//! - [`HotplugResult`] — outcome of a hotplug operation
//! - [`MemoryBlock`] — a single hotpluggable block descriptor
//! - [`HotplugStats`] — aggregate operation counters
//! - [`MemoryHotplug`] — the hotplug subsystem
//!
//! Reference: Linux `mm/memory_hotplug.c`, `mm/memory_hotremove.c`,
//! `admin-guide/mm/memory-hotplug.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Size of one hotpluggable memory block (128 MiB).
pub const BLOCK_SIZE_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum number of memory blocks the subsystem tracks.
const MAX_BLOCKS: usize = 256;

/// Maximum number of registered hotplug notifiers.
const MAX_NOTIFIERS: usize = 32;

/// Maximum number of events in the event log.
const MAX_EVENT_LOG: usize = 128;

// -------------------------------------------------------------------
// HotplugState
// -------------------------------------------------------------------

/// Lifecycle state of a memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugState {
    /// Block is absent — not present in the system.
    Absent,
    /// Block is offline — present but not available for allocation.
    #[default]
    Offline,
    /// Block is transitioning from offline to online (transient).
    GoingOnline,
    /// Block is online — pages are managed by the allocator.
    Online,
    /// Block is transitioning from online to offline (transient).
    GoingOffline,
    /// Block is being removed (transient).
    GoingAbsent,
}

// -------------------------------------------------------------------
// HotplugZone
// -------------------------------------------------------------------

/// Destination zone for a memory block being onlined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugZone {
    /// Normal zone — general-purpose memory.
    #[default]
    Normal,
    /// Movable zone — pages can be migrated/compacted.
    Movable,
    /// DMA32 zone — reachable by 32-bit DMA engines.
    Dma32,
}

// -------------------------------------------------------------------
// HotplugNotifyEvent
// -------------------------------------------------------------------

/// Event delivered to hotplug notifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugNotifyEvent {
    /// A block is being added (transitions Absent → Offline).
    AddMemory,
    /// A block is about to go online.
    OnlinePrepare,
    /// A block has gone online.
    Online,
    /// A block is about to go offline.
    OfflinePrepare,
    /// A block has gone offline.
    Offline,
    /// A block is about to be removed.
    RemovePrepare,
    /// A block has been removed (transitions Offline → Absent).
    RemoveMemory,
}

// -------------------------------------------------------------------
// HotplugResult
// -------------------------------------------------------------------

/// Result of a hotplug operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugResult {
    /// Operation completed successfully.
    #[default]
    Success,
    /// A notifier vetoed the operation.
    Vetoed,
    /// Block had in-use pages that could not be migrated.
    PagesBusy,
    /// Internal subsystem error.
    InternalError,
}

// -------------------------------------------------------------------
// HotplugNotifier (function pointer wrapper)
// -------------------------------------------------------------------

/// A registered hotplug event notifier.
///
/// `callback` is invoked with the relevant event and block descriptor.
/// Returning `false` from `prepare` events vetoes the operation.
#[derive(Clone, Copy)]
pub struct HotplugNotifier {
    /// Unique identifier for this notifier.
    pub id: u32,
    /// Priority — lower values fire first.
    pub priority: u32,
    /// Whether the notifier is active.
    pub active: bool,
}

impl HotplugNotifier {
    /// Creates a new notifier descriptor.
    pub const fn new(id: u32, priority: u32) -> Self {
        Self {
            id,
            priority,
            active: true,
        }
    }
}

// -------------------------------------------------------------------
// MemoryBlock
// -------------------------------------------------------------------

/// Descriptor for one hotpluggable memory block.
///
/// Each block covers `BLOCK_SIZE_BYTES` of physical address space
/// starting at `base_addr`.
#[derive(Debug, Clone, Default)]
pub struct MemoryBlock {
    /// Block index (block N covers `N * BLOCK_SIZE_BYTES`).
    pub index: u32,
    /// Physical base address of the block.
    pub base_addr: u64,
    /// NUMA node this block belongs to.
    pub node: u32,
    /// Current lifecycle state.
    pub state: HotplugState,
    /// Zone this block was (or will be) onlined into.
    pub zone: HotplugZone,
    /// Number of pages in this block.
    pub page_count: u64,
    /// Number of pages currently free within the block.
    pub free_pages: u64,
    /// Whether the block is tracked by the subsystem (slot in use).
    pub present: bool,
}

impl MemoryBlock {
    /// Creates a new block descriptor.
    pub const fn new(index: u32, base_addr: u64, node: u32) -> Self {
        Self {
            index,
            base_addr,
            node,
            state: HotplugState::Offline,
            zone: HotplugZone::Normal,
            page_count: BLOCK_SIZE_BYTES / 4096,
            free_pages: BLOCK_SIZE_BYTES / 4096,
            present: false,
        }
    }
}

// -------------------------------------------------------------------
// HotplugEvent (internal log)
// -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct HotplugEventLog {
    tick: u64,
    block_index: u32,
    event: Option<HotplugNotifyEvent>,
    result: HotplugResult,
}

// -------------------------------------------------------------------
// HotplugStats
// -------------------------------------------------------------------

/// Aggregate hotplug operation counters.
#[derive(Debug, Default, Clone, Copy)]
pub struct HotplugStats {
    /// Total add_memory() calls.
    pub adds: u64,
    /// Total remove_memory() calls.
    pub removes: u64,
    /// Total online_memory() calls.
    pub onlines: u64,
    /// Total offline_memory() calls.
    pub offlines: u64,
    /// Operations vetoed by a notifier.
    pub vetoes: u64,
    /// Operations that failed due to busy pages.
    pub pages_busy_failures: u64,
}

// -------------------------------------------------------------------
// MemoryHotplug
// -------------------------------------------------------------------

/// The memory hotplug subsystem.
///
/// Manages up to [`MAX_BLOCKS`] memory blocks and up to
/// [`MAX_NOTIFIERS`] registered event notifiers.
pub struct MemoryHotplug {
    blocks: [MemoryBlock; MAX_BLOCKS],
    block_count: usize,
    notifiers: [Option<HotplugNotifier>; MAX_NOTIFIERS],
    notifier_count: usize,
    event_log: [HotplugEventLog; MAX_EVENT_LOG],
    event_log_write: usize,
    event_log_count: usize,
    clock: u64,
    stats: HotplugStats,
}

impl MemoryHotplug {
    /// Creates an empty hotplug subsystem.
    pub fn new() -> Self {
        Self {
            blocks: core::array::from_fn(|_| MemoryBlock::default()),
            block_count: 0,
            notifiers: [const { None }; MAX_NOTIFIERS],
            notifier_count: 0,
            event_log: [const {
                HotplugEventLog {
                    tick: 0,
                    block_index: 0,
                    event: None,
                    result: HotplugResult::Success,
                }
            }; MAX_EVENT_LOG],
            event_log_write: 0,
            event_log_count: 0,
            clock: 0,
            stats: HotplugStats::default(),
        }
    }

    /// Ticks the internal clock.
    pub fn tick(&mut self) {
        self.clock = self.clock.wrapping_add(1);
    }

    // --- notifier management ---

    /// Registers a hotplug notifier.
    ///
    /// Notifiers with lower `priority` values are called first.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` — the notifier table is full.
    /// - `AlreadyExists` — a notifier with the same `id` is already registered.
    pub fn register_notifier(&mut self, id: u32, priority: u32) -> Result<()> {
        for slot in self.notifiers.iter() {
            if let Some(n) = slot {
                if n.id == id {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.notifiers.iter_mut() {
            if slot.is_none() {
                *slot = Some(HotplugNotifier::new(id, priority));
                self.notifier_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a hotplug notifier by `id`.
    pub fn unregister_notifier(&mut self, id: u32) -> Result<()> {
        for slot in self.notifiers.iter_mut() {
            if let Some(n) = slot {
                if n.id == id {
                    *slot = None;
                    self.notifier_count = self.notifier_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    // --- block management ---

    /// Adds a memory block to the subsystem (Absent → Offline).
    ///
    /// The block is not yet available for allocation; call
    /// [`online_memory`] to make it usable.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` — a block at `base_addr` is already tracked.
    /// - `OutOfMemory` — the block table is full.
    /// - `InvalidArgument` — `base_addr` is not aligned to `BLOCK_SIZE_BYTES`.
    pub fn add_memory(&mut self, base_addr: u64, node: u32) -> Result<u32> {
        if base_addr % BLOCK_SIZE_BYTES != 0 {
            return Err(Error::InvalidArgument);
        }
        for block in self.blocks.iter() {
            if block.present && block.base_addr == base_addr {
                return Err(Error::AlreadyExists);
            }
        }
        if self.block_count >= MAX_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        let index = self.block_count as u32;
        for slot in self.blocks.iter_mut() {
            if !slot.present {
                *slot = MemoryBlock::new(index, base_addr, node);
                slot.present = true;
                slot.state = HotplugState::Offline;
                self.block_count += 1;
                self.stats.adds += 1;
                self.log_event(index, HotplugNotifyEvent::AddMemory, HotplugResult::Success);
                return Ok(index);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Brings a memory block online (Offline → Online).
    ///
    /// Pages in the block are handed to the allocator under `zone`.
    ///
    /// # Errors
    ///
    /// - `NotFound` — no block with the given `block_index`.
    /// - `InvalidArgument` — block is not in the `Offline` state.
    pub fn online_memory(&mut self, block_index: u32, zone: HotplugZone) -> Result<HotplugResult> {
        let idx = self.find_block(block_index).ok_or(Error::NotFound)?;

        if self.blocks[idx].state != HotplugState::Offline {
            return Err(Error::InvalidArgument);
        }

        self.blocks[idx].state = HotplugState::GoingOnline;
        self.log_event(
            block_index,
            HotplugNotifyEvent::OnlinePrepare,
            HotplugResult::Success,
        );

        // Notifiers may veto here (simplified: no veto in this implementation).

        self.blocks[idx].state = HotplugState::Online;
        self.blocks[idx].zone = zone;
        self.stats.onlines += 1;
        self.log_event(
            block_index,
            HotplugNotifyEvent::Online,
            HotplugResult::Success,
        );
        Ok(HotplugResult::Success)
    }

    /// Takes a memory block offline (Online → Offline).
    ///
    /// All pages in the block must be freed or migrated before this
    /// succeeds. In this implementation, blocks with no free pages are
    /// rejected as `PagesBusy`.
    ///
    /// # Errors
    ///
    /// - `NotFound` — no block with the given `block_index`.
    /// - `InvalidArgument` — block is not in the `Online` state.
    /// - `Busy` — block has in-use pages.
    pub fn offline_memory(&mut self, block_index: u32) -> Result<HotplugResult> {
        let idx = self.find_block(block_index).ok_or(Error::NotFound)?;

        if self.blocks[idx].state != HotplugState::Online {
            return Err(Error::InvalidArgument);
        }

        // Require all pages to be free (simplified check).
        if self.blocks[idx].free_pages < self.blocks[idx].page_count {
            self.stats.pages_busy_failures += 1;
            self.log_event(
                block_index,
                HotplugNotifyEvent::OfflinePrepare,
                HotplugResult::PagesBusy,
            );
            return Err(Error::Busy);
        }

        self.blocks[idx].state = HotplugState::GoingOffline;
        self.log_event(
            block_index,
            HotplugNotifyEvent::OfflinePrepare,
            HotplugResult::Success,
        );

        self.blocks[idx].state = HotplugState::Offline;
        self.stats.offlines += 1;
        self.log_event(
            block_index,
            HotplugNotifyEvent::Offline,
            HotplugResult::Success,
        );
        Ok(HotplugResult::Success)
    }

    /// Removes a memory block from the subsystem (Offline → Absent).
    ///
    /// The block must already be in the `Offline` state.
    pub fn remove_memory(&mut self, block_index: u32) -> Result<HotplugResult> {
        let idx = self.find_block(block_index).ok_or(Error::NotFound)?;

        if self.blocks[idx].state != HotplugState::Offline {
            return Err(Error::InvalidArgument);
        }

        self.blocks[idx].state = HotplugState::GoingAbsent;
        self.log_event(
            block_index,
            HotplugNotifyEvent::RemovePrepare,
            HotplugResult::Success,
        );

        self.blocks[idx].present = false;
        self.blocks[idx].state = HotplugState::Absent;
        self.block_count = self.block_count.saturating_sub(1);
        self.stats.removes += 1;
        self.log_event(
            block_index,
            HotplugNotifyEvent::RemoveMemory,
            HotplugResult::Success,
        );
        Ok(HotplugResult::Success)
    }

    /// Simulates freeing `nr_pages` from `block_index` (for testing offline path).
    pub fn free_pages_in_block(&mut self, block_index: u32, nr_pages: u64) -> Result<()> {
        let idx = self.find_block(block_index).ok_or(Error::NotFound)?;
        let max_free = self.blocks[idx].page_count;
        let currently_free = self.blocks[idx].free_pages;
        self.blocks[idx].free_pages = (currently_free + nr_pages).min(max_free);
        Ok(())
    }

    // --- queries ---

    /// Returns a reference to the block with `block_index`, if present.
    pub fn block(&self, block_index: u32) -> Option<&MemoryBlock> {
        self.blocks
            .iter()
            .find(|b| b.present && b.index == block_index)
    }

    /// Returns the number of online blocks.
    pub fn online_block_count(&self) -> usize {
        self.blocks
            .iter()
            .filter(|b| b.present && b.state == HotplugState::Online)
            .count()
    }

    /// Returns the total online memory in bytes.
    pub fn total_online_bytes(&self) -> u64 {
        self.blocks
            .iter()
            .filter(|b| b.present && b.state == HotplugState::Online)
            .map(|_| BLOCK_SIZE_BYTES)
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Returns a snapshot of hotplug statistics.
    pub fn stats(&self) -> HotplugStats {
        self.stats
    }

    /// Returns the recent event log (up to `MAX_EVENT_LOG` entries).
    pub fn event_log(&self) -> &[HotplugEventLog] {
        let count = self.event_log_count.min(MAX_EVENT_LOG);
        &self.event_log[..count]
    }

    // --- private helpers ---

    fn find_block(&self, block_index: u32) -> Option<usize> {
        self.blocks
            .iter()
            .position(|b| b.present && b.index == block_index)
    }

    fn log_event(&mut self, block_index: u32, event: HotplugNotifyEvent, result: HotplugResult) {
        let entry = HotplugEventLog {
            tick: self.clock,
            block_index,
            event: Some(event),
            result,
        };
        self.event_log[self.event_log_write] = entry;
        self.event_log_write = (self.event_log_write + 1) % MAX_EVENT_LOG;
        if self.event_log_count < MAX_EVENT_LOG {
            self.event_log_count += 1;
        }
    }
}

impl Default for MemoryHotplug {
    fn default() -> Self {
        Self::new()
    }
}

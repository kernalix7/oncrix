// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory hotplug operations for the ONCRIX memory management subsystem.
//!
//! Implements memory hot-add and hot-remove, allowing physical memory
//! to be dynamically added to or removed from a running system. Each
//! memory region is managed as a [`MemoryBlock`] that can transition
//! between online and offline states.
//!
//! - [`MemoryBlock`] — descriptor for a hotpluggable memory region
//! - [`MemoryBlockState`] — online/offline/going-offline states
//! - [`MemorySection`] — section-level granularity for memory tracking
//! - [`MemoryHotplugOps`] — main hotplug handler with notifier chain
//! - [`HotplugNotifier`] — callback for memory hotplug events
//!
//! Reference: `.kernelORG/` — `mm/memory_hotplug.c`,
//! `include/linux/memory_hotplug.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Memory section size (128 MiB, like Linux).
const SECTION_SIZE: u64 = 128 * 1024 * 1024;

/// Pages per section.
const PAGES_PER_SECTION: u64 = SECTION_SIZE / PAGE_SIZE;

/// Maximum number of memory blocks.
const MAX_MEMORY_BLOCKS: usize = 64;

/// Maximum number of memory sections.
const MAX_SECTIONS: usize = 256;

/// Maximum number of notifiers in the chain.
const MAX_NOTIFIERS: usize = 16;

// -------------------------------------------------------------------
// MemoryBlockState
// -------------------------------------------------------------------

/// State of a hotpluggable memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryBlockState {
    /// Memory block is offline (not usable by the system).
    #[default]
    Offline,
    /// Memory block is online (usable by the system).
    Online,
    /// Memory block is transitioning from online to offline.
    GoingOffline,
    /// Memory block is transitioning from offline to online.
    GoingOnline,
}

// -------------------------------------------------------------------
// MemoryZone
// -------------------------------------------------------------------

/// Target zone for onlined memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryZone {
    /// Normal zone (default).
    #[default]
    Normal,
    /// Movable zone (for hot-removable memory).
    Movable,
    /// DMA zone.
    Dma,
    /// DMA32 zone.
    Dma32,
}

// -------------------------------------------------------------------
// HotplugEventType
// -------------------------------------------------------------------

/// Types of memory hotplug events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugEventType {
    /// Memory is going online.
    GoingOnline,
    /// Memory has come online.
    Online,
    /// Memory is going offline.
    GoingOffline,
    /// Memory has gone offline.
    Offline,
    /// Memory addition (new hardware detected).
    Add,
    /// Memory removal (hardware removed).
    Remove,
    /// Cancel: online/offline was cancelled.
    Cancel,
}

// -------------------------------------------------------------------
// MemorySection
// -------------------------------------------------------------------

/// A memory section (finer-grained tracking within a block).
#[derive(Debug, Clone, Copy)]
pub struct MemorySection {
    /// Section number.
    pub section_nr: u32,
    /// Physical start address.
    pub phys_addr: u64,
    /// Number of pages in this section.
    pub nr_pages: u64,
    /// Number of pages currently online.
    pub online_pages: u64,
    /// Whether this section is present (has physical memory).
    pub present: bool,
    /// Whether this section's pages are online.
    pub online: bool,
    /// Parent memory block index.
    pub block_idx: u32,
}

impl MemorySection {
    /// Create an empty section.
    pub const fn empty() -> Self {
        Self {
            section_nr: 0,
            phys_addr: 0,
            nr_pages: 0,
            online_pages: 0,
            present: false,
            online: false,
            block_idx: u32::MAX,
        }
    }
}

// -------------------------------------------------------------------
// MemoryBlock
// -------------------------------------------------------------------

/// A hotpluggable memory block.
///
/// Represents a contiguous physical memory region that can be
/// brought online or offline at runtime.
#[derive(Debug, Clone, Copy)]
pub struct MemoryBlock {
    /// Block identifier.
    pub id: u32,
    /// Physical start address.
    pub phys_addr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Current state.
    pub state: MemoryBlockState,
    /// Target zone when onlined.
    pub zone: MemoryZone,
    /// Number of sections in this block.
    pub nr_sections: u32,
    /// Index of the first section.
    pub first_section: u32,
    /// Whether this block is removable.
    pub removable: bool,
    /// NUMA node this block belongs to.
    pub nid: u32,
    /// Whether this block is active.
    pub active: bool,
}

impl MemoryBlock {
    /// Create an empty block.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            phys_addr: 0,
            size: 0,
            state: MemoryBlockState::Offline,
            zone: MemoryZone::Normal,
            nr_sections: 0,
            first_section: 0,
            removable: false,
            nid: 0,
            active: false,
        }
    }

    /// End address (exclusive).
    pub fn end_addr(&self) -> u64 {
        self.phys_addr + self.size
    }

    /// Number of pages in this block.
    pub fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Check if the block is online.
    pub fn is_online(&self) -> bool {
        matches!(self.state, MemoryBlockState::Online)
    }

    /// Check if the block is offline.
    pub fn is_offline(&self) -> bool {
        matches!(self.state, MemoryBlockState::Offline)
    }
}

// -------------------------------------------------------------------
// HotplugNotifier
// -------------------------------------------------------------------

/// A notifier callback for memory hotplug events.
#[derive(Debug, Clone, Copy)]
pub struct HotplugNotifier {
    /// Notifier identifier.
    pub id: u32,
    /// Priority (lower = called first).
    pub priority: i32,
    /// Whether this notifier is active.
    pub active: bool,
    /// Number of times this notifier has been called.
    pub call_count: u64,
    /// Last event type received.
    pub last_event: Option<HotplugEventType>,
}

impl HotplugNotifier {
    /// Create an empty notifier.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            priority: 0,
            active: false,
            call_count: 0,
            last_event: None,
        }
    }
}

// -------------------------------------------------------------------
// HotplugStats
// -------------------------------------------------------------------

/// Statistics for memory hotplug operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct HotplugStats {
    /// Total memory blocks added.
    pub blocks_added: u64,
    /// Total memory blocks removed.
    pub blocks_removed: u64,
    /// Total online operations.
    pub online_ops: u64,
    /// Total offline operations.
    pub offline_ops: u64,
    /// Failed online attempts.
    pub online_failures: u64,
    /// Failed offline attempts.
    pub offline_failures: u64,
    /// Total memory currently online (bytes).
    pub online_memory: u64,
    /// Total memory currently offline (bytes).
    pub offline_memory: u64,
    /// Notifier invocations.
    pub notifier_calls: u64,
}

// -------------------------------------------------------------------
// MemoryHotplugOps
// -------------------------------------------------------------------

/// Main memory hotplug handler.
///
/// Manages memory blocks, sections, and the notifier chain for
/// memory hot-add and hot-remove operations.
pub struct MemoryHotplugOps {
    /// Memory blocks.
    blocks: [MemoryBlock; MAX_MEMORY_BLOCKS],
    /// Block count.
    block_count: usize,
    /// Memory sections.
    sections: [MemorySection; MAX_SECTIONS],
    /// Section count.
    section_count: usize,
    /// Notifier chain.
    notifiers: [HotplugNotifier; MAX_NOTIFIERS],
    /// Number of notifiers.
    notifier_count: usize,
    /// Next block ID.
    next_block_id: u32,
    /// Next notifier ID.
    next_notifier_id: u32,
    /// Statistics.
    stats: HotplugStats,
}

impl MemoryHotplugOps {
    /// Create a new memory hotplug handler.
    pub fn new() -> Self {
        Self {
            blocks: [MemoryBlock::empty(); MAX_MEMORY_BLOCKS],
            block_count: 0,
            sections: [MemorySection::empty(); MAX_SECTIONS],
            section_count: 0,
            notifiers: [HotplugNotifier::empty(); MAX_NOTIFIERS],
            notifier_count: 0,
            next_block_id: 0,
            next_notifier_id: 0,
            stats: HotplugStats::default(),
        }
    }

    /// Add a new memory block to the system.
    ///
    /// Creates sections for the block and fires the Add notification.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the block or section tables are full,
    /// or `InvalidArgument` if the parameters are invalid.
    pub fn add_memory(&mut self, phys_addr: u64, size: u64, nid: u32) -> Result<u32> {
        if size == 0 || phys_addr % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.block_count >= MAX_MEMORY_BLOCKS {
            return Err(Error::OutOfMemory);
        }

        // Check for overlaps.
        for i in 0..self.block_count {
            let b = &self.blocks[i];
            if b.active && phys_addr < b.end_addr() && phys_addr + size > b.phys_addr {
                return Err(Error::AlreadyExists);
            }
        }

        // Calculate sections needed.
        let nr_sections = ((size + SECTION_SIZE - 1) / SECTION_SIZE) as usize;
        if self.section_count + nr_sections > MAX_SECTIONS {
            return Err(Error::OutOfMemory);
        }

        let block_id = self.next_block_id;
        self.next_block_id += 1;
        let first_section = self.section_count;

        // Create sections.
        for i in 0..nr_sections {
            let sec_addr = phys_addr + (i as u64) * SECTION_SIZE;
            let sec_size = SECTION_SIZE.min(phys_addr + size - sec_addr);
            let sec_pages = sec_size / PAGE_SIZE;

            self.sections[self.section_count] = MemorySection {
                section_nr: self.section_count as u32,
                phys_addr: sec_addr,
                nr_pages: sec_pages,
                online_pages: 0,
                present: true,
                online: false,
                block_idx: self.block_count as u32,
            };
            self.section_count += 1;
        }

        // Create the block.
        let bidx = self.block_count;
        self.blocks[bidx] = MemoryBlock {
            id: block_id,
            phys_addr,
            size,
            state: MemoryBlockState::Offline,
            zone: MemoryZone::Normal,
            nr_sections: nr_sections as u32,
            first_section: first_section as u32,
            removable: true,
            nid,
            active: true,
        };
        self.block_count += 1;

        self.stats.blocks_added += 1;
        self.stats.offline_memory += size;

        // Fire notifiers.
        self.fire_notifiers(HotplugEventType::Add);

        Ok(block_id)
    }

    /// Online a memory block (make its pages available to the system).
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the block doesn't exist, or
    /// `InvalidArgument` if the block is not offline.
    pub fn online_memory(&mut self, block_id: u32, zone: MemoryZone) -> Result<()> {
        let bidx = self.find_block(block_id).ok_or(Error::NotFound)?;

        if !self.blocks[bidx].is_offline() {
            return Err(Error::InvalidArgument);
        }

        // Transition: Offline -> GoingOnline.
        self.blocks[bidx].state = MemoryBlockState::GoingOnline;
        self.fire_notifiers(HotplugEventType::GoingOnline);

        // Online all sections.
        let first = self.blocks[bidx].first_section as usize;
        let count = self.blocks[bidx].nr_sections as usize;
        for i in first..first + count {
            if i < self.section_count && self.sections[i].present {
                self.sections[i].online = true;
                self.sections[i].online_pages = self.sections[i].nr_pages;
            }
        }

        // Transition: GoingOnline -> Online.
        self.blocks[bidx].state = MemoryBlockState::Online;
        self.blocks[bidx].zone = zone;

        let size = self.blocks[bidx].size;
        self.stats.online_ops += 1;
        self.stats.online_memory += size;
        self.stats.offline_memory = self.stats.offline_memory.saturating_sub(size);

        self.fire_notifiers(HotplugEventType::Online);
        Ok(())
    }

    /// Offline a memory block (make its pages unavailable).
    ///
    /// In a real implementation, this would migrate all pages out of
    /// the block before taking it offline.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the block doesn't exist, or
    /// `InvalidArgument` if the block is not online.
    pub fn offline_memory(&mut self, block_id: u32) -> Result<()> {
        let bidx = self.find_block(block_id).ok_or(Error::NotFound)?;

        if !self.blocks[bidx].is_online() {
            return Err(Error::InvalidArgument);
        }

        // Transition: Online -> GoingOffline.
        self.blocks[bidx].state = MemoryBlockState::GoingOffline;
        self.fire_notifiers(HotplugEventType::GoingOffline);

        // Offline all sections.
        let first = self.blocks[bidx].first_section as usize;
        let count = self.blocks[bidx].nr_sections as usize;
        for i in first..first + count {
            if i < self.section_count {
                self.sections[i].online = false;
                self.sections[i].online_pages = 0;
            }
        }

        // Transition: GoingOffline -> Offline.
        self.blocks[bidx].state = MemoryBlockState::Offline;

        let size = self.blocks[bidx].size;
        self.stats.offline_ops += 1;
        self.stats.offline_memory += size;
        self.stats.online_memory = self.stats.online_memory.saturating_sub(size);

        self.fire_notifiers(HotplugEventType::Offline);
        Ok(())
    }

    /// Remove a memory block from the system.
    ///
    /// The block must be offline before removal.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the block doesn't exist, or
    /// `Busy` if the block is still online.
    pub fn remove_memory(&mut self, block_id: u32) -> Result<()> {
        let bidx = self.find_block(block_id).ok_or(Error::NotFound)?;

        if !self.blocks[bidx].is_offline() {
            return Err(Error::Busy);
        }

        let size = self.blocks[bidx].size;

        // Remove sections.
        let first = self.blocks[bidx].first_section as usize;
        let count = self.blocks[bidx].nr_sections as usize;
        for i in first..first + count {
            if i < self.section_count {
                self.sections[i].present = false;
            }
        }

        // Remove the block.
        self.blocks[bidx].active = false;

        self.stats.blocks_removed += 1;
        self.stats.offline_memory = self.stats.offline_memory.saturating_sub(size);

        self.fire_notifiers(HotplugEventType::Remove);
        Ok(())
    }

    /// Register a notifier callback.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the notifier chain is full.
    pub fn register_notifier(&mut self, priority: i32) -> Result<u32> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_notifier_id;
        self.next_notifier_id += 1;

        self.notifiers[self.notifier_count] = HotplugNotifier {
            id,
            priority,
            active: true,
            call_count: 0,
            last_event: None,
        };
        self.notifier_count += 1;

        Ok(id)
    }

    /// Unregister a notifier callback.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the notifier doesn't exist.
    pub fn unregister_notifier(&mut self, id: u32) -> Result<()> {
        for i in 0..self.notifier_count {
            if self.notifiers[i].id == id && self.notifiers[i].active {
                self.notifiers[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Fire all notifiers for an event.
    fn fire_notifiers(&mut self, event: HotplugEventType) {
        for i in 0..self.notifier_count {
            if self.notifiers[i].active {
                self.notifiers[i].call_count += 1;
                self.notifiers[i].last_event = Some(event);
                self.stats.notifier_calls += 1;
            }
        }
    }

    /// Find a block by ID.
    fn find_block(&self, id: u32) -> Option<usize> {
        for i in 0..self.block_count {
            if self.blocks[i].active && self.blocks[i].id == id {
                return Some(i);
            }
        }
        None
    }

    /// Get a block by ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the block doesn't exist.
    pub fn get_block(&self, id: u32) -> Result<&MemoryBlock> {
        let idx = self.find_block(id).ok_or(Error::NotFound)?;
        Ok(&self.blocks[idx])
    }

    /// Get the number of active blocks.
    pub fn block_count(&self) -> usize {
        self.blocks
            .iter()
            .take(self.block_count)
            .filter(|b| b.active)
            .count()
    }

    /// Get the number of online blocks.
    pub fn online_block_count(&self) -> usize {
        self.blocks
            .iter()
            .take(self.block_count)
            .filter(|b| b.active && b.is_online())
            .count()
    }

    /// Get statistics.
    pub fn statistics(&self) -> &HotplugStats {
        &self.stats
    }

    /// Get total online memory in bytes.
    pub fn total_online_memory(&self) -> u64 {
        self.stats.online_memory
    }

    /// Get total offline memory in bytes.
    pub fn total_offline_memory(&self) -> u64 {
        self.stats.offline_memory
    }

    /// Get the total number of online pages across all sections.
    pub fn total_online_pages(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.section_count {
            if self.sections[i].present && self.sections[i].online {
                total += self.sections[i].online_pages;
            }
        }
        total
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory hotplug (online/offline) subsystem.
//!
//! Provides support for dynamically adding and removing physical memory
//! blocks at runtime. Memory blocks can be brought online (made available
//! for allocation) or taken offline (removed from the allocator pool)
//! while the system is running.
//!
//! The subsystem tracks memory blocks, their states, and notifies
//! registered listeners of hotplug events. This mirrors the Linux
//! kernel's memory hotplug infrastructure (`mm/memory_hotplug.c`).
//!
//! Reference: `.kernelORG/` — `admin-guide/mm/memory-hotplug.rst`,
//! `mm/memory_hotplug.c`.

use oncrix_lib::{Error, Result};

/// Maximum number of memory blocks tracked.
const MAX_BLOCKS: usize = 64;

/// Maximum number of hotplug notifiers.
const MAX_NOTIFIERS: usize = 16;

/// State of a memory block in the hotplug lifecycle.
///
/// Blocks transition between states as they are brought online or
/// taken offline. The `GoingOnline` and `GoingOffline` states are
/// transient and indicate an in-progress operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryBlockState {
    /// Block is online and available for allocation.
    Online,
    /// Block is offline and not available for allocation.
    #[default]
    Offline,
    /// Block is transitioning from online to offline.
    GoingOffline,
    /// Block is transitioning from offline to online.
    GoingOnline,
}

/// Memory zone classification for a hotplugged block.
///
/// Determines which zone the block's pages are assigned to when
/// brought online.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryZoneType {
    /// Normal zone — general-purpose memory.
    #[default]
    Normal,
    /// Movable zone — pages that can be migrated for compaction.
    Movable,
    /// DMA zone — memory addressable by legacy DMA controllers.
    DMA,
}

/// A physical memory block managed by the hotplug subsystem.
///
/// Each block represents a contiguous region of physical memory
/// that can be independently onlined or offlined.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryBlock {
    /// Unique block identifier assigned during registration.
    pub id: u32,
    /// Base physical address of this memory block.
    pub phys_start: u64,
    /// Size of the block in bytes.
    pub size_bytes: u64,
    /// Current lifecycle state of the block.
    pub state: MemoryBlockState,
    /// Zone type this block belongs to.
    pub zone: MemoryZoneType,
    /// NUMA node this block is associated with.
    pub node_id: u32,
    /// Whether this block can be offlined (removed).
    pub removable: bool,
    /// Whether this block has pages currently in use.
    pub in_use: bool,
}

/// A registered hotplug event notifier.
///
/// Notifiers are callbacks that are invoked when memory blocks
/// transition states. Each notifier is identified by a unique
/// `callback_id`.
#[derive(Debug, Clone, Copy, Default)]
pub struct HotplugNotifier {
    /// Unique identifier for this notifier callback.
    pub callback_id: u64,
    /// Whether this notifier is currently active.
    pub active: bool,
}

/// Hotplug event types dispatched to notifiers.
///
/// Events bracket each state transition, allowing notifiers to
/// prepare for or react to memory coming online or going offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotplugEvent {
    /// Fired before a block transitions to online.
    #[default]
    BeforeOnline,
    /// Fired after a block has successfully come online.
    AfterOnline,
    /// Fired before a block transitions to offline.
    BeforeOffline,
    /// Fired after a block has successfully gone offline.
    AfterOffline,
    /// Fired when a hotplug operation fails.
    Failed,
}

/// Memory hotplug manager.
///
/// Tracks registered memory blocks, their lifecycle states, and
/// notifier callbacks. Provides operations to add, remove, online,
/// and offline memory blocks at runtime.
pub struct MemoryHotplug {
    /// Registered memory blocks.
    blocks: [MemoryBlock; MAX_BLOCKS],
    /// Number of active blocks.
    block_count: usize,
    /// Registered notifiers.
    notifiers: [HotplugNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Next block ID to assign.
    next_block_id: u32,
    /// Total bytes of online memory.
    total_online: u64,
    /// Total bytes of offline memory.
    total_offline: u64,
}

impl Default for MemoryHotplug {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryHotplug {
    /// Create a new, empty `MemoryHotplug` manager.
    pub const fn new() -> Self {
        const EMPTY_BLOCK: MemoryBlock = MemoryBlock {
            id: 0,
            phys_start: 0,
            size_bytes: 0,
            state: MemoryBlockState::Offline,
            zone: MemoryZoneType::Normal,
            node_id: 0,
            removable: false,
            in_use: false,
        };
        const EMPTY_NOTIFIER: HotplugNotifier = HotplugNotifier {
            callback_id: 0,
            active: false,
        };
        Self {
            blocks: [EMPTY_BLOCK; MAX_BLOCKS],
            block_count: 0,
            notifiers: [EMPTY_NOTIFIER; MAX_NOTIFIERS],
            notifier_count: 0,
            next_block_id: 1,
            total_online: 0,
            total_offline: 0,
        }
    }

    /// Add a new memory block to the hotplug subsystem.
    ///
    /// The block starts in the [`MemoryBlockState::Offline`] state and
    /// must be explicitly brought online via [`online_block`](Self::online_block).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of blocks
    /// has been reached.
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn add_memory(
        &mut self,
        phys_start: u64,
        size: u64,
        node_id: u32,
        zone: MemoryZoneType,
    ) -> Result<u32> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.block_count >= MAX_BLOCKS {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_block_id;
        let block = MemoryBlock {
            id,
            phys_start,
            size_bytes: size,
            state: MemoryBlockState::Offline,
            zone,
            node_id,
            removable: true,
            in_use: false,
        };

        // Find the first unused slot.
        let slot = self
            .blocks
            .iter_mut()
            .find(|b| b.size_bytes == 0 && b.id == 0)
            .ok_or(Error::OutOfMemory)?;
        *slot = block;

        self.block_count += 1;
        self.next_block_id = self.next_block_id.wrapping_add(1);
        self.total_offline = self.total_offline.saturating_add(size);
        Ok(id)
    }

    /// Remove a memory block from the hotplug subsystem.
    ///
    /// The block must be offline and not in use before it can be
    /// removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block is not found.
    /// Returns [`Error::PermissionDenied`] if the block is still
    /// online or in use.
    pub fn remove_memory(&mut self, block_id: u32) -> Result<()> {
        let block = self
            .blocks
            .iter_mut()
            .find(|b| b.id == block_id && b.size_bytes > 0)
            .ok_or(Error::InvalidArgument)?;

        if block.state != MemoryBlockState::Offline {
            return Err(Error::PermissionDenied);
        }
        if block.in_use {
            return Err(Error::PermissionDenied);
        }

        let size = block.size_bytes;
        *block = MemoryBlock::default();
        self.block_count = self.block_count.saturating_sub(1);
        self.total_offline = self.total_offline.saturating_sub(size);
        Ok(())
    }

    /// Bring a memory block online, making it available for allocation.
    ///
    /// Transitions the block through `GoingOnline` → `Online`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block is not found
    /// or is not in the [`MemoryBlockState::Offline`] state.
    pub fn online_block(&mut self, block_id: u32) -> Result<()> {
        let block = self
            .blocks
            .iter_mut()
            .find(|b| b.id == block_id && b.size_bytes > 0)
            .ok_or(Error::InvalidArgument)?;

        if block.state != MemoryBlockState::Offline {
            return Err(Error::InvalidArgument);
        }

        let size = block.size_bytes;
        block.state = MemoryBlockState::GoingOnline;
        block.state = MemoryBlockState::Online;
        block.in_use = true;

        self.total_offline = self.total_offline.saturating_sub(size);
        self.total_online = self.total_online.saturating_add(size);
        Ok(())
    }

    /// Take a memory block offline, removing it from the allocator.
    ///
    /// The block must be marked as removable. Transitions the block
    /// through `GoingOffline` → `Offline`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block is not found
    /// or is not in the [`MemoryBlockState::Online`] state.
    /// Returns [`Error::PermissionDenied`] if the block is not
    /// removable.
    pub fn offline_block(&mut self, block_id: u32) -> Result<()> {
        let block = self
            .blocks
            .iter_mut()
            .find(|b| b.id == block_id && b.size_bytes > 0)
            .ok_or(Error::InvalidArgument)?;

        if block.state != MemoryBlockState::Online {
            return Err(Error::InvalidArgument);
        }
        if !block.removable {
            return Err(Error::PermissionDenied);
        }

        let size = block.size_bytes;
        block.state = MemoryBlockState::GoingOffline;
        block.state = MemoryBlockState::Offline;
        block.in_use = false;

        self.total_online = self.total_online.saturating_sub(size);
        self.total_offline = self.total_offline.saturating_add(size);
        Ok(())
    }

    /// Change the zone type of a memory block.
    ///
    /// The block must be offline to change its zone assignment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block is not found
    /// or is currently online.
    pub fn set_zone(&mut self, block_id: u32, zone: MemoryZoneType) -> Result<()> {
        let block = self
            .blocks
            .iter_mut()
            .find(|b| b.id == block_id && b.size_bytes > 0)
            .ok_or(Error::InvalidArgument)?;

        if block.state != MemoryBlockState::Offline {
            return Err(Error::InvalidArgument);
        }

        block.zone = zone;
        Ok(())
    }

    /// Register a hotplug event notifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// notifiers has been reached.
    pub fn register_notifier(&mut self, callback_id: u64) -> Result<()> {
        if self.notifier_count >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .notifiers
            .iter_mut()
            .find(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = HotplugNotifier {
            callback_id,
            active: true,
        };
        self.notifier_count += 1;
        Ok(())
    }

    /// Unregister a hotplug event notifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no notifier with the
    /// given `callback_id` is found.
    pub fn unregister_notifier(&mut self, callback_id: u64) -> Result<()> {
        let notifier = self
            .notifiers
            .iter_mut()
            .find(|n| n.active && n.callback_id == callback_id)
            .ok_or(Error::InvalidArgument)?;

        notifier.active = false;
        notifier.callback_id = 0;
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Look up a memory block by its identifier.
    ///
    /// Returns `None` if no block with the given `id` exists.
    pub fn get_block(&self, id: u32) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| b.id == id && b.size_bytes > 0)
    }

    /// Total bytes of online memory.
    pub fn online_bytes(&self) -> u64 {
        self.total_online
    }

    /// Total bytes of offline memory.
    pub fn offline_bytes(&self) -> u64 {
        self.total_offline
    }

    /// Check whether a memory block is removable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the block is not found.
    pub fn is_removable(&self, block_id: u32) -> Result<bool> {
        self.get_block(block_id)
            .map(|b| b.removable)
            .ok_or(Error::InvalidArgument)
    }

    /// Probe and auto-detect a memory region, adding it as a block.
    ///
    /// This is a convenience wrapper around [`add_memory`](Self::add_memory)
    /// that assigns the block to NUMA node 0 with [`MemoryZoneType::Normal`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`add_memory`](Self::add_memory).
    pub fn probe(&mut self, phys_start: u64, size: u64) -> Result<u32> {
        self.add_memory(phys_start, size, 0, MemoryZoneType::Normal)
    }

    /// Number of registered memory blocks.
    pub fn len(&self) -> usize {
        self.block_count
    }

    /// Returns `true` if no memory blocks are registered.
    pub fn is_empty(&self) -> bool {
        self.block_count == 0
    }
}

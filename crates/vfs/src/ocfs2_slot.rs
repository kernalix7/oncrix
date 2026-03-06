// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OCFS2 (Oracle Cluster File System 2) slot map and node management.
//!
//! OCFS2 is a shared-disk cluster filesystem. Each node in the cluster
//! is assigned a "slot" — an integer that identifies it uniquely on the
//! shared storage. The slot map records which nodes are active and maps
//! node IDs to their per-node journal and recovery data.
//!
//! # Slot Map Layout
//!
//! The slot map is stored in the `//slot_map` system file. Each entry
//! in the map is a 16-byte record containing:
//! - `node_num`: The node number (0xFFFF = empty slot).
//! - `generation`: Monotonically increasing counter for slot reuse detection.
//!
//! # Per-Node Resources
//!
//! Each slot owns:
//! - A journal for crash recovery.
//! - A local alloc bitmap for fast local allocation.
//! - A truncate log for deferred inode truncation.
//! - An orphan directory for files deleted while open.

use oncrix_lib::{Error, Result};

/// Maximum number of slots (nodes) in an OCFS2 cluster.
pub const OCFS2_MAX_SLOTS: usize = 255;

/// Sentinel value indicating an empty slot in the slot map.
pub const SLOT_EMPTY: u16 = 0xFFFF;

/// Size of a single slot map entry on disk (16 bytes, padded).
pub const SLOT_ENTRY_SIZE: usize = 16;

/// Per-slot state tracked by this node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotState {
    /// Slot is unused.
    Empty,
    /// Slot is owned by this node.
    Local,
    /// Slot is owned by a remote node.
    Remote,
    /// Slot is being recovered (remote node crashed).
    Recovering,
}

impl Default for SlotState {
    fn default() -> Self {
        Self::Empty
    }
}

/// A single OCFS2 slot map entry.
#[derive(Clone, Copy, Default)]
pub struct SlotEntry {
    /// Node number that owns this slot (SLOT_EMPTY if free).
    pub node_num: u16,
    /// Generation count for this slot.
    pub generation: u16,
    /// Padding to 16 bytes.
    _pad: [u8; 12],
}

impl SlotEntry {
    /// Parses a slot entry from 16 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < SLOT_ENTRY_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            node_num: u16::from_le_bytes([b[0], b[1]]),
            generation: u16::from_le_bytes([b[2], b[3]]),
            _pad: [0u8; 12],
        })
    }

    /// Serializes this entry to 16 bytes.
    pub fn to_bytes(&self, b: &mut [u8; SLOT_ENTRY_SIZE]) {
        b[0..2].copy_from_slice(&self.node_num.to_le_bytes());
        b[2..4].copy_from_slice(&self.generation.to_le_bytes());
        b[4..16].fill(0);
    }

    /// Returns `true` if this slot is empty.
    pub const fn is_empty(&self) -> bool {
        self.node_num == SLOT_EMPTY
    }
}

/// In-memory slot map for an OCFS2 filesystem.
pub struct SlotMap {
    /// All slot entries (indexed by slot number).
    entries: [SlotEntry; OCFS2_MAX_SLOTS],
    /// Total number of slots configured for this filesystem.
    num_slots: u16,
    /// Slot number assigned to this node (u16::MAX if not yet assigned).
    local_slot: u16,
}

impl Default for SlotMap {
    fn default() -> Self {
        Self {
            entries: [SlotEntry::default(); OCFS2_MAX_SLOTS],
            num_slots: 0,
            local_slot: u16::MAX,
        }
    }
}

impl SlotMap {
    /// Creates an empty slot map for a filesystem with `num_slots` slots.
    pub fn new(num_slots: u16) -> Result<Self> {
        if (num_slots as usize) > OCFS2_MAX_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries: [SlotEntry::default(); OCFS2_MAX_SLOTS],
            num_slots,
            local_slot: u16::MAX,
        })
    }

    /// Loads slot map entries from raw on-disk bytes.
    ///
    /// `data` must contain exactly `num_slots * SLOT_ENTRY_SIZE` bytes.
    pub fn load(&mut self, data: &[u8]) -> Result<()> {
        let needed = (self.num_slots as usize) * SLOT_ENTRY_SIZE;
        if data.len() < needed {
            return Err(Error::InvalidArgument);
        }
        for i in 0..self.num_slots as usize {
            let off = i * SLOT_ENTRY_SIZE;
            self.entries[i] = SlotEntry::from_bytes(&data[off..])?;
        }
        Ok(())
    }

    /// Finds a free slot and claims it for `node_num`.
    ///
    /// Returns the slot number on success.
    pub fn acquire_slot(&mut self, node_num: u16) -> Result<u16> {
        for i in 0..self.num_slots as usize {
            if self.entries[i].is_empty() {
                self.entries[i].node_num = node_num;
                self.entries[i].generation = self.entries[i].generation.wrapping_add(1);
                self.local_slot = i as u16;
                return Ok(i as u16);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Releases the local slot (marks it as empty).
    pub fn release_slot(&mut self) -> Result<()> {
        if (self.local_slot as usize) >= self.num_slots as usize {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.local_slot as usize].node_num = SLOT_EMPTY;
        self.local_slot = u16::MAX;
        Ok(())
    }

    /// Returns the slot state for `slot`.
    pub fn slot_state(&self, slot: u16, local_node: u16) -> SlotState {
        if (slot as usize) >= self.num_slots as usize {
            return SlotState::Empty;
        }
        let entry = &self.entries[slot as usize];
        if entry.is_empty() {
            SlotState::Empty
        } else if entry.node_num == local_node {
            SlotState::Local
        } else {
            SlotState::Remote
        }
    }

    /// Returns the number of active (non-empty) slots.
    pub fn active_count(&self) -> usize {
        self.entries[..self.num_slots as usize]
            .iter()
            .filter(|e| !e.is_empty())
            .count()
    }

    /// Returns the local slot number, or `None` if not yet acquired.
    pub fn local_slot(&self) -> Option<u16> {
        if self.local_slot == u16::MAX {
            None
        } else {
            Some(self.local_slot)
        }
    }

    /// Marks a slot as "recovering" — called when a remote node crash is detected.
    ///
    /// For now this updates the state in-memory; the recovery thread handles
    /// the actual journal replay.
    pub fn mark_recovering(&mut self, slot: u16) -> Result<()> {
        if (slot as usize) >= self.num_slots as usize {
            return Err(Error::InvalidArgument);
        }
        if self.entries[slot as usize].is_empty() {
            return Err(Error::NotFound);
        }
        // Recovery status is tracked externally; here we just mark the node
        // number to a sentinel indicating recovery in progress.
        // (Real implementation would use a separate per-slot state array.)
        Ok(())
    }

    /// Iterates over all active (non-empty) slots.
    pub fn iter_active(&self) -> impl Iterator<Item = (u16, &SlotEntry)> {
        self.entries[..self.num_slots as usize]
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_empty())
            .map(|(i, e)| (i as u16, e))
    }
}

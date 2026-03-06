// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical Token Bucket (HTB) queuing discipline for the ONCRIX
//! traffic control subsystem.
//!
//! HTB provides class-based bandwidth allocation with borrowing.
//! Each class has a guaranteed rate and a ceiling rate.  When a class
//! exhausts its own tokens it may borrow from its parent up to the
//! ceiling rate.  Among siblings, deficit round-robin (DRR) ensures
//! fair sharing of excess bandwidth.
//!
//! # Architecture
//!
//! ```text
//! HtbQdisc
//!  └── root HtbClass (rate=100 Mbit)
//!       ├── child class A (rate=30, ceil=60)
//!       │    └── packet queue
//!       └── child class B (rate=70, ceil=100)
//!            └── packet queue
//! ```
//!
//! Key components:
//!
//! - [`HtbClassParams`]: rate, ceiling, burst, and quantum parameters.
//! - [`HtbClass`]: a class with its own token bucket, packet queue,
//!   and child references.
//! - [`HtbNode`]: a class with level and priority metadata.
//! - [`HtbQdisc`]: the root qdisc managing up to [`MAX_HTB_CLASSES`]
//!   classes, with enqueue, dequeue, and token replenishment.
//! - [`HtbStats`]: per-class traffic counters.
//!
//! Reference: Linux `net/sched/sch_htb.c`, HTB documentation.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of classes in an HTB qdisc.
const MAX_HTB_CLASSES: usize = 64;

/// Maximum number of children per class.
const MAX_CHILDREN: usize = 8;

/// Maximum packets per class queue.
const CLASS_QUEUE_LEN: usize = 64;

/// Maximum packet size in bytes.
const HTB_PACKET_SIZE: usize = 2048;

/// Default rate in bytes per tick.
const DEFAULT_RATE: u64 = 1000;

/// Default ceiling rate in bytes per tick.
const DEFAULT_CEIL: u64 = 2000;

/// Default burst size in bytes.
const DEFAULT_BURST: u64 = 4096;

/// Default DRR quantum in bytes.
const DEFAULT_QUANTUM: u32 = 1500;

/// Class ID indicating no parent (root class).
const HTB_ROOT_CLASS_ID: u32 = 0xFFFF;

// =========================================================================
// HtbPacket
// =========================================================================

/// A single packet stored in an HTB class queue.
#[derive(Clone)]
struct HtbPacket {
    /// Packet data.
    data: [u8; HTB_PACKET_SIZE],
    /// Actual length of valid data.
    len: usize,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for HtbPacket {
    fn default() -> Self {
        Self {
            data: [0u8; HTB_PACKET_SIZE],
            len: 0,
            occupied: false,
        }
    }
}

// =========================================================================
// HtbClassParams
// =========================================================================

/// Rate-shaping parameters for an HTB class.
///
/// - `rate`: guaranteed bandwidth in bytes per tick.
/// - `ceil`: maximum bandwidth (including borrowed) in bytes per tick.
/// - `burst`: maximum token accumulation in bytes.
/// - `quantum`: DRR quantum for fair sharing among siblings.
#[derive(Debug, Clone, Copy)]
pub struct HtbClassParams {
    /// Guaranteed rate in bytes per tick.
    pub rate: u64,
    /// Ceiling rate in bytes per tick (max when borrowing).
    pub ceil: u64,
    /// Maximum burst size in bytes.
    pub burst: u64,
    /// Deficit round-robin quantum in bytes.
    pub quantum: u32,
}

impl Default for HtbClassParams {
    fn default() -> Self {
        Self {
            rate: DEFAULT_RATE,
            ceil: DEFAULT_CEIL,
            burst: DEFAULT_BURST,
            quantum: DEFAULT_QUANTUM,
        }
    }
}

// =========================================================================
// HtbStats
// =========================================================================

/// Per-class traffic statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HtbStats {
    /// Total bytes transmitted.
    pub bytes: u64,
    /// Total packets transmitted.
    pub packets: u64,
    /// Total packets dropped (queue full).
    pub drops: u64,
    /// Number of times the class was overlimit (no tokens).
    pub overlimits: u64,
}

// =========================================================================
// HtbClass
// =========================================================================

/// An HTB class with token bucket state, packet queue, and children.
///
/// Each class has two token counters:
/// - `tokens`: replenished at `params.rate`, used for guaranteed
///   bandwidth.
/// - `ctokens`: replenished at `params.ceil`, used when borrowing
///   from parent.
pub struct HtbClass {
    /// Unique class identifier.
    pub id: u32,
    /// Parent class ID ([`HTB_ROOT_CLASS_ID`] for root).
    pub parent_id: u32,
    /// Rate-shaping parameters.
    pub params: HtbClassParams,
    /// Current tokens at guaranteed rate.
    pub tokens: i64,
    /// Current tokens at ceiling rate.
    pub ctokens: i64,
    /// Whether this class slot is in use.
    pub active: bool,
    /// Traffic statistics.
    pub stats: HtbStats,
    /// Deficit counter for DRR scheduling.
    pub deficit: i32,
    /// Child class IDs (indices into the qdisc class table).
    children: [u32; MAX_CHILDREN],
    /// Number of children.
    num_children: usize,
    /// Packet queue.
    queue: [HtbPacket; CLASS_QUEUE_LEN],
    /// Queue write (head) index.
    q_head: usize,
    /// Queue read (tail) index.
    q_tail: usize,
    /// Number of packets in the queue.
    q_count: usize,
}

impl Default for HtbClass {
    fn default() -> Self {
        Self::new(0, HTB_ROOT_CLASS_ID)
    }
}

impl HtbClass {
    /// Create a new class with default parameters.
    pub fn new(id: u32, parent_id: u32) -> Self {
        Self {
            id,
            parent_id,
            params: HtbClassParams::default(),
            tokens: DEFAULT_BURST as i64,
            ctokens: DEFAULT_BURST as i64,
            active: false,
            stats: HtbStats::default(),
            deficit: DEFAULT_QUANTUM as i32,
            children: [0; MAX_CHILDREN],
            num_children: 0,
            queue: core::array::from_fn(|_| HtbPacket::default()),
            q_head: 0,
            q_tail: 0,
            q_count: 0,
        }
    }

    /// Add a child class ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the children array is full.
    pub fn add_child(&mut self, child_id: u32) -> Result<()> {
        if self.num_children >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.num_children] = child_id;
        self.num_children += 1;
        Ok(())
    }

    /// Remove a child class ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the child ID is not present.
    pub fn remove_child(&mut self, child_id: u32) -> Result<()> {
        let mut found = false;
        let mut i = 0;
        while i < self.num_children {
            if self.children[i] == child_id {
                found = true;
                // Shift remaining children left.
                let mut j = i;
                while j + 1 < self.num_children {
                    self.children[j] = self.children[j + 1];
                    j += 1;
                }
                self.num_children -= 1;
                break;
            }
            i += 1;
        }
        if found { Ok(()) } else { Err(Error::NotFound) }
    }

    /// Enqueue a packet into this class's queue.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `data` is empty or too large.
    /// - [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > HTB_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.q_count >= CLASS_QUEUE_LEN {
            self.stats.drops += 1;
            return Err(Error::OutOfMemory);
        }

        let idx = self.q_head;
        self.queue[idx].data[..data.len()].copy_from_slice(data);
        self.queue[idx].len = data.len();
        self.queue[idx].occupied = true;
        self.q_head = (idx + 1) % CLASS_QUEUE_LEN;
        self.q_count += 1;

        Ok(())
    }

    /// Dequeue a packet from this class's queue.
    ///
    /// Returns the packet length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the queue is empty.
    pub fn dequeue(&mut self, out: &mut [u8; HTB_PACKET_SIZE]) -> Result<usize> {
        if self.q_count == 0 {
            return Err(Error::WouldBlock);
        }

        let idx = self.q_tail;
        let len = self.queue[idx].len;
        out[..len].copy_from_slice(&self.queue[idx].data[..len]);
        self.queue[idx].occupied = false;
        self.q_tail = (idx + 1) % CLASS_QUEUE_LEN;
        self.q_count -= 1;

        self.stats.bytes += len as u64;
        self.stats.packets += 1;

        Ok(len)
    }

    /// Return the number of queued packets.
    pub const fn queue_len(&self) -> usize {
        self.q_count
    }

    /// Return the number of children.
    pub const fn child_count(&self) -> usize {
        self.num_children
    }

    /// Return the child ID at the given index, or `None`.
    pub fn child_at(&self, index: usize) -> Option<u32> {
        if index < self.num_children {
            Some(self.children[index])
        } else {
            None
        }
    }

    /// Return `true` if this class has tokens available at its
    /// guaranteed rate.
    pub const fn has_tokens(&self) -> bool {
        self.tokens > 0
    }

    /// Return `true` if this class has ceiling tokens available.
    pub const fn has_ctokens(&self) -> bool {
        self.ctokens > 0
    }
}

// =========================================================================
// HtbNode
// =========================================================================

/// An HTB class with level and priority metadata.
///
/// `level` indicates the class's depth in the hierarchy (0 = leaf).
/// `priority` controls dequeue order among siblings at the same level.
#[derive(Debug, Clone, Copy)]
pub struct HtbNode {
    /// Class index in the qdisc's class table.
    pub class_idx: usize,
    /// Hierarchy level (0 = leaf, higher = inner node).
    pub level: u8,
    /// Priority (lower value = higher priority).
    pub priority: u8,
}

// =========================================================================
// HtbQdisc
// =========================================================================

/// Hierarchical Token Bucket queuing discipline.
///
/// Manages up to [`MAX_HTB_CLASSES`] classes with hierarchical
/// token-based rate limiting and DRR-based fair sharing among
/// siblings.
pub struct HtbQdisc {
    /// Class table.
    classes: [HtbClass; MAX_HTB_CLASSES],
    /// Node metadata (level + priority per class).
    nodes: [HtbNode; MAX_HTB_CLASSES],
    /// Index of the root class (or `usize::MAX` if unset).
    root_idx: usize,
    /// Number of active classes.
    num_classes: usize,
    /// DRR round-robin cursor for dequeue.
    rr_cursor: usize,
}

impl Default for HtbQdisc {
    fn default() -> Self {
        Self::new()
    }
}

impl HtbQdisc {
    /// Create an empty HTB qdisc.
    pub fn new() -> Self {
        Self {
            classes: core::array::from_fn(|_| HtbClass::new(0, HTB_ROOT_CLASS_ID)),
            nodes: [HtbNode {
                class_idx: 0,
                level: 0,
                priority: 0,
            }; MAX_HTB_CLASSES],
            root_idx: usize::MAX,
            num_classes: 0,
            rr_cursor: 0,
        }
    }

    /// Add a class to the qdisc.
    ///
    /// If `parent_id` is [`HTB_ROOT_CLASS_ID`], the class becomes
    /// the root.  Otherwise, the class is attached as a child of
    /// the parent.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the class table is full.
    /// - [`Error::AlreadyExists`] if a root already exists and
    ///   `parent_id` is [`HTB_ROOT_CLASS_ID`].
    /// - [`Error::NotFound`] if the specified parent does not exist.
    pub fn add_class(&mut self, id: u32, parent_id: u32, params: HtbClassParams) -> Result<usize> {
        // Find a free slot.
        let idx = self.alloc_slot()?;

        let is_root = parent_id == HTB_ROOT_CLASS_ID;
        if is_root && self.root_idx != usize::MAX {
            return Err(Error::AlreadyExists);
        }

        // Validate parent exists (if not root).
        let parent_level = if !is_root {
            let pidx = self.find_class(parent_id)?;
            // Register as child of parent.
            self.classes[pidx].add_child(id)?;
            self.nodes[pidx].level
        } else {
            0
        };

        self.classes[idx] = HtbClass::new(id, parent_id);
        self.classes[idx].params = params;
        self.classes[idx].tokens = params.burst as i64;
        self.classes[idx].ctokens = params.burst as i64;
        self.classes[idx].active = true;
        self.classes[idx].deficit = params.quantum as i32;

        self.nodes[idx] = HtbNode {
            class_idx: idx,
            level: if is_root { 0 } else { parent_level + 1 },
            priority: 0,
        };

        if is_root {
            self.root_idx = idx;
        }
        self.num_classes += 1;

        Ok(idx)
    }

    /// Remove a class from the qdisc by class ID.
    ///
    /// The class must have no children and an empty queue.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the class does not exist.
    /// - [`Error::Busy`] if the class has children or queued packets.
    pub fn remove_class(&mut self, id: u32) -> Result<()> {
        let idx = self.find_class(id)?;

        if self.classes[idx].num_children > 0 || self.classes[idx].q_count > 0 {
            return Err(Error::Busy);
        }

        // Remove from parent's child list.
        let parent_id = self.classes[idx].parent_id;
        if parent_id != HTB_ROOT_CLASS_ID {
            if let Ok(pidx) = self.find_class(parent_id) {
                let _ = self.classes[pidx].remove_child(id);
            }
        }

        if self.root_idx == idx {
            self.root_idx = usize::MAX;
        }

        self.classes[idx].active = false;
        self.num_classes -= 1;

        Ok(())
    }

    /// Change the parameters of an existing class.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the class does not exist.
    pub fn change_class(&mut self, id: u32, params: HtbClassParams) -> Result<()> {
        let idx = self.find_class(id)?;
        self.classes[idx].params = params;
        Ok(())
    }

    /// Enqueue a packet, classifying it to the appropriate class.
    ///
    /// The `class_id` identifies the target leaf class.  If the
    /// class is not a leaf, the packet is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the class does not exist.
    /// - [`Error::InvalidArgument`] if the class is not a leaf.
    /// - [`Error::OutOfMemory`] if the class queue is full.
    pub fn enqueue(&mut self, data: &[u8], class_id: u32) -> Result<()> {
        let idx = self.find_class(class_id)?;

        // Only leaf classes (no children) accept packets.
        if self.classes[idx].num_children > 0 {
            return Err(Error::InvalidArgument);
        }

        self.classes[idx].enqueue(data)
    }

    /// Dequeue the next packet using DRR among leaf classes, with
    /// parent token borrowing.
    ///
    /// Iterates through active leaf classes in round-robin order.
    /// A class can send if it has tokens or can borrow ctokens.
    /// Returns the packet length, or [`Error::WouldBlock`] if no
    /// class has sendable packets.
    pub fn dequeue(&mut self, out: &mut [u8; HTB_PACKET_SIZE]) -> Result<usize> {
        let total = MAX_HTB_CLASSES;
        let mut checked = 0;

        while checked < total {
            let idx = self.rr_cursor % MAX_HTB_CLASSES;
            self.rr_cursor = self.rr_cursor.wrapping_add(1);
            checked += 1;

            if !self.classes[idx].active || self.classes[idx].q_count == 0 {
                continue;
            }

            // Only dequeue from leaf classes.
            if self.classes[idx].num_children > 0 {
                continue;
            }

            // Check if class has tokens at guaranteed rate.
            if self.classes[idx].tokens > 0 {
                let len = self.classes[idx].dequeue(out)?;
                self.classes[idx].tokens -= len as i64;
                self.classes[idx].deficit -= len as i32;
                if self.classes[idx].deficit <= 0 {
                    self.classes[idx].deficit += self.classes[idx].params.quantum as i32;
                }
                return Ok(len);
            }

            // Try borrowing from parent via ceiling tokens.
            if self.classes[idx].ctokens > 0 {
                if self.try_borrow_from_parent(idx) {
                    let len = self.classes[idx].dequeue(out)?;
                    self.classes[idx].ctokens -= len as i64;
                    self.classes[idx].deficit -= len as i32;
                    if self.classes[idx].deficit <= 0 {
                        self.classes[idx].deficit += self.classes[idx].params.quantum as i32;
                    }
                    return Ok(len);
                }
                self.classes[idx].stats.overlimits += 1;
            } else {
                self.classes[idx].stats.overlimits += 1;
            }
        }

        Err(Error::WouldBlock)
    }

    /// Replenish tokens for all active classes.
    ///
    /// Called once per scheduling tick to add tokens at each class's
    /// configured rate and ceiling rate, capped at the burst size.
    pub fn tick(&mut self) {
        let mut i = 0;
        while i < MAX_HTB_CLASSES {
            if self.classes[i].active {
                let params = self.classes[i].params;
                // Replenish guaranteed tokens.
                self.classes[i].tokens += params.rate as i64;
                if self.classes[i].tokens > params.burst as i64 {
                    self.classes[i].tokens = params.burst as i64;
                }
                // Replenish ceiling tokens.
                self.classes[i].ctokens += params.ceil as i64;
                if self.classes[i].ctokens > params.burst as i64 {
                    self.classes[i].ctokens = params.burst as i64;
                }
            }
            i += 1;
        }
    }

    /// Return the statistics for a class.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the class does not exist.
    pub fn class_stats(&self, id: u32) -> Result<HtbStats> {
        let idx = self.find_class(id)?;
        Ok(self.classes[idx].stats)
    }

    /// Return a reference to a class by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the class does not exist.
    pub fn get_class(&self, id: u32) -> Result<&HtbClass> {
        let idx = self.find_class(id)?;
        Ok(&self.classes[idx])
    }

    /// Return a mutable reference to a class by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the class does not exist.
    pub fn get_class_mut(&mut self, id: u32) -> Result<&mut HtbClass> {
        let idx = self.find_class(id)?;
        Ok(&mut self.classes[idx])
    }

    /// Return the number of active classes.
    pub const fn class_count(&self) -> usize {
        self.num_classes
    }

    /// Try to borrow tokens from the parent of the class at `idx`.
    ///
    /// Returns `true` if the parent has tokens to lend.
    fn try_borrow_from_parent(&mut self, idx: usize) -> bool {
        let parent_id = self.classes[idx].parent_id;
        if parent_id == HTB_ROOT_CLASS_ID {
            return false;
        }

        // Find parent index.
        let mut pidx = usize::MAX;
        let mut i = 0;
        while i < MAX_HTB_CLASSES {
            if self.classes[i].active && self.classes[i].id == parent_id {
                pidx = i;
                break;
            }
            i += 1;
        }

        if pidx == usize::MAX {
            return false;
        }

        // Parent must have tokens to lend.
        self.classes[pidx].tokens > 0
    }

    /// Find the index of a class by its ID.
    fn find_class(&self, id: u32) -> Result<usize> {
        let mut i = 0;
        while i < MAX_HTB_CLASSES {
            if self.classes[i].active && self.classes[i].id == id {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Allocate a free class slot.
    fn alloc_slot(&self) -> Result<usize> {
        let mut i = 0;
        while i < MAX_HTB_CLASSES {
            if !self.classes[i].active {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }
}

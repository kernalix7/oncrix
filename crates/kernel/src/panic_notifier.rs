// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Panic notifier chain — callback registration for kernel panics.
//!
//! Provides an ordered chain of notifier blocks that are invoked
//! during a kernel panic. Each block carries a priority and a
//! callback identifier; the chain invokes all registered blocks
//! in priority order (lowest numeric value = highest priority).
//!
//! The notifier chain pattern is also usable for other kernel
//! events beyond panics (e.g., reboot, netdevice events).
//!
//! # Architecture
//!
//! ```text
//!  PanicNotifierList (specialized for panic events)
//!    └──► NotifierChain (32 blocks max, sorted by priority)
//!           └──► NotifierBlock
//!                  ├── name (64 bytes)
//!                  ├── priority (NotifierPriority)
//!                  ├── callback_id (u64)
//!                  └── enabled flag
//! ```
//!
//! Reference: Linux `kernel/notifier.c`,
//! `include/linux/notifier.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of notifier blocks in a chain.
const MAX_NOTIFIER_BLOCKS: usize = 32;

/// Maximum length of a notifier block name (bytes).
const MAX_NAME_LEN: usize = 64;

/// Return value from a notifier callback indicating the chain
/// should stop (no further blocks are called).
pub const NOTIFY_STOP: u32 = 1;

/// Return value from a notifier callback indicating the chain
/// should continue to the next block.
pub const NOTIFY_OK: u32 = 0;

/// Return value indicating a callback encountered an error but
/// the chain should continue.
pub const NOTIFY_BAD: u32 = 2;

// -------------------------------------------------------------------
// NotifierPriority
// -------------------------------------------------------------------

/// Priority levels for notifier blocks.
///
/// Blocks with lower numeric priority values are called first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum NotifierPriority {
    /// Called first — critical system components.
    Highest = 0,
    /// High priority.
    High = 64,
    /// Default priority for most subscribers.
    Default = 128,
    /// Low priority.
    Low = 192,
    /// Called last — non-critical cleanup.
    Lowest = 255,
}

impl NotifierPriority {
    /// Return the raw numeric priority value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

// -------------------------------------------------------------------
// NotifierBlock
// -------------------------------------------------------------------

/// A single notifier block registered in a chain.
///
/// Each block has a human-readable name, a priority that determines
/// call order, and a `callback_id` that the dispatcher uses to
/// look up the actual callback function.
#[derive(Debug, Clone, Copy)]
pub struct NotifierBlock {
    /// Human-readable name of this notifier (e.g., "crashdump").
    name: [u8; MAX_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Priority — lower values are called first.
    pub priority: NotifierPriority,
    /// Opaque identifier for the callback function.
    pub callback_id: u64,
    /// Whether this block is enabled. Disabled blocks are skipped
    /// during chain invocation but remain registered.
    pub enabled: bool,
    /// Whether this slot is occupied.
    in_use: bool,
}

/// An empty notifier block for array initialization.
const EMPTY_NOTIFIER_BLOCK: NotifierBlock = NotifierBlock {
    name: [0; MAX_NAME_LEN],
    name_len: 0,
    priority: NotifierPriority::Default,
    callback_id: 0,
    enabled: false,
    in_use: false,
};

impl NotifierBlock {
    /// Create a new notifier block.
    pub fn new(name: &[u8], priority: NotifierPriority, callback_id: u64) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut block = EMPTY_NOTIFIER_BLOCK;
        let nlen = name.len().min(MAX_NAME_LEN);
        block.name[..nlen].copy_from_slice(&name[..nlen]);
        block.name_len = nlen;
        block.priority = priority;
        block.callback_id = callback_id;
        block.enabled = true;
        block.in_use = true;
        Ok(block)
    }

    /// Return the name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// -------------------------------------------------------------------
// NotifierResult
// -------------------------------------------------------------------

/// Result of invoking a notifier chain.
#[derive(Debug, Clone, Copy)]
pub struct NotifierResult {
    /// Number of blocks that were called.
    pub called: usize,
    /// Number of blocks that returned `NOTIFY_STOP`.
    pub stopped: bool,
    /// Callback ID that caused the stop, if any.
    pub stopped_by: u64,
}

impl NotifierResult {
    /// Create a default result (no blocks called, not stopped).
    const fn empty() -> Self {
        Self {
            called: 0,
            stopped: false,
            stopped_by: 0,
        }
    }
}

// -------------------------------------------------------------------
// NotifierChain
// -------------------------------------------------------------------

/// Ordered chain of notifier blocks, sorted by priority.
///
/// When the chain is called, blocks are invoked in priority order
/// (lowest numeric value first). If any block returns
/// [`NOTIFY_STOP`], the chain stops and no further blocks are
/// called.
pub struct NotifierChain {
    /// Registered notifier blocks.
    blocks: [NotifierBlock; MAX_NOTIFIER_BLOCKS],
    /// Number of registered (in_use) blocks.
    count: usize,
}

impl Default for NotifierChain {
    fn default() -> Self {
        Self::new()
    }
}

impl NotifierChain {
    /// Create an empty notifier chain.
    pub const fn new() -> Self {
        Self {
            blocks: [EMPTY_NOTIFIER_BLOCK; MAX_NOTIFIER_BLOCKS],
            count: 0,
        }
    }

    /// Register a notifier block in the chain.
    ///
    /// The block is inserted in priority order. Returns the slot
    /// index on success, or an error if the chain is full or a
    /// block with the same `callback_id` already exists.
    pub fn register(&mut self, block: NotifierBlock) -> Result<usize> {
        if self.count >= MAX_NOTIFIER_BLOCKS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate callback_id.
        for b in &self.blocks {
            if b.in_use && b.callback_id == block.callback_id {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        for (idx, slot) in self.blocks.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = block;
                self.count += 1;
                self.sort_by_priority();
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister a notifier block by callback ID.
    pub fn unregister(&mut self, callback_id: u64) -> Result<()> {
        for slot in self.blocks.iter_mut() {
            if slot.in_use && slot.callback_id == callback_id {
                *slot = EMPTY_NOTIFIER_BLOCK;
                self.count = self.count.saturating_sub(1);
                self.sort_by_priority();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Invoke the notifier chain.
    ///
    /// Calls each enabled block in priority order. The
    /// `evaluate_callback` closure receives the `callback_id` and
    /// must return a `NOTIFY_*` constant. If any callback returns
    /// [`NOTIFY_STOP`], the chain stops immediately.
    pub fn call_chain<F>(&self, mut evaluate_callback: F) -> NotifierResult
    where
        F: FnMut(u64) -> u32,
    {
        let mut result = NotifierResult::empty();

        for block in &self.blocks {
            if !block.in_use || !block.enabled {
                continue;
            }
            result.called += 1;
            let ret = evaluate_callback(block.callback_id);
            if ret == NOTIFY_STOP {
                result.stopped = true;
                result.stopped_by = block.callback_id;
                break;
            }
        }

        result
    }

    /// Return the number of registered blocks.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the block at the given index, if it is in use.
    pub fn get(&self, index: usize) -> Option<&NotifierBlock> {
        if index < MAX_NOTIFIER_BLOCKS && self.blocks[index].in_use {
            Some(&self.blocks[index])
        } else {
            None
        }
    }

    /// Sort blocks by priority, placing unused slots at the end.
    fn sort_by_priority(&mut self) {
        // Simple insertion sort — chain is small (max 32 entries).
        for i in 1..MAX_NOTIFIER_BLOCKS {
            let mut j = i;
            while j > 0 && should_swap(&self.blocks[j - 1], &self.blocks[j]) {
                self.blocks.swap(j - 1, j);
                j -= 1;
            }
        }
    }
}

/// Returns `true` if `a` should be placed after `b` in the sorted order.
///
/// Active blocks come before inactive blocks; among active blocks,
/// lower priority values come first.
fn should_swap(a: &NotifierBlock, b: &NotifierBlock) -> bool {
    match (a.in_use, b.in_use) {
        // Both active: sort by priority (lower value first).
        (true, true) => a.priority > b.priority,
        // Active block should come before inactive.
        (false, true) => true,
        // Already in correct order.
        (true, false) | (false, false) => false,
    }
}

impl core::fmt::Debug for NotifierChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifierChain")
            .field("count", &self.count)
            .field("capacity", &MAX_NOTIFIER_BLOCKS)
            .finish()
    }
}

// -------------------------------------------------------------------
// PanicNotifierList
// -------------------------------------------------------------------

/// Specialized notifier chain for kernel panic events.
///
/// Wraps a [`NotifierChain`] with panic-specific semantics:
/// - The chain is invoked during a kernel panic.
/// - Callbacks should be minimal (e.g., flush logs, notify
///   watchdog, save crash dump).
/// - Uses atomic-like call semantics (no locks, as the system
///   may be in an inconsistent state during a panic).
pub struct PanicNotifierList {
    /// The underlying notifier chain.
    pub chain: NotifierChain,
    /// Whether a panic is currently being processed.
    pub in_panic: bool,
}

impl Default for PanicNotifierList {
    fn default() -> Self {
        Self::new()
    }
}

impl PanicNotifierList {
    /// Create a new, empty panic notifier list.
    pub const fn new() -> Self {
        Self {
            chain: NotifierChain::new(),
            in_panic: false,
        }
    }

    /// Register a panic notifier block.
    pub fn register(&mut self, block: NotifierBlock) -> Result<usize> {
        self.chain.register(block)
    }

    /// Unregister a panic notifier block by callback ID.
    pub fn unregister(&mut self, callback_id: u64) -> Result<()> {
        self.chain.unregister(callback_id)
    }

    /// Invoke the panic notifier chain.
    ///
    /// Sets `in_panic` to `true` before calling the chain. The
    /// `evaluate_callback` closure is called for each registered,
    /// enabled block in priority order.
    ///
    /// This is the "atomic notifier call chain" — it must not
    /// acquire any locks or sleep, as the kernel may be in an
    /// inconsistent state.
    pub fn atomic_notifier_call_chain<F>(&mut self, evaluate_callback: F) -> NotifierResult
    where
        F: FnMut(u64) -> u32,
    {
        self.in_panic = true;
        self.chain.call_chain(evaluate_callback)
    }

    /// Return the number of registered notifier blocks.
    pub fn count(&self) -> usize {
        self.chain.count()
    }
}

impl core::fmt::Debug for PanicNotifierList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PanicNotifierList")
            .field("chain", &self.chain)
            .field("in_panic", &self.in_panic)
            .finish()
    }
}

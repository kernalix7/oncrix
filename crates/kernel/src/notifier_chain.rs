// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Notifier chain infrastructure.
//!
//! Provides a priority-sorted chain of callback functions that are
//! invoked in order when an event occurs. Modeled after Linux's
//! `kernel/notifier.c` and `include/linux/notifier.h`.
//!
//! # Architecture
//!
//! ```text
//! NotifierChainManager
//! ├── chains: [NotifierChain; MAX_CHAINS]
//! │   ├── name, chain_type
//! │   └── blocks: [NotifierBlock; MAX_BLOCKS_PER_CHAIN]
//! │       ├── priority (higher = called first)
//! │       └── callback fn pointer
//! └── stats: NotifierStats
//! ```
//!
//! # Chain Types
//!
//! | Type | Description |
//! |------|-------------|
//! | Blocking | Callbacks may sleep (process context) |
//! | Atomic | Callbacks must not sleep (interrupt context) |
//! | Raw | No locking, caller responsible |
//!
//! # Notification Return Values
//!
//! Callbacks return a [`NotifierAction`] to control chain
//! traversal. `Stop` halts further callbacks; `Done` and `Ok`
//! continue to the next block.
//!
//! # Reference
//!
//! Linux `kernel/notifier.c`, `include/linux/notifier.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of notifier chains.
const MAX_CHAINS: usize = 64;

/// Maximum number of blocks (callbacks) per chain.
const MAX_BLOCKS_PER_CHAIN: usize = 32;

/// Maximum chain name length in bytes.
const MAX_NAME_LEN: usize = 32;

/// Default callback priority.
const _DEFAULT_PRIORITY: i32 = 0;

// ── NotifierAction ──────────────────────────────────────────

/// Return value from a notifier callback controlling chain
/// traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierAction {
    /// Callback processed successfully — continue chain.
    Done,
    /// Callback processed, notification acknowledged — continue.
    Ok,
    /// Stop calling further callbacks in the chain.
    Stop,
    /// Callback failed — continue chain but record error.
    Bad,
}

impl NotifierAction {
    /// Whether this action stops the chain.
    pub fn stops_chain(self) -> bool {
        matches!(self, Self::Stop)
    }
}

// ── ChainType ───────────────────────────────────────────────

/// Type of notifier chain determining synchronisation guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainType {
    /// Blocking notifier chain — callbacks may sleep.
    #[default]
    Blocking,
    /// Atomic notifier chain — callbacks must not sleep.
    Atomic,
    /// Raw notifier chain — no locking, caller-managed.
    Raw,
}

impl ChainType {
    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Atomic => "atomic",
            Self::Raw => "raw",
        }
    }
}

// ── NotifierCallback ────────────────────────────────────────

/// Callback function signature for notifier blocks.
///
/// Parameters: (event_type, event_data) -> NotifierAction
pub type NotifierCallback = fn(u64, u64) -> NotifierAction;

// ── NotifierBlock ───────────────────────────────────────────

/// A single callback registration in a notifier chain.
///
/// Blocks are sorted by priority (higher numeric value = called
/// first). Within the same priority, insertion order is preserved.
#[derive(Clone, Copy)]
pub struct NotifierBlock {
    /// Unique block identifier.
    id: u32,
    /// Callback function.
    callback: Option<NotifierCallback>,
    /// Priority (higher = called first, can be negative).
    priority: i32,
    /// Whether this slot is occupied.
    active: bool,
}

impl core::fmt::Debug for NotifierBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifierBlock")
            .field("id", &self.id)
            .field("priority", &self.priority)
            .field("active", &self.active)
            .finish()
    }
}

impl NotifierBlock {
    /// Create an empty notifier block.
    const fn empty() -> Self {
        Self {
            id: 0,
            callback: None,
            priority: 0,
            active: false,
        }
    }

    /// Returns the block ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Whether this block is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ── CallChainResult ─────────────────────────────────────────

/// Result of calling a notifier chain.
#[derive(Debug, Clone, Copy)]
pub struct CallChainResult {
    /// Number of callbacks invoked.
    pub called: u32,
    /// Last action returned by a callback.
    pub last_action: NotifierAction,
    /// Whether the chain was stopped early.
    pub stopped: bool,
    /// Number of callbacks that returned Bad.
    pub errors: u32,
}

impl CallChainResult {
    /// Create a default (no callbacks called) result.
    pub const fn empty() -> Self {
        Self {
            called: 0,
            last_action: NotifierAction::Done,
            stopped: false,
            errors: 0,
        }
    }
}

// ── NotifierChain ───────────────────────────────────────────

/// A single notifier chain containing priority-sorted callbacks.
pub struct NotifierChain {
    /// Chain name.
    name: [u8; MAX_NAME_LEN],
    /// Valid length of name.
    name_len: usize,
    /// Chain type.
    chain_type: ChainType,
    /// Registered blocks, sorted by priority descending.
    blocks: [NotifierBlock; MAX_BLOCKS_PER_CHAIN],
    /// Number of active blocks.
    block_count: usize,
    /// Total times this chain has been called.
    call_count: u64,
    /// Whether this chain slot is in use.
    active: bool,
    /// Unique chain identifier.
    id: u32,
    /// Next block ID.
    next_block_id: u32,
}

impl NotifierChain {
    /// Create an empty chain.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            chain_type: ChainType::Blocking,
            blocks: [NotifierBlock::empty(); MAX_BLOCKS_PER_CHAIN],
            block_count: 0,
            call_count: 0,
            active: false,
            id: 0,
            next_block_id: 1,
        }
    }

    /// Return the chain name.
    pub fn name_str(&self) -> &str {
        let len = self.name_len.min(MAX_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Return the chain type.
    pub fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    /// Return number of active blocks.
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    /// Return total call count.
    pub fn call_count(&self) -> u64 {
        self.call_count
    }

    /// Register a notifier block with a given priority.
    ///
    /// The block is inserted in priority-sorted order (descending).
    /// Returns the assigned block ID.
    pub fn register(&mut self, callback: NotifierCallback, priority: i32) -> Result<u32> {
        let slot = self
            .blocks
            .iter()
            .position(|b| !b.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_block_id;
        self.next_block_id = self.next_block_id.wrapping_add(1);

        self.blocks[slot] = NotifierBlock {
            id,
            callback: Some(callback),
            priority,
            active: true,
        };
        self.block_count += 1;

        // Re-sort by priority descending (simple insertion sort).
        self.sort_blocks();

        Ok(id)
    }

    /// Unregister a notifier block by ID.
    pub fn unregister(&mut self, block_id: u32) -> Result<()> {
        let block = self
            .blocks
            .iter_mut()
            .find(|b| b.active && b.id == block_id)
            .ok_or(Error::NotFound)?;
        block.active = false;
        block.callback = None;
        self.block_count = self.block_count.saturating_sub(1);
        Ok(())
    }

    /// Call all registered blocks in priority order.
    ///
    /// Traverses the chain from highest to lowest priority.
    /// Stops if a callback returns [`NotifierAction::Stop`].
    pub fn call_chain(&mut self, event_type: u64, event_data: u64) -> CallChainResult {
        self.call_count = self.call_count.saturating_add(1);
        let mut result = CallChainResult::empty();

        for block in &self.blocks {
            if !block.active {
                continue;
            }
            if let Some(cb) = block.callback {
                let action = cb(event_type, event_data);
                result.called += 1;
                result.last_action = action;

                if action == NotifierAction::Bad {
                    result.errors += 1;
                }
                if action.stops_chain() {
                    result.stopped = true;
                    break;
                }
            }
        }

        result
    }

    /// Sort blocks by priority descending.
    fn sort_blocks(&mut self) {
        // Simple bubble sort — MAX_BLOCKS_PER_CHAIN is small.
        for i in 0..MAX_BLOCKS_PER_CHAIN {
            for j in (i + 1)..MAX_BLOCKS_PER_CHAIN {
                let pri_i = if self.blocks[i].active {
                    self.blocks[i].priority
                } else {
                    i32::MIN
                };
                let pri_j = if self.blocks[j].active {
                    self.blocks[j].priority
                } else {
                    i32::MIN
                };
                if pri_j > pri_i {
                    self.blocks.swap(i, j);
                }
            }
        }
    }
}

// ── NotifierStats ───────────────────────────────────────────

/// Global statistics for the notifier subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotifierStats {
    /// Total chains created.
    pub chains_created: u64,
    /// Total blocks registered.
    pub blocks_registered: u64,
    /// Total blocks unregistered.
    pub blocks_unregistered: u64,
    /// Total chain calls.
    pub total_calls: u64,
    /// Total callbacks invoked.
    pub total_callbacks: u64,
    /// Total chain stops.
    pub total_stops: u64,
}

impl NotifierStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            chains_created: 0,
            blocks_registered: 0,
            blocks_unregistered: 0,
            total_calls: 0,
            total_callbacks: 0,
            total_stops: 0,
        }
    }
}

// ── NotifierChainManager ────────────────────────────────────

/// Central manager for all notifier chains.
pub struct NotifierChainManager {
    /// Registered chains.
    chains: [NotifierChain; MAX_CHAINS],
    /// Number of active chains.
    chain_count: usize,
    /// Next chain ID.
    next_chain_id: u32,
    /// Statistics.
    stats: NotifierStats,
}

impl NotifierChainManager {
    /// Create a new, empty manager.
    pub const fn new() -> Self {
        Self {
            chains: [const { NotifierChain::empty() }; MAX_CHAINS],
            chain_count: 0,
            next_chain_id: 1,
            stats: NotifierStats::new(),
        }
    }

    /// Create a new notifier chain. Returns the chain ID.
    pub fn create_chain(&mut self, name: &str, chain_type: ChainType) -> Result<u32> {
        let slot = self
            .chains
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_chain_id;
        self.next_chain_id = self.next_chain_id.wrapping_add(1);

        self.chains[slot] = NotifierChain::empty();
        self.chains[slot].id = id;
        self.chains[slot].chain_type = chain_type;
        self.chains[slot].active = true;

        let copy_len = name.len().min(MAX_NAME_LEN);
        self.chains[slot].name[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        self.chains[slot].name_len = copy_len;

        self.chain_count += 1;
        self.stats.chains_created += 1;
        Ok(id)
    }

    /// Destroy a notifier chain by ID.
    pub fn destroy_chain(&mut self, chain_id: u32) -> Result<()> {
        let chain = self
            .chains
            .iter_mut()
            .find(|c| c.active && c.id == chain_id)
            .ok_or(Error::NotFound)?;
        chain.active = false;
        self.chain_count = self.chain_count.saturating_sub(1);
        Ok(())
    }

    /// Register a callback on a chain. Returns the block ID.
    pub fn register(
        &mut self,
        chain_id: u32,
        callback: NotifierCallback,
        priority: i32,
    ) -> Result<u32> {
        let chain = self
            .chains
            .iter_mut()
            .find(|c| c.active && c.id == chain_id)
            .ok_or(Error::NotFound)?;
        let block_id = chain.register(callback, priority)?;
        self.stats.blocks_registered += 1;
        Ok(block_id)
    }

    /// Unregister a callback from a chain.
    pub fn unregister(&mut self, chain_id: u32, block_id: u32) -> Result<()> {
        let chain = self
            .chains
            .iter_mut()
            .find(|c| c.active && c.id == chain_id)
            .ok_or(Error::NotFound)?;
        chain.unregister(block_id)?;
        self.stats.blocks_unregistered += 1;
        Ok(())
    }

    /// Call a notifier chain with the given event.
    pub fn call_chain(
        &mut self,
        chain_id: u32,
        event_type: u64,
        event_data: u64,
    ) -> Result<CallChainResult> {
        let chain = self
            .chains
            .iter_mut()
            .find(|c| c.active && c.id == chain_id)
            .ok_or(Error::NotFound)?;
        let result = chain.call_chain(event_type, event_data);
        self.stats.total_calls += 1;
        self.stats.total_callbacks += result.called as u64;
        if result.stopped {
            self.stats.total_stops += 1;
        }
        Ok(result)
    }

    /// Find a chain by name.
    pub fn find_chain_by_name(&self, name: &str) -> Option<u32> {
        self.chains
            .iter()
            .find(|c| c.active && c.name_str() == name)
            .map(|c| c.id)
    }

    /// Get a reference to a chain by ID.
    pub fn get_chain(&self, chain_id: u32) -> Result<&NotifierChain> {
        self.chains
            .iter()
            .find(|c| c.active && c.id == chain_id)
            .ok_or(Error::NotFound)
    }

    /// Return the number of active chains.
    pub fn chain_count(&self) -> usize {
        self.chain_count
    }

    /// Return global statistics.
    pub fn stats(&self) -> &NotifierStats {
        &self.stats
    }
}

impl Default for NotifierChainManager {
    fn default() -> Self {
        Self::new()
    }
}

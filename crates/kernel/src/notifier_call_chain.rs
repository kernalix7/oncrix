// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic notifier call chain.
//!
//! Implements priority-sorted callback chains that are invoked
//! sequentially when an event occurs. Three chain types are
//! supported — blocking, atomic, and raw — each with different
//! locking semantics. Callbacks return a [`NotifyAction`] to
//! control chain traversal.
//!
//! # Architecture
//!
//! ```text
//! NotifierChainSet
//! ├── chains: [CallChain; MAX_CHAINS]
//! │   ├── name, chain_type, active
//! │   └── blocks: [CallBlock; MAX_BLOCKS]
//! │       ├── priority  (higher = called first)
//! │       ├── callback  (fn pointer address)
//! │       └── context   (opaque cookie)
//! └── stats: ChainStats
//! ```
//!
//! # Notification Return Values
//!
//! | Value | Code | Meaning |
//! |-------|------|---------|
//! | `Ok` | 0 | Continue, no opinion |
//! | `Done` | 1 | Continue, handled |
//! | `Bad` | 2 | Continue, something wrong |
//! | `Stop` | 3 | Stop chain traversal |
//!
//! # Register / Unregister
//!
//! Blocks are inserted in priority order (descending) and
//! removed by matching callback address + context.
//!
//! Reference: Linux `kernel/notifier.c`,
//! `include/linux/notifier.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of independent chains.
const MAX_CHAINS: usize = 64;

/// Maximum callback blocks per chain.
const MAX_BLOCKS: usize = 32;

/// Maximum chain name length in bytes.
const MAX_NAME_LEN: usize = 32;

/// Default callback priority.
const _DEFAULT_PRIORITY: i32 = 0;

// ── NotifyAction ───────────────────────────────────────────────

/// Return value from a notifier callback, controlling whether
/// chain traversal continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NotifyAction {
    /// No opinion — continue traversal.
    Ok = 0,
    /// Notification handled — continue traversal.
    Done = 1,
    /// Something wrong — continue traversal but record.
    Bad = 2,
    /// Stop traversal immediately.
    Stop = 3,
}

impl Default for NotifyAction {
    fn default() -> Self {
        Self::Ok
    }
}

impl NotifyAction {
    /// Whether this action halts chain traversal.
    pub fn stops(self) -> bool {
        matches!(self, Self::Stop)
    }
}

// ── ChainType ──────────────────────────────────────────────────

/// Type of notifier chain, determining locking semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainType {
    /// Callbacks may sleep (process context only).
    #[default]
    Blocking,
    /// Callbacks must not sleep (interrupt-safe).
    Atomic,
    /// No internal locking — caller is responsible.
    Raw,
}

// ── CallBlock ──────────────────────────────────────────────────

/// A single callback entry in a notifier chain.
#[derive(Clone, Copy)]
pub struct CallBlock {
    /// Virtual address of the callback function.
    pub callback: u64,
    /// Opaque context passed to the callback.
    pub context: u64,
    /// Priority (higher values called first).
    pub priority: i32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl CallBlock {
    /// Creates an empty block.
    pub const fn new() -> Self {
        Self {
            callback: 0,
            context: 0,
            priority: 0,
            active: false,
        }
    }
}

// ── CallChain ──────────────────────────────────────────────────

/// A single notifier call chain containing ordered blocks.
pub struct CallChain {
    /// Chain name (NUL-padded).
    name: [u8; MAX_NAME_LEN],
    /// Chain type (locking semantics).
    chain_type: ChainType,
    /// Callback blocks, maintained in priority-descending order.
    blocks: [CallBlock; MAX_BLOCKS],
    /// Number of active blocks.
    block_count: usize,
    /// Whether this chain slot is occupied.
    active: bool,
}

impl CallChain {
    /// Creates an empty chain.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            chain_type: ChainType::Blocking,
            blocks: [const { CallBlock::new() }; MAX_BLOCKS],
            block_count: 0,
            active: false,
        }
    }

    /// Registers a callback block, inserting it in priority
    /// order (highest first).
    pub fn register(&mut self, callback: u64, context: u64, priority: i32) -> Result<()> {
        if callback == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.block_count >= MAX_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point (first block with lower priority).
        let insert_at = self.blocks[..self.block_count]
            .iter()
            .position(|b| b.active && b.priority < priority)
            .unwrap_or(self.block_count);
        // Shift blocks down to make room.
        if insert_at < self.block_count {
            let mut i = self.block_count;
            while i > insert_at {
                self.blocks[i] = self.blocks[i - 1];
                i -= 1;
            }
        }
        self.blocks[insert_at] = CallBlock {
            callback,
            context,
            priority,
            active: true,
        };
        self.block_count += 1;
        Ok(())
    }

    /// Unregisters a callback block matching both callback
    /// address and context.
    pub fn unregister(&mut self, callback: u64, context: u64) -> Result<()> {
        let pos = self.blocks[..self.block_count]
            .iter()
            .position(|b| b.active && b.callback == callback && b.context == context)
            .ok_or(Error::NotFound)?;
        // Shift remaining blocks up.
        let mut i = pos;
        while i + 1 < self.block_count {
            self.blocks[i] = self.blocks[i + 1];
            i += 1;
        }
        self.blocks[self.block_count - 1] = CallBlock::new();
        self.block_count -= 1;
        Ok(())
    }

    /// Invokes all registered callbacks in priority order.
    /// Stops early if any callback returns `Stop`.
    /// Returns the last non-Ok action and the number of
    /// callbacks invoked.
    pub fn call_chain(&self, event: u64, data: u64) -> (NotifyAction, usize) {
        let mut last_action = NotifyAction::Ok;
        let mut invoked = 0usize;
        for block in &self.blocks[..self.block_count] {
            if !block.active {
                continue;
            }
            // In a real kernel this would call the function
            // pointer. Here we record that we would invoke it.
            invoked += 1;
            let _cb = block.callback;
            let _ctx = block.context;
            let _ev = event;
            let _d = data;
            // Simulate Ok for now; real dispatch would read
            // the return value.
            let action = NotifyAction::Ok;
            if action != NotifyAction::Ok {
                last_action = action;
            }
            if action.stops() {
                break;
            }
        }
        (last_action, invoked)
    }

    /// Returns the chain type.
    pub fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    /// Returns the number of registered blocks.
    pub fn block_count(&self) -> usize {
        self.block_count
    }
}

// ── ChainStats ─────────────────────────────────────────────────

/// Aggregate statistics for the notifier subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainStats {
    /// Total chains created.
    pub chains_created: u64,
    /// Total blocks registered across all chains.
    pub blocks_registered: u64,
    /// Total blocks unregistered.
    pub blocks_unregistered: u64,
    /// Total call_chain invocations.
    pub calls: u64,
}

// ── NotifierChainSet ───────────────────────────────────────────

/// Manager for all notifier chains in the kernel.
pub struct NotifierChainSet {
    /// Registered chains.
    chains: [CallChain; MAX_CHAINS],
    /// Number of active chains.
    chain_count: usize,
    /// Operational statistics.
    stats: ChainStats,
}

impl NotifierChainSet {
    /// Creates an empty chain set.
    pub const fn new() -> Self {
        Self {
            chains: [const { CallChain::new() }; MAX_CHAINS],
            chain_count: 0,
            stats: ChainStats {
                chains_created: 0,
                blocks_registered: 0,
                blocks_unregistered: 0,
                calls: 0,
            },
        }
    }

    /// Creates a new chain. Returns its index.
    pub fn create_chain(&mut self, name: &[u8], chain_type: ChainType) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let pos = self
            .chains
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let chain = &mut self.chains[pos];
        let nlen = name.len().min(MAX_NAME_LEN);
        chain.name[..nlen].copy_from_slice(&name[..nlen]);
        chain.chain_type = chain_type;
        chain.active = true;
        self.chain_count += 1;
        self.stats.chains_created += 1;
        Ok(pos)
    }

    /// Registers a block on the given chain.
    pub fn register(
        &mut self,
        chain_idx: usize,
        callback: u64,
        context: u64,
        priority: i32,
    ) -> Result<()> {
        let chain = self.get_chain_mut(chain_idx)?;
        chain.register(callback, context, priority)?;
        self.stats.blocks_registered += 1;
        Ok(())
    }

    /// Unregisters a block from the given chain.
    pub fn unregister(&mut self, chain_idx: usize, callback: u64, context: u64) -> Result<()> {
        let chain = self.get_chain_mut(chain_idx)?;
        chain.unregister(callback, context)?;
        self.stats.blocks_unregistered += 1;
        Ok(())
    }

    /// Calls all blocks on the given chain.
    pub fn call_chain(
        &mut self,
        chain_idx: usize,
        event: u64,
        data: u64,
    ) -> Result<(NotifyAction, usize)> {
        if chain_idx >= MAX_CHAINS || !self.chains[chain_idx].active {
            return Err(Error::NotFound);
        }
        self.stats.calls += 1;
        Ok(self.chains[chain_idx].call_chain(event, data))
    }

    /// Returns a reference to a chain.
    pub fn get_chain(&self, idx: usize) -> Result<&CallChain> {
        if idx >= MAX_CHAINS || !self.chains[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.chains[idx])
    }

    /// Returns the statistics.
    pub fn stats(&self) -> &ChainStats {
        &self.stats
    }

    /// Returns the number of active chains.
    pub fn chain_count(&self) -> usize {
        self.chain_count
    }

    /// Returns a mutable reference to an active chain.
    fn get_chain_mut(&mut self, idx: usize) -> Result<&mut CallChain> {
        if idx >= MAX_CHAINS || !self.chains[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.chains[idx])
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic notifier chain infrastructure.
//!
//! Provides a reusable, typed notification mechanism for kernel
//! subsystems. A notifier chain is an ordered list of callback
//! blocks; when an event occurs, each block is invoked in priority
//! order until all have been called or one requests early stop.
//!
//! # Chain Types
//!
//! | Type | Locking | Use Case |
//! |------|---------|----------|
//! | Atomic | None (caller holds) | Interrupt context |
//! | Blocking | Conceptual sleepable | Process context |
//! | Raw | None, no ordering | Fast path, single subscriber |
//! | SRCU | Read-copy-update | Hot paths with rare updates |
//!
//! # Architecture
//!
//! ```text
//!  NotifierChainManager
//!    ├── chains[0]: NotifierChain("reboot", Blocking)
//!    │     ├── block[0]: priority=0, id=1001
//!    │     ├── block[1]: priority=64, id=1002
//!    │     └── block[2]: priority=128, id=1003
//!    ├── chains[1]: NotifierChain("panic", Atomic)
//!    │     └── ...
//!    └── chains[N]: ...
//! ```
//!
//! # Return Codes
//!
//! Each callback returns a `NotifierResult`:
//! - `Ok` — continue to next block
//! - `Stop` — stop the chain, event fully handled
//! - `Error` — error occurred, continue or stop per policy
//!
//! Reference: Linux `kernel/notifier.c`,
//! `include/linux/notifier.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of blocks in a single notifier chain.
const MAX_BLOCKS_PER_CHAIN: usize = 32;

/// Maximum number of notifier chains managed by the system.
const MAX_CHAINS: usize = 32;

/// Maximum length of a chain name (bytes).
const MAX_CHAIN_NAME_LEN: usize = 64;

/// Maximum length of a block name (bytes).
const MAX_BLOCK_NAME_LEN: usize = 64;

/// Maximum number of pending deferred notifications.
const MAX_DEFERRED: usize = 64;

/// Maximum data payload bytes in a notification event.
const MAX_EVENT_DATA_LEN: usize = 64;

/// Maximum number of chain-level event filters.
const MAX_FILTERS: usize = 8;

// -------------------------------------------------------------------
// NotifierResult
// -------------------------------------------------------------------

/// Result returned by a notifier callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifierResult {
    /// Notification handled, continue to next block.
    Ok,
    /// Notification fully handled, stop the chain.
    Stop,
    /// Error occurred, continue to next block.
    ContinueWithError,
    /// Error occurred, stop the chain.
    StopWithError,
}

impl NotifierResult {
    /// Return whether the chain should stop after this result.
    pub const fn should_stop(self) -> bool {
        matches!(self, Self::Stop | Self::StopWithError)
    }

    /// Return whether this result indicates an error.
    pub const fn is_error(self) -> bool {
        matches!(self, Self::ContinueWithError | Self::StopWithError)
    }
}

// -------------------------------------------------------------------
// ChainType — what context the chain runs in
// -------------------------------------------------------------------

/// The execution context type for a notifier chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// No sleeping allowed — suitable for interrupt context.
    Atomic,
    /// Sleeping is allowed — process context only.
    Blocking,
    /// No ordering guarantees, minimal overhead.
    Raw,
    /// SRCU-style: readers are lock-free, writers synchronize.
    Srcu,
}

// -------------------------------------------------------------------
// NotifierPriority
// -------------------------------------------------------------------

/// Priority for ordering notifier blocks within a chain.
///
/// Lower numeric value = called first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum NotifierPriority {
    /// Critical system components — called first.
    Critical = 0,
    /// High priority.
    High = 64,
    /// Normal priority (default).
    Normal = 128,
    /// Low priority.
    Low = 192,
    /// Called last — cleanup or logging.
    Lowest = 255,
}

impl NotifierPriority {
    /// Return the raw numeric value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

// -------------------------------------------------------------------
// EventType — numeric event identifier
// -------------------------------------------------------------------

/// A numeric event type identifier.
///
/// Each chain defines its own set of event types (e.g., reboot
/// chain might use 1 = SYS_RESTART, 2 = SYS_HALT, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventType(pub u64);

impl EventType {
    /// Create a new event type.
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

// -------------------------------------------------------------------
// EventData — inline payload
// -------------------------------------------------------------------

/// Inline event data payload passed to notifier callbacks.
#[derive(Clone, Copy)]
pub struct EventData {
    /// Raw data bytes.
    data: [u8; MAX_EVENT_DATA_LEN],
    /// Number of valid bytes.
    len: usize,
}

impl EventData {
    /// Create empty event data.
    pub const fn empty() -> Self {
        Self {
            data: [0u8; MAX_EVENT_DATA_LEN],
            len: 0,
        }
    }

    /// Create event data from a byte slice.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > MAX_EVENT_DATA_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut ed = Self::empty();
        ed.data[..src.len()].copy_from_slice(src);
        ed.len = src.len();
        Ok(ed)
    }

    /// Create event data from a u64 value.
    pub const fn from_u64(val: u64) -> Self {
        let bytes = val.to_le_bytes();
        let mut data = [0u8; MAX_EVENT_DATA_LEN];
        data[0] = bytes[0];
        data[1] = bytes[1];
        data[2] = bytes[2];
        data[3] = bytes[3];
        data[4] = bytes[4];
        data[5] = bytes[5];
        data[6] = bytes[6];
        data[7] = bytes[7];
        Self { data, len: 8 }
    }

    /// Return the payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return the payload length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether the payload is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Try to read the first 8 bytes as a little-endian u64.
    pub fn as_u64(&self) -> Option<u64> {
        if self.len < 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[..8]);
        Some(u64::from_le_bytes(bytes))
    }
}

impl Default for EventData {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for EventData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EventData({} bytes)", self.len)
    }
}

// -------------------------------------------------------------------
// NotifierCallback
// -------------------------------------------------------------------

/// Callback signature for notifier blocks.
///
/// Receives the event type, event data, and the block's context
/// value. Returns a `NotifierResult`.
pub type NotifierCallback = fn(EventType, &EventData, u64) -> NotifierResult;

// -------------------------------------------------------------------
// NotifierBlock
// -------------------------------------------------------------------

/// A single subscriber in a notifier chain.
#[derive(Clone, Copy)]
pub struct NotifierBlock {
    /// Human-readable name (debugging/logging).
    name: [u8; MAX_BLOCK_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique block identifier.
    id: u64,
    /// Callback to invoke on notification.
    callback: NotifierCallback,
    /// Opaque context value passed to callback.
    context: u64,
    /// Priority (lower = called first).
    priority: NotifierPriority,
    /// Whether this block is enabled.
    enabled: bool,
    /// Whether this slot is occupied.
    active: bool,
    /// Number of times this block has been invoked.
    invoke_count: u64,
    /// Number of errors returned by this block.
    error_count: u64,
}

/// Default callback that does nothing.
fn default_callback(_event: EventType, _data: &EventData, _ctx: u64) -> NotifierResult {
    NotifierResult::Ok
}

impl NotifierBlock {
    /// Create an empty, inactive block.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_BLOCK_NAME_LEN],
            name_len: 0,
            id: 0,
            callback: default_callback,
            context: 0,
            priority: NotifierPriority::Normal,
            enabled: false,
            active: false,
            invoke_count: 0,
            error_count: 0,
        }
    }

    /// Return the block name as bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the block ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the priority.
    pub const fn priority(&self) -> NotifierPriority {
        self.priority
    }

    /// Return whether the block is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the invocation count.
    pub const fn invoke_count(&self) -> u64 {
        self.invoke_count
    }

    /// Return the error count.
    pub const fn error_count(&self) -> u64 {
        self.error_count
    }
}

impl core::fmt::Debug for NotifierBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifierBlock")
            .field("id", &self.id)
            .field("priority", &self.priority)
            .field("enabled", &self.enabled)
            .field("invoke_count", &self.invoke_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// EventFilter
// -------------------------------------------------------------------

/// An event filter restricts which events a chain processes.
#[derive(Debug, Clone, Copy)]
struct EventFilter {
    /// Minimum event type value (inclusive).
    min_event: u64,
    /// Maximum event type value (inclusive).
    max_event: u64,
    /// Whether this filter slot is active.
    active: bool,
}

impl EventFilter {
    const fn empty() -> Self {
        Self {
            min_event: 0,
            max_event: u64::MAX,
            active: false,
        }
    }

    /// Check if an event passes this filter.
    const fn matches(&self, event: EventType) -> bool {
        event.0 >= self.min_event && event.0 <= self.max_event
    }
}

// -------------------------------------------------------------------
// CallStats — per-call statistics
// -------------------------------------------------------------------

/// Statistics from a single notification call.
#[derive(Debug, Clone, Copy)]
pub struct CallStats {
    /// Number of blocks invoked.
    pub blocks_invoked: usize,
    /// Number of blocks that returned Ok.
    pub ok_count: usize,
    /// Number of blocks that returned Stop.
    pub stop_count: usize,
    /// Number of blocks that returned an error.
    pub error_count: usize,
    /// Whether the chain was stopped early.
    pub stopped_early: bool,
}

impl CallStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            blocks_invoked: 0,
            ok_count: 0,
            stop_count: 0,
            error_count: 0,
            stopped_early: false,
        }
    }
}

// -------------------------------------------------------------------
// NotifierChain
// -------------------------------------------------------------------

/// A single notifier chain with ordered subscriber blocks.
pub struct NotifierChain {
    /// Chain name.
    name: [u8; MAX_CHAIN_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique chain identifier.
    chain_id: u64,
    /// Execution context type.
    chain_type: ChainType,
    /// Subscriber blocks (sorted by priority).
    blocks: [NotifierBlock; MAX_BLOCKS_PER_CHAIN],
    /// Number of active blocks.
    block_count: usize,
    /// Next block ID to assign.
    next_block_id: u64,
    /// Event filters (empty = accept all events).
    filters: [EventFilter; MAX_FILTERS],
    /// Number of active filters.
    filter_count: usize,
    /// Total notifications dispatched on this chain.
    total_calls: u64,
    /// Whether the chain is frozen (no new registrations).
    frozen: bool,
    /// Whether the chain slot is occupied.
    active: bool,
}

impl NotifierChain {
    /// Create an empty, inactive chain.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_CHAIN_NAME_LEN],
            name_len: 0,
            chain_id: 0,
            chain_type: ChainType::Blocking,
            blocks: [const { NotifierBlock::empty() }; MAX_BLOCKS_PER_CHAIN],
            block_count: 0,
            next_block_id: 1,
            filters: [const { EventFilter::empty() }; MAX_FILTERS],
            filter_count: 0,
            total_calls: 0,
            frozen: false,
            active: false,
        }
    }

    /// Return the chain name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Return the chain type.
    pub const fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    /// Return the number of active blocks.
    pub const fn block_count(&self) -> usize {
        self.block_count
    }

    /// Return the total call count.
    pub const fn total_calls(&self) -> u64 {
        self.total_calls
    }

    /// Return whether the chain is frozen.
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Register a new notifier block.
    ///
    /// The block is inserted in priority order (lower value first).
    /// Returns the assigned block ID.
    pub fn register(
        &mut self,
        name: &[u8],
        callback: NotifierCallback,
        context: u64,
        priority: NotifierPriority,
    ) -> Result<u64> {
        if self.frozen {
            return Err(Error::PermissionDenied);
        }
        if name.is_empty() || name.len() > MAX_BLOCK_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.block_count >= MAX_BLOCKS_PER_CHAIN {
            return Err(Error::OutOfMemory);
        }

        // Find insertion point to maintain priority order.
        let insert_idx = self.find_insert_index(priority);

        // Shift blocks down to make room.
        let mut i = self.block_count;
        while i > insert_idx {
            self.blocks.swap(i, i - 1);
            i -= 1;
        }

        let id = self.next_block_id;
        self.next_block_id += 1;

        self.blocks[insert_idx].name[..name.len()].copy_from_slice(name);
        self.blocks[insert_idx].name_len = name.len();
        self.blocks[insert_idx].id = id;
        self.blocks[insert_idx].callback = callback;
        self.blocks[insert_idx].context = context;
        self.blocks[insert_idx].priority = priority;
        self.blocks[insert_idx].enabled = true;
        self.blocks[insert_idx].active = true;
        self.blocks[insert_idx].invoke_count = 0;
        self.blocks[insert_idx].error_count = 0;
        self.block_count += 1;
        Ok(id)
    }

    /// Find the index where a block with the given priority should
    /// be inserted to maintain sorted order.
    fn find_insert_index(&self, priority: NotifierPriority) -> usize {
        let pval = priority.as_u16();
        for i in 0..self.block_count {
            if self.blocks[i].priority.as_u16() > pval {
                return i;
            }
        }
        self.block_count
    }

    /// Unregister a block by ID.
    pub fn unregister(&mut self, block_id: u64) -> Result<()> {
        let idx = self.find_block_index(block_id).ok_or(Error::NotFound)?;

        // Shift remaining blocks up.
        let mut i = idx;
        while i + 1 < self.block_count {
            self.blocks.swap(i, i + 1);
            i += 1;
        }
        self.blocks[self.block_count - 1] = NotifierBlock::empty();
        self.block_count -= 1;
        Ok(())
    }

    /// Find a block's index by ID.
    fn find_block_index(&self, block_id: u64) -> Option<usize> {
        (0..self.block_count).find(|&i| self.blocks[i].active && self.blocks[i].id == block_id)
    }

    /// Enable or disable a block.
    pub fn set_enabled(&mut self, block_id: u64, enabled: bool) -> Result<()> {
        let idx = self.find_block_index(block_id).ok_or(Error::NotFound)?;
        self.blocks[idx].enabled = enabled;
        Ok(())
    }

    /// Dispatch a notification to all enabled blocks.
    ///
    /// Blocks are called in priority order. If a block returns
    /// `Stop` or `StopWithError`, no further blocks are called.
    pub fn call_chain(&mut self, event: EventType, data: &EventData) -> CallStats {
        let mut stats = CallStats::new();

        // Check filters.
        if self.filter_count > 0 && !self.passes_filters(event) {
            return stats;
        }

        self.total_calls += 1;

        for i in 0..self.block_count {
            if !self.blocks[i].active || !self.blocks[i].enabled {
                continue;
            }

            let cb = self.blocks[i].callback;
            let ctx = self.blocks[i].context;
            let result = cb(event, data, ctx);

            self.blocks[i].invoke_count += 1;
            stats.blocks_invoked += 1;

            match result {
                NotifierResult::Ok => stats.ok_count += 1,
                NotifierResult::Stop => {
                    stats.stop_count += 1;
                    stats.stopped_early = true;
                    break;
                }
                NotifierResult::ContinueWithError => {
                    stats.error_count += 1;
                    self.blocks[i].error_count += 1;
                }
                NotifierResult::StopWithError => {
                    stats.error_count += 1;
                    self.blocks[i].error_count += 1;
                    stats.stopped_early = true;
                    break;
                }
            }
        }
        stats
    }

    /// Check if an event passes all active filters.
    fn passes_filters(&self, event: EventType) -> bool {
        for i in 0..self.filter_count {
            if self.filters[i].active && !self.filters[i].matches(event) {
                return false;
            }
        }
        true
    }

    /// Add an event filter to this chain.
    pub fn add_filter(&mut self, min_event: u64, max_event: u64) -> Result<()> {
        if min_event > max_event {
            return Err(Error::InvalidArgument);
        }
        if self.filter_count >= MAX_FILTERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.filter_count;
        self.filters[idx].min_event = min_event;
        self.filters[idx].max_event = max_event;
        self.filters[idx].active = true;
        self.filter_count += 1;
        Ok(())
    }

    /// Remove all event filters.
    pub fn clear_filters(&mut self) {
        for i in 0..self.filter_count {
            self.filters[i].active = false;
        }
        self.filter_count = 0;
    }

    /// Freeze the chain (prevent new registrations).
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Unfreeze the chain.
    pub fn unfreeze(&mut self) {
        self.frozen = false;
    }

    /// Return a reference to a block by index.
    pub fn block_at(&self, index: usize) -> Option<&NotifierBlock> {
        if index < self.block_count && self.blocks[index].active {
            Some(&self.blocks[index])
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// DeferredNotification
// -------------------------------------------------------------------

/// A notification that has been deferred for later processing.
#[derive(Clone, Copy)]
struct DeferredNotification {
    /// Target chain ID.
    chain_id: u64,
    /// Event type.
    event: EventType,
    /// Event data payload.
    data: EventData,
    /// Whether this slot is occupied.
    active: bool,
}

impl DeferredNotification {
    const fn empty() -> Self {
        Self {
            chain_id: 0,
            event: EventType::new(0),
            data: EventData::empty(),
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// NotifierChainManager
// -------------------------------------------------------------------

/// System-wide notifier chain manager.
///
/// Manages all notifier chains and provides deferred notification
/// support for cases where a chain cannot be called immediately
/// (e.g., from NMI context).
pub struct NotifierChainManager {
    /// All registered notifier chains.
    chains: [NotifierChain; MAX_CHAINS],
    /// Number of active chains.
    chain_count: usize,
    /// Next chain ID to assign.
    next_chain_id: u64,
    /// Deferred notification queue.
    deferred: [DeferredNotification; MAX_DEFERRED],
    /// Number of pending deferred notifications.
    deferred_count: usize,
    /// Total notifications dispatched across all chains.
    total_dispatched: u64,
    /// Total deferred notifications processed.
    total_deferred_processed: u64,
}

impl Default for NotifierChainManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NotifierChainManager {
    /// Create a new, empty manager.
    pub const fn new() -> Self {
        Self {
            chains: [const { NotifierChain::empty() }; MAX_CHAINS],
            chain_count: 0,
            next_chain_id: 1,
            deferred: [const { DeferredNotification::empty() }; MAX_DEFERRED],
            deferred_count: 0,
            total_dispatched: 0,
            total_deferred_processed: 0,
        }
    }

    /// Create a new notifier chain.
    ///
    /// Returns the chain ID.
    pub fn create_chain(&mut self, name: &[u8], chain_type: ChainType) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_CHAIN_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate names.
        for i in 0..self.chain_count {
            if !self.chains[i].active {
                continue;
            }
            if self.chains[i].name_len == name.len() && self.chains[i].name[..name.len()] == *name {
                return Err(Error::AlreadyExists);
            }
        }

        let slot = self.find_free_chain_slot()?;
        let id = self.next_chain_id;
        self.next_chain_id += 1;

        self.chains[slot].name[..name.len()].copy_from_slice(name);
        self.chains[slot].name_len = name.len();
        self.chains[slot].chain_id = id;
        self.chains[slot].chain_type = chain_type;
        self.chains[slot].block_count = 0;
        self.chains[slot].next_block_id = 1;
        self.chains[slot].filter_count = 0;
        self.chains[slot].total_calls = 0;
        self.chains[slot].frozen = false;
        self.chains[slot].active = true;
        self.chain_count += 1;
        Ok(id)
    }

    /// Find a free chain slot.
    fn find_free_chain_slot(&self) -> Result<usize> {
        for i in 0..MAX_CHAINS {
            if !self.chains[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a chain's index by ID.
    fn find_chain_index(&self, chain_id: u64) -> Option<usize> {
        (0..MAX_CHAINS).find(|&i| self.chains[i].active && self.chains[i].chain_id == chain_id)
    }

    /// Find a chain's index by name.
    fn find_chain_index_by_name(&self, name: &[u8]) -> Option<usize> {
        (0..MAX_CHAINS).find(|&i| {
            self.chains[i].active
                && self.chains[i].name_len == name.len()
                && self.chains[i].name[..name.len()] == *name
        })
    }

    /// Destroy a notifier chain.
    pub fn destroy_chain(&mut self, chain_id: u64) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        if self.chains[idx].block_count > 0 {
            return Err(Error::Busy);
        }
        self.chains[idx].active = false;
        self.chain_count -= 1;
        Ok(())
    }

    /// Register a notifier block on a chain by chain ID.
    pub fn register_block(
        &mut self,
        chain_id: u64,
        name: &[u8],
        callback: NotifierCallback,
        context: u64,
        priority: NotifierPriority,
    ) -> Result<u64> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].register(name, callback, context, priority)
    }

    /// Unregister a block from a chain.
    pub fn unregister_block(&mut self, chain_id: u64, block_id: u64) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].unregister(block_id)
    }

    /// Dispatch a notification on a chain by ID.
    pub fn notify(
        &mut self,
        chain_id: u64,
        event: EventType,
        data: &EventData,
    ) -> Result<CallStats> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.total_dispatched += 1;
        Ok(self.chains[idx].call_chain(event, data))
    }

    /// Dispatch a notification on a chain by name.
    pub fn notify_by_name(
        &mut self,
        name: &[u8],
        event: EventType,
        data: &EventData,
    ) -> Result<CallStats> {
        let idx = self.find_chain_index_by_name(name).ok_or(Error::NotFound)?;
        self.total_dispatched += 1;
        Ok(self.chains[idx].call_chain(event, data))
    }

    /// Queue a deferred notification.
    ///
    /// Use this when calling `notify()` is not safe (e.g., from
    /// NMI or hard-IRQ context for a Blocking chain).
    pub fn defer_notify(
        &mut self,
        chain_id: u64,
        event: EventType,
        data: &EventData,
    ) -> Result<()> {
        // Verify chain exists.
        if self.find_chain_index(chain_id).is_none() {
            return Err(Error::NotFound);
        }
        if self.deferred_count >= MAX_DEFERRED {
            return Err(Error::OutOfMemory);
        }
        // Find free slot.
        for item in self.deferred.iter_mut() {
            if !item.active {
                item.chain_id = chain_id;
                item.event = event;
                item.data = *data;
                item.active = true;
                self.deferred_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Process all pending deferred notifications.
    ///
    /// This should be called from a safe context (workqueue, softirq).
    pub fn process_deferred(&mut self) -> usize {
        let mut processed = 0;

        for i in 0..MAX_DEFERRED {
            if !self.deferred[i].active {
                continue;
            }

            let chain_id = self.deferred[i].chain_id;
            let event = self.deferred[i].event;
            // Copy the data before borrowing self mutably.
            let data = self.deferred[i].data;

            self.deferred[i].active = false;
            self.deferred_count -= 1;

            if let Some(idx) = self.find_chain_index(chain_id) {
                self.chains[idx].call_chain(event, &data);
                self.total_deferred_processed += 1;
            }
            processed += 1;
        }
        processed
    }

    /// Return the number of active chains.
    pub const fn chain_count(&self) -> usize {
        self.chain_count
    }

    /// Return a reference to a chain by ID.
    pub fn chain(&self, chain_id: u64) -> Option<&NotifierChain> {
        self.find_chain_index(chain_id).map(|idx| &self.chains[idx])
    }

    /// Return a reference to a chain by name.
    pub fn chain_by_name(&self, name: &[u8]) -> Option<&NotifierChain> {
        self.find_chain_index_by_name(name)
            .map(|idx| &self.chains[idx])
    }

    /// Enable or disable a block on a chain.
    pub fn set_block_enabled(&mut self, chain_id: u64, block_id: u64, enabled: bool) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].set_enabled(block_id, enabled)
    }

    /// Freeze a chain (prevent new registrations).
    pub fn freeze_chain(&mut self, chain_id: u64) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].freeze();
        Ok(())
    }

    /// Unfreeze a chain.
    pub fn unfreeze_chain(&mut self, chain_id: u64) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].unfreeze();
        Ok(())
    }

    /// Add an event filter to a chain.
    pub fn add_chain_filter(
        &mut self,
        chain_id: u64,
        min_event: u64,
        max_event: u64,
    ) -> Result<()> {
        let idx = self.find_chain_index(chain_id).ok_or(Error::NotFound)?;
        self.chains[idx].add_filter(min_event, max_event)
    }

    /// Return the total dispatched notifications.
    pub const fn total_dispatched(&self) -> u64 {
        self.total_dispatched
    }

    /// Return the total deferred notifications processed.
    pub const fn total_deferred_processed(&self) -> u64 {
        self.total_deferred_processed
    }

    /// Return the number of pending deferred notifications.
    pub const fn deferred_count(&self) -> usize {
        self.deferred_count
    }
}

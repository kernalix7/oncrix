// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4-style journal (JBD2) foundations for the ONCRIX VFS.
//!
//! Provides write-ahead logging for filesystem metadata and data
//! integrity. Transactions group related block updates and are
//! committed atomically, enabling crash recovery by replaying
//! or revoking uncommitted changes.
//!
//! # Design
//!
//! The journal maintains a circular log of [`JournalEntry`] records.
//! Each entry wraps a [`Transaction`] containing block tags and
//! optional data. The lifecycle is:
//!
//! 1. [`Journal::start_transaction`] — allocate a new transaction
//! 2. [`Journal::journal_block`] — record block writes
//! 3. [`Journal::commit_transaction`] — mark as committed
//! 4. [`Journal::checkpoint`] — flush committed entries to disk
//! 5. [`Journal::recover`] — replay committed entries after crash

use oncrix_lib::{Error, Result};

/// Maximum number of block tags per transaction.
const MAX_BLOCKS_PER_TXN: usize = 64;

/// Maximum data payload size per transaction (bytes).
const MAX_TXN_DATA: usize = 4096;

/// Maximum number of journal entries.
const MAX_JOURNAL_ENTRIES: usize = 32;

/// JBD2 journal superblock magic number.
const JOURNAL_MAGIC: u32 = 0xC03B_3998;

/// Journal block type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JournalBlockType {
    /// Descriptor block — lists the filesystem blocks in a transaction.
    #[default]
    Descriptor,
    /// Commit block — marks the end of a transaction.
    Commit,
    /// Superblock — journal metadata header.
    Superblock,
    /// Revoke block — lists blocks that should not be replayed.
    Revoke,
}

/// A tag describing a single journaled filesystem block.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalBlockTag {
    /// Filesystem block number this tag refers to.
    pub blocknr: u64,
    /// Flags for this block tag (e.g., escape, same-UUID, last-tag).
    pub flags: u32,
    /// CRC32 checksum of the block data.
    pub checksum: u32,
}

/// On-disk journal superblock structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JournalSuperblock {
    /// Magic number ([`JOURNAL_MAGIC`]).
    pub magic: u32,
    /// Block type identifier for the superblock itself.
    pub block_type: u32,
    /// Current transaction sequence number.
    pub sequence: u32,
    /// Journal block size in bytes.
    pub block_size: u32,
    /// Maximum number of journal blocks.
    pub max_len: u32,
    /// First usable journal block.
    pub first_block: u32,
    /// Sequence number of the first valid transaction.
    pub first_sequence: u32,
    /// Journal head position (next block to write).
    pub head: u32,
    /// Error number stored when journal is aborted (0 = no error).
    pub errno: i32,
}

impl Default for JournalSuperblock {
    fn default() -> Self {
        Self {
            magic: JOURNAL_MAGIC,
            block_type: 0,
            sequence: 0,
            block_size: 4096,
            max_len: 0,
            first_block: 1,
            first_sequence: 1,
            head: 0,
            errno: 0,
        }
    }
}

/// Transaction state in the journal lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JournalState {
    /// No active transaction work.
    #[default]
    Idle,
    /// Transaction is accumulating block writes.
    Running,
    /// Transaction is being committed to the journal.
    Committing,
    /// Committed data is being flushed to final locations.
    Flushing,
    /// Transaction has been aborted due to an error.
    Aborted,
}

/// A single transaction grouping related block updates.
pub struct Transaction {
    /// Transaction identifier.
    pub tid: u64,
    /// Current state of this transaction.
    pub state: JournalState,
    /// Block tags recorded in this transaction.
    blocks: [JournalBlockTag; MAX_BLOCKS_PER_TXN],
    /// Number of block tags currently recorded.
    block_count: usize,
    /// Optional data payload for the transaction.
    data: [u8; MAX_TXN_DATA],
    /// Length of valid data in the data buffer.
    data_len: usize,
    /// Timestamp (tick) when this transaction started.
    pub start_time: u64,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            tid: 0,
            state: JournalState::default(),
            blocks: [JournalBlockTag::default(); MAX_BLOCKS_PER_TXN],
            block_count: 0,
            data: [0u8; MAX_TXN_DATA],
            data_len: 0,
            start_time: 0,
        }
    }
}

impl Transaction {
    /// Add a block tag to this transaction.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the transaction already contains the
    ///   maximum number of block tags.
    pub fn add_block(&mut self, blocknr: u64, flags: u32) -> Result<()> {
        if self.block_count >= MAX_BLOCKS_PER_TXN {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.block_count] = JournalBlockTag {
            blocknr,
            flags,
            checksum: 0,
        };
        self.block_count = self.block_count.saturating_add(1);
        Ok(())
    }

    /// Set the data payload for this transaction.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `data` exceeds the maximum payload size.
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_TXN_DATA {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        Ok(())
    }

    /// Return the number of block tags in this transaction.
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    /// Return the valid data payload length.
    pub fn data_len(&self) -> usize {
        self.data_len
    }
}

/// A journal entry wrapping a transaction with status flags.
#[derive(Default)]
pub struct JournalEntry {
    /// The wrapped transaction.
    pub transaction: Transaction,
    /// Whether this entry has been committed to the journal log.
    pub committed: bool,
    /// Whether this entry has been checkpointed to final storage.
    pub checkpointed: bool,
    /// Whether this entry slot is occupied.
    pub in_use: bool,
}

/// JBD2-style write-ahead journal for filesystem integrity.
///
/// Manages a fixed-size ring of [`JournalEntry`] slots.
/// Transactions are started, populated with block writes,
/// committed, and eventually checkpointed (flushed) to disk.
pub struct Journal {
    /// Journal superblock metadata.
    superblock: JournalSuperblock,
    /// Fixed-size array of journal entries.
    entries: [JournalEntry; MAX_JOURNAL_ENTRIES],
    /// Number of active (in-use) entries.
    entry_count: usize,
    /// Next transaction identifier to assign.
    current_tid: u64,
    /// Overall journal state.
    state: JournalState,
    /// Whether write barriers are enabled.
    barrier: bool,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    /// Create a new, empty journal with default superblock settings.
    pub const fn new() -> Self {
        const EMPTY_ENTRY: JournalEntry = JournalEntry {
            transaction: Transaction {
                tid: 0,
                state: JournalState::Idle,
                blocks: [JournalBlockTag {
                    blocknr: 0,
                    flags: 0,
                    checksum: 0,
                }; MAX_BLOCKS_PER_TXN],
                block_count: 0,
                data: [0u8; MAX_TXN_DATA],
                data_len: 0,
                start_time: 0,
            },
            committed: false,
            checkpointed: false,
            in_use: false,
        };
        Self {
            superblock: JournalSuperblock {
                magic: JOURNAL_MAGIC,
                block_type: 0,
                sequence: 0,
                block_size: 4096,
                max_len: 0,
                first_block: 1,
                first_sequence: 1,
                head: 0,
                errno: 0,
            },
            entries: [EMPTY_ENTRY; MAX_JOURNAL_ENTRIES],
            entry_count: 0,
            current_tid: 1,
            state: JournalState::Idle,
            barrier: true,
        }
    }

    /// Start a new transaction and return its identifier.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free journal entry slots are available.
    /// - `InvalidArgument` if the journal has been aborted.
    pub fn start_transaction(&mut self) -> Result<u64> {
        if self.state == JournalState::Aborted {
            return Err(Error::InvalidArgument);
        }
        if self.entry_count >= MAX_JOURNAL_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let tid = self.current_tid;
        for entry in self.entries.iter_mut() {
            if !entry.in_use {
                entry.in_use = true;
                entry.committed = false;
                entry.checkpointed = false;
                entry.transaction.tid = tid;
                entry.transaction.state = JournalState::Running;
                entry.transaction.block_count = 0;
                entry.transaction.data_len = 0;
                entry.transaction.start_time = 0;
                self.current_tid = self.current_tid.saturating_add(1);
                self.entry_count = self.entry_count.saturating_add(1);
                self.state = JournalState::Running;
                return Ok(tid);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Record a filesystem block in an active transaction.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no transaction with the given `tid` exists.
    /// - `InvalidArgument` if the transaction is not in the `Running` state.
    /// - `OutOfMemory` if the transaction block list is full.
    pub fn journal_block(&mut self, tid: u64, blocknr: u64) -> Result<()> {
        let entry = self.find_entry_mut(tid)?;
        if entry.transaction.state != JournalState::Running {
            return Err(Error::InvalidArgument);
        }
        entry.transaction.add_block(blocknr, 0)
    }

    /// Commit an active transaction to the journal log.
    ///
    /// Transitions the transaction from `Running` to `Committing`
    /// and then marks it as committed. Updates the journal superblock
    /// sequence number.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no transaction with the given `tid` exists.
    /// - `InvalidArgument` if the transaction is not in the `Running` state.
    pub fn commit_transaction(&mut self, tid: u64) -> Result<()> {
        let entry = self.find_entry_mut(tid)?;
        if entry.transaction.state != JournalState::Running {
            return Err(Error::InvalidArgument);
        }
        entry.transaction.state = JournalState::Committing;
        entry.committed = true;
        entry.transaction.state = JournalState::Idle;
        self.superblock.sequence = self.superblock.sequence.saturating_add(1);
        Ok(())
    }

    /// Abort an active transaction, discarding its contents.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no transaction with the given `tid` exists.
    pub fn abort_transaction(&mut self, tid: u64) -> Result<()> {
        let entry = self.find_entry_mut(tid)?;
        entry.transaction.state = JournalState::Aborted;
        entry.in_use = false;
        entry.committed = false;
        entry.checkpointed = false;
        self.entry_count = self.entry_count.saturating_sub(1);
        Ok(())
    }

    /// Checkpoint committed entries, flushing them to final storage.
    ///
    /// Returns the number of entries flushed. Entries that have been
    /// committed but not yet checkpointed are marked as checkpointed
    /// and their slots are released.
    pub fn checkpoint(&mut self) -> Result<u32> {
        let mut flushed: u32 = 0;
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.committed && !entry.checkpointed {
                entry.transaction.state = JournalState::Flushing;
                entry.checkpointed = true;
                entry.transaction.state = JournalState::Idle;
                entry.in_use = false;
                self.entry_count = self.entry_count.saturating_sub(1);
                flushed = flushed.saturating_add(1);
            }
        }
        if self.entry_count == 0 {
            self.state = JournalState::Idle;
        }
        Ok(flushed)
    }

    /// Recover the journal after a crash by replaying committed entries.
    ///
    /// Returns the number of entries replayed. Only committed,
    /// non-checkpointed entries are eligible for replay.
    pub fn recover(&mut self) -> Result<u32> {
        let mut replayed: u32 = 0;
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.committed && !entry.checkpointed {
                // In a real implementation, block data would be written
                // back to the filesystem here.
                entry.checkpointed = true;
                entry.in_use = false;
                self.entry_count = self.entry_count.saturating_sub(1);
                replayed = replayed.saturating_add(1);
            }
        }
        if self.entry_count == 0 {
            self.state = JournalState::Idle;
        }
        Ok(replayed)
    }

    /// Enable or disable write barriers.
    ///
    /// When barriers are enabled, the journal issues cache flush
    /// commands to storage devices to ensure ordering.
    pub fn set_barrier(&mut self, enabled: bool) {
        self.barrier = enabled;
    }

    /// Look up a transaction by its identifier.
    pub fn get_transaction(&self, tid: u64) -> Option<&Transaction> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.transaction.tid == tid)
            .map(|e| &e.transaction)
    }

    /// Check whether any committed entries need checkpointing.
    pub fn needs_checkpoint(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.in_use && e.committed && !e.checkpointed)
    }

    /// Return the number of active (in-use) transactions.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    /// Check whether the journal has no active transactions.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Return a reference to the journal superblock.
    pub fn superblock(&self) -> &JournalSuperblock {
        &self.superblock
    }

    /// Return whether write barriers are enabled.
    pub fn barrier_enabled(&self) -> bool {
        self.barrier
    }

    /// Return the current journal state.
    pub fn state(&self) -> JournalState {
        self.state
    }

    /// Find a mutable reference to the entry with the given tid.
    fn find_entry_mut(&mut self, tid: u64) -> Result<&mut JournalEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.in_use && e.transaction.tid == tid)
            .ok_or(Error::NotFound)
    }
}

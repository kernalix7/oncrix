// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem journaling core for the ONCRIX VFS.
//!
//! Provides the foundational data structures and state management for
//! write-ahead logging (WAL) journaling used by ext3/ext4 (jbd2), XFS,
//! and other journaled filesystems. The journal prevents filesystem
//! corruption by recording metadata changes before applying them.

use oncrix_lib::{Error, Result};

/// Magic number written at the start of every journal block.
pub const JOURNAL_MAGIC: u32 = 0xC03B3998;

/// Journal block size (must match filesystem block size).
pub const JOURNAL_BLOCK_SIZE: usize = 4096;

/// Maximum number of active transactions in the journal at once.
pub const JOURNAL_MAX_TRANSACTIONS: usize = 4;

/// Maximum number of blocks that can be modified in a single transaction.
pub const JOURNAL_MAX_BLOCKS_PER_TX: usize = 1024;

/// Journal block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JournalBlockType {
    /// Descriptor block — lists data blocks in the following commit.
    Descriptor = 1,
    /// Commit block — marks the end of a committed transaction.
    Commit = 2,
    /// Superblock V1.
    SuperblockV1 = 3,
    /// Superblock V2.
    SuperblockV2 = 4,
    /// Revoke block — lists blocks that must not be replayed.
    Revoke = 5,
}

/// Journal feature flags stored in the journal superblock.
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalFeatures {
    /// 64-bit block numbers are supported.
    pub large_blocks: bool,
    /// Checksums are stored in commit blocks.
    pub checksums: bool,
    /// Async commits are enabled.
    pub async_commit: bool,
    /// Journal stores data as well as metadata.
    pub data_mode: bool,
}

/// On-disk journal superblock (first block of the journal device/file).
#[derive(Debug, Clone, Copy)]
pub struct JournalSuperblock {
    /// Magic number (must equal `JOURNAL_MAGIC`).
    pub magic: u32,
    /// Block type (3 = V1 superblock, 4 = V2 superblock).
    pub block_type: u32,
    /// Journal format version.
    pub format_version: u32,
    /// Total number of blocks in the journal.
    pub total_blocks: u32,
    /// Block number of the first log block.
    pub first_block: u32,
    /// Sequence number of the first committed transaction.
    pub first_commit_seq: u32,
    /// Block size of the journal.
    pub block_size: u32,
    /// Maximum transaction size in blocks.
    pub max_transaction: u32,
    /// Compatible feature set.
    pub feature_compat: u32,
    /// Incompatible feature set.
    pub feature_incompat: u32,
    /// Read-only compatible feature set.
    pub feature_ro_compat: u32,
}

impl JournalSuperblock {
    /// Construct a default journal superblock.
    pub const fn new(total_blocks: u32) -> Self {
        Self {
            magic: JOURNAL_MAGIC,
            block_type: JournalBlockType::SuperblockV2 as u32,
            format_version: 2,
            total_blocks,
            first_block: 1,
            first_commit_seq: 1,
            block_size: JOURNAL_BLOCK_SIZE as u32,
            max_transaction: JOURNAL_MAX_BLOCKS_PER_TX as u32,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
        }
    }

    /// Validate that the superblock magic and version are correct.
    pub fn validate(&self) -> Result<()> {
        if self.magic != JOURNAL_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.format_version < 1 || self.format_version > 2 {
            return Err(Error::InvalidArgument);
        }
        if self.block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for JournalSuperblock {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// State of a journal transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionState {
    /// Transaction is open and accepting new block modifications.
    #[default]
    Running,
    /// Transaction is being committed (flushing to journal).
    Committing,
    /// Transaction has been committed to the journal.
    Committed,
    /// Transaction has been checkpointed (data written to disk).
    Checkpointed,
}

/// A single journal transaction.
#[derive(Debug, Clone, Copy)]
pub struct JournalTransaction {
    /// Monotonically increasing sequence number.
    pub seq: u32,
    /// Current state.
    pub state: TransactionState,
    /// Block numbers modified by this transaction.
    blocks: [u64; JOURNAL_MAX_BLOCKS_PER_TX],
    /// Number of modified blocks.
    block_count: usize,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl JournalTransaction {
    /// Create a new running transaction.
    pub const fn new(seq: u32) -> Self {
        Self {
            seq,
            state: TransactionState::Running,
            blocks: [0u64; JOURNAL_MAX_BLOCKS_PER_TX],
            block_count: 0,
            active: true,
        }
    }

    /// Add a block number to this transaction's modification list.
    pub fn add_block(&mut self, block: u64) -> Result<()> {
        if self.block_count >= JOURNAL_MAX_BLOCKS_PER_TX {
            return Err(Error::OutOfMemory);
        }
        // Deduplication: don't add the same block twice.
        for i in 0..self.block_count {
            if self.blocks[i] == block {
                return Ok(());
            }
        }
        self.blocks[self.block_count] = block;
        self.block_count += 1;
        Ok(())
    }

    /// Return a slice of the modified block numbers.
    pub fn blocks(&self) -> &[u64] {
        &self.blocks[..self.block_count]
    }

    /// Return the number of blocks modified in this transaction.
    pub fn block_count(&self) -> usize {
        self.block_count
    }
}

impl Default for JournalTransaction {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The in-memory journal state for a mounted filesystem.
pub struct Journal {
    /// Journal superblock.
    pub superblock: JournalSuperblock,
    /// Active and recently committed transactions.
    transactions: [JournalTransaction; JOURNAL_MAX_TRANSACTIONS],
    /// Next sequence number to assign.
    next_seq: u32,
    /// Index of the currently open (running) transaction, if any.
    running_tx: Option<usize>,
}

impl Journal {
    /// Create a journal backed by a device with `total_blocks` journal blocks.
    pub const fn new(total_blocks: u32) -> Self {
        Self {
            superblock: JournalSuperblock::new(total_blocks),
            transactions: [const { JournalTransaction::new(0) }; JOURNAL_MAX_TRANSACTIONS],
            next_seq: 1,
            running_tx: None,
        }
    }

    /// Start a new transaction. Returns `Busy` if the maximum is reached.
    pub fn start_transaction(&mut self) -> Result<usize> {
        if self.running_tx.is_some() {
            return Err(Error::Busy);
        }
        for (i, slot) in self.transactions.iter_mut().enumerate() {
            if !slot.active {
                let seq = self.next_seq;
                self.next_seq = self.next_seq.wrapping_add(1);
                *slot = JournalTransaction::new(seq);
                self.running_tx = Some(i);
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Get a mutable reference to a transaction by index.
    pub fn transaction_mut(&mut self, idx: usize) -> Result<&mut JournalTransaction> {
        if idx >= JOURNAL_MAX_TRANSACTIONS || !self.transactions[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.transactions[idx])
    }

    /// Mark the running transaction as committing.
    pub fn begin_commit(&mut self) -> Result<usize> {
        let idx = self.running_tx.ok_or(Error::NotFound)?;
        self.transactions[idx].state = TransactionState::Committing;
        self.running_tx = None;
        Ok(idx)
    }

    /// Mark a transaction as committed.
    pub fn finish_commit(&mut self, idx: usize) -> Result<()> {
        if idx >= JOURNAL_MAX_TRANSACTIONS {
            return Err(Error::InvalidArgument);
        }
        self.transactions[idx].state = TransactionState::Committed;
        Ok(())
    }

    /// Mark a transaction as checkpointed and free its slot.
    pub fn checkpoint(&mut self, idx: usize) -> Result<()> {
        if idx >= JOURNAL_MAX_TRANSACTIONS || !self.transactions[idx].active {
            return Err(Error::NotFound);
        }
        self.transactions[idx].active = false;
        Ok(())
    }
}

impl Default for Journal {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Compute a simple 32-bit checksum over `data` using XOR accumulation.
pub fn journal_checksum(data: &[u8]) -> u32 {
    let mut csum = JOURNAL_MAGIC;
    for chunk in data.chunks(4) {
        let mut word = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            word |= (b as u32) << (i * 8);
        }
        csum ^= word;
    }
    csum
}

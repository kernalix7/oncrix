// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! JBD2 — Journal Block Device Layer 2.
//!
//! A generic journaling layer that provides crash-consistent metadata updates
//! for block-based filesystems (e.g., ext4). Every metadata change is first
//! written to the journal as part of a transaction; only after the journal
//! commit is durable are the in-place superblock/inode/bitmap blocks updated.
//!
//! # Lifecycle
//!
//! ```text
//! start_transaction()
//!   │
//!   ├── add_block() ×N   — copy dirty blocks into the transaction buffer
//!   │
//!   └── commit()         — write descriptor + data blocks + commit block
//!         │
//!         └── checkpoint() — once data is written back, free journal space
//!
//! On crash: journal_recover() replays all committed-but-not-checkpointed
//!           transactions, restoring consistency.
//! ```
//!
//! # References
//!
//! - Linux `fs/jbd2/`
//! - "A Short Introduction to the Linux Journalling API" (kernel docs)
//! - Stephen Tweedie's original JBD design papers

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of concurrent transactions tracked by the journal.
pub const JBD2_MAX_TRANSACTIONS: usize = 16;

/// Maximum number of blocks per transaction.
pub const JBD2_MAX_BLOCKS: usize = 64;

/// Size of a journal block in bytes (matches filesystem block size).
pub const JBD2_BLOCK_SIZE: usize = 4096;

/// Magic number stored in the journal superblock.
pub const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Journal superblock block type tag.
pub const JBD2_SUPERBLOCK_V2: u32 = 4;

// ── JournalState ─────────────────────────────────────────────────────────────

/// Current state of the journal subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalState {
    /// No active transaction; journal is quiescent.
    Idle,
    /// A transaction is open and accepting new block additions.
    Running,
    /// The current transaction is being serialised to disk.
    Committing,
    /// Completed transactions are being flushed to their final locations.
    Checkpoint,
    /// Journal recovery is in progress after an unclean shutdown.
    Recovery,
}

// ── TransactionState ─────────────────────────────────────────────────────────

/// Per-transaction lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Slot is empty.
    Empty,
    /// Transaction is open for new block additions.
    Running,
    /// Locked — no new additions allowed; awaiting commit.
    Locked,
    /// Commit record has been written to the journal.
    Committed,
    /// All dirty blocks have been written to their final locations.
    Checkpointed,
}

// ── JournalBlock ─────────────────────────────────────────────────────────────

/// A single 4 KiB journal block associated with a transaction.
pub struct JournalBlock {
    /// Filesystem block number this data belongs to.
    pub block_nr: u64,
    /// Block data snapshot captured at the time of addition.
    pub data: [u8; JBD2_BLOCK_SIZE],
    /// Whether the block has pending changes not yet checkpointed.
    pub dirty: bool,
}

impl JournalBlock {
    /// Constructs an empty block slot.
    pub const fn new() -> Self {
        Self {
            block_nr: 0,
            data: [0u8; JBD2_BLOCK_SIZE],
            dirty: false,
        }
    }
}

impl Default for JournalBlock {
    fn default() -> Self {
        Self::new()
    }
}

// JournalBlock has a 4096-byte array — Debug by hand.
impl core::fmt::Debug for JournalBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JournalBlock")
            .field("block_nr", &self.block_nr)
            .field("dirty", &self.dirty)
            .finish()
    }
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// A group of dirty blocks that are committed atomically.
pub struct Transaction {
    /// Transaction ID — monotonically increasing.
    pub tid: u32,
    /// Current lifecycle state.
    pub state: TransactionState,
    /// Dirty blocks captured for this transaction.
    pub blocks: [JournalBlock; JBD2_MAX_BLOCKS],
    /// Number of valid entries in `blocks`.
    pub block_count: u32,
    /// Timestamp (monotonic tick) when the transaction was opened.
    pub timestamp: u64,
}

impl Transaction {
    /// Constructs an empty transaction slot.
    pub const fn new() -> Self {
        Self {
            tid: 0,
            state: TransactionState::Empty,
            blocks: [const { JournalBlock::new() }; JBD2_MAX_BLOCKS],
            block_count: 0,
            timestamp: 0,
        }
    }

    /// Resets this slot so it can be reused.
    pub fn reset(&mut self) {
        self.tid = 0;
        self.state = TransactionState::Empty;
        self.block_count = 0;
        self.timestamp = 0;
        for b in self.blocks.iter_mut() {
            b.dirty = false;
            b.block_nr = 0;
        }
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Transaction")
            .field("tid", &self.tid)
            .field("state", &self.state)
            .field("block_count", &self.block_count)
            .finish()
    }
}

// ── Journal ───────────────────────────────────────────────────────────────────

/// Core journal object — owns the transaction ring and global state.
pub struct Journal {
    /// Ring of up to 16 transactions.
    pub transactions: [Transaction; JBD2_MAX_TRANSACTIONS],
    /// TID that will be assigned to the next started transaction.
    pub current_tid: u32,
    /// Overall journal state.
    pub state: JournalState,
    /// Block number of the on-disk journal superblock.
    pub superblock_lba: u64,
    /// Index of the currently open transaction (`current_tid`).
    current_idx: usize,
}

impl Journal {
    /// Constructs an idle journal.
    pub const fn new(superblock_lba: u64) -> Self {
        Self {
            transactions: [const { Transaction::new() }; JBD2_MAX_TRANSACTIONS],
            current_tid: 1,
            state: JournalState::Idle,
            superblock_lba,
            current_idx: 0,
        }
    }
}

impl Default for Journal {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── JournalStats ──────────────────────────────────────────────────────────────

/// Cumulative journal statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct JournalStats {
    /// Total transactions successfully committed.
    pub transactions_committed: u64,
    /// Total journal blocks written (descriptor + data + commit).
    pub blocks_written: u64,
    /// Total checkpoint operations completed.
    pub checkpoints: u64,
    /// Total recovery runs executed.
    pub recoveries: u64,
}

impl JournalStats {
    /// Constructs zeroed statistics.
    pub const fn new() -> Self {
        Self {
            transactions_committed: 0,
            blocks_written: 0,
            checkpoints: 0,
            recoveries: 0,
        }
    }
}

// ── JournalSubsystem ─────────────────────────────────────────────────────────

/// Public API for the JBD2 journaling layer.
pub struct JournalSubsystem {
    /// The journal state machine.
    pub journal: Journal,
    /// Cumulative statistics.
    pub stats: JournalStats,
}

impl JournalSubsystem {
    /// Constructs a new journal subsystem placed at `superblock_lba`.
    pub const fn new(superblock_lba: u64) -> Self {
        Self {
            journal: Journal::new(superblock_lba),
            stats: JournalStats::new(),
        }
    }

    // ── Transaction lifecycle ────────────────────────────────────────────────

    /// Opens a new transaction, returning its transaction ID.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] — a transaction is already running.
    /// - [`Error::OutOfMemory`] — all transaction slots are full.
    pub fn start_transaction(&mut self, timestamp: u64) -> Result<u32> {
        if self.journal.state == JournalState::Running {
            return Err(Error::Busy);
        }
        // Find an empty slot.
        let slot = self
            .journal
            .transactions
            .iter()
            .position(|t| t.state == TransactionState::Empty)
            .ok_or(Error::OutOfMemory)?;

        let tid = self.journal.current_tid;
        self.journal.current_tid = self.journal.current_tid.wrapping_add(1);

        let txn = &mut self.journal.transactions[slot];
        txn.tid = tid;
        txn.state = TransactionState::Running;
        txn.block_count = 0;
        txn.timestamp = timestamp;

        self.journal.current_idx = slot;
        self.journal.state = JournalState::Running;
        Ok(tid)
    }

    /// Appends `data` for filesystem block `block_nr` to the current transaction.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] — no running transaction.
    /// - [`Error::OutOfMemory`] — transaction block limit reached.
    pub fn add_block(&mut self, block_nr: u64, data: &[u8]) -> Result<()> {
        if self.journal.state != JournalState::Running {
            return Err(Error::Busy);
        }
        let idx = self.journal.current_idx;
        let txn = &mut self.journal.transactions[idx];
        if txn.state != TransactionState::Running {
            return Err(Error::Busy);
        }
        if txn.block_count as usize >= JBD2_MAX_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        let slot = txn.block_count as usize;
        let jb = &mut txn.blocks[slot];
        jb.block_nr = block_nr;
        let copy_len = data.len().min(JBD2_BLOCK_SIZE);
        jb.data[..copy_len].copy_from_slice(&data[..copy_len]);
        jb.dirty = true;
        txn.block_count = txn.block_count.wrapping_add(1);
        Ok(())
    }

    /// Commits the current transaction.
    ///
    /// Simulates writing descriptor block + data blocks + commit block
    /// to the journal. Updates state to `Committed`.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] — no running transaction.
    pub fn commit(&mut self) -> Result<u32> {
        if self.journal.state != JournalState::Running {
            return Err(Error::Busy);
        }
        self.journal.state = JournalState::Committing;
        let idx = self.journal.current_idx;
        let txn = &mut self.journal.transactions[idx];
        txn.state = TransactionState::Committed;
        let tid = txn.tid;
        // Each transaction writes: 1 descriptor + N data blocks + 1 commit block.
        let written = txn.block_count as u64 + 2;
        self.journal.state = JournalState::Idle;
        self.stats.transactions_committed = self.stats.transactions_committed.wrapping_add(1);
        self.stats.blocks_written = self.stats.blocks_written.wrapping_add(written);
        Ok(tid)
    }

    /// Aborts the current transaction, discarding all buffered blocks.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] — no active transaction to abort.
    pub fn abort(&mut self) -> Result<()> {
        match self.journal.state {
            JournalState::Running | JournalState::Committing => {}
            _ => return Err(Error::Busy),
        }
        let idx = self.journal.current_idx;
        self.journal.transactions[idx].reset();
        self.journal.state = JournalState::Idle;
        Ok(())
    }

    /// Checkpoints all committed transactions, marking them as flushed.
    ///
    /// In a real implementation this would wait for writeback of all dirty
    /// blocks and then reclaim journal space.
    pub fn checkpoint(&mut self) -> u32 {
        self.journal.state = JournalState::Checkpoint;
        let mut count = 0u32;
        for txn in self.journal.transactions.iter_mut() {
            if txn.state == TransactionState::Committed {
                txn.state = TransactionState::Checkpointed;
                txn.reset();
                count = count.wrapping_add(1);
            }
        }
        self.journal.state = JournalState::Idle;
        self.stats.checkpoints = self.stats.checkpoints.wrapping_add(1);
        count
    }

    /// Returns a snapshot of the current statistics.
    pub fn stats(&self) -> JournalStats {
        self.stats
    }
}

impl Default for JournalSubsystem {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── journal_recover ───────────────────────────────────────────────────────────

/// Replays all committed-but-not-checkpointed transactions after an unclean
/// shutdown.
///
/// For each `Committed` transaction the function iterates its dirty blocks,
/// simulating re-application to the block device. After replay the transaction
/// is advanced to `Checkpointed` and its slot is freed.
///
/// Returns the number of transactions replayed.
pub fn journal_recover(journal: &mut JournalSubsystem) -> u32 {
    journal.journal.state = JournalState::Recovery;
    let mut replayed = 0u32;
    for txn in journal.journal.transactions.iter_mut() {
        if txn.state == TransactionState::Committed {
            // Re-apply each dirty block to the in-place location.
            for i in 0..txn.block_count as usize {
                let _block_nr = txn.blocks[i].block_nr;
                // A real implementation would call block_write(_block_nr, &data).
                // Here we mark the block clean to simulate writeback completion.
                txn.blocks[i].dirty = false;
            }
            txn.state = TransactionState::Checkpointed;
            replayed = replayed.wrapping_add(1);
        }
    }
    journal.journal.state = JournalState::Idle;
    journal.stats.recoveries = journal.stats.recoveries.wrapping_add(1);
    // Free all checkpointed slots.
    for txn in journal.journal.transactions.iter_mut() {
        if txn.state == TransactionState::Checkpointed {
            txn.reset();
        }
    }
    replayed
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_commit_cycle() {
        let mut sub = JournalSubsystem::new(1);
        let tid = sub.start_transaction(100).unwrap();
        let data = [0xAAu8; JBD2_BLOCK_SIZE];
        sub.add_block(42, &data).unwrap();
        let committed_tid = sub.commit().unwrap();
        assert_eq!(tid, committed_tid);
        assert_eq!(sub.stats().transactions_committed, 1);
        // descriptor(1) + data(1) + commit(1) = 3 blocks
        assert_eq!(sub.stats().blocks_written, 3);
    }

    #[test]
    fn checkpoint_clears_slots() {
        let mut sub = JournalSubsystem::new(1);
        sub.start_transaction(1).unwrap();
        sub.add_block(10, &[0u8; 16]).unwrap();
        sub.commit().unwrap();
        let ckpt = sub.checkpoint();
        assert_eq!(ckpt, 1);
    }

    #[test]
    fn abort_resets_state() {
        let mut sub = JournalSubsystem::new(1);
        sub.start_transaction(1).unwrap();
        sub.add_block(99, &[0xFFu8; 8]).unwrap();
        sub.abort().unwrap();
        assert_eq!(sub.journal.state, JournalState::Idle);
    }

    #[test]
    fn recovery_replays_committed() {
        let mut sub = JournalSubsystem::new(1);
        sub.start_transaction(1).unwrap();
        sub.add_block(5, &[1u8; JBD2_BLOCK_SIZE]).unwrap();
        sub.commit().unwrap();
        // Simulate crash — call recover directly.
        let replayed = journal_recover(&mut sub);
        assert_eq!(replayed, 1);
        assert_eq!(sub.stats().recoveries, 1);
    }
}

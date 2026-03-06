// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Journal recovery for the ONCRIX VFS.
//!
//! Implements replay of committed but un-checkpointed journal transactions
//! after an unclean shutdown. The recovery scanner reads the journal forward
//! from the last known committed sequence, replays valid transactions, and
//! discards incomplete ones.

use oncrix_lib::{Error, Result};

/// Maximum number of committed transactions that can be replayed in one pass.
pub const RECOVER_MAX_TX: usize = 256;

/// Maximum number of revoke records processed per recovery scan.
pub const RECOVER_MAX_REVOKE: usize = 1024;

/// Phase of the recovery process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryPhase {
    /// Not yet started.
    #[default]
    Idle,
    /// Scanning the journal to find the last committed transaction.
    Scan,
    /// Replaying committed transactions.
    Replay,
    /// Processing revoke records.
    Revoke,
    /// Recovery completed successfully.
    Done,
    /// Recovery failed due to I/O or checksum error.
    Failed,
}

/// A single revoke record: a block number that must NOT be replayed.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevokeRecord {
    /// The block number that is revoked.
    pub block: u64,
    /// Sequence number at which this revoke was recorded.
    pub seq: u32,
    /// Whether this record is active.
    pub active: bool,
}

impl RevokeRecord {
    /// Construct a new revoke record.
    pub const fn new(block: u64, seq: u32) -> Self {
        Self {
            block,
            seq,
            active: true,
        }
    }
}

/// Table of revoke records accumulated during recovery.
pub struct RevokeTable {
    records: [RevokeRecord; RECOVER_MAX_REVOKE],
    count: usize,
}

impl RevokeTable {
    /// Create an empty revoke table.
    pub const fn new() -> Self {
        Self {
            records: [RevokeRecord {
                block: 0,
                seq: 0,
                active: false,
            }; RECOVER_MAX_REVOKE],
            count: 0,
        }
    }

    /// Insert a revoke record. Returns `OutOfMemory` if the table is full.
    pub fn insert(&mut self, block: u64, seq: u32) -> Result<()> {
        if self.count >= RECOVER_MAX_REVOKE {
            return Err(Error::OutOfMemory);
        }
        // Update existing entry for the same block if seq is newer.
        for i in 0..self.count {
            if self.records[i].active && self.records[i].block == block {
                if seq >= self.records[i].seq {
                    self.records[i].seq = seq;
                }
                return Ok(());
            }
        }
        self.records[self.count] = RevokeRecord::new(block, seq);
        self.count += 1;
        Ok(())
    }

    /// Return `true` if `block` was revoked at or after `seq`.
    pub fn is_revoked(&self, block: u64, seq: u32) -> bool {
        for i in 0..self.count {
            let r = &self.records[i];
            if r.active && r.block == block && r.seq >= seq {
                return true;
            }
        }
        false
    }

    /// Return the count of active revoke records.
    pub fn len(&self) -> usize {
        self.records[..self.count]
            .iter()
            .filter(|r| r.active)
            .count()
    }

    /// Return `true` if no revoke records are active.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RevokeTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Describes a committed transaction found during the scan phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoveredTx {
    /// Transaction sequence number.
    pub seq: u32,
    /// Journal block number where this transaction's descriptor starts.
    pub start_block: u64,
    /// Number of data blocks in this transaction.
    pub block_count: usize,
    /// Whether this transaction passed checksum verification.
    pub checksum_ok: bool,
    /// Whether this transaction has been replayed.
    pub replayed: bool,
}

impl RecoveredTx {
    /// Construct a new recovered transaction descriptor.
    pub const fn new(seq: u32, start_block: u64) -> Self {
        Self {
            seq,
            start_block,
            block_count: 0,
            checksum_ok: false,
            replayed: false,
        }
    }
}

/// State maintained throughout a journal recovery pass.
pub struct RecoveryContext {
    /// Current recovery phase.
    pub phase: RecoveryPhase,
    /// Sequence number of the last known good checkpoint.
    pub last_checkpoint_seq: u32,
    /// Sequence number of the last committed transaction found.
    pub last_committed_seq: u32,
    /// Transactions discovered during the scan phase.
    pub tx_list: [RecoveredTx; RECOVER_MAX_TX],
    /// Number of discovered transactions.
    pub tx_count: usize,
    /// Revoke table populated during replay.
    pub revoke: RevokeTable,
    /// Number of blocks replayed.
    pub blocks_replayed: usize,
    /// Number of blocks skipped due to revokes.
    pub blocks_revoked: usize,
}

impl RecoveryContext {
    /// Create a new recovery context starting from `last_checkpoint_seq`.
    pub const fn new(last_checkpoint_seq: u32) -> Self {
        Self {
            phase: RecoveryPhase::Idle,
            last_checkpoint_seq,
            last_committed_seq: last_checkpoint_seq,
            tx_list: [const { RecoveredTx::new(0, 0) }; RECOVER_MAX_TX],
            tx_count: 0,
            revoke: RevokeTable::new(),
            blocks_replayed: 0,
            blocks_revoked: 0,
        }
    }

    /// Advance to the next recovery phase.
    pub fn advance_phase(&mut self) -> Result<()> {
        self.phase = match self.phase {
            RecoveryPhase::Idle => RecoveryPhase::Scan,
            RecoveryPhase::Scan => RecoveryPhase::Revoke,
            RecoveryPhase::Revoke => RecoveryPhase::Replay,
            RecoveryPhase::Replay => RecoveryPhase::Done,
            RecoveryPhase::Done => return Err(Error::InvalidArgument),
            RecoveryPhase::Failed => return Err(Error::IoError),
        };
        Ok(())
    }

    /// Record a transaction found during the scan phase.
    pub fn record_tx(&mut self, tx: RecoveredTx) -> Result<()> {
        if self.tx_count >= RECOVER_MAX_TX {
            return Err(Error::OutOfMemory);
        }
        if tx.seq > self.last_committed_seq {
            self.last_committed_seq = tx.seq;
        }
        self.tx_list[self.tx_count] = tx;
        self.tx_count += 1;
        Ok(())
    }

    /// Return `true` if a given sequence number needs replay.
    pub fn needs_replay(&self, seq: u32) -> bool {
        seq > self.last_checkpoint_seq && seq <= self.last_committed_seq
    }

    /// Mark the recovery as failed.
    pub fn fail(&mut self) {
        self.phase = RecoveryPhase::Failed;
    }

    /// Return a summary of the recovery outcome.
    pub fn summary(&self) -> RecoverySummary {
        RecoverySummary {
            transactions_found: self.tx_count,
            blocks_replayed: self.blocks_replayed,
            blocks_skipped: self.blocks_revoked,
            last_seq: self.last_committed_seq,
        }
    }
}

impl Default for RecoveryContext {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Summary statistics returned after a completed recovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoverySummary {
    /// Number of committed transactions found in the journal.
    pub transactions_found: usize,
    /// Number of blocks replayed to the filesystem.
    pub blocks_replayed: usize,
    /// Number of blocks skipped due to revoke records.
    pub blocks_skipped: usize,
    /// Sequence number of the last replayed transaction.
    pub last_seq: u32,
}

/// Determine whether a 4-byte magic field matches the journal magic.
pub fn is_journal_block(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) == 0xC03B3998
}

/// Compute the next journal block number (wrapping around the journal).
pub fn next_journal_block(current: u64, total_blocks: u64, first_block: u64) -> u64 {
    let next = current + 1;
    if next >= first_block + total_blocks {
        first_block
    } else {
        next
    }
}

/// Check whether `seq_a` is logically after `seq_b` in a 32-bit wrap-around space.
pub fn seq_gt(seq_a: u32, seq_b: u32) -> bool {
    seq_a.wrapping_sub(seq_b) < 0x8000_0000
}

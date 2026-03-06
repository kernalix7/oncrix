// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 journal integration layer (JBD2 — Journaling Block Device 2).
//!
//! ext4 uses the JBD2 journaling layer to provide atomic, crash-consistent
//! updates to the filesystem.  Each logical operation (e.g., `write(2)`,
//! `unlink(2)`) is wrapped in a *transaction*, which groups block modifications
//! into a single journal commit.  On crash, the journal is replayed to bring
//! the filesystem back to a consistent state.
//!
//! This module implements the ONCRIX journal integration layer that sits between
//! ext4 operations and the block device, providing:
//! - Transaction begin / commit / abort
//! - Block descriptor (journal handle) tracking
//! - Checkpoint management (pruning old journal entries)
//! - Journal superblock serialization
//!
//! # Journal layout
//!
//! ```text
//! Journal:
//!   [superblock (block 0)]
//!   [descriptor block] [data block...] [commit block]  ← transaction N
//!   [descriptor block] [data block...] [commit block]  ← transaction N+1
//!   ...
//! ```
//!
//! # Linux reference
//! `fs/jbd2/` — `journal.c`, `transaction.c`, `commit.c`, `checkpoint.c`
//! `include/linux/jbd2.h` — `journal_t`, `transaction_t`, `handle_t`
//!
//! # POSIX reference
//! Not directly specified by POSIX; enables POSIX durability guarantees.

use oncrix_lib::{Error, Result};

// ── Journal constants ─────────────────────────────────────────────────────────

/// JBD2 journal superblock magic number.
pub const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Journal superblock block type.
pub const JBD2_SUPERBLOCK_V1: u32 = 1;
/// Journal superblock block type v2 (with UUID and feature flags).
pub const JBD2_SUPERBLOCK_V2: u32 = 2;

/// Journal descriptor block type.
pub const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
/// Journal commit block type.
pub const JBD2_COMMIT_BLOCK: u32 = 2;
/// Journal revoke block type.
pub const JBD2_REVOKE_BLOCK: u32 = 5;

/// Maximum number of simultaneous transactions in the journal ring.
const MAX_TRANSACTIONS: usize = 64;

/// Maximum number of blocks in a single transaction.
const MAX_BLOCKS_PER_TX: usize = 256;

/// Maximum number of revoked block numbers per transaction.
const MAX_REVOKES_PER_TX: usize = 64;

/// Maximum number of in-flight journal handles.
const MAX_HANDLES: usize = 128;

/// Journal block size (matching ext4 default: 4 KiB).
pub const JOURNAL_BLOCK_SIZE: usize = 4096;

/// UUID size in bytes.
const UUID_LEN: usize = 16;

// ── Journal feature flags ─────────────────────────────────────────────────────

/// Journal feature flags (stored in superblock `s_feature_compat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFeatures {
    /// Compatible feature flags (can be mounted r/w without understanding them).
    pub compat: u32,
    /// Incompatible feature flags (must understand to mount).
    pub incompat: u32,
    /// Read-only compatible features.
    pub ro_compat: u32,
}

impl JournalFeatures {
    /// Feature: 64-bit block numbers.
    pub const INCOMPAT_64BIT: u32 = 0x2;
    /// Feature: async commit.
    pub const INCOMPAT_ASYNC_COMMIT: u32 = 0x4;
    /// Feature: checksum v2.
    pub const INCOMPAT_CSUM_V2: u32 = 0x8;
    /// Feature: checksum v3.
    pub const INCOMPAT_CSUM_V3: u32 = 0x10;

    /// Construct a default feature set.
    pub const fn default_features() -> Self {
        Self {
            compat: 0,
            incompat: Self::INCOMPAT_64BIT,
            ro_compat: 0,
        }
    }
}

// ── Journal superblock ────────────────────────────────────────────────────────

/// JBD2 journal superblock (block 0 of the journal device/file).
///
/// Serialised as big-endian on disk, matching the JBD2 on-disk format.
#[derive(Debug, Clone, Copy)]
pub struct JournalSuperblock {
    /// Magic number (`JBD2_MAGIC`).
    pub s_header_magic: u32,
    /// Superblock block type.
    pub s_header_blocktype: u32,
    /// Total number of blocks in the journal.
    pub s_maxlen: u32,
    /// Block number of the first usable journal block.
    pub s_first: u32,
    /// Sequence number of the first transaction in the journal.
    pub s_sequence: u32,
    /// Block number of the first transaction start.
    pub s_start: u32,
    /// Errno from the last journal error.
    pub s_errno: i32,
    /// Compatible feature set.
    pub s_feature_compat: u32,
    /// Incompatible feature set.
    pub s_feature_incompat: u32,
    /// Read-only-compatible feature set.
    pub s_feature_ro_compat: u32,
    /// 128-bit journal UUID.
    pub s_uuid: [u8; UUID_LEN],
    /// Number of filesystems sharing this journal.
    pub s_nr_users: u32,
    /// Location of the superblock copy in the "dynamic" superblock.
    pub s_dynsuper: u32,
    /// Limit of journal blocks per transaction.
    pub s_max_transaction: u32,
    /// Limit of data blocks per transaction.
    pub s_max_trans_data: u32,
    /// Checksum type (0 = none, 1 = CRC32c).
    pub s_checksum_type: u8,
    /// Padding.
    pub _padding: [u8; 3],
    /// Number of write/read barriers used.
    pub s_num_fc_blks: u32,
}

impl Default for JournalSuperblock {
    fn default() -> Self {
        Self {
            s_header_magic: JBD2_MAGIC,
            s_header_blocktype: JBD2_SUPERBLOCK_V2,
            s_maxlen: 1024,
            s_first: 1,
            s_sequence: 1,
            s_start: 0,
            s_errno: 0,
            s_feature_compat: 0,
            s_feature_incompat: JournalFeatures::INCOMPAT_64BIT,
            s_feature_ro_compat: 0,
            s_uuid: [0u8; UUID_LEN],
            s_nr_users: 1,
            s_dynsuper: 0,
            s_max_transaction: MAX_BLOCKS_PER_TX as u32,
            s_max_trans_data: MAX_BLOCKS_PER_TX as u32 / 2,
            s_checksum_type: 1,
            _padding: [0u8; 3],
            s_num_fc_blks: 0,
        }
    }
}

impl JournalSuperblock {
    /// Serialise the superblock to `buf` in big-endian format.
    ///
    /// Returns the number of bytes written, or `InvalidArgument` if `buf` is
    /// too short.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 256 {
            return Err(Error::InvalidArgument);
        }
        buf[0..4].copy_from_slice(&self.s_header_magic.to_be_bytes());
        buf[4..8].copy_from_slice(&self.s_header_blocktype.to_be_bytes());
        buf[8..12].copy_from_slice(&self.s_maxlen.to_be_bytes());
        buf[12..16].copy_from_slice(&self.s_first.to_be_bytes());
        buf[16..20].copy_from_slice(&self.s_sequence.to_be_bytes());
        buf[20..24].copy_from_slice(&self.s_start.to_be_bytes());
        buf[24..28].copy_from_slice(&self.s_errno.to_be_bytes());
        buf[28..32].copy_from_slice(&self.s_feature_compat.to_be_bytes());
        buf[32..36].copy_from_slice(&self.s_feature_incompat.to_be_bytes());
        buf[36..40].copy_from_slice(&self.s_feature_ro_compat.to_be_bytes());
        buf[40..56].copy_from_slice(&self.s_uuid);
        buf[56..60].copy_from_slice(&self.s_nr_users.to_be_bytes());
        buf[60..64].copy_from_slice(&self.s_dynsuper.to_be_bytes());
        buf[64..68].copy_from_slice(&self.s_max_transaction.to_be_bytes());
        buf[68..72].copy_from_slice(&self.s_max_trans_data.to_be_bytes());
        buf[72] = self.s_checksum_type;
        buf[73..76].copy_from_slice(&self._padding);
        buf[76..80].copy_from_slice(&self.s_num_fc_blks.to_be_bytes());
        Ok(80)
    }

    /// Deserialise the superblock from `buf` in big-endian format.
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < 80 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != JBD2_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let mut uuid = [0u8; UUID_LEN];
        uuid.copy_from_slice(&buf[40..56]);
        Ok(Self {
            s_header_magic: magic,
            s_header_blocktype: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            s_maxlen: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            s_first: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            s_sequence: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            s_start: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
            s_errno: i32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
            s_feature_compat: u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]),
            s_feature_incompat: u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]),
            s_feature_ro_compat: u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]),
            s_uuid: uuid,
            s_nr_users: u32::from_be_bytes([buf[56], buf[57], buf[58], buf[59]]),
            s_dynsuper: u32::from_be_bytes([buf[60], buf[61], buf[62], buf[63]]),
            s_max_transaction: u32::from_be_bytes([buf[64], buf[65], buf[66], buf[67]]),
            s_max_trans_data: u32::from_be_bytes([buf[68], buf[69], buf[70], buf[71]]),
            s_checksum_type: buf[72],
            _padding: [buf[73], buf[74], buf[75]],
            s_num_fc_blks: u32::from_be_bytes([buf[76], buf[77], buf[78], buf[79]]),
        })
    }
}

// ── Transaction state ─────────────────────────────────────────────────────────

/// Transaction lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    /// Transaction is open and accepting new block modifications.
    Running,
    /// Transaction is being assembled for commit.
    Committing,
    /// Transaction has been committed to the journal.
    Committed,
    /// Transaction has been checkpointed to the filesystem.
    Checkpointed,
    /// Transaction was aborted due to an error.
    Aborted,
}

/// A single journal transaction.
pub struct Transaction {
    /// Unique transaction sequence number.
    pub sequence: u64,
    /// Current state.
    pub state: TxState,
    /// Block numbers modified in this transaction.
    modified_blocks: [u64; MAX_BLOCKS_PER_TX],
    /// Number of modified blocks.
    block_count: usize,
    /// Block numbers revoked in this transaction.
    revoked_blocks: [u64; MAX_REVOKES_PER_TX],
    /// Number of revoked blocks.
    revoke_count: usize,
    /// Number of open handles referencing this transaction.
    handle_count: u32,
    /// Journal block where this transaction's descriptor starts.
    pub journal_start_block: u64,
    /// Number of journal blocks consumed.
    pub journal_block_count: u64,
    /// Error flag (set if any handle encountered an error).
    pub has_error: bool,
}

impl Transaction {
    fn new(sequence: u64) -> Self {
        Self {
            sequence,
            state: TxState::Running,
            modified_blocks: [0u64; MAX_BLOCKS_PER_TX],
            block_count: 0,
            revoked_blocks: [0u64; MAX_REVOKES_PER_TX],
            revoke_count: 0,
            handle_count: 0,
            journal_start_block: 0,
            journal_block_count: 0,
            has_error: false,
        }
    }

    /// Record that `block_no` was modified in this transaction.
    pub fn record_block(&mut self, block_no: u64) -> Result<()> {
        if self.block_count >= MAX_BLOCKS_PER_TX {
            return Err(Error::OutOfMemory);
        }
        // Dedup: do not record the same block twice.
        if self.modified_blocks[..self.block_count].contains(&block_no) {
            return Ok(());
        }
        self.modified_blocks[self.block_count] = block_no;
        self.block_count += 1;
        Ok(())
    }

    /// Revoke `block_no` — future transactions will not replay it on recovery.
    pub fn revoke_block(&mut self, block_no: u64) -> Result<()> {
        if self.revoke_count >= MAX_REVOKES_PER_TX {
            return Err(Error::OutOfMemory);
        }
        if self.revoked_blocks[..self.revoke_count].contains(&block_no) {
            return Ok(());
        }
        self.revoked_blocks[self.revoke_count] = block_no;
        self.revoke_count += 1;
        Ok(())
    }

    /// Return the list of modified block numbers.
    pub fn modified_blocks(&self) -> &[u64] {
        &self.modified_blocks[..self.block_count]
    }

    /// Return the list of revoked block numbers.
    pub fn revoked_blocks(&self) -> &[u64] {
        &self.revoked_blocks[..self.revoke_count]
    }
}

// ── Journal handle ────────────────────────────────────────────────────────────

/// A journal handle: a caller's reference into an in-progress transaction.
///
/// Created by `journal_start()`, released by `journal_stop()`.
#[derive(Debug, Clone, Copy)]
pub struct JournalHandle {
    /// Handle ID (index in the handle table).
    pub id: u32,
    /// Sequence of the transaction this handle is attached to.
    pub transaction_seq: u64,
    /// Number of buffer credits reserved for this handle.
    pub credits: u32,
    /// Whether this handle has been aborted.
    pub aborted: bool,
}

// ── Journal ───────────────────────────────────────────────────────────────────

/// The JBD2 journal object.
///
/// Manages the transaction ring, handle table, and journal block allocator.
pub struct Journal {
    /// Journal superblock.
    pub superblock: JournalSuperblock,
    /// Transaction ring buffer.
    transactions: [Option<Transaction>; MAX_TRANSACTIONS],
    /// Index of the current running transaction (if any).
    current_tx: Option<usize>,
    /// Monotonically increasing sequence counter.
    next_sequence: u64,
    /// Handle table.
    handles: [Option<JournalHandle>; MAX_HANDLES],
    /// Next handle ID.
    next_handle_id: u32,
    /// Next journal block to allocate.
    next_journal_block: u64,
    /// Total journal blocks available.
    journal_size: u64,
    /// Whether the journal is in an error state.
    pub aborted: bool,
    /// Number of committed transactions awaiting checkpoint.
    pending_checkpoints: usize,
}

impl Journal {
    /// Initialise a new journal with `journal_size` blocks.
    pub fn new(journal_size: u64) -> Self {
        let mut sb = JournalSuperblock::default();
        sb.s_maxlen = journal_size as u32;
        sb.s_first = 1;
        Self {
            superblock: sb,
            transactions: [const { None }; MAX_TRANSACTIONS],
            current_tx: None,
            next_sequence: 1,
            handles: [const { None }; MAX_HANDLES],
            next_handle_id: 1,
            next_journal_block: 1,
            journal_size,
            aborted: false,
            pending_checkpoints: 0,
        }
    }

    // ── Handle lifecycle ──────────────────────────────────────────────────────

    /// Begin a new journal operation, attaching to (or creating) the current
    /// running transaction.
    ///
    /// `credits` — the number of metadata blocks this operation may modify.
    ///
    /// Returns a `JournalHandle` that must be passed to `journal_stop()`.
    pub fn journal_start(&mut self, credits: u32) -> Result<JournalHandle> {
        if self.aborted {
            return Err(Error::IoError);
        }
        // Ensure a running transaction exists.
        let tx_seq = self.ensure_running_transaction()?;
        // Allocate handle slot.
        let handle_slot = self
            .handles
            .iter_mut()
            .enumerate()
            .find(|(_, h)| h.is_none())
            .map(|(i, h)| (i, h))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_handle_id;
        self.next_handle_id = self.next_handle_id.wrapping_add(1);
        let handle = JournalHandle {
            id,
            transaction_seq: tx_seq,
            credits,
            aborted: false,
        };
        *handle_slot.1 = Some(handle);
        // Increment the transaction's handle count.
        if let Some(idx) = self.current_tx {
            if let Some(tx) = &mut self.transactions[idx] {
                tx.handle_count += 1;
            }
        }
        Ok(handle)
    }

    /// Get the mutable reference to the transaction associated with a handle.
    fn tx_for_handle_mut(&mut self, handle: &JournalHandle) -> Option<&mut Transaction> {
        self.transactions
            .iter_mut()
            .filter_map(|t| t.as_mut())
            .find(|t| t.sequence == handle.transaction_seq)
    }

    /// Record a block modification via a handle.
    ///
    /// Must be called before modifying the block content.
    pub fn journal_get_write_access(
        &mut self,
        handle: &JournalHandle,
        block_no: u64,
    ) -> Result<()> {
        if handle.aborted {
            return Err(Error::InvalidArgument);
        }
        let seq = handle.transaction_seq;
        let tx = self
            .transactions
            .iter_mut()
            .filter_map(|t| t.as_mut())
            .find(|t| t.sequence == seq)
            .ok_or(Error::NotFound)?;
        tx.record_block(block_no)
    }

    /// Mark a block as "dirty" (modified and ready for journal commit).
    ///
    /// In a real implementation this would attach the block buffer to the
    /// transaction's dirty list.  Here we simply ensure it is recorded.
    pub fn journal_dirty_metadata(&mut self, handle: &JournalHandle, block_no: u64) -> Result<()> {
        self.journal_get_write_access(handle, block_no)
    }

    /// Revoke a block number: prevent replaying it during recovery.
    pub fn journal_revoke(&mut self, handle: &JournalHandle, block_no: u64) -> Result<()> {
        if handle.aborted {
            return Err(Error::InvalidArgument);
        }
        let seq = handle.transaction_seq;
        let tx = self
            .transactions
            .iter_mut()
            .filter_map(|t| t.as_mut())
            .find(|t| t.sequence == seq)
            .ok_or(Error::NotFound)?;
        tx.revoke_block(block_no)
    }

    /// Stop (release) a journal handle.
    ///
    /// Decrements the transaction's handle count.  When the count reaches
    /// zero the transaction becomes eligible for commit.
    pub fn journal_stop(&mut self, handle: JournalHandle) -> Result<()> {
        // Remove handle from table.
        for slot in &mut self.handles {
            if let Some(h) = slot {
                if h.id == handle.id {
                    let seq = h.transaction_seq;
                    *slot = None;
                    // Decrement handle count on the transaction.
                    if let Some(tx) = self
                        .transactions
                        .iter_mut()
                        .filter_map(|t| t.as_mut())
                        .find(|t| t.sequence == seq)
                    {
                        if tx.handle_count > 0 {
                            tx.handle_count -= 1;
                        }
                    }
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    // ── Transaction commit ────────────────────────────────────────────────────

    /// Commit the current running transaction to the journal.
    ///
    /// Transitions the transaction from `Running` → `Committed`.
    /// Updates the journal superblock's sequence and start fields.
    pub fn journal_commit_transaction(&mut self) -> Result<u64> {
        let idx = self.current_tx.ok_or(Error::NotFound)?;
        {
            let tx = self.transactions[idx].as_mut().ok_or(Error::NotFound)?;
            if tx.state != TxState::Running {
                return Err(Error::Busy);
            }
            if tx.has_error {
                tx.state = TxState::Aborted;
                self.current_tx = None;
                return Err(Error::IoError);
            }
            tx.state = TxState::Committing;
        }
        // Allocate journal blocks for descriptor + data + commit blocks.
        let block_count = self.transactions[idx]
            .as_ref()
            .ok_or(Error::NotFound)?
            .block_count;
        let blocks_needed = 1 + block_count as u64 + 1; // desc + data + commit
        let start_block = self.alloc_journal_blocks(blocks_needed)?;
        let tx = self.transactions[idx].as_mut().ok_or(Error::NotFound)?;
        tx.journal_start_block = start_block;
        tx.journal_block_count = blocks_needed;
        tx.state = TxState::Committed;
        let committed_seq = tx.sequence;
        self.current_tx = None;
        self.pending_checkpoints += 1;
        // Update superblock.
        self.superblock.s_sequence = committed_seq as u32 + 1;
        Ok(committed_seq)
    }

    // ── Checkpoint ───────────────────────────────────────────────────────────

    /// Checkpoint all committed transactions: write their blocks to the
    /// filesystem and free their journal space.
    ///
    /// Returns the number of transactions checkpointed.
    pub fn journal_checkpoint(&mut self) -> Result<usize> {
        let mut count = 0usize;
        for slot in &mut self.transactions {
            if let Some(tx) = slot {
                if tx.state == TxState::Committed {
                    tx.state = TxState::Checkpointed;
                    count += 1;
                }
            }
        }
        if count > 0 && self.pending_checkpoints >= count {
            self.pending_checkpoints -= count;
        }
        // Advance journal start pointer past checkpointed blocks.
        // In a real implementation we'd reclaim the journal blocks here.
        Ok(count)
    }

    /// Flush and checkpoint all transactions, then update the journal
    /// superblock `s_start = 0` to indicate no replay is needed.
    pub fn journal_flush(&mut self) -> Result<()> {
        // Commit any running transaction first.
        if self.current_tx.is_some() {
            self.journal_commit_transaction()?;
        }
        self.journal_checkpoint()?;
        self.superblock.s_start = 0;
        Ok(())
    }

    // ── Error handling ────────────────────────────────────────────────────────

    /// Abort the journal with the given error code.
    ///
    /// All subsequent `journal_start()` calls will return `IoError`.
    pub fn journal_abort(&mut self, errno: i32) {
        self.aborted = true;
        self.superblock.s_errno = errno;
        // Mark the current transaction (if any) as aborted.
        if let Some(idx) = self.current_tx {
            if let Some(tx) = &mut self.transactions[idx] {
                tx.state = TxState::Aborted;
            }
        }
        self.current_tx = None;
    }

    /// Acknowledge a journal error, allowing the journal to resume.
    ///
    /// Should only be called after `fsck` has repaired the filesystem.
    pub fn journal_clear_err(&mut self) -> Result<()> {
        if self.aborted {
            self.aborted = false;
            self.superblock.s_errno = 0;
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Returns the number of journal blocks currently in use.
    pub fn blocks_used(&self) -> u64 {
        self.next_journal_block.saturating_sub(1)
    }

    /// Returns the number of free journal blocks.
    pub fn blocks_free(&self) -> u64 {
        self.journal_size.saturating_sub(self.blocks_used())
    }

    /// Returns the number of transactions pending checkpoint.
    pub fn pending_checkpoints(&self) -> usize {
        self.pending_checkpoints
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn ensure_running_transaction(&mut self) -> Result<u64> {
        if let Some(idx) = self.current_tx {
            if let Some(tx) = &self.transactions[idx] {
                if tx.state == TxState::Running {
                    return Ok(tx.sequence);
                }
            }
        }
        // Start a new transaction.
        let seq = self.next_sequence;
        self.next_sequence += 1;
        let slot = self
            .transactions
            .iter_mut()
            .enumerate()
            .find(|(_, t)| t.is_none())
            .map(|(i, t)| (i, t))
            .ok_or(Error::OutOfMemory)?;
        let idx = slot.0;
        *slot.1 = Some(Transaction::new(seq));
        self.current_tx = Some(idx);
        Ok(seq)
    }

    fn alloc_journal_blocks(&mut self, count: u64) -> Result<u64> {
        // Wrap around the journal ring.
        let start =
            self.next_journal_block % self.journal_size.max(1) + self.superblock.s_first as u64;
        let new_next = self.next_journal_block + count;
        if new_next > self.journal_size + self.superblock.s_first as u64 {
            // Simple wrap-around: assume checkpointed space is available.
            self.next_journal_block = count;
            return Ok(self.superblock.s_first as u64);
        }
        self.next_journal_block = new_next;
        Ok(start)
    }

    /// Returns the `JournalHandle` for a given handle ID (immutable).
    pub fn get_handle(&self, id: u32) -> Option<&JournalHandle> {
        self.handles
            .iter()
            .filter_map(|h| h.as_ref())
            .find(|h| h.id == id)
    }

    /// Check the handle table for a handle associated with `transaction_seq`.
    pub fn tx_for_handle(&self, handle: &JournalHandle) -> Option<&Transaction> {
        self.transactions
            .iter()
            .filter_map(|t| t.as_ref())
            .find(|t| t.sequence == handle.transaction_seq)
    }
}

// ── Recovery helpers ──────────────────────────────────────────────────────────

/// Journal recovery pass types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPass {
    /// Scan the journal to find the extent of committed transactions.
    Scan,
    /// Replay committed transactions to bring the FS to a consistent state.
    Replay,
    /// Revoke blocks that were explicitly revoked.
    Revoke,
}

/// Lightweight record of a journal block descriptor entry.
#[derive(Debug, Clone, Copy)]
pub struct JournalBlockTag {
    /// Filesystem block number.
    pub fs_block: u64,
    /// Journal block offset where the data for this block is stored.
    pub journal_block: u64,
    /// True if this is the last entry in the descriptor block.
    pub last: bool,
}

/// Result of a journal scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoveryScanResult {
    /// First transaction sequence found in the journal.
    pub first_seq: u64,
    /// Last valid committed sequence found.
    pub last_seq: u64,
    /// Number of transactions to replay.
    pub tx_count: u64,
}

/// Perform a scan-only recovery pass on a raw journal buffer.
///
/// In production this would scan the journal device block by block.  Here we
/// parse the superblock and compute the range of committed transactions.
pub fn journal_recover_scan(sb: &JournalSuperblock) -> RecoveryScanResult {
    let first = sb.s_sequence as u64;
    // If s_start == 0 the journal was cleanly unmounted; nothing to replay.
    if sb.s_start == 0 {
        return RecoveryScanResult {
            first_seq: first,
            last_seq: first,
            tx_count: 0,
        };
    }
    RecoveryScanResult {
        first_seq: first,
        last_seq: first + 1,
        tx_count: 1,
    }
}

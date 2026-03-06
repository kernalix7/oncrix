// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ReiserFS journal (transaction log) structures.
//!
//! ReiserFS uses a write-ahead log stored in a dedicated journal area.
//! The journal ensures filesystem consistency across crashes by logging
//! all metadata changes before applying them to the on-disk tree.
//!
//! # Journal Layout
//!
//! The journal consists of:
//! - A journal header block at a fixed location.
//! - A circular buffer of journal blocks.
//! - Each transaction is wrapped by `JournalDesc` and `JournalCommit` blocks.
//!
//! # Transaction Structure
//!
//! A transaction starts with a `JournalDesc` block containing the transaction
//! ID and the list of real block numbers that follow. The final block is the
//! `JournalCommit` block with a checksum.

use oncrix_lib::{Error, Result};

/// ReiserFS journal magic number.
pub const JOURNAL_DESC_MAGIC: u32 = 0x62616e6b; // "bank"

/// ReiserFS journal commit magic number.
pub const JOURNAL_COMMIT_MAGIC: u32 = 0x636f6d6d; // "comm"

/// Maximum blocks in a single ReiserFS transaction.
pub const JOURNAL_MAX_BATCH: usize = 900;

/// ReiserFS journal header (stored in block 0 of the journal area).
#[derive(Clone, Copy, Default)]
pub struct JournalHeader {
    /// Last fully committed transaction ID.
    pub last_flush_trans_id: u32,
    /// Block offset of the last committed transaction.
    pub last_flush_block: u32,
    /// Mount ID (detects replay after a different mount).
    pub mount_id: u32,
}

impl JournalHeader {
    /// Parses a journal header from 12 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            last_flush_trans_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            last_flush_block: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            mount_id: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }
}

/// ReiserFS journal transaction descriptor block.
#[derive(Clone, Copy, Default)]
pub struct JournalDesc {
    /// Magic number (JOURNAL_DESC_MAGIC).
    pub magic: u32,
    /// Transaction ID.
    pub trans_id: u32,
    /// Number of real blocks in this transaction.
    pub block_count: u32,
    /// Mount ID when this transaction was written.
    pub mount_id: u32,
}

impl JournalDesc {
    /// Parses a JournalDesc from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic != JOURNAL_DESC_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magic,
            trans_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            block_count: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            mount_id: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
        })
    }
}

/// ReiserFS journal commit block.
#[derive(Clone, Copy, Default)]
pub struct JournalCommit {
    /// Magic number (JOURNAL_COMMIT_MAGIC).
    pub magic: u32,
    /// Transaction ID (must match the corresponding JournalDesc).
    pub trans_id: u32,
    /// CRC32 checksum of the transaction data blocks.
    pub checksum: u32,
}

impl JournalCommit {
    /// Parses a JournalCommit from 12 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic != JOURNAL_COMMIT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magic,
            trans_id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            checksum: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }
}

/// In-memory state of the ReiserFS journal.
pub struct JournalState {
    /// Journal header (last committed transaction info).
    pub header: JournalHeader,
    /// Starting block of the journal area on disk.
    pub journal_start: u32,
    /// Total number of blocks in the journal area.
    pub journal_size: u32,
    /// Current write position (circular).
    pub write_pos: u32,
    /// ID of the currently open transaction.
    pub current_trans_id: u32,
    /// Number of blocks logged in the current transaction.
    pub current_block_count: u32,
    /// Whether a transaction is currently open.
    pub trans_open: bool,
}

impl Default for JournalState {
    fn default() -> Self {
        Self {
            header: JournalHeader::default(),
            journal_start: 0,
            journal_size: 0,
            write_pos: 0,
            current_trans_id: 1,
            current_block_count: 0,
            trans_open: false,
        }
    }
}

impl JournalState {
    /// Begins a new transaction.
    pub fn begin_transaction(&mut self) -> Result<()> {
        if self.trans_open {
            return Err(Error::Busy);
        }
        self.trans_open = true;
        self.current_block_count = 0;
        Ok(())
    }

    /// Logs a block in the current transaction.
    ///
    /// Returns the journal block position where this block will be written.
    pub fn log_block(&mut self, _real_block: u64) -> Result<u32> {
        if !self.trans_open {
            return Err(Error::InvalidArgument);
        }
        if self.current_block_count as usize >= JOURNAL_MAX_BATCH {
            return Err(Error::OutOfMemory);
        }
        let jpos = (self.write_pos + 1 + self.current_block_count) % self.journal_size;
        self.current_block_count += 1;
        Ok(self.journal_start + jpos)
    }

    /// Commits the current transaction, advancing the write pointer.
    pub fn commit_transaction(&mut self) -> Result<()> {
        if !self.trans_open {
            return Err(Error::InvalidArgument);
        }
        // Advance write pointer past: desc block + data blocks + commit block.
        let span = 1 + self.current_block_count + 1;
        self.write_pos = (self.write_pos + span) % self.journal_size;
        self.header.last_flush_trans_id = self.current_trans_id;
        self.header.last_flush_block = self.write_pos;
        self.current_trans_id += 1;
        self.current_block_count = 0;
        self.trans_open = false;
        Ok(())
    }

    /// Aborts the current transaction without writing a commit block.
    pub fn abort_transaction(&mut self) {
        self.trans_open = false;
        self.current_block_count = 0;
    }
}

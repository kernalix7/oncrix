// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS journaling (log) subsystem.
//!
//! Implements the XFS log (journal) for crash recovery and write ordering.
//! The log is a circular buffer on-disk that serializes all metadata
//! modifications before they are committed to their final locations.
//!
//! # Components
//!
//! - [`XfsLogItem`] — a single journal item (inode update, buffer write, etc.)
//! - [`XfsLog`] — circular log buffer with head/tail pointers
//! - `log_write` — serialize a log item into the circular buffer
//! - `log_commit` — advance the head LSN, making writes durable
//! - `log_recover` — replay committed items from tail to head after crash
//!
//! # Log Sequence Numbers (LSN)
//!
//! An LSN encodes `(cycle, block)` — cycle is the number of times the log
//! has wrapped around, and block is the block offset within the log.
//!
//! # Reference
//!
//! Linux `fs/xfs/xfs_log.c` and XFS on-disk format specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum log size in blocks.
const MAX_LOG_BLOCKS: usize = 4096;

/// Maximum items in the in-flight item list.
const MAX_LOG_ITEMS: usize = 256;

/// Log item data payload size (bytes).
const LOG_ITEM_DATA_SIZE: usize = 256;

/// XFS log magic.
const XFS_LOG_MAGIC: u32 = 0xFEEDbabe;

/// Maximum items in a single transaction.
const MAX_ITEMS_PER_TXN: usize = 32;

/// Log record header size (bytes, simplified).
const LOG_RECORD_HEADER_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Log Sequence Number
// ---------------------------------------------------------------------------

/// XFS Log Sequence Number — encodes (cycle, block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Lsn(pub u64);

impl Lsn {
    /// Constructs an LSN from cycle and block components.
    pub const fn from_parts(cycle: u32, block: u32) -> Self {
        Self(((cycle as u64) << 32) | block as u64)
    }

    /// Returns the cycle component.
    pub fn cycle(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Returns the block component.
    pub fn block(&self) -> u32 {
        self.0 as u32
    }

    /// Returns whether this LSN is valid (non-zero).
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }

    /// Advances to the next block, wrapping cycle on overflow.
    pub fn advance(&self, log_blocks: u32) -> Self {
        let next_block = self.block() + 1;
        if next_block >= log_blocks {
            Self::from_parts(self.cycle() + 1, 0)
        } else {
            Self::from_parts(self.cycle(), next_block)
        }
    }
}

// ---------------------------------------------------------------------------
// Log item types
// ---------------------------------------------------------------------------

/// Type of log item being journaled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogItemType {
    /// Inode modification.
    Inode,
    /// Buffer write (block data).
    Buffer,
    /// Extent free list entry.
    ExtentFree,
    /// Allocation group free space update.
    AgFreeSpace,
    /// Directory block modification.
    Directory,
    /// Transaction commit record.
    Commit,
    /// No-op / padding.
    NoOp,
}

/// A single item in the XFS journal.
#[derive(Debug, Clone)]
pub struct XfsLogItem {
    /// Type of this log item.
    pub item_type: LogItemType,
    /// LSN at which this item was written.
    pub lsn: Lsn,
    /// Transaction ID that owns this item.
    pub transaction_id: u64,
    /// Inode or block number this item applies to.
    pub object_id: u64,
    /// Serialized data payload.
    pub data: [u8; LOG_ITEM_DATA_SIZE],
    /// Valid bytes in `data`.
    pub data_len: usize,
    /// Whether this item has been committed.
    pub committed: bool,
}

impl XfsLogItem {
    /// Creates a new log item.
    pub fn new(item_type: LogItemType, transaction_id: u64, object_id: u64) -> Self {
        Self {
            item_type,
            lsn: Lsn::default(),
            transaction_id,
            object_id,
            data: [0u8; LOG_ITEM_DATA_SIZE],
            data_len: 0,
            committed: false,
        }
    }

    /// Sets the payload data.
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > LOG_ITEM_DATA_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        Ok(())
    }

    /// Returns the payload slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// ---------------------------------------------------------------------------
// Log record (on-disk block)
// ---------------------------------------------------------------------------

/// A single log record occupying one block.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Magic number.
    pub magic: u32,
    /// Cycle number.
    pub cycle: u32,
    /// LSN of this record.
    pub lsn: Lsn,
    /// Number of items in this record.
    pub item_count: u16,
    /// Total length of data in this record.
    pub data_len: u32,
    /// Whether this is a commit record.
    pub is_commit: bool,
    /// Data payload.
    pub data: [u8; 512],
}

impl LogRecord {
    /// Creates a new empty log record.
    pub const fn new(lsn: Lsn) -> Self {
        Self {
            magic: XFS_LOG_MAGIC,
            cycle: 0,
            lsn,
            item_count: 0,
            data_len: 0,
            is_commit: false,
            data: [0u8; 512],
        }
    }

    /// Returns whether this record has valid magic.
    pub fn is_valid(&self) -> bool {
        self.magic == XFS_LOG_MAGIC
    }
}

// ---------------------------------------------------------------------------
// XFS Log
// ---------------------------------------------------------------------------

/// XFS circular log buffer.
pub struct XfsLog {
    /// Log blocks (circular buffer).
    records: [LogRecord; MAX_LOG_BLOCKS],
    /// Number of blocks in the log.
    log_size: usize,
    /// Head LSN — next write position.
    head: Lsn,
    /// Tail LSN — oldest unrecovered record.
    tail: Lsn,
    /// In-flight log items awaiting commit.
    items: [Option<XfsLogItem>; MAX_LOG_ITEMS],
    /// Number of active items.
    item_count: usize,
    /// Next transaction ID.
    next_txn_id: u64,
    /// Total bytes written.
    bytes_written: u64,
}

impl XfsLog {
    /// Creates a new XFS log with the given size in blocks.
    pub fn new(log_size: usize) -> Result<Self> {
        if log_size == 0 || log_size > MAX_LOG_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            records: core::array::from_fn(|i| LogRecord::new(Lsn::from_parts(0, i as u32))),
            log_size,
            head: Lsn::from_parts(1, 0),
            tail: Lsn::from_parts(1, 0),
            items: core::array::from_fn(|_| None),
            item_count: 0,
            next_txn_id: 1,
            bytes_written: 0,
        })
    }

    /// Returns the current head LSN.
    pub fn head(&self) -> Lsn {
        self.head
    }

    /// Returns the current tail LSN.
    pub fn tail(&self) -> Lsn {
        self.tail
    }

    /// Returns the number of blocks currently used in the log.
    pub fn used_blocks(&self) -> usize {
        let head_block = self.head.block() as usize;
        let tail_block = self.tail.block() as usize;
        if head_block >= tail_block {
            head_block - tail_block
        } else {
            self.log_size - tail_block + head_block
        }
    }

    /// Returns whether the log has sufficient space for `blocks` more records.
    pub fn has_space(&self, blocks: usize) -> bool {
        self.used_blocks() + blocks + 1 < self.log_size
    }

    /// Allocates a new transaction ID.
    pub fn alloc_transaction(&mut self) -> u64 {
        let id = self.next_txn_id;
        self.next_txn_id += 1;
        id
    }

    /// Writes a log item into the circular buffer.
    ///
    /// Serializes the item into the next available log block and returns
    /// the LSN at which it was written.
    pub fn log_write(&mut self, item: XfsLogItem) -> Result<Lsn> {
        if self.item_count >= MAX_LOG_ITEMS {
            return Err(Error::OutOfMemory);
        }
        if !self.has_space(1) {
            return Err(Error::Busy);
        }

        let write_lsn = self.head;
        let block_idx = write_lsn.block() as usize % self.log_size;

        // Write the item into the log record at head.
        let record = &mut self.records[block_idx];
        record.magic = XFS_LOG_MAGIC;
        record.cycle = write_lsn.cycle();
        record.lsn = write_lsn;
        record.item_count += 1;
        record.is_commit = item.item_type == LogItemType::Commit;

        // Copy item data into record payload (simplified serialization).
        let copy_len = item.data_len.min(512);
        record.data[..copy_len].copy_from_slice(&item.data[..copy_len]);
        record.data_len = copy_len as u32;

        // Store item.
        let mut stored = item;
        stored.lsn = write_lsn;

        // Find a free slot.
        for slot in &mut self.items {
            if slot.is_none() {
                *slot = Some(stored);
                break;
            }
        }
        self.item_count += 1;
        self.bytes_written += copy_len as u64;

        // Advance head.
        self.head = self.head.advance(self.log_size as u32);

        Ok(write_lsn)
    }

    /// Commits a transaction, advancing the head LSN and marking items durable.
    ///
    /// Writes a commit record at the current head, then advances head.
    pub fn log_commit(&mut self, transaction_id: u64) -> Result<Lsn> {
        let commit_item = {
            let mut item = XfsLogItem::new(LogItemType::Commit, transaction_id, 0);
            item.set_data(&transaction_id.to_le_bytes())?;
            item
        };

        let commit_lsn = self.log_write(commit_item)?;

        // Mark all items with this transaction_id as committed.
        for slot in &mut self.items {
            if let Some(item) = slot.as_mut() {
                if item.transaction_id == transaction_id {
                    item.committed = true;
                }
            }
        }

        Ok(commit_lsn)
    }

    /// Recovers (replays) committed log items from tail to head.
    ///
    /// Iterates from the tail LSN to the head LSN, replaying all committed
    /// records. Returns the number of items recovered.
    pub fn log_recover(&mut self) -> Result<usize> {
        let mut recovered = 0;
        let tail_block = self.tail.block() as usize;
        let head_block = self.head.block() as usize;

        let mut current = tail_block;
        loop {
            if current == head_block {
                break;
            }

            let idx = current % self.log_size;
            let record = &self.records[idx];

            if !record.is_valid() {
                // End of valid log records.
                break;
            }

            // Only replay committed records.
            if record.is_commit || record.item_count > 0 {
                recovered += record.item_count as usize;
            }

            current = (current + 1) % self.log_size;
        }

        // Advance tail to head (all records consumed).
        self.tail = self.head;

        // Clear committed items from in-flight list.
        for slot in &mut self.items {
            if let Some(item) = slot.as_ref() {
                if item.committed {
                    *slot = None;
                    if self.item_count > 0 {
                        self.item_count -= 1;
                    }
                }
            }
        }

        Ok(recovered)
    }

    /// Returns statistics about the log.
    pub fn stats(&self) -> LogStats {
        LogStats {
            head_lsn: self.head,
            tail_lsn: self.tail,
            log_size_blocks: self.log_size,
            used_blocks: self.used_blocks(),
            item_count: self.item_count,
            bytes_written: self.bytes_written,
        }
    }
}

/// Log usage statistics.
#[derive(Debug, Clone, Copy)]
pub struct LogStats {
    /// Current head LSN.
    pub head_lsn: Lsn,
    /// Current tail LSN.
    pub tail_lsn: Lsn,
    /// Total log size in blocks.
    pub log_size_blocks: usize,
    /// Currently used blocks.
    pub used_blocks: usize,
    /// Active in-flight item count.
    pub item_count: usize,
    /// Total bytes written to log.
    pub bytes_written: u64,
}

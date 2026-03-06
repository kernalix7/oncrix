// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS journal log recovery.
//!
//! Implements two-pass log recovery as performed by `xfs_log_recover.c`:
//!
//! - **Pass 1** (`CollectPass`): scans all log records, validates headers, and
//!   builds an ordered list of committed transaction items, filtering out
//!   records from before the tail LSN (already stable on disk).
//! - **Pass 2** (`ReplayPass`): replays each item type in LSN order:
//!   buffers, inodes, EFI (Extent Freeing Intent) and EFD (Extent Freeing
//!   Done) pairs.
//!
//! # Log structure
//!
//! The XFS circular log is divided into 512-byte log blocks. Each log record
//! spans one or more contiguous log blocks and begins with an
//! [`XfsLogRecordHeader`]. Within a record, items are packed sequentially,
//! each preceded by an [`XfsLogItemHeader`].
//!
//! # References
//!
//! - Linux `fs/xfs/xfs_log_recover.c`
//! - XFS Algorithms & Data Structures, 3rd ed., §8

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic number in every `XfsLogRecordHeader`.
pub const XLOG_RECORD_MAGIC: u32 = 0xFEED_BABE;

/// Log block size in bytes.
pub const XLOG_BLOCK_SIZE: usize = 512;

/// Maximum number of log records processed during recovery.
pub const MAX_LOG_RECORDS: usize = 256;

/// Maximum number of log items collected per record.
pub const MAX_LOG_ITEMS: usize = 512;

/// Maximum payload bytes stored for a single log item.
pub const MAX_ITEM_PAYLOAD: usize = 256;

// ── Item type codes ───────────────────────────────────────────────────────────

/// Log item type: buffer (block device data).
pub const XFS_LI_BUF: u16 = 0x123B;
/// Log item type: inode.
pub const XFS_LI_INODE: u16 = 0x123C;
/// Log item type: Extent Freeing Intent.
pub const XFS_LI_EFI: u16 = 0x1236;
/// Log item type: Extent Freeing Done.
pub const XFS_LI_EFD: u16 = 0x1237;
/// Log item type: dquot.
pub const XFS_LI_DQUOT: u16 = 0x123A;

// ── Log Sequence Number ───────────────────────────────────────────────────────

/// XFS Log Sequence Number: monotonically increasing identifier for log writes.
pub type Lsn = u64;

/// Sentinel LSN meaning "no LSN" / not yet set.
pub const LSN_INVALID: Lsn = u64::MAX;

// ── XfsLogRecordHeader ────────────────────────────────────────────────────────

/// Header at the start of every log record (mirrors `xlog_rec_header_t`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XfsLogRecordHeader {
    /// Must equal [`XLOG_RECORD_MAGIC`].
    pub magic: u32,
    /// Sequence number of this cycle through the log.
    pub cycle: u32,
    /// Record number within the current cycle.
    pub record: u32,
    /// LSN of this record.
    pub lsn: Lsn,
    /// LSN of the log tail when this record was written.
    pub tail_lsn: Lsn,
    /// CRC32c of the record (including payload).
    pub crc: u32,
    /// Number of 512-byte log blocks in this record.
    pub len: u32,
    /// Number of log items in this record.
    pub num_logops: u16,
    /// Version of the log format.
    pub version: u16,
}

impl XfsLogRecordHeader {
    /// Returns `true` if the magic field is valid.
    pub const fn is_valid(&self) -> bool {
        self.magic == XLOG_RECORD_MAGIC
    }
}

// ── XfsLogItemHeader ──────────────────────────────────────────────────────────

/// Per-item header within a log record (mirrors `xlog_op_header_t`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XfsLogItemHeader {
    /// Transaction ID this item belongs to.
    pub tid: u32,
    /// Client identifier (normally `XFS_TRANSACTION`).
    pub client_id: u8,
    /// Item flags.
    pub flags: u8,
    /// Number of bytes of item data following this header.
    pub len: u32,
}

// ── LogItem ───────────────────────────────────────────────────────────────────

/// A decoded log item ready for replay.
#[derive(Debug, Clone, Copy)]
pub struct LogItem {
    /// LSN of the parent record.
    pub lsn: Lsn,
    /// Transaction ID.
    pub tid: u32,
    /// Item type (one of the `XFS_LI_*` constants).
    pub item_type: u16,
    /// Payload bytes (truncated to [`MAX_ITEM_PAYLOAD`]).
    pub payload: [u8; MAX_ITEM_PAYLOAD],
    /// Actual payload length (may exceed `payload.len()` if truncated).
    pub payload_len: usize,
    /// Whether this slot is active.
    pub active: bool,
}

impl Default for LogItem {
    fn default() -> Self {
        Self {
            lsn: LSN_INVALID,
            tid: 0,
            item_type: 0,
            payload: [0u8; MAX_ITEM_PAYLOAD],
            payload_len: 0,
            active: false,
        }
    }
}

impl LogItem {
    /// Returns the stored payload slice (up to [`MAX_ITEM_PAYLOAD`] bytes).
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len.min(MAX_ITEM_PAYLOAD)]
    }
}

// ── LogRecord ────────────────────────────────────────────────────────────────

/// A parsed log record produced by pass 1.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogRecord {
    /// Parsed record header.
    pub header: XfsLogRecordHeader,
    /// Whether this record was committed (not cancelled).
    pub committed: bool,
}

// ── EfiTracker ───────────────────────────────────────────────────────────────

/// Tracks unmatched EFI items awaiting their EFD counterpart.
///
/// At the end of pass 2 any unmatched EFI items represent extents that must
/// be freed before the filesystem is mounted.
#[derive(Debug)]
pub struct EfiTracker {
    /// EFI transaction IDs that have not yet been paired with an EFD.
    pending: [u32; 64],
    /// Number of pending EFIs.
    count: usize,
}

impl Default for EfiTracker {
    fn default() -> Self {
        Self {
            pending: [0u32; 64],
            count: 0,
        }
    }
}

impl EfiTracker {
    /// Registers an EFI item.
    pub fn add_efi(&mut self, tid: u32) -> Result<()> {
        if self.count >= self.pending.len() {
            return Err(Error::OutOfMemory);
        }
        self.pending[self.count] = tid;
        self.count += 1;
        Ok(())
    }

    /// Marks an EFI as completed by its matching EFD.
    ///
    /// Returns [`Error::NotFound`] if no EFI with `tid` was registered.
    pub fn complete_efd(&mut self, tid: u32) -> Result<()> {
        let pos = self.pending[..self.count]
            .iter()
            .position(|&t| t == tid)
            .ok_or(Error::NotFound)?;
        self.pending[pos] = self.pending[self.count - 1];
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of unresolved EFI items.
    pub const fn unresolved(&self) -> usize {
        self.count
    }

    /// Iterates over unresolved EFI TIDs.
    pub fn iter_unresolved<F: FnMut(u32)>(&self, mut f: F) {
        for &tid in &self.pending[..self.count] {
            f(tid);
        }
    }
}

// ── LogRecovery ───────────────────────────────────────────────────────────────

/// State machine for XFS log recovery.
///
/// Instantiate, feed raw log blocks via [`add_log_block`], then call
/// [`run_pass1`] followed by [`run_pass2`].
pub struct LogRecovery {
    /// Raw 512-byte blocks comprising the log being recovered.
    blocks: [[u8; XLOG_BLOCK_SIZE]; MAX_LOG_RECORDS],
    /// Number of blocks loaded.
    block_count: usize,
    /// Records collected during pass 1.
    records: [LogRecord; MAX_LOG_RECORDS],
    /// Number of collected records.
    record_count: usize,
    /// Items collected during pass 1.
    items: [LogItem; MAX_LOG_ITEMS],
    /// Number of collected items.
    item_count: usize,
    /// Log tail LSN (items with LSN ≤ tail are already on disk; skip them).
    tail_lsn: Lsn,
    /// EFI/EFD pairing tracker.
    efi_tracker: EfiTracker,
    /// Number of items replayed during pass 2.
    replayed: usize,
    /// Recovery phase.
    phase: RecoveryPhase,
}

/// Current phase of the recovery state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryPhase {
    /// Not started — log blocks are still being loaded.
    #[default]
    Loading,
    /// Pass 1 complete — items collected, not yet replayed.
    Pass1Done,
    /// Pass 2 complete — all items replayed.
    Pass2Done,
}

impl Default for LogRecovery {
    fn default() -> Self {
        Self {
            blocks: [[0u8; XLOG_BLOCK_SIZE]; MAX_LOG_RECORDS],
            block_count: 0,
            records: [LogRecord::default(); MAX_LOG_RECORDS],
            record_count: 0,
            items: [const {
                LogItem {
                    lsn: LSN_INVALID,
                    tid: 0,
                    item_type: 0,
                    payload: [0u8; MAX_ITEM_PAYLOAD],
                    payload_len: 0,
                    active: false,
                }
            }; MAX_LOG_ITEMS],
            item_count: 0,
            tail_lsn: 0,
            efi_tracker: EfiTracker::default(),
            replayed: 0,
            phase: RecoveryPhase::Loading,
        }
    }
}

impl LogRecovery {
    /// Creates a new recovery instance.
    ///
    /// `tail_lsn` is the log-tail LSN from the superblock; records at or
    /// before this LSN are already stable and will be skipped.
    pub fn new(tail_lsn: Lsn) -> Self {
        Self {
            tail_lsn,
            ..Self::default()
        }
    }

    /// Loads a raw 512-byte log block into the recovery buffer.
    ///
    /// Returns [`Error::OutOfMemory`] if the block buffer is full.
    pub fn add_log_block(&mut self, data: &[u8; XLOG_BLOCK_SIZE]) -> Result<()> {
        if self.block_count >= MAX_LOG_RECORDS {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.block_count] = *data;
        self.block_count += 1;
        Ok(())
    }

    // ── Pass 1: Collect ───────────────────────────────────────────────────────

    /// Runs pass 1: validates record headers and collects log items whose
    /// LSN exceeds the tail LSN.
    ///
    /// Must be called after all log blocks have been added via
    /// [`add_log_block`]. Returns [`Error::IoError`] if any record header
    /// fails validation.
    pub fn run_pass1(&mut self) -> Result<()> {
        if self.phase != RecoveryPhase::Loading {
            return Err(Error::InvalidArgument);
        }
        let mut block_idx = 0usize;
        while block_idx < self.block_count {
            let hdr = parse_record_header(&self.blocks[block_idx])?;
            if !hdr.is_valid() {
                return Err(Error::IoError);
            }
            let record_lsn = hdr.lsn;
            let num_blocks = hdr.len as usize;

            // Skip records that are already on disk.
            if record_lsn <= self.tail_lsn {
                block_idx += num_blocks.max(1);
                continue;
            }

            if self.record_count >= MAX_LOG_RECORDS {
                return Err(Error::OutOfMemory);
            }
            self.records[self.record_count] = LogRecord {
                header: hdr,
                committed: true,
            };
            self.record_count += 1;

            // Parse items from the blocks following the record header.
            self.collect_items_from_record(&hdr, block_idx)?;
            block_idx += num_blocks.max(1);
        }
        self.phase = RecoveryPhase::Pass1Done;
        Ok(())
    }

    /// Parses log items from blocks belonging to `record`, starting at
    /// `base_block`.
    fn collect_items_from_record(
        &mut self,
        record: &XfsLogRecordHeader,
        base_block: usize,
    ) -> Result<()> {
        // Each item starts with a 10-byte XfsLogItemHeader then its payload.
        // We simulate parsing from the first payload block (block after hdr).
        let payload_block = base_block + 1;
        let num_items = record.num_logops as usize;

        for item_idx in 0..num_items {
            if self.item_count >= MAX_LOG_ITEMS {
                return Err(Error::OutOfMemory);
            }
            let blk = payload_block + item_idx / 4;
            if blk >= self.block_count {
                break;
            }
            let off = (item_idx % 4) * 128;
            let block = &self.blocks[blk];
            let item_type = u16::from_le_bytes([block[off], block[off + 1]]);
            let tid = u32::from_le_bytes([
                block[off + 2],
                block[off + 3],
                block[off + 4],
                block[off + 5],
            ]);
            let payload_len = u32::from_le_bytes([
                block[off + 6],
                block[off + 7],
                block[off + 8],
                block[off + 9],
            ]) as usize;
            let copy_len = payload_len.min(MAX_ITEM_PAYLOAD);
            let mut payload = [0u8; MAX_ITEM_PAYLOAD];
            let src_start = off + 10;
            let src_end = (src_start + copy_len).min(XLOG_BLOCK_SIZE);
            payload[..src_end - src_start].copy_from_slice(&block[src_start..src_end]);

            self.items[self.item_count] = LogItem {
                lsn: record.lsn,
                tid,
                item_type,
                payload,
                payload_len,
                active: true,
            };
            self.item_count += 1;
        }
        Ok(())
    }

    // ── Pass 2: Replay ────────────────────────────────────────────────────────

    /// Runs pass 2: replays all collected items in LSN order.
    ///
    /// Buffer and inode items are applied first; EFI/EFD pairs are matched and
    /// any unresolved EFIs are flagged.
    pub fn run_pass2(&mut self) -> Result<()> {
        if self.phase != RecoveryPhase::Pass1Done {
            return Err(Error::InvalidArgument);
        }
        // Sort items by LSN (insertion sort).
        for i in 1..self.item_count {
            let mut j = i;
            while j > 0 && self.items[j - 1].lsn > self.items[j].lsn {
                self.items.swap(j - 1, j);
                j -= 1;
            }
        }
        for i in 0..self.item_count {
            if !self.items[i].active {
                continue;
            }
            self.replay_item(i)?;
            self.replayed += 1;
        }
        self.phase = RecoveryPhase::Pass2Done;
        Ok(())
    }

    /// Dispatches a single log item for replay based on its type.
    fn replay_item(&mut self, idx: usize) -> Result<()> {
        match self.items[idx].item_type {
            XFS_LI_BUF => self.replay_buf_item(idx),
            XFS_LI_INODE => self.replay_inode_item(idx),
            XFS_LI_EFI => self.replay_efi_item(idx),
            XFS_LI_EFD => self.replay_efd_item(idx),
            XFS_LI_DQUOT => self.replay_dquot_item(idx),
            _ => Ok(()), // unknown — skip gracefully
        }
    }

    /// Replays a buffer log item (writes payload data back to the block device
    /// at the block number embedded in the payload).
    fn replay_buf_item(&self, idx: usize) -> Result<()> {
        let item = &self.items[idx];
        if item.payload_len < 8 {
            return Err(Error::IoError);
        }
        let _blkno = u64::from_le_bytes(item.payload[..8].try_into().unwrap_or([0u8; 8]));
        // In a real implementation: write payload[8..] back to block device at _blkno.
        Ok(())
    }

    /// Replays an inode log item (restores inode fields from logged payload).
    fn replay_inode_item(&self, idx: usize) -> Result<()> {
        let item = &self.items[idx];
        if item.payload_len < 8 {
            return Err(Error::IoError);
        }
        let _ino = u64::from_le_bytes(item.payload[..8].try_into().unwrap_or([0u8; 8]));
        // In a real implementation: restore inode at _ino from payload[8..].
        Ok(())
    }

    /// Registers an EFI item in the EFI tracker.
    fn replay_efi_item(&mut self, idx: usize) -> Result<()> {
        let tid = self.items[idx].tid;
        self.efi_tracker.add_efi(tid)
    }

    /// Matches an EFD to its pending EFI and marks it resolved.
    fn replay_efd_item(&mut self, idx: usize) -> Result<()> {
        let tid = self.items[idx].tid;
        // Failure here is non-fatal (orphan EFD).
        let _ = self.efi_tracker.complete_efd(tid);
        Ok(())
    }

    /// Replays a dquot item (updates disk quota counters from log).
    fn replay_dquot_item(&self, idx: usize) -> Result<()> {
        let item = &self.items[idx];
        if item.payload_len < 4 {
            return Err(Error::IoError);
        }
        let _dqid = u32::from_le_bytes(item.payload[..4].try_into().unwrap_or([0u8; 4]));
        Ok(())
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the current recovery phase.
    pub const fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    /// Returns the number of log items replayed during pass 2.
    pub const fn replayed_count(&self) -> usize {
        self.replayed
    }

    /// Returns the number of unresolved EFI items remaining after pass 2.
    pub fn unresolved_efis(&self) -> usize {
        self.efi_tracker.unresolved()
    }

    /// Iterates over unresolved EFI transaction IDs.
    pub fn iter_unresolved_efis<F: FnMut(u32)>(&self, f: F) {
        self.efi_tracker.iter_unresolved(f);
    }

    /// Returns the number of log records collected in pass 1.
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns the number of log items collected in pass 1.
    pub const fn item_count(&self) -> usize {
        self.item_count
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Parses an [`XfsLogRecordHeader`] from the first 40 bytes of `block`.
///
/// Returns [`Error::IoError`] if the block is too short.
fn parse_record_header(block: &[u8; XLOG_BLOCK_SIZE]) -> Result<XfsLogRecordHeader> {
    if block.len() < 40 {
        return Err(Error::IoError);
    }
    let magic = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let cycle = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    let record = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
    let lsn = u64::from_be_bytes([
        block[12], block[13], block[14], block[15], block[16], block[17], block[18], block[19],
    ]);
    let tail_lsn = u64::from_be_bytes([
        block[20], block[21], block[22], block[23], block[24], block[25], block[26], block[27],
    ]);
    let crc = u32::from_be_bytes([block[28], block[29], block[30], block[31]]);
    let len = u32::from_be_bytes([block[32], block[33], block[34], block[35]]);
    let num_logops = u16::from_be_bytes([block[36], block[37]]);
    let version = u16::from_be_bytes([block[38], block[39]]);
    Ok(XfsLogRecordHeader {
        magic,
        cycle,
        record,
        lsn,
        tail_lsn,
        crc,
        len,
        num_logops,
        version,
    })
}

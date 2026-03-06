// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS flush and checkpoint synchronisation.
//!
//! F2FS uses checkpoints as the primary mechanism for ensuring filesystem
//! consistency.  A checkpoint captures a consistent snapshot of all in-memory
//! state — node pages, data pages, and the segment summary area — and writes
//! it atomically to the checkpoint area (CP) on storage.
//!
//! # Checkpoint structure
//!
//! ```text
//! CP area layout:
//! ┌────────────────────────────────────────────────────────┐
//! │  Checkpoint Header Pack 1 (CP block 0)                 │
//! │    - cp_ver, elapsed_time, alloc_type, cp_pack_bits    │
//! │    - active segment numbers, free segment count        │
//! │  Node summary area (NAT/SIT bitmaps)                   │
//! │  Orphan inode list                                     │
//! │  Checkpoint Footer Pack 1 (CRC, cp_pack_total_block_count) │
//! ├────────────────────────────────────────────────────────┤
//! │  CP area Pack 2 (same layout, alternate write target)  │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! # Flush trigger conditions
//!
//! - `fsync(2)` on a data file (triggers a partial or full flush).
//! - Periodic background checkpoint (kthread wakeup, default: 5 s).
//! - Segment exhaustion (no more free segments available).
//! - Umount sequence (final flush with `CP_UMOUNT_FLAG`).
//! - Error recovery (`CP_ERROR_FLAG`).
//!
//! # References
//!
//! - Linux `fs/f2fs/checkpoint.c`, `fs/f2fs/segment.c`
//! - F2FS design document: `Documentation/filesystems/f2fs.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of orphan inodes tracked in a single checkpoint.
pub const MAX_ORPHAN_INODES: usize = 128;

/// Maximum number of dirty node pages captured per flush.
pub const MAX_DIRTY_NODES: usize = 256;

/// Checkpoint pack 1 is stored starting at this logical block offset.
pub const CP_PACK1_START: u64 = 0;
/// Checkpoint pack 2 is stored starting at this logical block offset.
pub const CP_PACK2_START: u64 = 512;

/// F2FS checkpoint magic.
pub const CP_MAGIC: u32 = 0xF2F5_2010;

// ---------------------------------------------------------------------------
// Checkpoint flag bits
// ---------------------------------------------------------------------------

/// Normal checkpoint (neither umount nor error recovery).
pub const CP_NONE_FLAG: u32 = 0x0000_0000;
/// Checkpoint was written during `umount`.
pub const CP_UMOUNT_FLAG: u32 = 0x0000_0001;
/// Checkpoint records a compaction GC pass.
pub const CP_COMPACT_SUM_FLAG: u32 = 0x0000_0002;
/// Error recovery checkpoint.
pub const CP_ERROR_FLAG: u32 = 0x0000_0004;
/// Checkpoint includes an orphan inode list.
pub const CP_ORPHAN_PRESENT_FLAG: u32 = 0x0000_0008;
/// Checkpoint triggers a trimming pass on next mount.
pub const CP_TRIMMED_FLAG: u32 = 0x0000_0010;
/// Checkpoint was written with CRC enabled.
pub const CP_CRC_RECOVERY_FLAG: u32 = 0x0000_0020;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// On-disk F2FS checkpoint header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CheckpointHeader {
    /// Checkpoint magic number.
    pub magic: u32,
    /// Checkpoint version, monotonically increasing.
    pub cp_ver: u64,
    /// Elapsed time in seconds since the filesystem was formatted.
    pub elapsed_time: u64,
    /// Combination of `CP_*_FLAG` bits.
    pub cp_flags: u32,
    /// Number of blocks in one checkpoint pack (header + data + footer).
    pub cp_pack_total_block_count: u32,
    /// Number of valid blocks in the NAT bitmap.
    pub valid_node_count: u32,
    /// Number of valid inodes.
    pub valid_inode_count: u32,
    /// Number of free segments at the time of this checkpoint.
    pub free_segment_count: u32,
    /// Segment number of the current node segment.
    pub cur_node_segno: u32,
    /// Block offset within `cur_node_segno`.
    pub cur_node_blkoff: u16,
    /// Segment number of the current data segment.
    pub cur_data_segno: u32,
    /// Block offset within `cur_data_segno`.
    pub cur_data_blkoff: u16,
    /// CRC32 of the entire checkpoint pack.
    pub checksum: u32,
}

/// In-memory representation of a pending checkpoint.
#[derive(Debug)]
pub struct PendingCheckpoint {
    /// Checkpoint header to be written.
    pub header: CheckpointHeader,
    /// Orphan inodes captured at the time of this checkpoint.
    pub orphan_inos: [u32; MAX_ORPHAN_INODES],
    /// Number of valid orphan inodes.
    pub n_orphans: usize,
    /// Dirty node page addresses captured for this checkpoint.
    pub dirty_nodes: [u64; MAX_DIRTY_NODES],
    /// Number of dirty nodes captured.
    pub n_dirty_nodes: usize,
    /// Whether this checkpoint has been written to storage.
    pub committed: bool,
}

impl PendingCheckpoint {
    /// Create a new pending checkpoint with default flags.
    pub fn new(cp_ver: u64, flags: u32) -> Self {
        Self {
            header: CheckpointHeader {
                magic: CP_MAGIC,
                cp_ver,
                elapsed_time: 0,
                cp_flags: flags,
                cp_pack_total_block_count: 0,
                valid_node_count: 0,
                valid_inode_count: 0,
                free_segment_count: 0,
                cur_node_segno: 0,
                cur_node_blkoff: 0,
                cur_data_segno: 0,
                cur_data_blkoff: 0,
                checksum: 0,
            },
            orphan_inos: [0u32; MAX_ORPHAN_INODES],
            n_orphans: 0,
            dirty_nodes: [0u64; MAX_DIRTY_NODES],
            n_dirty_nodes: 0,
            committed: false,
        }
    }

    /// Add an orphan inode to this checkpoint.
    pub fn add_orphan(&mut self, ino: u32) -> Result<()> {
        if self.n_orphans >= MAX_ORPHAN_INODES {
            return Err(Error::OutOfMemory);
        }
        self.orphan_inos[self.n_orphans] = ino;
        self.n_orphans += 1;
        if self.n_orphans > 0 {
            self.header.cp_flags |= CP_ORPHAN_PRESENT_FLAG;
        }
        Ok(())
    }

    /// Record a dirty node page address for flush.
    pub fn add_dirty_node(&mut self, blkaddr: u64) -> Result<()> {
        if self.n_dirty_nodes >= MAX_DIRTY_NODES {
            return Err(Error::OutOfMemory);
        }
        self.dirty_nodes[self.n_dirty_nodes] = blkaddr;
        self.n_dirty_nodes += 1;
        Ok(())
    }

    /// Compute a simple checksum over the header fields.
    pub fn compute_checksum(&mut self) {
        let mut crc = self.header.magic;
        crc ^= (self.header.cp_ver & 0xFFFF_FFFF) as u32;
        crc ^= self.header.cp_flags;
        crc ^= self.header.free_segment_count;
        crc ^= self.header.valid_node_count;
        self.header.checksum = crc;
    }
}

// ---------------------------------------------------------------------------
// Flush state machine
// ---------------------------------------------------------------------------

/// Phase of an in-progress flush operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushPhase {
    /// Initial state: no flush in progress.
    Idle,
    /// Collecting dirty pages and orphan inodes.
    Collecting,
    /// Writing node pages to the current node segment.
    WritingNodes,
    /// Writing data pages to the current data segment.
    WritingData,
    /// Writing the checkpoint header and footer.
    WritingCheckpoint,
    /// Waiting for I/O completion.
    WaitingIo,
    /// Flush completed successfully.
    Done,
    /// Flush failed.
    Failed,
}

/// F2FS flush / checkpoint controller for a single mounted filesystem.
#[derive(Debug)]
pub struct F2fsFlushCtrl {
    /// Monotonically increasing checkpoint version counter.
    pub cp_ver: u64,
    /// Current flush phase.
    pub phase: FlushPhase,
    /// Pending checkpoint being assembled (if `phase != Idle`).
    pub pending: Option<PendingCheckpoint>,
    /// Which checkpoint pack to write next (alternates between 1 and 2).
    pub next_pack: u8,
    /// Total number of successful checkpoints written.
    pub cp_written: u64,
    /// Total number of failed checkpoint attempts.
    pub cp_failed: u64,
    /// Whether background flushing (periodic kthread) is enabled.
    pub bg_flush_enabled: bool,
    /// Background flush interval in milliseconds.
    pub bg_flush_interval_ms: u64,
    /// Last background flush timestamp (abstract time units).
    pub last_bg_flush_time: u64,
}

impl F2fsFlushCtrl {
    /// Create a new flush controller starting from checkpoint version `cp_ver`.
    pub fn new(cp_ver: u64) -> Self {
        Self {
            cp_ver,
            phase: FlushPhase::Idle,
            pending: None,
            next_pack: 1,
            cp_written: 0,
            cp_failed: 0,
            bg_flush_enabled: true,
            bg_flush_interval_ms: 5_000,
            last_bg_flush_time: 0,
        }
    }

    /// Begin a new flush cycle.
    ///
    /// Returns `Err(Busy)` if a flush is already in progress.
    pub fn begin_flush(&mut self, flags: u32) -> Result<()> {
        if self.phase != FlushPhase::Idle {
            return Err(Error::Busy);
        }
        self.cp_ver += 1;
        let cp = PendingCheckpoint::new(self.cp_ver, flags);
        self.pending = Some(cp);
        self.phase = FlushPhase::Collecting;
        Ok(())
    }

    /// Add an orphan inode to the pending checkpoint.
    ///
    /// Returns `Err(InvalidArgument)` if no flush is in progress.
    pub fn add_orphan(&mut self, ino: u32) -> Result<()> {
        match &mut self.pending {
            Some(cp) => cp.add_orphan(ino),
            None => Err(Error::InvalidArgument),
        }
    }

    /// Add a dirty node page to the pending checkpoint.
    pub fn add_dirty_node(&mut self, blkaddr: u64) -> Result<()> {
        match &mut self.pending {
            Some(cp) => cp.add_dirty_node(blkaddr),
            None => Err(Error::InvalidArgument),
        }
    }

    /// Advance the flush through the node-writing phase.
    pub fn advance_to_write_nodes(&mut self) -> Result<()> {
        if self.phase != FlushPhase::Collecting {
            return Err(Error::InvalidArgument);
        }
        self.phase = FlushPhase::WritingNodes;
        Ok(())
    }

    /// Advance the flush through the data-writing phase.
    pub fn advance_to_write_data(&mut self) -> Result<()> {
        if self.phase != FlushPhase::WritingNodes {
            return Err(Error::InvalidArgument);
        }
        self.phase = FlushPhase::WritingData;
        Ok(())
    }

    /// Commit the checkpoint header and footer, completing the flush cycle.
    ///
    /// Returns the checkpoint version that was written.
    pub fn commit(&mut self) -> Result<u64> {
        if self.phase != FlushPhase::WritingData {
            return Err(Error::InvalidArgument);
        }
        self.phase = FlushPhase::WritingCheckpoint;
        let cp = self.pending.as_mut().ok_or(Error::InvalidArgument)?;
        cp.compute_checksum();
        cp.committed = true;
        let ver = cp.header.cp_ver;
        self.phase = FlushPhase::Done;
        self.cp_written += 1;
        self.next_pack = if self.next_pack == 1 { 2 } else { 1 };
        self.pending = None;
        self.phase = FlushPhase::Idle;
        Ok(ver)
    }

    /// Abort the current flush cycle (e.g., on I/O error).
    pub fn abort(&mut self) {
        self.cp_failed += 1;
        self.pending = None;
        self.phase = FlushPhase::Failed;
        // Allow restart.
        self.phase = FlushPhase::Idle;
    }

    /// Run a complete flush cycle from `Idle → Done` in one call.
    ///
    /// This convenience function is used in test paths and simple recovery.
    ///
    /// Returns the committed checkpoint version.
    pub fn run_full_flush(&mut self, flags: u32) -> Result<u64> {
        self.begin_flush(flags)?;
        self.advance_to_write_nodes()?;
        self.advance_to_write_data()?;
        self.commit()
    }

    /// Check whether a background flush should be triggered given the current
    /// monotonic time `now_ms`.
    pub fn should_bg_flush(&self, now_ms: u64) -> bool {
        self.bg_flush_enabled
            && self.phase == FlushPhase::Idle
            && now_ms.saturating_sub(self.last_bg_flush_time) >= self.bg_flush_interval_ms
    }

    /// Record that a background flush was triggered at time `now_ms`.
    pub fn record_bg_flush(&mut self, now_ms: u64) {
        self.last_bg_flush_time = now_ms;
    }

    /// Return the logical block address of the checkpoint pack to write next.
    pub fn current_cp_start_lba(&self) -> u64 {
        if self.next_pack == 1 {
            CP_PACK1_START
        } else {
            CP_PACK2_START
        }
    }
}

// ---------------------------------------------------------------------------
// fsync helper
// ---------------------------------------------------------------------------

/// Outcome of an fsync-triggered flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsyncOutcome {
    /// fsync was satisfied by a partial flush (node pages only).
    Partial,
    /// fsync triggered a full checkpoint.
    FullCheckpoint,
    /// fsync required no I/O (file was clean).
    AlreadyClean,
}

/// Decide whether an fsync for `ino` requires a full checkpoint or only a
/// partial node-page flush.
///
/// F2FS uses a heuristic: if the inode's node chain is shorter than
/// `FSYNC_NODE_THRESHOLD`, a partial flush is sufficient.
pub fn fsync_decide_flush_depth(dirty_node_count: u32) -> FsyncOutcome {
    const FSYNC_NODE_THRESHOLD: u32 = 8;
    if dirty_node_count == 0 {
        FsyncOutcome::AlreadyClean
    } else if dirty_node_count < FSYNC_NODE_THRESHOLD {
        FsyncOutcome::Partial
    } else {
        FsyncOutcome::FullCheckpoint
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS checkpoint and recovery.
//!
//! F2FS uses a dual-checkpoint scheme to ensure crash consistency. Two
//! checkpoint areas (CP area 1 and CP area 2) are maintained, and they
//! alternate as the active checkpoint. Recovery reads the more recent
//! valid checkpoint and replays the roll-forward log.

use oncrix_lib::{Error, Result};

/// F2FS magic number in the super block.
pub const F2FS_MAGIC: u32 = 0xF2F5_2010;

/// Checkpoint flag: final checkpoint (vs. interim).
pub const CP_FINAL_FLAG: u32 = 0x0001;
/// Checkpoint flag: compacted summary.
pub const CP_COMPACT_SUM_FLAG: u32 = 0x0002;
/// Checkpoint flag: error occurred.
pub const CP_ERROR_FLAG: u32 = 0x0008;
/// Checkpoint flag: node summary present.
pub const CP_NODE_SUMMARY_FLAG: u32 = 0x0080;
/// Checkpoint flag: fsck required.
pub const CP_FSCK_FLAG: u32 = 0x0100;

/// Size of the checkpoint pack header (bytes).
pub const CP_CHKSUM_OFFSET: usize = 4092;
/// Number of valid entries in the checkpoint orphan list per block.
pub const MAX_ORPHAN_INODE_ENTRY: usize = 1020;

/// Checkpoint pack header as stored on disk.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawCheckpoint {
    /// Checkpoint version (sequence number).
    pub checkpoint_ver: u64,
    /// User block count.
    pub user_block_count: u64,
    /// Valid block count.
    pub valid_block_count: u64,
    /// Reserved block count.
    pub rsvd_segment_count: u32,
    /// Occupied segment count.
    pub overprov_segment_count: u32,
    /// Free segment count at checkpoint.
    pub free_segment_count: u32,
    /// Information about current data/node segments (12 entries).
    pub cur_data_segno: [u32; 8],
    pub cur_data_blkoff: [u16; 8],
    pub cur_node_segno: [u32; 8],
    pub cur_node_blkoff: [u16; 8],
    /// NAT (node address table) version bitmap.
    pub nat_upd_block_count: u32,
    pub nat_bits_version: u32,
    /// SIT (segment information table) journal entries.
    pub sit_nat_journaling: u32,
    /// Checkpoint flags.
    pub cp_pack_total_block_count: u32,
    pub cp_pack_start_sum: u32,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub next_free_nid: u32,
    pub sit_ver_bitmap_bytesize: u32,
    pub nat_ver_bitmap_bytesize: u32,
    pub checksum_offset: u32,
    pub elapsed_time: u64,
    /// Checkpoint flags.
    pub ckpt_flags: u32,
    pub cp_pack_bitmap: u32,
    pub reserved: [u8; 8],
}

impl RawCheckpoint {
    /// Check whether this checkpoint was written cleanly.
    pub fn is_clean(&self) -> bool {
        self.ckpt_flags & CP_ERROR_FLAG == 0
    }

    /// Check whether fsck is required.
    pub fn needs_fsck(&self) -> bool {
        self.ckpt_flags & CP_FSCK_FLAG != 0
    }
}

/// In-memory representation of a checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Checkpoint version (monotonically increasing).
    pub version: u64,
    /// Timestamp in seconds since epoch.
    pub elapsed_time: u64,
    /// Valid block count at the time of checkpoint.
    pub valid_block_count: u64,
    /// Free segment count at checkpoint.
    pub free_segment_count: u32,
    /// Valid node count.
    pub valid_node_count: u32,
    /// Valid inode count.
    pub valid_inode_count: u32,
    /// Checkpoint flags.
    pub flags: u32,
    /// Current segment numbers (per stream type).
    pub cur_segno: [u32; 6],
    /// Current block offsets within current segments.
    pub cur_blkoff: [u16; 6],
    /// Orphan inode list (inodes with no dentries).
    pub orphan_inodes: [u32; 32],
    /// Number of valid orphan entries.
    pub orphan_count: u32,
}

impl Checkpoint {
    /// Create a new empty checkpoint.
    pub const fn new() -> Self {
        Self {
            version: 0,
            elapsed_time: 0,
            valid_block_count: 0,
            free_segment_count: 0,
            valid_node_count: 0,
            valid_inode_count: 0,
            flags: 0,
            cur_segno: [0u32; 6],
            cur_blkoff: [0u16; 6],
            orphan_inodes: [0u32; 32],
            orphan_count: 0,
        }
    }

    /// Return true if this checkpoint is newer than `other`.
    pub fn is_newer_than(&self, other: &Checkpoint) -> bool {
        self.version > other.version
    }

    /// Add an orphan inode to the list.
    pub fn add_orphan(&mut self, ino: u32) -> Result<()> {
        if self.orphan_count >= self.orphan_inodes.len() as u32 {
            return Err(Error::OutOfMemory);
        }
        // Avoid duplicates.
        for i in 0..self.orphan_count as usize {
            if self.orphan_inodes[i] == ino {
                return Ok(());
            }
        }
        self.orphan_inodes[self.orphan_count as usize] = ino;
        self.orphan_count += 1;
        Ok(())
    }

    /// Remove an orphan inode from the list.
    pub fn remove_orphan(&mut self, ino: u32) {
        for i in 0..self.orphan_count as usize {
            if self.orphan_inodes[i] == ino {
                // Swap with last.
                let last = self.orphan_count as usize - 1;
                self.orphan_inodes[i] = self.orphan_inodes[last];
                self.orphan_count -= 1;
                return;
            }
        }
    }

    /// Iterate over orphan inodes.
    pub fn orphans(&self) -> &[u32] {
        &self.orphan_inodes[..self.orphan_count as usize]
    }
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// Checkpoint manager — owns the two checkpoint areas.
#[derive(Debug)]
pub struct CheckpointManager {
    /// Checkpoint area 0.
    pub cp0: Checkpoint,
    /// Checkpoint area 1.
    pub cp1: Checkpoint,
    /// Index of the currently active checkpoint area (0 or 1).
    pub active: u8,
    /// Whether a checkpoint is currently in progress.
    pub in_progress: bool,
    /// Pending checkpoint accumulation.
    pub pending: Checkpoint,
}

impl CheckpointManager {
    /// Create a new checkpoint manager.
    pub const fn new() -> Self {
        Self {
            cp0: Checkpoint::new(),
            cp1: Checkpoint::new(),
            active: 0,
            in_progress: false,
            pending: Checkpoint::new(),
        }
    }

    /// Return a reference to the currently active checkpoint.
    pub fn active_cp(&self) -> &Checkpoint {
        if self.active == 0 {
            &self.cp0
        } else {
            &self.cp1
        }
    }

    /// Begin a new checkpoint transaction.
    pub fn begin_checkpoint(&mut self) -> Result<()> {
        if self.in_progress {
            return Err(Error::Busy);
        }
        self.in_progress = true;
        // Snapshot current state into pending.
        self.pending = self.active_cp().clone();
        self.pending.version += 1;
        Ok(())
    }

    /// Commit the pending checkpoint to the inactive area.
    ///
    /// This alternates active <-> inactive using the dual-CP scheme.
    pub fn commit_checkpoint(&mut self, elapsed_time: u64) -> Result<()> {
        if !self.in_progress {
            return Err(Error::InvalidArgument);
        }
        self.pending.elapsed_time = elapsed_time;
        self.pending.flags = CP_FINAL_FLAG;

        // Write to the inactive area.
        let inactive = 1 - self.active;
        if inactive == 0 {
            self.cp0 = self.pending.clone();
        } else {
            self.cp1 = self.pending.clone();
        }
        // Swap active.
        self.active = inactive;
        self.in_progress = false;
        Ok(())
    }

    /// Abort a pending checkpoint (e.g., on error).
    pub fn abort_checkpoint(&mut self) {
        self.in_progress = false;
    }

    /// Update block counts in the pending checkpoint.
    pub fn update_counts(
        &mut self,
        valid_blocks: u64,
        free_segs: u32,
        valid_nodes: u32,
        valid_inodes: u32,
    ) -> Result<()> {
        if !self.in_progress {
            return Err(Error::InvalidArgument);
        }
        self.pending.valid_block_count = valid_blocks;
        self.pending.free_segment_count = free_segs;
        self.pending.valid_node_count = valid_nodes;
        self.pending.valid_inode_count = valid_inodes;
        Ok(())
    }

    /// Update current segment positions in the pending checkpoint.
    pub fn update_curseg(&mut self, seg_type: usize, segno: u32, blkoff: u16) -> Result<()> {
        if !self.in_progress {
            return Err(Error::InvalidArgument);
        }
        if seg_type >= 6 {
            return Err(Error::InvalidArgument);
        }
        self.pending.cur_segno[seg_type] = segno;
        self.pending.cur_blkoff[seg_type] = blkoff;
        Ok(())
    }

    /// Add an orphan inode to the pending checkpoint.
    pub fn add_orphan(&mut self, ino: u32) -> Result<()> {
        if !self.in_progress {
            return Err(Error::InvalidArgument);
        }
        self.pending.add_orphan(ino)
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    /// No recovery needed.
    Clean,
    /// Roll-forward recovery in progress.
    RollForward,
    /// Recovery completed.
    Done,
    /// Recovery failed.
    Failed,
}

/// F2FS roll-forward recovery context.
#[derive(Debug)]
pub struct RecoveryContext {
    /// Current recovery state.
    pub state: RecoveryState,
    /// Checkpoint used as recovery base.
    pub base_version: u64,
    /// Number of blocks recovered.
    pub recovered_blocks: u64,
    /// Number of orphan inodes processed.
    pub orphans_processed: u32,
}

impl RecoveryContext {
    /// Create a new recovery context.
    pub const fn new() -> Self {
        Self {
            state: RecoveryState::Clean,
            base_version: 0,
            recovered_blocks: 0,
            orphans_processed: 0,
        }
    }

    /// Begin recovery from the given checkpoint.
    pub fn begin(&mut self, base_version: u64) {
        self.state = RecoveryState::RollForward;
        self.base_version = base_version;
        self.recovered_blocks = 0;
        self.orphans_processed = 0;
    }

    /// Record a recovered block.
    pub fn record_block(&mut self) {
        self.recovered_blocks += 1;
    }

    /// Record an orphan processed.
    pub fn record_orphan(&mut self) {
        self.orphans_processed += 1;
    }

    /// Mark recovery as complete.
    pub fn finish(&mut self) {
        self.state = RecoveryState::Done;
    }

    /// Mark recovery as failed.
    pub fn fail(&mut self) {
        self.state = RecoveryState::Failed;
    }
}

impl Default for RecoveryContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Select the more recent valid checkpoint from two candidates.
///
/// Returns a reference to the newer checkpoint, or an error if both are invalid.
pub fn select_active_checkpoint<'a>(
    cp0: &'a Checkpoint,
    cp1: &'a Checkpoint,
) -> Result<&'a Checkpoint> {
    let cp0_valid = cp0.flags & CP_ERROR_FLAG == 0;
    let cp1_valid = cp1.flags & CP_ERROR_FLAG == 0;

    match (cp0_valid, cp1_valid) {
        (true, true) => {
            if cp0.is_newer_than(cp1) {
                Ok(cp0)
            } else {
                Ok(cp1)
            }
        }
        (true, false) => Ok(cp0),
        (false, true) => Ok(cp1),
        (false, false) => Err(Error::IoError),
    }
}

/// Process orphan inodes found in a checkpoint during recovery.
///
/// In a real implementation this would truncate and delete each orphan inode.
/// Here we invoke the callback for each orphan.
pub fn process_orphans<F>(cp: &Checkpoint, mut on_orphan: F) -> Result<()>
where
    F: FnMut(u32) -> Result<()>,
{
    for &ino in cp.orphans() {
        on_orphan(ino)?;
    }
    Ok(())
}

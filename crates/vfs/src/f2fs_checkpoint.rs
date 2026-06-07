// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS checkpoint and recovery.
//!
//! F2FS uses a dual-checkpoint scheme to ensure crash consistency. Two
//! checkpoint areas (CP area 1 and CP area 2) are maintained, and they
//! alternate as the active checkpoint. Recovery reads the more recent
//! valid checkpoint and replays the roll-forward log.

use oncrix_lib::{Error, Result};

// ── Block size ───────────────────────────────────────────────────────────────

/// F2FS block size in bytes (always 4096).
pub const BLOCK_SIZE: usize = 4096;

// ── CRC32 (zlib / ISO 3309, reflected poly 0xEDB88320) ──────────────────────

/// Software CRC32 using the zlib / ISO 3309 polynomial (reflected bit order).
///
/// F2FS uses standard zlib CRC32 (same poly as cramfs) to protect checkpoint
/// blocks.  The reflected polynomial 0xEDB8_8320 matches the Linux F2FS
/// implementation (`f2fs_crc32`).
///
/// # SECURITY
///
/// Do NOT substitute crc32c (Castagnoli) or any weaker hash — the checkpoint
/// integrity check would become forgeable by an attacker supplying a crafted
/// filesystem image.
fn crc32_zlib(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

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

/// Verify the integrity of a raw F2FS checkpoint block before parsing.
///
/// This function MUST be called on the raw on-disk bytes of a checkpoint block
/// before the block is trusted.  It performs three security checks:
///
/// 1. **checksum_offset bounds** — the 4-byte CRC stored at `checksum_offset`
///    must fit within the block.
/// 2. **CRC32 verification** — the CRC32 (zlib) over the first `checksum_offset`
///    bytes must equal the stored 4-byte CRC.
/// 3. **bitmap bytesize** — `sit_ver_bitmap_bytesize` and
///    `nat_ver_bitmap_bytesize` must not exceed the total bytes available in
///    the checkpoint pack (`cp_pack_total_block_count * BLOCK_SIZE`).
///
/// # SECURITY
///
/// A mounted filesystem image is fully attacker-controlled.  Accepting a
/// checkpoint without CRC verification means a forged checkpoint is fully
/// trusted, allowing arbitrary file-system state to be injected at mount time.
/// An oversized bitmap bytesize can cause an out-of-bounds slice index.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the block is shorter than
/// `BLOCK_SIZE`, `checksum_offset` is out of range, the CRC does not match,
/// or either bitmap size exceeds the pack capacity.
pub fn verify_raw_checkpoint(block: &[u8]) -> Result<()> {
    // The checkpoint block must be exactly one F2FS block.
    if block.len() < BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Parse the on-disk fields we need.  All fields are little-endian u32 at
    // fixed offsets derived from the RawCheckpoint layout:
    //
    //   offset   field
    //   ──────   ──────────────────────────────
    //    0.. 7   checkpoint_ver (u64)
    //    8..15   user_block_count (u64)
    //   16..23   valid_block_count (u64)
    //   24..27   rsvd_segment_count (u32)
    //   28..31   overprov_segment_count (u32)
    //   32..35   free_segment_count (u32)
    //   36..67   cur_data_segno [8×u32]
    //   68..83   cur_data_blkoff [8×u16]
    //   84..115  cur_node_segno [8×u32]
    //  116..131  cur_node_blkoff [8×u16]
    //  132..135  nat_upd_block_count (u32)
    //  136..139  nat_bits_version (u32)
    //  140..143  sit_nat_journaling (u32)
    //  144..147  cp_pack_total_block_count (u32)
    //  148..151  cp_pack_start_sum (u32)
    //  152..155  valid_node_count (u32)
    //  156..159  valid_inode_count (u32)
    //  160..163  next_free_nid (u32)
    //  164..167  sit_ver_bitmap_bytesize (u32)
    //  168..171  nat_ver_bitmap_bytesize (u32)
    //  172..175  checksum_offset (u32)
    //  176..183  elapsed_time (u64)
    //  184..187  ckpt_flags (u32)
    //  188..191  cp_pack_bitmap (u32)
    //  192..199  reserved [8]

    /// Read a little-endian u32 from `buf` at `off`.
    #[inline(always)]
    fn read_u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    // SECURITY [Fix 3 — OOB]: bound-check checksum_offset before any use.
    // The stored value is a byte offset; the 4-byte CRC must fit in the block.
    let checksum_offset = read_u32_le(block, 172) as usize;
    if checksum_offset
        .checked_add(4)
        .ok_or(Error::InvalidArgument)?
        > BLOCK_SIZE
    {
        // SECURITY: reject — checksum_offset points outside the block.
        return Err(Error::InvalidArgument);
    }

    // SECURITY [Fix 2 — CRC]: compute CRC32 over block[0..checksum_offset]
    // and compare to the stored 4-byte value at block[checksum_offset..+4].
    let computed_crc = crc32_zlib(&block[..checksum_offset]);
    let stored_crc = read_u32_le(block, checksum_offset);
    if computed_crc != stored_crc {
        // SECURITY: reject — checkpoint CRC mismatch; block is corrupt or forged.
        return Err(Error::InvalidArgument);
    }

    // SECURITY [Fix 4 — bitmap sizes]: validate sit/nat bitmap bytesizes.
    // Both values are attacker-controlled on-disk counts.  They must not
    // exceed the total bytes in the checkpoint pack.
    let cp_pack_total = read_u32_le(block, 144);
    // SECURITY: use checked_mul to guard against overflow on the total capacity.
    let max_bitmap_bytes = (cp_pack_total as usize)
        .checked_mul(BLOCK_SIZE)
        .ok_or(Error::InvalidArgument)?;

    let sit_bitmap_bytes = read_u32_le(block, 164) as usize;
    let nat_bitmap_bytes = read_u32_le(block, 168) as usize;

    if sit_bitmap_bytes > max_bitmap_bytes {
        // SECURITY: reject — sit_ver_bitmap_bytesize exceeds pack capacity.
        return Err(Error::InvalidArgument);
    }
    if nat_bitmap_bytes > max_bitmap_bytes {
        // SECURITY: reject — nat_ver_bitmap_bytesize exceeds pack capacity.
        return Err(Error::InvalidArgument);
    }

    Ok(())
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

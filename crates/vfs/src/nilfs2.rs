// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NILFS2 — log-structured filesystem with continuous snapshotting.
//!
//! NILFS2 (New Implementation of a Log-structured File System) writes all
//! data and metadata sequentially to the end of a log.  This provides:
//!
//! - **Continuous snapshotting**: every checkpoint is a consistent filesystem
//!   image that can be promoted to a snapshot.
//! - **Fast crash recovery**: the log head is always consistent; recovery
//!   simply replays the last partial segment.
//! - **Garbage collection**: a segment cleaner reclaims space from old
//!   segments whose live blocks have been rewritten elsewhere.
//!
//! # On-disk layout
//!
//! ```text
//! ┌──────────────┬──────────────┬──────────────┬─── ─ ─ ───┐
//! │  Superblock   │  Segment 0   │  Segment 1   │    ...     │
//! │  (1 block)    │  (N blocks)  │  (N blocks)  │            │
//! └──────────────┴──────────────┴──────────────┴─── ─ ─ ───┘
//! ```
//!
//! Each segment contains:
//! - Segment summary (block bitmap, finfo, binfo entries)
//! - Data blocks and B-tree node blocks
//! - A partial checkpoint at the tail of the writing segment
//!
//! # Key structures
//!
//! - [`Nilfs2Superblock`] — primary superblock at byte offset 1024
//! - [`SegmentUsage`] — per-segment liveness metadata
//! - [`BTreeNode`] — metadata B-tree node (4-level max)
//! - [`Checkpoint`] / [`Snapshot`] — filesystem state markers
//! - [`Nilfs2Inode`] — on-disk inode with inline/extent addressing
//! - [`Nilfs2Fs`] — mounted filesystem handle with segment cleaner

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// NILFS2 magic number (same as Linux: `0x3434`).
pub const NILFS2_MAGIC: u16 = 0x3434;

/// NILFS2 on-disk format version.
pub const NILFS2_VERSION: u32 = 2;

/// Default block size (4 KiB).
const BLOCK_SIZE: u32 = 4096;

/// Blocks per segment (default 2048 = 8 MiB segments at 4K blocks).
const BLOCKS_PER_SEGMENT: u32 = 2048;

/// Maximum number of segments tracked in the filesystem.
const MAX_SEGMENTS: usize = 256;

/// Maximum number of inodes.
const MAX_INODES: usize = 512;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file data size in bytes (limited for in-memory model).
const MAX_FILE_DATA: usize = 65536;

/// Maximum B-tree keys per node.
const MAX_BTREE_KEYS: usize = 64;

/// Maximum B-tree depth.
const MAX_BTREE_DEPTH: usize = 4;

/// Maximum checkpoints stored.
const MAX_CHECKPOINTS: usize = 128;

/// Maximum snapshots (promoted checkpoints).
const MAX_SNAPSHOTS: usize = 32;

/// Maximum filename length in a directory entry.
const MAX_NAME_LEN: usize = 255;

// ── Superblock ───────────────────────────────────────────────────────────────

/// NILFS2 on-disk superblock (resides at byte offset 1024).
///
/// Contains global filesystem parameters, the segment geometry, and
/// pointers to the latest checkpoint and the segment usage file.
#[derive(Debug, Clone, Copy)]
pub struct Nilfs2Superblock {
    /// Magic number ([`NILFS2_MAGIC`]).
    pub magic: u16,
    /// On-disk format version.
    pub version: u32,
    /// Block size in bytes (always a power of two, min 1024).
    pub block_size: u32,
    /// Total number of blocks on the device.
    pub total_blocks: u64,
    /// Number of segments.
    pub segment_count: u32,
    /// Blocks per segment.
    pub blocks_per_segment: u32,
    /// Inode of the checkpoint file (metadata).
    pub cpfile_ino: u64,
    /// Inode of the segment usage file (metadata).
    pub sufile_ino: u64,
    /// Inode of the DAT (disk address translation) file.
    pub dat_ino: u64,
    /// Sequence number of the latest checkpoint.
    pub last_cno: u64,
    /// Segment number currently being written.
    pub current_segment: u32,
    /// Block offset of the write frontier within current segment.
    pub write_pointer: u32,
    /// UUID (128 bits stored as two u64).
    pub uuid_hi: u64,
    /// UUID low 64 bits.
    pub uuid_lo: u64,
    /// Total free blocks across all segments.
    pub free_blocks: u64,
    /// Filesystem state flags.
    pub state: SuperblockState,
}

/// Superblock state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperblockState {
    /// Filesystem was cleanly unmounted.
    Clean,
    /// Filesystem is mounted or was not cleanly unmounted.
    Dirty,
    /// Filesystem has errors.
    HasErrors,
}

impl Nilfs2Superblock {
    /// Create a fresh superblock for a device of `total_blocks` blocks.
    pub fn new(total_blocks: u64) -> Self {
        let segment_count = (total_blocks / u64::from(BLOCKS_PER_SEGMENT)) as u32;
        Self {
            magic: NILFS2_MAGIC,
            version: NILFS2_VERSION,
            block_size: BLOCK_SIZE,
            total_blocks,
            segment_count,
            blocks_per_segment: BLOCKS_PER_SEGMENT,
            cpfile_ino: 2,
            sufile_ino: 3,
            dat_ino: 4,
            last_cno: 0,
            current_segment: 0,
            write_pointer: 0,
            uuid_hi: 0,
            uuid_lo: 0,
            free_blocks: total_blocks,
            state: SuperblockState::Clean,
        }
    }

    /// Validate superblock fields.
    pub fn validate(&self) -> Result<()> {
        if self.magic != NILFS2_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if !self.block_size.is_power_of_two() || self.block_size < 1024 {
            return Err(Error::InvalidArgument);
        }
        if self.segment_count == 0 || self.total_blocks == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── Segment usage ────────────────────────────────────────────────────────────

/// Per-segment liveness state tracked by the segment usage file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentState {
    /// Segment is free and available for writing.
    Free,
    /// Segment is currently being written (open segment).
    Active,
    /// Segment contains committed data — may have live or dead blocks.
    Full,
    /// Segment is marked dirty (needs GC consideration).
    Dirty,
}

/// Segment usage entry (one per segment).
#[derive(Debug, Clone, Copy)]
pub struct SegmentUsage {
    /// Segment number.
    pub segment_number: u32,
    /// Current state.
    pub state: SegmentState,
    /// Number of live (referenced) blocks in this segment.
    pub live_blocks: u32,
    /// Total blocks written to this segment.
    pub total_blocks: u32,
    /// Checkpoint number at which this segment was last modified.
    pub last_checkpoint: u64,
    /// Timestamp of last modification (seconds since epoch).
    pub modification_time: u64,
}

impl SegmentUsage {
    /// Create a new free segment entry.
    pub fn new(segment_number: u32) -> Self {
        Self {
            segment_number,
            state: SegmentState::Free,
            live_blocks: 0,
            total_blocks: 0,
            last_checkpoint: 0,
            modification_time: 0,
        }
    }

    /// Fraction of live blocks in [0, 100].
    pub fn liveness_percent(&self) -> u32 {
        if self.total_blocks == 0 {
            return 0;
        }
        (u64::from(self.live_blocks) * 100 / u64::from(self.total_blocks)) as u32
    }
}

// ── B-tree node ──────────────────────────────────────────────────────────────

/// Key type for B-tree lookups (virtual block number).
pub type BTreeKey = u64;

/// Value type (physical block number or child node block).
pub type BTreeValue = u64;

/// A single B-tree node used for metadata indexing (DAT, inode map, etc.).
///
/// NILFS2 uses copy-on-write B-trees: modified nodes are written to new
/// locations (the log head), keeping older versions intact for snapshots.
#[derive(Debug, Clone)]
pub struct BTreeNode {
    /// Node level (0 = leaf).
    pub level: u8,
    /// Number of valid keys.
    pub key_count: u16,
    /// Keys (sorted).
    pub keys: [BTreeKey; MAX_BTREE_KEYS],
    /// Values: for leaves these are block addresses; for internal nodes
    /// they are child node block numbers.
    pub values: [BTreeValue; MAX_BTREE_KEYS],
}

impl BTreeNode {
    /// Create an empty leaf node.
    pub fn new_leaf() -> Self {
        Self {
            level: 0,
            key_count: 0,
            keys: [0; MAX_BTREE_KEYS],
            values: [0; MAX_BTREE_KEYS],
        }
    }

    /// Create an empty internal node at the given level.
    pub fn new_internal(level: u8) -> Self {
        Self {
            level,
            key_count: 0,
            keys: [0; MAX_BTREE_KEYS],
            values: [0; MAX_BTREE_KEYS],
        }
    }

    /// Binary search for `key`; returns `Ok(index)` for exact match,
    /// `Err(index)` for the insertion point.
    pub fn search(&self, key: BTreeKey) -> core::result::Result<usize, usize> {
        let count = self.key_count as usize;
        self.keys[..count].binary_search(&key)
    }

    /// Insert a key-value pair (leaf only). Returns error if full.
    pub fn insert(&mut self, key: BTreeKey, value: BTreeValue) -> Result<()> {
        let count = self.key_count as usize;
        if count >= MAX_BTREE_KEYS {
            return Err(Error::OutOfMemory);
        }
        let pos = match self.search(key) {
            Ok(i) => {
                // Key exists — update value.
                self.values[i] = value;
                return Ok(());
            }
            Err(i) => i,
        };
        // Shift entries right.
        let mut i = count;
        while i > pos {
            self.keys[i] = self.keys[i - 1];
            self.values[i] = self.values[i - 1];
            i -= 1;
        }
        self.keys[pos] = key;
        self.values[pos] = value;
        self.key_count += 1;
        Ok(())
    }

    /// Remove the entry with the given key. Returns the removed value.
    pub fn remove(&mut self, key: BTreeKey) -> Result<BTreeValue> {
        let count = self.key_count as usize;
        let pos = self.search(key).map_err(|_| Error::NotFound)?;
        let val = self.values[pos];
        let mut i = pos;
        while i + 1 < count {
            self.keys[i] = self.keys[i + 1];
            self.values[i] = self.values[i + 1];
            i += 1;
        }
        self.key_count -= 1;
        Ok(val)
    }
}

// ── Checkpoint / Snapshot ────────────────────────────────────────────────────

/// Checkpoint flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointFlags {
    /// Ordinary checkpoint (can be garbage-collected).
    Checkpoint,
    /// Promoted to snapshot (will not be garbage-collected).
    Snapshot,
}

/// A checkpoint records a consistent filesystem state.
///
/// Checkpoints are created automatically at each segment boundary.  A
/// checkpoint can be promoted to a [`Snapshot`] to prevent its data
/// from being garbage-collected.
#[derive(Debug, Clone, Copy)]
pub struct Checkpoint {
    /// Checkpoint number (monotonically increasing).
    pub cno: u64,
    /// Creation timestamp (seconds since epoch).
    pub create_time: u64,
    /// Number of blocks used at this checkpoint.
    pub blocks_used: u64,
    /// Inode count at this checkpoint.
    pub inode_count: u32,
    /// Flags (checkpoint or snapshot).
    pub flags: CheckpointFlags,
    /// Root inode number for this checkpoint's directory tree.
    pub root_ino: u64,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(cno: u64, root_ino: u64) -> Self {
        Self {
            cno,
            create_time: 0,
            blocks_used: 0,
            inode_count: 0,
            flags: CheckpointFlags::Checkpoint,
            root_ino,
        }
    }

    /// Return `true` if this checkpoint has been promoted to a snapshot.
    pub fn is_snapshot(&self) -> bool {
        self.flags == CheckpointFlags::Snapshot
    }
}

/// A snapshot is a checkpoint that is preserved from GC.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    /// The underlying checkpoint.
    pub checkpoint: Checkpoint,
    /// User-supplied description (first 64 bytes used).
    pub description: [u8; 64],
}

impl Snapshot {
    /// Create a snapshot from a checkpoint.
    pub fn from_checkpoint(cp: Checkpoint) -> Self {
        Self {
            checkpoint: Checkpoint {
                flags: CheckpointFlags::Snapshot,
                ..cp
            },
            description: [0u8; 64],
        }
    }
}

// ── On-disk inode ────────────────────────────────────────────────────────────

/// NILFS2 on-disk inode.
///
/// Small files may store data inline; larger files use B-tree extent
/// addressing through the DAT.
#[derive(Debug, Clone, Copy)]
pub struct Nilfs2Inode {
    /// Inode number.
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Access time (seconds since epoch).
    pub atime: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Change time (seconds since epoch).
    pub ctime: u64,
    /// Generation number for NFS export.
    pub generation: u32,
    /// Block count (512-byte units as POSIX).
    pub blocks: u64,
    /// Flags (immutable, append, etc.).
    pub flags: u32,
}

impl Nilfs2Inode {
    /// Create a new inode.
    pub fn new(ino: u64, file_type: FileType, mode: u16) -> Self {
        Self {
            ino,
            file_type,
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 1,
            atime: 0,
            mtime: 0,
            ctime: 0,
            generation: 0,
            blocks: 0,
            flags: 0,
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = self.size;
        vfs.nlink = self.nlink;
        vfs.uid = self.uid;
        vfs.gid = self.gid;
        vfs
    }
}

// ── Directory entry ──────────────────────────────────────────────────────────

/// A directory entry mapping a name to an inode number.
#[derive(Debug, Clone)]
pub struct Nilfs2DirEntry {
    /// Inode number this entry points to.
    pub ino: u64,
    /// File type (cached for readdir performance).
    pub file_type: FileType,
    /// Entry name.
    pub name: String,
}

// ── File data storage ────────────────────────────────────────────────────────

/// In-memory file data for the NILFS2 simulation.
struct FileData {
    /// Owning inode number.
    ino: u64,
    /// Raw byte content.
    data: Vec<u8>,
}

// ── Segment cleaner ──────────────────────────────────────────────────────────

/// GC cost estimation for a segment.
#[derive(Debug, Clone, Copy)]
pub struct GcCost {
    /// Segment number.
    pub segment: u32,
    /// Estimated cost = age * (1 - utilisation).
    pub cost: u64,
}

/// Segment cleaner (garbage collector) configuration.
#[derive(Debug, Clone, Copy)]
pub struct SegmentCleanerConfig {
    /// Minimum number of free segments before GC triggers.
    pub min_free_segments: u32,
    /// Minimum segment age (in checkpoints) before eligible for GC.
    pub min_age: u64,
    /// Maximum liveness percent threshold for GC candidate selection.
    pub gc_threshold_percent: u32,
    /// Number of segments to clean per GC pass.
    pub segments_per_pass: u32,
}

impl Default for SegmentCleanerConfig {
    fn default() -> Self {
        Self {
            min_free_segments: 4,
            min_age: 10,
            gc_threshold_percent: 50,
            segments_per_pass: 4,
        }
    }
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted NILFS2 filesystem handle.
///
/// Provides full VFS operations as well as NILFS2-specific functionality
/// such as checkpoint management, snapshot creation, and segment cleaning.
pub struct Nilfs2Fs {
    /// Superblock.
    sb: Nilfs2Superblock,
    /// Segment usage table.
    segments: Vec<SegmentUsage>,
    /// Inode table.
    inodes: Vec<Nilfs2Inode>,
    /// Directory entries (flat list; parent ino identifies the directory).
    dir_entries: Vec<(u64, Nilfs2DirEntry)>,
    /// File data blobs.
    file_data: Vec<FileData>,
    /// Checkpoint list.
    checkpoints: Vec<Checkpoint>,
    /// Snapshot list (subset of checkpoints).
    snapshots: Vec<Snapshot>,
    /// Next inode number to allocate.
    next_ino: u64,
    /// Segment cleaner configuration.
    gc_config: SegmentCleanerConfig,
}

impl Nilfs2Fs {
    /// Create and mount a new NILFS2 filesystem on a device of `total_blocks`.
    pub fn new(total_blocks: u64) -> Result<Self> {
        let sb = Nilfs2Superblock::new(total_blocks);
        sb.validate()?;

        let seg_count = sb.segment_count.min(MAX_SEGMENTS as u32) as usize;
        let mut segments = Vec::with_capacity(seg_count);
        for i in 0..seg_count {
            segments.push(SegmentUsage::new(i as u32));
        }

        // Create root inode (ino 1, directory).
        let root = Nilfs2Inode::new(1, FileType::Directory, 0o755);

        let mut fs = Self {
            sb,
            segments,
            inodes: Vec::new(),
            dir_entries: Vec::new(),
            file_data: Vec::new(),
            checkpoints: Vec::new(),
            snapshots: Vec::new(),
            next_ino: 2,
            gc_config: SegmentCleanerConfig::default(),
        };
        fs.inodes.push(root);

        // Create initial checkpoint for the fresh filesystem.
        let cp = Checkpoint::new(1, 1);
        fs.checkpoints.push(cp);
        fs.sb.last_cno = 1;

        Ok(fs)
    }

    /// Return a reference to the superblock.
    pub fn superblock(&self) -> &Nilfs2Superblock {
        &self.sb
    }

    /// Return the GC configuration.
    pub fn gc_config(&self) -> &SegmentCleanerConfig {
        &self.gc_config
    }

    /// Set the GC configuration.
    pub fn set_gc_config(&mut self, config: SegmentCleanerConfig) {
        self.gc_config = config;
    }

    // ── Inode helpers ────────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&Nilfs2Inode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Find a mutable inode by number.
    fn find_inode_mut(&mut self, ino: u64) -> Result<&mut Nilfs2Inode> {
        self.inodes
            .iter_mut()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Allocate a new inode number.
    fn alloc_ino(&mut self) -> Result<u64> {
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        Ok(ino)
    }

    // ── Directory helpers ────────────────────────────────────────────

    /// Look up a directory entry by parent inode and name.
    fn find_dir_entry(&self, parent_ino: u64, name: &str) -> Result<&Nilfs2DirEntry> {
        self.dir_entries
            .iter()
            .find(|(p, e)| *p == parent_ino && e.name == name)
            .map(|(_, e)| e)
            .ok_or(Error::NotFound)
    }

    /// Count entries in a directory.
    fn dir_entry_count(&self, parent_ino: u64) -> usize {
        self.dir_entries
            .iter()
            .filter(|(p, _)| *p == parent_ino)
            .count()
    }

    // ── File data helpers ────────────────────────────────────────────

    /// Get file data for an inode.
    fn get_file_data(&self, ino: u64) -> Option<&FileData> {
        self.file_data.iter().find(|f| f.ino == ino)
    }

    /// Get or create mutable file data for an inode.
    fn get_or_create_file_data(&mut self, ino: u64) -> &mut FileData {
        if !self.file_data.iter().any(|f| f.ino == ino) {
            self.file_data.push(FileData {
                ino,
                data: Vec::new(),
            });
        }
        self.file_data.iter_mut().find(|f| f.ino == ino).unwrap()
    }

    // ── Segment operations ───────────────────────────────────────────

    /// Advance the write pointer by `blocks` within the current segment.
    /// Opens a new segment when the current one is exhausted.
    pub fn advance_log(&mut self, blocks: u32) -> Result<()> {
        let seg_idx = self.sb.current_segment as usize;
        if seg_idx >= self.segments.len() {
            return Err(Error::OutOfMemory);
        }
        self.segments[seg_idx].state = SegmentState::Active;
        self.segments[seg_idx].total_blocks += blocks;
        self.segments[seg_idx].live_blocks += blocks;
        self.sb.write_pointer += blocks;

        if self.sb.write_pointer >= self.sb.blocks_per_segment {
            // Seal the current segment and open the next.
            self.segments[seg_idx].state = SegmentState::Full;
            let next = self.sb.current_segment + 1;
            if next as usize >= self.segments.len() {
                return Err(Error::OutOfMemory);
            }
            self.sb.current_segment = next;
            self.sb.write_pointer = 0;
        }
        if self.sb.free_blocks >= u64::from(blocks) {
            self.sb.free_blocks -= u64::from(blocks);
        }
        Ok(())
    }

    // ── Checkpoint / snapshot management ─────────────────────────────

    /// Create a new checkpoint capturing the current filesystem state.
    pub fn create_checkpoint(&mut self) -> Result<u64> {
        if self.checkpoints.len() >= MAX_CHECKPOINTS {
            return Err(Error::OutOfMemory);
        }
        let cno = self.sb.last_cno + 1;
        let cp = Checkpoint {
            cno,
            create_time: 0,
            blocks_used: self.sb.total_blocks - self.sb.free_blocks,
            inode_count: self.inodes.len() as u32,
            flags: CheckpointFlags::Checkpoint,
            root_ino: 1,
        };
        self.checkpoints.push(cp);
        self.sb.last_cno = cno;
        Ok(cno)
    }

    /// Promote checkpoint `cno` to a snapshot.
    pub fn create_snapshot(&mut self, cno: u64) -> Result<&Snapshot> {
        if self.snapshots.len() >= MAX_SNAPSHOTS {
            return Err(Error::OutOfMemory);
        }
        let cp_idx = self
            .checkpoints
            .iter()
            .position(|c| c.cno == cno)
            .ok_or(Error::NotFound)?;
        self.checkpoints[cp_idx].flags = CheckpointFlags::Snapshot;
        let snap = Snapshot::from_checkpoint(self.checkpoints[cp_idx]);
        self.snapshots.push(snap);
        let idx = self.snapshots.len() - 1;
        Ok(&self.snapshots[idx])
    }

    /// Delete a snapshot, allowing its blocks to be garbage-collected.
    pub fn delete_snapshot(&mut self, cno: u64) -> Result<()> {
        let snap_idx = self
            .snapshots
            .iter()
            .position(|s| s.checkpoint.cno == cno)
            .ok_or(Error::NotFound)?;
        self.snapshots.remove(snap_idx);
        // Revert the checkpoint flag if it still exists.
        if let Some(cp) = self.checkpoints.iter_mut().find(|c| c.cno == cno) {
            cp.flags = CheckpointFlags::Checkpoint;
        }
        Ok(())
    }

    /// List all checkpoints.
    pub fn list_checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// List all snapshots.
    pub fn list_snapshots(&self) -> &[Snapshot] {
        &self.snapshots
    }

    // ── Segment cleaner (GC) ─────────────────────────────────────────

    /// Estimate GC cost for a segment (cost-benefit policy).
    ///
    /// Lower cost = better candidate for cleaning.
    fn gc_cost(&self, seg: &SegmentUsage) -> u64 {
        let utilisation = seg.liveness_percent() as u64;
        let age = self.sb.last_cno.saturating_sub(seg.last_checkpoint);
        // Cost-benefit: age * (1 - u) / (1 + u)
        if utilisation >= 100 {
            return u64::MAX;
        }
        let benefit = age * (100 - utilisation);
        let cost = 1 + utilisation;
        benefit / cost
    }

    /// Identify candidate segments for garbage collection.
    pub fn gc_candidates(&self) -> Vec<GcCost> {
        let mut candidates: Vec<GcCost> = self
            .segments
            .iter()
            .filter(|s| {
                s.state == SegmentState::Full
                    && s.liveness_percent() <= self.gc_config.gc_threshold_percent
                    && self.sb.last_cno.saturating_sub(s.last_checkpoint) >= self.gc_config.min_age
            })
            .map(|s| GcCost {
                segment: s.segment_number,
                cost: self.gc_cost(s),
            })
            .collect();
        // Sort descending by cost (highest benefit first).
        candidates.sort_by(|a, b| b.cost.cmp(&a.cost));
        candidates
            .into_iter()
            .take(self.gc_config.segments_per_pass as usize)
            .collect()
    }

    /// Run a GC pass: clean candidate segments by marking dead blocks free.
    ///
    /// In a real implementation this would relocate live blocks to the log
    /// head.  Here we simulate by zeroing the live/total counts and marking
    /// the segment free.
    pub fn run_gc(&mut self) -> Result<u32> {
        let candidates = self.gc_candidates();
        let mut freed = 0u32;
        let seg_numbers: Vec<u32> = candidates.iter().map(|c| c.segment).collect();
        for seg_num in seg_numbers {
            if let Some(seg) = self
                .segments
                .iter_mut()
                .find(|s| s.segment_number == seg_num)
            {
                let dead = seg.total_blocks - seg.live_blocks;
                self.sb.free_blocks += u64::from(dead);
                freed += dead;
                seg.live_blocks = 0;
                seg.total_blocks = 0;
                seg.state = SegmentState::Free;
            }
        }
        Ok(freed)
    }

    /// Count free segments.
    pub fn free_segment_count(&self) -> u32 {
        self.segments
            .iter()
            .filter(|s| s.state == SegmentState::Free)
            .count() as u32
    }

    /// Return `true` if GC should be triggered based on free segment count.
    pub fn needs_gc(&self) -> bool {
        self.free_segment_count() < self.gc_config.min_free_segments
    }
}

// ── InodeOps implementation ──────────────────────────────────────────────────

impl InodeOps for Nilfs2Fs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let entry = self.find_dir_entry(parent.ino.0, name)?;
        let inode = self.find_inode(entry.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.alloc_ino()?;
        let disk_inode = Nilfs2Inode::new(ino, FileType::Regular, mode.0);
        self.inodes.push(disk_inode);

        self.dir_entries.push((
            parent.ino.0,
            Nilfs2DirEntry {
                ino,
                file_type: FileType::Regular,
                name: String::from(name),
            },
        ));

        // Log the write.
        let _ = self.advance_log(1);

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.alloc_ino()?;
        let disk_inode = Nilfs2Inode::new(ino, FileType::Directory, mode.0);
        self.inodes.push(disk_inode);

        self.dir_entries.push((
            parent.ino.0,
            Nilfs2DirEntry {
                ino,
                file_type: FileType::Directory,
                name: String::from(name),
            },
        ));

        let _ = self.advance_log(1);

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type == FileType::Directory {
            return Err(Error::InvalidArgument);
        }

        // Remove directory entry.
        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);

        // Decrement nlink; remove inode and data if zero.
        let inode_mut = self.find_inode_mut(entry_ino)?;
        inode_mut.nlink = inode_mut.nlink.saturating_sub(1);
        if inode_mut.nlink == 0 {
            self.inodes.retain(|i| i.ino != entry_ino);
            self.file_data.retain(|f| f.ino != entry_ino);
        }

        let _ = self.advance_log(1);
        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type != FileType::Directory {
            return Err(Error::InvalidArgument);
        }
        // Must be empty.
        if self.dir_entry_count(entry_ino) > 0 {
            return Err(Error::Busy);
        }

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);
        self.inodes.retain(|i| i.ino != entry_ino);

        let _ = self.advance_log(1);
        Ok(())
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let fd = match self.get_file_data(inode.ino.0) {
            Some(fd) => fd,
            None => return Ok(0),
        };
        let start = offset as usize;
        if start >= fd.data.len() {
            return Ok(0);
        }
        let available = fd.data.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&fd.data[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let end = offset as usize + data.len();
        if end > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let fd = self.get_or_create_file_data(inode.ino.0);
        if fd.data.len() < end {
            fd.data.resize(end, 0);
        }
        fd.data[offset as usize..end].copy_from_slice(data);

        let new_size = fd.data.len() as u64;
        let inode_mut = self.find_inode_mut(inode.ino.0)?;
        inode_mut.size = new_size;
        inode_mut.blocks = (new_size + 511) / 512;

        // Log the write.
        let blocks = ((data.len() + BLOCK_SIZE as usize - 1) / BLOCK_SIZE as usize) as u32;
        let _ = self.advance_log(blocks.max(1));

        Ok(data.len())
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let disk_inode = self.find_inode(inode.ino.0)?;
        if disk_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        if size as usize > MAX_FILE_DATA {
            return Err(Error::OutOfMemory);
        }

        let fd = self.get_or_create_file_data(inode.ino.0);
        fd.data.resize(size as usize, 0);

        let inode_mut = self.find_inode_mut(inode.ino.0)?;
        inode_mut.size = size;
        inode_mut.blocks = (size + 511) / 512;

        let _ = self.advance_log(1);
        Ok(())
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS — Flash-Friendly File System.
//!
//! Implements the core on-disk structures and operations for F2FS, a
//! log-structured filesystem designed for flash-based storage (eMMC,
//! SSD, SD cards). F2FS uses multi-head logging with hot/warm/cold
//! data separation to reduce write amplification and improve flash
//! lifetime.
//!
//! # Design
//!
//! - [`F2fsSuperblock`] — repr(C) superblock with filesystem geometry
//! - [`F2fsSegmentType`] — 6-type hot/warm/cold classification for
//!   data and node blocks
//! - [`F2fsSegment`] — segment metadata (512 blocks per segment)
//! - [`F2fsNode`] — on-disk inode with direct block addresses
//! - [`F2fsCheckpoint`] — checkpoint for crash recovery
//! - [`F2fsGc`] — greedy garbage collector (victim = least valid blocks)
//! - [`F2fsFs`] — filesystem instance (64 segments, 256 nodes)
//! - [`F2fsRegistry`] — global registry (4 mount slots)
//!
//! # On-disk Layout
//!
//! ```text
//! [Superblock | Checkpoint | Segment Info Table | Node Area | Data Area]
//! ```
//!
//! Reference: Linux `fs/f2fs/`, `Documentation/filesystems/f2fs.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// F2FS superblock magic number.
const F2FS_MAGIC: u32 = 0xF2F5_2010;

/// Block size in bytes (4 KiB).
const BLOCK_SIZE: usize = 4096;

/// Blocks per segment.
const BLOCKS_PER_SEGMENT: usize = 512;

/// Maximum number of segments.
const MAX_SEGMENTS: usize = 64;

/// Maximum number of nodes (inodes).
const MAX_NODES: usize = 256;

/// Maximum direct block addresses per node.
const MAX_DIRECT_ADDRS: usize = 32;

/// Segment summary entries per segment.
const SEGMENT_SUMMARY_SIZE: usize = 16;

/// Maximum directory entries per directory node.
const MAX_DIR_ENTRIES: usize = 32;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of mounted F2FS instances.
const MAX_F2FS_INSTANCES: usize = 4;

/// Invalid block address (not allocated).
const NULL_ADDR: u64 = 0;

// ── F2fsSuperblock ──────────────────────────────────────────────

/// F2FS superblock containing filesystem geometry.
///
/// Stored at the beginning of the device and replicated at an
/// alternate location for crash recovery.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct F2fsSuperblock {
    /// Magic number (must be [`F2FS_MAGIC`]).
    pub magic: u32,
    /// Block size in bytes (always 4096).
    pub block_size: u32,
    /// Total number of segments.
    pub segment_count: u32,
    /// Number of sections (groups of segments).
    pub section_count: u32,
    /// Segments per section.
    pub segments_per_section: u32,
    /// Blocks per segment (always 512).
    pub blocks_per_segment: u32,
    /// Root directory inode number.
    pub root_ino: u64,
    /// Total allocated node count.
    pub node_count: u32,
    /// Total blocks in the filesystem.
    pub total_blocks: u64,
}

impl Default for F2fsSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl F2fsSuperblock {
    /// Create a new F2FS superblock with default geometry.
    pub const fn new() -> Self {
        Self {
            magic: F2FS_MAGIC,
            block_size: BLOCK_SIZE as u32,
            segment_count: MAX_SEGMENTS as u32,
            section_count: 8,
            segments_per_section: MAX_SEGMENTS as u32 / 8,
            blocks_per_segment: BLOCKS_PER_SEGMENT as u32,
            root_ino: 1,
            node_count: 0,
            total_blocks: (MAX_SEGMENTS * BLOCKS_PER_SEGMENT) as u64,
        }
    }

    /// Validate the superblock magic number.
    pub fn validate(&self) -> Result<()> {
        if self.magic != F2FS_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.block_size != BLOCK_SIZE as u32 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── F2fsSegmentType ─────────────────────────────────────────────

/// Segment type classification for multi-head logging.
///
/// F2FS separates data into hot/warm/cold categories for both
/// data blocks and node blocks, reducing GC overhead by grouping
/// blocks with similar lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum F2fsSegmentType {
    /// Hot data — frequently updated small files.
    HotData = 0,
    /// Warm data — general file data.
    WarmData = 1,
    /// Cold data — rarely modified (multimedia, archives).
    ColdData = 2,
    /// Hot node — directory inodes and inline data.
    HotNode = 3,
    /// Warm node — regular file inodes.
    WarmNode = 4,
    /// Cold node — indirect block nodes.
    ColdNode = 5,
}

// ── F2fsSegment ─────────────────────────────────────────────────

/// A single segment in the F2FS log area.
///
/// Each segment contains [`BLOCKS_PER_SEGMENT`] blocks and tracks
/// the number of valid (live) blocks for garbage collection.
#[derive(Debug, Clone, Copy)]
pub struct F2fsSegment {
    /// Segment type (hot/warm/cold data or node).
    pub seg_type: F2fsSegmentType,
    /// Number of valid (live) blocks in this segment.
    pub valid_blocks: u32,
    /// Starting block address of this segment.
    pub blkaddr: u64,
    /// Summary table: maps block offsets to owning inode numbers.
    pub summary: [u64; SEGMENT_SUMMARY_SIZE],
}

impl F2fsSegment {
    /// Create a new empty segment.
    const fn new(seg_type: F2fsSegmentType, blkaddr: u64) -> Self {
        Self {
            seg_type,
            valid_blocks: 0,
            blkaddr,
            summary: [0; SEGMENT_SUMMARY_SIZE],
        }
    }

    /// Check whether this segment is completely empty (no valid blocks).
    pub fn is_empty(&self) -> bool {
        self.valid_blocks == 0
    }

    /// Check whether this segment is full.
    pub fn is_full(&self) -> bool {
        self.valid_blocks >= BLOCKS_PER_SEGMENT as u32
    }
}

// ── F2fsNode ────────────────────────────────────────────────────

/// F2FS on-disk node (inode) structure.
///
/// Contains file metadata and up to [`MAX_DIRECT_ADDRS`] direct
/// block addresses. Files larger than 32 blocks (128 KiB) are not
/// supported in this implementation.
#[derive(Debug, Clone, Copy)]
pub struct F2fsNode {
    /// Inode number.
    pub ino: u64,
    /// File mode (permission bits + type encoding).
    pub mode: u16,
    /// File size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Access time (seconds since epoch).
    pub atime: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Direct block addresses.
    pub addrs: [u64; MAX_DIRECT_ADDRS],
    /// Whether this node slot is allocated.
    pub allocated: bool,
    /// Whether this node is a directory.
    pub is_dir: bool,
}

impl F2fsNode {
    /// Create a new empty node.
    const fn empty() -> Self {
        Self {
            ino: 0,
            mode: 0,
            size: 0,
            nlink: 0,
            atime: 0,
            mtime: 0,
            addrs: [NULL_ADDR; MAX_DIRECT_ADDRS],
            allocated: false,
            is_dir: false,
        }
    }
}

// ── F2fsDirEntry ────────────────────────────────────────────────

/// A directory entry within an F2FS directory.
#[derive(Debug, Clone)]
struct F2fsDirEntry {
    /// Entry name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: u8,
    /// Child inode number.
    ino: u64,
}

impl F2fsDirEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            ino: 0,
        }
    }
}

/// Per-directory entry storage.
#[derive(Debug, Clone)]
struct F2fsDirData {
    /// Directory entries.
    entries: [Option<F2fsDirEntry>; MAX_DIR_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl F2fsDirData {
    const fn new() -> Self {
        const NONE: Option<F2fsDirEntry> = None;
        Self {
            entries: [NONE; MAX_DIR_ENTRIES],
            count: 0,
        }
    }
}

// ── F2fsCheckpoint ──────────────────────────────────────────────

/// Checkpoint pack for crash recovery.
///
/// Contains a snapshot of the filesystem state at a consistent
/// point. On mount, the most recent valid checkpoint is loaded
/// to recover from unclean shutdowns.
#[derive(Debug, Clone, Copy)]
pub struct F2fsCheckpoint {
    /// Checkpoint version (monotonically increasing).
    pub checkpoint_ver: u64,
    /// Number of valid data blocks across all segments.
    pub valid_block_count: u64,
    /// Number of free (completely empty) segments.
    pub free_segment_count: u32,
}

impl F2fsCheckpoint {
    /// Create an initial checkpoint.
    const fn new() -> Self {
        Self {
            checkpoint_ver: 1,
            valid_block_count: 0,
            free_segment_count: MAX_SEGMENTS as u32,
        }
    }
}

// ── F2fsGc ──────────────────────────────────────────────────────

/// Garbage collector for F2FS.
///
/// Uses a greedy policy: the segment with the fewest valid blocks
/// is chosen as the victim, minimizing the number of blocks that
/// must be migrated.
#[derive(Debug)]
pub struct F2fsGc {
    /// Number of GC cycles performed.
    pub gc_count: u64,
    /// Total blocks migrated across all GC runs.
    pub blocks_migrated: u64,
}

impl F2fsGc {
    /// Create a new GC instance.
    const fn new() -> Self {
        Self {
            gc_count: 0,
            blocks_migrated: 0,
        }
    }

    /// Select a victim segment using the greedy policy.
    ///
    /// Returns the index of the segment with the fewest valid blocks
    /// that is not empty (has at least one valid block to migrate).
    /// Returns `None` if no suitable victim exists.
    fn select_victim(segments: &[F2fsSegment; MAX_SEGMENTS]) -> Option<usize> {
        let mut best: Option<(usize, u32)> = None;
        for (idx, seg) in segments.iter().enumerate() {
            if seg.valid_blocks == 0 {
                continue;
            }
            match best {
                None => best = Some((idx, seg.valid_blocks)),
                Some((_, best_valid)) if seg.valid_blocks < best_valid => {
                    best = Some((idx, seg.valid_blocks));
                }
                _ => {}
            }
        }
        best.map(|(idx, _)| idx)
    }

    /// Run one GC cycle: pick victim, migrate valid blocks, free segment.
    ///
    /// Returns the number of blocks migrated, or `Ok(0)` if no victim
    /// was found.
    fn run_gc(&mut self, segments: &mut [F2fsSegment; MAX_SEGMENTS]) -> Result<u32> {
        let victim_idx = match Self::select_victim(segments) {
            Some(idx) => idx,
            None => return Ok(0),
        };

        let migrated = segments[victim_idx].valid_blocks;

        // In a real implementation, valid blocks would be copied to a
        // clean segment. Here we simulate by zeroing the victim.
        segments[victim_idx].valid_blocks = 0;
        segments[victim_idx].summary = [0; SEGMENT_SUMMARY_SIZE];

        self.gc_count += 1;
        self.blocks_migrated += migrated as u64;

        Ok(migrated)
    }
}

// ── F2fsFs ──────────────────────────────────────────────────────

/// F2FS filesystem instance.
///
/// Manages segments, nodes, and provides mount/read/write/gc/sync
/// operations. Each instance supports up to [`MAX_SEGMENTS`]
/// segments and [`MAX_NODES`] inodes.
pub struct F2fsFs {
    /// On-disk superblock.
    superblock: F2fsSuperblock,
    /// Segment table.
    segments: [F2fsSegment; MAX_SEGMENTS],
    /// Node (inode) table.
    nodes: [F2fsNode; MAX_NODES],
    /// Per-directory data (parallel to nodes array).
    dir_data: [Option<F2fsDirData>; MAX_NODES],
    /// File data blocks (simplified: one block per node address).
    file_blocks: [[u8; BLOCK_SIZE]; MAX_DIRECT_ADDRS],
    /// Checkpoint state.
    checkpoint: F2fsCheckpoint,
    /// Garbage collector.
    gc: F2fsGc,
    /// Whether the filesystem is mounted.
    mounted: bool,
    /// Next inode number to allocate.
    next_ino: u64,
    /// Current write segment index.
    cur_segment: usize,
    /// Current block offset within the current segment.
    cur_block_off: u32,
}

impl F2fsFs {
    /// Create a new F2FS filesystem instance.
    pub fn new() -> Self {
        const EMPTY_NODE: F2fsNode = F2fsNode::empty();
        const NONE_DIR: Option<F2fsDirData> = None;

        let mut segments = [F2fsSegment::new(F2fsSegmentType::WarmData, 0); MAX_SEGMENTS];
        // Assign segment types in round-robin across the 6 types.
        let types = [
            F2fsSegmentType::HotData,
            F2fsSegmentType::WarmData,
            F2fsSegmentType::ColdData,
            F2fsSegmentType::HotNode,
            F2fsSegmentType::WarmNode,
            F2fsSegmentType::ColdNode,
        ];
        for (idx, seg) in segments.iter_mut().enumerate() {
            seg.seg_type = types[idx % types.len()];
            seg.blkaddr = (idx * BLOCKS_PER_SEGMENT) as u64;
        }

        Self {
            superblock: F2fsSuperblock::new(),
            segments,
            nodes: [EMPTY_NODE; MAX_NODES],
            dir_data: [NONE_DIR; MAX_NODES],
            file_blocks: [[0u8; BLOCK_SIZE]; MAX_DIRECT_ADDRS],
            checkpoint: F2fsCheckpoint::new(),
            gc: F2fsGc::new(),
            mounted: false,
            next_ino: 2,
            cur_segment: 0,
            cur_block_off: 0,
        }
    }

    /// Mount the filesystem, creating a root directory if needed.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        self.superblock.validate()?;

        // Create root directory node if not present.
        if !self.nodes[0].allocated {
            self.nodes[0] = F2fsNode {
                ino: 1,
                mode: 0o755,
                size: 0,
                nlink: 2,
                atime: 0,
                mtime: 0,
                addrs: [NULL_ADDR; MAX_DIRECT_ADDRS],
                allocated: true,
                is_dir: true,
            };
            self.dir_data[0] = Some(F2fsDirData::new());
            self.superblock.node_count = 1;
        }

        self.mounted = true;
        Ok(())
    }

    /// Unmount the filesystem.
    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.sync()?;
        self.mounted = false;
        Ok(())
    }

    /// Find the node table index for a given inode number.
    fn node_slot(&self, ino: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.allocated && n.ino == ino)
    }

    /// Allocate a new node (inode).
    fn alloc_node(&mut self, is_dir: bool, mode: u16) -> Result<(usize, u64)> {
        let ino = self.next_ino;
        self.next_ino += 1;

        for (idx, node) in self.nodes.iter_mut().enumerate() {
            if !node.allocated {
                *node = F2fsNode {
                    ino,
                    mode,
                    size: 0,
                    nlink: 1,
                    atime: 0,
                    mtime: 0,
                    addrs: [NULL_ADDR; MAX_DIRECT_ADDRS],
                    allocated: true,
                    is_dir,
                };
                self.superblock.node_count += 1;
                return Ok((idx, ino));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a node by slot index.
    fn free_node(&mut self, slot: usize) {
        if slot < MAX_NODES && self.nodes[slot].allocated {
            self.nodes[slot].allocated = false;
            self.dir_data[slot] = None;
            self.superblock.node_count = self.superblock.node_count.saturating_sub(1);
        }
    }

    /// Look up a child entry in a directory.
    fn dir_lookup(&self, parent_slot: usize, name: &str) -> Result<u64> {
        let dir = self.dir_data[parent_slot]
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        let name_bytes = name.as_bytes();
        for entry in dir.entries.iter().flatten() {
            if entry.name_len as usize == name_bytes.len()
                && &entry.name[..entry.name_len as usize] == name_bytes
            {
                return Ok(entry.ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Add a directory entry to a parent directory.
    fn dir_add(&mut self, parent_slot: usize, name: &str, child_ino: u64) -> Result<()> {
        let dir = self.dir_data[parent_slot]
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        if dir.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.len() > MAX_NAME_LEN || name_bytes.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicates.
        for entry in dir.entries.iter().flatten() {
            if entry.name_len as usize == name_bytes.len()
                && &entry.name[..entry.name_len as usize] == name_bytes
            {
                return Err(Error::AlreadyExists);
            }
        }

        let mut entry = F2fsDirEntry::empty();
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        entry.name_len = name_bytes.len() as u8;
        entry.ino = child_ino;

        for slot in dir.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                dir.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a directory entry by name, returning the child inode number.
    fn dir_remove(&mut self, parent_slot: usize, name: &str) -> Result<u64> {
        let dir = self.dir_data[parent_slot]
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        let name_bytes = name.as_bytes();
        for slot in dir.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.name_len as usize == name_bytes.len()
                    && &entry.name[..entry.name_len as usize] == name_bytes
                {
                    let ino = entry.ino;
                    *slot = None;
                    dir.count -= 1;
                    return Ok(ino);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Create a file or directory under a parent.
    pub fn create_entry(
        &mut self,
        parent_ino: u64,
        name: &str,
        is_dir: bool,
        mode: u16,
    ) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let parent_slot = self.node_slot(parent_ino).ok_or(Error::NotFound)?;
        if !self.nodes[parent_slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        let (child_slot, child_ino) = self.alloc_node(is_dir, mode)?;
        if is_dir {
            self.dir_data[child_slot] = Some(F2fsDirData::new());
        }

        if let Err(e) = self.dir_add(parent_slot, name, child_ino) {
            self.free_node(child_slot);
            return Err(e);
        }

        Ok(child_ino)
    }

    /// Read data from a file.
    pub fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let slot = self.node_slot(ino).ok_or(Error::NotFound)?;
        let node = &self.nodes[slot];
        if node.is_dir {
            return Err(Error::InvalidArgument);
        }

        let off = offset as usize;
        let file_len = node.size as usize;
        if off >= file_len {
            return Ok(0);
        }

        let available = file_len - off;
        let to_read = buf.len().min(available);

        let mut bytes_read = 0;
        let mut file_pos = off;

        while bytes_read < to_read {
            let block_idx = file_pos / BLOCK_SIZE;
            let block_off = file_pos % BLOCK_SIZE;
            let chunk = (BLOCK_SIZE - block_off).min(to_read - bytes_read);

            if block_idx < MAX_DIRECT_ADDRS && node.addrs[block_idx] != NULL_ADDR {
                let blk_slot = node.addrs[block_idx] as usize;
                if blk_slot < MAX_DIRECT_ADDRS {
                    buf[bytes_read..bytes_read + chunk]
                        .copy_from_slice(&self.file_blocks[blk_slot][block_off..block_off + chunk]);
                } else {
                    buf[bytes_read..bytes_read + chunk].fill(0);
                }
            } else {
                buf[bytes_read..bytes_read + chunk].fill(0);
            }

            bytes_read += chunk;
            file_pos += chunk;
        }

        Ok(bytes_read)
    }

    /// Write data to a file.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let slot = self.node_slot(ino).ok_or(Error::NotFound)?;
        if self.nodes[slot].is_dir {
            return Err(Error::InvalidArgument);
        }

        let off = offset as usize;
        let end = off + data.len();
        let max_size = MAX_DIRECT_ADDRS * BLOCK_SIZE;
        if end > max_size {
            return Err(Error::OutOfMemory);
        }

        let mut bytes_written = 0;
        let mut file_pos = off;

        while bytes_written < data.len() {
            let block_idx = file_pos / BLOCK_SIZE;
            let block_off = file_pos % BLOCK_SIZE;
            let chunk = (BLOCK_SIZE - block_off).min(data.len() - bytes_written);

            // Allocate block if not yet assigned.
            if self.nodes[slot].addrs[block_idx] == NULL_ADDR {
                // Use block_idx as the storage slot (simplified).
                self.nodes[slot].addrs[block_idx] = block_idx as u64;
                self.file_blocks[block_idx] = [0u8; BLOCK_SIZE];

                // Update segment accounting.
                if self.cur_segment < MAX_SEGMENTS {
                    self.segments[self.cur_segment].valid_blocks += 1;
                    self.checkpoint.valid_block_count += 1;
                    self.cur_block_off += 1;
                    if self.segments[self.cur_segment].is_full() {
                        self.cur_segment = (self.cur_segment + 1) % MAX_SEGMENTS;
                        self.cur_block_off = 0;
                    }
                }
            }

            let blk_slot = self.nodes[slot].addrs[block_idx] as usize;
            if blk_slot < MAX_DIRECT_ADDRS {
                self.file_blocks[blk_slot][block_off..block_off + chunk]
                    .copy_from_slice(&data[bytes_written..bytes_written + chunk]);
            }

            bytes_written += chunk;
            file_pos += chunk;
        }

        if end as u64 > self.nodes[slot].size {
            self.nodes[slot].size = end as u64;
        }

        Ok(bytes_written)
    }

    /// Unlink a file from a directory.
    pub fn unlink(&mut self, parent_ino: u64, name: &str) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let parent_slot = self.node_slot(parent_ino).ok_or(Error::NotFound)?;
        let child_ino = self.dir_remove(parent_slot, name)?;
        let child_slot = self.node_slot(child_ino).ok_or(Error::NotFound)?;

        if self.nodes[child_slot].is_dir {
            return Err(Error::PermissionDenied);
        }

        self.free_node(child_slot);
        Ok(())
    }

    /// Remove a directory.
    pub fn rmdir(&mut self, parent_ino: u64, name: &str) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let parent_slot = self.node_slot(parent_ino).ok_or(Error::NotFound)?;

        // Look up the child first to check it is a directory and empty.
        let child_ino = self.dir_lookup(parent_slot, name)?;
        let child_slot = self.node_slot(child_ino).ok_or(Error::NotFound)?;

        if !self.nodes[child_slot].is_dir {
            return Err(Error::InvalidArgument);
        }
        if let Some(dir) = &self.dir_data[child_slot] {
            if dir.count > 0 {
                return Err(Error::InvalidArgument);
            }
        }

        self.dir_remove(parent_slot, name)?;
        self.free_node(child_slot);
        Ok(())
    }

    /// Run one garbage collection cycle.
    pub fn gc(&mut self) -> Result<u32> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.gc.run_gc(&mut self.segments)
    }

    /// Sync the filesystem — write a new checkpoint.
    pub fn sync(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        // Update checkpoint state.
        self.checkpoint.checkpoint_ver += 1;

        let mut free_count: u32 = 0;
        for seg in &self.segments {
            if seg.is_empty() {
                free_count += 1;
            }
        }
        self.checkpoint.free_segment_count = free_count;

        Ok(())
    }

    /// Return the current checkpoint.
    pub fn checkpoint(&self) -> &F2fsCheckpoint {
        &self.checkpoint
    }

    /// Return the superblock.
    pub fn superblock(&self) -> &F2fsSuperblock {
        &self.superblock
    }

    /// Return GC statistics.
    pub fn gc_stats(&self) -> &F2fsGc {
        &self.gc
    }
}

impl Default for F2fsFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for F2fsFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("F2fsFs")
            .field("mounted", &self.mounted)
            .field("node_count", &self.superblock.node_count)
            .field("checkpoint_ver", &self.checkpoint.checkpoint_ver)
            .field("gc_count", &self.gc.gc_count)
            .finish()
    }
}

// ── F2fsRegistry ────────────────────────────────────────────────

/// Global registry of mounted F2FS instances.
///
/// Supports up to [`MAX_F2FS_INSTANCES`] concurrent mounts.
pub struct F2fsRegistry {
    /// Mount path for each instance.
    paths: [[u8; MAX_NAME_LEN]; MAX_F2FS_INSTANCES],
    /// Path lengths.
    path_lens: [usize; MAX_F2FS_INSTANCES],
    /// Whether each slot is in use.
    active: [bool; MAX_F2FS_INSTANCES],
}

impl F2fsRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            paths: [[0u8; MAX_NAME_LEN]; MAX_F2FS_INSTANCES],
            path_lens: [0; MAX_F2FS_INSTANCES],
            active: [false; MAX_F2FS_INSTANCES],
        }
    }

    /// Register a new F2FS mount at the given path.
    pub fn register(&mut self, path: &str) -> Result<usize> {
        let path_bytes = path.as_bytes();
        if path_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        for (idx, used) in self.active.iter_mut().enumerate() {
            if !*used {
                self.paths[idx][..path_bytes.len()].copy_from_slice(path_bytes);
                self.path_lens[idx] = path_bytes.len();
                *used = true;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a mount by slot index.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_F2FS_INSTANCES || !self.active[idx] {
            return Err(Error::NotFound);
        }
        self.active[idx] = false;
        self.path_lens[idx] = 0;
        Ok(())
    }

    /// Find a mount by path, returning its slot index.
    pub fn find(&self, path: &str) -> Option<usize> {
        let path_bytes = path.as_bytes();
        for (idx, used) in self.active.iter().enumerate() {
            if *used
                && self.path_lens[idx] == path_bytes.len()
                && &self.paths[idx][..self.path_lens[idx]] == path_bytes
            {
                return Some(idx);
            }
        }
        None
    }
}

impl Default for F2fsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for F2fsRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let count = self.active.iter().filter(|a| **a).count();
        f.debug_struct("F2fsRegistry")
            .field("active_mounts", &count)
            .finish()
    }
}

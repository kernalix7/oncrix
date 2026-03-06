// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GFS2 journaling log subsystem.
//!
//! GFS2 (Global File System 2) is a cluster-aware journaling filesystem.
//! This module implements the log layer: log descriptor construction,
//! commit records, log-flush sequencing, and log-tail advancement used
//! during journal replay and normal operation.

use oncrix_lib::{Error, Result};

/// GFS2 log block size (same as filesystem block size, typically 4 KiB).
pub const GFS2_LOG_BLOCK_SIZE: usize = 4096;

/// Maximum number of log segments tracked in this module.
pub const GFS2_MAX_LOG_SEGMENTS: usize = 64;

/// Magic number present in every GFS2 metadata block header.
pub const GFS2_MAGIC: u32 = 0x01161990;

/// Block type tags stored in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Gfs2BlockType {
    /// Log descriptor block (list of journaled data blocks).
    LogDescriptor = 6,
    /// Log header (checkpoint / commit).
    LogHeader = 5,
    /// Journaled data block.
    Data = 0,
}

/// GFS2 metadata block header (on-disk layout, big-endian fields).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Gfs2MetaHeader {
    pub magic: u32,
    pub block_type: u32,
    pub format: u32,
    pub sequence: u32,
}

impl Gfs2MetaHeader {
    /// Create a header for a log descriptor block.
    pub fn log_descriptor(sequence: u32) -> Self {
        Self {
            magic: GFS2_MAGIC,
            block_type: Gfs2BlockType::LogDescriptor as u32,
            format: 0,
            sequence,
        }
    }

    /// Create a header for a log header / commit block.
    pub fn log_header(sequence: u32) -> Self {
        Self {
            magic: GFS2_MAGIC,
            block_type: Gfs2BlockType::LogHeader as u32,
            format: 0,
            sequence,
        }
    }

    /// Validate the magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == GFS2_MAGIC
    }
}

/// Flags in a GFS2 log header.
#[derive(Debug, Clone, Copy)]
pub struct LogHeaderFlags(pub u32);

impl LogHeaderFlags {
    pub const UNMOUNT: u32 = 0x0001;
    pub const FLUSH: u32 = 0x0002;

    pub fn is_unmount(&self) -> bool {
        self.0 & Self::UNMOUNT != 0
    }
    pub fn is_flush(&self) -> bool {
        self.0 & Self::FLUSH != 0
    }
}

/// In-memory representation of a GFS2 log segment.
#[derive(Debug, Clone)]
pub struct LogSegment {
    /// Journal block number of the first block in this segment.
    pub start_block: u64,
    /// Number of blocks in this segment.
    pub block_count: u32,
    /// Sequence number of the commit that closed this segment.
    pub sequence: u32,
    /// Whether this segment has been committed.
    pub committed: bool,
}

impl LogSegment {
    /// Create a new uncommitted log segment.
    pub fn new(start_block: u64, block_count: u32, sequence: u32) -> Self {
        Self {
            start_block,
            block_count,
            sequence,
            committed: false,
        }
    }
}

/// GFS2 journal log manager.
pub struct Gfs2Log {
    /// Ordered ring of log segments.
    segments: [Option<LogSegment>; GFS2_MAX_LOG_SEGMENTS],
    /// Number of valid segments.
    seg_count: usize,
    /// Monotonically increasing commit sequence number.
    sequence: u32,
    /// Journal block at which the log head currently sits.
    log_head: u64,
    /// Journal block at which the log tail sits (oldest unreclaimed segment).
    log_tail: u64,
    /// Total number of journal blocks available.
    journal_blocks: u64,
    /// Whether the log is in a clean (post-unmount) state.
    clean: bool,
}

impl Gfs2Log {
    /// Create a new GFS2 log manager.
    pub const fn new(journal_blocks: u64) -> Self {
        Self {
            segments: [const { None }; GFS2_MAX_LOG_SEGMENTS],
            seg_count: 0,
            sequence: 1,
            log_head: 0,
            log_tail: 0,
            journal_blocks,
            clean: true,
        }
    }

    /// Reserve `block_count` contiguous journal blocks and open a new segment.
    ///
    /// Returns `Err(OutOfMemory)` if there is insufficient journal space.
    pub fn begin_segment(&mut self, block_count: u32) -> Result<u64> {
        if self.seg_count >= GFS2_MAX_LOG_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        let available = self.available_blocks();
        if (block_count as u64) > available {
            return Err(Error::OutOfMemory);
        }
        let start = self.log_head;
        let seg = LogSegment::new(start, block_count, self.sequence);
        self.segments[self.seg_count] = Some(seg);
        self.seg_count += 1;
        self.log_head = (self.log_head + block_count as u64) % self.journal_blocks;
        self.clean = false;
        Ok(start)
    }

    /// Commit the most recently opened segment.
    pub fn commit_segment(&mut self) -> Result<u32> {
        // Find the last uncommitted segment.
        let seq = self.sequence;
        for slot in &mut self.segments[..self.seg_count] {
            if let Some(seg) = slot.as_mut() {
                if seg.sequence == seq && !seg.committed {
                    seg.committed = true;
                    self.sequence += 1;
                    return Ok(seq);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Advance the log tail, reclaiming all committed segments up to `target`.
    ///
    /// This is called during log cleaning to free journal space.
    pub fn advance_tail(&mut self, target_sequence: u32) -> Result<u64> {
        let mut reclaimed = 0u64;
        let mut i = 0;
        while i < self.seg_count {
            let committed = self.segments[i]
                .as_ref()
                .map(|s| s.committed && s.sequence <= target_sequence)
                .unwrap_or(false);
            if committed {
                if let Some(seg) = &self.segments[i] {
                    reclaimed += seg.block_count as u64;
                    self.log_tail =
                        (seg.start_block + seg.block_count as u64) % self.journal_blocks;
                }
                // Compact: move remaining segments down.
                self.segments[i] = None;
                for j in i..self.seg_count - 1 {
                    self.segments[j] = self.segments[j + 1].take();
                }
                self.seg_count -= 1;
            } else {
                i += 1;
            }
        }
        Ok(reclaimed)
    }

    /// Number of free journal blocks currently available.
    pub fn available_blocks(&self) -> u64 {
        if self.log_head >= self.log_tail {
            self.journal_blocks - self.log_head + self.log_tail
        } else {
            self.log_tail - self.log_head
        }
    }

    /// Current log head (next write position).
    #[inline]
    pub fn log_head(&self) -> u64 {
        self.log_head
    }

    /// Current log tail (oldest un-reclaimed position).
    #[inline]
    pub fn log_tail(&self) -> u64 {
        self.log_tail
    }

    /// Current commit sequence number.
    #[inline]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Whether the journal is in a clean state.
    #[inline]
    pub fn is_clean(&self) -> bool {
        self.clean
    }

    /// Mark the journal clean (called during unmount after a final flush).
    pub fn mark_clean(&mut self) {
        self.clean = true;
    }
}

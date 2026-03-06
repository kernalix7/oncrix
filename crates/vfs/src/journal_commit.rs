// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Journal commit processing for the ONCRIX VFS.
//!
//! Handles the mechanics of writing a committed transaction to the journal:
//! building descriptor blocks, writing modified data blocks, and writing
//! the final commit block that makes the transaction durable.

use oncrix_lib::{Error, Result};

/// Size of a journal descriptor block header in bytes.
pub const JOURNAL_DESC_HDR_SIZE: usize = 12;

/// Size of a single block tag within a descriptor block.
pub const JOURNAL_BLOCK_TAG_SIZE: usize = 16;

/// Maximum number of block tags in a single descriptor block.
pub const JOURNAL_DESC_MAX_TAGS: usize = (4096 - JOURNAL_DESC_HDR_SIZE) / JOURNAL_BLOCK_TAG_SIZE;

/// Flag bits for journal block tags.
pub const TAG_FLAG_SAME_UUID: u32 = 0x0001;
pub const TAG_FLAG_LAST_TAG: u32 = 0x0008;
pub const TAG_FLAG_ESCAPE: u32 = 0x0002;

/// A journal block tag describing one data block in a descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalBlockTag {
    /// Logical block number on the filesystem.
    pub fs_block: u64,
    /// Length of the block in bytes (0 = default block size).
    pub length: u32,
    /// Tag flags.
    pub flags: u32,
}

impl JournalBlockTag {
    /// Construct a new block tag.
    pub const fn new(fs_block: u64, flags: u32) -> Self {
        Self {
            fs_block,
            length: 0,
            flags,
        }
    }

    /// Return `true` if this is the last tag in a descriptor block.
    pub fn is_last(&self) -> bool {
        self.flags & TAG_FLAG_LAST_TAG != 0
    }

    /// Encode this tag into a 16-byte buffer (little-endian).
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < JOURNAL_BLOCK_TAG_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf[0..8].copy_from_slice(&self.fs_block.to_le_bytes());
        buf[8..12].copy_from_slice(&self.length.to_le_bytes());
        buf[12..16].copy_from_slice(&self.flags.to_le_bytes());
        Ok(())
    }

    /// Decode a block tag from a 16-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < JOURNAL_BLOCK_TAG_SIZE {
            return Err(Error::InvalidArgument);
        }
        let fs_block = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let length = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let flags = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self {
            fs_block,
            length,
            flags,
        })
    }
}

/// A journal descriptor block (maps journal blocks to filesystem blocks).
pub struct JournalDescriptor {
    /// Tags for each data block in this descriptor.
    tags: [JournalBlockTag; JOURNAL_DESC_MAX_TAGS],
    /// Number of valid tags.
    tag_count: usize,
    /// Sequence number of the transaction this descriptor belongs to.
    pub sequence: u32,
}

impl JournalDescriptor {
    /// Create an empty descriptor for the given transaction sequence.
    pub const fn new(sequence: u32) -> Self {
        Self {
            tags: [JournalBlockTag {
                fs_block: 0,
                length: 0,
                flags: 0,
            }; JOURNAL_DESC_MAX_TAGS],
            tag_count: 0,
            sequence,
        }
    }

    /// Add a block tag. Returns `OutOfMemory` if the descriptor is full.
    pub fn add_tag(&mut self, tag: JournalBlockTag) -> Result<()> {
        if self.tag_count >= JOURNAL_DESC_MAX_TAGS {
            return Err(Error::OutOfMemory);
        }
        self.tags[self.tag_count] = tag;
        self.tag_count += 1;
        Ok(())
    }

    /// Mark the last tag with `TAG_FLAG_LAST_TAG`.
    pub fn seal(&mut self) {
        if self.tag_count > 0 {
            self.tags[self.tag_count - 1].flags |= TAG_FLAG_LAST_TAG;
        }
    }

    /// Return a slice of the tag list.
    pub fn tags(&self) -> &[JournalBlockTag] {
        &self.tags[..self.tag_count]
    }

    /// Return the number of tags in this descriptor.
    pub fn tag_count(&self) -> usize {
        self.tag_count
    }
}

/// Commit block written at the end of a transaction in the journal.
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalCommitBlock {
    /// Transaction sequence number.
    pub sequence: u32,
    /// Timestamp seconds (wall clock at commit time).
    pub commit_sec: u64,
    /// Timestamp nanoseconds.
    pub commit_nsec: u32,
    /// Checksum of the entire transaction.
    pub checksum: u32,
}

impl JournalCommitBlock {
    /// Construct a new commit block.
    pub const fn new(sequence: u32, commit_sec: u64, commit_nsec: u32, checksum: u32) -> Self {
        Self {
            sequence,
            commit_sec,
            commit_nsec,
            checksum,
        }
    }

    /// Encode into a 32-byte buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < 32 {
            return Err(Error::InvalidArgument);
        }
        buf[0..4].copy_from_slice(&self.sequence.to_le_bytes());
        buf[4..12].copy_from_slice(&self.commit_sec.to_le_bytes());
        buf[12..16].copy_from_slice(&self.commit_nsec.to_le_bytes());
        buf[16..20].copy_from_slice(&self.checksum.to_le_bytes());
        for b in &mut buf[20..32] {
            *b = 0;
        }
        Ok(())
    }

    /// Decode from a 32-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            sequence: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            commit_sec: u64::from_le_bytes([
                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
            ]),
            commit_nsec: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            checksum: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }
}

/// State machine for a single journal commit pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CommitPhase {
    /// Not yet started.
    #[default]
    Idle,
    /// Writing descriptor blocks and data blocks to the journal.
    WritingData,
    /// Writing the commit block.
    WritingCommit,
    /// Commit completed; data is durable in the journal.
    Complete,
    /// Commit failed due to I/O error.
    Failed,
}

/// Context for executing a journal commit.
pub struct CommitContext {
    /// Transaction sequence being committed.
    pub sequence: u32,
    /// Current commit phase.
    pub phase: CommitPhase,
    /// Number of data blocks written so far.
    pub blocks_written: usize,
    /// Accumulated transaction checksum.
    pub checksum: u32,
}

impl CommitContext {
    /// Create a new commit context for the given sequence.
    pub const fn new(sequence: u32) -> Self {
        Self {
            sequence,
            phase: CommitPhase::Idle,
            blocks_written: 0,
            checksum: 0,
        }
    }

    /// Advance the checksum with a new data word.
    pub fn mix_checksum(&mut self, word: u32) {
        self.checksum ^= word.wrapping_add(self.sequence);
    }

    /// Transition to the next commit phase.
    pub fn advance(&mut self) -> Result<()> {
        self.phase = match self.phase {
            CommitPhase::Idle => CommitPhase::WritingData,
            CommitPhase::WritingData => CommitPhase::WritingCommit,
            CommitPhase::WritingCommit => CommitPhase::Complete,
            CommitPhase::Complete => return Err(Error::InvalidArgument),
            CommitPhase::Failed => return Err(Error::IoError),
        };
        Ok(())
    }

    /// Mark the commit as failed.
    pub fn fail(&mut self) {
        self.phase = CommitPhase::Failed;
    }
}

impl Default for CommitContext {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Build the 12-byte descriptor block header into `buf`.
pub fn build_descriptor_header(buf: &mut [u8], sequence: u32, block_type: u32) -> Result<()> {
    // magic[4] block_type[4] sequence[4]
    if buf.len() < JOURNAL_DESC_HDR_SIZE {
        return Err(Error::InvalidArgument);
    }
    buf[0..4].copy_from_slice(&0xC03B3998u32.to_le_bytes());
    buf[4..8].copy_from_slice(&block_type.to_le_bytes());
    buf[8..12].copy_from_slice(&sequence.to_le_bytes());
    Ok(())
}

/// Verify the descriptor header magic and return the block type.
pub fn parse_descriptor_header(buf: &[u8]) -> Result<(u32, u32)> {
    if buf.len() < JOURNAL_DESC_HDR_SIZE {
        return Err(Error::InvalidArgument);
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != 0xC03B3998 {
        return Err(Error::InvalidArgument);
    }
    let block_type = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let sequence = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Ok((block_type, sequence))
}

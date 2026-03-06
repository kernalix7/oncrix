// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NTFS index allocation and $INDEX_ALLOCATION attribute handling.
//!
//! NTFS uses B+ tree indexes to store sorted directory entries and other
//! sorted data (e.g., security descriptors, object IDs). The index is
//! stored in the `$INDEX_ROOT` attribute for small directories and in the
//! `$INDEX_ALLOCATION` attribute for larger ones.
//!
//! # Index Node Structure
//!
//! Each index allocation block (INDX) is 4 KiB by default and contains:
//! - An INDX header identifying the block.
//! - An index node header describing entry locations.
//! - An array of index entries, each containing the key and (for leaf nodes)
//!   a reference to the file record.
//!
//! # Index Entry Flags
//!
//! - `INDEX_ENTRY_NODE`: This entry has a sub-node pointer (internal node).
//! - `INDEX_ENTRY_END`: This is the last (sentinel) entry in the node.

use oncrix_lib::{Error, Result};

/// NTFS INDX block magic ("INDX" in little-endian).
pub const INDX_MAGIC: u32 = 0x58444E49;

/// Default size of an NTFS index allocation block.
pub const INDX_BLOCK_SIZE: usize = 4096;

/// Index entry flags.
pub mod entry_flags {
    /// Entry has a sub-node (VCN of child index block follows the entry).
    pub const INDEX_ENTRY_NODE: u16 = 0x0001;
    /// This is the end (sentinel) entry.
    pub const INDEX_ENTRY_END: u16 = 0x0002;
}

/// NTFS INDX block header (40 bytes).
#[derive(Clone, Copy, Default)]
pub struct IndxHeader {
    /// Magic number (INDX_MAGIC).
    pub magic: u32,
    /// Update sequence array offset.
    pub usa_offset: u16,
    /// Update sequence array count.
    pub usa_count: u16,
    /// Log file sequence number.
    pub lsn: u64,
    /// Virtual cluster number of this index block.
    pub index_block_vcn: u64,
}

impl IndxHeader {
    /// Parses an INDX header from 40 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 40 {
            return Err(Error::InvalidArgument);
        }
        let magic = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        if magic != INDX_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magic,
            usa_offset: u16::from_le_bytes([b[4], b[5]]),
            usa_count: u16::from_le_bytes([b[6], b[7]]),
            lsn: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            index_block_vcn: u64::from_le_bytes([
                b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
            ]),
        })
    }
}

/// NTFS index node header (16 bytes, follows the INDX header).
#[derive(Clone, Copy, Default)]
pub struct IndexNodeHeader {
    /// Offset of the first index entry, relative to the start of this header.
    pub entries_offset: u32,
    /// Total size of index entries (including the end sentinel).
    pub index_length: u32,
    /// Allocated size of the index block.
    pub allocated_size: u32,
    /// Non-leaf flag (1 = has children).
    pub flags: u8,
}

impl IndexNodeHeader {
    /// Parses from 16 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            entries_offset: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            index_length: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            allocated_size: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            flags: b[12],
        })
    }

    /// Returns `true` if this index node has child nodes.
    pub const fn has_children(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

/// An NTFS index entry (variable length).
#[derive(Clone, Copy, Default)]
pub struct IndexEntry {
    /// File reference (MFT record number in low 48 bits, sequence in high 16).
    pub file_reference: u64,
    /// Total length of this entry in bytes (including key and sub-node pointer).
    pub length: u16,
    /// Length of the key (attribute value) in bytes.
    pub key_length: u16,
    /// Entry flags (see [`entry_flags`]).
    pub flags: u16,
}

/// Minimum index entry header size.
pub const INDEX_ENTRY_HEADER_SIZE: usize = 16;

impl IndexEntry {
    /// Parses the fixed-size portion of an index entry header.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < INDEX_ENTRY_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            file_reference: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            length: u16::from_le_bytes([b[8], b[9]]),
            key_length: u16::from_le_bytes([b[10], b[11]]),
            flags: u16::from_le_bytes([b[12], b[13]]),
        })
    }

    /// Returns `true` if this is the end sentinel entry.
    pub const fn is_end(&self) -> bool {
        self.flags & entry_flags::INDEX_ENTRY_END != 0
    }

    /// Returns `true` if this entry has a child node pointer.
    pub const fn has_sub_node(&self) -> bool {
        self.flags & entry_flags::INDEX_ENTRY_NODE != 0
    }

    /// Returns the MFT record number (48-bit).
    pub const fn mft_record_number(&self) -> u64 {
        self.file_reference & 0x0000_FFFF_FFFF_FFFF
    }

    /// Returns the sequence number for the file reference.
    pub const fn sequence_number(&self) -> u16 {
        ((self.file_reference >> 48) & 0xFFFF) as u16
    }
}

/// Iterator over NTFS index entries within an INDX block.
pub struct IndexEntryIter<'a> {
    data: &'a [u8],
    /// Absolute offset of the first entry (relative to start of `data`).
    offset: usize,
    done: bool,
}

impl<'a> IndexEntryIter<'a> {
    /// Creates a new iterator.
    ///
    /// `entries_start` is the absolute byte offset of the first entry
    /// within `data` (INDX header offset + index node header offset + entries_offset).
    pub const fn new(data: &'a [u8], entries_start: usize) -> Self {
        Self {
            data,
            offset: entries_start,
            done: false,
        }
    }

    /// Returns the next index entry.
    pub fn next_entry(&mut self) -> Result<Option<IndexEntry>> {
        if self.done || self.offset + INDEX_ENTRY_HEADER_SIZE > self.data.len() {
            return Ok(None);
        }
        let entry = IndexEntry::from_bytes(&self.data[self.offset..])?;
        if entry.is_end() {
            self.done = true;
            return Ok(None);
        }
        if (entry.length as usize) < INDEX_ENTRY_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.offset += entry.length as usize;
        Ok(Some(entry))
    }
}

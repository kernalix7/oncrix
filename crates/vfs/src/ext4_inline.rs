// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 inline data support.
//!
//! Small files can be stored directly in the inode's block area (up to ~60 bytes)
//! or in the extended attribute area (up to ~3500 bytes with the inline data
//! xattr entry). This avoids block allocation for tiny files.
//!
//! # Inline data layout
//!
//! - `i_block[0..60]` — raw inline data (standard inline area)
//! - xattr area entry `EXT4_XATTR_INDEX_SYSTEM` / `"data"` — extended inline area
//! - Conversion to extent tree occurs when data exceeds `MAX_INLINE_DATA`
//!
//! # References
//!
//! - Linux `fs/ext4/inline.c`
//! - ext4 wiki: Inline Data feature

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum bytes stored in standard inline data area (i_block[]).
pub const MAX_INLINE_DATA: usize = 60;

/// Maximum bytes stored with extended xattr inline area.
pub const MAX_INLINE_DATA_XATTR: usize = 3500;

/// ext4 feature flag for inline data (EXT4_FEATURE_INCOMPAT_INLINE_DATA).
pub const EXT4_FEATURE_INLINE_DATA: u32 = 0x8000;

/// System xattr index for inline data.
pub const EXT4_XATTR_INDEX_SYSTEM: u8 = 7;

/// Maximum inode number we track.
const MAX_INODES: usize = 256;

/// Magic value indicating inode has inline data.
const INLINE_DATA_MAGIC: u32 = 0x494E4C44; // "INLD"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// State of inline data for a single inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineDataState {
    /// No inline data; file uses block/extent map.
    None,
    /// Data stored in standard i_block area (≤ 60 bytes).
    Standard,
    /// Data stored in standard + xattr extended area.
    Extended,
}

/// Inline data buffer: standard area (60 bytes) + extended area (3500 bytes).
#[derive(Clone)]
pub struct InlineData {
    /// Standard inline area.
    pub standard: [u8; MAX_INLINE_DATA],
    /// Extended xattr-backed area.
    pub extended: [u8; MAX_INLINE_DATA_XATTR],
    /// Number of bytes used in standard area.
    pub standard_len: usize,
    /// Number of bytes used in extended area.
    pub extended_len: usize,
    /// Current state.
    pub state: InlineDataState,
    /// Magic marker to detect valid inline data.
    magic: u32,
}

impl InlineData {
    /// Create a new empty inline data container.
    pub const fn new() -> Self {
        Self {
            standard: [0u8; MAX_INLINE_DATA],
            extended: [0u8; MAX_INLINE_DATA_XATTR],
            standard_len: 0,
            extended_len: 0,
            state: InlineDataState::None,
            magic: 0,
        }
    }

    /// Total bytes of inline content.
    pub fn total_len(&self) -> usize {
        self.standard_len + self.extended_len
    }

    /// Returns true if the inline data is marked valid.
    pub fn is_valid(&self) -> bool {
        self.magic == INLINE_DATA_MAGIC
    }
}

impl Default for InlineData {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-inode inline data entry in the table.
#[derive(Clone)]
struct InlineEntry {
    inode: u64,
    data: InlineData,
    in_use: bool,
}

impl InlineEntry {
    const fn empty() -> Self {
        Self {
            inode: 0,
            data: InlineData::new(),
            in_use: false,
        }
    }
}

/// Global table of inodes with inline data.
pub struct InlineDataTable {
    entries: [InlineEntry; MAX_INODES],
    count: usize,
}

impl InlineDataTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        const EMPTY: InlineEntry = InlineEntry::empty();
        Self {
            entries: [EMPTY; MAX_INODES],
            count: 0,
        }
    }

    /// Find the slot index for `inode`, if present.
    fn find(&self, inode: u64) -> Option<usize> {
        for i in 0..MAX_INODES {
            if self.entries[i].in_use && self.entries[i].inode == inode {
                return Some(i);
            }
        }
        None
    }

    /// Allocate a new slot for `inode`.
    fn alloc_slot(&mut self, inode: u64) -> Result<usize> {
        for i in 0..MAX_INODES {
            if !self.entries[i].in_use {
                self.entries[i].in_use = true;
                self.entries[i].inode = inode;
                self.entries[i].data = InlineData::new();
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for InlineDataTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Check whether an inode has inline data enabled.
///
/// Returns `true` if the inode has the inline-data state set to `Standard`
/// or `Extended`.
pub fn ext4_has_inline_data(table: &InlineDataTable, inode: u64) -> bool {
    match table.find(inode) {
        Some(idx) => table.entries[idx].data.state != InlineDataState::None,
        None => false,
    }
}

/// Read inline data for `inode` into `buf`.
///
/// Returns the number of bytes copied, or an error if the inode has no
/// inline data or `buf` is too small.
pub fn inline_data_get(
    table: &InlineDataTable,
    inode: u64,
    buf: &mut [u8],
    offset: usize,
) -> Result<usize> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    let entry = &table.entries[idx];
    if !entry.data.is_valid() {
        return Err(Error::NotFound);
    }

    let total = entry.data.total_len();
    if offset >= total {
        return Ok(0);
    }

    let src_len = total - offset;
    let copy_len = src_len.min(buf.len());

    // Copy from standard area first, then extended.
    let std_len = entry.data.standard_len;
    let mut copied = 0usize;

    if offset < std_len {
        let std_off = offset;
        let std_copy = (std_len - std_off).min(copy_len);
        buf[..std_copy].copy_from_slice(&entry.data.standard[std_off..std_off + std_copy]);
        copied += std_copy;
    }

    if copied < copy_len && entry.data.extended_len > 0 {
        let ext_off = if offset > std_len {
            offset - std_len
        } else {
            0
        };
        let ext_copy = (entry.data.extended_len - ext_off).min(copy_len - copied);
        buf[copied..copied + ext_copy]
            .copy_from_slice(&entry.data.extended[ext_off..ext_off + ext_copy]);
        copied += ext_copy;
    }

    Ok(copied)
}

/// Write inline data for `inode` from `buf`.
///
/// Automatically promotes to `Extended` state if data exceeds the standard
/// area limit. Returns `Err(InvalidArgument)` if data exceeds
/// `MAX_INLINE_DATA_XATTR`.
pub fn inline_data_set(
    table: &mut InlineDataTable,
    inode: u64,
    buf: &[u8],
    offset: usize,
) -> Result<()> {
    let end = offset + buf.len();
    if end > MAX_INLINE_DATA + MAX_INLINE_DATA_XATTR {
        return Err(Error::InvalidArgument);
    }

    let idx = match table.find(inode) {
        Some(i) => i,
        None => table.alloc_slot(inode)?,
    };

    let entry = &mut table.entries[idx];

    // Write into standard area.
    let std_end = end.min(MAX_INLINE_DATA);
    if offset < MAX_INLINE_DATA {
        let std_src_start = 0;
        let std_dst_start = offset;
        let std_count = std_end - offset;
        entry.data.standard[std_dst_start..std_dst_start + std_count]
            .copy_from_slice(&buf[std_src_start..std_src_start + std_count]);
        entry.data.standard_len = entry.data.standard_len.max(std_end);
    }

    // Write into extended area if needed.
    if end > MAX_INLINE_DATA {
        let ext_start = if offset > MAX_INLINE_DATA {
            offset - MAX_INLINE_DATA
        } else {
            0
        };
        let ext_end = end - MAX_INLINE_DATA;
        let buf_off = if offset < MAX_INLINE_DATA {
            MAX_INLINE_DATA - offset
        } else {
            0
        };
        let ext_count = ext_end - ext_start;
        entry.data.extended[ext_start..ext_start + ext_count]
            .copy_from_slice(&buf[buf_off..buf_off + ext_count]);
        entry.data.extended_len = entry.data.extended_len.max(ext_end);
        entry.data.state = InlineDataState::Extended;
    } else {
        if entry.data.state == InlineDataState::None {
            entry.data.state = InlineDataState::Standard;
        }
    }

    entry.data.magic = INLINE_DATA_MAGIC;
    Ok(())
}

/// Convert inline data to extent-based storage.
///
/// Marks the inode as no longer having inline data and returns the
/// previously inlined bytes for the caller to write to a new extent.
/// After this call `ext4_has_inline_data` returns `false` for `inode`.
pub fn inline_data_convert_to_extent(
    table: &mut InlineDataTable,
    inode: u64,
    out_buf: &mut [u8; MAX_INLINE_DATA + MAX_INLINE_DATA_XATTR],
) -> Result<usize> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    let total = table.entries[idx].data.total_len();
    let std_len = table.entries[idx].data.standard_len;
    let ext_len = table.entries[idx].data.extended_len;

    out_buf[..std_len].copy_from_slice(&table.entries[idx].data.standard[..std_len]);
    out_buf[std_len..std_len + ext_len]
        .copy_from_slice(&table.entries[idx].data.extended[..ext_len]);

    // Clear inline state.
    table.entries[idx].data.state = InlineDataState::None;
    table.entries[idx].data.standard_len = 0;
    table.entries[idx].data.extended_len = 0;
    table.entries[idx].data.magic = 0;

    Ok(total)
}

/// Remove the inline data entry for `inode`.
///
/// Called when the file is deleted or the inode is reclaimed.
pub fn inline_data_remove(table: &mut InlineDataTable, inode: u64) -> Result<()> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    table.entries[idx] = InlineEntry::empty();
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Return total inline bytes for `inode`, or 0 if not inline.
pub fn inline_data_size(table: &InlineDataTable, inode: u64) -> usize {
    match table.find(inode) {
        Some(idx) => table.entries[idx].data.total_len(),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Filesystem-level helpers
// ---------------------------------------------------------------------------

/// Result of an inline data check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineCheck {
    /// Inode uses inline data; length returned.
    Inline(usize),
    /// Inode uses extent/block map.
    Extent,
}

/// Determine whether to use inline path or extent path for a read.
pub fn ext4_inline_check(table: &InlineDataTable, inode: u64) -> InlineCheck {
    match table.find(inode) {
        Some(idx) if table.entries[idx].data.state != InlineDataState::None => {
            InlineCheck::Inline(table.entries[idx].data.total_len())
        }
        _ => InlineCheck::Extent,
    }
}

/// Truncate inline data for `inode` to `new_len` bytes.
///
/// If `new_len` is 0 the data is cleared but the inline state is preserved
/// until [`inline_data_remove`] is called.
pub fn inline_data_truncate(table: &mut InlineDataTable, inode: u64, new_len: usize) -> Result<()> {
    if new_len > MAX_INLINE_DATA + MAX_INLINE_DATA_XATTR {
        return Err(Error::InvalidArgument);
    }
    let idx = table.find(inode).ok_or(Error::NotFound)?;

    if new_len <= MAX_INLINE_DATA {
        // Truncate to standard-only.
        table.entries[idx].data.standard_len = new_len;
        table.entries[idx].data.extended_len = 0;
        if new_len > 0 {
            table.entries[idx].data.state = InlineDataState::Standard;
        }
    } else {
        // Truncate extended area.
        table.entries[idx].data.standard_len = MAX_INLINE_DATA;
        table.entries[idx].data.extended_len = new_len - MAX_INLINE_DATA;
        table.entries[idx].data.state = InlineDataState::Extended;
    }

    Ok(())
}

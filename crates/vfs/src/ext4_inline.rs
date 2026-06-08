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
//! # Inode size variants
//!
//! - 128-byte inode: standard inline area is 60 bytes (i_block region)
//! - 256-byte inode: additional 128 bytes in extra inode space, giving ~160 bytes
//!   before overflow to xattr area
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

/// Maximum bytes stored in 256-byte inode extra space (additional inline area).
pub const MAX_INLINE_DATA_EXTRA: usize = 100;

/// Maximum bytes stored with extended xattr inline area.
pub const MAX_INLINE_DATA_XATTR: usize = 3500;

/// Maximum total inline capacity including extra inode space and xattr area.
pub const MAX_INLINE_TOTAL: usize = MAX_INLINE_DATA + MAX_INLINE_DATA_EXTRA + MAX_INLINE_DATA_XATTR;

/// ext4 feature flag for inline data (EXT4_FEATURE_INCOMPAT_INLINE_DATA).
pub const EXT4_FEATURE_INLINE_DATA: u32 = 0x8000;

/// System xattr index for inline data.
pub const EXT4_XATTR_INDEX_SYSTEM: u8 = 7;

/// Maximum inode number we track.
const MAX_INODES: usize = 256;

/// Magic value indicating inode has inline data.
const INLINE_DATA_MAGIC: u32 = 0x494E_4C44; // "INLD"

/// Xattr name for inline data (ASCII "data").
pub const XATTR_NAME_INLINE_DATA: [u8; 4] = [b'd', b'a', b't', b'a'];

/// Maximum number of xattr entries per inode.
const MAX_XATTR_ENTRIES: usize = 16;

/// Maximum xattr value size.
const MAX_XATTR_VALUE_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Inode size variant controlling inline data capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InodeSizeVariant {
    /// 128-byte inode: only standard 60-byte i_block area available.
    #[default]
    Small,
    /// 256-byte inode: additional 100-byte extra area available.
    Large,
}

impl InodeSizeVariant {
    /// Returns the maximum standard+extra inline bytes for this inode size.
    pub fn max_inline_inode_bytes(self) -> usize {
        match self {
            InodeSizeVariant::Small => MAX_INLINE_DATA,
            InodeSizeVariant::Large => MAX_INLINE_DATA + MAX_INLINE_DATA_EXTRA,
        }
    }
}

/// State of inline data for a single inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlineDataState {
    /// No inline data; file uses block/extent map.
    None,
    /// Data stored in standard i_block area (≤ 60 bytes).
    Standard,
    /// Data stored in standard + extra inode area (≤ 160 bytes, 256-byte inode only).
    Extra,
    /// Data stored in standard + [extra +] xattr extended area.
    Extended,
}

/// Inline data buffer: standard area (60 bytes) + extra inode area (100 bytes)
/// + extended xattr area (3500 bytes).
#[derive(Clone)]
pub struct InlineData {
    /// Standard inline area (i_block[]).
    pub standard: [u8; MAX_INLINE_DATA],
    /// Extra inode area (256-byte inode only).
    pub extra: [u8; MAX_INLINE_DATA_EXTRA],
    /// Extended xattr-backed area.
    pub extended: [u8; MAX_INLINE_DATA_XATTR],
    /// Number of bytes used in standard area.
    pub standard_len: usize,
    /// Number of bytes used in extra area.
    pub extra_len: usize,
    /// Number of bytes used in extended area.
    pub extended_len: usize,
    /// Current state.
    pub state: InlineDataState,
    /// Inode size variant.
    pub inode_variant: InodeSizeVariant,
    /// Magic marker to detect valid inline data.
    magic: u32,
}

impl InlineData {
    /// Create a new empty inline data container.
    pub const fn new() -> Self {
        Self {
            standard: [0u8; MAX_INLINE_DATA],
            extra: [0u8; MAX_INLINE_DATA_EXTRA],
            extended: [0u8; MAX_INLINE_DATA_XATTR],
            standard_len: 0,
            extra_len: 0,
            extended_len: 0,
            state: InlineDataState::None,
            inode_variant: InodeSizeVariant::Small,
            magic: 0,
        }
    }

    /// Total bytes of inline content.
    pub fn total_len(&self) -> usize {
        self.standard_len + self.extra_len + self.extended_len
    }

    /// Returns true if the inline data is marked valid.
    pub fn is_valid(&self) -> bool {
        self.magic == INLINE_DATA_MAGIC
    }

    /// Maximum capacity before conversion to extents is required.
    pub fn capacity(&self) -> usize {
        self.inode_variant.max_inline_inode_bytes() + MAX_INLINE_DATA_XATTR
    }
}

impl Default for InlineData {
    fn default() -> Self {
        Self::new()
    }
}

/// A single xattr entry stored inline.
#[derive(Clone, Copy)]
pub struct InlineXattrEntry {
    /// Xattr namespace index (e.g. `EXT4_XATTR_INDEX_SYSTEM`).
    pub index: u8,
    /// Xattr name length in bytes.
    pub name_len: u8,
    /// Xattr name bytes (null-padded).
    pub name: [u8; 16],
    /// Xattr value.
    pub value: [u8; MAX_XATTR_VALUE_SIZE],
    /// Number of valid bytes in `value`.
    pub value_len: usize,
    /// Slot is occupied.
    pub in_use: bool,
}

impl InlineXattrEntry {
    /// Create an empty entry.
    pub const fn empty() -> Self {
        Self {
            index: 0,
            name_len: 0,
            name: [0u8; 16],
            value: [0u8; MAX_XATTR_VALUE_SIZE],
            value_len: 0,
            in_use: false,
        }
    }
}

impl Default for InlineXattrEntry {
    fn default() -> Self {
        Self::empty()
    }
}

/// Per-inode xattr table stored inline.
#[derive(Clone)]
pub struct InlineXattrTable {
    entries: [InlineXattrEntry; MAX_XATTR_ENTRIES],
    count: usize,
}

impl InlineXattrTable {
    /// Create an empty xattr table.
    pub const fn new() -> Self {
        const EMPTY: InlineXattrEntry = InlineXattrEntry::empty();
        Self {
            entries: [EMPTY; MAX_XATTR_ENTRIES],
            count: 0,
        }
    }

    /// Find an entry by index and name.
    pub fn find(&self, index: u8, name: &[u8]) -> Option<usize> {
        for (i, e) in self.entries.iter().enumerate() {
            if e.in_use
                && e.index == index
                && e.name_len as usize == name.len()
                && e.name[..name.len()] == *name
            {
                return Some(i);
            }
        }
        None
    }

    /// Set (insert or update) an xattr value.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `name` or `value` exceed capacity.
    /// - [`Error::OutOfMemory`] if the table is full.
    pub fn set(&mut self, index: u8, name: &[u8], value: &[u8]) -> Result<()> {
        if name.len() > 16 || value.len() > MAX_XATTR_VALUE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Update existing.
        if let Some(slot) = self.find(index, name) {
            let e = &mut self.entries[slot];
            e.value[..value.len()].copy_from_slice(value);
            e.value_len = value.len();
            return Ok(());
        }
        // Allocate new slot.
        for e in self.entries.iter_mut() {
            if !e.in_use {
                e.index = index;
                e.name_len = name.len() as u8;
                e.name[..name.len()].copy_from_slice(name);
                e.value[..value.len()].copy_from_slice(value);
                e.value_len = value.len();
                e.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get an xattr value slice.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no matching entry exists.
    pub fn get<'a>(&'a self, index: u8, name: &[u8]) -> Result<&'a [u8]> {
        let slot = self.find(index, name).ok_or(Error::NotFound)?;
        let e = &self.entries[slot];
        Ok(&e.value[..e.value_len])
    }

    /// Remove an xattr entry.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no matching entry exists.
    pub fn remove(&mut self, index: u8, name: &[u8]) -> Result<()> {
        let slot = self.find(index, name).ok_or(Error::NotFound)?;
        self.entries[slot] = InlineXattrEntry::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of active xattr entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for InlineXattrTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-inode inline data entry in the table.
#[derive(Clone)]
struct InlineEntry {
    inode: u64,
    data: InlineData,
    xattrs: InlineXattrTable,
    in_use: bool,
}

impl InlineEntry {
    const fn empty() -> Self {
        const EMPTY_XATTR: InlineXattrEntry = InlineXattrEntry::empty();
        Self {
            inode: 0,
            data: InlineData::new(),
            xattrs: InlineXattrTable {
                entries: [EMPTY_XATTR; MAX_XATTR_ENTRIES],
                count: 0,
            },
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
        for (i, e) in self.entries.iter().enumerate() {
            if e.in_use && e.inode == inode {
                return Some(i);
            }
        }
        None
    }

    /// Allocate a new slot for `inode`.
    fn alloc_slot(&mut self, inode: u64) -> Result<usize> {
        for (i, e) in self.entries.iter_mut().enumerate() {
            if !e.in_use {
                e.in_use = true;
                e.inode = inode;
                e.data = InlineData::new();
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
/// Returns `true` if the inode has the inline-data state set to `Standard`,
/// `Extra`, or `Extended`.
pub fn ext4_has_inline_data(table: &InlineDataTable, inode: u64) -> bool {
    match table.find(inode) {
        Some(idx) => table.entries[idx].data.state != InlineDataState::None,
        None => false,
    }
}

/// Configure the inode size variant for an inode.
///
/// Must be called before writing inline data if using 256-byte inodes.
/// Defaults to [`InodeSizeVariant::Small`] if not set.
pub fn inline_data_set_inode_variant(
    table: &mut InlineDataTable,
    inode: u64,
    variant: InodeSizeVariant,
) -> Result<()> {
    let idx = match table.find(inode) {
        Some(i) => i,
        None => table.alloc_slot(inode)?,
    };
    table.entries[idx].data.inode_variant = variant;
    Ok(())
}

/// Returns the inode size variant for `inode`.
pub fn inline_data_inode_variant(table: &InlineDataTable, inode: u64) -> InodeSizeVariant {
    match table.find(inode) {
        Some(idx) => table.entries[idx].data.inode_variant,
        None => InodeSizeVariant::Small,
    }
}

/// Check whether `new_size` bytes of data would exceed the inline threshold
/// for this inode, requiring conversion to extents.
///
/// Returns `true` when the caller must call [`inline_data_convert_to_extent`].
pub fn inline_data_needs_convert(table: &InlineDataTable, inode: u64, new_size: usize) -> bool {
    match table.find(inode) {
        Some(idx) => new_size > table.entries[idx].data.capacity(),
        None => {
            // Unknown inode: default small inode capacity.
            new_size > MAX_INLINE_DATA + MAX_INLINE_DATA_XATTR
        }
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

    let available = total - offset;
    let copy_len = available.min(buf.len());
    let std_len = entry.data.standard_len;
    let extra_len = entry.data.extra_len;

    // Regions: [0..std_len] standard, [std_len..std_len+extra_len] extra,
    //          [std_len+extra_len..total] extended.
    let mut dest_off = 0usize;
    let mut src_pos = offset;

    // --- standard region ---
    if dest_off < copy_len && src_pos < std_len {
        let from = src_pos;
        let until = std_len.min(offset + copy_len);
        let n = until - from;
        buf[dest_off..dest_off + n].copy_from_slice(&entry.data.standard[from..from + n]);
        dest_off += n;
        src_pos += n;
    }

    // --- extra region ---
    let extra_start = std_len;
    let extra_end = std_len + extra_len;
    if dest_off < copy_len && src_pos < extra_end && extra_len > 0 {
        let from = src_pos - extra_start;
        let until = extra_end.min(offset + copy_len) - extra_start;
        let n = until - from;
        buf[dest_off..dest_off + n].copy_from_slice(&entry.data.extra[from..from + n]);
        dest_off += n;
        src_pos += n;
    }

    // --- extended region ---
    let ext_start = std_len + extra_len;
    if dest_off < copy_len && src_pos >= ext_start && entry.data.extended_len > 0 {
        let from = src_pos - ext_start;
        let avail_ext = entry.data.extended_len.saturating_sub(from);
        let n = avail_ext.min(copy_len - dest_off);
        buf[dest_off..dest_off + n].copy_from_slice(&entry.data.extended[from..from + n]);
        dest_off += n;
    }

    Ok(dest_off)
}

/// Write inline data for `inode` from `buf`.
///
/// Automatically promotes to `Extra` state (256-byte inode) or `Extended`
/// state if data exceeds the standard area limit. Returns
/// `Err(InvalidArgument)` if data exceeds total inline capacity.
pub fn inline_data_set(
    table: &mut InlineDataTable,
    inode: u64,
    buf: &[u8],
    offset: usize,
) -> Result<()> {
    let idx = match table.find(inode) {
        Some(i) => i,
        None => table.alloc_slot(inode)?,
    };

    let capacity = table.entries[idx].data.capacity();

    // SECURITY: `offset` and `buf.len()` both derive from caller-supplied (and
    // potentially on-disk) values.  A raw `offset + buf.len()` overflows `usize`
    // when an attacker crafts a large offset, producing a small `end` that would
    // bypass the `end > capacity` guard below and allow writes into arbitrary
    // positions of the fixed-size arrays.  Use checked_add and reject on overflow.
    let end = offset
        .checked_add(buf.len())
        .ok_or(Error::InvalidArgument)?;

    // SECURITY: Also reject a non-zero-length write that starts beyond capacity
    // so that the subsequent slice arithmetic cannot underflow.
    if offset > capacity {
        return Err(Error::InvalidArgument);
    }
    if end > capacity {
        return Err(Error::InvalidArgument);
    }

    let inode_max = table.entries[idx]
        .data
        .inode_variant
        .max_inline_inode_bytes();
    let entry = &mut table.entries[idx];

    // Write standard area.
    if offset < MAX_INLINE_DATA {
        let std_end = end.min(MAX_INLINE_DATA);
        let count = std_end - offset;
        entry.data.standard[offset..std_end].copy_from_slice(&buf[..count]);
        entry.data.standard_len = entry.data.standard_len.max(std_end);
    }

    // Write extra area (256-byte inode only).
    if end > MAX_INLINE_DATA && offset < inode_max {
        let extra_start = MAX_INLINE_DATA;
        let dst_from = offset.saturating_sub(extra_start);
        let dst_to = (end.min(inode_max)) - extra_start;
        let src_from = if offset < extra_start {
            extra_start - offset
        } else {
            0
        };
        let count = dst_to - dst_from;
        entry.data.extra[dst_from..dst_to].copy_from_slice(&buf[src_from..src_from + count]);
        entry.data.extra_len = entry.data.extra_len.max(dst_to);
    }

    // Write extended (xattr) area.
    if end > inode_max {
        let ext_base = inode_max;
        let dst_from = offset.saturating_sub(ext_base);
        let dst_to = end - ext_base;
        let src_from = if offset < ext_base {
            ext_base - offset
        } else {
            0
        };
        let count = dst_to - dst_from;
        entry.data.extended[dst_from..dst_to].copy_from_slice(&buf[src_from..src_from + count]);
        entry.data.extended_len = entry.data.extended_len.max(dst_to);
    }

    // Update state.
    entry.data.state = if entry.data.extended_len > 0 {
        InlineDataState::Extended
    } else if entry.data.extra_len > 0 {
        InlineDataState::Extra
    } else {
        InlineDataState::Standard
    };

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
    out_buf: &mut [u8; MAX_INLINE_DATA + MAX_INLINE_DATA_EXTRA + MAX_INLINE_DATA_XATTR],
) -> Result<usize> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    let std_len = table.entries[idx].data.standard_len;
    let extra_len = table.entries[idx].data.extra_len;
    let ext_len = table.entries[idx].data.extended_len;
    let total = std_len + extra_len + ext_len;

    // Flatten: standard | extra | extended → contiguous.
    out_buf[..std_len].copy_from_slice(&table.entries[idx].data.standard[..std_len]);
    out_buf[std_len..std_len + extra_len]
        .copy_from_slice(&table.entries[idx].data.extra[..extra_len]);
    out_buf[std_len + extra_len..total]
        .copy_from_slice(&table.entries[idx].data.extended[..ext_len]);

    // Clear inline state.
    table.entries[idx].data.state = InlineDataState::None;
    table.entries[idx].data.standard_len = 0;
    table.entries[idx].data.extra_len = 0;
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
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    let inode_max = table.entries[idx]
        .data
        .inode_variant
        .max_inline_inode_bytes();
    let capacity = table.entries[idx].data.capacity();

    if new_len > capacity {
        return Err(Error::InvalidArgument);
    }

    if new_len <= MAX_INLINE_DATA {
        table.entries[idx].data.standard_len = new_len;
        table.entries[idx].data.extra_len = 0;
        table.entries[idx].data.extended_len = 0;
        if new_len > 0 {
            table.entries[idx].data.state = InlineDataState::Standard;
        }
    } else if new_len <= inode_max {
        table.entries[idx].data.standard_len = MAX_INLINE_DATA;
        table.entries[idx].data.extra_len = new_len - MAX_INLINE_DATA;
        table.entries[idx].data.extended_len = 0;
        table.entries[idx].data.state = InlineDataState::Extra;
    } else {
        table.entries[idx].data.standard_len = MAX_INLINE_DATA;
        table.entries[idx].data.extra_len = inode_max - MAX_INLINE_DATA;
        table.entries[idx].data.extended_len = new_len - inode_max;
        table.entries[idx].data.state = InlineDataState::Extended;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Inline xattr operations
// ---------------------------------------------------------------------------

/// Set an inline xattr entry for `inode`.
///
/// Stores extended attributes in the inode's inline xattr area. This is
/// used both for user-visible xattrs and for the internal `system.data`
/// entry that backs the extended inline data area.
///
/// # Errors
///
/// - [`Error::NotFound`] if the inode has no inline data slot.
/// - [`Error::InvalidArgument`] if name or value exceed capacity.
/// - [`Error::OutOfMemory`] if the xattr table is full.
pub fn inline_xattr_set(
    table: &mut InlineDataTable,
    inode: u64,
    index: u8,
    name: &[u8],
    value: &[u8],
) -> Result<()> {
    let idx = match table.find(inode) {
        Some(i) => i,
        None => table.alloc_slot(inode)?,
    };
    table.entries[idx].xattrs.set(index, name, value)
}

/// Get an inline xattr value for `inode`.
///
/// # Errors
///
/// - [`Error::NotFound`] if the inode or the xattr entry does not exist.
pub fn inline_xattr_get<'a>(
    table: &'a InlineDataTable,
    inode: u64,
    index: u8,
    name: &[u8],
) -> Result<&'a [u8]> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    table.entries[idx].xattrs.get(index, name)
}

/// Remove an inline xattr entry for `inode`.
///
/// # Errors
///
/// - [`Error::NotFound`] if the inode or entry does not exist.
pub fn inline_xattr_remove(
    table: &mut InlineDataTable,
    inode: u64,
    index: u8,
    name: &[u8],
) -> Result<()> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    table.entries[idx].xattrs.remove(index, name)
}

/// Store the extended inline data area into the `system.data` xattr slot.
///
/// This mirrors ext4's approach of persisting the xattr-backed inline area.
/// Returns the number of bytes stored.
///
/// # Errors
///
/// - [`Error::NotFound`] if the inode has no inline data.
/// - [`Error::InvalidArgument`] if the extended area exceeds xattr capacity.
pub fn inline_data_sync_xattr(table: &mut InlineDataTable, inode: u64) -> Result<usize> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    let ext_len = table.entries[idx].data.extended_len;
    if ext_len == 0 {
        return Ok(0);
    }
    if ext_len > MAX_XATTR_VALUE_SIZE {
        return Err(Error::InvalidArgument);
    }
    // Snapshot the extended data slice before the mutable borrow.
    let mut tmp = [0u8; MAX_XATTR_VALUE_SIZE];
    tmp[..ext_len].copy_from_slice(&table.entries[idx].data.extended[..ext_len]);
    table.entries[idx].xattrs.set(
        EXT4_XATTR_INDEX_SYSTEM,
        &XATTR_NAME_INLINE_DATA,
        &tmp[..ext_len],
    )?;
    Ok(ext_len)
}

/// Restore the extended inline data area from the `system.data` xattr slot.
///
/// Used during inode read to reload xattr-backed inline data.
///
/// # Errors
///
/// - [`Error::NotFound`] if the inode or xattr does not exist.
pub fn inline_data_restore_xattr(table: &mut InlineDataTable, inode: u64) -> Result<usize> {
    let idx = table.find(inode).ok_or(Error::NotFound)?;
    // Read from xattr table into a temporary buffer.
    let value = table.entries[idx]
        .xattrs
        .get(EXT4_XATTR_INDEX_SYSTEM, &XATTR_NAME_INLINE_DATA)?;
    let len = value.len().min(MAX_INLINE_DATA_XATTR);
    // Copy via a local array to avoid simultaneous borrow issues.
    let mut tmp = [0u8; MAX_INLINE_DATA_XATTR];
    tmp[..len].copy_from_slice(&value[..len]);
    table.entries[idx].data.extended[..len].copy_from_slice(&tmp[..len]);
    table.entries[idx].data.extended_len = len;
    if len > 0 && table.entries[idx].data.state != InlineDataState::Extended {
        table.entries[idx].data.state = InlineDataState::Extended;
    }
    Ok(len)
}

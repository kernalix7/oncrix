// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS pNFS layout management.
//!
//! Implements the client-side layout state machine for parallel NFS (pNFS)
//! as defined in RFC 5661 §12 and mirrored in `fs/nfs/pnfs.c`.
//!
//! # Layout lifecycle
//!
//! ```text
//! INVALID ──LAYOUTGET──► VALID ──RECALL──► RECALLED ──RETURN──► INVALID
//!                            └──────────────────────────────────────────┘
//! ```
//!
//! A layout covers a logical byte range `[offset, offset+length)` of a file
//! and specifies whether the range is readable, writable, or both (`iomode`).
//! Multiple non-overlapping layout segments may coexist for the same file.
//!
//! # Device information
//!
//! Each layout references a data server (DS) via a device ID. Device records
//! store the DS network address and are cached in [`DeviceTable`].
//!
//! # References
//!
//! - Linux `fs/nfs/pnfs.c`
//! - RFC 5661 §12: pNFS operation
//! - RFC 5663: pNFS Parallel NFS (pNFS) Block/Volume Layout

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of layout segments tracked per file.
pub const MAX_LAYOUT_SEGMENTS: usize = 32;

/// Maximum number of files with active layouts.
pub const MAX_LAYOUT_FILES: usize = 64;

/// Maximum number of device records cached globally.
pub const MAX_DEVICES: usize = 32;

/// Maximum byte length of a device address string.
pub const DEVICE_ADDR_MAX: usize = 64;

/// Layout type: file layout (RFC 5661 §13).
pub const LAYOUT_TYPE_FILE: u32 = 1;

/// Layout type: block/volume layout (RFC 5663).
pub const LAYOUT_TYPE_BLOCK: u32 = 2;

/// Layout type: object-based layout (RFC 5664).
pub const LAYOUT_TYPE_OBJECT: u32 = 3;

// ── IoMode ───────────────────────────────────────────────────────────────────

/// Access mode for a layout segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum IoMode {
    /// Read-only access.
    #[default]
    Read = 1,
    /// Read-write access.
    ReadWrite = 2,
}

// ── LayoutState ──────────────────────────────────────────────────────────────

/// State of a single layout segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LayoutState {
    /// Not yet obtained or already returned.
    #[default]
    Invalid,
    /// Successfully obtained from the server.
    Valid,
    /// Server has recalled the layout; return is pending.
    Recalled,
    /// Return is in progress.
    Returning,
}

// ── LayoutSegment ────────────────────────────────────────────────────────────

/// A single layout segment for a byte range of a file.
#[derive(Debug, Clone, Copy, Default)]
pub struct LayoutSegment {
    /// Access mode granted for this segment.
    pub iomode: IoMode,
    /// File byte offset where this segment begins.
    pub offset: u64,
    /// Length of this segment in bytes.
    pub length: u64,
    /// Device ID of the data server handling this segment.
    pub device_id: u64,
    /// Layout type (file, block, object).
    pub layout_type: u32,
    /// Current state of this segment.
    pub state: LayoutState,
    /// Generation counter of the owning layout (for staleness detection).
    pub layout_gen: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl LayoutSegment {
    /// Returns `true` if this segment overlaps the range `[off, off+len)`.
    pub const fn overlaps(&self, off: u64, len: u64) -> bool {
        self.offset < off + len && off < self.offset + self.length
    }

    /// Returns `true` if the segment can satisfy an access of the given mode.
    pub const fn satisfies(&self, iomode: IoMode) -> bool {
        matches!(
            (self.iomode, iomode),
            (IoMode::ReadWrite, _) | (IoMode::Read, IoMode::Read)
        )
    }
}

// ── DeviceAddr ───────────────────────────────────────────────────────────────

/// Network address of a pNFS data server.
#[derive(Clone, Copy)]
pub struct DeviceAddr {
    /// Raw address bytes (e.g. UTF-8 `ip:port`).
    pub bytes: [u8; DEVICE_ADDR_MAX],
    /// Number of valid bytes.
    pub len: usize,
}

impl Default for DeviceAddr {
    fn default() -> Self {
        Self {
            bytes: [0u8; DEVICE_ADDR_MAX],
            len: 0,
        }
    }
}

impl core::fmt::Debug for DeviceAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DeviceAddr")
            .field(&&self.bytes[..self.len])
            .finish()
    }
}

impl DeviceAddr {
    /// Creates a `DeviceAddr` from a byte slice.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > DEVICE_ADDR_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut addr = Self::default();
        addr.bytes[..src.len()].copy_from_slice(src);
        addr.len = src.len();
        Ok(addr)
    }

    /// Returns the address as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// ── DeviceRecord ─────────────────────────────────────────────────────────────

/// Cached device information for a pNFS data server.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceRecord {
    /// Unique device identifier assigned by the metadata server.
    pub device_id: u64,
    /// Network address of this data server.
    pub addr: DeviceAddr,
    /// Layout type this device serves.
    pub layout_type: u32,
    /// Whether this record is valid/active.
    pub active: bool,
}

// ── DeviceTable ──────────────────────────────────────────────────────────────

/// Cache of known pNFS data server device records.
#[derive(Debug, Default)]
pub struct DeviceTable {
    /// Stored device records.
    records: [DeviceRecord; MAX_DEVICES],
    /// Number of active records.
    count: usize,
}

impl DeviceTable {
    /// Inserts or updates a device record.
    pub fn insert(&mut self, rec: DeviceRecord) -> Result<()> {
        for r in &mut self.records[..self.count] {
            if r.active && r.device_id == rec.device_id {
                *r = rec;
                return Ok(());
            }
        }
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.records[self.count] = rec;
        self.count += 1;
        Ok(())
    }

    /// Looks up a device record by ID.
    pub fn get(&self, device_id: u64) -> Option<&DeviceRecord> {
        self.records[..self.count]
            .iter()
            .find(|r| r.active && r.device_id == device_id)
    }

    /// Removes a device record by ID.
    pub fn remove(&mut self, device_id: u64) -> Result<()> {
        let pos = self.records[..self.count]
            .iter()
            .position(|r| r.active && r.device_id == device_id)
            .ok_or(Error::NotFound)?;
        self.records[pos] = self.records[self.count - 1];
        self.records[self.count - 1] = DeviceRecord::default();
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of cached device records.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── FileLayout ────────────────────────────────────────────────────────────────

/// All layout segments for a single file.
pub struct FileLayout {
    /// Inode number of the file.
    pub inode_no: u64,
    /// Layout segments.
    segments: [LayoutSegment; MAX_LAYOUT_SEGMENTS],
    /// Number of active segments.
    seg_count: usize,
    /// Generation counter incremented each time segments are added or removed.
    generation: u64,
    /// Whether a layout recall is in progress.
    recall_pending: bool,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl Default for FileLayout {
    fn default() -> Self {
        Self {
            inode_no: 0,
            segments: [LayoutSegment::default(); MAX_LAYOUT_SEGMENTS],
            seg_count: 0,
            generation: 0,
            recall_pending: false,
            active: false,
        }
    }
}

impl FileLayout {
    /// Creates a new, empty layout for `inode_no`.
    pub const fn new(inode_no: u64) -> Self {
        Self {
            inode_no,
            segments: [const {
                LayoutSegment {
                    iomode: IoMode::Read,
                    offset: 0,
                    length: 0,
                    device_id: 0,
                    layout_type: 0,
                    state: LayoutState::Invalid,
                    layout_gen: 0,
                    active: false,
                }
            }; MAX_LAYOUT_SEGMENTS],
            seg_count: 0,
            generation: 0,
            recall_pending: false,
            active: true,
        }
    }

    /// Returns the current layout generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns `true` if a layout recall is pending.
    pub const fn recall_pending(&self) -> bool {
        self.recall_pending
    }

    // ── LAYOUTGET ─────────────────────────────────────────────────────────────

    /// Adds a layout segment obtained from a successful LAYOUTGET operation.
    ///
    /// Returns [`Error::OutOfMemory`] if the segment table is full, or
    /// [`Error::AlreadyExists`] if an identical segment already exists.
    pub fn add_segment(&mut self, seg: LayoutSegment) -> Result<()> {
        for s in &self.segments[..self.seg_count] {
            if s.active
                && s.iomode == seg.iomode
                && s.offset == seg.offset
                && s.length == seg.length
            {
                return Err(Error::AlreadyExists);
            }
        }
        if self.seg_count >= MAX_LAYOUT_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        let mut new_seg = seg;
        new_seg.layout_gen = self.generation;
        new_seg.state = LayoutState::Valid;
        new_seg.active = true;
        self.segments[self.seg_count] = new_seg;
        self.seg_count += 1;
        self.generation += 1;
        Ok(())
    }

    // ── LAYOUTRETURN ──────────────────────────────────────────────────────────

    /// Marks all segments in `[offset, offset+length)` as returned (invalid).
    ///
    /// After return the segments are removed from the table and the generation
    /// is bumped.
    pub fn return_segment(&mut self, iomode: IoMode, offset: u64, length: u64) -> Result<()> {
        let mut found = false;
        let mut i = 0;
        while i < self.seg_count {
            if self.segments[i].active
                && self.segments[i].iomode == iomode
                && self.segments[i].overlaps(offset, length)
            {
                self.segments[i] = self.segments[self.seg_count - 1];
                self.segments[self.seg_count - 1] = LayoutSegment::default();
                self.seg_count -= 1;
                found = true;
                self.generation += 1;
                // Do NOT increment i; re-examine position i.
            } else {
                i += 1;
            }
        }
        if self.recall_pending && self.seg_count == 0 {
            self.recall_pending = false;
        }
        if found { Ok(()) } else { Err(Error::NotFound) }
    }

    // ── LAYOUTRECALL ─────────────────────────────────────────────────────────

    /// Handles a server-initiated layout recall for the given range.
    ///
    /// Transitions all affected segments to [`LayoutState::Recalled`] and sets
    /// the recall_pending flag.
    pub fn handle_recall(&mut self, iomode: IoMode, offset: u64, length: u64) {
        for s in &mut self.segments[..self.seg_count] {
            if s.active && s.iomode == iomode && s.overlaps(offset, length) {
                s.state = LayoutState::Recalled;
            }
        }
        self.recall_pending = true;
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Finds a valid segment that covers `[offset, offset+length)` with the
    /// given `iomode`.
    pub fn find_segment(&self, iomode: IoMode, offset: u64, length: u64) -> Option<&LayoutSegment> {
        self.segments[..self.seg_count].iter().find(|s| {
            s.active
                && s.state == LayoutState::Valid
                && s.satisfies(iomode)
                && s.overlaps(offset, length)
        })
    }

    /// Returns all active segments.
    pub fn iter_segments<F: FnMut(&LayoutSegment)>(&self, mut f: F) {
        for s in &self.segments[..self.seg_count] {
            if s.active {
                f(s);
            }
        }
    }

    /// Returns the number of active segments.
    pub const fn seg_count(&self) -> usize {
        self.seg_count
    }
}

// ── LayoutCache ───────────────────────────────────────────────────────────────

/// Global client-side layout cache holding layouts for up to
/// [`MAX_LAYOUT_FILES`] files.
pub struct LayoutCache {
    /// Per-file layout entries.
    files: [FileLayout; MAX_LAYOUT_FILES],
    /// Number of active file entries.
    count: usize,
    /// Shared device information table.
    pub devices: DeviceTable,
}

impl Default for LayoutCache {
    fn default() -> Self {
        Self {
            files: [const { FileLayout::new(0) }; MAX_LAYOUT_FILES],
            count: 0,
            devices: DeviceTable::default(),
        }
    }
}

impl LayoutCache {
    /// Creates a new, empty layout cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the layout for `inode_no`, if present.
    pub fn get(&self, inode_no: u64) -> Option<&FileLayout> {
        self.files[..self.count]
            .iter()
            .find(|f| f.active && f.inode_no == inode_no)
    }

    /// Returns a mutable reference to the layout for `inode_no`, if present.
    pub fn get_mut(&mut self, inode_no: u64) -> Option<&mut FileLayout> {
        self.files[..self.count]
            .iter_mut()
            .find(|f| f.active && f.inode_no == inode_no)
    }

    /// Obtains a mutable reference to the layout for `inode_no`, creating a
    /// new empty layout if one does not exist.
    pub fn get_or_create(&mut self, inode_no: u64) -> Result<&mut FileLayout> {
        // Check for existing entry first by position.
        let pos = self.files[..self.count]
            .iter()
            .position(|f| f.active && f.inode_no == inode_no);
        if let Some(idx) = pos {
            return Ok(&mut self.files[idx]);
        }
        if self.count >= MAX_LAYOUT_FILES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.files[idx] = FileLayout::new(inode_no);
        self.count += 1;
        Ok(&mut self.files[idx])
    }

    /// Removes all layout segments for `inode_no` and frees the file slot.
    pub fn remove(&mut self, inode_no: u64) -> Result<()> {
        let pos = self.files[..self.count]
            .iter()
            .position(|f| f.active && f.inode_no == inode_no)
            .ok_or(Error::NotFound)?;
        let last = core::mem::replace(&mut self.files[self.count - 1], FileLayout::default());
        self.files[pos] = last;
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of files with cached layouts.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no layouts are cached.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

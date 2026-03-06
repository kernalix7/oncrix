// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFSv4.1 pNFS LAYOUTRETURN operation handling.
//!
//! In the pNFS architecture, clients are granted *layouts* that describe how
//! file data is distributed across one or more storage devices.  A layout
//! return operation (`LAYOUTRETURN`) is sent by the client to surrender all or
//! part of a previously granted layout back to the metadata server (MDS).
//!
//! # Return types
//!
//! | Type      | Scope |
//! |-----------|-------|
//! | `FILE`    | Return the layout for a single file |
//! | `FSID`    | Return all layouts on a specific filesystem |
//! | `ALL`     | Return all layouts held by this client session |
//!
//! # State machine
//!
//! ```text
//! GRANTED → [RECALL_PENDING] → RETURNING → RETURNED
//!                                  ↕
//!                               ERROR
//! ```
//!
//! # References
//!
//! - RFC 8881 §18.44 (LAYOUTRETURN)
//! - Linux `fs/nfs/pnfs.c`, `fs/nfs/nfs4proc.c` (layoutreturn path)
//! - Linux `include/linux/nfs4.h` (layout type constants)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of layout segments tracked per file.
pub const MAX_LAYOUT_SEGMENTS: usize = 16;

/// Maximum number of active layout entries in the server table.
pub const MAX_LAYOUT_ENTRIES: usize = 128;

/// Maximum length of the layout body returned in a LAYOUTRETURN.
pub const MAX_LR_BODY_LEN: usize = 256;

/// pNFS layout type: block/volume layout.
pub const LAYOUT_TYPE_BLOCK: u32 = 1;
/// pNFS layout type: object storage layout.
pub const LAYOUT_TYPE_OBJ: u32 = 2;
/// pNFS layout type: NFS v4.1 files layout.
pub const LAYOUT_TYPE_FILES: u32 = 4;
/// pNFS layout type: SCSI layout.
pub const LAYOUT_TYPE_SCSI: u32 = 5;
/// pNFS layout type: Flex Files layout.
pub const LAYOUT_TYPE_FLEX_FILES: u32 = 6;

// ---------------------------------------------------------------------------
// Layout return scope
// ---------------------------------------------------------------------------

/// Scope of a LAYOUTRETURN operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LrReturnType {
    /// Return the layout for a single file by stateid.
    File,
    /// Return all layouts for files sharing a given filesystem ID.
    Fsid,
    /// Return all layouts held by the client.
    All,
}

// ---------------------------------------------------------------------------
// Layout stateid (NFSv4 stateid format)
// ---------------------------------------------------------------------------

/// 16-byte NFSv4 stateid.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stateid {
    /// Sequence number (for state reclaim / replay detection).
    pub seqid: u32,
    /// Opaque stateid other — 12 bytes.
    pub other: [u8; 12],
}

impl Stateid {
    /// Construct a stateid from raw parts.
    pub const fn new(seqid: u32, other: [u8; 12]) -> Self {
        Self { seqid, other }
    }

    /// Return `true` if this is a "special" all-zeros stateid.
    pub fn is_zero(&self) -> bool {
        self.seqid == 0 && self.other == [0u8; 12]
    }
}

// ---------------------------------------------------------------------------
// Layout segment
// ---------------------------------------------------------------------------

/// Describes a single segment (byte range) within a layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LayoutSegment {
    /// Byte offset of this segment within the file.
    pub offset: u64,
    /// Length of this segment in bytes (`u64::MAX` = until EOF).
    pub length: u64,
    /// I/O mode: `1` = read, `2` = read/write.
    pub iomode: u32,
    /// Layout type (`LAYOUT_TYPE_*`).
    pub layout_type: u32,
}

impl LayoutSegment {
    /// Create a whole-file read/write segment.
    pub const fn whole_file(layout_type: u32) -> Self {
        Self {
            offset: 0,
            length: u64::MAX,
            iomode: 2,
            layout_type,
        }
    }

    /// Return `true` if this segment covers the given byte range.
    pub fn covers(&self, off: u64, len: u64) -> bool {
        let end = off.saturating_add(len);
        let seg_end = self.offset.saturating_add(self.length);
        self.offset <= off && end <= seg_end
    }
}

// ---------------------------------------------------------------------------
// Layout entry (server-side tracking)
// ---------------------------------------------------------------------------

/// Lifecycle state of a layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutState {
    /// Layout has been granted to a client.
    Granted,
    /// A recall has been sent; waiting for the client to return.
    RecallPending,
    /// Client is in the process of returning the layout.
    Returning,
    /// Layout has been successfully returned.
    Returned,
    /// Layout return encountered an error.
    Error,
}

/// A single tracked layout entry (server-side).
#[derive(Debug)]
pub struct LayoutEntry {
    /// File inode number this layout was granted for.
    pub ino: u64,
    /// Stateid assigned to this layout.
    pub stateid: Stateid,
    /// Client ID that holds this layout.
    pub client_id: u64,
    /// Number of valid segments.
    pub n_segments: usize,
    /// Layout segments (ranges granted).
    pub segments: [LayoutSegment; MAX_LAYOUT_SEGMENTS],
    /// Current lifecycle state.
    pub state: LayoutState,
    /// Monotonic timestamp of when the layout was granted.
    pub grant_time: u64,
    /// Monotonic timestamp of when the recall was sent (0 if not recalled).
    pub recall_time: u64,
}

impl LayoutEntry {
    /// Create a new granted layout entry.
    pub fn new(ino: u64, stateid: Stateid, client_id: u64) -> Self {
        Self {
            ino,
            stateid,
            client_id,
            n_segments: 0,
            segments: [const {
                LayoutSegment {
                    offset: 0,
                    length: 0,
                    iomode: 0,
                    layout_type: 0,
                }
            }; MAX_LAYOUT_SEGMENTS],
            state: LayoutState::Granted,
            grant_time: 0,
            recall_time: 0,
        }
    }

    /// Add a segment to this layout entry.
    pub fn add_segment(&mut self, seg: LayoutSegment) -> Result<()> {
        if self.n_segments >= MAX_LAYOUT_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        self.segments[self.n_segments] = seg;
        self.n_segments += 1;
        Ok(())
    }

    /// Return `true` if this entry's stateid matches `sid`.
    pub fn matches_stateid(&self, sid: &Stateid) -> bool {
        self.stateid == *sid
    }
}

// ---------------------------------------------------------------------------
// LAYOUTRETURN request/response
// ---------------------------------------------------------------------------

/// Parameters of a LAYOUTRETURN compound operation.
#[derive(Debug, Clone)]
pub struct LayoutReturnArgs {
    /// Whether this is a reclaim return (after server reboot).
    pub reclaim: bool,
    /// Layout type being returned.
    pub layout_type: u32,
    /// Return scope.
    pub return_type: LrReturnType,
    /// Stateid being returned (relevant for `FILE` scope).
    pub stateid: Stateid,
    /// Layout body (opaque, device-specific data up to `MAX_LR_BODY_LEN`).
    pub body_len: usize,
    /// Byte range offset (for partial returns; 0 = from start).
    pub offset: u64,
    /// Byte range length (for partial returns; `u64::MAX` = until EOF).
    pub length: u64,
}

impl LayoutReturnArgs {
    /// Construct a whole-file FILE-scope return.
    pub const fn file_return(layout_type: u32, stateid: Stateid) -> Self {
        Self {
            reclaim: false,
            layout_type,
            return_type: LrReturnType::File,
            stateid,
            body_len: 0,
            offset: 0,
            length: u64::MAX,
        }
    }

    /// Construct an ALL-scope return.
    pub const fn all_return(layout_type: u32) -> Self {
        Self {
            reclaim: false,
            layout_type,
            return_type: LrReturnType::All,
            stateid: Stateid {
                seqid: 0,
                other: [0u8; 12],
            },
            body_len: 0,
            offset: 0,
            length: u64::MAX,
        }
    }
}

/// Result of processing a LAYOUTRETURN.
#[derive(Debug, Clone, Copy)]
pub struct LayoutReturnResult {
    /// `true` if the server still holds a matching layout (partial return).
    pub layout_retained: bool,
    /// Updated stateid (if the layout was partially returned).
    pub new_stateid: Option<Stateid>,
}

// ---------------------------------------------------------------------------
// Server-side layout return table
// ---------------------------------------------------------------------------

/// Server-side layout manager tracking all outstanding layouts.
pub struct LayoutReturnTable {
    /// All layout entries.
    pub entries: [Option<LayoutEntry>; MAX_LAYOUT_ENTRIES],
    /// Number of active entries.
    pub count: usize,
    /// Total successful returns processed.
    pub returns_completed: u64,
    /// Total recalls sent.
    pub recalls_sent: u64,
}

impl LayoutReturnTable {
    /// Create an empty layout return table.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
            returns_completed: 0,
            recalls_sent: 0,
        }
    }

    /// Register a newly granted layout.
    pub fn grant(&mut self, entry: LayoutEntry) -> Result<()> {
        let slot = (0..MAX_LAYOUT_ENTRIES)
            .find(|&i| self.entries[i].is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Initiate a recall for all layouts covering file `ino`.
    ///
    /// Returns the number of recalls sent.
    pub fn recall_for_inode(&mut self, ino: u64, now: u64) -> usize {
        let mut count = 0;
        for slot in &mut self.entries {
            if let Some(entry) = slot.as_mut() {
                if entry.ino == ino && entry.state == LayoutState::Granted {
                    entry.state = LayoutState::RecallPending;
                    entry.recall_time = now;
                    count += 1;
                    self.recalls_sent += 1;
                }
            }
        }
        count
    }

    /// Process a LAYOUTRETURN from a client.
    ///
    /// Returns `Err(NotFound)` if no matching layout is found.
    pub fn process_return(&mut self, args: &LayoutReturnArgs) -> Result<LayoutReturnResult> {
        match args.return_type {
            LrReturnType::File => self.return_file(args),
            LrReturnType::Fsid => {
                // FSID return: mark all layouts for this client as returned.
                self.return_all_for_client(args.stateid.seqid as u64);
                Ok(LayoutReturnResult {
                    layout_retained: false,
                    new_stateid: None,
                })
            }
            LrReturnType::All => {
                self.return_all_for_client(args.stateid.seqid as u64);
                Ok(LayoutReturnResult {
                    layout_retained: false,
                    new_stateid: None,
                })
            }
        }
    }

    /// Process a FILE-scope LAYOUTRETURN.
    fn return_file(&mut self, args: &LayoutReturnArgs) -> Result<LayoutReturnResult> {
        let pos = self
            .entries
            .iter()
            .position(|e| {
                e.as_ref()
                    .map(|e| e.matches_stateid(&args.stateid))
                    .unwrap_or(false)
            })
            .ok_or(Error::NotFound)?;

        let entry = self.entries[pos].as_mut().ok_or(Error::NotFound)?;

        // Transition to Returning, then Returned.
        entry.state = LayoutState::Returning;
        // Check for partial return (byte range does not cover all segments).
        let partial = entry.segments[..entry.n_segments].iter().any(|s| {
            !LayoutSegment {
                offset: args.offset,
                length: args.length,
                ..*s
            }
            .covers(s.offset, s.length)
        });

        if partial {
            // Retain the layout for the unreturned segments (simplified).
            entry.state = LayoutState::Granted;
            self.returns_completed += 1;
            Ok(LayoutReturnResult {
                layout_retained: true,
                new_stateid: Some(entry.stateid),
            })
        } else {
            entry.state = LayoutState::Returned;
            self.returns_completed += 1;
            Ok(LayoutReturnResult {
                layout_retained: false,
                new_stateid: None,
            })
        }
    }

    /// Mark all layouts held by `client_id` as returned.
    fn return_all_for_client(&mut self, client_id: u64) {
        for slot in &mut self.entries {
            if let Some(entry) = slot.as_mut() {
                if entry.client_id == client_id {
                    entry.state = LayoutState::Returned;
                    self.returns_completed += 1;
                }
            }
        }
    }

    /// Remove all entries that have reached the `Returned` state.
    pub fn purge_returned(&mut self) {
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .map(|e| e.state == LayoutState::Returned)
                .unwrap_or(false)
            {
                *slot = None;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the number of active (non-None) layout entries.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    /// Return the number of layouts currently pending recall.
    pub fn pending_recall_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                e.as_ref()
                    .map(|e| e.state == LayoutState::RecallPending)
                    .unwrap_or(false)
            })
            .count()
    }
}

impl Default for LayoutReturnTable {
    fn default() -> Self {
        Self::new()
    }
}

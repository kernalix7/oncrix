// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ext4 fast-commit journal (EXT4_FEATURE_COMPAT_FAST_COMMIT).
//!
//! Fast commit is an optimised journaling path introduced in Linux 5.10 that
//! records only the *logical* changes needed to recover an fsync rather than
//! full data-block copies.  A fast-commit record is far smaller than a full
//! JBD2 transaction and avoids the overhead of commit I/O for every fsync(2).
//!
//! # Record types
//!
//! | Tag | Meaning |
//! |-----|---------|
//! | `ADD_RANGE`  | Inode gained an extent range |
//! | `DEL_RANGE`  | Inode lost an extent range   |
//! | `INODE`      | Inode metadata changed       |
//! | `DENTRY_ADD` | Directory entry added        |
//! | `DENTRY_DEL` | Directory entry removed      |
//! | `PAD`        | Padding / alignment          |
//! | `TAIL`       | Tail record (commit marker)  |
//!
//! # On-disk layout
//!
//! ```text
//! [FastCommitHead][FC record 0][FC record 1]...[FC tail]
//! ```
//!
//! The fast-commit area lives at the tail of the JBD2 journal and is a
//! fixed-size ring allocated from the last `s_fast_commit_blocks` blocks.
//!
//! # Recovery
//!
//! On mount after a crash, if the fast-commit area is non-empty and valid,
//! the kernel replays each record in order to reach a consistent state,
//! then truncates the area.
//!
//! # References
//!
//! - Linux `fs/ext4/fast_commit.c`, `fs/ext4/fast_commit.h`
//! - Ext4 documentation: `Documentation/filesystems/ext4/fast_commit.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic number embedded in each fast-commit record header.
pub const FC_MAGIC: u32 = 0x4645_4332; // "FEC2"

/// Maximum number of fast-commit records in the ring buffer.
pub const MAX_FC_RECORDS: usize = 256;

/// Maximum number of extent ranges that can be encoded in a single record.
pub const MAX_EXTENTS_PER_RECORD: usize = 8;

/// Fast-commit area block count (default).
pub const FC_DEFAULT_BLOCKS: u32 = 256;

/// Maximum byte length of a file name stored in a dentry record.
pub const FC_MAX_NAME_LEN: usize = 255;

// ---------------------------------------------------------------------------
// Record tag constants
// ---------------------------------------------------------------------------

/// Inode gained a new extent range (or an existing one was extended).
pub const FC_TAG_ADD_RANGE: u16 = 1;
/// Inode lost an existing extent range (truncate / hole-punch).
pub const FC_TAG_DEL_RANGE: u16 = 2;
/// Inode metadata (timestamps, size, mode, link-count) changed.
pub const FC_TAG_INODE: u16 = 3;
/// A new directory entry was added.
pub const FC_TAG_DENTRY_ADD: u16 = 4;
/// An existing directory entry was removed.
pub const FC_TAG_DENTRY_DEL: u16 = 5;
/// Padding record used for block alignment.
pub const FC_TAG_PAD: u16 = 6;
/// Tail (commit) record — marks the end of a valid fast-commit sequence.
pub const FC_TAG_TAIL: u16 = 7;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

/// Header common to every fast-commit record.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcRecordHeader {
    /// Magic identifier (`FC_MAGIC`).
    pub magic: u32,
    /// Record type tag (one of `FC_TAG_*`).
    pub tag: u16,
    /// Length of the payload that follows this header, in bytes.
    pub len: u16,
    /// Monotonically increasing transaction identifier.
    pub tid: u32,
}

/// A single logical extent range used by `ADD_RANGE` / `DEL_RANGE` records.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FcExtent {
    /// Logical block offset within the file.
    pub lblk: u32,
    /// Number of contiguous logical blocks.
    pub len: u32,
    /// Physical block start on the device.
    pub pblk: u64,
}

/// Payload for `FC_TAG_ADD_RANGE` and `FC_TAG_DEL_RANGE` records.
#[derive(Clone, Copy, Debug)]
pub struct FcRangeRecord {
    /// Inode number this range belongs to.
    pub ino: u32,
    /// Number of valid entries in `extents`.
    pub n_extents: u8,
    /// Packed extent list.
    pub extents: [FcExtent; MAX_EXTENTS_PER_RECORD],
}

/// Payload for `FC_TAG_INODE` — abbreviated inode metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcInodeRecord {
    /// Inode number.
    pub ino: u32,
    /// File size in bytes.
    pub size: u64,
    /// Access time (seconds since epoch).
    pub atime: i64,
    /// Modification time (seconds since epoch).
    pub mtime: i64,
    /// Change time (seconds since epoch).
    pub ctime: i64,
    /// File mode and type bits.
    pub mode: u16,
    /// Hard-link count.
    pub nlinks: u16,
}

/// Payload for `FC_TAG_DENTRY_ADD` and `FC_TAG_DENTRY_DEL` records.
#[derive(Clone, Debug)]
pub struct FcDentryRecord {
    /// Parent directory inode number.
    pub parent_ino: u32,
    /// Target inode number.
    pub ino: u32,
    /// File type byte (same encoding as `d_type` in `struct dirent`).
    pub file_type: u8,
    /// Name length.
    pub name_len: u8,
    /// File name bytes (only `name_len` bytes are valid).
    pub name: [u8; FC_MAX_NAME_LEN],
}

/// Tail record payload — commits the fast-commit sequence.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FcTailRecord {
    /// Transaction identifier this tail closes.
    pub tid: u32,
    /// CRC32c of all records in this sequence including the tail header.
    pub crc: u32,
}

/// Unified fast-commit record variant.
#[derive(Debug)]
pub enum FcRecord {
    /// Extent range added to an inode.
    AddRange(FcRangeRecord),
    /// Extent range removed from an inode.
    DelRange(FcRangeRecord),
    /// Inode metadata update.
    Inode(FcInodeRecord),
    /// Directory entry addition.
    DentryAdd(FcDentryRecord),
    /// Directory entry removal.
    DentryDel(FcDentryRecord),
    /// Padding (no payload).
    Pad,
    /// Tail / commit marker.
    Tail(FcTailRecord),
}

/// A pending fast-commit sequence: a list of records to be written.
#[derive(Debug)]
pub struct FcSequence {
    /// Transaction identifier for this sequence.
    pub tid: u32,
    /// Number of valid records stored.
    pub n_records: usize,
    /// Fixed-size record ring.
    pub records: [Option<FcRecord>; MAX_FC_RECORDS],
}

/// Fast-commit journal state for one ext4 instance.
#[derive(Debug)]
pub struct FastCommitJournal {
    /// Enabled flag — fast-commit may be disabled at mount time.
    pub enabled: bool,
    /// Next transaction ID to assign.
    next_tid: u32,
    /// Number of fast commits performed (statistics).
    pub commits_done: u64,
    /// Number of records replayed during recovery (statistics).
    pub records_replayed: u64,
    /// Pending (unflushed) sequence.
    pending: FcSequence,
    /// Whether the pending sequence has been dirtied.
    dirty: bool,
}

// ---------------------------------------------------------------------------
// FcRangeRecord helpers
// ---------------------------------------------------------------------------

impl FcRangeRecord {
    /// Create a new empty range record for the given inode.
    pub const fn new(ino: u32) -> Self {
        Self {
            ino,
            n_extents: 0,
            extents: [const {
                FcExtent {
                    lblk: 0,
                    len: 0,
                    pblk: 0,
                }
            }; MAX_EXTENTS_PER_RECORD],
        }
    }

    /// Append an extent to this record.
    ///
    /// Returns `Err(InvalidArgument)` if the record is already full.
    pub fn push_extent(&mut self, e: FcExtent) -> Result<()> {
        if self.n_extents as usize >= MAX_EXTENTS_PER_RECORD {
            return Err(Error::InvalidArgument);
        }
        self.extents[self.n_extents as usize] = e;
        self.n_extents += 1;
        Ok(())
    }

    /// Iterate over the valid extents in this record.
    pub fn extents(&self) -> &[FcExtent] {
        &self.extents[..self.n_extents as usize]
    }
}

// ---------------------------------------------------------------------------
// FcSequence helpers
// ---------------------------------------------------------------------------

impl FcSequence {
    /// Construct an empty sequence for the given transaction ID.
    pub fn new(tid: u32) -> Self {
        // Initialize with all None slots.
        Self {
            tid,
            n_records: 0,
            records: core::array::from_fn(|_| None),
        }
    }

    /// Append a record to this sequence.
    ///
    /// Returns `Err(OutOfMemory)` if the ring is full.
    pub fn push(&mut self, record: FcRecord) -> Result<()> {
        if self.n_records >= MAX_FC_RECORDS {
            return Err(Error::OutOfMemory);
        }
        self.records[self.n_records] = Some(record);
        self.n_records += 1;
        Ok(())
    }

    /// Reset the sequence, discarding all pending records.
    pub fn reset(&mut self, new_tid: u32) {
        for slot in &mut self.records[..self.n_records] {
            *slot = None;
        }
        self.n_records = 0;
        self.tid = new_tid;
    }
}

// ---------------------------------------------------------------------------
// FastCommitJournal
// ---------------------------------------------------------------------------

impl FastCommitJournal {
    /// Create a new fast-commit journal, initially disabled.
    pub fn new() -> Self {
        Self {
            enabled: false,
            next_tid: 1,
            commits_done: 0,
            records_replayed: 0,
            pending: FcSequence::new(1),
            dirty: false,
        }
    }

    /// Enable fast-commit mode.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Return whether fast-commit is active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Allocate and return the next transaction ID.
    fn alloc_tid(&mut self) -> u32 {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);
        tid
    }

    /// Log an inode metadata change into the pending sequence.
    ///
    /// Returns `Err(NotImplemented)` if fast-commit is disabled.
    /// Returns `Err(OutOfMemory)` if the pending ring is full.
    pub fn log_inode_change(&mut self, rec: FcInodeRecord) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.pending.push(FcRecord::Inode(rec))?;
        self.dirty = true;
        Ok(())
    }

    /// Log an extent addition for an inode.
    pub fn log_add_range(&mut self, rec: FcRangeRecord) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.pending.push(FcRecord::AddRange(rec))?;
        self.dirty = true;
        Ok(())
    }

    /// Log an extent removal for an inode.
    pub fn log_del_range(&mut self, rec: FcRangeRecord) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.pending.push(FcRecord::DelRange(rec))?;
        self.dirty = true;
        Ok(())
    }

    /// Log a directory entry addition.
    pub fn log_dentry_add(&mut self, rec: FcDentryRecord) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.pending.push(FcRecord::DentryAdd(rec))?;
        self.dirty = true;
        Ok(())
    }

    /// Log a directory entry removal.
    pub fn log_dentry_del(&mut self, rec: FcDentryRecord) -> Result<()> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        self.pending.push(FcRecord::DentryDel(rec))?;
        self.dirty = true;
        Ok(())
    }

    /// Commit the current pending sequence.
    ///
    /// In a real implementation this serialises all records to the fast-commit
    /// area on disk and writes the tail block.  Here we simulate the commit by
    /// appending a tail record and advancing the transaction counter.
    ///
    /// Returns the committed transaction ID on success.
    pub fn commit(&mut self) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if !self.dirty {
            // Nothing to commit.
            return Ok(self.pending.tid);
        }
        let tid = self.pending.tid;
        // Simulate CRC computation.
        let crc = self.compute_crc();
        self.pending
            .push(FcRecord::Tail(FcTailRecord { tid, crc }))?;
        // Advance to the next transaction sequence.
        let next_tid = self.alloc_tid();
        self.pending.reset(next_tid);
        self.dirty = false;
        self.commits_done += 1;
        Ok(tid)
    }

    /// Abort the current pending sequence without committing.
    pub fn abort(&mut self) {
        let next_tid = self.alloc_tid();
        self.pending.reset(next_tid);
        self.dirty = false;
    }

    /// Replay a serialised sequence of records, applying each to the
    /// provided replay context.
    ///
    /// Returns the number of records processed on success.
    pub fn replay<C: FcReplayContext>(&mut self, ctx: &mut C) -> Result<usize> {
        let mut count = 0usize;
        // Walk the pending ring (simulating reading from disk).
        for i in 0..self.pending.n_records {
            match &self.pending.records[i] {
                Some(FcRecord::AddRange(r)) => {
                    ctx.apply_add_range(r)?;
                    count += 1;
                }
                Some(FcRecord::DelRange(r)) => {
                    ctx.apply_del_range(r)?;
                    count += 1;
                }
                Some(FcRecord::Inode(r)) => {
                    ctx.apply_inode(r)?;
                    count += 1;
                }
                Some(FcRecord::DentryAdd(r)) => {
                    ctx.apply_dentry_add(r)?;
                    count += 1;
                }
                Some(FcRecord::DentryDel(r)) => {
                    ctx.apply_dentry_del(r)?;
                    count += 1;
                }
                Some(FcRecord::Tail(_)) | Some(FcRecord::Pad) | None => {}
            }
        }
        self.records_replayed += count as u64;
        Ok(count)
    }

    /// Compute a simple XOR-based "CRC" over the pending records for simulation.
    fn compute_crc(&self) -> u32 {
        let mut crc = FC_MAGIC;
        for i in 0..self.pending.n_records {
            match &self.pending.records[i] {
                Some(FcRecord::Inode(r)) => {
                    crc ^= r.ino ^ (r.size as u32);
                }
                Some(FcRecord::AddRange(r)) | Some(FcRecord::DelRange(r)) => {
                    crc ^= r.ino ^ (r.n_extents as u32);
                }
                Some(FcRecord::DentryAdd(r)) | Some(FcRecord::DentryDel(r)) => {
                    crc ^= r.parent_ino ^ r.ino;
                }
                Some(FcRecord::Tail(t)) => crc ^= t.tid,
                Some(FcRecord::Pad) | None => {}
            }
        }
        crc
    }

    /// Return the number of records in the pending (uncommitted) sequence.
    pub fn pending_record_count(&self) -> usize {
        self.pending.n_records
    }
}

impl Default for FastCommitJournal {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Replay context trait
// ---------------------------------------------------------------------------

/// Callback interface supplied by the ext4 recovery path to apply fast-commit
/// records to the in-memory filesystem state.
pub trait FcReplayContext {
    /// Apply an `ADD_RANGE` record (re-insert extents for an inode).
    fn apply_add_range(&mut self, rec: &FcRangeRecord) -> Result<()>;
    /// Apply a `DEL_RANGE` record (remove extents from an inode).
    fn apply_del_range(&mut self, rec: &FcRangeRecord) -> Result<()>;
    /// Apply an `INODE` record (restore inode metadata).
    fn apply_inode(&mut self, rec: &FcInodeRecord) -> Result<()>;
    /// Apply a `DENTRY_ADD` record (re-create a directory entry).
    fn apply_dentry_add(&mut self, rec: &FcDentryRecord) -> Result<()>;
    /// Apply a `DENTRY_DEL` record (re-remove a directory entry).
    fn apply_dentry_del(&mut self, rec: &FcDentryRecord) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Tail optimisation: scanning for the last valid fast-commit tail
// ---------------------------------------------------------------------------

/// Result of scanning the fast-commit area for a valid tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailScanResult {
    /// A valid tail was found with the given transaction ID and CRC.
    Found {
        tid: u32,
        crc: u32,
        record_count: usize,
    },
    /// The area contains no valid tail (e.g., after a clean unmount).
    Empty,
    /// The tail exists but the CRC does not match (corruption).
    Corrupted {
        tid: u32,
        stored_crc: u32,
        computed_crc: u32,
    },
}

/// Scan a serialised byte buffer (simulating the fast-commit blocks on disk)
/// and locate the last valid [`FcTailRecord`].
///
/// This is called during ext4 recovery before replaying any records.
pub fn scan_for_tail(journal: &FastCommitJournal) -> TailScanResult {
    // Scan backwards through the pending ring for a Tail record.
    let n = journal.pending.n_records;
    if n == 0 {
        return TailScanResult::Empty;
    }
    for i in (0..n).rev() {
        if let Some(FcRecord::Tail(t)) = &journal.pending.records[i] {
            let computed = journal.compute_crc();
            if computed == t.crc {
                return TailScanResult::Found {
                    tid: t.tid,
                    crc: t.crc,
                    record_count: i,
                };
            } else {
                return TailScanResult::Corrupted {
                    tid: t.tid,
                    stored_crc: t.crc,
                    computed_crc: computed,
                };
            }
        }
    }
    TailScanResult::Empty
}

// ---------------------------------------------------------------------------
// Builder helpers for common record types
// ---------------------------------------------------------------------------

/// Build an [`FcInodeRecord`] from constituent fields.
pub fn build_inode_record(
    ino: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    mode: u16,
    nlinks: u16,
) -> FcInodeRecord {
    FcInodeRecord {
        ino,
        size,
        atime,
        mtime,
        ctime,
        mode,
        nlinks,
    }
}

/// Build an [`FcDentryRecord`] from a name byte slice.
///
/// Returns `Err(InvalidArgument)` if `name` exceeds [`FC_MAX_NAME_LEN`].
pub fn build_dentry_record(
    parent_ino: u32,
    ino: u32,
    file_type: u8,
    name: &[u8],
) -> Result<FcDentryRecord> {
    if name.len() > FC_MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    let mut buf = [0u8; FC_MAX_NAME_LEN];
    buf[..name.len()].copy_from_slice(name);
    Ok(FcDentryRecord {
        parent_ino,
        ino,
        file_type,
        name_len: name.len() as u8,
        name: buf,
    })
}

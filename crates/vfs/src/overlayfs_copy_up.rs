// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs copy-up mechanics.
//!
//! When a process writes to a file that exists only in a lower (read-only)
//! layer of an overlay mount, overlayfs must first *copy* the file up to the
//! upper (writable) layer before the write can proceed.  This module
//! implements the full copy-up pipeline:
//!
//! 1. **Atomic copy-up** — file data copied via the work directory, then
//!    renamed into the upper layer so the operation is crash-consistent.
//! 2. **Metadata preservation** — permissions, ownership, extended
//!    attributes, and timestamps are reproduced faithfully on the upper copy.
//! 3. **Metacopy** — metadata-only copy-up: only the inode metadata (stat,
//!    xattr) is copied to the upper layer; a `trusted.overlay.metacopy`
//!    xattr marks the entry so reads still fall through to the lower layer
//!    data.  Writing then triggers a full data copy-up.
//! 4. **Opaque directories** — when a directory is renamed or a new
//!    directory with the same name replaces a lower one, the upper directory
//!    is marked opaque via the `trusted.overlay.opaque = "y"` xattr to
//!    suppress lower-layer directory merging.
//! 5. **Redirect** — when a directory is renamed in the upper layer, a
//!    `trusted.overlay.redirect` xattr records the old path so that the
//!    lower layer entry can still be found during lookups.
//!
//! # Relationship to `overlayfs.rs`
//!
//! `overlayfs.rs` owns the merged view and path resolution logic.  This
//! module provides the stateless algorithms and data structures for the
//! copy-up operations that `overlayfs.rs` calls when a write is triggered.
//!
//! # Reference
//!
//! Linux `fs/overlayfs/copy_up.c`, `fs/overlayfs/dir.c`, overlayfs
//! documentation at `Documentation/filesystems/overlayfs.rst`.

use crate::inode::{FileMode, FileType, Inode, InodeNumber};
use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum path length for paths and xattr values.
const MAX_PATH_LEN: usize = 256;

/// Maximum xattr name length.
const MAX_XATTR_NAME: usize = 128;

/// Maximum xattr value length.
const MAX_XATTR_VALUE: usize = 256;

/// Maximum number of xattrs per copy-up entry.
const MAX_XATTRS: usize = 16;

/// Maximum file data that can be held in one copy-up buffer (64 KiB).
const MAX_COPY_DATA: usize = 65536;

/// Maximum number of pending copy-up operations tracked at once.
const MAX_COPY_UP_OPS: usize = 64;

/// Maximum number of redirect entries.
const MAX_REDIRECTS: usize = 32;

/// Maximum number of opaque directory markers.
const MAX_OPAQUES: usize = 32;

// ── Overlayfs xattr keys ──────────────────────────────────────────────────────

/// Xattr that marks a directory as opaque (do not merge with lower).
///
/// Value: `"y"`
pub const XATTR_OPAQUE: &str = "trusted.overlay.opaque";

/// Xattr that records a redirect to the original lower-layer path.
///
/// Value: original path bytes.
pub const XATTR_REDIRECT: &str = "trusted.overlay.redirect";

/// Xattr that marks an upper inode as a metadata-only copy-up.
///
/// Value: SHA-256 digest of lower data (or empty string if not verified).
pub const XATTR_METACOPY: &str = "trusted.overlay.metacopy";

/// Xattr that carries the lower inode's UUID for origin tracking.
///
/// Value: 16 raw bytes (UUID).
pub const XATTR_ORIGIN: &str = "trusted.overlay.origin";

// ── Xattr storage ─────────────────────────────────────────────────────────────

/// A single extended attribute (name + value pair).
#[derive(Debug, Clone, Copy)]
pub struct Xattr {
    /// Attribute name.
    name: [u8; MAX_XATTR_NAME],
    /// Name length.
    name_len: usize,
    /// Attribute value.
    value: [u8; MAX_XATTR_VALUE],
    /// Value length.
    value_len: usize,
}

impl Xattr {
    /// Create a new xattr from string name and byte value.
    pub fn new(name: &str, value: &[u8]) -> Result<Self> {
        let nb = name.as_bytes();
        if nb.len() > MAX_XATTR_NAME || value.len() > MAX_XATTR_VALUE {
            return Err(Error::InvalidArgument);
        }
        let mut na = [0u8; MAX_XATTR_NAME];
        na[..nb.len()].copy_from_slice(nb);
        let mut va = [0u8; MAX_XATTR_VALUE];
        va[..value.len()].copy_from_slice(value);
        Ok(Self {
            name: na,
            name_len: nb.len(),
            value: va,
            value_len: value.len(),
        })
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    /// Check whether the name equals a string slice.
    pub fn name_eq(&self, s: &str) -> bool {
        self.name_bytes() == s.as_bytes()
    }
}

/// A set of extended attributes carried during copy-up.
#[derive(Debug, Clone, Copy)]
pub struct XattrSet {
    attrs: [Option<Xattr>; MAX_XATTRS],
    count: usize,
}

impl XattrSet {
    /// Create an empty xattr set.
    pub const fn new() -> Self {
        const NONE: Option<Xattr> = None;
        Self {
            attrs: [NONE; MAX_XATTRS],
            count: 0,
        }
    }

    /// Add an xattr to the set.
    pub fn insert(&mut self, xattr: Xattr) -> Result<()> {
        if self.count >= MAX_XATTRS {
            return Err(Error::OutOfMemory);
        }
        // Replace existing entry with the same name.
        for slot in self.attrs[..self.count].iter_mut().flatten() {
            if slot.name_bytes() == xattr.name_bytes() {
                *slot = xattr;
                return Ok(());
            }
        }
        self.attrs[self.count] = Some(xattr);
        self.count += 1;
        Ok(())
    }

    /// Remove an xattr by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let pos = self.attrs[..self.count]
            .iter()
            .position(|x| x.as_ref().map(|a| a.name_eq(name)).unwrap_or(false));
        if let Some(p) = pos {
            self.count -= 1;
            self.attrs[p] = self.attrs[self.count];
            self.attrs[self.count] = None;
            true
        } else {
            false
        }
    }

    /// Look up an xattr by name.
    pub fn get(&self, name: &str) -> Option<&Xattr> {
        self.attrs[..self.count]
            .iter()
            .flatten()
            .find(|a| a.name_eq(name))
    }

    /// Return the number of attributes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all attributes (populated slots only).
    pub fn iter(&self) -> impl Iterator<Item = &Xattr> {
        self.attrs[..self.count].iter().flatten()
    }
}

impl Default for XattrSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── Copy-up operation state ───────────────────────────────────────────────────

/// The phase of a copy-up operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyUpPhase {
    /// Initial state: copy-up has not started.
    Pending,
    /// Data has been written to the work directory (staging).
    Staged,
    /// Upper-layer inode created with metadata; data not yet copied.
    MetaOnly,
    /// Data copy complete; entry renamed into the upper layer.
    Completed,
    /// Copy-up failed; the operation was rolled back.
    Failed,
}

/// Kind of copy-up to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyUpKind {
    /// Full copy-up: copy both metadata and data.
    Full,
    /// Metadata-only copy-up: copy inode metadata; defer data copy.
    MetaOnly,
}

/// A pending or completed copy-up operation.
///
/// Copy-up proceeds atomically via the work directory:
/// 1. Write data to `work_dir/.tmp_<ino>`.
/// 2. Set metadata (mode, ownership, xattrs) on the work file.
/// 3. Rename the work file into the upper layer.
#[derive(Debug, Clone)]
pub struct CopyUpOp {
    /// Unique operation ID.
    pub id: u32,
    /// Source inode (in lower layer).
    pub source_ino: InodeNumber,
    /// Source layer index.
    pub source_layer: u32,
    /// Destination inode (in upper layer, assigned after staging).
    pub dest_ino: InodeNumber,
    /// File type being copied.
    pub file_type: FileType,
    /// Permissions to apply to the upper copy.
    pub mode: FileMode,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Kind of copy-up.
    pub kind: CopyUpKind,
    /// Current phase.
    pub phase: CopyUpPhase,
    /// Xattrs to propagate (plus overlay-specific markers added during copy).
    pub xattrs: XattrSet,
    /// Data buffer (used for full copy-up of regular files).
    data: [u8; MAX_COPY_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Whether the destination inode has been allocated.
    pub dest_allocated: bool,
}

impl CopyUpOp {
    /// Create a new pending copy-up operation from a lower-layer inode.
    pub fn new(id: u32, source: &Inode, source_layer: u32, kind: CopyUpKind) -> Self {
        Self {
            id,
            source_ino: source.ino,
            source_layer,
            dest_ino: InodeNumber(0),
            file_type: source.file_type,
            mode: source.mode,
            uid: source.uid,
            gid: source.gid,
            kind,
            phase: CopyUpPhase::Pending,
            xattrs: XattrSet::new(),
            data: [0u8; MAX_COPY_DATA],
            data_len: 0,
            dest_allocated: false,
        }
    }

    /// Stage file data into the internal buffer (simulates writing to workdir).
    ///
    /// For `MetaOnly` copy-up this is a no-op; data is staged later when
    /// a write actually occurs.
    pub fn stage_data(&mut self, src_data: &[u8]) -> Result<()> {
        if src_data.len() > MAX_COPY_DATA {
            return Err(Error::InvalidArgument);
        }
        self.data[..src_data.len()].copy_from_slice(src_data);
        self.data_len = src_data.len();
        self.phase = CopyUpPhase::Staged;
        Ok(())
    }

    /// Apply overlay xattrs (origin, metacopy marker if needed).
    ///
    /// Called after data staging, before the rename into the upper layer.
    pub fn apply_overlay_xattrs(&mut self) -> Result<()> {
        // Always set origin so we can trace back to the lower inode.
        let mut origin_val = [0u8; 16];
        let ino_bytes = self.source_ino.0.to_le_bytes();
        origin_val[..8].copy_from_slice(&ino_bytes);
        let layer_bytes = self.source_layer.to_le_bytes();
        origin_val[8..12].copy_from_slice(&layer_bytes);
        self.xattrs.insert(Xattr::new(XATTR_ORIGIN, &origin_val)?)?;

        if self.kind == CopyUpKind::MetaOnly {
            self.xattrs.insert(Xattr::new(XATTR_METACOPY, b"")?)?;
            self.phase = CopyUpPhase::MetaOnly;
        }
        Ok(())
    }

    /// Complete the copy-up: assign the destination inode number and
    /// transition to `Completed`.
    ///
    /// In a real implementation this step corresponds to the atomic rename
    /// from the work directory into the upper layer directory.
    pub fn complete(&mut self, dest_ino: InodeNumber) -> Result<()> {
        if self.phase != CopyUpPhase::Staged && self.phase != CopyUpPhase::MetaOnly {
            return Err(Error::InvalidArgument);
        }
        self.dest_ino = dest_ino;
        self.dest_allocated = true;
        self.phase = CopyUpPhase::Completed;
        Ok(())
    }

    /// Mark the operation as failed and reset it so it can be retried.
    pub fn fail(&mut self) {
        self.phase = CopyUpPhase::Failed;
        self.data_len = 0;
        self.dest_allocated = false;
    }

    /// Promote a MetaOnly copy-up to a full copy by staging data.
    ///
    /// Called when the first actual data write occurs on a metacopy inode.
    pub fn promote_to_full(&mut self, src_data: &[u8]) -> Result<()> {
        if self.phase != CopyUpPhase::MetaOnly {
            return Err(Error::InvalidArgument);
        }
        self.stage_data(src_data)?;
        self.xattrs.remove(XATTR_METACOPY);
        self.kind = CopyUpKind::Full;
        Ok(())
    }

    /// Return the staged data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Return whether the copy-up is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.phase, CopyUpPhase::Completed | CopyUpPhase::Failed)
    }

    /// Return whether this copy-up inode still requires data copy.
    pub fn needs_data_copy(&self) -> bool {
        self.kind == CopyUpKind::MetaOnly && self.phase == CopyUpPhase::MetaOnly
    }
}

// ── Redirect entry ────────────────────────────────────────────────────────────

/// A redirect entry recording that an upper-layer directory entry has been
/// renamed and its original lower-layer path is stored in an xattr.
///
/// When a directory `d/foo` is renamed to `d/bar`, overlayfs writes a
/// `trusted.overlay.redirect = "/d/foo"` xattr on the upper `bar` entry.
/// Subsequent lookups of the original `foo` name in lower layers can be
/// matched via the redirect chain.
#[derive(Debug, Clone, Copy)]
pub struct RedirectEntry {
    /// The new (current) name in the upper layer.
    new_name: [u8; MAX_PATH_LEN],
    /// Length of the new name.
    new_name_len: usize,
    /// The original lower-layer path stored in the redirect xattr.
    orig_path: [u8; MAX_PATH_LEN],
    /// Length of the original path.
    orig_path_len: usize,
    /// Inode number of the upper-layer entry.
    pub upper_ino: InodeNumber,
    /// Parent inode of the upper-layer entry.
    pub parent_ino: InodeNumber,
}

impl RedirectEntry {
    /// Create a new redirect from an upper inode's new name to its original path.
    pub fn new(
        new_name: &str,
        orig_path: &str,
        upper_ino: InodeNumber,
        parent_ino: InodeNumber,
    ) -> Result<Self> {
        let nn = new_name.as_bytes();
        let op = orig_path.as_bytes();
        if nn.len() > MAX_PATH_LEN || op.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut na = [0u8; MAX_PATH_LEN];
        na[..nn.len()].copy_from_slice(nn);
        let mut oa = [0u8; MAX_PATH_LEN];
        oa[..op.len()].copy_from_slice(op);
        Ok(Self {
            new_name: na,
            new_name_len: nn.len(),
            orig_path: oa,
            orig_path_len: op.len(),
            upper_ino,
            parent_ino,
        })
    }

    /// Return the new name as a byte slice.
    pub fn new_name_bytes(&self) -> &[u8] {
        &self.new_name[..self.new_name_len]
    }

    /// Return the original path as a byte slice.
    pub fn orig_path_bytes(&self) -> &[u8] {
        &self.orig_path[..self.orig_path_len]
    }
}

// ── Opaque directory marker ───────────────────────────────────────────────────

/// Marks an upper-layer directory as opaque so that lower directories with
/// the same name are not merged into its listing.
///
/// A directory becomes opaque when it is newly created in the upper layer
/// (via `mkdir`) or when its parent is copied up and the directory itself
/// is renamed.
#[derive(Debug, Clone, Copy)]
pub struct OpaqueMarker {
    /// Inode number of the opaque upper-layer directory.
    pub ino: InodeNumber,
    /// Parent inode.
    pub parent_ino: InodeNumber,
    /// Directory name.
    name: [u8; MAX_PATH_LEN],
    /// Name length.
    name_len: usize,
}

impl OpaqueMarker {
    /// Create a new opaque marker for the given directory.
    pub fn new(name: &str, ino: InodeNumber, parent_ino: InodeNumber) -> Result<Self> {
        let nb = name.as_bytes();
        if nb.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut na = [0u8; MAX_PATH_LEN];
        na[..nb.len()].copy_from_slice(nb);
        Ok(Self {
            ino,
            parent_ino,
            name: na,
            name_len: nb.len(),
        })
    }

    /// Return the directory name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── Copy-up context ───────────────────────────────────────────────────────────

/// The copy-up context maintains the queue of pending operations, redirect
/// entries, and opaque directory markers for a single overlay mount.
///
/// The typical call sequence for a write-triggered copy-up is:
/// 1. [`CopyUpContext::enqueue`] — create a [`CopyUpOp`] and add it to the queue.
/// 2. [`CopyUpContext::stage`] — write lower-layer data into the work buffer.
/// 3. [`CopyUpContext::finalize`] — apply overlay xattrs and mark as staged.
/// 4. [`CopyUpContext::commit`] — assign the upper inode and mark as completed.
/// 5. The caller updates the upper layer's directory entry.
pub struct CopyUpContext {
    /// Pending / in-progress / completed operations.
    ops: [Option<CopyUpOp>; MAX_COPY_UP_OPS],
    /// Number of allocated operation slots.
    op_count: usize,
    /// Next operation ID.
    next_id: u32,
    /// Redirect entries.
    redirects: [Option<RedirectEntry>; MAX_REDIRECTS],
    /// Number of redirect entries.
    redirect_count: usize,
    /// Opaque directory markers.
    opaques: [Option<OpaqueMarker>; MAX_OPAQUES],
    /// Number of opaque markers.
    opaque_count: usize,
}

impl CopyUpContext {
    /// Create an empty copy-up context.
    pub const fn new() -> Self {
        const NONE_OP: Option<CopyUpOp> = None;
        const NONE_RE: Option<RedirectEntry> = None;
        const NONE_OM: Option<OpaqueMarker> = None;
        Self {
            ops: [NONE_OP; MAX_COPY_UP_OPS],
            op_count: 0,
            next_id: 1,
            redirects: [NONE_RE; MAX_REDIRECTS],
            redirect_count: 0,
            opaques: [NONE_OM; MAX_OPAQUES],
            opaque_count: 0,
        }
    }

    // ── Copy-up operation management ──────────────────────────────────────────

    /// Enqueue a new copy-up operation for a lower-layer inode.
    ///
    /// Returns the operation ID on success.
    pub fn enqueue(&mut self, source: &Inode, source_layer: u32, kind: CopyUpKind) -> Result<u32> {
        if self.op_count >= MAX_COPY_UP_OPS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.ops[self.op_count] = Some(CopyUpOp::new(id, source, source_layer, kind));
        self.op_count += 1;
        Ok(id)
    }

    /// Stage data for a pending copy-up operation.
    ///
    /// `op_id` identifies the operation; `data` is the file content from
    /// the lower layer.
    pub fn stage(&mut self, op_id: u32, data: &[u8]) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        if op.phase != CopyUpPhase::Pending {
            return Err(Error::InvalidArgument);
        }
        op.stage_data(data)
    }

    /// Apply overlay xattrs and advance to staged/metacopy state.
    ///
    /// Should be called after [`stage`](Self::stage) and before
    /// [`commit`](Self::commit).
    pub fn finalize(&mut self, op_id: u32) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        op.apply_overlay_xattrs()
    }

    /// Add extra xattrs to be copied from the lower inode.
    pub fn add_xattrs(&mut self, op_id: u32, xattrs: &[Xattr]) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        for xa in xattrs {
            op.xattrs.insert(*xa)?;
        }
        Ok(())
    }

    /// Commit the copy-up: assign the upper-layer inode number.
    ///
    /// Transitions the operation to [`CopyUpPhase::Completed`].
    pub fn commit(&mut self, op_id: u32, dest_ino: InodeNumber) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        op.complete(dest_ino)
    }

    /// Promote a MetaOnly operation to a full copy-up when data is needed.
    pub fn promote_metacopy(&mut self, op_id: u32, lower_data: &[u8]) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        op.promote_to_full(lower_data)
    }

    /// Abort a copy-up operation on error.
    pub fn abort(&mut self, op_id: u32) -> Result<()> {
        let op = self.find_op_mut(op_id)?;
        op.fail();
        Ok(())
    }

    /// Retrieve a completed copy-up operation result.
    ///
    /// Returns `None` if the operation is not yet complete or was not found.
    pub fn result(&self, op_id: u32) -> Option<&CopyUpOp> {
        self.ops[..self.op_count]
            .iter()
            .flatten()
            .find(|op| op.id == op_id && op.phase == CopyUpPhase::Completed)
    }

    /// Look up the destination inode for a source inode that has been
    /// successfully copied up.
    ///
    /// Returns `None` if no completed copy-up exists for the source.
    pub fn find_upper_ino(&self, source_ino: InodeNumber) -> Option<InodeNumber> {
        self.ops[..self.op_count]
            .iter()
            .flatten()
            .find(|op| op.source_ino == source_ino && op.phase == CopyUpPhase::Completed)
            .map(|op| op.dest_ino)
    }

    /// Return whether a source inode has been copied up (full or metacopy).
    pub fn is_copied_up(&self, source_ino: InodeNumber) -> bool {
        self.ops[..self.op_count].iter().flatten().any(|op| {
            op.source_ino == source_ino
                && matches!(op.phase, CopyUpPhase::Completed | CopyUpPhase::MetaOnly)
        })
    }

    /// Return whether a source inode is a metacopy (metadata only, no data yet).
    pub fn is_metacopy(&self, source_ino: InodeNumber) -> bool {
        self.ops[..self.op_count]
            .iter()
            .flatten()
            .any(|op| op.source_ino == source_ino && op.phase == CopyUpPhase::MetaOnly)
    }

    /// Evict a completed or failed operation to free a slot.
    pub fn evict(&mut self, op_id: u32) -> Result<()> {
        let pos = self.ops[..self.op_count]
            .iter()
            .position(|x| x.as_ref().map(|o| o.id == op_id).unwrap_or(false))
            .ok_or(Error::NotFound)?;
        self.op_count -= 1;
        self.ops[pos] = self.ops[self.op_count].take();
        Ok(())
    }

    // ── Redirect management ───────────────────────────────────────────────────

    /// Register a redirect: upper inode `upper_ino` was renamed from
    /// `orig_path` to `new_name` under `parent_ino`.
    pub fn add_redirect(
        &mut self,
        new_name: &str,
        orig_path: &str,
        upper_ino: InodeNumber,
        parent_ino: InodeNumber,
    ) -> Result<()> {
        if self.redirect_count >= MAX_REDIRECTS {
            return Err(Error::OutOfMemory);
        }
        let entry = RedirectEntry::new(new_name, orig_path, upper_ino, parent_ino)?;
        self.redirects[self.redirect_count] = Some(entry);
        self.redirect_count += 1;
        Ok(())
    }

    /// Look up the redirect entry for a given upper inode.
    pub fn find_redirect(&self, upper_ino: InodeNumber) -> Option<&RedirectEntry> {
        self.redirects[..self.redirect_count]
            .iter()
            .flatten()
            .find(|r| r.upper_ino == upper_ino)
    }

    /// Resolve an original lower-layer path to its current upper-layer inode.
    ///
    /// Used during path resolution to follow the redirect chain.
    pub fn resolve_redirect(&self, orig_path: &str) -> Option<InodeNumber> {
        let bytes = orig_path.as_bytes();
        self.redirects[..self.redirect_count]
            .iter()
            .flatten()
            .find(|r| r.orig_path_bytes() == bytes)
            .map(|r| r.upper_ino)
    }

    /// Remove a redirect entry for a given upper inode.
    pub fn remove_redirect(&mut self, upper_ino: InodeNumber) -> bool {
        let pos = self.redirects[..self.redirect_count].iter().position(|x| {
            x.as_ref()
                .map(|r| r.upper_ino == upper_ino)
                .unwrap_or(false)
        });
        if let Some(p) = pos {
            self.redirect_count -= 1;
            self.redirects[p] = self.redirects[self.redirect_count].take();
            true
        } else {
            false
        }
    }

    // ── Opaque directory management ───────────────────────────────────────────

    /// Mark a directory as opaque (suppress lower-layer merge).
    ///
    /// A directory is marked opaque when it is:
    /// - Newly `mkdir`-ed in the upper layer over an existing lower directory.
    /// - Renamed such that it no longer corresponds to its lower-layer
    ///   counterpart by name.
    pub fn mark_opaque(
        &mut self,
        name: &str,
        ino: InodeNumber,
        parent_ino: InodeNumber,
    ) -> Result<()> {
        if self.opaque_count >= MAX_OPAQUES {
            return Err(Error::OutOfMemory);
        }
        // Avoid duplicates.
        for slot in self.opaques[..self.opaque_count].iter().flatten() {
            if slot.ino == ino {
                return Ok(());
            }
        }
        let marker = OpaqueMarker::new(name, ino, parent_ino)?;
        self.opaques[self.opaque_count] = Some(marker);
        self.opaque_count += 1;
        Ok(())
    }

    /// Check whether an upper-layer directory inode is opaque.
    pub fn is_opaque(&self, ino: InodeNumber) -> bool {
        self.opaques[..self.opaque_count]
            .iter()
            .flatten()
            .any(|m| m.ino == ino)
    }

    /// Remove an opaque marker (e.g., on directory removal).
    pub fn unmark_opaque(&mut self, ino: InodeNumber) -> bool {
        let pos = self.opaques[..self.opaque_count]
            .iter()
            .position(|x| x.as_ref().map(|m| m.ino == ino).unwrap_or(false));
        if let Some(p) = pos {
            self.opaque_count -= 1;
            self.opaques[p] = self.opaques[self.opaque_count].take();
            true
        } else {
            false
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Return (pending_ops, redirect_count, opaque_count).
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.op_count, self.redirect_count, self.opaque_count)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn find_op_mut(&mut self, op_id: u32) -> Result<&mut CopyUpOp> {
        let count = self.op_count;
        self.ops[..count]
            .iter_mut()
            .flatten()
            .find(|op| op.id == op_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for CopyUpContext {
    fn default() -> Self {
        Self::new()
    }
}

// ── High-level copy-up driver ─────────────────────────────────────────────────

/// High-level helper that orchestrates a full copy-up of a single file inode.
///
/// This function represents the combined work that Linux's
/// `ovl_copy_up_one()` performs:
/// 1. Enqueue the operation.
/// 2. Load lower-layer data (caller supplies via `lower_data`).
/// 3. Copy lower xattrs (caller supplies via `lower_xattrs`).
/// 4. Apply overlay xattrs.
/// 5. Commit with the new upper-layer inode number.
///
/// On success the caller should update the upper directory entry to point
/// to `dest_ino`.
pub fn copy_up_file(
    ctx: &mut CopyUpContext,
    source: &Inode,
    source_layer: u32,
    lower_data: &[u8],
    lower_xattrs: &[Xattr],
    dest_ino: InodeNumber,
) -> Result<u32> {
    let op_id = ctx.enqueue(source, source_layer, CopyUpKind::Full)?;
    ctx.stage(op_id, lower_data)?;
    ctx.add_xattrs(op_id, lower_xattrs)?;
    ctx.finalize(op_id)?;
    ctx.commit(op_id, dest_ino)?;
    Ok(op_id)
}

/// High-level helper that performs a metadata-only copy-up.
///
/// Equivalent to `ovl_copy_up_flags()` with `OVL_COPY_UP_METADATA_ONLY`.
/// The data remains in the lower layer; reads transparently fall through.
pub fn copy_up_metadata(
    ctx: &mut CopyUpContext,
    source: &Inode,
    source_layer: u32,
    lower_xattrs: &[Xattr],
    dest_ino: InodeNumber,
) -> Result<u32> {
    let op_id = ctx.enqueue(source, source_layer, CopyUpKind::MetaOnly)?;
    // Stage empty data for MetaOnly (no data written to work dir).
    ctx.stage(op_id, &[])?;
    ctx.add_xattrs(op_id, lower_xattrs)?;
    ctx.finalize(op_id)?;
    ctx.commit(op_id, dest_ino)?;
    Ok(op_id)
}

/// Perform a directory copy-up with opaque marking.
///
/// Used when a new upper directory hides a lower directory of the same name.
/// The upper directory is marked opaque, preventing lower entries from
/// bleeding into the merged view.
pub fn copy_up_opaque_dir(
    ctx: &mut CopyUpContext,
    source: &Inode,
    source_layer: u32,
    lower_xattrs: &[Xattr],
    dest_ino: InodeNumber,
    parent_ino: InodeNumber,
    name: &str,
) -> Result<u32> {
    let op_id = copy_up_metadata(ctx, source, source_layer, lower_xattrs, dest_ino)?;

    // Mark the upper directory as opaque.
    ctx.mark_opaque(name, dest_ino, parent_ino)?;

    // Also inject the opaque xattr into the operation for persistence.
    let opaque_xattr = Xattr::new(XATTR_OPAQUE, b"y")?;
    ctx.add_xattrs(op_id, &[opaque_xattr])?;

    Ok(op_id)
}

/// Perform a directory rename copy-up with redirect.
///
/// Used when `rename(old, new)` is called on a directory that originated
/// in a lower layer.  The upper copy gets a redirect xattr pointing to the
/// original lower-layer path so lookups via the old name still work.
pub fn copy_up_renamed_dir(
    ctx: &mut CopyUpContext,
    source: &Inode,
    source_layer: u32,
    lower_xattrs: &[Xattr],
    dest_ino: InodeNumber,
    parent_ino: InodeNumber,
    new_name: &str,
    orig_path: &str,
) -> Result<u32> {
    let op_id = copy_up_metadata(ctx, source, source_layer, lower_xattrs, dest_ino)?;

    // Record the redirect.
    ctx.add_redirect(new_name, orig_path, dest_ino, parent_ino)?;

    // Inject the redirect xattr.
    let orig_bytes = orig_path.as_bytes();
    if orig_bytes.len() <= MAX_XATTR_VALUE {
        let redirect_xattr = Xattr::new(XATTR_REDIRECT, orig_bytes)?;
        ctx.add_xattrs(op_id, &[redirect_xattr])?;
    }

    Ok(op_id)
}

// ── Copy-up policy helpers ────────────────────────────────────────────────────

/// Determine whether a copy-up is required before the given access.
///
/// - Write access to a lower-layer inode always triggers copy-up.
/// - `O_TRUNC` opens trigger copy-up even with data discarded.
/// - Read-only access never triggers copy-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    /// Read-only access (no copy-up needed).
    Read,
    /// Write access (full or metacopy copy-up needed).
    Write,
    /// Truncate (treated as write).
    Truncate,
    /// Metadata-only update (setattr, setxattr — metacopy sufficient).
    MetaUpdate,
}

/// Decide the [`CopyUpKind`] required for a given access on a lower inode.
///
/// Returns `None` if no copy-up is needed (read-only access).
pub fn required_copy_up(access: AccessKind) -> Option<CopyUpKind> {
    match access {
        AccessKind::Read => None,
        AccessKind::Write | AccessKind::Truncate => Some(CopyUpKind::Full),
        AccessKind::MetaUpdate => Some(CopyUpKind::MetaOnly),
    }
}

// ── Work directory path helpers ───────────────────────────────────────────────

/// A temporary work-directory path for staging a copy-up.
///
/// Linux uses `<workdir>/.tmp_<ino>` as the staging name.  We replicate
/// that convention here.
#[derive(Debug, Clone, Copy)]
pub struct WorkPath {
    buf: [u8; MAX_PATH_LEN],
    len: usize,
}

impl WorkPath {
    /// Build a staging path from a work directory root and an inode number.
    ///
    /// Result: `<work_dir>/.tmp_<ino>` (e.g., `/work/.tmp_42`).
    pub fn staging(work_dir: &str, ino: InodeNumber) -> Result<Self> {
        let wd = work_dir.as_bytes();
        // ".tmp_" prefix + up to 20 decimal digits.
        const SUFFIX_MAX: usize = 25;
        if wd.len() + 1 + SUFFIX_MAX > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        let mut pos = 0;
        buf[pos..pos + wd.len()].copy_from_slice(wd);
        pos += wd.len();
        buf[pos] = b'/';
        pos += 1;

        let suffix = b".tmp_";
        buf[pos..pos + suffix.len()].copy_from_slice(suffix);
        pos += suffix.len();

        pos += write_u64_decimal(&mut buf[pos..], ino.0)?;
        Ok(Self { buf, len: pos })
    }

    /// Return the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Write a `u64` as ASCII decimal digits into `buf`.
///
/// Returns the number of bytes written.
fn write_u64_decimal(buf: &mut [u8], mut n: u64) -> Result<usize> {
    let mut tmp = [0u8; 20];
    let mut d = 0usize;
    if n == 0 {
        tmp[0] = b'0';
        d = 1;
    } else {
        while n > 0 {
            tmp[d] = b'0' + (n % 10) as u8;
            n /= 10;
            d += 1;
        }
        tmp[..d].reverse();
    }
    if d > buf.len() {
        return Err(Error::InvalidArgument);
    }
    buf[..d].copy_from_slice(&tmp[..d]);
    Ok(d)
}

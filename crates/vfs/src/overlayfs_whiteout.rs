// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OverlayFS whiteout and opaque-directory handling.
//!
//! When a file or directory from a lower (read-only) layer is deleted in an
//! overlayfs mount, the deletion cannot be recorded on the lower layer.
//! Instead, a *whiteout* entry is created in the upper (writable) layer to
//! mask the lower entry.
//!
//! Two kinds of whiteout markers exist:
//!
//! 1. **File whiteout** — a character device with device number 0:0 placed at
//!    the same path as the deleted file.  Recognised by overlayfs via the
//!    `WHITEOUT_DEV` attribute.
//!
//! 2. **Opaque directory** — a directory in the upper layer decorated with
//!    the `trusted.overlay.opaque = "y"` extended attribute.  An opaque
//!    directory hides all content from lower layers; lookups never fall through
//!    to lower layers.
//!
//! Additionally, when a file/directory from a lower layer is *renamed* into a
//! directory that exists in both layers, a *redirect* xattr is written on the
//! upper entry (`trusted.overlay.redirect = "<original-lower-path>"`).
//!
//! # Linux reference
//! `fs/overlayfs/whiteout.c` — `ovl_whiteout()`, `ovl_do_whiteout()`
//! `fs/overlayfs/dir.c` — `ovl_create()`, `ovl_rename()`, opaque creation
//! `Documentation/filesystems/overlayfs.rst` — whiteout / opaque description
//!
//! # POSIX reference
//! POSIX.1-2024 `unlink(2)`, `rename(2)` — deletion and rename semantics

use crate::inode::{FileMode, FileType, Inode, InodeNumber};
use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum path / name length.
const MAX_NAME_LEN: usize = 255;
/// Maximum path length.
const MAX_PATH_LEN: usize = 4096;
/// Maximum number of whiteout entries in the upper layer table.
const MAX_WHITEOUTS: usize = 512;
/// Maximum number of opaque directory entries.
const MAX_OPAQUES: usize = 256;
/// Maximum number of redirect entries.
const MAX_REDIRECTS: usize = 256;

// ── Xattr key strings ─────────────────────────────────────────────────────────

/// Xattr key marking a directory as opaque.
pub const OVL_XATTR_OPAQUE: &[u8] = b"trusted.overlay.opaque";
/// Value for the opaque xattr.
pub const OVL_XATTR_OPAQUE_VAL: &[u8] = b"y";

/// Xattr key carrying a redirect path for renamed entries.
pub const OVL_XATTR_REDIRECT: &[u8] = b"trusted.overlay.redirect";

/// Xattr key carrying the origin inode info (for NFS-exportable overlays).
pub const OVL_XATTR_ORIGIN: &[u8] = b"trusted.overlay.origin";

/// Xattr key marking upper entries as impure (contain whiteouts in subtree).
pub const OVL_XATTR_IMPURE: &[u8] = b"trusted.overlay.impure";

// ── Whiteout device number ────────────────────────────────────────────────────

/// Character-device major number for whiteout files (always 0).
pub const WHITEOUT_MAJOR: u32 = 0;
/// Character-device minor number for whiteout files (always 0).
pub const WHITEOUT_MINOR: u32 = 0;
/// Combined device number for whiteout files.
pub const WHITEOUT_DEV: u64 = 0;

// ── Name buffer ───────────────────────────────────────────────────────────────

/// Fixed-size name buffer.
#[derive(Debug, Clone, Copy)]
pub struct Name {
    buf: [u8; MAX_NAME_LEN],
    len: usize,
}

impl Name {
    /// Construct from a byte slice.  Truncates silently if too long.
    pub fn from_bytes(src: &[u8]) -> Self {
        let len = src.len().min(MAX_NAME_LEN);
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..len].copy_from_slice(&src[..len]);
        Self { buf, len }
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns `true` if the names are equal.
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

// ── Path buffer ───────────────────────────────────────────────────────────────

/// Fixed-size path buffer.
#[derive(Debug, Clone, Copy)]
pub struct PathBuf {
    buf: [u8; MAX_PATH_LEN],
    len: usize,
}

impl PathBuf {
    /// Construct from a byte slice.  Truncates silently if too long.
    pub fn from_bytes(src: &[u8]) -> Self {
        let len = src.len().min(MAX_PATH_LEN);
        let mut buf = [0u8; MAX_PATH_LEN];
        buf[..len].copy_from_slice(&src[..len]);
        Self { buf, len }
    }

    /// Returns the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns `true` if the paths are equal.
    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}

impl Default for PathBuf {
    fn default() -> Self {
        Self {
            buf: [0u8; MAX_PATH_LEN],
            len: 0,
        }
    }
}

// ── Whiteout entry ────────────────────────────────────────────────────────────

/// A whiteout entry in the upper layer table.
///
/// Records that a name at a given directory path has been deleted from the
/// merged view.  Any lookup that matches a whiteout should return `NotFound`
/// rather than falling through to lower layers.
#[derive(Debug, Clone)]
pub struct WhiteoutEntry {
    /// Directory path (absolute, within the upper layer root).
    pub dir_path: PathBuf,
    /// Filename that has been whited out.
    pub name: Name,
    /// Inode number of the whiteout character device in the upper layer.
    pub upper_ino: InodeNumber,
    /// Whether this whiteout has been removed (e.g., a new file was created
    /// at the same path).
    pub removed: bool,
}

impl WhiteoutEntry {
    /// Construct a new whiteout entry.
    pub fn new(dir_path: &[u8], name: &[u8], upper_ino: InodeNumber) -> Self {
        Self {
            dir_path: PathBuf::from_bytes(dir_path),
            name: Name::from_bytes(name),
            upper_ino,
            removed: false,
        }
    }
}

// ── Opaque directory entry ────────────────────────────────────────────────────

/// An opaque directory registration.
///
/// When a directory is made opaque, its `trusted.overlay.opaque = "y"` xattr
/// is set and it is registered here so lookups within it never consult lower
/// layers.
#[derive(Debug, Clone)]
pub struct OpaqueDir {
    /// Absolute path of the opaque directory (within the upper layer root).
    pub path: PathBuf,
    /// Inode number of the opaque directory in the upper layer.
    pub upper_ino: InodeNumber,
}

impl OpaqueDir {
    /// Construct a new opaque directory entry.
    pub fn new(path: &[u8], upper_ino: InodeNumber) -> Self {
        Self {
            path: PathBuf::from_bytes(path),
            upper_ino,
        }
    }
}

// ── Redirect entry ────────────────────────────────────────────────────────────

/// A redirect entry for a renamed file/directory.
///
/// When an entry is renamed across directories (and the entry existed in a
/// lower layer), a `trusted.overlay.redirect` xattr is written pointing at
/// the original lower-layer path.  This allows overlayfs to locate the
/// copy-up source on future lookups.
#[derive(Debug, Clone)]
pub struct RedirectEntry {
    /// Current path of the entry in the upper layer.
    pub upper_path: PathBuf,
    /// Original path in the lower layer.
    pub lower_path: PathBuf,
    /// Inode number in the upper layer.
    pub upper_ino: InodeNumber,
}

impl RedirectEntry {
    /// Construct a new redirect entry.
    pub fn new(upper_path: &[u8], lower_path: &[u8], upper_ino: InodeNumber) -> Self {
        Self {
            upper_path: PathBuf::from_bytes(upper_path),
            lower_path: PathBuf::from_bytes(lower_path),
            upper_ino,
        }
    }
}

// ── Whiteout table ────────────────────────────────────────────────────────────

/// The OverlayFS whiteout / opaque / redirect table for a single overlay mount.
pub struct OverlayWhiteoutTable {
    /// Whiteout entries.
    whiteouts: [Option<WhiteoutEntry>; MAX_WHITEOUTS],
    whiteout_count: usize,
    /// Opaque directory entries.
    opaques: [Option<OpaqueDir>; MAX_OPAQUES],
    opaque_count: usize,
    /// Redirect entries.
    redirects: [Option<RedirectEntry>; MAX_REDIRECTS],
    redirect_count: usize,
    /// Next inode number to assign for whiteout character devices.
    next_ino: u64,
}

impl OverlayWhiteoutTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            whiteouts: [const { None }; MAX_WHITEOUTS],
            whiteout_count: 0,
            opaques: [const { None }; MAX_OPAQUES],
            opaque_count: 0,
            redirects: [const { None }; MAX_REDIRECTS],
            redirect_count: 0,
            next_ino: 1,
        }
    }

    // ── Whiteout operations ───────────────────────────────────────────────────

    /// Create a whiteout for `name` inside `dir_path`.
    ///
    /// Allocates a virtual inode number for the whiteout device node and
    /// records the entry.  Returns the inode number of the whiteout.
    pub fn create_whiteout(&mut self, dir_path: &[u8], name: &[u8]) -> Result<InodeNumber> {
        // Ensure no duplicate whiteout exists for this path/name.
        if self.find_whiteout(dir_path, name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.whiteout_count >= MAX_WHITEOUTS {
            return Err(Error::OutOfMemory);
        }
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;
        let entry = WhiteoutEntry::new(dir_path, name, ino);
        let slot = self
            .whiteouts
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(entry);
        self.whiteout_count += 1;
        Ok(ino)
    }

    /// Remove a whiteout (e.g., when a new file is created at the same path).
    ///
    /// Returns `NotFound` if no matching whiteout exists.
    pub fn remove_whiteout(&mut self, dir_path: &[u8], name: &[u8]) -> Result<()> {
        for slot in &mut self.whiteouts {
            if let Some(wo) = slot {
                if !wo.removed && wo.dir_path.eq_bytes(dir_path) && wo.name.eq_bytes(name) {
                    wo.removed = true;
                    self.whiteout_count = self.whiteout_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Check whether `name` inside `dir_path` is whited out.
    ///
    /// Returns `true` if a non-removed whiteout entry matches.
    pub fn is_whiteout(&self, dir_path: &[u8], name: &[u8]) -> bool {
        self.find_whiteout(dir_path, name).is_some()
    }

    fn find_whiteout(&self, dir_path: &[u8], name: &[u8]) -> Option<&WhiteoutEntry> {
        self.whiteouts
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|wo| !wo.removed && wo.dir_path.eq_bytes(dir_path) && wo.name.eq_bytes(name))
    }

    /// Check whether a VFS inode is a whiteout character device.
    ///
    /// An inode is a whiteout if it is a character device with size 0 and no
    /// link permissions (mode `0o020_000`).
    pub fn is_whiteout_inode(inode: &Inode) -> bool {
        inode.file_type == FileType::CharDevice && inode.mode.0 == 0o020_000 && inode.size == 0
    }

    // ── Opaque directory operations ───────────────────────────────────────────

    /// Mark the directory at `path` as opaque.
    ///
    /// Returns `AlreadyExists` if the directory is already opaque.
    pub fn make_opaque(&mut self, path: &[u8], upper_ino: InodeNumber) -> Result<()> {
        if self.is_opaque(path) {
            return Err(Error::AlreadyExists);
        }
        if self.opaque_count >= MAX_OPAQUES {
            return Err(Error::OutOfMemory);
        }
        let entry = OpaqueDir::new(path, upper_ino);
        let slot = self
            .opaques
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(entry);
        self.opaque_count += 1;
        Ok(())
    }

    /// Remove the opaque mark from a directory.
    ///
    /// Returns `NotFound` if the directory was not opaque.
    pub fn clear_opaque(&mut self, path: &[u8]) -> Result<()> {
        for slot in &mut self.opaques {
            if let Some(od) = slot {
                if od.path.eq_bytes(path) {
                    *slot = None;
                    self.opaque_count = self.opaque_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns `true` if the directory at `path` is opaque.
    pub fn is_opaque(&self, path: &[u8]) -> bool {
        self.opaques
            .iter()
            .filter_map(|s| s.as_ref())
            .any(|od| od.path.eq_bytes(path))
    }

    /// Check whether a lookup inside `dir_path` should consult lower layers.
    ///
    /// Returns `false` (do not fall through) if `dir_path` or any parent
    /// path component is opaque.
    pub fn should_fallthrough(&self, dir_path: &[u8]) -> bool {
        // Check the directory itself.
        if self.is_opaque(dir_path) {
            return false;
        }
        // Check parent components.  Walk up the path.
        let mut path = dir_path;
        loop {
            // Find the last '/'.
            let slash_pos = path.iter().rposition(|&b| b == b'/');
            match slash_pos {
                Some(0) | None => break,
                Some(pos) => {
                    path = &path[..pos];
                    if self.is_opaque(path) {
                        return false;
                    }
                }
            }
        }
        true
    }

    // ── Redirect operations ───────────────────────────────────────────────────

    /// Record a redirect from `upper_path` to `lower_path`.
    ///
    /// This is called when an entry from a lower layer is renamed in the
    /// upper layer.
    pub fn add_redirect(
        &mut self,
        upper_path: &[u8],
        lower_path: &[u8],
        upper_ino: InodeNumber,
    ) -> Result<()> {
        if self.redirect_count >= MAX_REDIRECTS {
            return Err(Error::OutOfMemory);
        }
        // Update existing redirect if one exists for this upper path.
        for slot in &mut self.redirects {
            if let Some(rd) = slot {
                if rd.upper_path.eq_bytes(upper_path) {
                    rd.lower_path = PathBuf::from_bytes(lower_path);
                    return Ok(());
                }
            }
        }
        let entry = RedirectEntry::new(upper_path, lower_path, upper_ino);
        let slot = self
            .redirects
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(entry);
        self.redirect_count += 1;
        Ok(())
    }

    /// Remove the redirect for `upper_path`.
    pub fn remove_redirect(&mut self, upper_path: &[u8]) -> Result<()> {
        for slot in &mut self.redirects {
            if let Some(rd) = slot {
                if rd.upper_path.eq_bytes(upper_path) {
                    *slot = None;
                    self.redirect_count = self.redirect_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up the lower-layer path for an upper-layer path.
    ///
    /// Returns `None` if no redirect is registered for `upper_path`.
    pub fn find_redirect(&self, upper_path: &[u8]) -> Option<&[u8]> {
        self.redirects
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|rd| rd.upper_path.eq_bytes(upper_path))
            .map(|rd| rd.lower_path.as_bytes())
    }

    // ── Lookup with whiteout / opaque awareness ───────────────────────────────

    /// Perform a whiteout-aware lookup for `name` inside `dir_path`.
    ///
    /// Returns the `LookupResult` indicating whether the entry is visible,
    /// whited out, or absent.
    pub fn lookup(&self, dir_path: &[u8], name: &[u8]) -> LookupResult {
        if self.is_whiteout(dir_path, name) {
            return LookupResult::WhitedOut;
        }
        if !self.should_fallthrough(dir_path) {
            return LookupResult::OpaqueBarrier;
        }
        LookupResult::FallThrough
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Number of active (non-removed) whiteout entries.
    pub fn whiteout_count(&self) -> usize {
        self.whiteout_count
    }

    /// Number of opaque directories.
    pub fn opaque_count(&self) -> usize {
        self.opaque_count
    }

    /// Number of redirect entries.
    pub fn redirect_count(&self) -> usize {
        self.redirect_count
    }
}

// ── Lookup result ─────────────────────────────────────────────────────────────

/// Result of a whiteout-aware lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    /// The entry is whited out; return `NotFound` to the caller.
    WhitedOut,
    /// The directory is opaque; do not consult lower layers.
    OpaqueBarrier,
    /// No whiteout or opaque barrier; fall through to lower layers.
    FallThrough,
}

// ── Xattr helpers ─────────────────────────────────────────────────────────────

/// Build the xattr bytes for `trusted.overlay.opaque = "y"`.
pub fn opaque_xattr_value() -> &'static [u8] {
    OVL_XATTR_OPAQUE_VAL
}

/// Check whether the given xattr key/value pair marks a directory as opaque.
pub fn is_opaque_xattr(key: &[u8], value: &[u8]) -> bool {
    key == OVL_XATTR_OPAQUE && value == OVL_XATTR_OPAQUE_VAL
}

/// Build the xattr bytes for `trusted.overlay.redirect = <path>`.
///
/// Copies `redirect_path` into `out` and returns the number of bytes written.
pub fn redirect_xattr_value(redirect_path: &[u8], out: &mut [u8]) -> usize {
    let len = redirect_path.len().min(out.len());
    out[..len].copy_from_slice(&redirect_path[..len]);
    len
}

// ── Whiteout inode factory ────────────────────────────────────────────────────

/// Create a minimal whiteout `Inode` (char-device, mode `c---------`).
pub fn make_whiteout_inode(ino: InodeNumber) -> Inode {
    Inode::new(ino, FileType::CharDevice, FileMode(0o020_000))
}

// ── Impure directory marking ──────────────────────────────────────────────────

/// Returns `true` if the xattr key/value pair marks a directory as "impure".
///
/// An impure directory is one whose subtree contains at least one whiteout or
/// opaque subdirectory.  The impure flag is used by `readdir` to decide
/// whether to scan the subtree for hidden entries.
pub fn is_impure_xattr(key: &[u8], value: &[u8]) -> bool {
    key == OVL_XATTR_IMPURE && value == b"y"
}

/// Returns the xattr key for impure marking.
pub fn impure_xattr_key() -> &'static [u8] {
    OVL_XATTR_IMPURE
}

// ── Directory merge helpers ───────────────────────────────────────────────────

/// Merge the names from `upper_names` and `lower_names`, filtering out entries
/// that are whited out in `dir_path`.
///
/// Fills `out` with the merged name pointers and returns the count.
/// `out` must have enough capacity; excess entries are silently dropped.
pub fn merge_readdir<'a>(
    table: &OverlayWhiteoutTable,
    dir_path: &[u8],
    upper_names: &[&'a [u8]],
    lower_names: &[&'a [u8]],
    out: &mut [&'a [u8]],
) -> usize {
    let mut pos = 0usize;
    // Add upper names (they always win).
    for &name in upper_names {
        if pos >= out.len() {
            break;
        }
        out[pos] = name;
        pos += 1;
    }
    // Add lower names not already in upper and not whited out.
    'lower: for &name in lower_names {
        if pos >= out.len() {
            break;
        }
        // Skip if whited out.
        if table.is_whiteout(dir_path, name) {
            continue 'lower;
        }
        // Skip if already present from upper layer.
        for &existing in &out[..pos] {
            if existing == name {
                continue 'lower;
            }
        }
        out[pos] = name;
        pos += 1;
    }
    pos
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs redirect-dir feature.
//!
//! When a directory in the upper layer is renamed, overlayfs needs a
//! way to track the original path of each directory across renames.
//! The redirect-dir feature stores a `trusted.overlay.redirect` xattr
//! on upper-layer directories that points to their lower-layer origin.
//!
//! # How redirect works
//!
//! ```text
//! lower/  foo/bar/      ← original directory tree
//! upper/  baz/          ← renamed copy of foo/bar (no redirect)
//!
//! With redirect:
//! upper/  baz/          ← xattr trusted.overlay.redirect = "foo/bar"
//!   → lookup("baz") in overlay → resolves to lower/foo/bar content
//! ```
//!
//! # Structures
//!
//! - [`RedirectMode`]      — global policy (off / follow / warn / block)
//! - [`RedirectEntry`]     — single redirect mapping (upper path → origin)
//! - [`RedirectTable`]     — fixed-size table of redirect mappings
//! - [`RedirectResolver`]  — resolves overlay paths through the redirect table
//! - [`RedirectRegistry`]  — global, process-wide redirect state
//!
//! # References
//!
//! - Linux `fs/overlayfs/namei.c`, `Documentation/filesystems/overlayfs.rst`
//! - `trusted.overlay.redirect` xattr

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of redirect entries in the table.
pub const MAX_REDIRECTS: usize = 256;

/// Maximum length of a path stored in a redirect entry.
pub const MAX_PATH_LEN: usize = 256;

/// Xattr name used to store the redirect path on upper-layer directories.
pub const REDIRECT_XATTR: &[u8] = b"trusted.overlay.redirect";

/// Maximum redirect chain depth before we report a cycle.
pub const MAX_REDIRECT_DEPTH: usize = 16;

// ── RedirectMode ─────────────────────────────────────────────────────────────

/// Global policy for how redirect-dir xattrs are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RedirectMode {
    /// Redirect-dir is completely disabled; xattrs are ignored.
    Off = 0,
    /// Redirect xattrs are read and followed during path resolution.
    #[default]
    Follow = 1,
    /// Redirect xattrs are followed but a warning is emitted.
    Warn = 2,
    /// Presence of a redirect xattr causes a lookup error.
    Block = 3,
}

// ── RedirectEntry ─────────────────────────────────────────────────────────────

/// A single directory redirect: maps an upper-layer path to a lower-layer origin.
#[derive(Debug, Clone)]
pub struct RedirectEntry {
    /// Upper-layer path (the directory as seen from the merged view).
    upper_path: [u8; MAX_PATH_LEN],
    upper_path_len: usize,
    /// Lower-layer origin path stored in the xattr value.
    origin_path: [u8; MAX_PATH_LEN],
    origin_path_len: usize,
    /// True when this entry is in use.
    valid: bool,
    /// Filesystem device number that owns this redirect.
    dev: u32,
    /// Inode number of the upper-layer directory.
    upper_ino: u64,
}

impl Default for RedirectEntry {
    fn default() -> Self {
        Self {
            upper_path: [0u8; MAX_PATH_LEN],
            upper_path_len: 0,
            origin_path: [0u8; MAX_PATH_LEN],
            origin_path_len: 0,
            valid: false,
            dev: 0,
            upper_ino: 0,
        }
    }
}

impl RedirectEntry {
    /// Return the upper-layer path as a byte slice.
    pub fn upper_path(&self) -> &[u8] {
        &self.upper_path[..self.upper_path_len]
    }

    /// Return the origin path as a byte slice.
    pub fn origin_path(&self) -> &[u8] {
        &self.origin_path[..self.origin_path_len]
    }
}

// ── RedirectTable ─────────────────────────────────────────────────────────────

/// Fixed-size table holding all active redirect mappings.
pub struct RedirectTable {
    entries: [RedirectEntry; MAX_REDIRECTS],
    count: usize,
}

impl Default for RedirectTable {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| RedirectEntry::default()),
            count: 0,
        }
    }
}

impl RedirectTable {
    /// Insert a redirect mapping.
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    /// Returns [`Error::AlreadyExists`] if an entry for `upper_ino` on `dev` exists.
    pub fn insert(
        &mut self,
        dev: u32,
        upper_ino: u64,
        upper_path: &[u8],
        origin_path: &[u8],
    ) -> Result<()> {
        if upper_path.len() > MAX_PATH_LEN || origin_path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.entries[..self.count]
            .iter()
            .any(|e| e.valid && e.dev == dev && e.upper_ino == upper_ino)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.valid)
            .ok_or(Error::OutOfMemory)?;
        let entry = &mut self.entries[slot];
        entry.dev = dev;
        entry.upper_ino = upper_ino;
        entry.upper_path[..upper_path.len()].copy_from_slice(upper_path);
        entry.upper_path_len = upper_path.len();
        entry.origin_path[..origin_path.len()].copy_from_slice(origin_path);
        entry.origin_path_len = origin_path.len();
        entry.valid = true;
        if slot >= self.count {
            self.count = slot + 1;
        }
        Ok(())
    }

    /// Remove a redirect by inode number.
    ///
    /// Returns [`Error::NotFound`] if no such entry exists.
    pub fn remove(&mut self, dev: u32, upper_ino: u64) -> Result<()> {
        let slot = self.entries[..self.count]
            .iter()
            .position(|e| e.valid && e.dev == dev && e.upper_ino == upper_ino)
            .ok_or(Error::NotFound)?;
        self.entries[slot].valid = false;
        Ok(())
    }

    /// Look up the origin path for a given upper inode.
    ///
    /// Returns a reference to the origin-path bytes, or [`Error::NotFound`].
    pub fn lookup_by_ino(&self, dev: u32, upper_ino: u64) -> Result<&[u8]> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.valid && e.dev == dev && e.upper_ino == upper_ino)
            .map(|e| e.origin_path())
            .ok_or(Error::NotFound)
    }

    /// Look up the origin path by upper path name.
    pub fn lookup_by_path(&self, dev: u32, upper_path: &[u8]) -> Result<&[u8]> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.valid && e.dev == dev && e.upper_path() == upper_path)
            .map(|e| e.origin_path())
            .ok_or(Error::NotFound)
    }

    /// Return the number of valid entries.
    pub fn len(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.valid)
            .count()
    }

    /// Returns `true` if the table contains no valid entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over valid redirect entries.
    pub fn iter(&self) -> impl Iterator<Item = &RedirectEntry> {
        self.entries[..self.count].iter().filter(|e| e.valid)
    }
}

// ── XattrStore ───────────────────────────────────────────────────────────────

/// Minimal xattr store for redirect xattrs on upper-layer directories.
///
/// In a real kernel implementation this would delegate to the underlying
/// filesystem's xattr operations.  Here we provide an in-memory store.
pub struct XattrStore {
    /// Stored xattr payloads indexed by inode number.
    entries: [(u64, [u8; MAX_PATH_LEN], usize); 64],
    count: usize,
}

impl Default for XattrStore {
    fn default() -> Self {
        Self {
            entries: [(0u64, [0u8; MAX_PATH_LEN], 0usize); 64],
            count: 0,
        }
    }
}

impl XattrStore {
    /// Set (or update) the redirect xattr for a given inode.
    pub fn set(&mut self, ino: u64, value: &[u8]) -> Result<()> {
        if value.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        // Update existing entry if present.
        for (entry_ino, buf, len) in self.entries[..self.count].iter_mut() {
            if *entry_ino == ino {
                buf[..value.len()].copy_from_slice(value);
                *len = value.len();
                return Ok(());
            }
        }
        // Allocate new slot.
        if self.count >= 64 {
            return Err(Error::OutOfMemory);
        }
        let (entry_ino, buf, len) = &mut self.entries[self.count];
        *entry_ino = ino;
        buf[..value.len()].copy_from_slice(value);
        *len = value.len();
        self.count += 1;
        Ok(())
    }

    /// Get the redirect xattr value for a given inode.
    pub fn get(&self, ino: u64) -> Result<&[u8]> {
        self.entries[..self.count]
            .iter()
            .find(|(entry_ino, _, _)| *entry_ino == ino)
            .map(|(_, buf, len)| &buf[..*len])
            .ok_or(Error::NotFound)
    }

    /// Remove the redirect xattr for a given inode.
    pub fn remove(&mut self, ino: u64) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|(entry_ino, _, _)| *entry_ino == ino)
            .ok_or(Error::NotFound)?;
        self.entries[pos] = self.entries[self.count - 1];
        self.count -= 1;
        Ok(())
    }
}

// ── RedirectResolver ─────────────────────────────────────────────────────────

/// Resolves overlay paths through the redirect table, following redirect chains.
pub struct RedirectResolver<'a> {
    table: &'a RedirectTable,
    xattrs: &'a XattrStore,
    mode: RedirectMode,
}

impl<'a> RedirectResolver<'a> {
    /// Create a new resolver bound to the given table and xattr store.
    pub fn new(table: &'a RedirectTable, xattrs: &'a XattrStore, mode: RedirectMode) -> Self {
        Self {
            table,
            xattrs,
            mode,
        }
    }

    /// Resolve an upper-layer directory path to its lower-layer origin.
    ///
    /// The resolved origin bytes are written into `out_buf`.
    /// Returns the length written, or an error.
    pub fn resolve(
        &self,
        dev: u32,
        upper_path: &[u8],
        out_buf: &mut [u8; MAX_PATH_LEN],
    ) -> Result<usize> {
        match self.mode {
            RedirectMode::Off => return Err(Error::NotImplemented),
            RedirectMode::Block => return Err(Error::PermissionDenied),
            RedirectMode::Follow | RedirectMode::Warn => {}
        }

        let mut current = upper_path;
        let mut depth = 0usize;
        let mut scratch = [[0u8; MAX_PATH_LEN]; MAX_REDIRECT_DEPTH];

        loop {
            if depth >= MAX_REDIRECT_DEPTH {
                return Err(Error::InvalidArgument);
            }

            match self.table.lookup_by_path(dev, current) {
                Ok(origin) => {
                    let len = origin.len().min(MAX_PATH_LEN);
                    scratch[depth][..len].copy_from_slice(&origin[..len]);
                    current = &scratch[depth][..len];
                    depth += 1;
                }
                Err(Error::NotFound) => {
                    // No further redirect — current is the final origin.
                    let len = current.len().min(MAX_PATH_LEN);
                    out_buf[..len].copy_from_slice(&current[..len]);
                    return Ok(len);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Load a redirect origin path from xattrs for the given inode.
    ///
    /// This is used during mount to populate the redirect table from
    /// the stored xattr values on upper-layer inodes.
    pub fn load_from_xattr(&self, ino: u64) -> Result<&[u8]> {
        self.xattrs.get(ino)
    }
}

// ── RedirectRegistry ─────────────────────────────────────────────────────────

/// Global registry of overlayfs redirect state.
pub struct RedirectRegistry {
    /// The redirect table.
    pub table: RedirectTable,
    /// The xattr store backing redirect values.
    pub xattrs: XattrStore,
    /// Active redirect mode.
    pub mode: RedirectMode,
    /// Counts of redirect operations performed.
    pub inserts: u64,
    pub removes: u64,
    pub resolves: u64,
    pub resolve_errors: u64,
}

impl Default for RedirectRegistry {
    fn default() -> Self {
        Self::new(RedirectMode::Follow)
    }
}

impl RedirectRegistry {
    /// Create a new registry with the given mode.
    pub fn new(mode: RedirectMode) -> Self {
        Self {
            table: RedirectTable::default(),
            xattrs: XattrStore::default(),
            mode,
            inserts: 0,
            removes: 0,
            resolves: 0,
            resolve_errors: 0,
        }
    }

    /// Register a directory redirect, also storing the xattr.
    pub fn register(
        &mut self,
        dev: u32,
        upper_ino: u64,
        upper_path: &[u8],
        origin_path: &[u8],
    ) -> Result<()> {
        self.xattrs.set(upper_ino, origin_path)?;
        self.table.insert(dev, upper_ino, upper_path, origin_path)?;
        self.inserts += 1;
        Ok(())
    }

    /// Deregister a redirect entry and remove the associated xattr.
    pub fn deregister(&mut self, dev: u32, upper_ino: u64) -> Result<()> {
        // Ignore xattr removal error if it was never set.
        let _ = self.xattrs.remove(upper_ino);
        self.table.remove(dev, upper_ino)?;
        self.removes += 1;
        Ok(())
    }

    /// Resolve an upper-layer path to its lower-layer origin.
    pub fn resolve(
        &mut self,
        dev: u32,
        upper_path: &[u8],
        out_buf: &mut [u8; MAX_PATH_LEN],
    ) -> Result<usize> {
        let resolver = RedirectResolver::new(&self.table, &self.xattrs, self.mode);
        match resolver.resolve(dev, upper_path, out_buf) {
            Ok(n) => {
                self.resolves += 1;
                Ok(n)
            }
            Err(e) => {
                self.resolve_errors += 1;
                Err(e)
            }
        }
    }

    /// Change the redirect mode at runtime.
    pub fn set_mode(&mut self, mode: RedirectMode) {
        self.mode = mode;
    }
}

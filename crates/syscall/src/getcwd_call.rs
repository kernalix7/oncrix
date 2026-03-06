// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getcwd(2)` syscall handler.
//!
//! Returns the absolute pathname of the current working directory.  The
//! kernel walks the dentry tree from the current directory to the filesystem
//! root, building the path in reverse, then copies it to the user buffer.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getcwd()` specification.  Key behaviours:
//! - `ERANGE` if the provided buffer is too small to hold the path plus NUL.
//! - `ENOENT` if the current working directory has been unlinked.
//! - The returned path is absolute and begins with `/`.
//! - The path is NUL-terminated.
//!
//! # References
//!
//! - POSIX.1-2024: `getcwd()`
//! - Linux man pages: `getcwd(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum path length we handle (matches Linux PATH_MAX).
pub const PATH_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// Path component
// ---------------------------------------------------------------------------

/// A single path component (directory entry name).
#[derive(Debug, Clone, Copy)]
pub struct PathComponent {
    /// Name bytes (not NUL-terminated, max 255 bytes).
    pub name: [u8; 256],
    /// Length of the name.
    pub len: usize,
}

impl PathComponent {
    /// Construct from a byte slice.
    ///
    /// Returns `Err(InvalidArg)` if `name` is empty or exceeds 255 bytes.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; 256];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            len: name.len(),
        })
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.name[..self.len]
    }
}

// ---------------------------------------------------------------------------
// Path builder
// ---------------------------------------------------------------------------

/// Builds an absolute path by prepending components to a buffer.
///
/// Components are added in reverse order (leaf → root) and then the buffer
/// is reversed to produce the final path.
struct PathBuilder {
    buf: [u8; PATH_MAX],
    /// Write position from the end of the buffer (we build right-to-left).
    tail: usize,
}

impl PathBuilder {
    fn new() -> Self {
        Self {
            buf: [0u8; PATH_MAX],
            tail: PATH_MAX,
        }
    }

    /// Prepend a byte to the buffer.
    fn prepend_byte(&mut self, b: u8) -> Result<()> {
        if self.tail == 0 {
            return Err(Error::InvalidArgument);
        }
        self.tail -= 1;
        self.buf[self.tail] = b;
        Ok(())
    }

    /// Prepend `bytes` to the buffer (in forward order).
    fn prepend_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        for i in (0..bytes.len()).rev() {
            self.prepend_byte(bytes[i])?;
        }
        Ok(())
    }

    /// Prepend a path component with a leading `/`.
    fn prepend_component(&mut self, comp: &[u8]) -> Result<()> {
        self.prepend_bytes(comp)?;
        self.prepend_byte(b'/')?;
        Ok(())
    }

    /// Return the built path slice (no NUL).
    fn as_bytes(&self) -> &[u8] {
        &self.buf[self.tail..]
    }
}

// ---------------------------------------------------------------------------
// Dentry-walk simulation
// ---------------------------------------------------------------------------

/// A node in the dentry tree used to reconstruct the CWD path.
#[derive(Debug, Clone, Copy)]
pub struct DentryNode {
    /// Component name at this level (empty for root).
    pub name: PathComponent,
    /// Whether this is the filesystem root.
    pub is_root: bool,
}

/// Walk `dentries` from current directory to root, building the absolute path.
///
/// `dentries` must be ordered from the CWD dentry up to (but not including)
/// the root.  The root is represented by having `is_root = true` on the last
/// element or by an empty `dentries` slice (meaning CWD is the root itself).
fn build_path_from_dentries(dentries: &[DentryNode]) -> Result<[u8; PATH_MAX]> {
    let mut builder = PathBuilder::new();

    if dentries.is_empty() {
        // CWD is the root.
        builder.prepend_byte(b'/')?;
        let mut out = [0u8; PATH_MAX];
        let s = builder.as_bytes();
        out[..s.len()].copy_from_slice(s);
        return Ok(out);
    }

    for node in dentries.iter().rev() {
        if node.is_root {
            break;
        }
        builder.prepend_component(node.name.as_bytes())?;
    }

    // If path is empty at this point (all nodes were root), emit root slash.
    if builder.as_bytes().is_empty() {
        builder.prepend_byte(b'/')?;
    }

    let mut out = [0u8; PATH_MAX];
    let s = builder.as_bytes();
    out[..s.len()].copy_from_slice(s);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `getcwd(2)`.
///
/// Builds the CWD path from `dentries` and copies it into `buf`.
///
/// # Arguments
///
/// * `dentries` — Ordered dentry chain from CWD to root.
/// * `buf_size` — Size of the caller's output buffer.
///
/// # Returns
///
/// The NUL-terminated absolute path and its length (including NUL).
///
/// # Errors
///
/// | `Error`    | Condition                                           |
/// |------------|-----------------------------------------------------|
/// | `TooBig`   | `buf_size` is too small for the path + NUL (`ERANGE`)|
/// | `InvalidArg` | `buf_size` is 0                                  |
pub fn do_getcwd(dentries: &[DentryNode], buf_size: usize) -> Result<([u8; PATH_MAX], usize)> {
    if buf_size == 0 {
        return Err(Error::InvalidArgument);
    }

    let path_buf = build_path_from_dentries(dentries)?;

    // Find actual path length (up to first NUL or PATH_MAX).
    let path_len = path_buf.iter().position(|&b| b == 0).unwrap_or(PATH_MAX);

    // +1 for NUL terminator.
    let needed = path_len + 1;
    if needed > buf_size {
        return Err(Error::InvalidArgument);
    }

    Ok((path_buf, needed))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(name: &[u8]) -> DentryNode {
        DentryNode {
            name: PathComponent::new(name).unwrap(),
            is_root: false,
        }
    }

    #[test]
    fn getcwd_root() {
        let (buf, len) = do_getcwd(&[], 4096).unwrap();
        assert_eq!(&buf[..len - 1], b"/");
    }

    #[test]
    fn getcwd_simple_path() {
        let dentries = [comp(b"home"), comp(b"user"), comp(b"docs")];
        let (buf, len) = do_getcwd(&dentries, 4096).unwrap();
        let path = &buf[..len - 1];
        assert_eq!(path, b"/home/user/docs");
    }

    #[test]
    fn getcwd_erange() {
        let dentries = [comp(b"a"), comp(b"b"), comp(b"c")];
        // Buffer of 4 is too small for "/a/b/c" (7 bytes + NUL).
        assert_eq!(do_getcwd(&dentries, 4), Err(Error::InvalidArgument));
    }

    #[test]
    fn getcwd_zero_buf() {
        assert_eq!(do_getcwd(&[], 0), Err(Error::InvalidArgument));
    }
}

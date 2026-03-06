// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! devpts — PTY device filesystem.
//!
//! Implements the `/dev/pts` filesystem that manages pseudo-terminal
//! slave devices. Each allocated PTY pair is represented as a numbered
//! entry under the mount point (e.g., `/dev/pts/0`, `/dev/pts/1`).
//!
//! The filesystem maintains PTY pairs with bidirectional ring buffers
//! for master-slave communication, along with inode metadata for each
//! active slave device.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Ring buffer size for each direction (4 KiB).
const PTY_BUF_SIZE: usize = 4096;

/// Maximum number of PTY pairs in a single devpts instance.
const MAX_PTY_PAIRS: usize = 64;

/// Maximum length of a slave device name (`/dev/pts/NN`).
const SLAVE_NAME_MAX: usize = 16;

/// Default permission mode for slave devices (owner rw, group w).
const DEFAULT_MODE: u16 = 0o620;

/// Default GID for PTY slave devices (tty group).
const DEFAULT_GID: u32 = 5;

/// Default maximum number of PTYs allowed.
const DEFAULT_MAX_PTYS: u32 = 256;

// ── PtyMode ────────────────────────────────────────────────────────

/// Terminal mode configuration for a PTY pair.
#[derive(Debug, Clone, Copy)]
pub struct PtyMode {
    /// Raw mode — pass bytes through without processing.
    pub raw: bool,
    /// Echo mode — echo slave input back to master output.
    pub echo: bool,
    /// Canonical mode — line-buffered input processing.
    pub canonical: bool,
}

impl Default for PtyMode {
    fn default() -> Self {
        Self {
            raw: false,
            echo: true,
            canonical: true,
        }
    }
}

// ── DevptsOptions ──────────────────────────────────────────────────

/// Mount options for the devpts filesystem.
#[derive(Debug, Clone, Copy)]
pub struct DevptsOptions {
    /// Maximum number of PTYs allowed on this mount.
    pub max_ptys: u32,
    /// Default permission mode for new slave devices.
    pub mode: u16,
    /// Default group ID for new slave devices (typically tty group).
    pub gid: u32,
}

impl Default for DevptsOptions {
    fn default() -> Self {
        Self {
            max_ptys: DEFAULT_MAX_PTYS,
            mode: DEFAULT_MODE,
            gid: DEFAULT_GID,
        }
    }
}

// ── PtyPair ────────────────────────────────────────────────────────

/// A single pseudo-terminal pair managed by devpts.
///
/// Contains the master and slave file descriptors, bidirectional
/// ring buffers, and open/in-use state tracking.
pub struct PtyPair {
    /// Master-side file descriptor identifier.
    pub master_fd: u64,
    /// Slave-side file descriptor identifier.
    pub slave_fd: u64,
    /// PTY index within the devpts filesystem.
    pub idx: u32,

    /// Buffer carrying data from master to slave (slave reads here).
    master_buf: [u8; PTY_BUF_SIZE],
    /// Buffer carrying data from slave to master (master reads here).
    slave_buf: [u8; PTY_BUF_SIZE],
    /// Number of valid bytes in `master_buf`.
    master_count: usize,
    /// Number of valid bytes in `slave_buf`.
    slave_count: usize,

    /// Whether the master side is currently open.
    pub master_open: bool,
    /// Whether the slave side is currently open.
    pub slave_open: bool,
    /// Whether this PTY pair slot is in use.
    pub in_use: bool,
}

impl PtyPair {
    /// Create a new PTY pair with the given index and file descriptors.
    const fn new(idx: u32, master_fd: u64, slave_fd: u64) -> Self {
        Self {
            master_fd,
            slave_fd,
            idx,
            master_buf: [0; PTY_BUF_SIZE],
            slave_buf: [0; PTY_BUF_SIZE],
            master_count: 0,
            slave_count: 0,
            master_open: true,
            slave_open: true,
            in_use: true,
        }
    }

    /// Create an empty (unused) PTY pair slot.
    const fn empty() -> Self {
        Self {
            master_fd: 0,
            slave_fd: 0,
            idx: 0,
            master_buf: [0; PTY_BUF_SIZE],
            slave_buf: [0; PTY_BUF_SIZE],
            master_count: 0,
            slave_count: 0,
            master_open: false,
            slave_open: false,
            in_use: false,
        }
    }

    /// Write data from the master into the slave's input buffer.
    ///
    /// Returns the number of bytes written. Returns `WouldBlock` if
    /// the buffer is completely full.
    pub fn master_write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.in_use || !self.master_open {
            return Err(Error::IoError);
        }

        let available = PTY_BUF_SIZE - self.master_count;
        if available == 0 {
            return Err(Error::WouldBlock);
        }

        let to_write = data.len().min(available);
        let dest = &mut self.master_buf[self.master_count..];
        dest.iter_mut()
            .zip(data.iter().take(to_write))
            .for_each(|(d, &s)| *d = s);
        self.master_count += to_write;
        Ok(to_write)
    }

    /// Read data from the master's output buffer (slave-written data).
    ///
    /// Returns the number of bytes read. Returns `WouldBlock` when
    /// the buffer is empty but the pair is still active.
    pub fn master_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.slave_count == 0 {
            if !self.in_use || !self.slave_open {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let to_read = buf.len().min(self.slave_count);
        buf.iter_mut()
            .take(to_read)
            .zip(self.slave_buf.iter())
            .for_each(|(d, &s)| *d = s);

        // Shift remaining data to the front.
        self.slave_buf.copy_within(to_read..self.slave_count, 0);
        self.slave_count -= to_read;
        Ok(to_read)
    }

    /// Write data from the slave into the master's output buffer.
    ///
    /// Returns the number of bytes written. Returns `WouldBlock` if
    /// the buffer is completely full.
    pub fn slave_write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.in_use || !self.slave_open {
            return Err(Error::IoError);
        }

        let available = PTY_BUF_SIZE - self.slave_count;
        if available == 0 {
            return Err(Error::WouldBlock);
        }

        let to_write = data.len().min(available);
        let dest = &mut self.slave_buf[self.slave_count..];
        dest.iter_mut()
            .zip(data.iter().take(to_write))
            .for_each(|(d, &s)| *d = s);
        self.slave_count += to_write;
        Ok(to_write)
    }

    /// Read data from the slave's input buffer (master-written data).
    ///
    /// Returns the number of bytes read. Returns `WouldBlock` when
    /// the buffer is empty but the pair is still active.
    pub fn slave_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.master_count == 0 {
            if !self.in_use || !self.master_open {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let to_read = buf.len().min(self.master_count);
        buf.iter_mut()
            .take(to_read)
            .zip(self.master_buf.iter())
            .for_each(|(d, &s)| *d = s);

        // Shift remaining data to the front.
        self.master_buf.copy_within(to_read..self.master_count, 0);
        self.master_count -= to_read;
        Ok(to_read)
    }
}

impl core::fmt::Debug for PtyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtyPair")
            .field("idx", &self.idx)
            .field("master_fd", &self.master_fd)
            .field("slave_fd", &self.slave_fd)
            .field("in_use", &self.in_use)
            .field("master_count", &self.master_count)
            .field("slave_count", &self.slave_count)
            .finish()
    }
}

// ── DevptsInode ────────────────────────────────────────────────────

/// Inode metadata for a slave PTY device in devpts.
#[derive(Debug, Clone, Copy)]
pub struct DevptsInode {
    /// PTY index (corresponds to `/dev/pts/<idx>`).
    pub idx: u32,
    /// File permission mode.
    pub mode: u16,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Last access time (seconds since epoch).
    pub atime: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Whether this inode slot is in use.
    pub in_use: bool,
}

impl Default for DevptsInode {
    fn default() -> Self {
        Self {
            idx: 0,
            mode: DEFAULT_MODE,
            uid: 0,
            gid: DEFAULT_GID,
            atime: 0,
            mtime: 0,
            in_use: false,
        }
    }
}

// ── DevptsFs ───────────────────────────────────────────────────────

/// The devpts filesystem instance.
///
/// Manages PTY pair allocations and their corresponding inodes.
/// Mount this filesystem at `/dev/pts` to provide numbered slave
/// device entries for each active pseudo-terminal.
pub struct DevptsFs {
    /// Mount options governing PTY allocation limits and defaults.
    options: DevptsOptions,
    /// PTY pair storage.
    pairs: [PtyPair; MAX_PTY_PAIRS],
    /// Number of active PTY pairs.
    pair_count: usize,
    /// Inode storage for slave device entries.
    inodes: [DevptsInode; MAX_PTY_PAIRS],
    /// Number of active inodes.
    inode_count: usize,
    /// Next PTY index to assign (monotonically increasing).
    next_idx: u32,
    /// Whether this filesystem is currently mounted.
    mounted: bool,
}

impl DevptsFs {
    /// Create a new unmounted devpts filesystem with default options.
    pub const fn new() -> Self {
        Self {
            options: DevptsOptions {
                max_ptys: DEFAULT_MAX_PTYS,
                mode: DEFAULT_MODE,
                gid: DEFAULT_GID,
            },
            pairs: [const { PtyPair::empty() }; MAX_PTY_PAIRS],
            pair_count: 0,
            inodes: [const {
                DevptsInode {
                    idx: 0,
                    mode: DEFAULT_MODE,
                    uid: 0,
                    gid: DEFAULT_GID,
                    atime: 0,
                    mtime: 0,
                    in_use: false,
                }
            }; MAX_PTY_PAIRS],
            inode_count: 0,
            next_idx: 0,
            mounted: false,
        }
    }

    /// Mount the devpts filesystem with the given options.
    ///
    /// Returns `AlreadyExists` if already mounted.
    pub fn mount(&mut self, options: DevptsOptions) -> Result<()> {
        if self.mounted {
            return Err(Error::AlreadyExists);
        }
        self.options = options;
        self.mounted = true;
        Ok(())
    }

    /// Allocate a new PTY pair.
    ///
    /// Returns `(master_fd, slave_fd, idx)` on success. The master
    /// and slave file descriptors are derived from the PTY index.
    ///
    /// Returns `OutOfMemory` if no free slot is available or the
    /// maximum number of PTYs has been reached.
    pub fn allocate_pty(&mut self) -> Result<(u64, u64, u32)> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if self.pair_count >= MAX_PTY_PAIRS {
            return Err(Error::OutOfMemory);
        }
        if self.next_idx >= self.options.max_ptys {
            return Err(Error::OutOfMemory);
        }

        let idx = self.next_idx;
        let master_fd = (idx as u64) * 2;
        let slave_fd = (idx as u64) * 2 + 1;

        // Find a free pair slot.
        let slot = self
            .pairs
            .iter_mut()
            .find(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;
        *slot = PtyPair::new(idx, master_fd, slave_fd);

        // Find a free inode slot.
        let inode = self
            .inodes
            .iter_mut()
            .find(|i| !i.in_use)
            .ok_or(Error::OutOfMemory)?;
        *inode = DevptsInode {
            idx,
            mode: self.options.mode,
            uid: 0,
            gid: self.options.gid,
            atime: 0,
            mtime: 0,
            in_use: true,
        };

        self.pair_count += 1;
        self.inode_count += 1;
        self.next_idx += 1;

        Ok((master_fd, slave_fd, idx))
    }

    /// Release (deallocate) a PTY pair by index.
    ///
    /// Marks both the pair slot and inode as unused.
    pub fn release_pty(&mut self, idx: u32) -> Result<()> {
        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.in_use && p.idx == idx)
            .ok_or(Error::NotFound)?;
        pair.in_use = false;
        pair.master_open = false;
        pair.slave_open = false;

        if let Some(inode) = self.inodes.iter_mut().find(|i| i.in_use && i.idx == idx) {
            inode.in_use = false;
        }

        self.pair_count = self.pair_count.saturating_sub(1);
        self.inode_count = self.inode_count.saturating_sub(1);
        Ok(())
    }

    /// Write data from the master side of PTY `idx`.
    pub fn master_write(&mut self, idx: u32, data: &[u8]) -> Result<usize> {
        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.in_use && p.idx == idx)
            .ok_or(Error::NotFound)?;
        pair.master_write(data)
    }

    /// Read data from the master side of PTY `idx`.
    pub fn master_read(&mut self, idx: u32, buf: &mut [u8]) -> Result<usize> {
        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.in_use && p.idx == idx)
            .ok_or(Error::NotFound)?;
        pair.master_read(buf)
    }

    /// Write data from the slave side of PTY `idx`.
    pub fn slave_write(&mut self, idx: u32, data: &[u8]) -> Result<usize> {
        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.in_use && p.idx == idx)
            .ok_or(Error::NotFound)?;
        pair.slave_write(data)
    }

    /// Read data from the slave side of PTY `idx`.
    pub fn slave_read(&mut self, idx: u32, buf: &mut [u8]) -> Result<usize> {
        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.in_use && p.idx == idx)
            .ok_or(Error::NotFound)?;
        pair.slave_read(buf)
    }

    /// Write the slave device name (`/dev/pts/N`) into `buf`.
    ///
    /// Returns the number of bytes written to `buf`.
    pub fn get_slave_name(&self, idx: u32, buf: &mut [u8]) -> Result<usize> {
        // Verify the PTY exists.
        if !self.pairs.iter().any(|p| p.in_use && p.idx == idx) {
            return Err(Error::NotFound);
        }

        let prefix = b"/dev/pts/";
        let mut name = [0u8; SLAVE_NAME_MAX];
        let mut pos = prefix.len();

        // Copy prefix.
        name[..pos].copy_from_slice(prefix);

        // Append decimal index.
        if idx == 0 {
            name[pos] = b'0';
            pos += 1;
        } else {
            let mut digits = [0u8; 5];
            let mut n = idx;
            let mut dcount = 0;
            while n > 0 {
                digits[dcount] = b'0' + (n % 10) as u8;
                n /= 10;
                dcount += 1;
            }
            let mut j = dcount;
            while j > 0 {
                j -= 1;
                if pos < SLAVE_NAME_MAX {
                    name[pos] = digits[j];
                    pos += 1;
                }
            }
        }

        if buf.len() < pos {
            return Err(Error::InvalidArgument);
        }
        buf[..pos].copy_from_slice(&name[..pos]);
        Ok(pos)
    }

    /// Return inode metadata for the PTY with the given index.
    pub fn stat(&self, idx: u32) -> Result<&DevptsInode> {
        self.inodes
            .iter()
            .find(|i| i.in_use && i.idx == idx)
            .ok_or(Error::NotFound)
    }

    /// Return a slice of all inode entries (including unused slots).
    ///
    /// Callers should filter by `in_use` to enumerate active entries.
    pub fn readdir(&self) -> &[DevptsInode] {
        &self.inodes[..MAX_PTY_PAIRS]
    }

    /// Return the number of currently active PTY pairs.
    pub fn active_ptys(&self) -> usize {
        self.pair_count
    }

    /// Return the total number of PTY pair slots.
    pub fn len(&self) -> usize {
        self.pair_count
    }

    /// Return `true` if no PTY pairs are active.
    pub fn is_empty(&self) -> bool {
        self.pair_count == 0
    }

    /// Return whether the filesystem is mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Return the current mount options.
    pub fn options(&self) -> &DevptsOptions {
        &self.options
    }
}

impl Default for DevptsFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for DevptsFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevptsFs")
            .field("mounted", &self.mounted)
            .field("pair_count", &self.pair_count)
            .field("inode_count", &self.inode_count)
            .field("next_idx", &self.next_idx)
            .field("options", &self.options)
            .finish()
    }
}

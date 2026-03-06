// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pseudo-terminal (PTY) implementation.
//!
//! A PTY provides a bidirectional communication channel that emulates
//! a hardware terminal. Each PTY pair consists of a master side
//! (typically held by a terminal emulator) and a slave side (used by
//! the shell or application). Data written to the master appears as
//! input on the slave, and vice versa.
//!
//! Basic line discipline processing is supported: `ECHO` feeds slave
//! input back to the master output, `OPOST` converts `\n` to `\r\n`
//! on slave writes, and `ICANON` is reserved for canonical mode.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Ring buffer size for each direction (4 KiB).
const PTY_BUF_SIZE: usize = 4096;

/// Maximum number of active PTY pairs system-wide.
const MAX_PTYS: usize = 64;

// ── Line discipline flags ──────────────────────────────────────────

/// Echo slave input back to the master output buffer.
pub const ECHO: u32 = 0x1;

/// Enable output post-processing (`\n` → `\r\n` on slave writes).
pub const OPOST: u32 = 0x2;

/// Canonical mode (line-buffered input). Reserved for future use.
pub const ICANON: u32 = 0x4;

/// Default line discipline flags: echo + output post-processing +
/// canonical mode.
const DEFAULT_FLAGS: u32 = ECHO | OPOST | ICANON;

/// Maximum length of a slave device name (`/dev/pts/NN`).
const SLAVE_NAME_MAX: usize = 16;

// ── PtyPair ────────────────────────────────────────────────────────

/// A single pseudo-terminal pair (master + slave).
///
/// Each direction uses a fixed-size ring buffer. The *master buffer*
/// carries data from the slave to the master (i.e., output the
/// terminal emulator reads). The *slave buffer* carries data from
/// the master to the slave (i.e., input the application reads).
pub struct PtyPair {
    // -- master-side ring buffer (slave → master output) ----------
    /// Ring buffer for master reads (slave output).
    master_buf: [u8; PTY_BUF_SIZE],
    /// Head index into `master_buf`.
    master_head: usize,
    /// Tail index into `master_buf`.
    master_tail: usize,
    /// Number of bytes stored in `master_buf`.
    master_count: usize,

    // -- slave-side ring buffer (master → slave input) -----------
    /// Ring buffer for slave reads (master input).
    slave_buf: [u8; PTY_BUF_SIZE],
    /// Head index into `slave_buf`.
    slave_head: usize,
    /// Tail index into `slave_buf`.
    slave_tail: usize,
    /// Number of bytes stored in `slave_buf`.
    slave_count: usize,

    /// Line discipline flags (see [`ECHO`], [`OPOST`], [`ICANON`]).
    flags: u32,

    /// Slave device name (e.g. `/dev/pts/0`).
    slave_name: [u8; SLAVE_NAME_MAX],
    /// Valid length of bytes in `slave_name`.
    slave_name_len: usize,

    /// PTY pair index inside the registry.
    index: u32,
    /// Whether this PTY pair is currently active.
    active: bool,
}

impl PtyPair {
    /// Create a new PTY pair with the given registry `index`.
    ///
    /// The slave side is named `/dev/pts/<index>`. The pair starts
    /// in the active state with default line discipline flags
    /// (`ECHO | OPOST | ICANON`).
    pub fn new(index: u32) -> Self {
        let mut name = [0u8; SLAVE_NAME_MAX];
        let prefix = b"/dev/pts/";
        let prefix_len = prefix.len();

        // Copy the fixed prefix.
        let mut i = 0;
        while i < prefix_len {
            name[i] = prefix[i];
            i += 1;
        }

        // Append the decimal index. We handle 0 specially so the
        // loop below always writes at least one digit.
        let mut pos = prefix_len;
        if index == 0 {
            name[pos] = b'0';
            pos += 1;
        } else {
            // Write digits into a small stack buffer, then reverse.
            let mut digits = [0u8; 5]; // up to 99999
            let mut n = index;
            let mut dcount = 0;
            while n > 0 {
                digits[dcount] = b'0' + (n % 10) as u8;
                n /= 10;
                dcount += 1;
            }
            // Copy digits in reverse (most-significant first).
            let mut j = dcount;
            while j > 0 {
                j -= 1;
                if pos < SLAVE_NAME_MAX {
                    name[pos] = digits[j];
                    pos += 1;
                }
            }
        }

        Self {
            master_buf: [0; PTY_BUF_SIZE],
            master_head: 0,
            master_tail: 0,
            master_count: 0,

            slave_buf: [0; PTY_BUF_SIZE],
            slave_head: 0,
            slave_tail: 0,
            slave_count: 0,

            flags: DEFAULT_FLAGS,

            slave_name: name,
            slave_name_len: pos,

            index,
            active: true,
        }
    }

    // -- master-side operations -----------------------------------

    /// Write data from the master into the slave's input buffer.
    ///
    /// When `ECHO` is set the same bytes are also placed into the
    /// master's output buffer so the terminal emulator can display
    /// them.
    ///
    /// Returns the number of bytes written. Returns `WouldBlock` if
    /// the slave buffer is completely full.
    pub fn master_write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::IoError);
        }

        let available = PTY_BUF_SIZE - self.slave_count;
        if available == 0 {
            return Err(Error::WouldBlock);
        }

        let to_write = data.len().min(available);
        for &byte in data.iter().take(to_write) {
            self.slave_buf[self.slave_tail] = byte;
            self.slave_tail = (self.slave_tail + 1) % PTY_BUF_SIZE;
        }
        self.slave_count += to_write;

        // ECHO: copy the same bytes into the master output buffer
        // so the terminal emulator sees what was typed.
        if self.flags & ECHO != 0 {
            self.echo_to_master(data, to_write);
        }

        Ok(to_write)
    }

    /// Read data from the master's output buffer.
    ///
    /// Returns the number of bytes read. Returns `WouldBlock` when
    /// the buffer is empty but the PTY is still active.
    pub fn master_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.master_count == 0 {
            if !self.active {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let to_read = buf.len().min(self.master_count);
        for byte in buf.iter_mut().take(to_read) {
            *byte = self.master_buf[self.master_head];
            self.master_head = (self.master_head + 1) % PTY_BUF_SIZE;
        }
        self.master_count -= to_read;
        Ok(to_read)
    }

    // -- slave-side operations ------------------------------------

    /// Write data from the slave into the master's output buffer.
    ///
    /// When `OPOST` is enabled, each `\n` byte is expanded to
    /// `\r\n`. Returns the number of **source** bytes consumed.
    /// Returns `WouldBlock` when the master buffer is full.
    pub fn slave_write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::IoError);
        }

        let opost = self.flags & OPOST != 0;
        let mut written = 0usize;

        for &byte in data {
            if opost && byte == b'\n' {
                // Need 2 bytes of space for \r\n.
                if self.master_count + 2 > PTY_BUF_SIZE {
                    break;
                }
                self.push_master(b'\r');
                self.push_master(b'\n');
            } else {
                if self.master_count >= PTY_BUF_SIZE {
                    break;
                }
                self.push_master(byte);
            }
            written += 1;
        }

        if written == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(written)
    }

    /// Read data from the slave's input buffer.
    ///
    /// Returns the number of bytes read. Returns `WouldBlock` when
    /// the buffer is empty but the PTY is still active.
    pub fn slave_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.slave_count == 0 {
            if !self.active {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }

        let to_read = buf.len().min(self.slave_count);
        for byte in buf.iter_mut().take(to_read) {
            *byte = self.slave_buf[self.slave_head];
            self.slave_head = (self.slave_head + 1) % PTY_BUF_SIZE;
        }
        self.slave_count -= to_read;
        Ok(to_read)
    }

    // -- accessors ------------------------------------------------

    /// Return the slave device name as a byte slice.
    pub fn slave_name(&self) -> &[u8] {
        &self.slave_name[..self.slave_name_len]
    }

    /// Return the PTY pair index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Return `true` if this PTY pair is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the current line discipline flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Set the line discipline flags.
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Deactivate this PTY pair (both sides become EOF).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    // -- private helpers ------------------------------------------

    /// Push a single byte into the master output ring buffer.
    fn push_master(&mut self, byte: u8) {
        self.master_buf[self.master_tail] = byte;
        self.master_tail = (self.master_tail + 1) % PTY_BUF_SIZE;
        self.master_count += 1;
    }

    /// Echo bytes into the master output buffer (best-effort; stops
    /// when the buffer is full).
    fn echo_to_master(&mut self, data: &[u8], limit: usize) {
        for &byte in data.iter().take(limit) {
            if self.master_count >= PTY_BUF_SIZE {
                break;
            }
            self.push_master(byte);
        }
    }
}

impl core::fmt::Debug for PtyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PtyPair")
            .field("index", &self.index)
            .field("active", &self.active)
            .field("master_count", &self.master_count)
            .field("slave_count", &self.slave_count)
            .field("flags", &self.flags)
            .finish()
    }
}

// ── PtyRegistry ────────────────────────────────────────────────────

/// System-wide pseudo-terminal registry.
///
/// Manages up to [`MAX_PTYS`] simultaneously active PTY pairs.
/// New pairs are created with [`PtyRegistry::create`] and accessed
/// by their slot index.
pub struct PtyRegistry {
    /// PTY pair slots.
    ptys: [Option<PtyPair>; MAX_PTYS],
}

impl Default for PtyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyRegistry {
    /// Create an empty PTY registry.
    pub const fn new() -> Self {
        const NONE: Option<PtyPair> = None;
        Self {
            ptys: [NONE; MAX_PTYS],
        }
    }

    /// Allocate a new PTY pair.
    ///
    /// Returns `(master_fd_index, slave_fd_index)` where both
    /// indices refer to the same slot (the caller distinguishes
    /// master vs. slave via the file description flags).
    ///
    /// Returns `OutOfMemory` if no free slot is available.
    pub fn create(&mut self) -> Result<(usize, usize)> {
        for (i, slot) in self.ptys.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PtyPair::new(i as u32));
                // Both master and slave share the same slot
                // index; the VFS layer distinguishes the two
                // endpoints through their file descriptions.
                return Ok((i, i));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to a PTY pair by slot index.
    pub fn get(&self, index: usize) -> Result<&PtyPair> {
        self.ptys
            .get(index)
            .and_then(|s| s.as_ref())
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a PTY pair by slot index.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut PtyPair> {
        self.ptys
            .get_mut(index)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Close (deallocate) a PTY pair by slot index.
    pub fn close(&mut self, index: usize) -> Result<()> {
        let slot = self.ptys.get_mut(index).ok_or(Error::InvalidArgument)?;
        if slot.is_none() {
            return Err(Error::NotFound);
        }
        *slot = None;
        Ok(())
    }

    /// Return the number of active PTY pairs.
    pub fn count(&self) -> usize {
        self.ptys.iter().filter(|s| s.is_some()).count()
    }
}

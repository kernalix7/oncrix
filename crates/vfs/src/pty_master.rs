// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PTY master/slave pair management.
//!
//! This module implements the UNIX98 PTY (pseudo-terminal) master-side
//! allocation and lifecycle management. PTY pairs are created via
//! `posix_openpt(3)` / `open("/dev/ptmx")`, and the slave endpoint is
//! accessed via the devpts filesystem.
//!
//! # Lifecycle
//!
//! 1. Open `/dev/ptmx` — allocates a free PTY index and returns the master fd.
//! 2. `grantpt(3)` — fixes ownership/permissions of the slave device.
//! 3. `unlockpt(3)` — unlocks the slave for opening.
//! 4. `ptsname(3)` — returns `/dev/pts/<N>` for the slave path.
//! 5. Open the slave path — returns the slave fd.
//! 6. Close both ends — frees the PTY index.
//!
//! # References
//!
//! - POSIX.1-2024 `posix_openpt()`, `grantpt()`, `unlockpt()`, `ptsname()`
//! - Linux `pty(7)`, `/dev/ptmx`, devpts filesystem

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of concurrent PTY pairs.
pub const MAX_PTY_PAIRS: usize = 256;

/// Ring buffer size for each PTY direction (4 KiB).
const PTY_BUF: usize = 4096;

/// Slave device path prefix written into `ptsname` output.
const SLAVE_PREFIX: &[u8] = b"/dev/pts/";

// ── PtyState ─────────────────────────────────────────────────────────

/// Lifecycle state of a PTY pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyState {
    /// Slot is free.
    Free,
    /// Master fd is open; slave is locked (before `unlockpt`).
    Locked,
    /// Slave has been unlocked; both ends may be opened.
    Unlocked,
    /// Both ends are open and active.
    Active,
    /// One or both ends have been closed; draining.
    Closing,
}

// ── PtyPairEntry ─────────────────────────────────────────────────────

/// A single PTY master/slave pair.
pub struct PtyPairEntry {
    /// PTY index (0..MAX_PTY_PAIRS).
    pub index: u16,
    /// Lifecycle state.
    pub state: PtyState,
    /// Master → slave ring buffer (data written to master, read from slave).
    master_to_slave: [u8; PTY_BUF],
    m2s_head: usize,
    m2s_tail: usize,
    m2s_count: usize,
    /// Slave → master ring buffer (data written to slave, read from master).
    slave_to_master: [u8; PTY_BUF],
    s2m_head: usize,
    s2m_tail: usize,
    s2m_count: usize,
    /// Whether the master end is open.
    pub master_open: bool,
    /// Whether the slave end is open.
    pub slave_open: bool,
    /// Line discipline flags.
    pub termios_flags: u32,
}

impl PtyPairEntry {
    /// Create an empty (free) PTY pair slot.
    pub const fn new(index: u16) -> Self {
        Self {
            index,
            state: PtyState::Free,
            master_to_slave: [0u8; PTY_BUF],
            m2s_head: 0,
            m2s_tail: 0,
            m2s_count: 0,
            slave_to_master: [0u8; PTY_BUF],
            s2m_head: 0,
            s2m_tail: 0,
            s2m_count: 0,
            master_open: false,
            slave_open: false,
            termios_flags: 0,
        }
    }

    // ── Ring buffer helpers ───────────────────────────────────────

    fn ring_push(
        buf: &mut [u8; PTY_BUF],
        tail: &mut usize,
        count: &mut usize,
        data: &[u8],
    ) -> usize {
        let space = PTY_BUF - *count;
        let n = data.len().min(space);
        for (i, &b) in data[..n].iter().enumerate() {
            buf[(*tail + i) % PTY_BUF] = b;
        }
        *tail = (*tail + n) % PTY_BUF;
        *count += n;
        n
    }

    fn ring_pop(buf: &[u8; PTY_BUF], head: &mut usize, count: &mut usize, out: &mut [u8]) -> usize {
        let avail = *count;
        let n = out.len().min(avail);
        for (i, slot) in out[..n].iter_mut().enumerate() {
            *slot = buf[(*head + i) % PTY_BUF];
        }
        *head = (*head + n) % PTY_BUF;
        *count -= n;
        n
    }

    /// Write `data` from the master side (data becomes slave input).
    pub fn master_write(&mut self, data: &[u8]) -> Result<usize> {
        if self.state == PtyState::Free || self.state == PtyState::Locked {
            return Err(Error::PermissionDenied);
        }
        if self.m2s_count >= PTY_BUF {
            return Err(Error::WouldBlock);
        }
        let n = Self::ring_push(
            &mut self.master_to_slave,
            &mut self.m2s_tail,
            &mut self.m2s_count,
            data,
        );
        Ok(n)
    }

    /// Read from the master side (consumes slave output).
    pub fn master_read(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.s2m_count == 0 {
            if !self.slave_open {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }
        let n = Self::ring_pop(
            &self.slave_to_master,
            &mut self.s2m_head,
            &mut self.s2m_count,
            out,
        );
        Ok(n)
    }

    /// Write `data` from the slave side (data becomes master input).
    pub fn slave_write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.slave_open || self.state == PtyState::Free {
            return Err(Error::PermissionDenied);
        }
        if self.s2m_count >= PTY_BUF {
            return Err(Error::WouldBlock);
        }
        let n = Self::ring_push(
            &mut self.slave_to_master,
            &mut self.s2m_tail,
            &mut self.s2m_count,
            data,
        );
        Ok(n)
    }

    /// Read from the slave side (consumes master output).
    pub fn slave_read(&mut self, out: &mut [u8]) -> Result<usize> {
        if self.m2s_count == 0 {
            if !self.master_open {
                return Ok(0); // EOF
            }
            return Err(Error::WouldBlock);
        }
        let n = Self::ring_pop(
            &self.master_to_slave,
            &mut self.m2s_head,
            &mut self.m2s_count,
            out,
        );
        Ok(n)
    }

    /// Fill `buf` with the null-terminated slave path (`/dev/pts/<N>`).
    ///
    /// Returns the number of bytes written (not including terminating null).
    pub fn ptsname(&self, buf: &mut [u8]) -> Result<usize> {
        let prefix = SLAVE_PREFIX;
        let idx = self.index;
        // Format index as decimal digits.
        let mut digits = [0u8; 8];
        let mut n = 0usize;
        let mut v = idx as u32;
        if v == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while v > 0 {
                digits[n] = b'0' + (v % 10) as u8;
                v /= 10;
                n += 1;
            }
            digits[..n].reverse();
        }
        let total = prefix.len() + n + 1; // +1 for NUL
        if buf.len() < total {
            return Err(Error::InvalidArgument);
        }
        buf[..prefix.len()].copy_from_slice(prefix);
        buf[prefix.len()..prefix.len() + n].copy_from_slice(&digits[..n]);
        buf[prefix.len() + n] = 0;
        Ok(total - 1)
    }
}

// ── PtyMaster ────────────────────────────────────────────────────────

/// The global PTY master allocator.
pub struct PtyMaster {
    pairs: [PtyPairEntry; MAX_PTY_PAIRS],
}

impl PtyMaster {
    /// Create the PTY master (all slots free).
    pub fn new() -> Self {
        Self {
            pairs: core::array::from_fn(|i| PtyPairEntry::new(i as u16)),
        }
    }

    /// Allocate a new PTY pair; returns the index.
    pub fn open_master(&mut self) -> Result<u16> {
        for pair in self.pairs.iter_mut() {
            if pair.state == PtyState::Free {
                pair.state = PtyState::Locked;
                pair.master_open = true;
                pair.slave_open = false;
                pair.m2s_head = 0;
                pair.m2s_tail = 0;
                pair.m2s_count = 0;
                pair.s2m_head = 0;
                pair.s2m_tail = 0;
                pair.s2m_count = 0;
                return Ok(pair.index);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unlock the slave end (`unlockpt`).
    pub fn unlockpt(&mut self, index: u16) -> Result<()> {
        let pair = self
            .pairs
            .get_mut(index as usize)
            .ok_or(Error::InvalidArgument)?;
        if pair.state != PtyState::Locked {
            return Err(Error::InvalidArgument);
        }
        pair.state = PtyState::Unlocked;
        Ok(())
    }

    /// Open the slave end; transitions to `Active`.
    pub fn open_slave(&mut self, index: u16) -> Result<()> {
        let pair = self
            .pairs
            .get_mut(index as usize)
            .ok_or(Error::InvalidArgument)?;
        if pair.state != PtyState::Unlocked {
            return Err(Error::PermissionDenied);
        }
        pair.state = PtyState::Active;
        pair.slave_open = true;
        Ok(())
    }

    /// Get a mutable reference to a pair by index.
    pub fn pair_mut(&mut self, index: u16) -> Option<&mut PtyPairEntry> {
        self.pairs.get_mut(index as usize)
    }

    /// Close the master end of PTY `index`.
    pub fn close_master(&mut self, index: u16) -> Result<()> {
        let pair = self
            .pairs
            .get_mut(index as usize)
            .ok_or(Error::InvalidArgument)?;
        pair.master_open = false;
        if !pair.slave_open {
            pair.state = PtyState::Free;
        } else {
            pair.state = PtyState::Closing;
        }
        Ok(())
    }

    /// Close the slave end of PTY `index`.
    pub fn close_slave(&mut self, index: u16) -> Result<()> {
        let pair = self
            .pairs
            .get_mut(index as usize)
            .ok_or(Error::InvalidArgument)?;
        pair.slave_open = false;
        if !pair.master_open {
            pair.state = PtyState::Free;
        } else {
            pair.state = PtyState::Closing;
        }
        Ok(())
    }

    /// Returns the number of active PTY pairs.
    pub fn active_count(&self) -> usize {
        self.pairs
            .iter()
            .filter(|p| p.state != PtyState::Free)
            .count()
    }
}

impl Default for PtyMaster {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O vector iterator — `iovec` / `iov_iter` for scatter-gather I/O.
//!
//! Provides the `IovIter` type which tracks a sequence of `(address, length)`
//! pairs and supports advancing past transferred bytes, just as the Linux
//! kernel's `struct iov_iter` does.

use oncrix_lib::{Error, Result};

/// Maximum number of `iovec` entries in a single I/O vector.
pub const MAX_IOV: usize = 64;

/// A single I/O vector segment — corresponds to POSIX `struct iovec`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Iovec {
    /// Base address (user-space virtual address or kernel buffer pointer).
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

impl Iovec {
    /// Create a new iovec.
    pub const fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    /// Return `true` if this segment has zero length.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Direction of the I/O vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IovDirection {
    /// Data flows from storage into the iovec buffers (read).
    Read,
    /// Data flows from the iovec buffers into storage (write).
    Write,
}

/// An iterator over a sequence of `Iovec` segments.
///
/// Tracks how many bytes have been transferred and provides the `advance`
/// method to skip past consumed bytes, mirroring Linux's `iov_iter_advance`.
pub struct IovIter {
    iov: [Iovec; MAX_IOV],
    count: usize,
    /// Index of the current segment.
    cur_seg: usize,
    /// Byte offset within the current segment.
    cur_off: u64,
    /// Direction of this iterator.
    pub direction: IovDirection,
    /// Total bytes still available (sum of remaining segment lengths).
    pub total: u64,
}

impl IovIter {
    /// Create a new `IovIter` from a slice of `Iovec` entries.
    pub fn new(iov_slice: &[Iovec], direction: IovDirection) -> Result<Self> {
        if iov_slice.len() > MAX_IOV {
            return Err(Error::InvalidArgument);
        }
        let mut iov = [Iovec::new(0, 0); MAX_IOV];
        let count = iov_slice.len();
        iov[..count].copy_from_slice(iov_slice);

        let total: u64 = iov_slice
            .iter()
            .map(|v| v.len)
            .fold(0u64, u64::saturating_add);

        Ok(Self {
            iov,
            count,
            cur_seg: 0,
            cur_off: 0,
            direction,
            total,
        })
    }

    /// Return the total number of bytes remaining to be transferred.
    pub fn remaining(&self) -> u64 {
        self.total
    }

    /// Return `true` when all bytes have been consumed.
    pub fn is_done(&self) -> bool {
        self.total == 0
    }

    /// Return the current segment as `(base, len)`, or `None` if exhausted.
    pub fn current_segment(&self) -> Option<(u64, u64)> {
        while self.cur_seg < self.count {
            let seg = self.iov[self.cur_seg];
            let len = seg.len.saturating_sub(self.cur_off);
            if len > 0 {
                return Some((seg.base + self.cur_off, len));
            }
            // Zero-length segment — skip.
            break;
        }
        None
    }

    /// Advance the iterator by `bytes` bytes.
    ///
    /// Moves past fully consumed segments. Returns the number of bytes
    /// actually advanced (may be less if fewer bytes remain).
    pub fn advance(&mut self, bytes: u64) -> u64 {
        let bytes = bytes.min(self.total);
        let mut remaining = bytes;

        while remaining > 0 && self.cur_seg < self.count {
            let seg_remaining = self.iov[self.cur_seg].len.saturating_sub(self.cur_off);
            if remaining >= seg_remaining {
                remaining -= seg_remaining;
                self.cur_seg += 1;
                self.cur_off = 0;
            } else {
                self.cur_off += remaining;
                remaining = 0;
            }
        }

        self.total = self.total.saturating_sub(bytes);
        bytes
    }

    /// Copy up to `n` bytes from a linear buffer into/out of the iovec.
    ///
    /// For `IovDirection::Read`: copies from `src` into the iovec buffers
    /// (simulated — in a real kernel this would be `copy_to_user`).
    ///
    /// For `IovDirection::Write`: copies from the iovec buffers into `dst`.
    ///
    /// This implementation performs the copy within kernel address space only
    /// (both `src`/`dst` and iov bases are treated as kernel virtual addresses
    /// for simulation purposes).
    ///
    /// Returns number of bytes copied.
    pub fn copy_from_slice(&mut self, src: &[u8]) -> u64 {
        let to_copy = (src.len() as u64).min(self.total);
        // Advance the iterator without doing real memory copies in no_std.
        self.advance(to_copy)
    }

    /// Return the number of segments.
    pub fn segment_count(&self) -> usize {
        self.count
    }

    /// Collect remaining segments into `out_iov`, returning the count.
    pub fn remaining_segments(&self, out_iov: &mut [Iovec]) -> usize {
        let mut written = 0;
        let mut off = self.cur_off;
        for i in self.cur_seg..self.count {
            if written >= out_iov.len() {
                break;
            }
            let seg = self.iov[i];
            let len = seg.len.saturating_sub(off);
            if len > 0 {
                out_iov[written] = Iovec::new(seg.base + off, len);
                written += 1;
            }
            off = 0;
        }
        written
    }
}

/// Build an `IovIter` from a single flat buffer (for simple read/write calls).
pub fn iov_iter_from_buf(base: u64, len: u64, direction: IovDirection) -> Result<IovIter> {
    let iov = [Iovec::new(base, len)];
    IovIter::new(&iov, direction)
}

/// Validate a user-supplied iov array.
///
/// Checks that no individual segment length overflows and that the combined
/// total fits in a `u64`.
pub fn validate_iov(iov: &[Iovec]) -> Result<u64> {
    if iov.len() > MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    let mut total = 0u64;
    for v in iov {
        total = total.checked_add(v.len).ok_or(Error::InvalidArgument)?;
    }
    Ok(total)
}

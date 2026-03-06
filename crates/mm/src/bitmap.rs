// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bitmap-based physical frame allocator.
//!
//! Uses a fixed-size bitmap where each bit represents one physical
//! page frame. Bit 0 = free, bit 1 = allocated.

use crate::addr::PhysAddr;
use crate::frame::{Frame, FrameAllocator};

/// Maximum number of physical frames the bitmap can track.
///
/// 32768 frames * 4 KiB = 128 MiB of physical memory.
/// This is sufficient for early boot; a more sophisticated allocator
/// can replace this once the kernel heap is available.
pub const MAX_FRAMES: usize = 32768;

/// Number of `u64` words needed for the bitmap.
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// A simple bitmap-based physical frame allocator.
///
/// Each bit in the bitmap corresponds to one 4 KiB frame.
/// `0` = free, `1` = allocated.
pub struct BitmapAllocator {
    /// The bitmap storage.
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of frames managed.
    total_frames: usize,
    /// Number of currently free frames.
    free_count: usize,
    /// Base physical address of the managed region.
    base: PhysAddr,
}

impl BitmapAllocator {
    /// Create a new allocator managing `frame_count` frames starting
    /// at `base`.
    ///
    /// All frames are initially marked as allocated. The caller must
    /// explicitly mark usable regions as free via [`mark_free`].
    pub const fn new(base: PhysAddr, frame_count: usize) -> Self {
        let total = if frame_count > MAX_FRAMES {
            MAX_FRAMES
        } else {
            frame_count
        };
        Self {
            bitmap: [!0u64; BITMAP_WORDS],
            total_frames: total,
            free_count: 0,
            base,
        }
    }

    /// Mark a range of frames as free (available for allocation).
    ///
    /// `start` and `end` are frame indices relative to `base`.
    pub fn mark_range_free(&mut self, start: usize, end: usize) {
        let end = if end > self.total_frames {
            self.total_frames
        } else {
            end
        };
        for idx in start..end {
            let word = idx / 64;
            let bit = idx % 64;
            if self.bitmap[word] & (1 << bit) != 0 {
                self.bitmap[word] &= !(1 << bit);
                self.free_count += 1;
            }
        }
    }

    /// Mark a range of frames as allocated.
    pub fn mark_range_used(&mut self, start: usize, end: usize) {
        let end = if end > self.total_frames {
            self.total_frames
        } else {
            end
        };
        for idx in start..end {
            let word = idx / 64;
            let bit = idx % 64;
            if self.bitmap[word] & (1 << bit) == 0 {
                self.bitmap[word] |= 1 << bit;
                self.free_count = self.free_count.saturating_sub(1);
            }
        }
    }
}

impl FrameAllocator for BitmapAllocator {
    fn allocate_frame(&mut self) -> Option<Frame> {
        // Scan bitmap words for any word with a free bit (not all 1s).
        for (word_idx, word) in self.bitmap[..words_for(self.total_frames)]
            .iter_mut()
            .enumerate()
        {
            if *word == !0u64 {
                continue;
            }
            // Find the first zero bit.
            let bit = (*word).trailing_ones() as usize;
            let frame_idx = word_idx * 64 + bit;
            if frame_idx >= self.total_frames {
                return None;
            }
            // Mark as allocated.
            *word |= 1 << bit;
            self.free_count = self.free_count.saturating_sub(1);
            let addr = self.base.as_u64() + (frame_idx as u64 * 4096);
            return Some(Frame::from_number(addr / 4096));
        }
        None
    }

    fn deallocate_frame(&mut self, frame: Frame) {
        let addr = frame.start_addr().as_u64();
        if addr < self.base.as_u64() {
            return;
        }
        let offset = (addr - self.base.as_u64()) / 4096;
        let idx = offset as usize;
        if idx >= self.total_frames {
            return;
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap[word] & (1 << bit) != 0 {
            self.bitmap[word] &= !(1 << bit);
            self.free_count += 1;
        }
    }

    fn free_frames(&self) -> usize {
        self.free_count
    }
}

/// How many u64 words are needed to cover `n` frames.
const fn words_for(n: usize) -> usize {
    n.div_ceil(64)
}

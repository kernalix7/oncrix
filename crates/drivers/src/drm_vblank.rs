// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM vertical blanking (vblank) management.
//!
//! Provides vblank interrupt tracking, counter management, and client wait
//! queuing for the ONCRIX Direct Rendering Manager (DRM) subsystem. Modelled
//! on Linux DRM's `drm_vblank.c`.

use oncrix_lib::{Error, Result};

/// Maximum number of CRTCs (display pipes) tracked.
pub const DRM_MAX_CRTCS: usize = 4;

/// Maximum number of concurrent vblank waiters per CRTC.
pub const VBLANK_MAX_WAITERS: usize = 16;

/// Vblank counter snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct VblankCounter {
    /// Sequence number (incremented on each vblank interrupt).
    pub seq: u64,
    /// Timestamp of this vblank (nanoseconds, monotonic clock).
    pub ts_ns: u64,
}

/// A single vblank waiter: waits for a specific sequence.
#[derive(Debug, Clone, Copy)]
pub struct VblankWaiter {
    /// CRTC index being waited on.
    pub crtc: usize,
    /// Target sequence number (the waiter is satisfied when counter.seq >= target).
    pub target_seq: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl VblankWaiter {
    /// Creates an inactive waiter.
    pub const fn new() -> Self {
        Self {
            crtc: 0,
            target_seq: 0,
            active: false,
        }
    }
}

impl Default for VblankWaiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CRTC vblank state.
#[derive(Debug)]
pub struct CrtcVblank {
    /// CRTC index.
    pub index: usize,
    /// Whether vblank interrupt is enabled for this CRTC.
    pub enabled: bool,
    /// Current vblank counter.
    pub counter: VblankCounter,
    /// Number of active users holding the vblank interrupt enabled.
    pub use_count: u32,
    /// Waiters queue.
    pub waiters: [VblankWaiter; VBLANK_MAX_WAITERS],
    /// Number of active waiters.
    pub waiter_count: usize,
}

impl CrtcVblank {
    /// Creates a new per-CRTC vblank state.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            enabled: false,
            counter: VblankCounter { seq: 0, ts_ns: 0 },
            use_count: 0,
            waiters: [const {
                VblankWaiter {
                    crtc: 0,
                    target_seq: 0,
                    active: false,
                }
            }; VBLANK_MAX_WAITERS],
            waiter_count: 0,
        }
    }
}

/// DRM vblank manager.
pub struct DrmVblankManager {
    /// Number of CRTCs.
    pub num_crtcs: usize,
    /// Per-CRTC state.
    pub crtcs: [CrtcVblank; DRM_MAX_CRTCS],
}

impl DrmVblankManager {
    /// Creates a new vblank manager for `num_crtcs` display pipes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `num_crtcs > DRM_MAX_CRTCS`.
    pub fn new(num_crtcs: usize) -> Result<Self> {
        if num_crtcs > DRM_MAX_CRTCS {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            num_crtcs,
            crtcs: [const {
                CrtcVblank {
                    index: 0,
                    enabled: false,
                    counter: VblankCounter { seq: 0, ts_ns: 0 },
                    use_count: 0,
                    waiters: [const {
                        VblankWaiter {
                            crtc: 0,
                            target_seq: 0,
                            active: false,
                        }
                    }; VBLANK_MAX_WAITERS],
                    waiter_count: 0,
                }
            }; DRM_MAX_CRTCS],
        })
    }

    /// Called from the CRTC interrupt handler when a vblank fires.
    ///
    /// Updates the counter and wakes any satisfied waiters.
    ///
    /// Returns the number of waiters satisfied.
    pub fn handle_vblank(&mut self, crtc: usize, ts_ns: u64) -> Result<usize> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        let c = &mut self.crtcs[crtc];
        c.counter.seq = c.counter.seq.wrapping_add(1);
        c.counter.ts_ns = ts_ns;
        let mut woken = 0usize;
        for w in c.waiters.iter_mut() {
            if w.active && w.crtc == crtc && c.counter.seq >= w.target_seq {
                w.active = false;
                if c.waiter_count > 0 {
                    c.waiter_count -= 1;
                }
                woken += 1;
            }
        }
        // If no more waiters, disable the vblank interrupt.
        if c.waiter_count == 0 && c.use_count == 0 {
            c.enabled = false;
        }
        Ok(woken)
    }

    /// Enables the vblank interrupt for `crtc` and returns the current sequence.
    pub fn enable(&mut self, crtc: usize) -> Result<u64> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        self.crtcs[crtc].use_count += 1;
        self.crtcs[crtc].enabled = true;
        Ok(self.crtcs[crtc].counter.seq)
    }

    /// Decrements the use count for `crtc`; disables interrupt when it reaches zero.
    pub fn disable(&mut self, crtc: usize) -> Result<()> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        let c = &mut self.crtcs[crtc];
        if c.use_count > 0 {
            c.use_count -= 1;
        }
        if c.use_count == 0 && c.waiter_count == 0 {
            c.enabled = false;
        }
        Ok(())
    }

    /// Registers a waiter that will be satisfied at or after `target_seq` on `crtc`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the waiter queue is full.
    pub fn wait_next(&mut self, crtc: usize, target_seq: u64) -> Result<usize> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        let c = &mut self.crtcs[crtc];
        // If already past target, return immediately.
        if c.counter.seq >= target_seq {
            return Ok(0);
        }
        let slot = c
            .waiters
            .iter()
            .position(|w| !w.active)
            .ok_or(Error::OutOfMemory)?;
        c.waiters[slot] = VblankWaiter {
            crtc,
            target_seq,
            active: true,
        };
        c.waiter_count += 1;
        c.enabled = true;
        Ok(slot)
    }

    /// Returns the current vblank counter for `crtc`.
    pub fn current(&self, crtc: usize) -> Result<VblankCounter> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        Ok(self.crtcs[crtc].counter)
    }

    /// Returns the next sequence number that will be emitted.
    pub fn next_seq(&self, crtc: usize) -> Result<u64> {
        if crtc >= self.num_crtcs {
            return Err(Error::InvalidArgument);
        }
        Ok(self.crtcs[crtc].counter.seq.wrapping_add(1))
    }

    /// Returns true if the vblank interrupt is currently enabled for `crtc`.
    pub fn is_enabled(&self, crtc: usize) -> bool {
        if crtc >= self.num_crtcs {
            return false;
        }
        self.crtcs[crtc].enabled
    }
}

impl Default for DrmVblankManager {
    fn default() -> Self {
        Self::new(1).unwrap_or(Self {
            num_crtcs: 0,
            crtcs: [const {
                CrtcVblank {
                    index: 0,
                    enabled: false,
                    counter: VblankCounter { seq: 0, ts_ns: 0 },
                    use_count: 0,
                    waiters: [const {
                        VblankWaiter {
                            crtc: 0,
                            target_seq: 0,
                            active: false,
                        }
                    }; VBLANK_MAX_WAITERS],
                    waiter_count: 0,
                }
            }; DRM_MAX_CRTCS],
        })
    }
}

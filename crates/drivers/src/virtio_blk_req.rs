// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO block request handling — request queue, virtqueue descriptors,
//! and completion handling.
//!
//! # Protocol Overview
//!
//! A virtio-blk request uses a three-descriptor chain on virtqueue 0:
//!
//! ```text
//! [Descriptor 0: BlkReqHeader (device-readable)]
//!        ↓ next
//! [Descriptor 1: Data buffer  (device-readable for WRITE, device-writable for READ)]
//!        ↓ next
//! [Descriptor 2: Status byte  (device-writable)]
//! ```
//!
//! Software submits the chain head index to the Available Ring and rings
//! the queue doorbell. The device writes a status byte (`0 = OK`, `1 = IO
//! error`, `2 = unsupported`) and places the chain head in the Used Ring.
//!
//! # Queue Model
//!
//! This module maintains a free-list of descriptor slots, a fixed-size
//! in-flight request table, and a simple virtqueue with Available and Used
//! rings — all without heap allocation.
//!
//! Reference: VirtIO Specification v1.2, §5.2 (Block Device); §2.7
//! (Virtqueues).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Virtqueue depth (number of descriptor slots).
pub const QUEUE_DEPTH: usize = 128;

/// Maximum in-flight requests (each uses 3 descriptors).
pub const MAX_INFLIGHT: usize = QUEUE_DEPTH / 3;

/// Sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum sectors per single request (256 KiB).
pub const MAX_SECTORS: u64 = 512;

// Block request types.
/// Read request (device writes data to the buffer).
pub const BLK_T_IN: u32 = 0;
/// Write request (device reads data from the buffer).
pub const BLK_T_OUT: u32 = 1;
/// Flush request (device flushes write cache).
pub const BLK_T_FLUSH: u32 = 4;
/// Get device ID string.
pub const BLK_T_GET_ID: u32 = 8;

// Block request status codes.
/// Request completed successfully.
pub const BLK_S_OK: u8 = 0;
/// I/O error.
pub const BLK_S_IOERR: u8 = 1;
/// Unsupported request.
pub const BLK_S_UNSUPP: u8 = 2;
/// Sentinel — request not yet completed.
pub const BLK_S_PENDING: u8 = 0xFF;

// Virtqueue descriptor flags.
/// Descriptor flag: chain continues (`next` field is valid).
pub const VDESC_NEXT: u16 = 0x01;
/// Descriptor flag: buffer is device-writable (else device-readable).
pub const VDESC_WRITE: u16 = 0x02;

// ---------------------------------------------------------------------------
// Address translation
// ---------------------------------------------------------------------------

/// Convert a virtual address to a physical (DMA bus) address.
///
/// During early boot the kernel uses identity mapping, so virtual and
/// physical addresses are equal. This function is the single callsite
/// that must be updated when a proper virtual-memory layer is enabled.
///
/// # TODO
/// Replace with a real page-table walk or IOMMU translation once the
/// virtual-memory subsystem is fully initialised.
#[inline]
fn virt_to_phys(vaddr: u64) -> u64 {
    // TODO: Implement proper virtual-to-physical translation.
    // Currently assumes identity mapping during early boot; all callers
    // must go through this helper so the transition is a single change.
    vaddr
}

// ---------------------------------------------------------------------------
// Virtqueue descriptor
// ---------------------------------------------------------------------------

/// A single virtqueue descriptor (16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (`VDESC_NEXT`, `VDESC_WRITE`).
    pub flags: u16,
    /// Index of the next descriptor (valid when `VDESC_NEXT` is set).
    pub next: u16,
}

// ---------------------------------------------------------------------------
// Block request header
// ---------------------------------------------------------------------------

/// VirtIO block request header — first descriptor in every chain.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BlkReqHeader {
    /// Request type (`BLK_T_IN`, `BLK_T_OUT`, …).
    pub req_type: u32,
    /// Reserved / IOPRIO (write zero for compatibility).
    pub reserved: u32,
    /// Sector number (512-byte units).
    pub sector: u64,
}

impl BlkReqHeader {
    /// Create a READ header for the given sector.
    pub const fn read(sector: u64) -> Self {
        Self {
            req_type: BLK_T_IN,
            reserved: 0,
            sector,
        }
    }

    /// Create a WRITE header for the given sector.
    pub const fn write(sector: u64) -> Self {
        Self {
            req_type: BLK_T_OUT,
            reserved: 0,
            sector,
        }
    }

    /// Create a FLUSH header (sector must be zero per spec).
    pub const fn flush() -> Self {
        Self {
            req_type: BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// In-flight request
// ---------------------------------------------------------------------------

/// Tracking record for one in-flight block request.
#[derive(Debug, Clone, Copy)]
pub struct InflightEntry {
    /// Head descriptor index in the virtqueue.
    pub head: u16,
    /// Request type (for completion checking).
    pub req_type: u32,
    /// Sector number.
    pub sector: u64,
    /// Number of sectors requested.
    pub sector_count: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl InflightEntry {
    const EMPTY: Self = Self {
        head: 0,
        req_type: 0,
        sector: 0,
        sector_count: 0,
        active: false,
    };
}

// ---------------------------------------------------------------------------
// Available ring
// ---------------------------------------------------------------------------

/// Virtqueue Available Ring (driver → device).
#[derive(Debug)]
pub struct AvailRing {
    /// Flags (0 = normal, 1 = no interrupt).
    pub flags: u16,
    /// Index of the next slot software will write.
    pub idx: u16,
    /// Ring entries (descriptor chain head indices).
    pub ring: [u16; QUEUE_DEPTH],
}

impl AvailRing {
    const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [0u16; QUEUE_DEPTH],
        }
    }

    /// Push a descriptor chain head into the ring and advance the index.
    pub fn push(&mut self, head: u16) {
        let slot = (self.idx as usize) % QUEUE_DEPTH;
        self.ring[slot] = head;
        self.idx = self.idx.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Used ring element
// ---------------------------------------------------------------------------

/// One element in the Used Ring — returned by the device on completion.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UsedElem {
    /// Descriptor chain head index.
    pub id: u32,
    /// Total bytes written by the device.
    pub len: u32,
}

/// Virtqueue Used Ring (device → driver).
#[derive(Debug)]
pub struct UsedRing {
    /// Flags (0 = normal, 1 = no notify).
    pub flags: u16,
    /// Index advanced by the device for each completed chain.
    pub idx: u16,
    /// Ring elements.
    pub ring: [UsedElem; QUEUE_DEPTH],
}

impl UsedRing {
    const fn new() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [UsedElem { id: 0, len: 0 }; QUEUE_DEPTH],
        }
    }
}

// ---------------------------------------------------------------------------
// BlkRequestQueue
// ---------------------------------------------------------------------------

/// VirtIO block device request queue.
///
/// Manages descriptor allocation, request submission, and completion
/// polling for a single virtio-blk virtqueue.
pub struct BlkRequestQueue {
    /// Descriptor table.
    descs: [VirtqDesc; QUEUE_DEPTH],
    /// Available ring.
    avail: AvailRing,
    /// Used ring (written by device).
    used: UsedRing,
    /// Free-list: stack of free descriptor indices.
    free_stack: [u16; QUEUE_DEPTH],
    /// Number of free descriptors.
    free_count: usize,
    /// In-flight request table.
    inflight: [InflightEntry; MAX_INFLIGHT],
    /// Request headers (one per in-flight slot).
    headers: [BlkReqHeader; MAX_INFLIGHT],
    /// Status bytes (one per in-flight slot, written by device).
    status: [u8; MAX_INFLIGHT],
    /// Shadow copy of the used-ring index (tracked by driver).
    last_used_idx: u16,
    /// MMIO base address (for doorbells).
    mmio_base: u64,
    /// Whether the queue is active.
    active: bool,
    /// Per-descriptor in-flight bitmap.
    ///
    /// `desc_inflight[i]` is `true` while descriptor `i` is the head of a
    /// chain currently submitted to the device.  A device-supplied used-ring
    /// `id` that is NOT set here is either a spurious or replayed completion
    /// from a malicious/buggy device and is silently dropped after advancing
    /// `last_used_idx` (no descriptor is freed for it — the driver never
    /// allocated a chain for that index in this cycle).
    desc_inflight: [bool; QUEUE_DEPTH],
}

impl BlkRequestQueue {
    /// Create a new, inactive request queue.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            descs: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; QUEUE_DEPTH],
            avail: AvailRing::new(),
            used: UsedRing::new(),
            free_stack: [0u16; QUEUE_DEPTH],
            free_count: 0,
            inflight: [InflightEntry::EMPTY; MAX_INFLIGHT],
            headers: [BlkReqHeader {
                req_type: 0,
                reserved: 0,
                sector: 0,
            }; MAX_INFLIGHT],
            status: [BLK_S_PENDING; MAX_INFLIGHT],
            last_used_idx: 0,
            mmio_base,
            active: false,
            desc_inflight: [false; QUEUE_DEPTH],
        }
    }

    /// Initialize the queue, populating the free descriptor stack.
    pub fn init(&mut self) {
        for i in 0..QUEUE_DEPTH {
            self.free_stack[i] = i as u16;
        }
        self.free_count = QUEUE_DEPTH;
        self.active = true;
    }

    /// Return the physical address of the descriptor table.
    pub fn desc_addr(&self) -> u64 {
        virt_to_phys(self.descs.as_ptr() as u64)
    }

    /// Return the physical address of the available ring.
    pub fn avail_addr(&self) -> u64 {
        virt_to_phys(&self.avail as *const AvailRing as u64)
    }

    /// Return the physical address of the used ring.
    pub fn used_addr(&self) -> u64 {
        virt_to_phys(&self.used as *const UsedRing as u64)
    }

    /// Submit a READ request.
    ///
    /// `buf` must be at least `sector_count * SECTOR_SIZE` bytes.
    ///
    /// Returns the in-flight slot index. Poll `check_completion(slot)` after
    /// the device signals the interrupt.
    pub fn submit_read(
        &mut self,
        sector: u64,
        sector_count: u64,
        buf: *mut u8,
        buf_len: usize,
    ) -> Result<usize> {
        self.submit(BLK_T_IN, sector, sector_count, buf, buf_len)
    }

    /// Submit a WRITE request.
    ///
    /// `buf` must be at least `sector_count * SECTOR_SIZE` bytes.
    pub fn submit_write(
        &mut self,
        sector: u64,
        sector_count: u64,
        buf: *const u8,
        buf_len: usize,
    ) -> Result<usize> {
        self.submit(BLK_T_OUT, sector, sector_count, buf as *mut u8, buf_len)
    }

    /// Submit a FLUSH request (does not transfer data).
    pub fn submit_flush(&mut self) -> Result<usize> {
        self.submit(BLK_T_FLUSH, 0, 0, core::ptr::null_mut(), 0)
    }

    /// Inner submit helper.
    fn submit(
        &mut self,
        req_type: u32,
        sector: u64,
        sector_count: u64,
        buf: *mut u8,
        buf_len: usize,
    ) -> Result<usize> {
        if !self.active {
            return Err(Error::IoError);
        }
        if req_type != BLK_T_FLUSH && sector_count == 0 {
            return Err(Error::InvalidArgument);
        }
        if sector_count > MAX_SECTORS {
            return Err(Error::InvalidArgument);
        }
        let needed = sector_count as usize * SECTOR_SIZE;
        if req_type != BLK_T_FLUSH && buf_len < needed {
            return Err(Error::InvalidArgument);
        }

        // Allocate an in-flight slot.
        let slot = self.alloc_inflight()?;

        // Allocate 3 (or 2 for flush) descriptors.
        let d0 = self.alloc_desc()?;
        let d1 = self.alloc_desc().map_err(|e| {
            self.free_desc(d0);
            e
        })?;
        let d2 = self.alloc_desc().map_err(|e| {
            self.free_desc(d0);
            self.free_desc(d1);
            e
        })?;

        // Descriptor 0: request header.
        self.headers[slot] = BlkReqHeader {
            req_type,
            reserved: 0,
            sector,
        };
        self.status[slot] = BLK_S_PENDING;
        self.descs[d0 as usize] = VirtqDesc {
            addr: virt_to_phys(&self.headers[slot] as *const BlkReqHeader as u64),
            len: core::mem::size_of::<BlkReqHeader>() as u32,
            flags: VDESC_NEXT,
            next: d1,
        };

        // Descriptor 1: data buffer (skipped for flush with zero-len).
        self.descs[d1 as usize] = VirtqDesc {
            addr: virt_to_phys(buf as u64),
            len: needed as u32,
            flags: if req_type == BLK_T_IN {
                VDESC_WRITE | VDESC_NEXT
            } else {
                VDESC_NEXT
            },
            next: d2,
        };

        // Descriptor 2: status byte.
        self.descs[d2 as usize] = VirtqDesc {
            addr: virt_to_phys(&self.status[slot] as *const u8 as u64),
            len: 1,
            flags: VDESC_WRITE,
            next: 0,
        };

        // Record in-flight.
        self.inflight[slot] = InflightEntry {
            head: d0,
            req_type,
            sector,
            sector_count,
            active: true,
        };
        // SECURITY: Mark this descriptor head as in-flight so that a replayed
        // used-ring entry from a malicious device is detected and dropped in
        // poll_completion (mirrors the VirtioBlk reference pattern).
        self.desc_inflight[d0 as usize] = true;

        // Publish to the available ring.
        self.avail.push(d0);

        // Notify the device via the queue notify MMIO register (offset 0x50).
        // SAFETY: mmio_base is a valid MMIO address provided by the caller;
        // offset 0x50 is the standard VirtIO MMIO queue notify register.
        unsafe {
            core::ptr::write_volatile((self.mmio_base + 0x50) as *mut u32, 0);
        }

        Ok(slot)
    }

    /// Poll the used ring for a completed request matching `slot`.
    ///
    /// Returns `Some(status)` where status is the device-written status byte,
    /// or `None` if the slot has no completion yet.
    ///
    /// # Security hardening
    ///
    /// ## Used-ring-id replay / double-free defence
    ///
    /// `elem.id` in the used ring is device-DMA-writable and can be replayed
    /// by a malicious backend.  Before freeing any descriptors we do an atomic
    /// test-and-clear of `desc_inflight[head]`.  A head that is not set in the
    /// bitmap means the completion is spurious (already processed or never
    /// submitted); we advance `last_used_idx` and skip descriptor freeing for
    /// that entry.  This prevents the free-stack from receiving the same index
    /// twice, which would allow a subsequent alloc to hand out the same
    /// descriptor to two concurrent requests.
    ///
    /// ## u16-wrap livelock defence
    ///
    /// The drain loop is bounded by `used_idx.wrapping_sub(last_used_idx)`
    /// capped at `QUEUE_DEPTH`.  Without this cap, a device that advances
    /// `used.idx` by 65535 before the driver processes any entry would cause
    /// the loop to run 65535 iterations in IRQ context (livelock / stall).
    ///
    /// ## Descriptor-chain aliasing / out-of-range `.next` defence
    ///
    /// The `.next` fields inside descriptors are also device-DMA-writable.
    /// Each hop is bounds-checked against `QUEUE_DEPTH` and checked for
    /// aliasing against all previously seen indices in the chain before being
    /// used as an array index.
    pub fn poll_completion(&mut self, slot: usize) -> Option<u8> {
        if slot >= MAX_INFLIGHT || !self.inflight[slot].active {
            return None;
        }

        // SAFETY: Reading the device-written used ring index with volatile to
        // ensure we observe the device's latest write without compiler reordering.
        let used_idx = unsafe { core::ptr::read_volatile(&self.used.idx as *const u16) };

        // SECURITY: Bound the drain loop by the number of entries the device
        // has produced since we last checked, capped at QUEUE_DEPTH.  A raw
        // `while last != used_idx` loop wraps after 65535 increments; capping
        // at QUEUE_DEPTH prevents a malicious device from stalling the IRQ
        // handler with a near-u16::MAX difference.
        let pending = used_idx.wrapping_sub(self.last_used_idx) as usize;
        let drain_count = pending.min(QUEUE_DEPTH);

        let mut found = false;

        for _ in 0..drain_count {
            let ring_slot = (self.last_used_idx as usize) % QUEUE_DEPTH;
            // SAFETY: `ring_slot` is bounded by QUEUE_DEPTH via modular arithmetic;
            // the used ring is part of the virtqueue DMA region set up during init.
            let elem =
                unsafe { core::ptr::read_volatile(&self.used.ring[ring_slot] as *const UsedElem) };
            // Advance unconditionally — every entry must be consumed regardless
            // of whether it belongs to the requested slot, to keep the shadow
            // index in sync with the device.
            self.last_used_idx = self.last_used_idx.wrapping_add(1);

            // SECURITY: Truncate the 32-bit device-supplied id to u16 to match
            // the descriptor-table index width used throughout this driver.
            let head = elem.id as u16;

            // SECURITY: Atomic test-and-clear on the in-flight bitmap.  If
            // `head` is not currently marked as in-flight the completion is
            // spurious or replayed; we skip descriptor freeing entirely for
            // this entry so the free stack cannot receive a duplicated index.
            // We still advance `last_used_idx` (done above) to avoid stalling.
            if (head as usize) >= QUEUE_DEPTH || !self.desc_inflight[head as usize] {
                // Spurious or replayed completion — drop silently.
                continue;
            }
            // Clear the bitmap exactly once (test-and-clear).
            self.desc_inflight[head as usize] = false;

            // Find the in-flight slot for this head and free its chain.
            // We search all slots rather than only `slot` so that completions
            // for other in-flight requests that happen to appear in the same
            // drain window are also retired correctly, preventing descriptor
            // leaks when a foreign-id entry would otherwise be silently skipped.
            let owner_slot = self.inflight[..MAX_INFLIGHT]
                .iter()
                .position(|e| e.active && e.head == head);

            if let Some(s) = owner_slot {
                // Free the 3-descriptor chain starting at `head`.
                // SECURITY: d1 and d2 are device-DMA-writable `.next` fields.
                // Validate bounds AND aliasing before using as indices.
                let d0 = head;
                let d1 = self.descs[d0 as usize].next;
                if (d1 as usize) >= QUEUE_DEPTH || d1 == d0 {
                    // Chain is corrupt — free only the known-good head.
                    self.free_desc(d0);
                    self.inflight[s].active = false;
                } else {
                    let d2 = self.descs[d1 as usize].next;
                    if (d2 as usize) >= QUEUE_DEPTH || d2 == d0 || d2 == d1 {
                        // SECURITY: d2 out-of-range or aliasing — free d0+d1 only.
                        self.free_desc(d1);
                        self.free_desc(d0);
                        self.inflight[s].active = false;
                    } else {
                        self.free_desc(d2);
                        self.free_desc(d1);
                        self.free_desc(d0);
                        self.inflight[s].active = false;
                    }
                }

                if s == slot {
                    found = true;
                }
            }
            // If no owner slot is found the bitmap entry was already cleared
            // above, so no further action is needed.
        }

        if found { Some(self.status[slot]) } else { None }
    }

    /// Check whether a completed request at `slot` succeeded.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if slot is out of range, `Busy` if the
    /// request is still in flight, or `IoError` if the device reported an
    /// error.
    pub fn check_result(&self, slot: usize) -> Result<()> {
        if slot >= MAX_INFLIGHT {
            return Err(Error::InvalidArgument);
        }
        if self.inflight[slot].active {
            return Err(Error::Busy);
        }
        match self.status[slot] {
            BLK_S_OK => Ok(()),
            BLK_S_PENDING => Err(Error::Busy),
            _ => Err(Error::IoError),
        }
    }

    /// Return the number of free descriptors.
    pub fn free_descriptors(&self) -> usize {
        self.free_count
    }

    /// Return `true` if the queue is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    // -- Descriptor free-list helpers --------------------------------------

    fn alloc_desc(&mut self) -> Result<u16> {
        if self.free_count == 0 {
            return Err(Error::Busy);
        }
        self.free_count -= 1;
        Ok(self.free_stack[self.free_count])
    }

    fn free_desc(&mut self, idx: u16) {
        if self.free_count < QUEUE_DEPTH {
            self.free_stack[self.free_count] = idx;
            self.free_count += 1;
        }
    }

    fn alloc_inflight(&self) -> Result<usize> {
        for (i, entry) in self.inflight.iter().enumerate() {
            if !entry.active {
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_init_free_count() {
        let mut q = BlkRequestQueue::new(0);
        q.init();
        assert_eq!(q.free_descriptors(), QUEUE_DEPTH);
        assert!(q.is_active());
    }

    #[test]
    fn blk_header_types() {
        let r = BlkReqHeader::read(10);
        assert_eq!(r.req_type, BLK_T_IN);
        assert_eq!(r.sector, 10);

        let w = BlkReqHeader::write(20);
        assert_eq!(w.req_type, BLK_T_OUT);

        let f = BlkReqHeader::flush();
        assert_eq!(f.req_type, BLK_T_FLUSH);
        assert_eq!(f.sector, 0);
    }

    #[test]
    fn alloc_desc_free_desc() {
        let mut q = BlkRequestQueue::new(0);
        q.init();
        let d = q.alloc_desc().unwrap();
        assert_eq!(q.free_descriptors(), QUEUE_DEPTH - 1);
        q.free_desc(d);
        assert_eq!(q.free_descriptors(), QUEUE_DEPTH);
    }

    #[test]
    fn inflight_alloc_full() {
        let mut q = BlkRequestQueue::new(0);
        q.init();
        // Mark all inflight slots as active.
        for entry in &mut q.inflight {
            entry.active = true;
        }
        assert!(q.alloc_inflight().is_err());
    }

    #[test]
    fn check_result_pending() {
        let mut q = BlkRequestQueue::new(0);
        q.init();
        // Slot 0 is inactive with PENDING status — should report Busy.
        assert_eq!(q.check_result(0).unwrap_err(), Error::Busy);
    }

    #[test]
    fn flush_header_zero_sector() {
        let f = BlkReqHeader::flush();
        assert_eq!(f.sector, 0);
        assert_eq!(f.reserved, 0);
    }
}

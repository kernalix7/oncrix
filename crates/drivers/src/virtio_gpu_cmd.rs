// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO GPU command processing.
//!
//! Implements the VIRTIO_GPU_CMD_* dispatch layer for the VirtIO GPU device.
//! Commands are submitted via a virtqueue and completions are signaled by
//! fences. This module provides typed command builders and a command
//! dispatcher that serialises requests into the virtqueue descriptor ring.
//!
//! # Supported Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | GET_DISPLAY_INFO | Query display configuration |
//! | RESOURCE_CREATE_2D | Allocate a 2-D resource (framebuffer) |
//! | RESOURCE_FLUSH | Flush resource region to display |
//! | TRANSFER_TO_HOST_2D | Transfer guest memory to host resource |
//! | SET_SCANOUT | Bind resource to a scanout (display head) |
//!
//! Reference: virtio-v1.2, Section 5.7;
//! Linux `drivers/gpu/drm/virtio/virtgpu_vq.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// VirtIO GPU Command Types
// ---------------------------------------------------------------------------

/// Command type: Get display information.
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
/// Command type: Create a 2-D resource.
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
/// Command type: Unreference (destroy) a resource.
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
/// Command type: Set scanout (bind resource to display head).
pub const CMD_SET_SCANOUT: u32 = 0x0103;
/// Command type: Flush a resource to screen.
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
/// Command type: Transfer data from guest to host resource.
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
/// Command type: Attach backing pages to a resource.
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
/// Command type: Detach backing pages from a resource.
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
/// Command type: Update cursor image.
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;

/// Response type: OK — no data.
pub const RESP_OK_NODATA: u32 = 0x1100;
/// Response type: OK — display info payload.
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
/// Response type: Error — unspecified.
pub const RESP_ERR_UNSPEC: u32 = 0x1200;
/// Response type: Error — out of memory.
pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
/// Response type: Error — invalid resource ID.
pub const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1202;

// ---------------------------------------------------------------------------
// Maximum constants
// ---------------------------------------------------------------------------

/// Maximum number of scanouts (display heads).
pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/// Maximum virtqueue descriptor ring depth.
const VQ_RING_DEPTH: usize = 64;

/// Maximum pending fence IDs.
const MAX_FENCES: usize = 64;

/// Maximum resource table entries (simultaneously live resources).
const MAX_RESOURCES: usize = 64;

/// Maximum allowed width or height for a 2-D resource (pixels).
///
/// 16 384 px is the cap from the virtio-gpu spec (virtio-v1.2 §5.7.6.8).
/// Values beyond this indicate a malicious or buggy host.
pub const MAX_RESOURCE_DIM: u32 = 16_384;

/// Maximum number of pixels in a 2-D resource (width * height).
///
/// Caps the total allocation at 256 M pixels (~1 GiB at 4 bpp), preventing
/// overflow in size arithmetic regardless of format.
pub const MAX_RESOURCE_PIXELS: u64 = 256 * 1024 * 1024;

/// Bytes per pixel for all supported formats (all are 32-bit / 4 bytes).
const BYTES_PER_PIXEL: u64 = 4;

/// Maximum backing-store size accepted for a single resource (bytes).
///
/// Derived from `MAX_RESOURCE_PIXELS * BYTES_PER_PIXEL`.
pub const MAX_RESOURCE_BYTES: u64 = MAX_RESOURCE_PIXELS * BYTES_PER_PIXEL;

// ---------------------------------------------------------------------------
// Common header
// ---------------------------------------------------------------------------

/// Common VirtIO GPU command/response header (8 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCtrlHdr {
    /// Command or response type.
    pub hdr_type: u32,
    /// Flags (bit 0 = fence).
    pub flags: u32,
    /// Fence ID (valid when flags bit 0 is set).
    pub fence_id: u64,
    /// Context ID (0 = default).
    pub ctx_id: u32,
    /// Padding.
    pub padding: u32,
}

impl GpuCtrlHdr {
    /// Create a command header with the given type.
    pub const fn cmd(hdr_type: u32) -> Self {
        Self {
            hdr_type,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            padding: 0,
        }
    }

    /// Create a fenced command header.
    pub const fn fenced(hdr_type: u32, fence_id: u64) -> Self {
        Self {
            hdr_type,
            flags: 0x01,
            fence_id,
            ctx_id: 0,
            padding: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Rectangle
// ---------------------------------------------------------------------------

/// A 2-D rectangle.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuRect {
    /// X offset in pixels.
    pub x: u32,
    /// Y offset in pixels.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl GpuRect {
    /// Returns `true` if the rectangle lies entirely within `(res_w, res_h)`.
    ///
    /// All arithmetic is checked to avoid overflow on untrusted wire values.
    pub fn fits_within(&self, res_w: u32, res_h: u32) -> bool {
        // checked_add catches x+width or y+height overflowing u32.
        let x_end = match self.x.checked_add(self.width) {
            Some(v) => v,
            None => return false,
        };
        let y_end = match self.y.checked_add(self.height) {
            Some(v) => v,
            None => return false,
        };
        x_end <= res_w && y_end <= res_h
    }
}

// ---------------------------------------------------------------------------
// Display Info
// ---------------------------------------------------------------------------

/// Per-scanout display mode.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuDisplayOne {
    /// Display rectangle.
    pub rect: GpuRect,
    /// Non-zero if this scanout is enabled.
    pub enabled: u32,
    /// Display flags (reserved, set to 0).
    pub flags: u32,
}

/// Response payload for GET_DISPLAY_INFO.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GpuRespDisplayInfo {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Per-scanout info.
    pub pmodes: [GpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}

impl Default for GpuRespDisplayInfo {
    fn default() -> Self {
        Self {
            hdr: GpuCtrlHdr::default(),
            pmodes: [const {
                GpuDisplayOne {
                    rect: GpuRect {
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                    },
                    enabled: 0,
                    flags: 0,
                }
            }; VIRTIO_GPU_MAX_SCANOUTS],
        }
    }
}

// ---------------------------------------------------------------------------
// Resource Create 2D
// ---------------------------------------------------------------------------

/// Pixel format identifiers (subset of virtio_gpu_formats).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum GpuFormat {
    /// 32-bit BGRA (blue-green-red-alpha).
    #[default]
    Bgra8888 = 1,
    /// 32-bit BGRX (alpha channel unused).
    Bgrx8888 = 2,
    /// 32-bit ARGB.
    Argb8888 = 3,
    /// 32-bit XRGB (alpha unused).
    Xrgb8888 = 4,
}

/// Command: RESOURCE_CREATE_2D.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCmdResourceCreate2d {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Resource ID (caller-assigned, must be unique and non-zero).
    pub resource_id: u32,
    /// Pixel format.
    pub format: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

// ---------------------------------------------------------------------------
// Resource Flush
// ---------------------------------------------------------------------------

/// Command: RESOURCE_FLUSH.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCmdResourceFlush {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Rectangle to flush.
    pub rect: GpuRect,
    /// Resource ID to flush.
    pub resource_id: u32,
    /// Padding.
    pub padding: u32,
}

// ---------------------------------------------------------------------------
// Transfer To Host 2D
// ---------------------------------------------------------------------------

/// Command: TRANSFER_TO_HOST_2D.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCmdTransferToHost2d {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Destination rectangle within the resource.
    pub rect: GpuRect,
    /// Source offset in the backing memory (bytes).
    pub offset: u64,
    /// Resource ID.
    pub resource_id: u32,
    /// Padding.
    pub padding: u32,
}

// ---------------------------------------------------------------------------
// Set Scanout
// ---------------------------------------------------------------------------

/// Command: SET_SCANOUT.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCmdSetScanout {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Rectangle of the resource to display.
    pub rect: GpuRect,
    /// Scanout ID (0 .. VIRTIO_GPU_MAX_SCANOUTS-1).
    pub scanout_id: u32,
    /// Resource ID (0 = disable scanout).
    pub resource_id: u32,
}

// ---------------------------------------------------------------------------
// Resource Unref
// ---------------------------------------------------------------------------

/// Command: RESOURCE_UNREF.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuCmdResourceUnref {
    /// Common header.
    pub hdr: GpuCtrlHdr,
    /// Resource ID to destroy.
    pub resource_id: u32,
    /// Padding.
    pub padding: u32,
}

// ---------------------------------------------------------------------------
// Backing Memory (scatter-gather for resource)
// ---------------------------------------------------------------------------

/// A single backing memory entry for RESOURCE_ATTACH_BACKING.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct GpuMemEntry {
    /// Guest physical address.
    pub addr: u64,
    /// Length in bytes.
    pub length: u32,
    /// Padding.
    pub padding: u32,
}

// ---------------------------------------------------------------------------
// Resource metadata (local tracking)
// ---------------------------------------------------------------------------

/// Kernel-side metadata for a live 2-D resource.
///
/// Populated when `dispatch_resource_create_2d` accepts a command so that
/// subsequent transfer/flush operations can validate their rect/offset
/// arguments without trusting the caller.
#[derive(Debug, Clone, Copy)]
struct ResourceMeta {
    /// Resource ID (non-zero).
    resource_id: u32,
    /// Width in pixels (validated, <= MAX_RESOURCE_DIM).
    width: u32,
    /// Height in pixels (validated, <= MAX_RESOURCE_DIM).
    height: u32,
    /// Total backing store size in bytes (width * height * BYTES_PER_PIXEL).
    backing_bytes: u64,
}

// ---------------------------------------------------------------------------
// Fence tracking
// ---------------------------------------------------------------------------

/// State of a pending GPU fence.
#[derive(Debug, Clone, Copy)]
struct FenceEntry {
    fence_id: u64,
    signaled: bool,
}

// ---------------------------------------------------------------------------
// Virtqueue ring slot
// ---------------------------------------------------------------------------

/// A single virtqueue descriptor ring entry (simplified).
#[derive(Clone, Copy, Default)]
struct VqDesc {
    /// Guest physical address of the command buffer.
    phys: u64,
    /// Length of the command buffer.
    len: u32,
    /// Flags (bit 1 = next, bit 2 = write-only for device).
    flags: u16,
    /// Index of next descriptor (if flags bit 1 set).
    next: u16,
}

// ---------------------------------------------------------------------------
// GPU Command Queue
// ---------------------------------------------------------------------------

/// VirtIO GPU command queue backed by a fixed-size descriptor ring.
pub struct GpuCmdQueue {
    /// Descriptor ring.
    descs: [VqDesc; VQ_RING_DEPTH],
    /// Available ring head index (modulo VQ_RING_DEPTH).
    avail_idx: u16,
    /// Used ring head index (tracks device consumption, modulo VQ_RING_DEPTH).
    used_idx: u16,
    /// Pending fences.
    fences: [Option<FenceEntry>; MAX_FENCES],
    /// Next fence ID to issue.
    next_fence_id: u64,
    /// Total commands submitted.
    pub submit_count: u64,
    /// Live resource metadata table.
    resources: [Option<ResourceMeta>; MAX_RESOURCES],
}

impl GpuCmdQueue {
    /// Create an empty GPU command queue.
    pub const fn new() -> Self {
        const NONE_FENCE: Option<FenceEntry> = None;
        const NONE_RES: Option<ResourceMeta> = None;
        Self {
            descs: [const {
                VqDesc {
                    phys: 0,
                    len: 0,
                    flags: 0,
                    next: 0,
                }
            }; VQ_RING_DEPTH],
            avail_idx: 0,
            used_idx: 0,
            fences: [NONE_FENCE; MAX_FENCES],
            next_fence_id: 1,
            submit_count: 0,
            resources: [NONE_RES; MAX_RESOURCES],
        }
    }

    /// Allocate a new fence ID.
    pub fn alloc_fence(&mut self) -> Result<u64> {
        let slot = self
            .fences
            .iter()
            .position(|f| f.is_none())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_fence_id;
        self.next_fence_id = self.next_fence_id.wrapping_add(1).max(1);
        self.fences[slot] = Some(FenceEntry {
            fence_id: id,
            signaled: false,
        });
        Ok(id)
    }

    /// Signal a fence by ID (called from interrupt handler).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the fence ID is not pending.
    pub fn signal_fence(&mut self, fence_id: u64) -> Result<()> {
        let idx = self
            .fences
            .iter()
            .position(|f| f.map_or(false, |e| e.fence_id == fence_id))
            .ok_or(Error::NotFound)?;
        self.fences[idx] = Some(FenceEntry {
            fence_id,
            signaled: true,
        });
        Ok(())
    }

    /// Returns `true` if the given fence has been signaled.
    pub fn is_fence_signaled(&self, fence_id: u64) -> bool {
        self.fences
            .iter()
            .flatten()
            .any(|e| e.fence_id == fence_id && e.signaled)
    }

    /// Retire a signaled fence, freeing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the fence is unknown.
    /// Returns [`Error::Busy`] if the fence has not been signaled yet.
    pub fn retire_fence(&mut self, fence_id: u64) -> Result<()> {
        let idx = self
            .fences
            .iter()
            .position(|f| f.map_or(false, |e| e.fence_id == fence_id))
            .ok_or(Error::NotFound)?;
        let entry = self.fences[idx].ok_or(Error::NotFound)?;
        if !entry.signaled {
            return Err(Error::Busy);
        }
        self.fences[idx] = None;
        Ok(())
    }

    /// Enqueue a command buffer at `phys_addr` with `len` bytes.
    ///
    /// Returns the descriptor index used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the ring is full.
    pub fn submit(&mut self, phys_addr: u64, len: u32) -> Result<u16> {
        // SAFETY (arithmetic): avail_idx is always kept < VQ_RING_DEPTH.
        // wrapping_add(1) prevents overflow under overflow-checks=on; the
        // subsequent modulo brings it back into ring range.
        let next_avail = self.avail_idx.wrapping_add(1) % VQ_RING_DEPTH as u16;
        if next_avail == self.used_idx {
            return Err(Error::Busy);
        }
        let slot = self.avail_idx as usize;
        self.descs[slot] = VqDesc {
            phys: phys_addr,
            len,
            flags: 0,
            next: 0,
        };
        let idx = self.avail_idx;
        self.avail_idx = next_avail;
        self.submit_count += 1;
        Ok(idx)
    }

    /// Acknowledge that the device has consumed descriptors up to `used_idx`.
    ///
    /// The value comes from the device-visible used ring and is therefore
    /// untrusted.  We validate it against the number of descriptors that were
    /// actually submitted (tracked by `avail_idx`):
    ///
    /// * The advance (number of newly consumed slots) must not exceed the
    ///   number of outstanding submitted-but-unacknowledged descriptors.
    ///   A device that claims to have consumed more than was submitted is
    ///   malicious or buggy.
    ///
    /// The ring indices are kept as ring-modulo values (`0..VQ_RING_DEPTH`).
    /// All arithmetic is done with wrapping operations to stay correct across
    /// the ring boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `used_idx` reflects more
    /// consumed slots than were ever submitted.  The caller should treat the
    /// queue as wedged and reset the device.
    pub fn advance_used(&mut self, used_idx: u16) -> Result<()> {
        let ring = VQ_RING_DEPTH as u16;
        let new_pos = used_idx % ring;

        // How many slots the device claims to have consumed since last ack.
        // wrapping_sub handles the modular ring boundary correctly.
        let advance = new_pos.wrapping_sub(self.used_idx) % ring;

        // How many slots were submitted but not yet acknowledged.
        // avail_idx is always kept in [0, ring) so this is also correct.
        let outstanding = self.avail_idx.wrapping_sub(self.used_idx) % ring;

        // If the device consumed more than was submitted it is lying.
        if advance > outstanding {
            return Err(Error::InvalidArgument);
        }

        self.used_idx = new_pos;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Resource metadata helpers (private)
    // -----------------------------------------------------------------------

    /// Register metadata for a newly created resource.
    ///
    /// Replaces an existing entry for the same `resource_id` if present
    /// (re-create after unref).
    fn register_resource(&mut self, meta: ResourceMeta) -> Result<()> {
        // Replace an existing entry for the same ID first.
        for slot in self.resources.iter_mut() {
            if slot.map_or(false, |m| m.resource_id == meta.resource_id) {
                *slot = Some(meta);
                return Ok(());
            }
        }
        // Find an empty slot.
        let slot = self
            .resources
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(meta);
        Ok(())
    }

    /// Look up resource metadata by ID.
    fn resource_meta(&self, resource_id: u32) -> Option<ResourceMeta> {
        self.resources
            .iter()
            .flatten()
            .find(|m| m.resource_id == resource_id)
            .copied()
    }

    /// Remove resource metadata (called on RESOURCE_UNREF).
    pub fn unregister_resource(&mut self, resource_id: u32) {
        for slot in self.resources.iter_mut() {
            if slot.map_or(false, |m| m.resource_id == resource_id) {
                *slot = None;
                return;
            }
        }
    }
}

impl Default for GpuCmdQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Command Dispatcher
// ---------------------------------------------------------------------------

/// Dispatch result from the GPU command dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchResult {
    /// Command submitted successfully; await fence signal.
    Submitted { fence_id: u64 },
    /// Command submitted without a fence.
    SubmittedNoFence,
}

/// Dispatch a GET_DISPLAY_INFO command.
///
/// `queue` — the GPU command queue.
/// `phys_addr` — DMA address of a `GpuCtrlHdr` + `GpuRespDisplayInfo` buffer.
pub fn dispatch_get_display_info(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
) -> Result<DispatchResult> {
    let len = core::mem::size_of::<GpuCtrlHdr>() as u32;
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::SubmittedNoFence)
}

/// Dispatch a RESOURCE_CREATE_2D command.
///
/// `width` and `height` must each be in `1..=MAX_RESOURCE_DIM`, and
/// `width * height * 4` must not overflow `u64`. Both constraints guard
/// against overflow in DMA-size arithmetic when overflow-checks are enabled
/// in dev/test builds.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if any argument is out of range or if
/// the total pixel count overflows the permitted maximum.
pub fn dispatch_resource_create_2d(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    resource_id: u32,
    format: GpuFormat,
    width: u32,
    height: u32,
) -> Result<DispatchResult> {
    if resource_id == 0 {
        return Err(Error::InvalidArgument);
    }
    // Clamp / reject out-of-range dimensions supplied by the host/caller.
    if width == 0 || width > MAX_RESOURCE_DIM {
        return Err(Error::InvalidArgument);
    }
    if height == 0 || height > MAX_RESOURCE_DIM {
        return Err(Error::InvalidArgument);
    }
    // Checked multiplication prevents width*height*bpp from overflowing.
    let pixels = (width as u64)
        .checked_mul(height as u64)
        .ok_or(Error::InvalidArgument)?;
    // `>=` so the exact maximum (16384*16384 == MAX_RESOURCE_PIXELS, a 1 GiB
    // backing) is also rejected; a single resource that large is excessive.
    if pixels >= MAX_RESOURCE_PIXELS {
        return Err(Error::InvalidArgument);
    }
    let backing_bytes = pixels
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(Error::InvalidArgument)?;

    // Record metadata so later transfer/flush calls can validate their rects.
    queue.register_resource(ResourceMeta {
        resource_id,
        width,
        height,
        backing_bytes,
    })?;

    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdResourceCreate2d>() as u32;
    // In a real driver the struct would be written to the DMA buffer at
    // phys_addr.  Here we validate args and submit the descriptor.
    let _ = (format,);
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

/// Dispatch a RESOURCE_FLUSH command.
///
/// `rect` is validated against the resource dimensions stored when the
/// resource was created. An unknown `resource_id` or an out-of-bounds rect
/// both return [`Error::InvalidArgument`].
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `resource_id` is zero, unknown, or
/// if `rect` extends beyond the resource boundary.
pub fn dispatch_resource_flush(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    resource_id: u32,
    rect: GpuRect,
) -> Result<DispatchResult> {
    if resource_id == 0 {
        return Err(Error::InvalidArgument);
    }
    let meta = queue
        .resource_meta(resource_id)
        .ok_or(Error::InvalidArgument)?;

    // Validate the flush rect lies entirely within the resource boundary.
    if !rect.fits_within(meta.width, meta.height) {
        return Err(Error::InvalidArgument);
    }

    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdResourceFlush>() as u32;
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

/// Dispatch a TRANSFER_TO_HOST_2D command.
///
/// Validates that:
/// * `rect` lies within the resource dimensions, and
/// * `offset + transfer_len` does not exceed the resource backing size,
///   where `transfer_len = rect.width * rect.height * 4` (checked multiply).
///
/// All arithmetic is checked to avoid overflow on untrusted wire values.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if any argument fails validation.
pub fn dispatch_transfer_to_host(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    resource_id: u32,
    rect: GpuRect,
    offset: u64,
) -> Result<DispatchResult> {
    if resource_id == 0 {
        return Err(Error::InvalidArgument);
    }
    let meta = queue
        .resource_meta(resource_id)
        .ok_or(Error::InvalidArgument)?;

    // Validate rect bounds against the resource dimensions.
    if !rect.fits_within(meta.width, meta.height) {
        return Err(Error::InvalidArgument);
    }

    // Compute the byte length of the transfer (checked to avoid overflow).
    let pixels = (rect.width as u64)
        .checked_mul(rect.height as u64)
        .ok_or(Error::InvalidArgument)?;
    let transfer_len = pixels
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(Error::InvalidArgument)?;

    // Validate offset + transfer_len does not exceed the backing store.
    let end = offset
        .checked_add(transfer_len)
        .ok_or(Error::InvalidArgument)?;
    if end > meta.backing_bytes {
        return Err(Error::InvalidArgument);
    }

    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdTransferToHost2d>() as u32;
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

/// Dispatch a SET_SCANOUT command.
pub fn dispatch_set_scanout(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    scanout_id: u32,
    resource_id: u32,
    rect: GpuRect,
) -> Result<DispatchResult> {
    if scanout_id as usize >= VIRTIO_GPU_MAX_SCANOUTS {
        return Err(Error::InvalidArgument);
    }
    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdSetScanout>() as u32;
    let _ = (resource_id, rect);
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: create a queue with one registered resource (64x64, id=1).
    fn queue_with_resource() -> GpuCmdQueue {
        let mut q = GpuCmdQueue::new();
        q.register_resource(ResourceMeta {
            resource_id: 1,
            width: 64,
            height: 64,
            backing_bytes: 64 * 64 * 4,
        })
        .unwrap();
        q
    }

    // -----------------------------------------------------------------------
    // Finding 1 — submit ring-index wrapping
    // -----------------------------------------------------------------------

    /// submit must not panic when avail_idx is at u16 boundary values.
    #[test]
    fn submit_no_overflow_at_ring_boundary() {
        let mut q = GpuCmdQueue::new();
        // Drive avail_idx to VQ_RING_DEPTH - 1 by submitting then acking.
        for _ in 0..(VQ_RING_DEPTH - 1) {
            q.submit(0x1000, 64).unwrap();
        }
        // Ack all consumed so the ring is empty again.
        q.advance_used(q.avail_idx).unwrap();
        // This submit must wrap cleanly without panic.
        let r = q.submit(0x2000, 64);
        assert!(r.is_ok(), "submit at ring boundary must succeed: {r:?}");
    }

    /// A full ring returns Busy.
    #[test]
    fn submit_full_ring_returns_busy() {
        let mut q = GpuCmdQueue::new();
        // Fill ring to capacity (ring_depth - 1 usable slots).
        for _ in 0..(VQ_RING_DEPTH - 1) {
            q.submit(0x1000, 64).unwrap();
        }
        assert_eq!(q.submit(0x2000, 64), Err(Error::Busy));
    }

    // -----------------------------------------------------------------------
    // Finding 2 — dispatch_resource_create_2d overflow checks
    // -----------------------------------------------------------------------

    /// width/height of 0 is rejected.
    #[test]
    fn create_2d_zero_dimensions_rejected() {
        let mut q = GpuCmdQueue::new();
        assert_eq!(
            dispatch_resource_create_2d(&mut q, 0, 1, GpuFormat::Bgra8888, 0, 64),
            Err(Error::InvalidArgument),
        );
        assert_eq!(
            dispatch_resource_create_2d(&mut q, 0, 1, GpuFormat::Bgra8888, 64, 0),
            Err(Error::InvalidArgument),
        );
    }

    /// Dimensions above MAX_RESOURCE_DIM are rejected.
    #[test]
    fn create_2d_excess_dimensions_rejected() {
        let mut q = GpuCmdQueue::new();
        assert_eq!(
            dispatch_resource_create_2d(
                &mut q,
                0,
                1,
                GpuFormat::Bgra8888,
                MAX_RESOURCE_DIM + 1,
                64,
            ),
            Err(Error::InvalidArgument),
        );
        assert_eq!(
            dispatch_resource_create_2d(
                &mut q,
                0,
                1,
                GpuFormat::Bgra8888,
                64,
                MAX_RESOURCE_DIM + 1,
            ),
            Err(Error::InvalidArgument),
        );
    }

    /// Pixel count above MAX_RESOURCE_PIXELS is rejected even if each dim
    /// is individually within MAX_RESOURCE_DIM.
    #[test]
    fn create_2d_pixel_overflow_rejected() {
        let mut q = GpuCmdQueue::new();
        // 16384 * 16384 = 268 435 456 == MAX_RESOURCE_PIXELS (256 M);
        // rejected by the `>=` cap (a 1 GiB single resource is excessive).
        assert_eq!(
            dispatch_resource_create_2d(
                &mut q,
                0,
                1,
                GpuFormat::Bgra8888,
                MAX_RESOURCE_DIM,
                MAX_RESOURCE_DIM,
            ),
            Err(Error::InvalidArgument),
        );
    }

    /// A valid small resource is accepted.
    #[test]
    fn create_2d_valid_accepted() {
        let mut q = GpuCmdQueue::new();
        let r = dispatch_resource_create_2d(&mut q, 0x1000, 1, GpuFormat::Bgra8888, 64, 64);
        assert!(matches!(r, Ok(DispatchResult::Submitted { .. })));
    }

    // -----------------------------------------------------------------------
    // Finding 3 — advance_used monotonicity / over-consumption guard
    // -----------------------------------------------------------------------

    /// A device that claims to have consumed more slots than were submitted is
    /// rejected.  Here: 0 descriptors submitted, device claims 1 consumed.
    #[test]
    fn advance_used_excess_over_submitted_rejected() {
        let mut q = GpuCmdQueue::new();
        // avail_idx = 0, used_idx = 0 → outstanding = 0.
        // Device claims new used_idx = 1 → advance = 1 > 0 = outstanding.
        assert_eq!(q.advance_used(1), Err(Error::InvalidArgument));
    }

    /// A device that acknowledges more than it was given is rejected even at
    /// the ring boundary (advance > outstanding after modular arithmetic).
    #[test]
    fn advance_used_more_than_submitted_rejected() {
        let mut q = GpuCmdQueue::new();
        // Submit 2 descriptors (avail_idx = 2, used_idx = 0 → outstanding = 2).
        q.submit(0x1000, 64).unwrap();
        q.submit(0x2000, 64).unwrap();
        // Device claims 3 consumed — one more than was submitted.
        assert_eq!(q.advance_used(3), Err(Error::InvalidArgument));
    }

    /// A simple valid advance succeeds and updates used_idx.
    #[test]
    fn advance_used_valid() {
        let mut q = GpuCmdQueue::new();
        q.submit(0x1000, 64).unwrap();
        q.submit(0x2000, 64).unwrap();
        // Device consumed 2 descriptors (exactly outstanding).
        assert!(q.advance_used(2).is_ok());
        assert_eq!(q.used_idx, 2);
    }

    /// Idempotent advance (same value twice) is always OK (advance = 0).
    #[test]
    fn advance_used_idempotent() {
        let mut q = GpuCmdQueue::new();
        q.submit(0x1000, 64).unwrap();
        q.advance_used(1).unwrap();
        // Sending the same used_idx again: advance = 0 ≤ 0 = outstanding.
        assert!(q.advance_used(1).is_ok());
    }

    /// Partial advance (consuming fewer than submitted) is always OK.
    #[test]
    fn advance_used_partial() {
        let mut q = GpuCmdQueue::new();
        q.submit(0x1000, 64).unwrap();
        q.submit(0x2000, 64).unwrap();
        q.submit(0x3000, 64).unwrap();
        // Device consumed only 2 of 3 submitted.
        assert!(q.advance_used(2).is_ok());
        assert_eq!(q.used_idx, 2);
    }

    // -----------------------------------------------------------------------
    // Finding 4 — dispatch_transfer_to_host validation
    // -----------------------------------------------------------------------

    /// A rect that fits within the resource is accepted.
    #[test]
    fn transfer_valid_rect_accepted() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: 0,
            y: 0,
            width: 32,
            height: 32,
        };
        let offset = 0u64;
        let r = dispatch_transfer_to_host(&mut q, 0x1000, 1, rect, offset);
        assert!(matches!(r, Ok(DispatchResult::Submitted { .. })));
    }

    /// A rect that exceeds the resource width is rejected.
    #[test]
    fn transfer_out_of_bounds_rect_rejected() {
        let mut q = queue_with_resource();
        // x=32, width=64 → x_end=96 > 64
        let rect = GpuRect {
            x: 32,
            y: 0,
            width: 64,
            height: 32,
        };
        assert_eq!(
            dispatch_transfer_to_host(&mut q, 0x1000, 1, rect, 0),
            Err(Error::InvalidArgument),
        );
    }

    /// An offset that pushes the transfer past the backing size is rejected.
    #[test]
    fn transfer_offset_overflow_rejected() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        // backing = 64*64*4 = 16384; offset=16384 + 1 rect-pixel = 16384+4 > 16384
        let offset = 64 * 64 * 4; // exactly at the end → +4 bytes will exceed
        assert_eq!(
            dispatch_transfer_to_host(&mut q, 0x1000, 1, rect, offset),
            Err(Error::InvalidArgument),
        );
    }

    /// rect with overflow (x + width wraps u32) is rejected.
    #[test]
    fn transfer_rect_coordinate_overflow_rejected() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: u32::MAX,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(
            dispatch_transfer_to_host(&mut q, 0x1000, 1, rect, 0),
            Err(Error::InvalidArgument),
        );
    }

    /// Unknown resource ID is rejected.
    #[test]
    fn transfer_unknown_resource_rejected() {
        let mut q = GpuCmdQueue::new();
        let rect = GpuRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(
            dispatch_transfer_to_host(&mut q, 0x1000, 99, rect, 0),
            Err(Error::InvalidArgument),
        );
    }

    // -----------------------------------------------------------------------
    // Finding 5 — dispatch_resource_flush validation
    // -----------------------------------------------------------------------

    /// A flush rect within the resource is accepted.
    #[test]
    fn flush_valid_rect_accepted() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: 0,
            y: 0,
            width: 64,
            height: 64,
        };
        let r = dispatch_resource_flush(&mut q, 0x1000, 1, rect);
        assert!(matches!(r, Ok(DispatchResult::Submitted { .. })));
    }

    /// A flush rect that is partially out of bounds is rejected.
    #[test]
    fn flush_out_of_bounds_rect_rejected() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: 1,
            y: 0,
            width: 64,
            height: 64,
        };
        assert_eq!(
            dispatch_resource_flush(&mut q, 0x1000, 1, rect),
            Err(Error::InvalidArgument),
        );
    }

    /// Unknown resource ID is rejected.
    #[test]
    fn flush_unknown_resource_rejected() {
        let mut q = GpuCmdQueue::new();
        let rect = GpuRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(
            dispatch_resource_flush(&mut q, 0x1000, 99, rect),
            Err(Error::InvalidArgument),
        );
    }

    /// rect with wrapping coordinate (y + height overflows) is rejected.
    #[test]
    fn flush_rect_y_overflow_rejected() {
        let mut q = queue_with_resource();
        let rect = GpuRect {
            x: 0,
            y: u32::MAX,
            width: 1,
            height: 1,
        };
        assert_eq!(
            dispatch_resource_flush(&mut q, 0x1000, 1, rect),
            Err(Error::InvalidArgument),
        );
    }
}

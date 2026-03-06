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
    /// Available ring head index.
    avail_idx: u16,
    /// Used ring head index (tracks device consumption).
    used_idx: u16,
    /// Pending fences.
    fences: [Option<FenceEntry>; MAX_FENCES],
    /// Next fence ID to issue.
    next_fence_id: u64,
    /// Total commands submitted.
    pub submit_count: u64,
}

impl GpuCmdQueue {
    /// Create an empty GPU command queue.
    pub const fn new() -> Self {
        const NONE: Option<FenceEntry> = None;
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
            fences: [NONE; MAX_FENCES],
            next_fence_id: 1,
            submit_count: 0,
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
        let next_avail = (self.avail_idx + 1) % VQ_RING_DEPTH as u16;
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

    /// Acknowledge that the device has consumed up to `used_idx`.
    pub fn advance_used(&mut self, used_idx: u16) {
        self.used_idx = used_idx % VQ_RING_DEPTH as u16;
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
pub fn dispatch_resource_create_2d(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    resource_id: u32,
    format: GpuFormat,
    width: u32,
    height: u32,
) -> Result<DispatchResult> {
    if resource_id == 0 || width == 0 || height == 0 {
        return Err(Error::InvalidArgument);
    }
    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdResourceCreate2d>() as u32;
    // In a real driver the struct would be written to the DMA buffer at phys_addr.
    // Here we validate args and submit the descriptor.
    let _ = (resource_id, format, width, height);
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

/// Dispatch a RESOURCE_FLUSH command.
pub fn dispatch_resource_flush(
    queue: &mut GpuCmdQueue,
    phys_addr: u64,
    resource_id: u32,
    rect: GpuRect,
) -> Result<DispatchResult> {
    if resource_id == 0 {
        return Err(Error::InvalidArgument);
    }
    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdResourceFlush>() as u32;
    let _ = rect;
    queue.submit(phys_addr, len)?;
    Ok(DispatchResult::Submitted { fence_id })
}

/// Dispatch a TRANSFER_TO_HOST_2D command.
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
    let fence_id = queue.alloc_fence()?;
    let len = core::mem::size_of::<GpuCmdTransferToHost2d>() as u32;
    let _ = (rect, offset);
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

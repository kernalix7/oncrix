// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! V4L2 (Video for Linux 2) video framework for the ONCRIX operating system.
//!
//! Provides a video capture/output device framework with V4L2-compatible
//! abstractions including device and subdevice management, buffer types
//! (MMAP/USERPTR/DMABUF), format negotiation, streaming control, buffer
//! queuing/dequeuing, control infrastructure, device registration, and
//! capability reporting.
//!
//! # Architecture
//!
//! - **V4l2BufType** — buffer transfer type (capture/output)
//! - **V4l2Memory** — buffer memory backing type (MMAP/USERPTR/DMABUF)
//! - **V4l2PixFormat** — pixel format description
//! - **V4l2Buffer** — a single video buffer descriptor
//! - **V4l2BufferQueue** — queue of video buffers for streaming
//! - **V4l2Control** — a device control (brightness, contrast, etc.)
//! - **V4l2Subdev** — a sub-device (sensor, encoder, scaler)
//! - **V4l2Capability** — device capability flags
//! - **V4l2Device** — a V4L2 device with format, buffers, and controls
//! - **V4l2Registry** — manages multiple V4L2 devices
//!
//! Reference: Linux `drivers/media/v4l2-core/`, `include/uapi/linux/videodev2.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum V4L2 devices in the registry.
const MAX_DEVICES: usize = 8;

/// Maximum buffers per buffer queue.
const MAX_BUFFERS: usize = 32;

/// Maximum controls per device.
const MAX_CONTROLS: usize = 32;

/// Maximum sub-devices per device.
const MAX_SUBDEVS: usize = 8;

/// Maximum supported formats per device.
const MAX_FORMATS: usize = 16;

// ---------------------------------------------------------------------------
// Pixel format FourCC codes
// ---------------------------------------------------------------------------

/// YUYV (4:2:2 packed).
pub const V4L2_PIX_FMT_YUYV: u32 = 0x5659_5559;
/// MJPEG compressed.
pub const V4L2_PIX_FMT_MJPEG: u32 = 0x4745_504D;
/// H.264 compressed.
pub const V4L2_PIX_FMT_H264: u32 = 0x3436_3248;
/// RGB24 (3 bytes per pixel).
pub const V4L2_PIX_FMT_RGB24: u32 = 0x3342_4752;
/// NV12 (4:2:0 semi-planar).
pub const V4L2_PIX_FMT_NV12: u32 = 0x3231_564E;

// ---------------------------------------------------------------------------
// V4l2BufType
// ---------------------------------------------------------------------------

/// Buffer transfer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2BufType {
    /// Video capture (camera input).
    #[default]
    VideoCapture,
    /// Video output (display output).
    VideoOutput,
    /// Video overlay.
    VideoOverlay,
    /// Video capture multiplanar.
    VideoCaptureMultiplanar,
    /// Video output multiplanar.
    VideoOutputMultiplanar,
}

// ---------------------------------------------------------------------------
// V4l2Memory
// ---------------------------------------------------------------------------

/// Buffer memory backing type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2Memory {
    /// Memory-mapped buffers (driver allocates, user mmaps).
    #[default]
    Mmap,
    /// User-pointer buffers (user allocates).
    UserPtr,
    /// DMA-BUF shared buffers.
    DmaBuf,
}

// ---------------------------------------------------------------------------
// V4l2Field
// ---------------------------------------------------------------------------

/// Video field order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2Field {
    /// Progressive (non-interlaced).
    #[default]
    None,
    /// Top field only.
    Top,
    /// Bottom field only.
    Bottom,
    /// Interlaced (both fields alternating).
    Interlaced,
}

// ---------------------------------------------------------------------------
// V4l2PixFormat
// ---------------------------------------------------------------------------

/// Pixel format description for a video frame.
#[derive(Debug, Clone, Copy)]
pub struct V4l2PixFormat {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// FourCC pixel format code.
    pub pixelformat: u32,
    /// Field order.
    pub field: V4l2Field,
    /// Bytes per line (stride).
    pub bytesperline: u32,
    /// Total image size in bytes.
    pub sizeimage: u32,
    /// Colour space identifier.
    pub colorspace: u32,
}

/// Constant empty pixel format for array initialisation.
const EMPTY_FMT: V4l2PixFormat = V4l2PixFormat {
    width: 0,
    height: 0,
    pixelformat: 0,
    field: V4l2Field::None,
    bytesperline: 0,
    sizeimage: 0,
    colorspace: 0,
};

impl V4l2PixFormat {
    /// Creates a new pixel format.
    pub fn new(width: u32, height: u32, pixelformat: u32) -> Self {
        let bpp = match pixelformat {
            V4L2_PIX_FMT_RGB24 => 3,
            V4L2_PIX_FMT_YUYV => 2,
            V4L2_PIX_FMT_NV12 => 1, // per-pixel average for planar
            _ => 2,                 // default assumption
        };
        let bytesperline = width * bpp;
        let sizeimage = bytesperline * height;
        Self {
            width,
            height,
            pixelformat,
            field: V4l2Field::None,
            bytesperline,
            sizeimage,
            colorspace: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// V4l2BufferState
// ---------------------------------------------------------------------------

/// State of a video buffer in the streaming pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2BufferState {
    /// Buffer is in the dequeued state (user-owned).
    #[default]
    Dequeued,
    /// Buffer is queued to the driver.
    Queued,
    /// Buffer is being filled/consumed by hardware.
    Active,
    /// Buffer is done and ready to be dequeued.
    Done,
    /// Buffer encountered an error.
    Error,
}

// ---------------------------------------------------------------------------
// V4l2Buffer
// ---------------------------------------------------------------------------

/// A single video buffer descriptor.
#[derive(Debug, Clone, Copy)]
pub struct V4l2Buffer {
    /// Buffer index in the queue.
    pub index: u32,
    /// Buffer type.
    pub buf_type: V4l2BufType,
    /// Memory backing type.
    pub memory: V4l2Memory,
    /// Current buffer state.
    pub state: V4l2BufferState,
    /// Offset for MMAP (filled by driver).
    pub offset: u32,
    /// User-space pointer for USERPTR.
    pub userptr: u64,
    /// DMA-BUF fd for DMABUF.
    pub dmabuf_fd: i32,
    /// Number of bytes used in the buffer.
    pub bytesused: u32,
    /// Total length of the buffer in bytes.
    pub length: u32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Sequence number.
    pub sequence: u32,
}

/// Constant empty buffer for array initialisation.
const EMPTY_BUF: V4l2Buffer = V4l2Buffer {
    index: 0,
    buf_type: V4l2BufType::VideoCapture,
    memory: V4l2Memory::Mmap,
    state: V4l2BufferState::Dequeued,
    offset: 0,
    userptr: 0,
    dmabuf_fd: -1,
    bytesused: 0,
    length: 0,
    timestamp_ns: 0,
    sequence: 0,
};

// ---------------------------------------------------------------------------
// V4l2BufferQueue
// ---------------------------------------------------------------------------

/// Queue of video buffers for streaming.
pub struct V4l2BufferQueue {
    /// Buffer pool.
    buffers: [V4l2Buffer; MAX_BUFFERS],
    /// Number of allocated buffers.
    count: usize,
    /// Buffer type for this queue.
    buf_type: V4l2BufType,
    /// Memory type for this queue.
    memory: V4l2Memory,
    /// Whether streaming is active.
    streaming: bool,
    /// Sequence counter.
    sequence: u32,
}

impl V4l2BufferQueue {
    /// Creates a new empty buffer queue.
    pub const fn new(buf_type: V4l2BufType, memory: V4l2Memory) -> Self {
        Self {
            buffers: [EMPTY_BUF; MAX_BUFFERS],
            count: 0,
            buf_type,
            memory,
            streaming: false,
            sequence: 0,
        }
    }

    /// Requests buffer allocation (VIDIOC_REQBUFS equivalent).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `count` exceeds [`MAX_BUFFERS`]
    /// or is zero.
    pub fn request_buffers(&mut self, count: usize, length: u32) -> Result<usize> {
        if count == 0 || count > MAX_BUFFERS {
            return Err(Error::InvalidArgument);
        }
        self.count = count;
        for i in 0..count {
            self.buffers[i] = V4l2Buffer {
                index: i as u32,
                buf_type: self.buf_type,
                memory: self.memory,
                state: V4l2BufferState::Dequeued,
                offset: (i as u32) * length,
                userptr: 0,
                dmabuf_fd: -1,
                bytesused: 0,
                length,
                timestamp_ns: 0,
                sequence: 0,
            };
        }
        Ok(count)
    }

    /// Queues a buffer to the driver (VIDIOC_QBUF equivalent).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range,
    /// or [`Error::Busy`] if the buffer is not in the dequeued state.
    pub fn qbuf(&mut self, index: u32) -> Result<()> {
        let idx = index as usize;
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        if self.buffers[idx].state != V4l2BufferState::Dequeued {
            return Err(Error::Busy);
        }
        self.buffers[idx].state = V4l2BufferState::Queued;
        Ok(())
    }

    /// Dequeues a completed buffer (VIDIOC_DQBUF equivalent).
    ///
    /// Returns the index of the dequeued buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if no buffer is in the done state.
    pub fn dqbuf(&mut self) -> Result<u32> {
        for buf in &mut self.buffers[..self.count] {
            if buf.state == V4l2BufferState::Done {
                buf.state = V4l2BufferState::Dequeued;
                return Ok(buf.index);
            }
        }
        Err(Error::WouldBlock)
    }

    /// Marks a buffer as done (called by driver when hardware completes).
    pub fn complete_buffer(&mut self, index: u32, bytesused: u32, timestamp_ns: u64) -> Result<()> {
        let idx = index as usize;
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.buffers[idx].bytesused = bytesused;
        self.buffers[idx].timestamp_ns = timestamp_ns;
        self.buffers[idx].sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        self.buffers[idx].state = V4l2BufferState::Done;
        Ok(())
    }

    /// Starts streaming (VIDIOC_STREAMON equivalent).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already streaming, or
    /// [`Error::InvalidArgument`] if no buffers are queued.
    pub fn stream_on(&mut self) -> Result<()> {
        if self.streaming {
            return Err(Error::Busy);
        }
        let queued = self.buffers[..self.count]
            .iter()
            .any(|b| b.state == V4l2BufferState::Queued);
        if !queued {
            return Err(Error::InvalidArgument);
        }
        self.streaming = true;
        // Move queued buffers to active
        for buf in &mut self.buffers[..self.count] {
            if buf.state == V4l2BufferState::Queued {
                buf.state = V4l2BufferState::Active;
            }
        }
        Ok(())
    }

    /// Stops streaming (VIDIOC_STREAMOFF equivalent).
    pub fn stream_off(&mut self) {
        self.streaming = false;
        for buf in &mut self.buffers[..self.count] {
            buf.state = V4l2BufferState::Dequeued;
        }
    }

    /// Returns whether streaming is active.
    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Returns the number of buffers in the given state.
    pub fn count_in_state(&self, state: V4l2BufferState) -> usize {
        self.buffers[..self.count]
            .iter()
            .filter(|b| b.state == state)
            .count()
    }

    /// Returns the number of allocated buffers.
    pub fn buffer_count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// V4l2ControlType
// ---------------------------------------------------------------------------

/// Type of V4L2 control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2ControlType {
    /// Integer control.
    #[default]
    Integer,
    /// Boolean control.
    Boolean,
    /// Menu control (enumeration).
    Menu,
    /// Button control (trigger action).
    Button,
    /// Integer64 control.
    Integer64,
}

// ---------------------------------------------------------------------------
// V4l2Control
// ---------------------------------------------------------------------------

/// A device control (brightness, contrast, saturation, etc.).
#[derive(Debug, Clone, Copy)]
pub struct V4l2Control {
    /// Control identifier.
    pub id: u32,
    /// Control type.
    pub ctrl_type: V4l2ControlType,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// Minimum value.
    pub minimum: i64,
    /// Maximum value.
    pub maximum: i64,
    /// Step size.
    pub step: i64,
    /// Default value.
    pub default_value: i64,
    /// Current value.
    pub value: i64,
}

/// Constant empty control for array initialisation.
const EMPTY_CTRL: V4l2Control = V4l2Control {
    id: 0,
    ctrl_type: V4l2ControlType::Integer,
    name: [0u8; 32],
    name_len: 0,
    minimum: 0,
    maximum: 0,
    step: 0,
    default_value: 0,
    value: 0,
};

impl V4l2Control {
    /// Creates a new integer control.
    pub fn new_integer(id: u32, name: &[u8], min: i64, max: i64, step: i64, default: i64) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            ctrl_type: V4l2ControlType::Integer,
            name: buf,
            name_len: copy_len,
            minimum: min,
            maximum: max,
            step,
            default_value: default,
            value: default,
        }
    }

    /// Sets the control value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the value is out of range.
    pub fn set_value(&mut self, val: i64) -> Result<()> {
        if val < self.minimum || val > self.maximum {
            return Err(Error::InvalidArgument);
        }
        // Snap to step
        if self.step > 0 {
            let offset = val - self.minimum;
            let snapped = self.minimum + (offset / self.step) * self.step;
            self.value = snapped;
        } else {
            self.value = val;
        }
        Ok(())
    }

    /// Resets the control to its default value.
    pub fn reset(&mut self) {
        self.value = self.default_value;
    }
}

// ---------------------------------------------------------------------------
// V4l2SubdevType
// ---------------------------------------------------------------------------

/// Type of V4L2 sub-device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V4l2SubdevType {
    /// Image sensor.
    #[default]
    Sensor,
    /// Video encoder.
    Encoder,
    /// Video decoder.
    Decoder,
    /// Scaler / image processing unit.
    Scaler,
    /// Lens controller.
    Lens,
    /// Flash controller.
    Flash,
}

// ---------------------------------------------------------------------------
// V4l2Subdev
// ---------------------------------------------------------------------------

/// A V4L2 sub-device (sensor, encoder, scaler, etc.).
#[derive(Debug, Clone, Copy)]
pub struct V4l2Subdev {
    /// Sub-device identifier.
    pub id: u32,
    /// Sub-device type.
    pub subdev_type: V4l2SubdevType,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// Whether this sub-device is active.
    pub active: bool,
}

/// Constant empty sub-device for array initialisation.
const EMPTY_SUBDEV: V4l2Subdev = V4l2Subdev {
    id: 0,
    subdev_type: V4l2SubdevType::Sensor,
    name: [0u8; 32],
    name_len: 0,
    active: false,
};

impl V4l2Subdev {
    /// Creates a new sub-device.
    pub fn new(id: u32, subdev_type: V4l2SubdevType, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            subdev_type,
            name: buf,
            name_len: copy_len,
            active: true,
        }
    }
}

// ---------------------------------------------------------------------------
// V4l2Capability
// ---------------------------------------------------------------------------

/// Device capability flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct V4l2Capability(u32);

impl V4l2Capability {
    /// Supports video capture.
    pub const VIDEO_CAPTURE: Self = Self(1 << 0);
    /// Supports video output.
    pub const VIDEO_OUTPUT: Self = Self(1 << 1);
    /// Supports video overlay.
    pub const VIDEO_OVERLAY: Self = Self(1 << 2);
    /// Supports streaming I/O.
    pub const STREAMING: Self = Self(1 << 4);
    /// Supports read/write I/O.
    pub const READWRITE: Self = Self(1 << 5);
    /// Supports multiplanar formats.
    pub const VIDEO_CAPTURE_MPLANE: Self = Self(1 << 12);
    /// Supports multiplanar output.
    pub const VIDEO_OUTPUT_MPLANE: Self = Self(1 << 13);

    /// Returns whether the given capability is set.
    pub fn contains(self, cap: Self) -> bool {
        self.0 & cap.0 != 0
    }

    /// Adds a capability.
    pub fn set(&mut self, cap: Self) {
        self.0 |= cap.0;
    }

    /// Returns the raw capability flags.
    pub fn bits(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// V4l2Device
// ---------------------------------------------------------------------------

/// A V4L2 video device with format negotiation, buffering, and controls.
pub struct V4l2Device {
    /// Device identifier.
    pub id: u32,
    /// Device name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// Device capabilities.
    pub caps: V4l2Capability,
    /// Current pixel format.
    pub format: V4l2PixFormat,
    /// Supported pixel formats (FourCC codes).
    pub supported_formats: [V4l2PixFormat; MAX_FORMATS],
    /// Number of supported formats.
    pub format_count: usize,
    /// Buffer queue.
    pub queue: V4l2BufferQueue,
    /// Device controls.
    pub controls: [V4l2Control; MAX_CONTROLS],
    /// Number of controls.
    pub control_count: usize,
    /// Sub-devices.
    pub subdevs: [V4l2Subdev; MAX_SUBDEVS],
    /// Number of sub-devices.
    pub subdev_count: usize,
    /// Whether the device is open.
    pub opened: bool,
}

impl V4l2Device {
    /// Creates a new V4L2 device.
    pub fn new(id: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            caps: V4l2Capability::default(),
            format: EMPTY_FMT,
            supported_formats: [EMPTY_FMT; MAX_FORMATS],
            format_count: 0,
            queue: V4l2BufferQueue::new(V4l2BufType::VideoCapture, V4l2Memory::Mmap),
            controls: [EMPTY_CTRL; MAX_CONTROLS],
            control_count: 0,
            subdevs: [EMPTY_SUBDEV; MAX_SUBDEVS],
            subdev_count: 0,
            opened: false,
        }
    }

    /// Opens the device for use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already opened.
    pub fn open(&mut self) -> Result<()> {
        if self.opened {
            return Err(Error::Busy);
        }
        self.opened = true;
        Ok(())
    }

    /// Closes the device, stopping any active stream.
    pub fn close(&mut self) {
        if self.queue.is_streaming() {
            self.queue.stream_off();
        }
        self.opened = false;
    }

    /// Adds a supported pixel format.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all format slots are used.
    pub fn add_format(&mut self, fmt: V4l2PixFormat) -> Result<()> {
        if self.format_count >= MAX_FORMATS {
            return Err(Error::OutOfMemory);
        }
        self.supported_formats[self.format_count] = fmt;
        self.format_count += 1;
        Ok(())
    }

    /// Sets the current format (VIDIOC_S_FMT equivalent).
    ///
    /// The format must match a supported format's pixel format code.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the pixel format is not
    /// supported, or [`Error::Busy`] if streaming is active.
    pub fn set_format(&mut self, fmt: V4l2PixFormat) -> Result<()> {
        if self.queue.is_streaming() {
            return Err(Error::Busy);
        }
        let supported = self.supported_formats[..self.format_count]
            .iter()
            .any(|f| f.pixelformat == fmt.pixelformat);
        if !supported && self.format_count > 0 {
            return Err(Error::InvalidArgument);
        }
        self.format = fmt;
        Ok(())
    }

    /// Returns the current format (VIDIOC_G_FMT equivalent).
    pub fn get_format(&self) -> &V4l2PixFormat {
        &self.format
    }

    /// Adds a control to the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all control slots are used.
    pub fn add_control(&mut self, ctrl: V4l2Control) -> Result<()> {
        if self.control_count >= MAX_CONTROLS {
            return Err(Error::OutOfMemory);
        }
        self.controls[self.control_count] = ctrl;
        self.control_count += 1;
        Ok(())
    }

    /// Gets a control value by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the control ID is not found.
    pub fn get_control(&self, ctrl_id: u32) -> Result<i64> {
        for ctrl in &self.controls[..self.control_count] {
            if ctrl.id == ctrl_id {
                return Ok(ctrl.value);
            }
        }
        Err(Error::NotFound)
    }

    /// Sets a control value by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the control ID is not found, or
    /// [`Error::InvalidArgument`] if the value is out of range.
    pub fn set_control(&mut self, ctrl_id: u32, value: i64) -> Result<()> {
        for ctrl in &mut self.controls[..self.control_count] {
            if ctrl.id == ctrl_id {
                return ctrl.set_value(value);
            }
        }
        Err(Error::NotFound)
    }

    /// Registers a sub-device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all sub-device slots are used.
    pub fn add_subdev(&mut self, subdev: V4l2Subdev) -> Result<()> {
        if self.subdev_count >= MAX_SUBDEVS {
            return Err(Error::OutOfMemory);
        }
        self.subdevs[self.subdev_count] = subdev;
        self.subdev_count += 1;
        Ok(())
    }

    /// Returns a reference to a sub-device by ID.
    pub fn get_subdev(&self, subdev_id: u32) -> Result<&V4l2Subdev> {
        for sd in &self.subdevs[..self.subdev_count] {
            if sd.id == subdev_id && sd.active {
                return Ok(sd);
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// V4l2Registry
// ---------------------------------------------------------------------------

/// Registry managing multiple V4L2 devices.
pub struct V4l2Registry {
    /// Registered devices.
    devices: [Option<V4l2Device>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl V4l2Registry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a V4L2 device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same ID exists.
    pub fn register(&mut self, device: V4l2Device) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a device by ID.
    pub fn get(&self, device_id: u32) -> Result<&V4l2Device> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device_id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a device by ID.
    pub fn get_mut(&mut self, device_id: u32) -> Result<&mut V4l2Device> {
        for slot in self.devices.iter_mut() {
            if let Some(d) = slot {
                if d.id == device_id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ALSA PCM audio abstraction layer.
//!
//! Provides PCM stream management including format/rate/channel configuration,
//! ring buffer management with hardware/application pointer tracking,
//! state machine for stream lifecycle, and a PCM ops trait for hardware backends.
//!
//! # Architecture
//!
//! ```text
//! User space (write/read)
//!        ↓
//! PcmSubstream (ring buffer, state machine)
//!        ↓
//! PcmOps trait (backend: HDA, VirtIO-snd, etc.)
//!        ↓
//! Hardware DMA engine
//! ```
//!
//! Reference: ALSA Project documentation, Linux kernel sound/core/pcm*.c.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// PCM Stream Direction
// ---------------------------------------------------------------------------

/// PCM stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmStream {
    /// Playback stream (host → device → speaker).
    Playback,
    /// Capture stream (microphone → device → host).
    Capture,
}

impl PcmStream {
    /// Returns the canonical name for this stream direction.
    pub fn name(self) -> &'static str {
        match self {
            PcmStream::Playback => "Playback",
            PcmStream::Capture => "Capture",
        }
    }
}

// ---------------------------------------------------------------------------
// PCM Sample Format
// ---------------------------------------------------------------------------

/// PCM sample format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmFormat {
    /// Signed 8-bit.
    S8,
    /// Unsigned 8-bit.
    U8,
    /// Signed 16-bit little-endian.
    S16Le,
    /// Signed 16-bit big-endian.
    S16Be,
    /// Unsigned 16-bit little-endian.
    U16Le,
    /// Signed 20-bit (packed in 3 bytes) little-endian.
    S20Le,
    /// Signed 24-bit (packed in 3 bytes) little-endian.
    S24Le,
    /// Signed 24-bit (packed in 4 bytes, MSB-justified) little-endian.
    S24_3Le,
    /// Signed 32-bit little-endian.
    S32Le,
    /// 32-bit IEEE 754 float little-endian.
    FloatLe,
    /// 64-bit IEEE 754 double little-endian.
    Float64Le,
    /// IEC-958 subframe little-endian.
    IEC958SubframeLe,
}

impl PcmFormat {
    /// Returns the sample size in bytes for this format.
    pub fn sample_bytes(self) -> usize {
        match self {
            PcmFormat::S8 | PcmFormat::U8 => 1,
            PcmFormat::S16Le | PcmFormat::S16Be | PcmFormat::U16Le => 2,
            PcmFormat::S20Le | PcmFormat::S24Le | PcmFormat::S24_3Le => 3,
            PcmFormat::S32Le | PcmFormat::FloatLe | PcmFormat::IEC958SubframeLe => 4,
            PcmFormat::Float64Le => 8,
        }
    }

    /// Returns whether this format is signed.
    pub fn is_signed(self) -> bool {
        !matches!(self, PcmFormat::U8 | PcmFormat::U16Le)
    }

    /// Returns whether this format uses little-endian byte order.
    pub fn is_little_endian(self) -> bool {
        !matches!(self, PcmFormat::S16Be)
    }

    /// Returns the format name string.
    pub fn name(self) -> &'static str {
        match self {
            PcmFormat::S8 => "S8",
            PcmFormat::U8 => "U8",
            PcmFormat::S16Le => "S16_LE",
            PcmFormat::S16Be => "S16_BE",
            PcmFormat::U16Le => "U16_LE",
            PcmFormat::S20Le => "S20_LE",
            PcmFormat::S24Le => "S24_LE",
            PcmFormat::S24_3Le => "S24_3LE",
            PcmFormat::S32Le => "S32_LE",
            PcmFormat::FloatLe => "FLOAT_LE",
            PcmFormat::Float64Le => "FLOAT64_LE",
            PcmFormat::IEC958SubframeLe => "IEC958_SUBFRAME_LE",
        }
    }
}

// ---------------------------------------------------------------------------
// PCM Hardware Parameters
// ---------------------------------------------------------------------------

/// Maximum buffer size in bytes accepted from an untrusted hw_params value (256 MiB).
///
/// Any combination of `buffer_size * bytes_per_frame` or `period_size *
/// bytes_per_frame` that would exceed this limit is rejected by
/// [`PcmHwParams::is_valid`] before any byte-count is computed.
pub const MAX_BUFFER_BYTES: u32 = 256 * 1024 * 1024;

/// PCM hardware configuration parameters.
#[derive(Debug, Clone, Copy)]
pub struct PcmHwParams {
    /// Sample format.
    pub format: PcmFormat,
    /// Sample rate in Hz.
    pub rate: u32,
    /// Number of channels.
    pub channels: u32,
    /// Period size in frames (frames per interrupt/callback).
    pub period_size: u32,
    /// Buffer size in frames (total ring buffer size).
    pub buffer_size: u32,
    /// Number of periods per buffer.
    pub periods: u32,
}

impl PcmHwParams {
    /// Creates default stereo 48 kHz 16-bit PCM parameters.
    pub const fn default_stereo_48k() -> Self {
        Self {
            format: PcmFormat::S16Le,
            rate: 48000,
            channels: 2,
            period_size: 1024,
            buffer_size: 4096,
            periods: 4,
        }
    }

    /// Returns bytes per frame (channels × bytes per sample).
    ///
    /// Returns `None` on arithmetic overflow (channels or format size
    /// too large for a `u32`).
    pub fn bytes_per_frame(&self) -> Option<u32> {
        self.channels.checked_mul(self.format.sample_bytes() as u32)
    }

    /// Returns bytes per period, or `None` on overflow.
    ///
    /// Callers should first verify [`is_valid`](Self::is_valid) returns
    /// `true`, which guarantees this value is bounded by
    /// [`MAX_BUFFER_BYTES`].
    pub fn bytes_per_period(&self) -> Option<u32> {
        let bpf = self.bytes_per_frame()?;
        self.period_size.checked_mul(bpf)
    }

    /// Returns total buffer size in bytes, or `None` on overflow.
    ///
    /// Callers should first verify [`is_valid`](Self::is_valid) returns
    /// `true`, which guarantees this value is bounded by
    /// [`MAX_BUFFER_BYTES`].
    pub fn buffer_bytes(&self) -> Option<u32> {
        let bpf = self.bytes_per_frame()?;
        self.buffer_size.checked_mul(bpf)
    }

    /// Returns the period duration in microseconds.
    pub fn period_us(&self) -> u32 {
        if self.rate == 0 {
            return 0;
        }
        (self.period_size as u64 * 1_000_000 / self.rate as u64) as u32
    }

    /// Validates that parameters are within sensible bounds.
    ///
    /// This function is guaranteed to be panic-free: every arithmetic
    /// operation uses [`checked_mul`](u32::checked_mul) so an
    /// overflow returns `false` instead of triggering a ring-0 panic.
    ///
    /// Additionally, `buffer_bytes()` must be `<= MAX_BUFFER_BYTES`
    /// (256 MiB) to prevent oversized DMA allocations.
    pub fn is_valid(&self) -> bool {
        // Basic range checks (no arithmetic yet).
        if self.rate == 0
            || self.channels == 0
            || self.channels > 32
            || self.period_size == 0
            || self.periods < 2
        {
            return false;
        }

        // period_size * periods must equal buffer_size (checked).
        let computed_buf = match self.period_size.checked_mul(self.periods) {
            Some(v) => v,
            None => return false,
        };
        if self.buffer_size != computed_buf || self.buffer_size < self.period_size {
            return false;
        }

        // buffer_bytes must be representable and <= MAX_BUFFER_BYTES.
        match self.buffer_bytes() {
            Some(bytes) => bytes <= MAX_BUFFER_BYTES,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// PCM State Machine
// ---------------------------------------------------------------------------

/// PCM substream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmState {
    /// Stream is open but not configured.
    Open,
    /// Hardware parameters are set.
    Setup,
    /// Stream is prepared (buffers allocated, DMA set up).
    Prepared,
    /// Stream is actively running (DMA in progress).
    Running,
    /// Buffer underrun (playback) or overrun (capture) occurred.
    Xrun,
    /// Drain in progress (waiting for playback to finish).
    Draining,
    /// Stream is paused.
    Paused,
    /// Stream is suspended (e.g., system sleep).
    Suspended,
    /// Stream has been disconnected (device removed).
    Disconnected,
}

impl PcmState {
    /// Returns the state name string.
    pub fn name(self) -> &'static str {
        match self {
            PcmState::Open => "OPEN",
            PcmState::Setup => "SETUP",
            PcmState::Prepared => "PREPARED",
            PcmState::Running => "RUNNING",
            PcmState::Xrun => "XRUN",
            PcmState::Draining => "DRAINING",
            PcmState::Paused => "PAUSED",
            PcmState::Suspended => "SUSPENDED",
            PcmState::Disconnected => "DISCONNECTED",
        }
    }

    /// Returns whether streaming (DMA) should be active in this state.
    pub fn is_active(self) -> bool {
        matches!(self, PcmState::Running | PcmState::Draining)
    }
}

// ---------------------------------------------------------------------------
// Trigger Commands
// ---------------------------------------------------------------------------

/// PCM trigger command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmTrigger {
    /// Start DMA transfer.
    Start,
    /// Stop DMA transfer immediately.
    Stop,
    /// Pause DMA transfer.
    Pause,
    /// Resume paused DMA transfer.
    Resume,
    /// Drain remaining playback data, then stop.
    Drain,
}

// ---------------------------------------------------------------------------
// PCM Ops Trait
// ---------------------------------------------------------------------------

/// PCM hardware backend operations.
///
/// Hardware drivers implement this trait to back a PCM substream.
pub trait PcmOps {
    /// Opens the PCM device. Called when a stream is first opened.
    fn open(&mut self, stream: PcmStream) -> Result<()>;

    /// Closes the PCM device. Called when the stream is closed.
    fn close(&mut self, stream: PcmStream) -> Result<()>;

    /// Sets hardware parameters. The driver programs the DMA engine.
    fn hw_params(&mut self, stream: PcmStream, params: &PcmHwParams) -> Result<()>;

    /// Frees hardware resources allocated in `hw_params`.
    fn hw_free(&mut self, stream: PcmStream) -> Result<()>;

    /// Prepares the stream for playback/capture (e.g., resets DMA pointers).
    fn prepare(&mut self, stream: PcmStream) -> Result<()>;

    /// Sends a trigger command to start, stop, pause, or resume the stream.
    fn trigger(&mut self, stream: PcmStream, cmd: PcmTrigger) -> Result<()>;

    /// Returns the current hardware pointer position in frames.
    ///
    /// This is called from the period interrupt handler to update `hw_ptr`.
    fn pointer(&mut self, stream: PcmStream) -> u32;
}

// ---------------------------------------------------------------------------
// Ring Buffer
// ---------------------------------------------------------------------------

/// PCM ring buffer state tracker (pointer management only — no data storage).
///
/// The actual sample data is stored in DMA-coherent memory allocated
/// by the hardware driver. This struct tracks pointers into that buffer.
pub struct PcmRingBuffer {
    /// Hardware pointer: position where hardware is currently reading/writing.
    pub hw_ptr: u64,
    /// Application pointer: position where user-space last read/wrote.
    pub appl_ptr: u64,
    /// Buffer size in frames.
    pub buffer_size: u32,
    /// Period size in frames.
    pub period_size: u32,
    /// Boundary: first value past which pointers wrap (multiple of buffer_size).
    pub boundary: u64,
    /// Total bytes transferred since stream start.
    pub bytes_transferred: u64,
    /// Number of xrun events (underruns/overruns).
    pub xrun_count: u32,
    /// Number of periods elapsed since stream start.
    pub period_count: u64,
}

impl PcmRingBuffer {
    /// Creates a new ring buffer tracker for the given hw params.
    pub fn new(params: &PcmHwParams) -> Self {
        // Boundary is the smallest power-of-two multiple of buffer_size
        // that is >= 2^31 frames (to allow 64-bit wrap detection).
        let boundary = compute_boundary(params.buffer_size as u64);
        Self {
            hw_ptr: 0,
            appl_ptr: 0,
            buffer_size: params.buffer_size,
            period_size: params.period_size,
            boundary,
            bytes_transferred: 0,
            xrun_count: 0,
            period_count: 0,
        }
    }

    /// Updates the hardware pointer from the driver's `pointer()` callback.
    ///
    /// Returns true if at least one period has elapsed since the last update.
    pub fn update_hw_ptr(&mut self, new_hw_pos: u32) -> bool {
        let old_hw_pos = (self.hw_ptr % self.boundary) as u32 % self.buffer_size;
        if new_hw_pos == old_hw_pos {
            return false;
        }

        let delta = if new_hw_pos >= old_hw_pos {
            (new_hw_pos - old_hw_pos) as u64
        } else {
            (self.buffer_size - old_hw_pos + new_hw_pos) as u64
        };

        self.hw_ptr = (self.hw_ptr + delta) % self.boundary;
        let old_periods = self.period_count;
        self.period_count = self.hw_ptr / self.period_size as u64;
        self.bytes_transferred += delta;

        self.period_count > old_periods
    }

    /// Returns the number of available frames for playback (space to write).
    pub fn avail_playback(&self) -> u32 {
        let hw = self.hw_ptr % self.buffer_size as u64;
        let appl = self.appl_ptr % self.buffer_size as u64;
        let avail = if appl <= hw {
            hw - appl
        } else {
            self.buffer_size as u64 - appl + hw
        };
        avail as u32
    }

    /// Returns the number of available frames for capture (data to read).
    pub fn avail_capture(&self) -> u32 {
        let hw = self.hw_ptr % self.buffer_size as u64;
        let appl = self.appl_ptr % self.buffer_size as u64;
        let avail = if hw >= appl {
            hw - appl
        } else {
            self.buffer_size as u64 - appl + hw
        };
        avail as u32
    }

    /// Advances the application pointer by `frames`.
    pub fn advance_appl_ptr(&mut self, frames: u32) {
        self.appl_ptr = (self.appl_ptr + frames as u64) % self.boundary;
    }

    /// Resets both pointers to zero (used in prepare).
    pub fn reset(&mut self) {
        self.hw_ptr = 0;
        self.appl_ptr = 0;
        self.bytes_transferred = 0;
        self.period_count = 0;
    }

    /// Records an xrun event.
    pub fn record_xrun(&mut self) {
        self.xrun_count = self.xrun_count.saturating_add(1);
    }
}

/// Computes the pointer boundary (smallest multiple of `buf_size` >= 2^31).
fn compute_boundary(buf_size: u64) -> u64 {
    const MIN_BOUNDARY: u64 = 1u64 << 31;
    // A zero buffer size would spin this loop forever (0 * 2 == 0, ring-0 hang)
    // and yield a zero boundary that is later used as a modulus (div-by-zero).
    // The wired set_hw_params path rejects buffer_size == 0 via is_valid(), but
    // the pub PcmRingBuffer::new constructor can be called directly, so guard
    // here at the choke point.
    if buf_size == 0 {
        return MIN_BOUNDARY;
    }
    let mut boundary = buf_size;
    while boundary < MIN_BOUNDARY {
        boundary *= 2;
    }
    boundary
}

// ---------------------------------------------------------------------------
// PCM Substream
// ---------------------------------------------------------------------------

/// A PCM substream: one direction (playback or capture) of a PCM device.
pub struct PcmSubstream {
    /// Stream direction.
    pub stream: PcmStream,
    /// Current state machine state.
    pub state: PcmState,
    /// Configured hardware parameters (valid in Setup state and beyond).
    pub hw_params: Option<PcmHwParams>,
    /// Ring buffer state.
    pub ring_buf: Option<PcmRingBuffer>,
    /// Physical address of the DMA ring buffer.
    pub dma_buf_phys: u64,
    /// Total DMA buffer size in bytes.
    pub dma_buf_size: u32,
    /// Substream index within the PCM device.
    pub index: u32,
    /// Number of open file descriptors.
    open_count: u32,
}

impl PcmSubstream {
    /// Creates a new PCM substream.
    pub fn new(stream: PcmStream, index: u32) -> Self {
        Self {
            stream,
            state: PcmState::Open,
            hw_params: None,
            ring_buf: None,
            dma_buf_phys: 0,
            dma_buf_size: 0,
            index,
            open_count: 0,
        }
    }

    /// Opens the substream (increments open count).
    pub fn open(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.state != PcmState::Open && self.open_count > 0 {
            return Err(Error::Busy);
        }
        ops.open(self.stream)?;
        self.open_count += 1;
        self.state = PcmState::Open;
        Ok(())
    }

    /// Closes the substream (decrements open count, frees hardware resources).
    pub fn close(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.open_count == 0 {
            return Err(Error::InvalidArgument);
        }
        ops.close(self.stream)?;
        self.open_count -= 1;
        if self.open_count == 0 {
            self.hw_params = None;
            self.ring_buf = None;
            self.state = PcmState::Open;
        }
        Ok(())
    }

    /// Sets hardware parameters and transitions to Setup state.
    pub fn set_hw_params(&mut self, ops: &mut dyn PcmOps, params: PcmHwParams) -> Result<()> {
        if !matches!(self.state, PcmState::Open | PcmState::Setup) {
            return Err(Error::Busy);
        }
        if !params.is_valid() {
            return Err(Error::InvalidArgument);
        }
        ops.hw_params(self.stream, &params)?;
        // is_valid() guarantees buffer_bytes() is Some and <= MAX_BUFFER_BYTES.
        self.dma_buf_size = params.buffer_bytes().ok_or(Error::InvalidArgument)?;
        self.ring_buf = Some(PcmRingBuffer::new(&params));
        self.hw_params = Some(params);
        self.state = PcmState::Setup;
        Ok(())
    }

    /// Frees hardware resources and transitions back to Open.
    pub fn free_hw_params(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.state == PcmState::Running {
            return Err(Error::Busy);
        }
        ops.hw_free(self.stream)?;
        self.hw_params = None;
        self.ring_buf = None;
        self.dma_buf_size = 0;
        self.state = PcmState::Open;
        Ok(())
    }

    /// Prepares the stream for playback/capture.
    pub fn prepare(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if !matches!(
            self.state,
            PcmState::Setup | PcmState::Prepared | PcmState::Xrun
        ) {
            return Err(Error::InvalidArgument);
        }
        if let Some(rb) = &mut self.ring_buf {
            rb.reset();
        }
        ops.prepare(self.stream)?;
        self.state = PcmState::Prepared;
        Ok(())
    }

    /// Starts the stream (transitions to Running).
    pub fn start(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.state != PcmState::Prepared {
            return Err(Error::InvalidArgument);
        }
        ops.trigger(self.stream, PcmTrigger::Start)?;
        self.state = PcmState::Running;
        Ok(())
    }

    /// Stops the stream immediately.
    pub fn stop(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if !self.state.is_active() {
            return Err(Error::InvalidArgument);
        }
        ops.trigger(self.stream, PcmTrigger::Stop)?;
        self.state = PcmState::Setup;
        Ok(())
    }

    /// Pauses the stream.
    pub fn pause(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.state != PcmState::Running {
            return Err(Error::InvalidArgument);
        }
        ops.trigger(self.stream, PcmTrigger::Pause)?;
        self.state = PcmState::Paused;
        Ok(())
    }

    /// Resumes a paused stream.
    pub fn resume(&mut self, ops: &mut dyn PcmOps) -> Result<()> {
        if self.state != PcmState::Paused {
            return Err(Error::InvalidArgument);
        }
        ops.trigger(self.stream, PcmTrigger::Resume)?;
        self.state = PcmState::Running;
        Ok(())
    }

    /// Handles a period elapsed interrupt.
    ///
    /// Updates the hardware pointer and returns true if the caller should
    /// notify the application (a full period has elapsed).
    pub fn period_elapsed(&mut self, ops: &mut dyn PcmOps) -> bool {
        if self.state != PcmState::Running {
            return false;
        }
        let hw_pos = ops.pointer(self.stream);
        if let Some(rb) = &mut self.ring_buf {
            let period_done = rb.update_hw_ptr(hw_pos);
            // Check for xrun: for playback, hw_ptr laps appl_ptr.
            if self.stream == PcmStream::Playback {
                let avail = rb.avail_playback();
                if avail == 0 {
                    rb.record_xrun();
                    let _ = rb;
                    self.state = PcmState::Xrun;
                    return false;
                }
            }
            period_done
        } else {
            false
        }
    }

    /// Returns the current hardware pointer position in frames (mod buffer_size).
    pub fn hw_ptr_pos(&self) -> u32 {
        self.ring_buf
            .as_ref()
            .map(|rb| (rb.hw_ptr % rb.buffer_size as u64) as u32)
            .unwrap_or(0)
    }

    /// Returns the current application pointer position in frames (mod buffer_size).
    pub fn appl_ptr_pos(&self) -> u32 {
        self.ring_buf
            .as_ref()
            .map(|rb| (rb.appl_ptr % rb.buffer_size as u64) as u32)
            .unwrap_or(0)
    }

    /// Returns the number of available frames for this stream direction.
    pub fn avail_frames(&self) -> u32 {
        let Some(rb) = &self.ring_buf else { return 0 };
        match self.stream {
            PcmStream::Playback => rb.avail_playback(),
            PcmStream::Capture => rb.avail_capture(),
        }
    }

    /// Returns xrun count.
    pub fn xrun_count(&self) -> u32 {
        self.ring_buf.as_ref().map(|rb| rb.xrun_count).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// PCM Device
// ---------------------------------------------------------------------------

/// Maximum number of substreams per direction per PCM device.
pub const MAX_SUBSTREAMS: usize = 8;

/// A PCM device containing playback and capture substreams.
pub struct PcmDevice {
    /// Device name (e.g., "hw:0,0").
    pub name: [u8; 16],
    /// Device index.
    pub device_index: u32,
    /// Playback substreams.
    pub playback: [Option<PcmSubstream>; MAX_SUBSTREAMS],
    /// Capture substreams.
    pub capture: [Option<PcmSubstream>; MAX_SUBSTREAMS],
    /// Number of playback substreams.
    pub playback_count: usize,
    /// Number of capture substreams.
    pub capture_count: usize,
}

impl PcmDevice {
    /// Creates a new PCM device.
    pub fn new(device_index: u32, name: [u8; 16]) -> Self {
        const EMPTY_SUB: Option<PcmSubstream> = None;
        Self {
            name,
            device_index,
            playback: [EMPTY_SUB; MAX_SUBSTREAMS],
            capture: [EMPTY_SUB; MAX_SUBSTREAMS],
            playback_count: 0,
            capture_count: 0,
        }
    }

    /// Adds a playback substream.
    pub fn add_playback_substream(&mut self) -> Result<usize> {
        if self.playback_count >= MAX_SUBSTREAMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.playback_count;
        self.playback[idx] = Some(PcmSubstream::new(PcmStream::Playback, idx as u32));
        self.playback_count += 1;
        Ok(idx)
    }

    /// Adds a capture substream.
    pub fn add_capture_substream(&mut self) -> Result<usize> {
        if self.capture_count >= MAX_SUBSTREAMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.capture_count;
        self.capture[idx] = Some(PcmSubstream::new(PcmStream::Capture, idx as u32));
        self.capture_count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to a playback substream.
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= MAX_SUBSTREAMS`.
    pub fn playback_mut(&mut self, index: usize) -> Result<&mut PcmSubstream> {
        if index >= MAX_SUBSTREAMS {
            return Err(Error::InvalidArgument);
        }
        self.playback[index].as_mut().ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a capture substream.
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= MAX_SUBSTREAMS`.
    pub fn capture_mut(&mut self, index: usize) -> Result<&mut PcmSubstream> {
        if index >= MAX_SUBSTREAMS {
            return Err(Error::InvalidArgument);
        }
        self.capture[index].as_mut().ok_or(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Maximum number of PCM devices.
pub const MAX_PCM_DEVICES: usize = 8;

/// Global PCM device registry.
pub struct PcmRegistry {
    devices: [Option<PcmDevice>; MAX_PCM_DEVICES],
    count: usize,
}

impl PcmRegistry {
    /// Creates an empty PCM registry.
    pub const fn new() -> Self {
        const EMPTY: Option<PcmDevice> = None;
        Self {
            devices: [EMPTY; MAX_PCM_DEVICES],
            count: 0,
        }
    }

    /// Registers a PCM device.
    pub fn register(&mut self, device: PcmDevice) -> Result<usize> {
        if self.count >= MAX_PCM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the PCM device at `index`.
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= MAX_PCM_DEVICES`.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut PcmDevice> {
        if index >= MAX_PCM_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[index].as_mut().ok_or(Error::NotFound)
    }

    /// Returns a reference to the PCM device at `index`.
    ///
    /// Returns [`Error::InvalidArgument`] if `index >= MAX_PCM_DEVICES`.
    pub fn get(&self, index: usize) -> Result<&PcmDevice> {
        if index >= MAX_PCM_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[index].as_ref().ok_or(Error::NotFound)
    }

    /// Returns the number of registered PCM devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no PCM devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

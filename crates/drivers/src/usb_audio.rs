// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Audio Class driver.
//!
//! Implements a USB Audio Class 1.0 device interface for streaming
//! audio data to/from USB audio peripherals such as headsets,
//! microphones, and speaker systems.
//!
//! # Architecture
//!
//! - **AudioSampleRate** — supported sample rates from 8 kHz to 192 kHz
//! - **AudioBitDepth** — 16-, 24-, or 32-bit sample depth
//! - **AudioStreamFormat** — full format descriptor (rate, depth, channels)
//! - **AudioEndpoint** — isochronous endpoint for audio streaming
//! - **AudioControl** — volume, mute, bass, and treble controls
//! - **UsbAudioDevice** — single audio device with stream management
//! - **UsbAudioRegistry** — tracks up to 8 attached audio devices
//!
//! Reference: USB Audio Class Specification 1.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// USB interface class code for Audio.
pub const AUDIO_CLASS: u8 = 0x01;

/// Audio Control interface subclass.
pub const AUDIO_SUBCLASS_CONTROL: u8 = 0x01;

/// Audio Streaming interface subclass.
pub const AUDIO_SUBCLASS_STREAMING: u8 = 0x02;

/// Maximum number of endpoints per audio device.
pub const MAX_ENDPOINTS: usize = 4;

/// Maximum number of supported stream formats per device.
pub const MAX_FORMATS: usize = 8;

/// Maximum number of concurrently tracked USB audio devices.
pub const MAX_USB_AUDIO_DEVICES: usize = 8;

/// Maximum number of audio channels.
pub const MAX_CHANNELS: u8 = 8;

// ---------------------------------------------------------------------------
// Audio Sample Rate
// ---------------------------------------------------------------------------

/// Supported audio sample rates.
///
/// Each variant corresponds to a standard sample rate used in audio
/// streaming. The numeric value is the rate in Hz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioSampleRate {
    /// 8,000 Hz — telephony quality.
    Rate8000,
    /// 16,000 Hz — wideband voice.
    Rate16000,
    /// 44,100 Hz — CD quality.
    Rate44100,
    /// 48,000 Hz — professional audio / DVD.
    Rate48000,
    /// 96,000 Hz — high-resolution audio.
    Rate96000,
    /// 192,000 Hz — studio-grade high-resolution audio.
    Rate192000,
}

impl AudioSampleRate {
    /// Return the sample rate in Hz.
    pub const fn hz(self) -> u32 {
        match self {
            Self::Rate8000 => 8_000,
            Self::Rate16000 => 16_000,
            Self::Rate44100 => 44_100,
            Self::Rate48000 => 48_000,
            Self::Rate96000 => 96_000,
            Self::Rate192000 => 192_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Audio Bit Depth
// ---------------------------------------------------------------------------

/// Supported audio sample bit depths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioBitDepth {
    /// 16 bits per sample.
    Bit16,
    /// 24 bits per sample.
    Bit24,
    /// 32 bits per sample.
    Bit32,
}

impl AudioBitDepth {
    /// Return the number of bits per sample.
    pub const fn bits(self) -> u8 {
        match self {
            Self::Bit16 => 16,
            Self::Bit24 => 24,
            Self::Bit32 => 32,
        }
    }

    /// Return the number of bytes per sample.
    pub const fn bytes(self) -> u8 {
        match self {
            Self::Bit16 => 2,
            Self::Bit24 => 3,
            Self::Bit32 => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Audio Stream Format
// ---------------------------------------------------------------------------

/// Describes the format of an audio stream.
///
/// Combines sample rate, bit depth, and channel count to fully
/// specify how audio data is laid out in isochronous transfers.
#[derive(Debug, Clone, Copy)]
pub struct AudioStreamFormat {
    /// Sample rate for this format.
    pub sample_rate: AudioSampleRate,
    /// Bit depth for this format.
    pub bit_depth: AudioBitDepth,
    /// Number of audio channels (1–8).
    pub channels: u8,
    /// Size of one audio frame in bytes (channels * bytes_per_sample).
    pub frame_size: u16,
}

impl AudioStreamFormat {
    /// Create a new audio stream format.
    ///
    /// `channels` is clamped to the range 1–[`MAX_CHANNELS`].
    /// `frame_size` is computed automatically from the bit depth
    /// and channel count.
    pub fn new(sample_rate: AudioSampleRate, bit_depth: AudioBitDepth, channels: u8) -> Self {
        let ch = if channels == 0 {
            1
        } else if channels > MAX_CHANNELS {
            MAX_CHANNELS
        } else {
            channels
        };
        let frame_size = u16::from(ch) * u16::from(bit_depth.bytes());
        Self {
            sample_rate,
            bit_depth,
            channels: ch,
            frame_size,
        }
    }
}

// ---------------------------------------------------------------------------
// Endpoint Direction
// ---------------------------------------------------------------------------

/// Direction of an audio endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDirection {
    /// Device to host (capture / microphone).
    In,
    /// Host to device (playback / speakers).
    Out,
}

// ---------------------------------------------------------------------------
// Audio Endpoint
// ---------------------------------------------------------------------------

/// An isochronous endpoint used for audio data transfer.
#[derive(Debug, Clone, Copy)]
pub struct AudioEndpoint {
    /// Transfer direction of this endpoint.
    pub direction: AudioDirection,
    /// Maximum packet size in bytes for this endpoint.
    pub max_packet_size: u16,
    /// Polling interval in milliseconds.
    pub interval_ms: u8,
    /// Audio format carried by this endpoint.
    pub format: AudioStreamFormat,
}

impl AudioEndpoint {
    /// Create a new audio endpoint descriptor.
    pub fn new(
        direction: AudioDirection,
        max_packet_size: u16,
        interval_ms: u8,
        format: AudioStreamFormat,
    ) -> Self {
        Self {
            direction,
            max_packet_size,
            interval_ms,
            format,
        }
    }
}

// ---------------------------------------------------------------------------
// Audio Control
// ---------------------------------------------------------------------------

/// Software-side audio control settings.
///
/// Tracks volume (0–100), mute state, and bass/treble levels (0–100).
#[derive(Debug, Clone, Copy)]
pub struct AudioControl {
    /// Master volume level (0 = silent, 100 = maximum).
    pub volume: u8,
    /// Whether audio output is muted.
    pub mute: bool,
    /// Bass level (0–100).
    pub bass: u8,
    /// Treble level (0–100).
    pub treble: u8,
}

impl AudioControl {
    /// Create default audio controls (volume 50, unmuted, neutral EQ).
    pub const fn new() -> Self {
        Self {
            volume: 50,
            mute: false,
            bass: 50,
            treble: 50,
        }
    }

    /// Clamp a value to the 0–100 range.
    fn clamp_100(val: u8) -> u8 {
        if val > 100 { 100 } else { val }
    }

    /// Set the master volume, clamped to 0–100.
    pub fn set_volume(&mut self, volume: u8) {
        self.volume = Self::clamp_100(volume);
    }

    /// Set the mute state.
    pub fn set_mute(&mut self, mute: bool) {
        self.mute = mute;
    }

    /// Set the bass level, clamped to 0–100.
    pub fn set_bass(&mut self, bass: u8) {
        self.bass = Self::clamp_100(bass);
    }

    /// Set the treble level, clamped to 0–100.
    pub fn set_treble(&mut self, treble: u8) {
        self.treble = Self::clamp_100(treble);
    }
}

impl Default for AudioControl {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// USB Audio Device
// ---------------------------------------------------------------------------

/// A single USB Audio Class device.
///
/// Manages endpoints, supported formats, audio controls, and
/// streaming state for one USB audio peripheral.
pub struct UsbAudioDevice {
    /// Unique device identifier within the registry.
    pub device_id: u8,
    /// Isochronous endpoints for audio transfer.
    endpoints: [Option<AudioEndpoint>; MAX_ENDPOINTS],
    /// Number of configured endpoints.
    endpoint_count: usize,
    /// List of supported audio stream formats.
    format_list: [Option<AudioStreamFormat>; MAX_FORMATS],
    /// Number of supported formats.
    format_count: usize,
    /// Current audio control settings.
    pub control: AudioControl,
    /// Index into `format_list` of the currently active format.
    active_format: Option<usize>,
    /// Whether the device is currently streaming audio data.
    streaming: bool,
}

impl UsbAudioDevice {
    /// Create a new USB audio device with the given identifier.
    ///
    /// The device starts with no endpoints, no formats, default
    /// controls, and is not streaming.
    pub fn new(device_id: u8) -> Self {
        Self {
            device_id,
            endpoints: [None; MAX_ENDPOINTS],
            endpoint_count: 0,
            format_list: [None; MAX_FORMATS],
            format_count: 0,
            control: AudioControl::new(),
            active_format: None,
            streaming: false,
        }
    }

    /// Add an endpoint to the device.
    ///
    /// Returns [`Error::OutOfMemory`] if all endpoint slots are full.
    pub fn add_endpoint(&mut self, endpoint: AudioEndpoint) -> Result<()> {
        for slot in &mut self.endpoints {
            if slot.is_none() {
                *slot = Some(endpoint);
                self.endpoint_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Add a supported stream format to the device.
    ///
    /// Returns [`Error::OutOfMemory`] if all format slots are full.
    pub fn add_format(&mut self, format: AudioStreamFormat) -> Result<()> {
        for slot in &mut self.format_list {
            if slot.is_none() {
                *slot = Some(format);
                self.format_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Start audio streaming on the device.
    ///
    /// An active format must be set before streaming can begin.
    /// Returns [`Error::InvalidArgument`] if no format is selected.
    pub fn start_stream(&mut self) -> Result<()> {
        if self.active_format.is_none() {
            return Err(Error::InvalidArgument);
        }
        self.streaming = true;
        Ok(())
    }

    /// Stop audio streaming on the device.
    pub fn stop_stream(&mut self) {
        self.streaming = false;
    }

    /// Set the master volume on the device, clamped to 0–100.
    pub fn set_volume(&mut self, volume: u8) {
        self.control.set_volume(volume);
    }

    /// Select the active stream format by index into the format list.
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range
    /// or the slot at that index is empty.
    /// Returns [`Error::Busy`] if the device is currently streaming.
    pub fn set_format(&mut self, index: usize) -> Result<()> {
        if self.streaming {
            return Err(Error::Busy);
        }
        if index >= MAX_FORMATS {
            return Err(Error::InvalidArgument);
        }
        if self.format_list[index].is_none() {
            return Err(Error::InvalidArgument);
        }
        self.active_format = Some(index);
        Ok(())
    }

    /// Return the currently active stream format, if any.
    pub fn active_format(&self) -> Option<&AudioStreamFormat> {
        self.active_format
            .and_then(|idx| self.format_list[idx].as_ref())
    }

    /// Return `true` if the device is currently streaming.
    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Return the number of configured endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoint_count
    }

    /// Return the number of supported formats.
    pub fn format_count(&self) -> usize {
        self.format_count
    }

    /// Get an endpoint by index.
    pub fn endpoint(&self, index: usize) -> Option<&AudioEndpoint> {
        if index < MAX_ENDPOINTS {
            self.endpoints[index].as_ref()
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// USB Audio Registry
// ---------------------------------------------------------------------------

/// Registry of attached USB Audio devices.
///
/// Tracks up to [`MAX_USB_AUDIO_DEVICES`] devices and provides
/// registration, removal, and lookup operations.
pub struct UsbAudioRegistry {
    /// Fixed-size array of device slots.
    devices: [Option<UsbAudioDevice>; MAX_USB_AUDIO_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for UsbAudioRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbAudioRegistry {
    /// Create an empty audio device registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }

    /// Register a new USB audio device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same
    /// `device_id` is already registered.
    pub fn register(&mut self, device: UsbAudioDevice) -> Result<()> {
        for d in self.devices.iter().flatten() {
            if d.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a device by its `device_id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that ID exists.
    pub fn unregister(&mut self, device_id: u8) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(d) = slot {
                if d.device_id == device_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a device by its `device_id`.
    ///
    /// Returns a shared reference to the device, or [`None`] if not
    /// found.
    pub fn find(&self, device_id: u8) -> Option<&UsbAudioDevice> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.device_id == device_id))
    }

    /// Find a device by its `device_id` (mutable).
    ///
    /// Returns a mutable reference to the device, or [`None`] if not
    /// found.
    pub fn find_mut(&mut self, device_id: u8) -> Option<&mut UsbAudioDevice> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.device_id == device_id))
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

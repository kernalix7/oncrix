// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tablet / digitizer input device driver.
//!
//! Reports absolute position, pressure, tilt, and tool type for
//! pen/stylus input devices. Supports Wacom-style digitizers, touch
//! screens with stylus, and generic HID tablets.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐
//! │  HID / USB    │
//! └──────┬───────┘
//!        │ raw reports
//! ┌──────▼───────┐
//! │  Tablet Drv   │ ← this module
//! └──────┬───────┘
//!        │ TabletEvent
//! ┌──────▼───────┐
//! │  Input Core   │
//! └──────────────┘
//! ```
//!
//! The driver normalises raw HID reports into [`TabletEvent`] values
//! that the input core subsystem dispatches to user-space consumers.
//!
//! Reference: Linux `drivers/hid/wacom_wac.c`,
//! `include/linux/input.h` (ABS_* and BTN_TOOL_* codes)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of tablet devices tracked.
const MAX_TABLET_DEVICES: usize = 8;

/// Maximum pending events in the event queue.
const MAX_EVENT_QUEUE: usize = 256;

/// Maximum supported axes per device.
const MAX_AXES: usize = 8;

/// Maximum buttons per tablet device.
const MAX_BUTTONS: usize = 16;

/// Default X-axis range maximum.
const DEFAULT_X_MAX: i32 = 32767;

/// Default Y-axis range maximum.
const DEFAULT_Y_MAX: i32 = 32767;

/// Default pressure range maximum.
const DEFAULT_PRESSURE_MAX: i32 = 8191;

/// Default tilt range (-90..+90 degrees scaled).
const DEFAULT_TILT_MAX: i32 = 127;

/// Default tilt minimum.
const DEFAULT_TILT_MIN: i32 = -127;

// ── Tool Type ───────────────────────────────────────────────────

/// Type of input tool in contact with the tablet surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolType {
    /// No tool in proximity.
    #[default]
    None,
    /// Standard pen tip.
    Pen,
    /// Pen eraser end.
    Eraser,
    /// Brush tool.
    Brush,
    /// Pencil tool.
    Pencil,
    /// Airbrush tool.
    Airbrush,
    /// Finger touch (touchscreen mode).
    Finger,
    /// Mouse-like tool.
    Mouse,
    /// Lens cursor.
    Lens,
}

// ── Tablet Axis ─────────────────────────────────────────────────

/// Identifier for a tablet input axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabletAxis {
    /// X coordinate (absolute).
    X,
    /// Y coordinate (absolute).
    Y,
    /// Pressure.
    Pressure,
    /// X tilt angle.
    TiltX,
    /// Y tilt angle.
    TiltY,
    /// Distance from surface.
    Distance,
    /// Rotation angle.
    Rotation,
    /// Slider / wheel.
    Slider,
}

// ── Axis Configuration ──────────────────────────────────────────

/// Configuration for a single tablet axis.
#[derive(Debug, Clone, Copy)]
pub struct AxisConfig {
    /// Axis identifier.
    pub axis: TabletAxis,
    /// Minimum value.
    pub min: i32,
    /// Maximum value.
    pub max: i32,
    /// Resolution (units per millimeter, 0 if unknown).
    pub resolution: u32,
    /// Fuzz (noise threshold for filtering).
    pub fuzz: i32,
    /// Flat zone (deadband).
    pub flat: i32,
}

impl AxisConfig {
    /// Create a default axis configuration.
    const fn new(axis: TabletAxis, min: i32, max: i32) -> Self {
        Self {
            axis,
            min,
            max,
            resolution: 0,
            fuzz: 0,
            flat: 0,
        }
    }
}

// ── Tablet Event ────────────────────────────────────────────────

/// Type of tablet event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventType {
    /// Absolute axis value change.
    #[default]
    AbsoluteAxis,
    /// Tool proximity enter/exit.
    Proximity,
    /// Button press/release.
    Button,
    /// Synchronisation event (report boundary).
    Sync,
}

/// A tablet input event.
///
/// Reports a single datum from the digitizer: an axis value,
/// button state, proximity change, or sync marker.
#[derive(Debug, Clone, Copy)]
pub struct TabletEvent {
    /// Device index that generated this event.
    pub device_index: u8,
    /// Event type.
    pub event_type: EventType,
    /// Axis (for AbsoluteAxis events).
    pub axis: TabletAxis,
    /// Value (axis value, button code, or proximity flag).
    pub value: i32,
    /// Tool type currently in proximity.
    pub tool: ToolType,
    /// Timestamp in microseconds (monotonic).
    pub timestamp_us: u64,
}

impl TabletEvent {
    /// Create an empty event.
    const fn empty() -> Self {
        Self {
            device_index: 0,
            event_type: EventType::Sync,
            axis: TabletAxis::X,
            value: 0,
            tool: ToolType::None,
            timestamp_us: 0,
        }
    }
}

// ── Device Capabilities ─────────────────────────────────────────

/// Bit flags describing tablet device capabilities.
#[derive(Debug, Clone, Copy)]
pub struct TabletCapabilities {
    /// Supports pressure reporting.
    pub has_pressure: bool,
    /// Supports tilt reporting.
    pub has_tilt: bool,
    /// Supports distance reporting.
    pub has_distance: bool,
    /// Supports rotation reporting.
    pub has_rotation: bool,
    /// Supports slider / wheel input.
    pub has_slider: bool,
    /// Supports eraser tool detection.
    pub has_eraser: bool,
    /// Number of supported buttons.
    pub button_count: u8,
    /// Maximum simultaneous contacts (for multi-touch pens).
    pub max_contacts: u8,
}

impl TabletCapabilities {
    /// Create default capabilities.
    const fn new() -> Self {
        Self {
            has_pressure: true,
            has_tilt: false,
            has_distance: false,
            has_rotation: false,
            has_slider: false,
            has_eraser: false,
            button_count: 2,
            max_contacts: 1,
        }
    }
}

// ── Tablet Device ───────────────────────────────────────────────

/// A tablet / digitizer input device.
///
/// Tracks device state including current tool, axis values,
/// capabilities, and button states. Events are queued and
/// delivered to the input subsystem via [`TabletDevice::flush_events`].
pub struct TabletDevice {
    /// Device name for identification.
    name: [u8; 64],
    /// Length of the name string.
    name_len: usize,
    /// Axis configurations.
    axes: [AxisConfig; MAX_AXES],
    /// Number of configured axes.
    axis_count: usize,
    /// Device capabilities.
    capabilities: TabletCapabilities,
    /// Current tool in proximity.
    current_tool: ToolType,
    /// Current axis values (indexed by axis ordinal).
    current_values: [i32; MAX_AXES],
    /// Button states (bitfield).
    button_state: u16,
    /// Whether a tool is in proximity.
    in_proximity: bool,
    /// Event queue.
    event_queue: [TabletEvent; MAX_EVENT_QUEUE],
    /// Number of events in the queue.
    event_count: usize,
    /// Write position in the event queue.
    event_head: usize,
    /// Read position in the event queue.
    event_tail: usize,
    /// Device index in the registry.
    device_index: u8,
    /// Whether the device has been initialised.
    initialised: bool,
}

impl TabletDevice {
    /// Create an uninitialised tablet device.
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            axes: [const { AxisConfig::new(TabletAxis::X, 0, 0) }; MAX_AXES],
            axis_count: 0,
            capabilities: TabletCapabilities::new(),
            current_tool: ToolType::None,
            current_values: [0i32; MAX_AXES],
            button_state: 0,
            in_proximity: false,
            event_queue: [const { TabletEvent::empty() }; MAX_EVENT_QUEUE],
            event_count: 0,
            event_head: 0,
            event_tail: 0,
            device_index: 0,
            initialised: false,
        }
    }

    /// Initialise the tablet device with default axis ranges.
    ///
    /// Sets up X, Y, and pressure axes with default ranges.
    /// Additional axes can be configured via [`set_range`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if already initialised.
    pub fn init(&mut self, name: &[u8], device_index: u8) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }

        let copy_len = name.len().min(self.name.len());
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
        self.device_index = device_index;

        // Configure default axes.
        self.axes[0] = AxisConfig::new(TabletAxis::X, 0, DEFAULT_X_MAX);
        self.axes[1] = AxisConfig::new(TabletAxis::Y, 0, DEFAULT_Y_MAX);
        self.axes[2] = AxisConfig::new(TabletAxis::Pressure, 0, DEFAULT_PRESSURE_MAX);
        self.axis_count = 3;

        self.initialised = true;
        Ok(())
    }

    /// Report an axis event from the hardware.
    ///
    /// Validates the value against the configured range, queues
    /// the event, and updates the current axis state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the axis is not
    /// configured for this device.
    /// Returns [`Error::OutOfMemory`] if the event queue is full.
    pub fn report_event(&mut self, axis: TabletAxis, value: i32, timestamp_us: u64) -> Result<()> {
        let axis_idx = self.find_axis(axis).ok_or(Error::InvalidArgument)?;
        let config = &self.axes[axis_idx];

        // Clamp value to configured range.
        let clamped = value.clamp(config.min, config.max);

        // Apply fuzz filtering.
        let old = self.current_values[axis_idx];
        let diff = (clamped - old).unsigned_abs() as i32;
        if config.fuzz > 0 && diff < config.fuzz {
            return Ok(());
        }

        self.current_values[axis_idx] = clamped;

        let event = TabletEvent {
            device_index: self.device_index,
            event_type: EventType::AbsoluteAxis,
            axis,
            value: clamped,
            tool: self.current_tool,
            timestamp_us,
        };

        self.enqueue_event(event)
    }

    /// Report a tool proximity change.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the event queue is full.
    pub fn report_proximity(
        &mut self,
        tool: ToolType,
        in_proximity: bool,
        timestamp_us: u64,
    ) -> Result<()> {
        self.current_tool = if in_proximity { tool } else { ToolType::None };
        self.in_proximity = in_proximity;

        let event = TabletEvent {
            device_index: self.device_index,
            event_type: EventType::Proximity,
            axis: TabletAxis::X,
            value: if in_proximity { 1 } else { 0 },
            tool,
            timestamp_us,
        };

        self.enqueue_event(event)
    }

    /// Report a button press or release.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `button` exceeds the
    /// device's button count.
    /// Returns [`Error::OutOfMemory`] if the event queue is full.
    pub fn report_button(&mut self, button: u8, pressed: bool, timestamp_us: u64) -> Result<()> {
        if button >= self.capabilities.button_count {
            return Err(Error::InvalidArgument);
        }

        if pressed {
            self.button_state |= 1 << button;
        } else {
            self.button_state &= !(1 << button);
        }

        let event = TabletEvent {
            device_index: self.device_index,
            event_type: EventType::Button,
            axis: TabletAxis::X,
            value: if pressed { 1 } else { 0 },
            tool: self.current_tool,
            timestamp_us,
        };

        self.enqueue_event(event)
    }

    /// Report a sync event (end of one input report).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the event queue is full.
    pub fn report_sync(&mut self, timestamp_us: u64) -> Result<()> {
        let event = TabletEvent {
            device_index: self.device_index,
            event_type: EventType::Sync,
            axis: TabletAxis::X,
            value: 0,
            tool: self.current_tool,
            timestamp_us,
        };

        self.enqueue_event(event)
    }

    /// Set the range for an axis.
    ///
    /// If the axis already exists, updates its range. Otherwise
    /// adds a new axis configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `min > max`.
    /// Returns [`Error::OutOfMemory`] if the axis table is full.
    pub fn set_range(
        &mut self,
        axis: TabletAxis,
        min: i32,
        max: i32,
        resolution: u32,
    ) -> Result<()> {
        if min > max {
            return Err(Error::InvalidArgument);
        }

        // Check if axis already exists.
        if let Some(idx) = self.find_axis(axis) {
            self.axes[idx].min = min;
            self.axes[idx].max = max;
            self.axes[idx].resolution = resolution;
            return Ok(());
        }

        // Add new axis.
        if self.axis_count >= MAX_AXES {
            return Err(Error::OutOfMemory);
        }

        self.axes[self.axis_count] = AxisConfig {
            axis,
            min,
            max,
            resolution,
            fuzz: 0,
            flat: 0,
        };
        self.axis_count += 1;

        Ok(())
    }

    /// Return the device capabilities.
    pub fn get_capabilities(&self) -> &TabletCapabilities {
        &self.capabilities
    }

    /// Set device capabilities.
    pub fn set_capabilities(&mut self, caps: TabletCapabilities) {
        self.capabilities = caps;
    }

    /// Flush all pending events from the queue.
    ///
    /// Returns the number of events flushed. The caller should
    /// read events via [`dequeue_event`] before calling flush.
    pub fn flush_events(&mut self) -> usize {
        let flushed = self.event_count;
        self.event_count = 0;
        self.event_head = 0;
        self.event_tail = 0;
        flushed
    }

    /// Dequeue the next event from the event queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue_event(&mut self) -> Option<TabletEvent> {
        if self.event_count == 0 {
            return None;
        }

        let event = self.event_queue[self.event_tail];
        self.event_tail = (self.event_tail + 1) % MAX_EVENT_QUEUE;
        self.event_count -= 1;

        Some(event)
    }

    /// Return the number of pending events.
    pub fn pending_events(&self) -> usize {
        self.event_count
    }

    /// Return the current tool in proximity.
    pub fn current_tool(&self) -> ToolType {
        self.current_tool
    }

    /// Return whether a tool is in proximity.
    pub fn is_in_proximity(&self) -> bool {
        self.in_proximity
    }

    /// Return the current button state as a bitfield.
    pub fn button_state(&self) -> u16 {
        self.button_state
    }

    /// Return whether the device is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    // ── Internal helpers ────────────────────────────────────

    /// Find an axis by type.
    fn find_axis(&self, axis: TabletAxis) -> Option<usize> {
        for i in 0..self.axis_count {
            if matches!(
                (&self.axes[i].axis, &axis),
                (TabletAxis::X, TabletAxis::X)
                    | (TabletAxis::Y, TabletAxis::Y)
                    | (TabletAxis::Pressure, TabletAxis::Pressure)
                    | (TabletAxis::TiltX, TabletAxis::TiltX)
                    | (TabletAxis::TiltY, TabletAxis::TiltY)
                    | (TabletAxis::Distance, TabletAxis::Distance)
                    | (TabletAxis::Rotation, TabletAxis::Rotation)
                    | (TabletAxis::Slider, TabletAxis::Slider)
            ) {
                return Some(i);
            }
        }
        None
    }

    /// Enqueue an event.
    fn enqueue_event(&mut self, event: TabletEvent) -> Result<()> {
        if self.event_count >= MAX_EVENT_QUEUE {
            return Err(Error::OutOfMemory);
        }

        self.event_queue[self.event_head] = event;
        self.event_head = (self.event_head + 1) % MAX_EVENT_QUEUE;
        self.event_count += 1;

        Ok(())
    }
}

impl Default for TabletDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tablet Device Registry ──────────────────────────────────────

/// Registry of tablet input devices.
pub struct TabletRegistry {
    /// Registered devices.
    devices: [Option<TabletDevice>; MAX_TABLET_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl TabletRegistry {
    /// Create an empty tablet registry.
    pub const fn new() -> Self {
        const NONE: Option<TabletDevice> = None;
        Self {
            devices: [NONE; MAX_TABLET_DEVICES],
            count: 0,
        }
    }

    /// Register a new tablet device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: TabletDevice) -> Result<usize> {
        if self.count >= MAX_TABLET_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Return a reference to a device by index.
    pub fn get(&self, index: usize) -> Option<&TabletDevice> {
        if index < self.count {
            self.devices[index].as_ref()
        } else {
            None
        }
    }

    /// Return a mutable reference to a device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut TabletDevice> {
        if index < self.count {
            self.devices[index].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for TabletRegistry {
    fn default() -> Self {
        Self::new()
    }
}

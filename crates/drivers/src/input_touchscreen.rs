// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Touchscreen input driver.
//!
//! Implements Multi-Touch (MT) protocol support for touchscreen devices.
//! Follows the Linux Multitouch Protocol Type B (slot-based tracking) model.
//!
//! # Multi-Touch Protocol
//! Each simultaneous touch point is assigned a **slot** (0 to max_slots-1).
//! Within a slot, the driver reports:
//! - `ABS_MT_TRACKING_ID`: unique ID for the contact; -1 to lift.
//! - `ABS_MT_POSITION_X`/`Y`: coordinates.
//! - `ABS_MT_PRESSURE`: optional contact pressure.
//!
//! After updating all slots, the driver calls `sync()` to signal frame completion.
//!
//! Reference: Linux kernel Documentation/input/multi-touch-protocol.rst

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ABS_MT Axis Codes (mirrors Linux input.h ABS_MT_* values)
// ---------------------------------------------------------------------------

/// ABS_MT_SLOT: Selects the active MT slot.
pub const ABS_MT_SLOT: u16 = 0x2F;
/// ABS_MT_TOUCH_MAJOR: Major axis of touching ellipse (optional).
pub const _ABS_MT_TOUCH_MAJOR: u16 = 0x30;
/// ABS_MT_TOUCH_MINOR: Minor axis (optional).
pub const _ABS_MT_TOUCH_MINOR: u16 = 0x31;
/// ABS_MT_WIDTH_MAJOR: Major axis of approaching tool (optional).
pub const _ABS_MT_WIDTH_MAJOR: u16 = 0x32;
/// ABS_MT_POSITION_X: X coordinate of the contact.
pub const ABS_MT_POSITION_X: u16 = 0x35;
/// ABS_MT_POSITION_Y: Y coordinate of the contact.
pub const ABS_MT_POSITION_Y: u16 = 0x36;
/// ABS_MT_TRACKING_ID: Unique ID per contact; -1 = lifted.
pub const ABS_MT_TRACKING_ID: u16 = 0x39;
/// ABS_MT_PRESSURE: Contact pressure.
pub const ABS_MT_PRESSURE: u16 = 0x3A;

/// Maximum number of simultaneous touch points supported.
pub const MAX_SLOTS: usize = 10;

/// Sentinel value for `tracking_id` meaning the finger is lifted.
pub const TRACKING_ID_LIFTED: i32 = -1;

// ---------------------------------------------------------------------------
// Touch Event
// ---------------------------------------------------------------------------

/// A single multi-touch contact event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TouchEvent {
    /// X coordinate of the contact (in device units).
    pub x: i32,
    /// Y coordinate of the contact (in device units).
    pub y: i32,
    /// Contact pressure (0 if not supported by hardware).
    pub pressure: u16,
    /// Tracking ID assigned by hardware/firmware. `TRACKING_ID_LIFTED` when lifted.
    pub tracking_id: i32,
    /// Slot index (0 to max_slots - 1).
    pub slot: u8,
}

impl TouchEvent {
    /// Creates a new touch-down event.
    pub const fn new(slot: u8, tracking_id: i32, x: i32, y: i32, pressure: u16) -> Self {
        Self {
            x,
            y,
            pressure,
            tracking_id,
            slot,
        }
    }

    /// Creates a lift event for `slot`.
    pub const fn lift(slot: u8) -> Self {
        Self {
            x: 0,
            y: 0,
            pressure: 0,
            tracking_id: TRACKING_ID_LIFTED,
            slot,
        }
    }

    /// Returns `true` if this event represents a finger lift.
    pub const fn is_lifted(&self) -> bool {
        self.tracking_id == TRACKING_ID_LIFTED
    }
}

// ---------------------------------------------------------------------------
// Slot State
// ---------------------------------------------------------------------------

/// State of a single MT slot.
#[derive(Clone, Copy, Debug, Default)]
struct SlotState {
    /// Current tracking ID, or `TRACKING_ID_LIFTED` if slot is free.
    tracking_id: i32,
    /// Last reported X.
    x: i32,
    /// Last reported Y.
    y: i32,
    /// Last reported pressure.
    pressure: u16,
    /// `true` if this slot has been updated since the last sync.
    dirty: bool,
}

// ---------------------------------------------------------------------------
// Touchscreen Device
// ---------------------------------------------------------------------------

/// Touchscreen input device driver.
pub struct TouchscreenDevice {
    /// Maximum X coordinate in device units.
    pub max_x: u32,
    /// Maximum Y coordinate in device units.
    pub max_y: u32,
    /// Number of simultaneous touch points supported.
    pub max_slots: u8,
    /// Per-slot state.
    slots: [SlotState; MAX_SLOTS],
    /// Currently selected slot index (set by `select_slot`).
    cur_slot: u8,
    /// Frame counter incremented on each `sync`.
    pub frame_count: u32,
}

impl TouchscreenDevice {
    /// Creates a new `TouchscreenDevice`.
    ///
    /// # Parameters
    /// - `max_x`, `max_y`: Maximum coordinate values reported by the hardware.
    /// - `max_slots`: Number of simultaneous contacts supported (capped at `MAX_SLOTS`).
    pub fn new(max_x: u32, max_y: u32, max_slots: u8) -> Self {
        let max_slots = max_slots.min(MAX_SLOTS as u8);
        let mut s = Self {
            max_x,
            max_y,
            max_slots,
            slots: [SlotState {
                tracking_id: TRACKING_ID_LIFTED,
                ..Default::default()
            }; MAX_SLOTS],
            cur_slot: 0,
            frame_count: 0,
        };
        // Initialise all slots with lifted tracking IDs
        for i in 0..MAX_SLOTS {
            s.slots[i].tracking_id = TRACKING_ID_LIFTED;
        }
        s
    }

    /// Selects the active slot for subsequent `report_*` calls.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `slot` >= `max_slots`.
    pub fn select_slot(&mut self, slot: u8) -> Result<()> {
        if slot >= self.max_slots {
            return Err(Error::InvalidArgument);
        }
        self.cur_slot = slot;
        Ok(())
    }

    /// Reports the tracking ID for the current slot.
    ///
    /// Use `TRACKING_ID_LIFTED` to release the slot.
    pub fn report_tracking_id(&mut self, tracking_id: i32) {
        let idx = self.cur_slot as usize;
        self.slots[idx].tracking_id = tracking_id;
        self.slots[idx].dirty = true;
    }

    /// Reports the X position for the current slot.
    pub fn report_x(&mut self, x: i32) {
        let idx = self.cur_slot as usize;
        self.slots[idx].x = x.clamp(0, self.max_x as i32);
        self.slots[idx].dirty = true;
    }

    /// Reports the Y position for the current slot.
    pub fn report_y(&mut self, y: i32) {
        let idx = self.cur_slot as usize;
        self.slots[idx].y = y.clamp(0, self.max_y as i32);
        self.slots[idx].dirty = true;
    }

    /// Reports the pressure for the current slot.
    pub fn report_pressure(&mut self, pressure: u16) {
        let idx = self.cur_slot as usize;
        self.slots[idx].pressure = pressure;
        self.slots[idx].dirty = true;
    }

    /// Reports a full touch contact in a single call.
    ///
    /// # Parameters
    /// - `slot`: Slot index.
    /// - `tracking_id`: Contact ID (or `TRACKING_ID_LIFTED`).
    /// - `x`, `y`: Contact coordinates.
    /// - `pressure`: Contact pressure (0 if unsupported).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `slot` >= `max_slots`.
    pub fn report_touch(
        &mut self,
        slot: u8,
        tracking_id: i32,
        x: i32,
        y: i32,
        pressure: u16,
    ) -> Result<()> {
        self.select_slot(slot)?;
        self.report_tracking_id(tracking_id);
        if tracking_id != TRACKING_ID_LIFTED {
            self.report_x(x);
            self.report_y(y);
            self.report_pressure(pressure);
        }
        Ok(())
    }

    /// Signals end of frame; increments frame counter and clears dirty flags.
    ///
    /// Returns a slice of events for all dirty slots.
    ///
    /// Callers should drain the returned events (e.g., push to an input queue)
    /// before the next frame arrives.
    pub fn sync(&mut self) -> SyncResult {
        let mut events = [TouchEvent::default(); MAX_SLOTS];
        let mut count = 0usize;
        for i in 0..self.max_slots as usize {
            if self.slots[i].dirty {
                let s = &self.slots[i];
                events[count] = TouchEvent {
                    slot: i as u8,
                    tracking_id: s.tracking_id,
                    x: s.x,
                    y: s.y,
                    pressure: s.pressure,
                };
                count += 1;
                self.slots[i].dirty = false;
            }
        }
        self.frame_count = self.frame_count.wrapping_add(1);
        SyncResult { events, count }
    }

    /// Returns the current contact count (number of active slots).
    pub fn contact_count(&self) -> usize {
        self.slots[..self.max_slots as usize]
            .iter()
            .filter(|s| s.tracking_id != TRACKING_ID_LIFTED)
            .count()
    }

    /// Returns the current state of slot `idx` as a `TouchEvent`.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `idx` >= `max_slots`.
    pub fn slot_event(&self, idx: u8) -> Result<TouchEvent> {
        if idx >= self.max_slots {
            return Err(Error::InvalidArgument);
        }
        let s = &self.slots[idx as usize];
        Ok(TouchEvent {
            slot: idx,
            tracking_id: s.tracking_id,
            x: s.x,
            y: s.y,
            pressure: s.pressure,
        })
    }

    /// Releases all active contacts (e.g., on driver unload or suspend).
    pub fn release_all(&mut self) {
        for i in 0..self.max_slots as usize {
            if self.slots[i].tracking_id != TRACKING_ID_LIFTED {
                self.slots[i].tracking_id = TRACKING_ID_LIFTED;
                self.slots[i].dirty = true;
            }
        }
    }
}

/// Result of a `sync()` call: a batch of dirty touch events for this frame.
pub struct SyncResult {
    events: [TouchEvent; MAX_SLOTS],
    /// Number of valid events in `events`.
    pub count: usize,
}

impl SyncResult {
    /// Returns the slice of valid events.
    pub fn events(&self) -> &[TouchEvent] {
        &self.events[..self.count]
    }
}

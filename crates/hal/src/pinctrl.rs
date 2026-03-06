// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pin control subsystem.
//!
//! Provides a Linux-style pinctrl framework adapted for a no_std microkernel.
//! Pin controllers manage the electrical configuration (mux, bias, drive strength,
//! slew rate) of SoC I/O pins.
//!
//! # Architecture
//!
//! - [`PinBias`] — pull resistor configuration for a pin.
//! - [`SlewRate`] — signal edge speed configuration.
//! - [`PinConfig`] — per-pin electrical configuration (bias, drive, slew).
//! - [`PinFunction`] — a named mux function a group of pins can be assigned to.
//! - [`PinGroup`] — a named group of pins that share a common function.
//! - [`PinState`] — a named collection of group-function assignments (default/sleep/idle).
//! - [`PinctrlDesc`] — static descriptor for a pin controller.
//! - [`PinctrlDev`] — runtime state of a registered pin controller.
//! - [`PinctrlRegistry`] — manages up to [`MAX_CONTROLLERS`] controllers.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pin controllers in the registry.
const MAX_CONTROLLERS: usize = 8;

/// Maximum number of pins per controller.
const MAX_PINS: usize = 256;

/// Maximum number of pin functions per controller.
const MAX_FUNCTIONS: usize = 32;

/// Maximum number of pin groups per controller.
const MAX_GROUPS: usize = 64;

/// Maximum number of pins per group.
const MAX_PINS_PER_GROUP: usize = 32;

/// Maximum number of pin states per controller.
const MAX_STATES: usize = 8;

/// Maximum number of group-function mappings per state.
const MAX_STATE_MAPS: usize = 16;

// -------------------------------------------------------------------
// PinBias
// -------------------------------------------------------------------

/// Pull resistor configuration for a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinBias {
    /// No pull resistor applied.
    #[default]
    Disable,
    /// Weak pull-up resistor enabled.
    PullUp,
    /// Weak pull-down resistor enabled.
    PullDown,
    /// Pin is driven to a known high-impedance state.
    HighZ,
}

// -------------------------------------------------------------------
// SlewRate
// -------------------------------------------------------------------

/// Signal edge speed (slew rate) configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlewRate {
    /// Slow slew — reduced EMI, lower power, limited frequency.
    Slow,
    /// Medium slew (default).
    #[default]
    Medium,
    /// Fast slew — high-frequency signals, higher EMI.
    Fast,
}

// -------------------------------------------------------------------
// PinConfig
// -------------------------------------------------------------------

/// Per-pin electrical configuration.
#[derive(Debug, Clone, Copy)]
pub struct PinConfig {
    /// Pull resistor setting.
    pub bias: PinBias,
    /// Drive strength in milliamperes.
    ///
    /// Common values: 2, 4, 6, 8, 12, 16 mA.
    pub drive_strength_ma: u8,
    /// Signal edge speed.
    pub slew_rate: SlewRate,
    /// Whether the pin is configured as open-drain.
    pub open_drain: bool,
    /// Whether Schmitt trigger input buffering is enabled.
    pub schmitt_trigger: bool,
}

impl Default for PinConfig {
    fn default() -> Self {
        Self {
            bias: PinBias::Disable,
            drive_strength_ma: 4,
            slew_rate: SlewRate::Medium,
            open_drain: false,
            schmitt_trigger: false,
        }
    }
}

// -------------------------------------------------------------------
// PinFunction
// -------------------------------------------------------------------

/// A named mux function that a group of pins can be assigned to.
#[derive(Debug, Clone, Copy)]
pub struct PinFunction {
    /// Unique function identifier within the controller.
    pub id: u32,
    /// Human-readable function name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
}

impl PinFunction {
    /// Creates a new pin function descriptor.
    ///
    /// `name` is truncated to 32 bytes if longer.
    pub fn new(id: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
        }
    }
}

/// Constant default for array initialisation.
const EMPTY_FUNCTION: PinFunction = PinFunction {
    id: 0,
    name: [0u8; 32],
    name_len: 0,
};

// -------------------------------------------------------------------
// PinGroup
// -------------------------------------------------------------------

/// A named group of pins sharing a common function.
#[derive(Debug, Clone, Copy)]
pub struct PinGroup {
    /// Unique group identifier within the controller.
    pub id: u32,
    /// Human-readable group name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Pin numbers belonging to this group.
    pub pins: [u16; MAX_PINS_PER_GROUP],
    /// Number of pins in this group.
    pub pin_count: usize,
    /// Per-pin electrical configuration for each pin in the group.
    pub configs: [PinConfig; MAX_PINS_PER_GROUP],
}

impl PinGroup {
    /// Creates a new pin group descriptor.
    ///
    /// `name` is truncated to 32 bytes if longer. Pins can be added
    /// with [`add_pin`](Self::add_pin).
    pub fn new(id: u32, name: &[u8]) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            pins: [0u16; MAX_PINS_PER_GROUP],
            pin_count: 0,
            configs: [PinConfig::default(); MAX_PINS_PER_GROUP],
        }
    }

    /// Adds a pin with the given configuration to this group.
    ///
    /// Returns [`Error::OutOfMemory`] if all [`MAX_PINS_PER_GROUP`] slots
    /// are occupied.
    pub fn add_pin(&mut self, pin: u16, config: PinConfig) -> Result<()> {
        if self.pin_count >= MAX_PINS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.pins[self.pin_count] = pin;
        self.configs[self.pin_count] = config;
        self.pin_count += 1;
        Ok(())
    }

    /// Returns a slice of the pin numbers in this group.
    pub fn pins(&self) -> &[u16] {
        &self.pins[..self.pin_count]
    }
}

/// Constant default for array initialisation.
const EMPTY_GROUP: PinGroup = PinGroup {
    id: 0,
    name: [0u8; 32],
    name_len: 0,
    pins: [0u16; MAX_PINS_PER_GROUP],
    pin_count: 0,
    configs: [PinConfig {
        bias: PinBias::Disable,
        drive_strength_ma: 4,
        slew_rate: SlewRate::Medium,
        open_drain: false,
        schmitt_trigger: false,
    }; MAX_PINS_PER_GROUP],
};

// -------------------------------------------------------------------
// PinStateKind
// -------------------------------------------------------------------

/// Named lifecycle state that a pin controller can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinStateKind {
    /// Normal operation state (active).
    #[default]
    Default,
    /// Low-power sleep state.
    Sleep,
    /// Idle state (peripheral inactive, pins tri-stated).
    Idle,
    /// Custom user-defined state.
    Custom(u8),
}

// -------------------------------------------------------------------
// PinStateMap
// -------------------------------------------------------------------

/// A mapping from a group to a function within a pin state.
#[derive(Debug, Clone, Copy, Default)]
pub struct PinStateMap {
    /// ID of the pin group to configure.
    pub group_id: u32,
    /// ID of the function to assign to the group.
    pub function_id: u32,
}

// -------------------------------------------------------------------
// PinState
// -------------------------------------------------------------------

/// A named collection of group-function assignments.
///
/// Selecting a state atomically applies all contained mappings.
#[derive(Debug, Clone, Copy)]
pub struct PinState {
    /// Unique state identifier within the controller.
    pub id: u32,
    /// Kind of state.
    pub kind: PinStateKind,
    /// Group-to-function mappings in this state.
    pub maps: [PinStateMap; MAX_STATE_MAPS],
    /// Number of active mappings.
    pub map_count: usize,
}

impl PinState {
    /// Creates a new, empty pin state.
    pub fn new(id: u32, kind: PinStateKind) -> Self {
        Self {
            id,
            kind,
            maps: [PinStateMap {
                group_id: 0,
                function_id: 0,
            }; MAX_STATE_MAPS],
            map_count: 0,
        }
    }

    /// Adds a group-function mapping to this state.
    ///
    /// Returns [`Error::OutOfMemory`] if all mapping slots are full.
    pub fn add_map(&mut self, group_id: u32, function_id: u32) -> Result<()> {
        if self.map_count >= MAX_STATE_MAPS {
            return Err(Error::OutOfMemory);
        }
        self.maps[self.map_count] = PinStateMap {
            group_id,
            function_id,
        };
        self.map_count += 1;
        Ok(())
    }

    /// Returns a slice of the active mappings.
    pub fn maps(&self) -> &[PinStateMap] {
        &self.maps[..self.map_count]
    }
}

/// Constant default for array initialisation.
const EMPTY_STATE: PinState = PinState {
    id: 0,
    kind: PinStateKind::Default,
    maps: [PinStateMap {
        group_id: 0,
        function_id: 0,
    }; MAX_STATE_MAPS],
    map_count: 0,
};

// -------------------------------------------------------------------
// PinctrlDesc
// -------------------------------------------------------------------

/// Static descriptor for a pin controller.
#[derive(Debug, Clone, Copy)]
pub struct PinctrlDesc {
    /// Unique controller identifier.
    pub id: u32,
    /// Human-readable controller name (UTF-8, not NUL-terminated).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Total number of pins managed by this controller.
    pub num_pins: u16,
}

impl PinctrlDesc {
    /// Creates a new controller descriptor.
    ///
    /// `name` is truncated to 32 bytes if longer.
    pub fn new(id: u32, name: &[u8], num_pins: u16) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            num_pins,
        }
    }
}

// -------------------------------------------------------------------
// PinctrlDev
// -------------------------------------------------------------------

/// Runtime state of a registered pin controller.
pub struct PinctrlDev {
    /// Static descriptor.
    pub desc: PinctrlDesc,
    /// Registered pin functions.
    functions: [PinFunction; MAX_FUNCTIONS],
    /// Number of registered functions.
    function_count: usize,
    /// Registered pin groups.
    groups: [PinGroup; MAX_GROUPS],
    /// Number of registered groups.
    group_count: usize,
    /// Defined pin states.
    states: [PinState; MAX_STATES],
    /// Number of defined states.
    state_count: usize,
    /// Currently active state id, or `None` if no state is selected.
    active_state: Option<u32>,
    /// Per-pin configuration shadow (indexed by pin number).
    pin_configs: [PinConfig; MAX_PINS],
}

impl PinctrlDev {
    /// Creates a new pin controller device with the given descriptor.
    pub fn new(desc: PinctrlDesc) -> Self {
        Self {
            desc,
            functions: [EMPTY_FUNCTION; MAX_FUNCTIONS],
            function_count: 0,
            groups: [EMPTY_GROUP; MAX_GROUPS],
            group_count: 0,
            states: [EMPTY_STATE; MAX_STATES],
            state_count: 0,
            active_state: None,
            pin_configs: [PinConfig::default(); MAX_PINS],
        }
    }

    /// Registers a pin function with this controller.
    ///
    /// Returns [`Error::OutOfMemory`] if the function table is full, or
    /// [`Error::AlreadyExists`] if a function with the same id exists.
    pub fn add_function(&mut self, func: PinFunction) -> Result<()> {
        if self.functions[..self.function_count]
            .iter()
            .any(|f| f.id == func.id)
        {
            return Err(Error::AlreadyExists);
        }
        if self.function_count >= MAX_FUNCTIONS {
            return Err(Error::OutOfMemory);
        }
        self.functions[self.function_count] = func;
        self.function_count += 1;
        Ok(())
    }

    /// Registers a pin group with this controller.
    ///
    /// Returns [`Error::OutOfMemory`] if the group table is full, or
    /// [`Error::AlreadyExists`] if a group with the same id exists.
    pub fn add_group(&mut self, group: PinGroup) -> Result<()> {
        if self.groups[..self.group_count]
            .iter()
            .any(|g| g.id == group.id)
        {
            return Err(Error::AlreadyExists);
        }
        if self.group_count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        self.groups[self.group_count] = group;
        self.group_count += 1;
        Ok(())
    }

    /// Defines a pin state for this controller.
    ///
    /// Returns [`Error::OutOfMemory`] if the state table is full, or
    /// [`Error::AlreadyExists`] if a state with the same id exists.
    pub fn add_state(&mut self, state: PinState) -> Result<()> {
        if self.states[..self.state_count]
            .iter()
            .any(|s| s.id == state.id)
        {
            return Err(Error::AlreadyExists);
        }
        if self.state_count >= MAX_STATES {
            return Err(Error::OutOfMemory);
        }
        self.states[self.state_count] = state;
        self.state_count += 1;
        Ok(())
    }

    /// Selects a pin state by id, applying all its group-function mappings.
    ///
    /// For each mapping in the state, the per-pin configuration of every
    /// pin in the group is copied into the controller's shadow config array.
    ///
    /// Returns [`Error::NotFound`] if the state id is unknown.
    pub fn select_state(&mut self, state_id: u32) -> Result<()> {
        // Find the state.
        let state_idx = self.states[..self.state_count]
            .iter()
            .position(|s| s.id == state_id)
            .ok_or(Error::NotFound)?;
        let state = self.states[state_idx];

        // Apply each group-function mapping.
        for map in state.maps() {
            // Verify function exists.
            if !self.functions[..self.function_count]
                .iter()
                .any(|f| f.id == map.function_id)
            {
                return Err(Error::NotFound);
            }
            // Find the group.
            let grp_idx = self.groups[..self.group_count]
                .iter()
                .position(|g| g.id == map.group_id)
                .ok_or(Error::NotFound)?;
            let group = self.groups[grp_idx];
            // Apply per-pin configuration.
            for i in 0..group.pin_count {
                let pin = group.pins[i] as usize;
                if pin < MAX_PINS {
                    self.pin_configs[pin] = group.configs[i];
                }
            }
        }
        self.active_state = Some(state_id);
        Ok(())
    }

    /// Returns the configuration of pin `pin_num`.
    ///
    /// Returns [`Error::InvalidArgument`] if `pin_num` is out of range.
    pub fn get_pin_config(&self, pin_num: u16) -> Result<PinConfig> {
        let idx = pin_num as usize;
        if idx >= MAX_PINS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.pin_configs[idx])
    }

    /// Sets the configuration of pin `pin_num` directly (bypassing state machinery).
    ///
    /// Returns [`Error::InvalidArgument`] if `pin_num` is out of range or
    /// exceeds [`PinctrlDesc::num_pins`].
    pub fn set_pin_config(&mut self, pin_num: u16, config: PinConfig) -> Result<()> {
        if pin_num >= self.desc.num_pins || (pin_num as usize) >= MAX_PINS {
            return Err(Error::InvalidArgument);
        }
        self.pin_configs[pin_num as usize] = config;
        Ok(())
    }

    /// Returns the currently active state id, if any.
    pub fn active_state(&self) -> Option<u32> {
        self.active_state
    }

    /// Returns the number of registered functions.
    pub fn function_count(&self) -> usize {
        self.function_count
    }

    /// Returns the number of registered groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }
}

// -------------------------------------------------------------------
// pinctrl_select_state (free function)
// -------------------------------------------------------------------

/// Selects a pin state by [`PinStateKind`] on the controller with `ctrl_id`.
///
/// Looks up the first state matching `kind` and calls
/// [`PinctrlDev::select_state`].
///
/// Returns [`Error::NotFound`] if the controller or matching state is not found.
pub fn pinctrl_select_state(
    registry: &mut PinctrlRegistry,
    ctrl_id: u32,
    kind: PinStateKind,
) -> Result<()> {
    let dev = registry.get_dev_mut(ctrl_id)?;
    let state_id = dev.states[..dev.state_count]
        .iter()
        .find(|s| s.kind == kind)
        .map(|s| s.id)
        .ok_or(Error::NotFound)?;
    dev.select_state(state_id)
}

// -------------------------------------------------------------------
// PinctrlRegistry
// -------------------------------------------------------------------

/// Registry managing up to [`MAX_CONTROLLERS`] pin controllers.
pub struct PinctrlRegistry {
    /// Registered pin controller devices.
    controllers: [Option<PinctrlDev>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for PinctrlRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PinctrlRegistry {
    /// Creates a new, empty pin control registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a pin controller device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a controller with the same id exists.
    pub fn register(&mut self, dev: PinctrlDev) -> Result<()> {
        for c in self.controllers.iter().flatten() {
            if c.desc.id == dev.desc.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.controllers {
            if slot.is_none() {
                *slot = Some(dev);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters the controller with the given `id`.
    ///
    /// Returns [`Error::NotFound`] if no controller with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in &mut self.controllers {
            let matches = slot.as_ref().is_some_and(|c| c.desc.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns an immutable reference to the controller with `id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_dev(&self, id: u32) -> Result<&PinctrlDev> {
        self.controllers
            .iter()
            .flatten()
            .find(|c| c.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the controller with `id`.
    pub fn get_dev_mut(&mut self, id: u32) -> Result<&mut PinctrlDev> {
        self.controllers
            .iter_mut()
            .flatten()
            .find(|c| c.desc.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

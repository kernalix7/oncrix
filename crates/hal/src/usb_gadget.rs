// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Device/Gadget Controller framework.
//!
//! Implements the device-side (peripheral) USB stack, allowing the system
//! to act as a USB device when connected to a host. The gadget framework
//! mirrors the Linux USB gadget layer: composite functions are bound to a
//! gadget driver which owns the low-level controller.
//!
//! # Architecture
//!
//! ```text
//! USB Host ──USB cable──► GadgetController ──► GadgetDriver
//!                                                  │
//!                              ┌───────────────────┤
//!                         GadgetFunction[0..4]   GadgetEndpoint[0..8]
//! ```
//!
//! - [`GadgetSpeed`] — negotiated link speed (LS/FS/HS/SS/SS+)
//! - [`GadgetState`] — device lifecycle state machine
//! - [`EndpointDirection`] — IN (device→host) or OUT (host→device)
//! - [`TransferType`] — Control/Bulk/Interrupt/Isochronous
//! - [`GadgetEndpoint`] — a single bidirectional or unidirectional endpoint
//! - [`GadgetFunction`] — a composite gadget function (CDC-ACM, MSC, …)
//! - [`GadgetDriver`] — the overall gadget device combining endpoints/functions
//! - [`GadgetRegistry`] — system-wide registry of gadget controllers
//!
//! Reference: USB 3.2 Specification, Linux `drivers/usb/gadget/`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of endpoints per gadget driver.
const MAX_ENDPOINTS: usize = 8;

/// Maximum number of functions per gadget driver.
const MAX_FUNCTIONS: usize = 4;

/// Maximum number of gadget controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// Maximum length of a USB device/function name.
const NAME_LEN: usize = 32;

/// Maximum length of a descriptor buffer (device + config + interface + endpoints).
const MAX_DESCRIPTOR_LEN: usize = 256;

// ---------------------------------------------------------------------------
// GadgetSpeed
// ---------------------------------------------------------------------------

/// Negotiated USB link speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GadgetSpeed {
    /// USB 1.0 Low Speed (1.5 Mbit/s).
    #[default]
    Low,
    /// USB 1.1 Full Speed (12 Mbit/s).
    Full,
    /// USB 2.0 High Speed (480 Mbit/s).
    High,
    /// USB 3.0 SuperSpeed (5 Gbit/s).
    Super,
    /// USB 3.1 SuperSpeed+ (10 Gbit/s).
    SuperPlus,
}

impl GadgetSpeed {
    /// Returns the maximum packet size for a bulk endpoint at this speed.
    pub fn bulk_max_packet(self) -> u16 {
        match self {
            GadgetSpeed::Low => 8,
            GadgetSpeed::Full => 64,
            GadgetSpeed::High => 512,
            GadgetSpeed::Super | GadgetSpeed::SuperPlus => 1024,
        }
    }

    /// Returns a human-readable name for the speed.
    pub fn name(self) -> &'static str {
        match self {
            GadgetSpeed::Low => "Low-Speed",
            GadgetSpeed::Full => "Full-Speed",
            GadgetSpeed::High => "High-Speed",
            GadgetSpeed::Super => "SuperSpeed",
            GadgetSpeed::SuperPlus => "SuperSpeed+",
        }
    }
}

// ---------------------------------------------------------------------------
// GadgetState
// ---------------------------------------------------------------------------

/// USB device lifecycle state machine.
///
/// Follows the USB specification §9.1 device states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GadgetState {
    /// No VBUS present; not connected to a host.
    #[default]
    Detached,
    /// VBUS detected but not yet in a powered state.
    Attached,
    /// Device is powered but has not received a reset.
    Powered,
    /// After bus reset — address is 0, using default control pipe.
    Default,
    /// Device has been assigned a non-zero address.
    Address,
    /// SET_CONFIGURATION has been issued — device is fully configured.
    Configured,
    /// Bus is in suspend (low-power) state.
    Suspended,
}

// ---------------------------------------------------------------------------
// EndpointDirection
// ---------------------------------------------------------------------------

/// USB endpoint transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EndpointDirection {
    /// Data flows from device to host.
    #[default]
    In,
    /// Data flows from host to device.
    Out,
}

// ---------------------------------------------------------------------------
// TransferType
// ---------------------------------------------------------------------------

/// USB endpoint transfer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferType {
    /// Control transfer (always on EP0).
    #[default]
    Control,
    /// Bulk transfer (high throughput, error-checked, no latency guarantee).
    Bulk,
    /// Interrupt transfer (low latency, bounded bandwidth).
    Interrupt,
    /// Isochronous transfer (real-time, no error recovery).
    Isochronous,
}

// ---------------------------------------------------------------------------
// SetupPacket
// ---------------------------------------------------------------------------

/// A standard USB SETUP packet (8 bytes, §9.3 USB 2.0 spec).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SetupPacket {
    /// Characteristics of request (direction, type, recipient).
    pub bm_request_type: u8,
    /// Specific request number.
    pub b_request: u8,
    /// Word-sized field that varies by request.
    pub w_value: u16,
    /// Word-sized field that varies by request; typically an index.
    pub w_index: u16,
    /// Number of bytes to transfer in the data stage (0 = no data).
    pub w_length: u16,
}

impl SetupPacket {
    /// Creates a new SETUP packet.
    pub const fn new(
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
    ) -> Self {
        Self {
            bm_request_type,
            b_request,
            w_value,
            w_index,
            w_length,
        }
    }

    /// Returns `true` if this is a standard request (type bits = 0).
    pub fn is_standard(&self) -> bool {
        (self.bm_request_type & 0x60) == 0x00
    }

    /// Returns `true` if this is a class request (type bits = 1).
    pub fn is_class(&self) -> bool {
        (self.bm_request_type & 0x60) == 0x20
    }

    /// Returns `true` if the data stage is device-to-host (IN).
    pub fn is_in(&self) -> bool {
        (self.bm_request_type & 0x80) != 0
    }
}

// ---------------------------------------------------------------------------
// SetupResponse
// ---------------------------------------------------------------------------

/// Outcome of processing a SETUP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupResponse {
    /// SETUP handled — reply data length in bytes (0 = status only).
    Handled(u16),
    /// Stall the control pipe (request not understood or invalid).
    Stall,
    /// SETUP deferred for asynchronous completion.
    Deferred,
}

// ---------------------------------------------------------------------------
// GadgetEndpoint
// ---------------------------------------------------------------------------

/// A USB endpoint within a gadget driver.
///
/// EP0 (control endpoint) always exists; additional endpoints are allocated
/// by bound functions. Each endpoint has a hardware address, direction,
/// transfer type, and maximum packet size.
#[derive(Debug, Clone, Copy)]
pub struct GadgetEndpoint {
    /// Endpoint number (0–15).
    pub address: u8,
    /// Transfer direction (IN or OUT).
    pub direction: EndpointDirection,
    /// Transfer type for this endpoint.
    pub transfer_type: TransferType,
    /// Maximum packet size in bytes (determined by speed + type).
    pub max_packet_size: u16,
    /// Whether this endpoint is enabled and ready.
    pub enabled: bool,
    /// Whether this endpoint is currently halted (stalled).
    pub halted: bool,
    /// Bytes transferred on this endpoint (informational).
    pub bytes_transferred: u64,
}

impl Default for GadgetEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetEndpoint {
    /// Creates a disabled, zeroed endpoint.
    pub const fn new() -> Self {
        Self {
            address: 0,
            direction: EndpointDirection::Out,
            transfer_type: TransferType::Control,
            max_packet_size: 0,
            enabled: false,
            halted: false,
            bytes_transferred: 0,
        }
    }

    /// Creates an endpoint with the given parameters.
    pub const fn with_params(
        address: u8,
        direction: EndpointDirection,
        transfer_type: TransferType,
        max_packet_size: u16,
    ) -> Self {
        Self {
            address,
            direction,
            transfer_type,
            max_packet_size,
            enabled: false,
            halted: false,
            bytes_transferred: 0,
        }
    }

    /// Enables this endpoint.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.halted = false;
    }

    /// Disables and resets this endpoint.
    pub fn disable(&mut self) {
        self.enabled = false;
        self.halted = false;
        self.bytes_transferred = 0;
    }

    /// Halts (stalls) the endpoint.
    pub fn halt(&mut self) {
        self.halted = true;
    }

    /// Clears a halt condition.
    pub fn clear_halt(&mut self) {
        self.halted = false;
    }

    /// Records bytes transferred through this endpoint.
    pub fn record_transfer(&mut self, bytes: u64) {
        self.bytes_transferred = self.bytes_transferred.wrapping_add(bytes);
    }

    /// Returns `true` if this endpoint slot is unused.
    pub fn is_empty(&self) -> bool {
        self.max_packet_size == 0
    }
}

// ---------------------------------------------------------------------------
// GadgetFunction
// ---------------------------------------------------------------------------

/// A USB composite gadget function (e.g., CDC-ACM, Mass Storage, HID).
///
/// Functions own endpoint resources and respond to class/vendor requests
/// on their interface(s). Multiple functions can coexist inside one gadget.
pub struct GadgetFunction {
    /// Human-readable function name (null-terminated ASCII).
    pub name: [u8; NAME_LEN],
    /// Descriptor bytes for this function (interface + endpoint descriptors).
    pub descriptors: [u8; MAX_DESCRIPTOR_LEN],
    /// Number of valid bytes in `descriptors`.
    pub descriptor_len: usize,
    /// Whether this function is bound to the active configuration.
    pub bound: bool,
    /// Interface number(s) allocated to this function.
    pub interface_count: u8,
    /// Number of endpoints owned by this function.
    pub endpoint_count: u8,
}

impl Default for GadgetFunction {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetFunction {
    /// Creates an empty, unbound function.
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            descriptors: [0u8; MAX_DESCRIPTOR_LEN],
            descriptor_len: 0,
            bound: false,
            interface_count: 0,
            endpoint_count: 0,
        }
    }

    /// Creates a function with a given name.
    pub fn with_name(name: &[u8]) -> Self {
        let mut f = Self::new();
        let copy_len = name.len().min(NAME_LEN - 1);
        f.name[..copy_len].copy_from_slice(&name[..copy_len]);
        f
    }

    /// Sets the function descriptor bytes.
    pub fn set_descriptors(&mut self, descriptors: &[u8]) -> Result<()> {
        if descriptors.len() > MAX_DESCRIPTOR_LEN {
            return Err(Error::InvalidArgument);
        }
        self.descriptor_len = descriptors.len();
        self.descriptors[..self.descriptor_len].copy_from_slice(descriptors);
        Ok(())
    }

    /// Returns `true` if this function slot is unused (empty name).
    pub fn is_empty(&self) -> bool {
        self.name[0] == 0
    }

    /// Binds the function to an active configuration.
    pub fn bind(&mut self) {
        self.bound = true;
    }

    /// Unbinds the function from the configuration.
    pub fn unbind(&mut self) {
        self.bound = false;
    }
}

// ---------------------------------------------------------------------------
// GadgetDriver
// ---------------------------------------------------------------------------

/// A USB gadget driver combining endpoints and composite functions.
///
/// One gadget driver represents the entire device personality visible to
/// the USB host. It holds the device and configuration descriptors, a set
/// of endpoints, and the bound composite functions.
pub struct GadgetDriver {
    /// Device descriptor (18 bytes per USB 2.0 §9.6.1).
    pub device_descriptor: [u8; 18],
    /// Configuration descriptor (9 bytes per USB 2.0 §9.6.3).
    pub config_descriptor: [u8; 9],
    /// Current link speed.
    pub speed: GadgetSpeed,
    /// Current device state.
    pub state: GadgetState,
    /// Gadget endpoints (EP0 at index 0).
    endpoints: [GadgetEndpoint; MAX_ENDPOINTS],
    /// Number of active endpoints.
    endpoint_count: usize,
    /// Composite functions bound to this driver.
    functions: [GadgetFunction; MAX_FUNCTIONS],
    /// Number of bound functions.
    function_count: usize,
    /// Device address assigned by the host (0 = default).
    pub address: u8,
    /// Current configuration value (0 = unconfigured).
    pub configuration: u8,
}

impl Default for GadgetDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetDriver {
    /// Creates a new, unconfigured gadget driver.
    pub const fn new() -> Self {
        Self {
            device_descriptor: [0u8; 18],
            config_descriptor: [0u8; 9],
            speed: GadgetSpeed::Full,
            state: GadgetState::Detached,
            endpoints: [const { GadgetEndpoint::new() }; MAX_ENDPOINTS],
            endpoint_count: 0,
            functions: [const { GadgetFunction::new() }; MAX_FUNCTIONS],
            function_count: 0,
            address: 0,
            configuration: 0,
        }
    }

    /// Sets the standard USB device descriptor bytes.
    pub fn set_device_descriptor(&mut self, desc: &[u8; 18]) {
        self.device_descriptor = *desc;
    }

    /// Adds an endpoint to this driver.
    pub fn add_endpoint(&mut self, ep: GadgetEndpoint) -> Result<usize> {
        if self.endpoint_count >= MAX_ENDPOINTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.endpoint_count;
        self.endpoints[idx] = ep;
        self.endpoint_count += 1;
        Ok(idx)
    }

    /// Returns a reference to an endpoint by index.
    pub fn get_endpoint(&self, index: usize) -> Option<&GadgetEndpoint> {
        if index < self.endpoint_count {
            Some(&self.endpoints[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to an endpoint by index.
    pub fn get_endpoint_mut(&mut self, index: usize) -> Option<&mut GadgetEndpoint> {
        if index < self.endpoint_count {
            Some(&mut self.endpoints[index])
        } else {
            None
        }
    }

    /// Adds a composite function to this driver.
    pub fn add_function(&mut self, func: GadgetFunction) -> Result<usize> {
        if self.function_count >= MAX_FUNCTIONS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.function_count;
        self.functions[idx] = func;
        self.function_count += 1;
        Ok(idx)
    }

    /// Enables the gadget (transitions Detached → Attached → Powered → Default).
    pub fn enable(&mut self) {
        if self.state == GadgetState::Detached {
            self.state = GadgetState::Powered;
        }
    }

    /// Disables the gadget and resets to Detached state.
    pub fn disable(&mut self) {
        self.state = GadgetState::Detached;
        self.address = 0;
        self.configuration = 0;
        for i in 0..self.endpoint_count {
            self.endpoints[i].disable();
        }
    }

    /// Resets the gadget as if a USB bus reset occurred.
    pub fn bus_reset(&mut self) {
        self.state = GadgetState::Default;
        self.address = 0;
        self.configuration = 0;
        self.speed = GadgetSpeed::Full;
    }

    /// Processes a SETUP packet on EP0.
    ///
    /// Handles standard requests (GET_DESCRIPTOR, SET_ADDRESS,
    /// SET_CONFIGURATION) and delegates class/vendor requests to functions.
    pub fn process_setup(&mut self, pkt: &SetupPacket) -> SetupResponse {
        if pkt.is_standard() {
            match pkt.b_request {
                // GET_DESCRIPTOR
                0x06 => {
                    let descriptor_type = (pkt.w_value >> 8) as u8;
                    match descriptor_type {
                        // Device descriptor (type 1)
                        0x01 => SetupResponse::Handled(self.device_descriptor[0] as u16),
                        // Configuration descriptor (type 2)
                        0x02 => SetupResponse::Handled(self.config_descriptor[0] as u16),
                        _ => SetupResponse::Stall,
                    }
                }
                // SET_ADDRESS
                0x05 => {
                    self.address = (pkt.w_value & 0x7F) as u8;
                    self.state = if self.address == 0 {
                        GadgetState::Default
                    } else {
                        GadgetState::Address
                    };
                    SetupResponse::Handled(0)
                }
                // SET_CONFIGURATION
                0x09 => {
                    self.configuration = (pkt.w_value & 0xFF) as u8;
                    self.state = if self.configuration == 0 {
                        GadgetState::Address
                    } else {
                        GadgetState::Configured
                    };
                    SetupResponse::Handled(0)
                }
                // GET_CONFIGURATION
                0x08 => SetupResponse::Handled(1),
                _ => SetupResponse::Stall,
            }
        } else {
            // Class/vendor requests: delegate to bound functions
            SetupResponse::Stall
        }
    }

    /// Returns the number of active endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoint_count
    }

    /// Returns the number of bound functions.
    pub fn function_count(&self) -> usize {
        self.function_count
    }
}

// ---------------------------------------------------------------------------
// GadgetRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of USB gadget controllers.
///
/// Up to [`MAX_CONTROLLERS`] gadget controllers can be registered.
/// Each entry pairs a controller hardware identifier with its driver.
pub struct GadgetRegistry {
    /// Registered gadget drivers (indexed by controller ID).
    drivers: [GadgetDriver; MAX_CONTROLLERS],
    /// Whether each slot is occupied.
    occupied: [bool; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for GadgetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetRegistry {
    /// Creates an empty gadget registry.
    pub fn new() -> Self {
        Self {
            drivers: [
                const { GadgetDriver::new() },
                const { GadgetDriver::new() },
                const { GadgetDriver::new() },
                const { GadgetDriver::new() },
            ],
            occupied: [false; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a gadget driver, returning its controller index.
    pub fn register(&mut self, driver: GadgetDriver) -> Result<usize> {
        for i in 0..MAX_CONTROLLERS {
            if !self.occupied[i] {
                self.drivers[i] = driver;
                self.occupied[i] = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters and removes a gadget driver by index.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CONTROLLERS || !self.occupied[index] {
            return Err(Error::NotFound);
        }
        self.drivers[index].disable();
        self.drivers[index] = GadgetDriver::new();
        self.occupied[index] = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller's driver.
    pub fn get(&self, index: usize) -> Result<&GadgetDriver> {
        if index >= MAX_CONTROLLERS || !self.occupied[index] {
            return Err(Error::NotFound);
        }
        Ok(&self.drivers[index])
    }

    /// Returns a mutable reference to a controller's driver.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut GadgetDriver> {
        if index >= MAX_CONTROLLERS || !self.occupied[index] {
            return Err(Error::NotFound);
        }
        Ok(&mut self.drivers[index])
    }

    /// Binds a function to the driver at `controller_index`.
    pub fn bind_function(&mut self, controller_index: usize, func: GadgetFunction) -> Result<()> {
        let driver = self.get_mut(controller_index)?;
        driver.add_function(func)?;
        Ok(())
    }

    /// Unbinds all functions from the driver at `controller_index`.
    pub fn unbind_all(&mut self, controller_index: usize) -> Result<()> {
        let driver = self.get_mut(controller_index)?;
        driver.function_count = 0;
        Ok(())
    }

    /// Enables the gadget controller at `index`.
    pub fn enable(&mut self, index: usize) -> Result<()> {
        self.get_mut(index)?.enable();
        Ok(())
    }

    /// Disables the gadget controller at `index`.
    pub fn disable(&mut self, index: usize) -> Result<()> {
        self.get_mut(index)?.disable();
        Ok(())
    }

    /// Issues a bus reset to the gadget controller at `index`.
    pub fn reset(&mut self, index: usize) -> Result<()> {
        self.get_mut(index)?.bus_reset();
        Ok(())
    }

    /// Delivers a SETUP packet to the gadget controller at `index`.
    pub fn process_setup(&mut self, index: usize, pkt: &SetupPacket) -> Result<SetupResponse> {
        let driver = self.get_mut(index)?;
        Ok(driver.process_setup(pkt))
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

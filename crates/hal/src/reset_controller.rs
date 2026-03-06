// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reset controller framework.
//!
//! Provides a generic reset controller abstraction for managing
//! hardware reset lines. Each reset controller owns a set of reset
//! lines that can be individually asserted, deasserted, toggled, or
//! queried for status.
//!
//! # Architecture
//!
//! - [`ResetLineMode`] -- shared vs exclusive access policy per line.
//! - [`ResetLineState`] -- current asserted/deasserted state of a line.
//! - [`ResetLine`] -- descriptor for a single reset line with
//!   reference-counted shared access.
//! - [`ResetController`] -- a controller managing up to
//!   [`MAX_LINES_PER_CONTROLLER`] reset lines.
//! - [`ResetControllerRegistry`] -- system-wide registry of controllers.
//! - [`PlatformResetType`] -- system-level reset types (warm, cold,
//!   watchdog, software).
//! - [`PlatformResetController`] -- top-level platform reset manager
//!   that delegates to the appropriate [`ResetController`].
//!
//! # Usage
//!
//! ```ignore
//! let mut ctrl = ResetController::new(0);
//! ctrl.init(8)?;                     // 8 reset lines
//! ctrl.assert_line(0)?;              // assert line 0
//! ctrl.deassert_line(0)?;            // deassert line 0
//! ctrl.reset_line(0, 100)?;          // toggle reset (assert + deassert)
//! ```

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of reset lines per controller.
const MAX_LINES_PER_CONTROLLER: usize = 32;

/// Maximum number of reset controllers in the registry.
const MAX_CONTROLLERS: usize = 8;

/// Maximum number of operations in a bulk reset sequence.
const MAX_BULK_OPS: usize = 16;

/// Default reset pulse width in arbitrary time units (microseconds
/// conceptually; the actual delay mechanism is platform-specific).
const DEFAULT_RESET_PULSE_US: u32 = 10;

// -------------------------------------------------------------------
// ResetLineMode
// -------------------------------------------------------------------

/// Access mode for a reset line.
///
/// Controls whether multiple consumers may share a reset line or
/// whether a single consumer has exclusive ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResetLineMode {
    /// The reset line may be shared among multiple consumers.
    /// Assert/deassert is reference-counted: the line is only
    /// physically deasserted when all consumers have released it.
    #[default]
    Shared,
    /// The reset line is exclusively owned by one consumer.
    /// Only that consumer may assert or deassert the line.
    Exclusive,
}

// -------------------------------------------------------------------
// ResetLineState
// -------------------------------------------------------------------

/// Physical state of a reset line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResetLineState {
    /// The reset line is deasserted (device is out of reset).
    #[default]
    Deasserted,
    /// The reset line is asserted (device is held in reset).
    Asserted,
}

// -------------------------------------------------------------------
// ResetLine
// -------------------------------------------------------------------

/// Descriptor for a single reset line managed by a
/// [`ResetController`].
///
/// Shared lines use a reference count: assert increments, deassert
/// decrements, and the hardware is only toggled at transitions
/// through zero.
#[derive(Debug, Clone, Copy)]
pub struct ResetLine {
    /// Global reset-line identifier (controller_id << 16 | line index).
    pub id: u32,
    /// Current physical state of the line.
    pub state: ResetLineState,
    /// Access mode (shared or exclusive).
    pub mode: ResetLineMode,
    /// Number of consumers that have asserted this line. Only
    /// meaningful when `mode == Shared`.
    pub assert_count: u32,
    /// Whether the line is currently acquired by any consumer.
    pub acquired: bool,
    /// Optional MMIO register offset for this line's control bit.
    pub reg_offset: u32,
    /// Bit position within the control register.
    pub bit_index: u8,
    /// Reset pulse width in microseconds (for toggle operations).
    pub pulse_width_us: u32,
}

impl ResetLine {
    /// Creates a new, idle reset line.
    const fn new() -> Self {
        Self {
            id: 0,
            state: ResetLineState::Deasserted,
            mode: ResetLineMode::Shared,
            assert_count: 0,
            acquired: false,
            reg_offset: 0,
            bit_index: 0,
            pulse_width_us: DEFAULT_RESET_PULSE_US,
        }
    }

    /// Returns `true` if the line is currently held in reset.
    pub fn is_asserted(&self) -> bool {
        self.state == ResetLineState::Asserted
    }
}

// -------------------------------------------------------------------
// BulkResetOp
// -------------------------------------------------------------------

/// A single operation in a bulk reset sequence.
#[derive(Debug, Clone, Copy)]
pub struct BulkResetOp {
    /// Index of the reset line within the controller.
    pub line_index: u8,
    /// Whether to assert (`true`) or deassert (`false`).
    pub assert: bool,
    /// Delay after this operation, in microseconds.
    pub delay_us: u32,
}

impl BulkResetOp {
    /// Creates an assert operation for `line_index` with a delay.
    pub const fn assert(line_index: u8, delay_us: u32) -> Self {
        Self {
            line_index,
            assert: true,
            delay_us,
        }
    }

    /// Creates a deassert operation for `line_index` with a delay.
    pub const fn deassert(line_index: u8, delay_us: u32) -> Self {
        Self {
            line_index,
            assert: false,
            delay_us,
        }
    }
}

// -------------------------------------------------------------------
// BulkResetSequence
// -------------------------------------------------------------------

/// An ordered sequence of reset operations executed atomically.
///
/// Used for complex reset sequencing where multiple lines must be
/// toggled in a specific order with prescribed inter-operation delays.
pub struct BulkResetSequence {
    /// Individual operations in execution order.
    ops: [BulkResetOp; MAX_BULK_OPS],
    /// Number of valid operations.
    count: usize,
}

impl Default for BulkResetSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkResetSequence {
    /// Creates an empty bulk sequence.
    pub const fn new() -> Self {
        Self {
            ops: [BulkResetOp {
                line_index: 0,
                assert: false,
                delay_us: 0,
            }; MAX_BULK_OPS],
            count: 0,
        }
    }

    /// Appends an operation to the sequence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the sequence is full.
    pub fn push(&mut self, op: BulkResetOp) -> Result<()> {
        if self.count >= MAX_BULK_OPS {
            return Err(Error::OutOfMemory);
        }
        self.ops[self.count] = op;
        self.count += 1;
        Ok(())
    }

    /// Returns a slice of the operations in this sequence.
    pub fn ops(&self) -> &[BulkResetOp] {
        &self.ops[..self.count]
    }

    /// Returns the number of operations.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the sequence contains no operations.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears all operations from the sequence.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

// -------------------------------------------------------------------
// ResetController
// -------------------------------------------------------------------

/// A reset controller that manages a bank of hardware reset lines.
///
/// Each controller owns up to [`MAX_LINES_PER_CONTROLLER`] lines.
/// Lines can be individually asserted, deasserted, toggled, or
/// queried. Shared lines use reference counting.
pub struct ResetController {
    /// Controller identifier.
    pub id: u32,
    /// Reset lines owned by this controller.
    lines: [ResetLine; MAX_LINES_PER_CONTROLLER],
    /// Number of lines configured for this controller.
    line_count: usize,
    /// MMIO base address of the reset controller registers.
    base_addr: u64,
    /// Whether the controller has been initialised.
    initialized: bool,
}

impl Default for ResetController {
    fn default() -> Self {
        Self::new(0)
    }
}

impl ResetController {
    /// Creates an uninitialised reset controller with the given `id`.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            lines: [const { ResetLine::new() }; MAX_LINES_PER_CONTROLLER],
            line_count: 0,
            base_addr: 0,
            initialized: false,
        }
    }

    /// Initialises the reset controller with `num_lines` lines.
    ///
    /// Each line is assigned a global ID formed as
    /// `(controller_id << 16) | line_index`, and default register
    /// offsets are computed assuming one bit per line packed into
    /// 32-bit control registers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `num_lines` is zero or
    /// exceeds [`MAX_LINES_PER_CONTROLLER`].
    pub fn init(&mut self, num_lines: usize) -> Result<()> {
        if num_lines == 0 || num_lines > MAX_LINES_PER_CONTROLLER {
            return Err(Error::InvalidArgument);
        }

        self.line_count = num_lines;

        for (i, line) in self.lines[..num_lines].iter_mut().enumerate() {
            line.id = (self.id << 16) | (i as u32);
            line.state = ResetLineState::Deasserted;
            line.mode = ResetLineMode::Shared;
            line.assert_count = 0;
            line.acquired = false;
            // Assume 32-bit registers, one bit per line.
            line.reg_offset = (i / 32) as u32 * 4;
            line.bit_index = (i % 32) as u8;
            line.pulse_width_us = DEFAULT_RESET_PULSE_US;
        }

        self.initialized = true;
        Ok(())
    }

    /// Sets the MMIO base address for this controller.
    pub fn set_base_addr(&mut self, addr: u64) {
        self.base_addr = addr;
    }

    /// Returns the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns `true` if the controller has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the number of reset lines.
    pub fn line_count(&self) -> usize {
        self.line_count
    }

    // ── Line validation ─────────────────────────────────────────

    /// Returns a shared reference to a line, validating the index.
    fn get_line(&self, index: usize) -> Result<&ResetLine> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if index >= self.line_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.lines[index])
    }

    /// Returns a mutable reference to a line, validating the index.
    fn get_line_mut(&mut self, index: usize) -> Result<&mut ResetLine> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if index >= self.line_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.lines[index])
    }

    // ── Acquire / release ───────────────────────────────────────

    /// Acquires a reset line for use.
    ///
    /// For exclusive lines, only one consumer may acquire the line
    /// at a time. For shared lines, multiple consumers may acquire.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range.
    /// - [`Error::Busy`] if the line is exclusive and already acquired.
    pub fn acquire_line(&mut self, index: usize, mode: ResetLineMode) -> Result<()> {
        let line = self.get_line_mut(index)?;

        if line.acquired && line.mode == ResetLineMode::Exclusive {
            return Err(Error::Busy);
        }

        if line.acquired && mode == ResetLineMode::Exclusive {
            return Err(Error::Busy);
        }

        line.mode = mode;
        line.acquired = true;
        Ok(())
    }

    /// Releases a previously acquired reset line.
    ///
    /// If the line is shared and still asserted, the assertion count
    /// for this consumer is decremented. If the count reaches zero,
    /// the line is physically deasserted.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range.
    /// - [`Error::NotFound`] if the line is not acquired.
    pub fn release_line(&mut self, index: usize) -> Result<()> {
        let line = self.get_line_mut(index)?;

        if !line.acquired {
            return Err(Error::NotFound);
        }

        // If shared and assert_count > 0, decrement it.
        if line.mode == ResetLineMode::Shared && line.assert_count > 0 {
            line.assert_count -= 1;
            if line.assert_count == 0 {
                line.state = ResetLineState::Deasserted;
            }
        } else {
            line.state = ResetLineState::Deasserted;
        }

        line.acquired = false;
        Ok(())
    }

    // ── Assert / deassert ───────────────────────────────────────

    /// Asserts a reset line (puts the device into reset).
    ///
    /// For shared lines, increments the assertion reference count.
    /// For exclusive lines, directly asserts the hardware.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range or
    ///   the controller is not initialised.
    pub fn assert_line(&mut self, index: usize) -> Result<()> {
        let line = self.get_line_mut(index)?;

        match line.mode {
            ResetLineMode::Shared => {
                line.assert_count += 1;
                line.state = ResetLineState::Asserted;
            }
            ResetLineMode::Exclusive => {
                line.state = ResetLineState::Asserted;
            }
        }

        Ok(())
    }

    /// Deasserts a reset line (takes the device out of reset).
    ///
    /// For shared lines, decrements the assertion reference count.
    /// The hardware is only deasserted when the count reaches zero.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range or
    ///   the controller is not initialised.
    /// - [`Error::InvalidArgument`] if a shared line's count is
    ///   already zero.
    pub fn deassert_line(&mut self, index: usize) -> Result<()> {
        let line = self.get_line_mut(index)?;

        match line.mode {
            ResetLineMode::Shared => {
                if line.assert_count == 0 {
                    return Err(Error::InvalidArgument);
                }
                line.assert_count -= 1;
                if line.assert_count == 0 {
                    line.state = ResetLineState::Deasserted;
                }
            }
            ResetLineMode::Exclusive => {
                line.state = ResetLineState::Deasserted;
            }
        }

        Ok(())
    }

    /// Toggles a reset line: asserts, holds for the configured
    /// pulse width, then deasserts.
    ///
    /// Returns the pulse width in microseconds so the caller can
    /// implement the actual delay (this layer is platform-agnostic
    /// and does not busy-wait).
    ///
    /// # Errors
    ///
    /// Returns errors from [`assert_line`](Self::assert_line) or
    /// [`deassert_line`](Self::deassert_line).
    pub fn reset_line(&mut self, index: usize, _delay_hint_us: u32) -> Result<u32> {
        let pulse = self.get_line(index)?.pulse_width_us;
        self.assert_line(index)?;
        // Caller is expected to wait `pulse` microseconds here.
        self.deassert_line(index)?;
        Ok(pulse)
    }

    /// Queries the current state of a reset line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn line_status(&self, index: usize) -> Result<ResetLineState> {
        Ok(self.get_line(index)?.state)
    }

    /// Returns a shared reference to a reset line descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn line_info(&self, index: usize) -> Result<&ResetLine> {
        self.get_line(index)
    }

    /// Sets the pulse width for a reset line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn set_pulse_width(&mut self, index: usize, width_us: u32) -> Result<()> {
        self.get_line_mut(index)?.pulse_width_us = width_us;
        Ok(())
    }

    // ── Bulk operations ─────────────────────────────────────────

    /// Asserts all lines in the given index slice.
    ///
    /// Stops at the first error and returns it. Lines that were
    /// already asserted before that point remain asserted.
    ///
    /// # Errors
    ///
    /// Returns any error from [`assert_line`](Self::assert_line).
    pub fn assert_bulk(&mut self, indices: &[usize]) -> Result<()> {
        for &idx in indices {
            self.assert_line(idx)?;
        }
        Ok(())
    }

    /// Deasserts all lines in the given index slice.
    ///
    /// # Errors
    ///
    /// Returns any error from [`deassert_line`](Self::deassert_line).
    pub fn deassert_bulk(&mut self, indices: &[usize]) -> Result<()> {
        for &idx in indices {
            self.deassert_line(idx)?;
        }
        Ok(())
    }

    /// Executes a [`BulkResetSequence`] on this controller.
    ///
    /// Each operation is executed in order. The accumulated delay
    /// (sum of per-operation `delay_us` fields) is returned so
    /// the caller can perform the blocking wait.
    ///
    /// # Errors
    ///
    /// Returns errors from the first failing assert/deassert
    /// operation.
    pub fn execute_sequence(&mut self, seq: &BulkResetSequence) -> Result<u32> {
        let mut total_delay_us: u32 = 0;

        for op in seq.ops() {
            let idx = op.line_index as usize;
            if op.assert {
                self.assert_line(idx)?;
            } else {
                self.deassert_line(idx)?;
            }
            total_delay_us = total_delay_us.saturating_add(op.delay_us);
        }

        Ok(total_delay_us)
    }
}

// -------------------------------------------------------------------
// ResetControllerRegistry
// -------------------------------------------------------------------

/// System-wide registry of [`ResetController`] instances.
///
/// Supports up to [`MAX_CONTROLLERS`] controllers, typically
/// discovered via ACPI or device tree enumeration.
pub struct ResetControllerRegistry {
    /// Registered controllers.
    controllers: [ResetController; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for ResetControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ResetControllerRegistry {
    /// Creates an empty controller registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { ResetController::new(0) }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a reset controller and returns its registry index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a controller with the same
    ///   `id` is already registered.
    pub fn register(&mut self, controller: ResetController) -> Result<usize> {
        for existing in &self.controllers[..self.count] {
            if existing.id == controller.id {
                return Err(Error::AlreadyExists);
            }
        }

        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.count;
        self.controllers[idx] = controller;
        self.count += 1;
        Ok(idx)
    }

    /// Returns a shared reference to a controller by registry index.
    pub fn get(&self, index: usize) -> Option<&ResetController> {
        if index < self.count {
            Some(&self.controllers[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to a controller by registry index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ResetController> {
        if index < self.count {
            Some(&mut self.controllers[index])
        } else {
            None
        }
    }

    /// Looks up a controller by its `id`.
    pub fn find_by_id(&self, id: u32) -> Option<&ResetController> {
        self.controllers[..self.count].iter().find(|c| c.id == id)
    }

    /// Looks up a mutable reference to a controller by its `id`.
    pub fn find_by_id_mut(&mut self, id: u32) -> Option<&mut ResetController> {
        self.controllers[..self.count]
            .iter_mut()
            .find(|c| c.id == id)
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

// -------------------------------------------------------------------
// PlatformResetType
// -------------------------------------------------------------------

/// System-level reset type.
///
/// Different reset types have different side-effects on hardware
/// state persistence:
///
/// - **Cold**: Full power cycle; all hardware state is lost.
/// - **Warm**: CPU and memory are reset but peripheral configuration
///   may be preserved.
/// - **Watchdog**: Reset triggered by the hardware watchdog timer.
/// - **Software**: Reset initiated by software (e.g., `reboot(2)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformResetType {
    /// Cold reset (full power cycle).
    Cold,
    /// Warm reset (CPU/memory only).
    Warm,
    /// Watchdog-triggered reset.
    Watchdog,
    /// Software-initiated reset.
    Software,
}

// -------------------------------------------------------------------
// PlatformResetHandler
// -------------------------------------------------------------------

/// Record of a registered platform reset handler.
///
/// The handler stores its priority and the controller + line it
/// should toggle to effect the requested reset type.
#[derive(Debug, Clone, Copy)]
pub struct PlatformResetHandler {
    /// Reset type this handler covers.
    pub reset_type: PlatformResetType,
    /// Priority (lower = higher priority, used first).
    pub priority: u8,
    /// Index of the controller in the global registry.
    pub controller_index: usize,
    /// Line index within the controller.
    pub line_index: usize,
    /// Whether this handler is enabled.
    pub enabled: bool,
}

/// Maximum number of platform reset handlers.
const MAX_PLATFORM_HANDLERS: usize = 8;

// -------------------------------------------------------------------
// PlatformResetController
// -------------------------------------------------------------------

/// Top-level platform reset manager.
///
/// Maintains a priority-ordered list of reset handlers and
/// delegates reset requests to the appropriate [`ResetController`]
/// line.
pub struct PlatformResetController {
    /// Registered handlers, in priority order (lowest first).
    handlers: [Option<PlatformResetHandler>; MAX_PLATFORM_HANDLERS],
    /// Number of registered handlers.
    handler_count: usize,
    /// Default reset type when none is specified.
    pub default_type: PlatformResetType,
    /// Whether platform reset is enabled.
    pub enabled: bool,
}

impl Default for PlatformResetController {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformResetController {
    /// Creates an uninitialised platform reset controller.
    pub const fn new() -> Self {
        Self {
            handlers: [const { None }; MAX_PLATFORM_HANDLERS],
            handler_count: 0,
            default_type: PlatformResetType::Cold,
            enabled: false,
        }
    }

    /// Initialises the platform reset controller.
    pub fn init(&mut self) -> Result<()> {
        self.enabled = true;
        Ok(())
    }

    /// Registers a platform reset handler.
    ///
    /// Handlers are inserted in priority order (lowest priority
    /// value first). Duplicate reset types are allowed; the
    /// lowest-priority handler is used first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the handler table is full.
    pub fn register_handler(&mut self, handler: PlatformResetHandler) -> Result<()> {
        if self.handler_count >= MAX_PLATFORM_HANDLERS {
            return Err(Error::OutOfMemory);
        }

        // Insert in sorted order by priority.
        let insert_pos = self.handlers[..self.handler_count]
            .iter()
            .position(|h| {
                h.as_ref()
                    .map_or(true, |existing| existing.priority > handler.priority)
            })
            .unwrap_or(self.handler_count);

        // Shift entries to make room.
        let mut i = self.handler_count;
        while i > insert_pos {
            self.handlers[i] = self.handlers[i - 1];
            i -= 1;
        }

        self.handlers[insert_pos] = Some(handler);
        self.handler_count += 1;
        Ok(())
    }

    /// Finds the best handler for a given reset type.
    ///
    /// Returns the highest-priority (lowest priority number) enabled
    /// handler that matches the requested reset type.
    pub fn find_handler(&self, reset_type: PlatformResetType) -> Option<&PlatformResetHandler> {
        self.handlers[..self.handler_count]
            .iter()
            .flatten()
            .find(|h| h.reset_type == reset_type && h.enabled)
    }

    /// Executes a platform reset of the given type against the
    /// provided [`ResetControllerRegistry`].
    ///
    /// Looks up the best handler for the requested type and asserts
    /// the corresponding reset line. In a real system this would not
    /// return; we return `Ok(())` to indicate the reset was issued.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the platform controller is not
    ///   enabled.
    /// - [`Error::NotFound`] if no handler is registered for the
    ///   requested reset type.
    /// - Errors from the underlying [`ResetController::assert_line`].
    pub fn execute_reset(
        &self,
        reset_type: PlatformResetType,
        registry: &mut ResetControllerRegistry,
    ) -> Result<()> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }

        let handler = self.find_handler(reset_type).ok_or(Error::NotFound)?;

        let ctrl = registry
            .get_mut(handler.controller_index)
            .ok_or(Error::NotFound)?;

        ctrl.assert_line(handler.line_index)?;
        Ok(())
    }

    /// Executes a reset using the default reset type.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`execute_reset`](Self::execute_reset).
    pub fn execute_default_reset(&self, registry: &mut ResetControllerRegistry) -> Result<()> {
        self.execute_reset(self.default_type, registry)
    }

    /// Returns the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handler_count
    }

    /// Enables or disables a handler by its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn set_handler_enabled(&mut self, index: usize, enabled: bool) -> Result<()> {
        let handler = self
            .handlers
            .get_mut(index)
            .and_then(|h| h.as_mut())
            .ok_or(Error::InvalidArgument)?;

        handler.enabled = enabled;
        Ok(())
    }

    /// Returns information about a handler by its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn handler_info(&self, index: usize) -> Result<&PlatformResetHandler> {
        self.handlers
            .get(index)
            .and_then(|h| h.as_ref())
            .ok_or(Error::InvalidArgument)
    }
}

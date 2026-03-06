// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock tree management framework.
//!
//! Provides a generic clock framework for managing clock sources,
//! dividers, multiplexers, and gates in a hierarchical clock tree.
//! Each clock source tracks its enable reference count, parent
//! relationship, and current rate.
//!
//! # Architecture
//!
//! - [`ClockType`] -- classification of a clock node (fixed, divider,
//!   mux, gate, PLL).
//! - [`ClockState`] -- whether a clock is enabled or gated off.
//! - [`ClockSource`] -- a single node in the clock tree, with rate,
//!   parent, enable count, and type-specific parameters.
//! - [`ClockDivider`] -- parameters for a divider clock.
//! - [`ClockMux`] -- parameters for a clock multiplexer.
//! - [`ClockGate`] -- parameters for a clock gate.
//! - [`ClockTree`] -- the top-level clock tree managing up to
//!   [`MAX_CLOCKS`] sources.
//! - [`ClockTreeDump`] -- snapshot of the clock tree for debugging.
//!
//! # Usage
//!
//! ```ignore
//! let mut tree = ClockTree::new();
//! let osc = tree.register_fixed("osc0", 24_000_000)?;
//! let pll = tree.register_clock("pll0", ClockType::Pll, Some(osc))?;
//! tree.set_rate(pll, 480_000_000)?;
//! tree.enable(pll)?;
//! ```

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of clocks in the tree.
const MAX_CLOCKS: usize = 64;

/// Maximum number of children per clock (for parent->child tracking).
const MAX_CHILDREN: usize = 8;

/// Maximum depth for recursive tree operations.
const MAX_TREE_DEPTH: usize = 16;

/// Maximum length of a clock name.
const MAX_NAME_LEN: usize = 32;

// -------------------------------------------------------------------
// ClockType
// -------------------------------------------------------------------

/// Type of clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockType {
    /// Fixed-rate oscillator (rate set at creation, cannot change).
    #[default]
    Fixed,
    /// Clock divider (output = parent_rate / divider).
    Divider,
    /// Clock multiplexer (selects one of several parent clocks).
    Mux,
    /// Clock gate (passes parent rate through or gates it off).
    Gate,
    /// Phase-locked loop (multiplies parent rate).
    Pll,
}

// -------------------------------------------------------------------
// ClockState
// -------------------------------------------------------------------

/// Current state of a clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClockState {
    /// Clock is disabled / gated off.
    #[default]
    Disabled,
    /// Clock is enabled and running.
    Enabled,
}

// -------------------------------------------------------------------
// ClockDivider
// -------------------------------------------------------------------

/// Parameters for a clock divider.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClockDivider {
    /// Current divider value (1-based; output = parent / divider).
    pub divider: u32,
    /// Minimum allowed divider.
    pub min_div: u32,
    /// Maximum allowed divider.
    pub max_div: u32,
    /// MMIO register offset for the divider field.
    pub reg_offset: u32,
    /// Bit shift of the divider field within the register.
    pub shift: u8,
    /// Bit width of the divider field.
    pub width: u8,
}

// -------------------------------------------------------------------
// ClockMux
// -------------------------------------------------------------------

/// Parameters for a clock multiplexer.
#[derive(Debug, Clone, Copy)]
pub struct ClockMux {
    /// Available parent clock indices.
    pub parents: [u16; MAX_CHILDREN],
    /// Number of valid parent entries.
    pub num_parents: u8,
    /// Currently selected parent index (into `parents`).
    pub selected: u8,
    /// MMIO register offset for the mux select field.
    pub reg_offset: u32,
    /// Bit shift of the select field.
    pub shift: u8,
    /// Bit width of the select field.
    pub width: u8,
}

impl Default for ClockMux {
    fn default() -> Self {
        Self {
            parents: [0; MAX_CHILDREN],
            num_parents: 0,
            selected: 0,
            reg_offset: 0,
            shift: 0,
            width: 0,
        }
    }
}

// -------------------------------------------------------------------
// ClockGate
// -------------------------------------------------------------------

/// Parameters for a clock gate.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClockGate {
    /// MMIO register offset for the gate bit.
    pub reg_offset: u32,
    /// Bit position of the gate control bit.
    pub bit_index: u8,
    /// Whether the gate sense is inverted (1 = gated off).
    pub inverted: bool,
}

// -------------------------------------------------------------------
// ClockSource
// -------------------------------------------------------------------

/// A single node in the clock tree.
///
/// Each clock source has a name, type, optional parent, rate, and
/// enable reference count. The clock is physically enabled only
/// when `enable_count > 0`.
#[derive(Debug, Clone, Copy)]
pub struct ClockSource {
    /// Clock identifier (index in the tree).
    pub id: u16,
    /// Human-readable name (null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub name_len: u8,
    /// Clock type.
    pub clock_type: ClockType,
    /// Current state (enabled / disabled).
    pub state: ClockState,
    /// Current output rate in Hz.
    pub rate_hz: u64,
    /// Parent clock index (u16::MAX if none / root).
    pub parent: u16,
    /// Number of consumers that have enabled this clock.
    /// The hardware clock is only active when count > 0.
    pub enable_count: u32,
    /// Whether this clock node is in use (registered).
    pub in_use: bool,
    /// Divider parameters (valid when `clock_type == Divider`).
    pub divider: ClockDivider,
    /// Mux parameters (valid when `clock_type == Mux`).
    pub mux: ClockMux,
    /// Gate parameters (valid when `clock_type == Gate`).
    pub gate: ClockGate,
    /// PLL multiplier (valid when `clock_type == Pll`).
    pub pll_mult: u32,
    /// PLL post-divider (valid when `clock_type == Pll`).
    pub pll_div: u32,
}

impl ClockSource {
    /// Creates an empty, unused clock source.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            clock_type: ClockType::Fixed,
            state: ClockState::Disabled,
            rate_hz: 0,
            parent: u16::MAX,
            enable_count: 0,
            in_use: false,
            divider: ClockDivider {
                divider: 1,
                min_div: 1,
                max_div: 1,
                reg_offset: 0,
                shift: 0,
                width: 0,
            },
            mux: ClockMux {
                parents: [0; MAX_CHILDREN],
                num_parents: 0,
                selected: 0,
                reg_offset: 0,
                shift: 0,
                width: 0,
            },
            gate: ClockGate {
                reg_offset: 0,
                bit_index: 0,
                inverted: false,
            },
            pll_mult: 1,
            pll_div: 1,
        }
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns `true` if the clock is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.state == ClockState::Enabled
    }

    /// Returns `true` if this is a root clock (no parent).
    pub fn is_root(&self) -> bool {
        self.parent == u16::MAX
    }

    /// Computes the output rate based on clock type and parent rate.
    fn compute_rate(&self, parent_rate: u64) -> u64 {
        match self.clock_type {
            ClockType::Fixed => self.rate_hz,
            ClockType::Divider => {
                if self.divider.divider == 0 {
                    0
                } else {
                    parent_rate / self.divider.divider as u64
                }
            }
            ClockType::Mux => parent_rate,
            ClockType::Gate => {
                if self.state == ClockState::Enabled {
                    parent_rate
                } else {
                    0
                }
            }
            ClockType::Pll => {
                if self.pll_div == 0 {
                    0
                } else {
                    parent_rate.saturating_mul(self.pll_mult as u64) / self.pll_div as u64
                }
            }
        }
    }
}

// -------------------------------------------------------------------
// ClockTreeDumpEntry
// -------------------------------------------------------------------

/// A single entry in a clock tree dump (for debugging).
#[derive(Debug, Clone, Copy)]
pub struct ClockTreeDumpEntry {
    /// Clock index.
    pub id: u16,
    /// Nesting depth (0 = root).
    pub depth: u8,
    /// Clock name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name length.
    pub name_len: u8,
    /// Clock type.
    pub clock_type: ClockType,
    /// Current state.
    pub state: ClockState,
    /// Current rate in Hz.
    pub rate_hz: u64,
    /// Enable reference count.
    pub enable_count: u32,
}

// -------------------------------------------------------------------
// ClockTreeDump
// -------------------------------------------------------------------

/// Snapshot of the entire clock tree for debugging or sysfs export.
pub struct ClockTreeDump {
    /// Dump entries, one per clock in tree-walk order.
    pub entries: [ClockTreeDumpEntry; MAX_CLOCKS],
    /// Number of valid entries.
    pub count: usize,
}

impl Default for ClockTreeDump {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockTreeDump {
    /// Creates an empty dump.
    pub const fn new() -> Self {
        Self {
            entries: [ClockTreeDumpEntry {
                id: 0,
                depth: 0,
                name: [0u8; MAX_NAME_LEN],
                name_len: 0,
                clock_type: ClockType::Fixed,
                state: ClockState::Disabled,
                rate_hz: 0,
                enable_count: 0,
            }; MAX_CLOCKS],
            count: 0,
        }
    }
}

// -------------------------------------------------------------------
// ClockTree
// -------------------------------------------------------------------

/// Manages a hierarchical tree of clock sources.
///
/// Supports up to [`MAX_CLOCKS`] clock nodes. The tree enforces
/// enable-count propagation: enabling a clock also enables its
/// parent chain, and disabling only physically gates the clock when
/// the reference count drops to zero.
pub struct ClockTree {
    /// All clock sources.
    clocks: [ClockSource; MAX_CLOCKS],
    /// Number of registered (in-use) clocks.
    count: usize,
    /// MMIO base address of the clock controller registers.
    base_addr: u64,
    /// Whether the clock tree has been initialised.
    initialized: bool,
}

impl Default for ClockTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockTree {
    /// Creates an empty, uninitialised clock tree.
    pub const fn new() -> Self {
        Self {
            clocks: [const { ClockSource::empty() }; MAX_CLOCKS],
            count: 0,
            base_addr: 0,
            initialized: false,
        }
    }

    /// Initialises the clock tree with an optional MMIO base address.
    pub fn init(&mut self, base_addr: u64) -> Result<()> {
        self.base_addr = base_addr;
        self.initialized = true;
        Ok(())
    }

    /// Returns the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the number of registered clocks.
    pub fn clock_count(&self) -> usize {
        self.count
    }

    // ── Registration ────────────────────────────────────────────

    /// Registers a new clock source in the tree.
    ///
    /// Returns the clock's index (which is also its `id`).
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the tree is full.
    /// - [`Error::InvalidArgument`] if `parent` is specified but
    ///   out of range.
    pub fn register_clock(
        &mut self,
        name: &[u8],
        clock_type: ClockType,
        parent: Option<u16>,
    ) -> Result<u16> {
        if self.count >= MAX_CLOCKS {
            return Err(Error::OutOfMemory);
        }

        if let Some(p) = parent {
            if p as usize >= self.count || !self.clocks[p as usize].in_use {
                return Err(Error::InvalidArgument);
            }
        }

        let idx = self.count;
        let clk = &mut self.clocks[idx];
        clk.id = idx as u16;

        let copy_len = name.len().min(MAX_NAME_LEN);
        clk.name[..copy_len].copy_from_slice(&name[..copy_len]);
        clk.name_len = copy_len as u8;

        clk.clock_type = clock_type;
        clk.state = ClockState::Disabled;
        clk.parent = parent.unwrap_or(u16::MAX);
        clk.enable_count = 0;
        clk.in_use = true;

        self.count += 1;
        Ok(idx as u16)
    }

    /// Registers a fixed-rate clock (root oscillator).
    ///
    /// Convenience wrapper around [`register_clock`](Self::register_clock)
    /// that sets the type to [`ClockType::Fixed`] and the rate to
    /// `rate_hz`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tree is full.
    pub fn register_fixed(&mut self, name: &[u8], rate_hz: u64) -> Result<u16> {
        let id = self.register_clock(name, ClockType::Fixed, None)?;
        self.clocks[id as usize].rate_hz = rate_hz;
        Ok(id)
    }

    /// Registers a divider clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tree is full, or
    /// [`Error::InvalidArgument`] if `parent` is invalid or
    /// `divider` is zero.
    pub fn register_divider(
        &mut self,
        name: &[u8],
        parent: u16,
        divider: u32,
        min_div: u32,
        max_div: u32,
    ) -> Result<u16> {
        if divider == 0 {
            return Err(Error::InvalidArgument);
        }
        let id = self.register_clock(name, ClockType::Divider, Some(parent))?;
        let clk = &mut self.clocks[id as usize];
        clk.divider = ClockDivider {
            divider,
            min_div,
            max_div,
            reg_offset: 0,
            shift: 0,
            width: 0,
        };
        self.recalc_rate(id);
        Ok(id)
    }

    /// Registers a gate clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tree is full, or
    /// [`Error::InvalidArgument`] if `parent` is invalid.
    pub fn register_gate(&mut self, name: &[u8], parent: u16, bit_index: u8) -> Result<u16> {
        let id = self.register_clock(name, ClockType::Gate, Some(parent))?;
        let clk = &mut self.clocks[id as usize];
        clk.gate = ClockGate {
            reg_offset: 0,
            bit_index,
            inverted: false,
        };
        self.recalc_rate(id);
        Ok(id)
    }

    /// Registers a PLL clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the tree is full, or
    /// [`Error::InvalidArgument`] if `parent` is invalid or
    /// `pll_div` is zero.
    pub fn register_pll(&mut self, name: &[u8], parent: u16, mult: u32, div: u32) -> Result<u16> {
        if div == 0 {
            return Err(Error::InvalidArgument);
        }
        let id = self.register_clock(name, ClockType::Pll, Some(parent))?;
        let clk = &mut self.clocks[id as usize];
        clk.pll_mult = mult;
        clk.pll_div = div;
        self.recalc_rate(id);
        Ok(id)
    }

    // ── Lookup ──────────────────────────────────────────────────

    /// Returns a shared reference to a clock by its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range or the clock is not in use.
    pub fn get(&self, id: u16) -> Result<&ClockSource> {
        let idx = id as usize;
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        let clk = &self.clocks[idx];
        if !clk.in_use {
            return Err(Error::InvalidArgument);
        }
        Ok(clk)
    }

    /// Looks up a clock by name.
    ///
    /// Returns the first clock whose name matches the given bytes.
    pub fn find_by_name(&self, name: &[u8]) -> Option<&ClockSource> {
        self.clocks[..self.count]
            .iter()
            .find(|c| c.in_use && c.name_len as usize == name.len() && c.name_bytes() == name)
    }

    // ── Rate management ─────────────────────────────────────────

    /// Returns the current output rate of a clock in Hz.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the clock index is
    /// out of range.
    pub fn get_rate(&self, id: u16) -> Result<u64> {
        Ok(self.get(id)?.rate_hz)
    }

    /// Sets the rate of a clock.
    ///
    /// For fixed clocks, directly updates the rate. For dividers,
    /// computes the best divider value from the parent rate. For
    /// PLLs, updates the multiplier and divider. Propagates rate
    /// changes to all downstream children.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the clock index is out of
    ///   range.
    /// - [`Error::NotImplemented`] if the clock type does not
    ///   support rate setting (e.g., Gate or Mux).
    pub fn set_rate(&mut self, id: u16, rate_hz: u64) -> Result<()> {
        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        match self.clocks[idx].clock_type {
            ClockType::Fixed => {
                self.clocks[idx].rate_hz = rate_hz;
            }
            ClockType::Divider => {
                let parent_rate = self.parent_rate(id);
                if parent_rate == 0 {
                    return Err(Error::InvalidArgument);
                }
                let div = (parent_rate / rate_hz.max(1)) as u32;
                let clamped = div.clamp(
                    self.clocks[idx].divider.min_div.max(1),
                    self.clocks[idx].divider.max_div.max(1),
                );
                self.clocks[idx].divider.divider = clamped;
                self.clocks[idx].rate_hz = parent_rate / clamped as u64;
            }
            ClockType::Pll => {
                let parent_rate = self.parent_rate(id);
                if parent_rate == 0 {
                    return Err(Error::InvalidArgument);
                }
                // Simple: set mult to achieve closest rate with div=1.
                let mult = (rate_hz / parent_rate.max(1)) as u32;
                let mult = mult.max(1);
                self.clocks[idx].pll_mult = mult;
                self.clocks[idx].pll_div = 1;
                self.clocks[idx].rate_hz = parent_rate.saturating_mul(mult as u64);
            }
            ClockType::Gate | ClockType::Mux => {
                return Err(Error::NotImplemented);
            }
        }

        // Propagate to children.
        self.propagate_rate(id);
        Ok(())
    }

    /// Rounds a requested rate to the nearest achievable rate for
    /// the given clock, without actually changing it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the clock index is
    /// out of range.
    pub fn round_rate(&self, id: u16, rate_hz: u64) -> Result<u64> {
        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        let clk = &self.clocks[idx];
        match clk.clock_type {
            ClockType::Fixed => Ok(clk.rate_hz),
            ClockType::Divider => {
                let parent_rate = self.parent_rate(id);
                if parent_rate == 0 {
                    return Ok(0);
                }
                let div = (parent_rate / rate_hz.max(1)) as u32;
                let clamped = div.clamp(clk.divider.min_div.max(1), clk.divider.max_div.max(1));
                Ok(parent_rate / clamped as u64)
            }
            ClockType::Pll => {
                let parent_rate = self.parent_rate(id);
                if parent_rate == 0 {
                    return Ok(0);
                }
                let mult = (rate_hz / parent_rate.max(1)) as u32;
                Ok(parent_rate.saturating_mul(mult.max(1) as u64))
            }
            ClockType::Gate | ClockType::Mux => Ok(self.parent_rate(id)),
        }
    }

    // ── Enable / disable ────────────────────────────────────────

    /// Enables a clock.
    ///
    /// Increments the clock's enable count. If the clock was
    /// previously disabled, enables the parent chain first
    /// (recursively). Stops recursion at root or already-enabled
    /// parents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the clock index is
    /// out of range.
    pub fn enable(&mut self, id: u16) -> Result<()> {
        self.enable_recursive(id, 0)
    }

    /// Recursive enable with depth guard.
    fn enable_recursive(&mut self, id: u16, depth: usize) -> Result<()> {
        if depth >= MAX_TREE_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        // Enable parent first if needed.
        let parent = self.clocks[idx].parent;
        if parent != u16::MAX {
            self.enable_recursive(parent, depth + 1)?;
        }

        self.clocks[idx].enable_count += 1;
        if self.clocks[idx].enable_count == 1 {
            self.clocks[idx].state = ClockState::Enabled;
            self.recalc_rate(id);
        }

        Ok(())
    }

    /// Disables a clock.
    ///
    /// Decrements the enable count. The hardware clock is only
    /// gated when the count reaches zero. Also decrements the
    /// parent's count (recursively).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the clock index is out of
    ///   range or the count is already zero.
    pub fn disable(&mut self, id: u16) -> Result<()> {
        self.disable_recursive(id, 0)
    }

    /// Recursive disable with depth guard.
    fn disable_recursive(&mut self, id: u16, depth: usize) -> Result<()> {
        if depth >= MAX_TREE_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        if self.clocks[idx].enable_count == 0 {
            return Err(Error::InvalidArgument);
        }

        self.clocks[idx].enable_count -= 1;
        if self.clocks[idx].enable_count == 0 {
            self.clocks[idx].state = ClockState::Disabled;
            self.recalc_rate(id);
        }

        // Propagate disable to parent.
        let parent = self.clocks[idx].parent;
        if parent != u16::MAX {
            self.disable_recursive(parent, depth + 1)?;
        }

        Ok(())
    }

    // ── Parent management ───────────────────────────────────────

    /// Returns the parent index of a clock, or `None` for root clocks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the clock index is
    /// out of range.
    pub fn get_parent(&self, id: u16) -> Result<Option<u16>> {
        let clk = self.get(id)?;
        if clk.parent == u16::MAX {
            Ok(None)
        } else {
            Ok(Some(clk.parent))
        }
    }

    /// Sets the parent of a clock.
    ///
    /// Only valid for Mux-type clocks. Updates the mux selection
    /// and recalculates the rate.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if either index is out of range.
    /// - [`Error::NotImplemented`] if the clock is not a mux.
    pub fn set_parent(&mut self, id: u16, new_parent: u16) -> Result<()> {
        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if new_parent as usize >= self.count || !self.clocks[new_parent as usize].in_use {
            return Err(Error::InvalidArgument);
        }

        if self.clocks[idx].clock_type != ClockType::Mux {
            return Err(Error::NotImplemented);
        }

        self.clocks[idx].parent = new_parent;
        self.recalc_rate(id);
        self.propagate_rate(id);
        Ok(())
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Returns the parent's rate for clock `id`, or 0 for root
    /// clocks.
    fn parent_rate(&self, id: u16) -> u64 {
        let idx = id as usize;
        if idx >= self.count {
            return 0;
        }
        let parent = self.clocks[idx].parent;
        if parent == u16::MAX {
            return 0;
        }
        let pidx = parent as usize;
        if pidx >= self.count {
            return 0;
        }
        self.clocks[pidx].rate_hz
    }

    /// Recalculates the rate for a single clock based on its parent
    /// and type-specific parameters.
    fn recalc_rate(&mut self, id: u16) {
        let parent_rate = self.parent_rate(id);
        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return;
        }
        self.clocks[idx].rate_hz = self.clocks[idx].compute_rate(parent_rate);
    }

    /// Propagates rate changes from clock `id` to all its
    /// descendants, breadth-first.
    fn propagate_rate(&mut self, id: u16) {
        // Simple iterative approach: scan all clocks whose parent
        // matches any clock in the "changed" set. Repeat until no
        // more changes.
        let mut changed = [false; MAX_CLOCKS];
        changed[id as usize] = true;

        for _depth in 0..MAX_TREE_DEPTH {
            let mut any = false;
            for i in 0..self.count {
                if !self.clocks[i].in_use {
                    continue;
                }
                let p = self.clocks[i].parent;
                if p == u16::MAX {
                    continue;
                }
                if changed[p as usize] && !changed[i] {
                    self.recalc_rate(i as u16);
                    changed[i] = true;
                    any = true;
                }
            }
            if !any {
                break;
            }
        }
    }

    // ── Tree traversal / dump ───────────────────────────────────

    /// Collects a snapshot of the entire clock tree into a
    /// [`ClockTreeDump`].
    ///
    /// Entries are ordered by a depth-first traversal starting from
    /// root clocks.
    pub fn dump(&self) -> ClockTreeDump {
        let mut out = ClockTreeDump::new();

        // Start from root clocks (no parent).
        for i in 0..self.count {
            if self.clocks[i].in_use && self.clocks[i].parent == u16::MAX {
                self.dump_subtree(i as u16, 0, &mut out);
            }
        }

        out
    }

    /// Recursively dumps a subtree rooted at `id`.
    fn dump_subtree(&self, id: u16, depth: u8, out: &mut ClockTreeDump) {
        let idx = id as usize;
        if idx >= self.count || !self.clocks[idx].in_use {
            return;
        }
        if out.count >= MAX_CLOCKS {
            return;
        }
        if depth as usize >= MAX_TREE_DEPTH {
            return;
        }

        let clk = &self.clocks[idx];
        let entry = &mut out.entries[out.count];
        entry.id = clk.id;
        entry.depth = depth;
        entry.name = clk.name;
        entry.name_len = clk.name_len;
        entry.clock_type = clk.clock_type;
        entry.state = clk.state;
        entry.rate_hz = clk.rate_hz;
        entry.enable_count = clk.enable_count;
        out.count += 1;

        // Recurse into children.
        for i in 0..self.count {
            if self.clocks[i].in_use && self.clocks[i].parent == id {
                self.dump_subtree(i as u16, depth.saturating_add(1), out);
            }
        }
    }

    /// Returns the indices of all children of a given clock.
    ///
    /// At most [`MAX_CHILDREN`] children are returned.
    pub fn get_children(&self, id: u16) -> ([u16; MAX_CHILDREN], usize) {
        let mut children = [0u16; MAX_CHILDREN];
        let mut count = 0;

        for i in 0..self.count {
            if self.clocks[i].in_use && self.clocks[i].parent == id {
                if count < MAX_CHILDREN {
                    children[count] = i as u16;
                    count += 1;
                }
            }
        }

        (children, count)
    }

    /// Returns the total number of enabled clocks in the tree.
    pub fn enabled_count(&self) -> usize {
        self.clocks[..self.count]
            .iter()
            .filter(|c| c.in_use && c.state == ClockState::Enabled)
            .count()
    }
}

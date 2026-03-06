// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clock framework HAL for the ONCRIX operating system.
//!
//! Provides a hierarchical clock tree with support for fixed oscillators,
//! PLLs, dividers, muxes, and gate clocks. All clock nodes are tracked in a
//! flat registry with parent–child relationships, enable reference counts,
//! and rate propagation through the tree.
//!
//! # Architecture
//!
//! - **ClkType** — node classification (fixed, PLL, divider, mux, gate)
//! - **ClkFlags** — per-node feature flags (critical, ignore-unused, etc.)
//! - **ClkNode** — a single clock tree node with rate, parent, ref count
//! - **ClkDividerCfg** — configuration for a divider clock node
//! - **ClkPllCfg** — configuration for a PLL clock node
//! - **ClkMuxCfg** — configuration for a multiplexer clock node
//! - **ClkFramework** — the top-level clock manager (up to [`MAX_CLOCKS`] nodes)
//! - **ClkHandle** — opaque index into the framework's clock array
//!
//! # Design Notes
//!
//! Rate propagation: when a parent's rate changes (e.g. PLL reconfiguration),
//! children rates are recomputed recursively. An enable/disable reference count
//! prevents gating a clock that is still consumed by a child or device.
//!
//! # Reference
//!
//! Linux: `drivers/clk/clk.c`, `include/linux/clk-provider.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of clock nodes in the framework.
const MAX_CLOCKS: usize = 64;

/// Maximum clock name length in bytes.
const MAX_NAME_LEN: usize = 32;

/// Maximum number of mux parents.
const MAX_MUX_PARENTS: usize = 8;

/// Maximum number of divider table entries.
const MAX_DIV_TABLE: usize = 16;

/// Special parent index meaning "no parent" (root clock).
const NO_PARENT: usize = usize::MAX;

// ---------------------------------------------------------------------------
// ClkType
// ---------------------------------------------------------------------------

/// Classification of a clock node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClkType {
    /// Fixed-rate oscillator — rate is set at registration and never changes.
    #[default]
    Fixed,
    /// Phase-locked loop — multiplies parent rate by N/M.
    Pll,
    /// Integer/fractional divider — divides parent rate by a configurable ratio.
    Divider,
    /// Clock multiplexer — selects one of several parent clocks.
    Mux,
    /// Gate — passes parent rate through when enabled; gated off when disabled.
    Gate,
}

// ---------------------------------------------------------------------------
// ClkFlags
// ---------------------------------------------------------------------------

/// Per-node feature flags stored as a bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClkFlags(pub u32);

impl ClkFlags {
    /// Critical clock — must not be gated even when unused.
    pub const CRITICAL: Self = Self(1 << 0);

    /// Ignore unused — suppress warnings for clocks with no consumers.
    pub const IGNORE_UNUSED: Self = Self(1 << 1);

    /// Rate is set by the bootloader and must not be changed by software.
    pub const RATE_UNMODIFIABLE: Self = Self(1 << 2);

    /// Propagate rate changes to children automatically.
    pub const RATE_PROPAGATES: Self = Self(1 << 3);

    /// Returns `true` if `flag` is set.
    pub fn has(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Returns new flags with `flag` added.
    pub fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }
}

// ---------------------------------------------------------------------------
// ClkDividerCfg
// ---------------------------------------------------------------------------

/// Configuration parameters for a divider clock node.
#[derive(Debug, Clone, Copy)]
pub struct ClkDividerCfg {
    /// Current divider value (output = parent_rate / divider).
    pub divider: u32,
    /// Minimum divider value.
    pub min_div: u32,
    /// Maximum divider value.
    pub max_div: u32,
    /// Optional divider lookup table (raw register value → actual divider).
    pub table: [(u32, u32); MAX_DIV_TABLE],
    /// Number of valid entries in `table` (0 = no table, use raw value).
    pub table_len: usize,
}

impl Default for ClkDividerCfg {
    fn default() -> Self {
        Self {
            divider: 1,
            min_div: 1,
            max_div: 256,
            table: [(0, 0); MAX_DIV_TABLE],
            table_len: 0,
        }
    }
}

impl ClkDividerCfg {
    /// Creates a simple divider config with the given initial `divider`.
    pub fn simple(divider: u32) -> Self {
        Self {
            divider,
            ..Self::default()
        }
    }

    /// Computes the output rate given the parent rate.
    pub fn output_rate(&self, parent_rate: u64) -> u64 {
        if self.divider == 0 {
            return 0;
        }
        parent_rate / u64::from(self.divider)
    }
}

// ---------------------------------------------------------------------------
// ClkPllCfg
// ---------------------------------------------------------------------------

/// Configuration parameters for a PLL clock node.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClkPllCfg {
    /// PLL multiplier (N in output = parent * N / M).
    pub n: u32,
    /// PLL divider (M).
    pub m: u32,
    /// Output post-divider (P).
    pub p: u32,
    /// Fractional part of N (for fractional PLLs), in ppm.
    pub frac_ppm: u32,
    /// MMIO register offset for the PLL control register.
    pub ctrl_offset: usize,
    /// MMIO register offset for the PLL lock status.
    pub lock_offset: usize,
    /// Lock status bit mask.
    pub lock_mask: u32,
}

impl ClkPllCfg {
    /// Computes the PLL output frequency given `ref_rate` (Hz).
    ///
    /// Formula: `ref_rate * N / (M * P)`, or 0 on division by zero.
    pub fn output_rate(&self, ref_rate: u64) -> u64 {
        let denom = u64::from(self.m) * u64::from(self.p.max(1));
        if denom == 0 {
            return 0;
        }
        ref_rate * u64::from(self.n) / denom
    }
}

// ---------------------------------------------------------------------------
// ClkMuxCfg
// ---------------------------------------------------------------------------

/// Configuration parameters for a mux clock node.
#[derive(Debug, Clone, Copy)]
pub struct ClkMuxCfg {
    /// Indices into the framework's clock array for each mux input.
    pub parents: [usize; MAX_MUX_PARENTS],
    /// Number of valid parent entries.
    pub num_parents: usize,
    /// Currently selected parent index (0..num_parents).
    pub selected: usize,
    /// MMIO offset of the mux select register.
    pub reg_offset: usize,
    /// Bit shift within the register.
    pub reg_shift: u8,
    /// Bit mask within the register (after shift).
    pub reg_mask: u32,
}

impl Default for ClkMuxCfg {
    fn default() -> Self {
        Self {
            parents: [NO_PARENT; MAX_MUX_PARENTS],
            num_parents: 0,
            selected: 0,
            reg_offset: 0,
            reg_shift: 0,
            reg_mask: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ClkHandle
// ---------------------------------------------------------------------------

/// Opaque handle to a clock node within the [`ClkFramework`].
///
/// The handle is simply an index into the internal clock array. It is
/// invalidated if the clock is unregistered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClkHandle(pub usize);

// ---------------------------------------------------------------------------
// ClkNode
// ---------------------------------------------------------------------------

/// A single node in the clock tree.
///
/// Stores the clock's name, type, rate, parent index, enable reference
/// count, and type-specific configuration.
pub struct ClkNode {
    /// Clock name (UTF-8, not NUL-terminated).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Clock type.
    pub clk_type: ClkType,
    /// Feature flags.
    pub flags: ClkFlags,
    /// Current output frequency in Hz.
    pub rate: u64,
    /// Parent clock index (or [`NO_PARENT`] for root clocks).
    pub parent: usize,
    /// Children clock indices.
    pub children: [usize; MAX_MUX_PARENTS],
    /// Number of valid children.
    pub child_count: usize,
    /// Enable reference count (0 = gated, >0 = enabled).
    pub enable_count: u32,
    /// Whether this slot is occupied.
    pub valid: bool,
    /// Type-specific divider configuration.
    pub div_cfg: ClkDividerCfg,
    /// Type-specific PLL configuration.
    pub pll_cfg: ClkPllCfg,
    /// Type-specific mux configuration.
    pub mux_cfg: ClkMuxCfg,
    /// MMIO base address for this clock's registers (0 if software-only).
    pub mmio_base: usize,
}

/// Constant empty node for array initialisation.
const EMPTY_NODE: ClkNode = ClkNode {
    name: [0u8; MAX_NAME_LEN],
    name_len: 0,
    clk_type: ClkType::Fixed,
    flags: ClkFlags(0),
    rate: 0,
    parent: NO_PARENT,
    children: [NO_PARENT; MAX_MUX_PARENTS],
    child_count: 0,
    enable_count: 0,
    valid: false,
    div_cfg: ClkDividerCfg {
        divider: 1,
        min_div: 1,
        max_div: 256,
        table: [(0, 0); MAX_DIV_TABLE],
        table_len: 0,
    },
    pll_cfg: ClkPllCfg {
        n: 1,
        m: 1,
        p: 1,
        frac_ppm: 0,
        ctrl_offset: 0,
        lock_offset: 0,
        lock_mask: 0,
    },
    mux_cfg: ClkMuxCfg {
        parents: [NO_PARENT; MAX_MUX_PARENTS],
        num_parents: 0,
        selected: 0,
        reg_offset: 0,
        reg_shift: 0,
        reg_mask: 0,
    },
    mmio_base: 0,
};

impl ClkNode {
    /// Creates a new fixed-rate clock node.
    fn new_fixed(name: &[u8], rate: u64) -> Self {
        let mut node = EMPTY_NODE;
        let copy_len = name.len().min(MAX_NAME_LEN);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        node.clk_type = ClkType::Fixed;
        node.rate = rate;
        node.valid = true;
        node.enable_count = 1; // fixed clocks are always on
        node
    }

    /// Creates a new configurable clock node with the given type and parent.
    fn new_with_parent(name: &[u8], clk_type: ClkType, parent: usize) -> Self {
        let mut node = EMPTY_NODE;
        let copy_len = name.len().min(MAX_NAME_LEN);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        node.clk_type = clk_type;
        node.parent = parent;
        node.valid = true;
        node
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if the clock is gated off.
    pub fn is_gated(&self) -> bool {
        self.enable_count == 0 && !self.flags.has(ClkFlags::CRITICAL)
    }

    /// Computes the current output rate from the parent rate.
    pub fn compute_rate(&self, parent_rate: u64) -> u64 {
        match self.clk_type {
            ClkType::Fixed => self.rate,
            ClkType::Gate => {
                if self.enable_count > 0 {
                    parent_rate
                } else {
                    0
                }
            }
            ClkType::Divider => self.div_cfg.output_rate(parent_rate),
            ClkType::Pll => self.pll_cfg.output_rate(parent_rate),
            ClkType::Mux => parent_rate,
        }
    }
}

// ---------------------------------------------------------------------------
// ClkFramework
// ---------------------------------------------------------------------------

/// The top-level clock manager for the ONCRIX platform.
///
/// Holds up to [`MAX_CLOCKS`] clock nodes in a flat array. Handles
/// registration, parent–child linking, enable/disable reference counting,
/// rate queries, and rate propagation through the tree.
pub struct ClkFramework {
    /// Clock node storage.
    nodes: [ClkNode; MAX_CLOCKS],
    /// Number of valid (registered) nodes.
    count: usize,
    /// Optional MMIO base for the global clock controller (e.g. CCF block).
    mmio_base: usize,
}

impl ClkFramework {
    /// Creates a new, empty clock framework.
    pub const fn new() -> Self {
        Self {
            nodes: [const { EMPTY_NODE }; MAX_CLOCKS],
            count: 0,
            mmio_base: 0,
        }
    }

    /// Sets the MMIO base address for the global clock controller.
    pub fn set_mmio_base(&mut self, base: usize) {
        self.mmio_base = base;
    }

    /// Returns the MMIO base address.
    pub fn mmio_base(&self) -> usize {
        self.mmio_base
    }

    /// Allocates a free slot in the nodes array.
    fn alloc_slot(&self) -> Option<usize> {
        self.nodes.iter().position(|n| !n.valid)
    }

    /// Registers a fixed-rate oscillator.
    ///
    /// Fixed clocks have no parent and their rate never changes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the framework is full, or
    /// [`Error::AlreadyExists`] if a clock with the same name exists.
    pub fn register_fixed(&mut self, name: &[u8], rate: u64) -> Result<ClkHandle> {
        self.check_name_unique(name)?;
        let slot = self.alloc_slot().ok_or(Error::OutOfMemory)?;
        self.nodes[slot] = ClkNode::new_fixed(name, rate);
        self.count += 1;
        Ok(ClkHandle(slot))
    }

    /// Registers a general-purpose clock with a given type and parent.
    ///
    /// The initial rate is computed from the parent's current rate
    /// using the default parameters for the clock type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `parent` is invalid, [`Error::OutOfMemory`]
    /// if the framework is full, or [`Error::AlreadyExists`] for duplicate names.
    pub fn register_clock(
        &mut self,
        name: &[u8],
        clk_type: ClkType,
        parent: Option<ClkHandle>,
    ) -> Result<ClkHandle> {
        self.check_name_unique(name)?;

        let parent_idx = match parent {
            Some(h) => {
                if !self.nodes[h.0].valid {
                    return Err(Error::NotFound);
                }
                h.0
            }
            None => NO_PARENT,
        };

        let slot = self.alloc_slot().ok_or(Error::OutOfMemory)?;
        let mut node = ClkNode::new_with_parent(name, clk_type, parent_idx);

        // Derive initial rate from parent
        if parent_idx != NO_PARENT {
            let prate = self.nodes[parent_idx].rate;
            node.rate = node.compute_rate(prate);
        }

        self.nodes[slot] = node;
        self.count += 1;

        // Link child into parent's child list
        if parent_idx != NO_PARENT {
            let cc = self.nodes[parent_idx].child_count;
            if cc < MAX_MUX_PARENTS {
                self.nodes[parent_idx].children[cc] = slot;
                self.nodes[parent_idx].child_count += 1;
            }
        }

        Ok(ClkHandle(slot))
    }

    /// Enables a clock (increments enable reference count).
    ///
    /// Propagates enable up the parent chain until a critical or
    /// already-enabled clock is reached.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn enable(&mut self, handle: ClkHandle) -> Result<()> {
        self.check_handle(handle)?;
        self.enable_recursive(handle.0, 0);
        Ok(())
    }

    fn enable_recursive(&mut self, idx: usize, depth: usize) {
        if depth > MAX_CLOCKS {
            return;
        }
        if !self.nodes[idx].valid {
            return;
        }
        self.nodes[idx].enable_count = self.nodes[idx].enable_count.saturating_add(1);
        let parent = self.nodes[idx].parent;
        if parent != NO_PARENT {
            self.enable_recursive(parent, depth + 1);
        }
    }

    /// Disables a clock (decrements enable reference count).
    ///
    /// A clock with `CRITICAL` flag or `enable_count > 1` after decrement
    /// remains enabled. Propagates disable up the parent chain if the
    /// reference count reaches zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn disable(&mut self, handle: ClkHandle) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].flags.has(ClkFlags::CRITICAL) {
            return Ok(());
        }
        self.disable_recursive(handle.0, 0);
        Ok(())
    }

    fn disable_recursive(&mut self, idx: usize, depth: usize) {
        if depth > MAX_CLOCKS {
            return;
        }
        if !self.nodes[idx].valid {
            return;
        }
        if self.nodes[idx].enable_count > 0 {
            self.nodes[idx].enable_count -= 1;
        }
        if self.nodes[idx].enable_count == 0 {
            let parent = self.nodes[idx].parent;
            if parent != NO_PARENT && !self.nodes[parent].flags.has(ClkFlags::CRITICAL) {
                self.disable_recursive(parent, depth + 1);
            }
        }
    }

    /// Returns the current rate of a clock in Hz.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn get_rate(&self, handle: ClkHandle) -> Result<u64> {
        self.check_handle(handle)?;
        Ok(self.nodes[handle.0].rate)
    }

    /// Sets the rate of a clock.
    ///
    /// For divider clocks, the divider is adjusted to best-approximate the
    /// requested rate given the parent's rate. For fixed clocks or those with
    /// `RATE_UNMODIFIABLE`, returns [`Error::PermissionDenied`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid,
    /// [`Error::PermissionDenied`] for unmodifiable clocks, or
    /// [`Error::InvalidArgument`] if the rate cannot be achieved.
    pub fn set_rate(&mut self, handle: ClkHandle, rate_hz: u64) -> Result<()> {
        self.check_handle(handle)?;
        let clk_type = self.nodes[handle.0].clk_type;

        if clk_type == ClkType::Fixed || self.nodes[handle.0].flags.has(ClkFlags::RATE_UNMODIFIABLE)
        {
            return Err(Error::PermissionDenied);
        }

        let parent_idx = self.nodes[handle.0].parent;
        let parent_rate = if parent_idx != NO_PARENT {
            self.nodes[parent_idx].rate
        } else {
            0
        };

        match clk_type {
            ClkType::Divider => {
                if parent_rate == 0 || rate_hz == 0 {
                    return Err(Error::InvalidArgument);
                }
                let div = ((parent_rate + rate_hz - 1) / rate_hz) as u32;
                let min_div = self.nodes[handle.0].div_cfg.min_div;
                let max_div = self.nodes[handle.0].div_cfg.max_div;
                let clamped = div.clamp(min_div, max_div);
                self.nodes[handle.0].div_cfg.divider = clamped;
                let new_rate = parent_rate / u64::from(clamped);
                self.nodes[handle.0].rate = new_rate;
                self.propagate_rate(handle.0, 0);
            }
            ClkType::Pll => {
                self.nodes[handle.0].rate = rate_hz;
                self.propagate_rate(handle.0, 0);
            }
            ClkType::Gate | ClkType::Mux => {
                // Gate/mux pass through parent rate; setting rate is a no-op
                self.nodes[handle.0].rate = parent_rate;
            }
            ClkType::Fixed => unreachable!(),
        }
        Ok(())
    }

    /// Selects a new parent for a mux clock.
    ///
    /// `parent_idx_in_mux` is the index within the mux's parent list
    /// (0..`num_parents`), not a global clock index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] for invalid handles, or
    /// [`Error::InvalidArgument`] if the mux index is out of range.
    pub fn set_parent(&mut self, handle: ClkHandle, parent_idx_in_mux: usize) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].clk_type != ClkType::Mux {
            return Err(Error::InvalidArgument);
        }
        let num_parents = self.nodes[handle.0].mux_cfg.num_parents;
        if parent_idx_in_mux >= num_parents {
            return Err(Error::InvalidArgument);
        }
        let new_parent_global = self.nodes[handle.0].mux_cfg.parents[parent_idx_in_mux];
        if new_parent_global == NO_PARENT || !self.nodes[new_parent_global].valid {
            return Err(Error::NotFound);
        }

        // Unlink from old parent
        let old_parent = self.nodes[handle.0].parent;
        if old_parent != NO_PARENT {
            self.remove_child(old_parent, handle.0);
        }

        // Link to new parent
        self.nodes[handle.0].parent = new_parent_global;
        self.nodes[handle.0].mux_cfg.selected = parent_idx_in_mux;
        let cc = self.nodes[new_parent_global].child_count;
        if cc < MAX_MUX_PARENTS {
            self.nodes[new_parent_global].children[cc] = handle.0;
            self.nodes[new_parent_global].child_count += 1;
        }

        // Update rate
        let prate = self.nodes[new_parent_global].rate;
        self.nodes[handle.0].rate = prate;
        self.propagate_rate(handle.0, 0);
        Ok(())
    }

    /// Removes `child_idx` from the children list of `parent_idx`.
    fn remove_child(&mut self, parent_idx: usize, child_idx: usize) {
        let cc = self.nodes[parent_idx].child_count;
        let mut found = cc; // sentinel: not found
        for i in 0..cc {
            if self.nodes[parent_idx].children[i] == child_idx {
                found = i;
                break;
            }
        }
        if found < cc {
            // Shift remaining children left
            for i in found..cc.saturating_sub(1) {
                self.nodes[parent_idx].children[i] = self.nodes[parent_idx].children[i + 1];
            }
            self.nodes[parent_idx].children[cc - 1] = NO_PARENT;
            self.nodes[parent_idx].child_count -= 1;
        }
    }

    /// Propagates a rate change down through all children.
    fn propagate_rate(&mut self, idx: usize, depth: usize) {
        if depth > MAX_CLOCKS {
            return;
        }
        let my_rate = self.nodes[idx].rate;
        let cc = self.nodes[idx].child_count;
        for ci in 0..cc {
            let child = self.nodes[idx].children[ci];
            if child == NO_PARENT || !self.nodes[child].valid {
                continue;
            }
            let new_rate = self.nodes[child].compute_rate(my_rate);
            self.nodes[child].rate = new_rate;
            self.propagate_rate(child, depth + 1);
        }
    }

    /// Returns the enable reference count for a clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn enable_count(&self, handle: ClkHandle) -> Result<u32> {
        self.check_handle(handle)?;
        Ok(self.nodes[handle.0].enable_count)
    }

    /// Sets flags on a clock node.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn set_flags(&mut self, handle: ClkHandle, flags: ClkFlags) -> Result<()> {
        self.check_handle(handle)?;
        self.nodes[handle.0].flags = self.nodes[handle.0].flags.with(flags);
        Ok(())
    }

    /// Configures the divider parameters for a divider clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid, or
    /// [`Error::InvalidArgument`] if the clock is not a divider.
    pub fn set_divider_cfg(&mut self, handle: ClkHandle, cfg: ClkDividerCfg) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].clk_type != ClkType::Divider {
            return Err(Error::InvalidArgument);
        }
        self.nodes[handle.0].div_cfg = cfg;
        let parent_idx = self.nodes[handle.0].parent;
        if parent_idx != NO_PARENT {
            let prate = self.nodes[parent_idx].rate;
            let new_rate = self.nodes[handle.0].div_cfg.output_rate(prate);
            self.nodes[handle.0].rate = new_rate;
        }
        Ok(())
    }

    /// Configures the PLL parameters for a PLL clock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid, or
    /// [`Error::InvalidArgument`] if the clock is not a PLL.
    pub fn set_pll_cfg(&mut self, handle: ClkHandle, cfg: ClkPllCfg) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].clk_type != ClkType::Pll {
            return Err(Error::InvalidArgument);
        }
        let parent_idx = self.nodes[handle.0].parent;
        let prate = if parent_idx != NO_PARENT {
            self.nodes[parent_idx].rate
        } else {
            0
        };
        let new_rate = cfg.output_rate(prate);
        self.nodes[handle.0].pll_cfg = cfg;
        self.nodes[handle.0].rate = new_rate;
        self.propagate_rate(handle.0, 0);
        Ok(())
    }

    /// Configures the mux parents for a mux clock.
    ///
    /// `parents` must contain valid [`ClkHandle`] indices into this framework.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if any handle is invalid, or
    /// [`Error::InvalidArgument`] if the clock is not a mux.
    pub fn set_mux_parents(&mut self, handle: ClkHandle, parents: &[ClkHandle]) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].clk_type != ClkType::Mux {
            return Err(Error::InvalidArgument);
        }
        let count = parents.len().min(MAX_MUX_PARENTS);
        let mut indices = [NO_PARENT; MAX_MUX_PARENTS];
        for (i, p) in parents.iter().take(count).enumerate() {
            self.check_handle(*p)?;
            indices[i] = p.0;
        }
        self.nodes[handle.0].mux_cfg.parents = indices;
        self.nodes[handle.0].mux_cfg.num_parents = count;
        Ok(())
    }

    /// Looks up a clock handle by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no clock with the given name exists.
    pub fn find_by_name(&self, name: &[u8]) -> Result<ClkHandle> {
        for (i, node) in self.nodes.iter().enumerate() {
            if !node.valid {
                continue;
            }
            if node.name_bytes() == name {
                return Ok(ClkHandle(i));
            }
        }
        Err(Error::NotFound)
    }

    /// Unregisters a clock by handle.
    ///
    /// Fails if the clock still has consumers (`enable_count > 0`) or
    /// if it has registered children.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if consumers/children remain, or
    /// [`Error::NotFound`] if invalid.
    pub fn unregister(&mut self, handle: ClkHandle) -> Result<()> {
        self.check_handle(handle)?;
        if self.nodes[handle.0].enable_count > 0 {
            return Err(Error::Busy);
        }
        if self.nodes[handle.0].child_count > 0 {
            return Err(Error::Busy);
        }
        // Remove from parent's child list
        let parent = self.nodes[handle.0].parent;
        if parent != NO_PARENT {
            self.remove_child(parent, handle.0);
        }
        self.nodes[handle.0] = EMPTY_NODE;
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of registered clocks.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no clocks are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Validates a [`ClkHandle`] and returns [`Error::NotFound`] if invalid.
    fn check_handle(&self, handle: ClkHandle) -> Result<()> {
        if handle.0 >= MAX_CLOCKS || !self.nodes[handle.0].valid {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Checks that `name` is not already registered.
    fn check_name_unique(&self, name: &[u8]) -> Result<()> {
        let copy_len = name.len().min(MAX_NAME_LEN);
        for node in &self.nodes {
            if !node.valid {
                continue;
            }
            if node.name_bytes() == &name[..copy_len] {
                return Err(Error::AlreadyExists);
            }
        }
        Ok(())
    }
}

impl Default for ClkFramework {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ClkSummary
// ---------------------------------------------------------------------------

/// A lightweight snapshot of one clock node for diagnostic output.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClkSummary {
    /// Index in the framework array.
    pub index: usize,
    /// Clock type.
    pub clk_type: ClkType,
    /// Current rate in Hz.
    pub rate: u64,
    /// Enable reference count.
    pub enable_count: u32,
    /// Parent clock index (NO_PARENT if root).
    pub parent: usize,
    /// Number of children.
    pub child_count: usize,
}

impl ClkSummary {
    /// Captures a summary from the given node index and node reference.
    pub fn from_node(index: usize, node: &ClkNode) -> Self {
        Self {
            index,
            clk_type: node.clk_type,
            rate: node.rate,
            enable_count: node.enable_count,
            parent: node.parent,
            child_count: node.child_count,
        }
    }
}

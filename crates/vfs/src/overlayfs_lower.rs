// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlayfs lower layer management.
//!
//! The lower layer (or stack of lower layers) provides the read-only baseline
//! content for an overlay mount.  This module tracks the ordered stack of
//! lower directories and implements the lookup/read path that searches them
//! from top to bottom.

use oncrix_lib::{Error, Result};

/// Maximum number of lower layers in an overlay stack.
pub const OVERLAY_MAX_LOWER: usize = 500;

/// Identifier for a lower layer, assigned at mount time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LowerLayerId(pub u32);

/// Metadata about a single lower layer directory.
#[derive(Debug, Clone)]
pub struct LowerLayerInfo {
    /// Stable identifier for this layer.
    pub id: LowerLayerId,
    /// Mount generation at the time the layer was registered.
    pub generation: u64,
    /// Whether this layer has a redirect directory.
    pub has_redirect: bool,
    /// Whether this layer supports opaque whiteouts.
    pub opaque: bool,
}

impl LowerLayerInfo {
    /// Create a new lower layer descriptor.
    pub fn new(id: LowerLayerId, generation: u64) -> Self {
        Self {
            id,
            generation,
            has_redirect: false,
            opaque: false,
        }
    }
}

/// Result of a lookup across the lower layer stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowerLookupResult {
    /// Entry found in the specified layer index.
    Found(usize),
    /// Entry not found in any layer.
    NotFound,
    /// A whiteout was encountered, hiding the entry.
    Whiteout,
}

/// Stack of lower layers for an overlay mount.
///
/// Layers are ordered: index 0 is the topmost lower layer (searched first),
/// higher indices are deeper/older layers.
pub struct LowerStack {
    layers: [Option<LowerLayerInfo>; OVERLAY_MAX_LOWER],
    count: usize,
    next_id: u32,
}

impl LowerStack {
    /// Create an empty lower stack.
    pub const fn new() -> Self {
        Self {
            layers: [const { None }; OVERLAY_MAX_LOWER],
            count: 0,
            next_id: 1,
        }
    }

    /// Push a new lower layer onto the bottom of the stack.
    ///
    /// Returns `Err(OutOfMemory)` when the maximum layer count is exceeded.
    pub fn push(&mut self, generation: u64) -> Result<LowerLayerId> {
        if self.count >= OVERLAY_MAX_LOWER {
            return Err(Error::OutOfMemory);
        }
        let id = LowerLayerId(self.next_id);
        self.next_id += 1;
        self.layers[self.count] = Some(LowerLayerInfo::new(id, generation));
        self.count += 1;
        Ok(id)
    }

    /// Number of registered lower layers.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Retrieve layer info by stack index.
    pub fn get(&self, index: usize) -> Option<&LowerLayerInfo> {
        if index < self.count {
            self.layers[index].as_ref()
        } else {
            None
        }
    }

    /// Mark a layer as having a redirect directory.
    pub fn set_redirect(&mut self, id: LowerLayerId) -> Result<()> {
        for slot in &mut self.layers[..self.count] {
            if let Some(layer) = slot.as_mut() {
                if layer.id == id {
                    layer.has_redirect = true;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a layer as opaque (supports whiteout directories).
    pub fn set_opaque(&mut self, id: LowerLayerId) -> Result<()> {
        for slot in &mut self.layers[..self.count] {
            if let Some(layer) = slot.as_mut() {
                if layer.id == id {
                    layer.opaque = true;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Simulate a lookup across all lower layers for a given name hash.
    ///
    /// In the real kernel this dereferences dentries; here we model the
    /// decision logic using a caller-supplied predicate.
    ///
    /// `found_in` — closure returning `true` if the name exists in `layer_idx`.
    /// `is_whiteout_in` — closure returning `true` if the name is a whiteout.
    pub fn lookup(
        &self,
        mut found_in: impl FnMut(usize) -> bool,
        mut is_whiteout_in: impl FnMut(usize) -> bool,
    ) -> LowerLookupResult {
        for idx in 0..self.count {
            if is_whiteout_in(idx) {
                return LowerLookupResult::Whiteout;
            }
            if found_in(idx) {
                return LowerLookupResult::Found(idx);
            }
        }
        LowerLookupResult::NotFound
    }
}

impl Default for LowerStack {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-path statistics for the lower stack.
#[derive(Debug, Default, Clone, Copy)]
pub struct LowerReadStats {
    /// Number of successful lookups.
    pub hits: u64,
    /// Number of whiteout encounters.
    pub whiteouts: u64,
    /// Number of misses (not found in any layer).
    pub misses: u64,
}

impl LowerReadStats {
    /// Record a lookup outcome.
    pub fn record(&mut self, result: LowerLookupResult) {
        match result {
            LowerLookupResult::Found(_) => self.hits += 1,
            LowerLookupResult::Whiteout => self.whiteouts += 1,
            LowerLookupResult::NotFound => self.misses += 1,
        }
    }
}

/// Combined lower-layer context attached to an overlay superblock.
pub struct LowerContext {
    /// Ordered stack of lower layers.
    pub stack: LowerStack,
    /// Accumulated read-path statistics.
    pub stats: LowerReadStats,
}

impl LowerContext {
    /// Create a new lower context with an empty stack.
    pub const fn new() -> Self {
        Self {
            stack: LowerStack::new(),
            stats: LowerReadStats {
                hits: 0,
                whiteouts: 0,
                misses: 0,
            },
        }
    }

    /// Perform a lookup and update statistics.
    pub fn lookup(
        &mut self,
        found_in: impl FnMut(usize) -> bool,
        is_whiteout_in: impl FnMut(usize) -> bool,
    ) -> LowerLookupResult {
        let result = self.stack.lookup(found_in, is_whiteout_in);
        self.stats.record(result);
        result
    }
}

impl Default for LowerContext {
    fn default() -> Self {
        Self::new()
    }
}

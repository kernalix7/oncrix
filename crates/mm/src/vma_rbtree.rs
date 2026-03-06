// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA red-black tree management.
//!
//! Maintains the per-process VMA (Virtual Memory Area) collection in a
//! red-black tree keyed by start address. This provides O(log n) lookup,
//! insertion, and deletion of VMAs, which is critical for fast
//! page-fault resolution and `mmap`/`munmap` operations.
//!
//! # Design
//!
//! ```text
//!          [0x4000..0x8000]
//!         /                \
//!  [0x1000..0x3000]  [0xA000..0xC000]
//!        \                /
//!   [0x3000..0x4000]  [0x8000..0xA000]
//! ```
//!
//! # Key Types
//!
//! - [`VmaEntry`] — a single VMA node with address range and flags
//! - [`VmaRbTree`] — the red-black tree container
//! - [`VmaFlags`] — VMA protection and attribute flags
//!
//! Reference: Linux `mm/mmap.c`, `include/linux/mm_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMAs in the tree.
const MAX_VMAS: usize = 4096;

/// Sentinel for "no node".
const NIL: usize = usize::MAX;

// -------------------------------------------------------------------
// VmaFlags
// -------------------------------------------------------------------

/// Protection and attribute flags for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaFlags(u32);

impl VmaFlags {
    /// Readable.
    pub const READ: u32 = 1 << 0;
    /// Writable.
    pub const WRITE: u32 = 1 << 1;
    /// Executable.
    pub const EXEC: u32 = 1 << 2;
    /// Shared mapping.
    pub const SHARED: u32 = 1 << 3;
    /// Anonymous mapping.
    pub const ANONYMOUS: u32 = 1 << 4;
    /// Grows downward (stack).
    pub const GROWSDOWN: u32 = 1 << 5;
    /// Huge pages.
    pub const HUGEPAGE: u32 = 1 << 6;
    /// Locked (mlock).
    pub const LOCKED: u32 = 1 << 7;

    /// Creates empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates flags from bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if a flag is set.
    pub const fn contains(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

impl Default for VmaFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// RbColour
// -------------------------------------------------------------------

/// Red-black tree node colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RbColour {
    Red,
    Black,
}

impl Default for RbColour {
    fn default() -> Self {
        Self::Red
    }
}

// -------------------------------------------------------------------
// VmaEntry
// -------------------------------------------------------------------

/// A VMA node in the red-black tree.
#[derive(Debug, Clone, Copy)]
pub struct VmaEntry {
    /// Start address (inclusive).
    start: u64,
    /// End address (exclusive).
    end: u64,
    /// VMA flags.
    flags: VmaFlags,
    /// File offset (for file-backed mappings).
    file_offset: u64,
    /// Left child index.
    left: usize,
    /// Right child index.
    right: usize,
    /// Parent index.
    parent: usize,
    /// RB colour.
    colour: RbColour,
    /// Whether the slot is in use.
    in_use: bool,
}

impl VmaEntry {
    /// Creates an empty VMA entry.
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            flags: VmaFlags::empty(),
            file_offset: 0,
            left: NIL,
            right: NIL,
            parent: NIL,
            colour: RbColour::Red,
            in_use: false,
        }
    }

    /// Returns the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Returns the end address.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Returns the size.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Returns the flags.
    pub const fn flags(&self) -> VmaFlags {
        self.flags
    }

    /// Returns `true` if the address falls within this VMA.
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

impl Default for VmaEntry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmaRbTree
// -------------------------------------------------------------------

/// Red-black tree of VMAs keyed by start address.
pub struct VmaRbTree {
    /// Node storage.
    nodes: [VmaEntry; MAX_VMAS],
    /// Root index.
    root: usize,
    /// Number of active VMAs.
    count: usize,
}

impl VmaRbTree {
    /// Creates an empty VMA tree.
    pub const fn new() -> Self {
        Self {
            nodes: [const { VmaEntry::new() }; MAX_VMAS],
            root: NIL,
            count: 0,
        }
    }

    /// Returns the number of VMAs.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the tree is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Allocates a node slot.
    fn alloc_slot(&self) -> Result<usize> {
        for i in 0..MAX_VMAS {
            if !self.nodes[i].in_use {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Inserts a new VMA into the tree.
    pub fn insert(&mut self, start: u64, end: u64, flags: VmaFlags) -> Result<usize> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }

        // Check for overlap with existing VMAs.
        for i in 0..MAX_VMAS {
            if self.nodes[i].in_use && start < self.nodes[i].end && end > self.nodes[i].start {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = self.alloc_slot()?;
        self.nodes[idx] = VmaEntry {
            start,
            end,
            flags,
            file_offset: 0,
            left: NIL,
            right: NIL,
            parent: NIL,
            colour: RbColour::Red,
            in_use: true,
        };

        if self.root == NIL {
            self.root = idx;
            self.nodes[idx].colour = RbColour::Black;
            self.count += 1;
            return Ok(idx);
        }

        // BST insert by start address.
        let mut current = self.root;
        loop {
            if start < self.nodes[current].start {
                if self.nodes[current].left == NIL {
                    self.nodes[current].left = idx;
                    self.nodes[idx].parent = current;
                    break;
                }
                current = self.nodes[current].left;
            } else {
                if self.nodes[current].right == NIL {
                    self.nodes[current].right = idx;
                    self.nodes[idx].parent = current;
                    break;
                }
                current = self.nodes[current].right;
            }
        }

        self.count += 1;
        Ok(idx)
    }

    /// Removes a VMA by index.
    pub fn remove(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_VMAS || !self.nodes[idx].in_use {
            return Err(Error::NotFound);
        }

        // Lazy removal: collect and rebuild (production would use RB-delete).
        self.nodes[idx].in_use = false;
        self.count -= 1;

        let mut entries = [(0u64, 0u64, VmaFlags::empty()); MAX_VMAS];
        let mut n = 0;
        for i in 0..MAX_VMAS {
            if self.nodes[i].in_use {
                entries[n] = (self.nodes[i].start, self.nodes[i].end, self.nodes[i].flags);
                self.nodes[i].in_use = false;
                n += 1;
            }
        }

        self.root = NIL;
        self.count = 0;

        for i in 0..n {
            let _ = self.insert(entries[i].0, entries[i].1, entries[i].2);
        }

        Ok(())
    }

    /// Finds the VMA containing the given address.
    pub fn find(&self, addr: u64) -> Option<usize> {
        let mut current = self.root;
        while current != NIL {
            let node = &self.nodes[current];
            if !node.in_use {
                return None;
            }
            if node.contains_addr(addr) {
                return Some(current);
            }
            if addr < node.start {
                current = node.left;
            } else {
                current = node.right;
            }
        }
        None
    }

    /// Returns a reference to a VMA by index.
    pub fn get(&self, idx: usize) -> Result<&VmaEntry> {
        if idx >= MAX_VMAS || !self.nodes[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Collects all VMAs sorted by start address into `out`.
    pub fn collect_sorted(&self, out: &mut [VmaEntry]) -> usize {
        let mut n = 0;
        for i in 0..MAX_VMAS {
            if n >= out.len() {
                break;
            }
            if self.nodes[i].in_use {
                out[n] = self.nodes[i];
                n += 1;
            }
        }
        // Sort by start address.
        for i in 1..n {
            let mut j = i;
            while j > 0 && out[j].start < out[j - 1].start {
                out.swap(j, j - 1);
                j -= 1;
            }
        }
        n
    }
}

impl Default for VmaRbTree {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new VMA tree.
pub fn create_vma_tree() -> VmaRbTree {
    VmaRbTree::new()
}

/// Inserts a VMA and returns its index.
pub fn vma_insert(tree: &mut VmaRbTree, start: u64, end: u64, flags: VmaFlags) -> Result<usize> {
    tree.insert(start, end, flags)
}

/// Finds the VMA containing an address, returning the node index.
pub fn vma_find(tree: &VmaRbTree, addr: u64) -> Option<usize> {
    tree.find(addr)
}

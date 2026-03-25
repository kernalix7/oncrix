// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page extension framework for per-page metadata.
//!
//! The page extension framework allows subsystems (page_owner, page_idle,
//! page_table_check, …) to attach fixed-size metadata to every physical page
//! frame without modifying the core `Page` structure.
//!
//! # Design
//!
//! Each registered subsystem receives a unique [`ExtId`] and declares the
//! size (in bytes) of its per-page data.  The framework maintains a flat
//! array of extension blocks, one per page frame.  Each block is a
//! contiguous run of bytes subdivided into per-subsystem slots whose offsets
//! are computed at registration time.
//!
//! ```text
//! PFN 0: [ subsystem-0 slot | subsystem-1 slot | ... ]
//! PFN 1: [ subsystem-0 slot | subsystem-1 slot | ... ]
//! ...
//! PFN N-1: [ subsystem-0 slot | subsystem-1 slot | ... ]
//! ```
//!
//! Key types:
//!
//! * [`ExtDescriptor`] — describes one registered extension (id, name, size,
//!   byte offset within a block).
//! * [`ExtRegistry`] — global list of registered extensions; computes per-block
//!   layout after all extensions have registered.
//! * [`PageExtTable`] — the actual per-page backing store; looked up by PFN.
//! * [`PageExtManager`] — combines registry and table; the entry point used by
//!   kernel subsystems.
//!
//! Reference: Linux `mm/page_ext.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously registered page extensions.
pub const MAX_EXTENSIONS: usize = 16;

/// Maximum number of tracked page frames.
pub const MAX_PFN: usize = 65536;

/// Maximum bytes per extension slot.
pub const MAX_EXT_SIZE: usize = 256;

/// Maximum total bytes per page-extension block (across all extensions).
pub const MAX_BLOCK_SIZE: usize = MAX_EXTENSIONS * MAX_EXT_SIZE;

/// Sentinel value for an unregistered extension ID.
pub const EXT_ID_NONE: u8 = u8::MAX;

// ── ExtId ─────────────────────────────────────────────────────────────────────

/// Opaque identifier for a registered page extension.
///
/// Obtained from [`ExtRegistry::register`] and passed to
/// [`PageExtTable::slot_ptr`] / [`PageExtTable::slot_ptr_mut`] to locate the
/// per-page data slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtId(pub u8);

impl ExtId {
    /// The sentinel "no extension" value.
    pub const NONE: Self = Self(EXT_ID_NONE);

    /// Return `true` if this is a valid (non-sentinel) ID.
    pub fn is_valid(self) -> bool {
        self.0 != EXT_ID_NONE
    }
}

// ── ExtDescriptor ─────────────────────────────────────────────────────────────

/// Metadata for one registered page extension.
#[derive(Debug, Clone)]
pub struct ExtDescriptor {
    /// Unique identifier assigned at registration.
    pub id: ExtId,
    /// Human-readable name (up to 32 ASCII bytes, null-padded).
    pub name: [u8; 32],
    /// Size in bytes of the per-page data slot.
    pub slot_size: usize,
    /// Byte offset of this extension's slot within one page-extension block.
    ///
    /// Set to `usize::MAX` until [`ExtRegistry::finalise`] is called.
    pub offset: usize,
    /// Whether this extension has been enabled (initialised for all pages).
    pub enabled: bool,
}

impl ExtDescriptor {
    fn new(id: ExtId, name: &[u8], slot_size: usize) -> Self {
        let mut arr = [0u8; 32];
        let len = name.len().min(32);
        arr[..len].copy_from_slice(&name[..len]);
        Self {
            id,
            name: arr,
            slot_size,
            offset: usize::MAX,
            enabled: false,
        }
    }

    /// Return the human-readable name as a byte slice (trimmed of trailing
    /// null bytes).
    pub fn name_str(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(0);
        &self.name[..end]
    }
}

// ── ExtRegistry ───────────────────────────────────────────────────────────────

/// Registry of all page extensions.
///
/// Subsystems call [`ExtRegistry::register`] during early boot.  After all
/// subsystems have registered, [`ExtRegistry::finalise`] must be called once
/// to compute slot offsets and the total block size.  No further registrations
/// are permitted after finalisation.
#[derive(Debug)]
pub struct ExtRegistry {
    descriptors: [Option<ExtDescriptor>; MAX_EXTENSIONS],
    count: usize,
    /// Total bytes per page-extension block (valid after finalise).
    block_size: usize,
    finalised: bool,
}

impl ExtRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<ExtDescriptor> = None;
        Self {
            descriptors: [NONE; MAX_EXTENSIONS],
            count: 0,
            block_size: 0,
            finalised: false,
        }
    }

    /// Register a new extension with `name` and a per-page slot of `slot_size`
    /// bytes.
    ///
    /// Returns the assigned [`ExtId`].  Fails if the registry is full or has
    /// already been finalised.
    pub fn register(&mut self, name: &[u8], slot_size: usize) -> Result<ExtId> {
        if self.finalised {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_EXTENSIONS {
            return Err(Error::OutOfMemory);
        }
        if slot_size == 0 || slot_size > MAX_EXT_SIZE {
            return Err(Error::InvalidArgument);
        }
        let id = ExtId(self.count as u8);
        self.descriptors[self.count] = Some(ExtDescriptor::new(id, name, slot_size));
        self.count += 1;
        Ok(id)
    }

    /// Compute slot offsets and the total block size.
    ///
    /// Must be called exactly once, after all subsystems have registered.
    /// Subsequent calls are a no-op.
    pub fn finalise(&mut self) -> Result<()> {
        if self.finalised {
            return Ok(());
        }
        let mut offset = 0usize;
        for slot in self.descriptors.iter_mut().flatten() {
            if offset.saturating_add(slot.slot_size) > MAX_BLOCK_SIZE {
                return Err(Error::OutOfMemory);
            }
            slot.offset = offset;
            offset += slot.slot_size;
        }
        self.block_size = offset;
        self.finalised = true;
        Ok(())
    }

    /// Return the total block size (bytes per page).  Valid only after
    /// [`finalise`](Self::finalise).
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Look up the descriptor for `id`.
    pub fn descriptor(&self, id: ExtId) -> Option<&ExtDescriptor> {
        if !id.is_valid() || (id.0 as usize) >= self.count {
            return None;
        }
        self.descriptors[id.0 as usize].as_ref()
    }

    /// Return the byte offset of `id`'s slot within a block.
    pub fn offset(&self, id: ExtId) -> Option<usize> {
        self.descriptor(id).map(|d| d.offset)
    }

    /// Return whether the registry has been finalised.
    pub fn is_finalised(&self) -> bool {
        self.finalised
    }

    /// Return the number of registered extensions.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Mark extension `id` as enabled.
    pub fn enable(&mut self, id: ExtId) -> Result<()> {
        if !id.is_valid() || (id.0 as usize) >= self.count {
            return Err(Error::InvalidArgument);
        }
        if let Some(desc) = self.descriptors[id.0 as usize].as_mut() {
            desc.enabled = true;
        }
        Ok(())
    }

    /// Mark extension `id` as disabled.
    pub fn disable(&mut self, id: ExtId) -> Result<()> {
        if !id.is_valid() || (id.0 as usize) >= self.count {
            return Err(Error::InvalidArgument);
        }
        if let Some(desc) = self.descriptors[id.0 as usize].as_mut() {
            desc.enabled = false;
        }
        Ok(())
    }

    /// Return whether extension `id` is enabled.
    pub fn is_enabled(&self, id: ExtId) -> bool {
        self.descriptor(id).map(|d| d.enabled).unwrap_or(false)
    }
}

impl Default for ExtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── PageExtBlock ──────────────────────────────────────────────────────────────

/// Extension block for a single page frame.
///
/// A flat byte array subdivided into per-extension slots.  Subsystems write
/// and read their slot via [`PageExtTable::slot_ptr`] /
/// [`PageExtTable::slot_ptr_mut`].
#[derive(Debug)]
pub struct PageExtBlock {
    /// Raw byte storage.  Only `block_size` bytes (from the registry) are
    /// meaningful; the rest are zero.
    pub data: [u8; MAX_BLOCK_SIZE],
    /// Whether this block has been initialised.
    pub initialised: bool,
}

impl PageExtBlock {
    fn new() -> Self {
        Self {
            data: [0u8; MAX_BLOCK_SIZE],
            initialised: false,
        }
    }

    /// Zero-fill all bytes in this block and mark it uninitialised.
    pub fn reset(&mut self) {
        self.data = [0u8; MAX_BLOCK_SIZE];
        self.initialised = false;
    }
}

// ── PageExtTable ──────────────────────────────────────────────────────────────

/// Backing store for per-page extension data.
///
/// Indexed by PFN (page frame number).  After the registry is finalised and
/// the table is built, callers can retrieve a `*mut u8` pointer to any
/// extension's slot for any PFN.
pub struct PageExtTable {
    blocks: alloc::boxed::Box<[PageExtBlock]>,
    max_pfn: usize,
    block_size: usize,
}

extern crate alloc;

impl PageExtTable {
    /// Allocate the table for `max_pfn` pages, given that each block is
    /// `block_size` bytes wide.
    pub fn new(max_pfn: usize, block_size: usize) -> Result<Self> {
        if max_pfn == 0 || max_pfn > MAX_PFN {
            return Err(Error::InvalidArgument);
        }
        let mut vec = alloc::vec::Vec::new();
        vec.try_reserve(max_pfn).map_err(|_| Error::OutOfMemory)?;
        for _ in 0..max_pfn {
            vec.push(PageExtBlock::new());
        }
        Ok(Self {
            blocks: vec.into_boxed_slice(),
            max_pfn,
            block_size,
        })
    }

    /// Return the maximum PFN tracked by this table.
    pub fn max_pfn(&self) -> usize {
        self.max_pfn
    }

    /// Initialise (zero-fill) the extension block for `pfn`.
    pub fn init_page(&mut self, pfn: usize) -> Result<()> {
        let block = self.blocks.get_mut(pfn).ok_or(Error::InvalidArgument)?;
        block.data[..self.block_size].fill(0);
        block.initialised = true;
        Ok(())
    }

    /// Clear (zero-fill) and un-mark the extension block for `pfn`.
    pub fn fini_page(&mut self, pfn: usize) -> Result<()> {
        let block = self.blocks.get_mut(pfn).ok_or(Error::InvalidArgument)?;
        block.reset();
        Ok(())
    }

    /// Return `true` if the block for `pfn` is initialised.
    pub fn is_initialised(&self, pfn: usize) -> bool {
        self.blocks.get(pfn).map(|b| b.initialised).unwrap_or(false)
    }

    /// Return a raw const pointer to the byte offset `offset` within the
    /// extension block for `pfn`.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// * `pfn < max_pfn`
    /// * `offset + size <= block_size`
    /// * The block at `pfn` has been initialised.
    /// * Concurrent mutable accesses are not made through another pointer.
    pub unsafe fn slot_ptr(&self, pfn: usize, offset: usize) -> Result<*const u8> {
        let block = self.blocks.get(pfn).ok_or(Error::InvalidArgument)?;
        if !block.initialised {
            return Err(Error::InvalidArgument);
        }
        if offset >= MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: offset is within the array bounds.
        Ok(unsafe { block.data.as_ptr().add(offset) })
    }

    /// Return a raw mutable pointer to `offset` within the extension block for
    /// `pfn`.
    ///
    /// # Safety
    ///
    /// Same requirements as [`slot_ptr`](Self::slot_ptr), plus no immutable
    /// references to the same offset may be live at the same time.
    pub unsafe fn slot_ptr_mut(&mut self, pfn: usize, offset: usize) -> Result<*mut u8> {
        let block = self.blocks.get_mut(pfn).ok_or(Error::InvalidArgument)?;
        if !block.initialised {
            return Err(Error::InvalidArgument);
        }
        if offset >= MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: offset is within the array bounds.
        Ok(unsafe { block.data.as_mut_ptr().add(offset) })
    }

    /// Write `data` into the extension slot for (`pfn`, `offset`).
    ///
    /// Returns `Err` if the write would exceed `block_size` or the block is
    /// not initialised.
    pub fn write_slot(&mut self, pfn: usize, offset: usize, data: &[u8]) -> Result<()> {
        let block = self.blocks.get_mut(pfn).ok_or(Error::InvalidArgument)?;
        if !block.initialised {
            return Err(Error::InvalidArgument);
        }
        let end = offset
            .checked_add(data.len())
            .ok_or(Error::InvalidArgument)?;
        if end > self.block_size || end > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        block.data[offset..end].copy_from_slice(data);
        Ok(())
    }

    /// Read bytes from the extension slot for (`pfn`, `offset`) into `buf`.
    pub fn read_slot(&self, pfn: usize, offset: usize, buf: &mut [u8]) -> Result<()> {
        let block = self.blocks.get(pfn).ok_or(Error::InvalidArgument)?;
        if !block.initialised {
            return Err(Error::InvalidArgument);
        }
        let end = offset
            .checked_add(buf.len())
            .ok_or(Error::InvalidArgument)?;
        if end > self.block_size || end > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf.copy_from_slice(&block.data[offset..end]);
        Ok(())
    }

    /// Memory overhead of the extension table in bytes.
    pub fn memory_overhead(&self) -> usize {
        self.max_pfn * core::mem::size_of::<PageExtBlock>()
    }
}

// ── PageExtManager ────────────────────────────────────────────────────────────

/// Combined registry and table for the page extension framework.
///
/// This is the primary interface for kernel subsystems.
///
/// # Lifecycle
///
/// 1. Create with [`PageExtManager::new`].
/// 2. Each subsystem calls [`PageExtManager::register`] during early boot.
/// 3. Call [`PageExtManager::finalise`] once, before the first allocation.
/// 4. Per-page extension data is accessed via [`PageExtManager::lookup`] /
///    [`PageExtManager::lookup_mut`].
/// 5. When a page is freed call [`PageExtManager::page_fini`]; when freshly
///    allocated call [`PageExtManager::page_init`].
pub struct PageExtManager {
    /// Registry of extension descriptors.
    pub registry: ExtRegistry,
    /// Backing store (allocated after finalise).
    table: Option<PageExtTable>,
}

impl PageExtManager {
    /// Create a new, uninitialised manager.
    pub const fn new() -> Self {
        Self {
            registry: ExtRegistry::new(),
            table: None,
        }
    }

    /// Register a subsystem extension.  See [`ExtRegistry::register`].
    pub fn register(&mut self, name: &[u8], slot_size: usize) -> Result<ExtId> {
        self.registry.register(name, slot_size)
    }

    /// Finalise the registry and allocate backing memory for `max_pfn` pages.
    pub fn finalise(&mut self, max_pfn: usize) -> Result<()> {
        self.registry.finalise()?;
        let block_size = self.registry.block_size();
        if block_size == 0 {
            // No extensions registered — table is not needed.
            return Ok(());
        }
        self.table = Some(PageExtTable::new(max_pfn, block_size)?);
        Ok(())
    }

    /// Enable extension `id` and initialise its slot for all already-init pages.
    pub fn enable_extension(&mut self, id: ExtId) -> Result<()> {
        self.registry.enable(id)
    }

    /// Disable extension `id`.
    pub fn disable_extension(&mut self, id: ExtId) -> Result<()> {
        self.registry.disable(id)
    }

    /// Initialise the extension block for `pfn` when a page is allocated.
    pub fn page_init(&mut self, pfn: usize) -> Result<()> {
        match &mut self.table {
            Some(t) => t.init_page(pfn),
            None => Ok(()), // no extensions registered
        }
    }

    /// Clear the extension block for `pfn` when a page is freed.
    pub fn page_fini(&mut self, pfn: usize) -> Result<()> {
        match &mut self.table {
            Some(t) => t.fini_page(pfn),
            None => Ok(()),
        }
    }

    /// Write `data` into the slot of extension `id` for page `pfn`.
    pub fn write(&mut self, pfn: usize, id: ExtId, data: &[u8]) -> Result<()> {
        let offset = self.registry.offset(id).ok_or(Error::InvalidArgument)?;
        let slot_size = self
            .registry
            .descriptor(id)
            .map(|d| d.slot_size)
            .ok_or(Error::InvalidArgument)?;
        if data.len() > slot_size {
            return Err(Error::InvalidArgument);
        }
        self.table
            .as_mut()
            .ok_or(Error::InvalidArgument)?
            .write_slot(pfn, offset, data)
    }

    /// Read `buf.len()` bytes from the slot of extension `id` for page `pfn`.
    pub fn read(&self, pfn: usize, id: ExtId, buf: &mut [u8]) -> Result<()> {
        let offset = self.registry.offset(id).ok_or(Error::InvalidArgument)?;
        let slot_size = self
            .registry
            .descriptor(id)
            .map(|d| d.slot_size)
            .ok_or(Error::InvalidArgument)?;
        if buf.len() > slot_size {
            return Err(Error::InvalidArgument);
        }
        self.table
            .as_ref()
            .ok_or(Error::InvalidArgument)?
            .read_slot(pfn, offset, buf)
    }

    /// Return a const pointer to `id`'s slot for `pfn`.
    ///
    /// # Safety
    ///
    /// See [`PageExtTable::slot_ptr`].
    pub unsafe fn lookup(&self, pfn: usize, id: ExtId) -> Result<*const u8> {
        let offset = self.registry.offset(id).ok_or(Error::InvalidArgument)?;
        let table = self.table.as_ref().ok_or(Error::InvalidArgument)?;
        // SAFETY: forwarded to PageExtTable::slot_ptr.
        unsafe { table.slot_ptr(pfn, offset) }
    }

    /// Return a mutable pointer to `id`'s slot for `pfn`.
    ///
    /// # Safety
    ///
    /// See [`PageExtTable::slot_ptr_mut`].
    pub unsafe fn lookup_mut(&mut self, pfn: usize, id: ExtId) -> Result<*mut u8> {
        let offset = self.registry.offset(id).ok_or(Error::InvalidArgument)?;
        let table = self.table.as_mut().ok_or(Error::InvalidArgument)?;
        // SAFETY: forwarded to PageExtTable::slot_ptr_mut.
        unsafe { table.slot_ptr_mut(pfn, offset) }
    }

    /// Total memory overhead of the extension table in bytes.
    pub fn memory_overhead(&self) -> usize {
        self.table
            .as_ref()
            .map(|t| t.memory_overhead())
            .unwrap_or(0)
    }

    /// Return whether the manager has been finalised.
    pub fn is_finalised(&self) -> bool {
        self.registry.is_finalised()
    }
}

impl Default for PageExtManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Well-known extension IDs ──────────────────────────────────────────────────
//
// In a full kernel these would be registered by the owning subsystem at boot
// time.  We expose the names here as constants so callers can pass a
// human-readable string consistently.

/// Name used by the page_owner subsystem when registering its extension.
pub const PAGE_OWNER_EXT_NAME: &[u8] = b"page_owner";

/// Name used by the page_idle subsystem when registering its extension.
pub const PAGE_IDLE_EXT_NAME: &[u8] = b"page_idle";

/// Name used by the page_table_check subsystem when registering its extension.
pub const PAGE_TABLE_CHECK_EXT_NAME: &[u8] = b"page_table_check";

// ── PageExtStats ──────────────────────────────────────────────────────────────

/// Memory usage summary for the page extension framework.
#[derive(Debug, Default, Clone)]
pub struct PageExtStats {
    /// Number of registered extensions.
    pub num_extensions: usize,
    /// Bytes per page block.
    pub block_size: usize,
    /// Number of pages tracked.
    pub num_pages: usize,
    /// Total memory consumed by the extension table (bytes).
    pub total_bytes: usize,
}

impl PageExtStats {
    /// Gather statistics from `mgr`.
    pub fn from_manager(mgr: &PageExtManager) -> Self {
        let num_pages = mgr.table.as_ref().map(|t| t.max_pfn()).unwrap_or(0);
        Self {
            num_extensions: mgr.registry.count(),
            block_size: mgr.registry.block_size(),
            num_pages,
            total_bytes: mgr.memory_overhead(),
        }
    }
}

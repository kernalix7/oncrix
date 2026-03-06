// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS mmap integration layer.
//!
//! Provides the VFS-level interface for memory-mapped file I/O.
//! Handles mapping requests from `mmap(2)`, coordinating between
//! the VFS inode/file, the page cache, and the memory management subsystem.

use oncrix_lib::{Error, Result};

/// mmap protection flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapProt(pub u32);

impl MmapProt {
    /// Pages may not be accessed.
    pub const PROT_NONE: u32 = 0;
    /// Pages may be read.
    pub const PROT_READ: u32 = 1;
    /// Pages may be written.
    pub const PROT_WRITE: u32 = 2;
    /// Pages may be executed.
    pub const PROT_EXEC: u32 = 4;

    /// Check if read access is requested.
    pub fn readable(self) -> bool {
        self.0 & Self::PROT_READ != 0
    }

    /// Check if write access is requested.
    pub fn writable(self) -> bool {
        self.0 & Self::PROT_WRITE != 0
    }

    /// Check if execute access is requested.
    pub fn executable(self) -> bool {
        self.0 & Self::PROT_EXEC != 0
    }

    /// Validate protection flags.
    pub fn is_valid(self) -> bool {
        self.0 & !0x7 == 0
    }
}

/// mmap mapping flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapFlags(pub u32);

impl MmapFlags {
    /// Mapping is shared.
    pub const MAP_SHARED: u32 = 0x01;
    /// Mapping is private (copy-on-write).
    pub const MAP_PRIVATE: u32 = 0x02;
    /// Fixed virtual address.
    pub const MAP_FIXED: u32 = 0x10;
    /// Anonymous mapping (not backed by file).
    pub const MAP_ANONYMOUS: u32 = 0x20;
    /// Populate page tables eagerly.
    pub const MAP_POPULATE: u32 = 0x08000;
    /// Lock pages in memory.
    pub const MAP_LOCKED: u32 = 0x02000;

    /// Check if shared mapping.
    pub fn is_shared(self) -> bool {
        self.0 & Self::MAP_SHARED != 0
    }

    /// Check if private (CoW) mapping.
    pub fn is_private(self) -> bool {
        self.0 & Self::MAP_PRIVATE != 0
    }

    /// Check if anonymous.
    pub fn is_anonymous(self) -> bool {
        self.0 & Self::MAP_ANONYMOUS != 0
    }

    /// Check if fixed address.
    pub fn is_fixed(self) -> bool {
        self.0 & Self::MAP_FIXED != 0
    }

    /// Validate: exactly one of MAP_SHARED/MAP_PRIVATE must be set.
    pub fn is_valid(self) -> bool {
        let shared = self.is_shared();
        let private = self.is_private();
        shared ^ private
    }
}

/// A VFS mmap request.
#[derive(Debug, Clone, Copy)]
pub struct MmapRequest {
    /// Inode number of the file to map.
    pub ino: u64,
    /// Mount ID of the filesystem.
    pub mount_id: u32,
    /// Offset within the file (must be page-aligned).
    pub offset: u64,
    /// Length of the mapping in bytes.
    pub length: usize,
    /// Protection flags.
    pub prot: MmapProt,
    /// Mapping flags.
    pub flags: MmapFlags,
    /// Suggested virtual address (or 0 for kernel to choose).
    pub addr_hint: usize,
}

impl MmapRequest {
    /// Create a new mmap request.
    pub const fn new(
        ino: u64,
        mount_id: u32,
        offset: u64,
        length: usize,
        prot: MmapProt,
        flags: MmapFlags,
    ) -> Self {
        MmapRequest {
            ino,
            mount_id,
            offset,
            length,
            prot,
            flags,
            addr_hint: 0,
        }
    }
}

/// Validation result for a mmap request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmapValidation {
    /// Request is valid and can proceed.
    Ok,
    /// Request is invalid.
    Invalid,
}

/// Validate a mmap request against inode properties.
pub fn validate_mmap(
    req: &MmapRequest,
    file_size: u64,
    inode_mode: u16,
    file_writable: bool,
) -> Result<()> {
    if !req.prot.is_valid() {
        return Err(Error::InvalidArgument);
    }
    if !req.flags.is_valid() {
        return Err(Error::InvalidArgument);
    }
    if req.length == 0 {
        return Err(Error::InvalidArgument);
    }
    // Offset must be page-aligned.
    if req.offset & 0xFFF != 0 {
        return Err(Error::InvalidArgument);
    }
    // Cannot map beyond file for shared writable mappings.
    if req.flags.is_shared() && req.prot.writable() && !file_writable {
        return Err(Error::PermissionDenied);
    }
    // Cannot execute from a noexec file.
    let is_noexec = inode_mode & 0o111 == 0;
    if req.prot.executable() && is_noexec {
        return Err(Error::PermissionDenied);
    }
    // Anonymous mappings don't need a file size check.
    if req.flags.is_anonymous() {
        return Ok(());
    }
    // Offset must not exceed file size.
    if req.offset > file_size {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// VFS mmap mapping descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VmArea {
    /// Virtual start address.
    pub vm_start: usize,
    /// Virtual end address (exclusive).
    pub vm_end: usize,
    /// Inode number backing this mapping.
    pub ino: u64,
    /// File offset.
    pub offset: u64,
    /// Protection flags.
    pub prot: MmapProt,
    /// Mapping flags.
    pub flags: MmapFlags,
}

impl VmArea {
    /// Create a new vm_area descriptor.
    pub const fn new(
        vm_start: usize,
        vm_end: usize,
        ino: u64,
        offset: u64,
        prot: MmapProt,
        flags: MmapFlags,
    ) -> Self {
        VmArea {
            vm_start,
            vm_end,
            ino,
            offset,
            prot,
            flags,
        }
    }

    /// Length in bytes.
    pub fn length(&self) -> usize {
        self.vm_end - self.vm_start
    }

    /// Check if `addr` falls within this mapping.
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.vm_start && addr < self.vm_end
    }
}

/// VFS mmap area table for a process.
pub struct VmAreaTable {
    areas: [Option<VmArea>; 256],
    count: usize,
}

impl VmAreaTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        VmAreaTable {
            areas: [const { None }; 256],
            count: 0,
        }
    }

    /// Add a new mapping.
    pub fn insert(&mut self, area: VmArea) -> Result<usize> {
        for (i, slot) in self.areas.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(area);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mapping by start address.
    pub fn remove_by_addr(&mut self, addr: usize) -> Result<VmArea> {
        for slot in &mut self.areas {
            if let Some(area) = slot {
                if area.vm_start == addr {
                    let a = *area;
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(a);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find the mapping containing `addr`.
    pub fn find(&self, addr: usize) -> Option<&VmArea> {
        self.areas.iter().flatten().find(|a| a.contains(addr))
    }

    /// Iterate over all mappings backed by a given inode.
    pub fn by_inode(&self, ino: u64) -> impl Iterator<Item = &VmArea> {
        self.areas.iter().flatten().filter(move |a| a.ino == ino)
    }

    /// Return count of active mappings.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for VmAreaTable {
    fn default() -> Self {
        Self::new()
    }
}

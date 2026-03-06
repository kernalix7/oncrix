// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device Tree (FDT/DTB) blob parser.
//!
//! Implements a minimal, zero-allocation parser for the Flattened Device
//! Tree format (dtspec v0.4). Supports:
//! - Validating the FDT magic and header
//! - Iterating the structure block (nodes, properties)
//! - Looking up named properties within a node
//! - Resolving strings from the string block
//!
//! This parser does NOT build an in-memory tree; it performs linear
//! traversal of the structure block on each call, which is appropriate
//! for early boot where no allocator is available.
//!
//! Reference: devicetree-specification v0.4, Chapter 5 (Flattened Devicetree)

use oncrix_lib::{Error, Result};

// ── FDT magic and constants ───────────────────────────────────────────────────

/// FDT magic number (big-endian `0xD00DFEED`).
pub const FDT_MAGIC: u32 = 0xD00D_FEED;

/// FDT token: start of node.
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
/// FDT token: end of node.
const FDT_END_NODE: u32 = 0x0000_0002;
/// FDT token: property.
const FDT_PROP: u32 = 0x0000_0003;
/// FDT token: no-op (skip).
const FDT_NOP: u32 = 0x0000_0004;
/// FDT token: end of structure block.
const FDT_END: u32 = 0x0000_0009;

/// Minimum FDT header size in bytes.
pub const FDT_HEADER_SIZE: usize = 40;

/// Maximum FDT blob size (64 MiB).
const MAX_FDT_SIZE: usize = 64 * 1024 * 1024;

// ── FdtHeader ────────────────────────────────────────────────────────────────

/// Flattened Device Tree header (all fields are big-endian).
///
/// Placed at the very beginning of the FDT blob.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FdtHeader {
    /// Magic number (must be `FDT_MAGIC = 0xD00DFEED`).
    pub magic: u32,
    /// Total size of the FDT blob in bytes.
    pub total_size: u32,
    /// Byte offset from the start of the blob to the structure block.
    pub off_dt_struct: u32,
    /// Byte offset from the start of the blob to the strings block.
    pub off_dt_strings: u32,
    /// Byte offset from the start of the blob to the memory reservation block.
    pub off_mem_rsvmap: u32,
    /// Version of the device tree format (current = 17).
    pub version: u32,
    /// Oldest compatible version (should be 16).
    pub last_comp_version: u32,
    /// Physical ID of the boot CPU.
    pub boot_cpuid_phys: u32,
    /// Length in bytes of the strings block.
    pub size_dt_strings: u32,
    /// Length in bytes of the structure block.
    pub size_dt_struct: u32,
}

impl FdtHeader {
    /// Parse a big-endian FDT header from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the slice is too short or
    /// magic does not match.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < FDT_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: data.len() >= FDT_HEADER_SIZE = 40 bytes, which covers
        // all 10 u32 fields (40 bytes). We convert from big-endian.
        let raw = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const [u32; 10]) };
        let hdr = Self {
            magic: u32::from_be(raw[0]),
            total_size: u32::from_be(raw[1]),
            off_dt_struct: u32::from_be(raw[2]),
            off_dt_strings: u32::from_be(raw[3]),
            off_mem_rsvmap: u32::from_be(raw[4]),
            version: u32::from_be(raw[5]),
            last_comp_version: u32::from_be(raw[6]),
            boot_cpuid_phys: u32::from_be(raw[7]),
            size_dt_strings: u32::from_be(raw[8]),
            size_dt_struct: u32::from_be(raw[9]),
        };
        if hdr.magic != FDT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(hdr)
    }
}

// ── FdtBlob ──────────────────────────────────────────────────────────────────

/// A validated FDT blob reference.
///
/// Holds a reference to the raw bytes and the parsed header. All
/// traversal operations are bounds-checked against the blob.
pub struct FdtBlob<'a> {
    data: &'a [u8],
    header: FdtHeader,
}

impl<'a> FdtBlob<'a> {
    /// Validate and wrap an FDT blob.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the magic is wrong, the
    /// blob is too short, or the structure/string offsets are out of bounds.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let header = FdtHeader::parse(data)?;
        if data.len() < header.total_size as usize {
            return Err(Error::InvalidArgument);
        }
        if header.total_size as usize > MAX_FDT_SIZE {
            return Err(Error::InvalidArgument);
        }
        let struct_end =
            (header.off_dt_struct as usize).saturating_add(header.size_dt_struct as usize);
        let string_end =
            (header.off_dt_strings as usize).saturating_add(header.size_dt_strings as usize);
        if struct_end > data.len() || string_end > data.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { data, header })
    }

    /// Return a reference to the raw blob data.
    pub fn raw(&self) -> &[u8] {
        self.data
    }

    /// Return the parsed FDT header.
    pub fn header(&self) -> &FdtHeader {
        &self.header
    }

    /// Return the structure block as a byte slice.
    pub fn struct_block(&self) -> &[u8] {
        let start = self.header.off_dt_struct as usize;
        let end = start + self.header.size_dt_struct as usize;
        &self.data[start..end]
    }

    /// Return the strings block as a byte slice.
    pub fn strings_block(&self) -> &[u8] {
        let start = self.header.off_dt_strings as usize;
        let end = start + self.header.size_dt_strings as usize;
        &self.data[start..end]
    }

    /// Resolve a string from the strings block at the given offset.
    ///
    /// Returns a null-terminated byte slice (not including the null byte).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offset is out of bounds.
    pub fn string_at(&self, offset: u32) -> Result<&[u8]> {
        let strings = self.strings_block();
        let start = offset as usize;
        if start >= strings.len() {
            return Err(Error::InvalidArgument);
        }
        let end = strings[start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::InvalidArgument)?;
        Ok(&strings[start..start + end])
    }

    /// Return a node iterator starting at the root.
    pub fn nodes(&self) -> NodeIterator<'_> {
        NodeIterator::new(self)
    }

    /// Find a node by its full path (e.g., "/cpus/cpu@0").
    ///
    /// Path components are separated by `/`. The root node is `/`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no node with the given path exists.
    pub fn find_node(&self, path: &[u8]) -> Result<FdtNode<'_>> {
        for node in self.nodes() {
            if node.name() == path {
                return Ok(node);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a property by node path and property name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if node or property not found.
    pub fn find_property(&self, node_path: &[u8], prop_name: &[u8]) -> Result<FdtProp<'_>> {
        let node = self.find_node(node_path)?;
        node.property(prop_name).ok_or(Error::NotFound)
    }

    /// Read a big-endian u32 property value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or [`Error::InvalidArgument`] if the
    /// property data is not exactly 4 bytes.
    pub fn property_u32(&self, node_path: &[u8], prop_name: &[u8]) -> Result<u32> {
        let prop = self.find_property(node_path, prop_name)?;
        if prop.data.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: prop.data.len() >= 4.
        let val = unsafe { core::ptr::read_unaligned(prop.data.as_ptr() as *const u32) };
        Ok(u32::from_be(val))
    }

    /// Read a big-endian u64 property value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or [`Error::InvalidArgument`] if the
    /// property data is not exactly 8 bytes.
    pub fn property_u64(&self, node_path: &[u8], prop_name: &[u8]) -> Result<u64> {
        let prop = self.find_property(node_path, prop_name)?;
        if prop.data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: prop.data.len() >= 8.
        let val = unsafe { core::ptr::read_unaligned(prop.data.as_ptr() as *const u64) };
        Ok(u64::from_be(val))
    }
}

// ── FdtProp ──────────────────────────────────────────────────────────────────

/// A single FDT property (name + raw data).
#[derive(Clone, Copy)]
pub struct FdtProp<'a> {
    /// Property name (not null-terminated).
    pub name: &'a [u8],
    /// Raw property data bytes.
    pub data: &'a [u8],
}

impl<'a> FdtProp<'a> {
    /// Read the property data as a big-endian u32.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if data < 4 bytes.
    pub fn as_u32(&self) -> Result<u32> {
        if self.data.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: data.len() >= 4.
        let val = unsafe { core::ptr::read_unaligned(self.data.as_ptr() as *const u32) };
        Ok(u32::from_be(val))
    }

    /// Read the property data as a big-endian u64.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if data < 8 bytes.
    pub fn as_u64(&self) -> Result<u64> {
        if self.data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: data.len() >= 8.
        let val = unsafe { core::ptr::read_unaligned(self.data.as_ptr() as *const u64) };
        Ok(u64::from_be(val))
    }

    /// Return the property data as a byte slice (including null terminator
    /// for string properties).
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Interpret the data as a null-terminated string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no null terminator found.
    pub fn as_str(&self) -> Result<&[u8]> {
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::InvalidArgument)?;
        Ok(&self.data[..end])
    }
}

// ── FdtNode ──────────────────────────────────────────────────────────────────

/// A node in the FDT structure block.
pub struct FdtNode<'a> {
    /// Full path of this node (not null-terminated).
    name: &'a [u8],
    /// Byte offset of this node's property data in the structure block.
    prop_start: usize,
    /// The parent blob (for string lookup).
    blob: &'a FdtBlob<'a>,
}

impl<'a> FdtNode<'a> {
    /// Return the node name (last path component + unit address).
    pub fn name(&self) -> &[u8] {
        self.name
    }

    /// Find a property by name within this node.
    ///
    /// Returns `None` if the property does not exist in this node.
    pub fn property(&self, name: &[u8]) -> Option<FdtProp<'a>> {
        let structure = self.blob.struct_block();
        let mut offset = self.prop_start;

        loop {
            // Align to 4 bytes.
            offset = (offset + 3) & !3;
            if offset + 4 > structure.len() {
                break;
            }
            // SAFETY: offset is 4-byte aligned and within structure.
            let token = u32::from_be(unsafe {
                core::ptr::read_unaligned(structure.as_ptr().add(offset) as *const u32)
            });
            offset += 4;

            match token {
                FDT_PROP => {
                    if offset + 8 > structure.len() {
                        break;
                    }
                    // SAFETY: reading prop len + nameoff.
                    let prop_len = u32::from_be(unsafe {
                        core::ptr::read_unaligned(structure.as_ptr().add(offset) as *const u32)
                    }) as usize;
                    let nameoff = u32::from_be(unsafe {
                        core::ptr::read_unaligned(structure.as_ptr().add(offset + 4) as *const u32)
                    });
                    offset += 8;
                    let data_end = offset + prop_len;
                    if data_end > structure.len() {
                        break;
                    }
                    let prop_data = &structure[offset..data_end];
                    offset = data_end;

                    if let Ok(prop_name) = self.blob.string_at(nameoff) {
                        if prop_name == name {
                            return Some(FdtProp {
                                name: prop_name,
                                data: prop_data,
                            });
                        }
                    }
                }
                FDT_NOP => {}
                FDT_BEGIN_NODE | FDT_END_NODE | FDT_END => break,
                _ => break,
            }
        }
        None
    }

    /// Return an iterator over this node's properties.
    pub fn properties(&self) -> PropIterator<'a> {
        PropIterator {
            blob: self.blob,
            offset: self.prop_start,
        }
    }
}

// ── PropIterator ─────────────────────────────────────────────────────────────

/// Iterator over properties within a single FDT node.
pub struct PropIterator<'a> {
    blob: &'a FdtBlob<'a>,
    offset: usize,
}

impl<'a> Iterator for PropIterator<'a> {
    type Item = FdtProp<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let structure = self.blob.struct_block();
        loop {
            self.offset = (self.offset + 3) & !3;
            if self.offset + 4 > structure.len() {
                return None;
            }
            // SAFETY: offset is aligned and in bounds.
            let token = u32::from_be(unsafe {
                core::ptr::read_unaligned(structure.as_ptr().add(self.offset) as *const u32)
            });
            self.offset += 4;

            match token {
                FDT_PROP => {
                    if self.offset + 8 > structure.len() {
                        return None;
                    }
                    // SAFETY: reading len + nameoff within structure bounds.
                    let prop_len = u32::from_be(unsafe {
                        core::ptr::read_unaligned(structure.as_ptr().add(self.offset) as *const u32)
                    }) as usize;
                    let nameoff = u32::from_be(unsafe {
                        core::ptr::read_unaligned(
                            structure.as_ptr().add(self.offset + 4) as *const u32
                        )
                    });
                    self.offset += 8;
                    let data_end = self.offset + prop_len;
                    if data_end > structure.len() {
                        return None;
                    }
                    let data = &structure[self.offset..data_end];
                    self.offset = data_end;
                    let name = self.blob.string_at(nameoff).unwrap_or(b"");
                    return Some(FdtProp { name, data });
                }
                FDT_NOP => {}
                _ => return None,
            }
        }
    }
}

// ── NodeIterator ─────────────────────────────────────────────────────────────

/// Flat iterator over all FDT nodes (depth-first, not including the root).
pub struct NodeIterator<'a> {
    blob: &'a FdtBlob<'a>,
    /// Current offset in the structure block.
    offset: usize,
    /// Current nesting depth.
    depth: i32,
}

impl<'a> NodeIterator<'a> {
    fn new(blob: &'a FdtBlob<'a>) -> Self {
        Self {
            blob,
            offset: 0,
            depth: 0,
        }
    }
}

impl<'a> Iterator for NodeIterator<'a> {
    type Item = FdtNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let structure = self.blob.struct_block();

        loop {
            self.offset = (self.offset + 3) & !3;
            if self.offset + 4 > structure.len() {
                return None;
            }
            // SAFETY: offset is aligned and in bounds.
            let token = u32::from_be(unsafe {
                core::ptr::read_unaligned(structure.as_ptr().add(self.offset) as *const u32)
            });
            self.offset += 4;

            match token {
                FDT_BEGIN_NODE => {
                    self.depth += 1;
                    // Read null-terminated node name.
                    let name_start = self.offset;
                    let name_end = structure[name_start..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| name_start + p)
                        .unwrap_or(structure.len());
                    let name = &structure[name_start..name_end];
                    // Advance past the name + null byte.
                    self.offset = name_end + 1;
                    // Properties start here (will be aligned on next loop).
                    let prop_start = self.offset;

                    // Skip past this node's properties to find the next node.
                    // We return a FdtNode that can lazily iterate its properties.
                    return Some(FdtNode {
                        name,
                        prop_start,
                        blob: self.blob,
                    });
                }
                FDT_END_NODE => {
                    self.depth -= 1;
                }
                FDT_PROP => {
                    // Skip this property.
                    if self.offset + 8 > structure.len() {
                        return None;
                    }
                    // SAFETY: reading prop_len within structure bounds.
                    let prop_len = u32::from_be(unsafe {
                        core::ptr::read_unaligned(structure.as_ptr().add(self.offset) as *const u32)
                    }) as usize;
                    self.offset += 8 + prop_len;
                }
                FDT_NOP => {}
                FDT_END => return None,
                _ => return None,
            }
        }
    }
}

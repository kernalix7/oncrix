// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF Type Format (BTF) type system.
//!
//! BTF provides compact type information for eBPF programs, enabling
//! the verifier and runtime to understand struct layouts, function
//! signatures, and variable types without external debug info.
//!
//! # Components
//!
//! - [`BtfHeader`] — `repr(C)` header identifying the BTF blob
//! - [`BtfKind`] — enumeration of all BTF type kinds (int, ptr,
//!   array, struct, union, enum, func, datasec, etc.)
//! - [`BtfType`] — type descriptor combining kind, name offset,
//!   and kind-specific data
//! - [`BtfStringTable`] — null-terminated string table for type
//!   and member names
//! - [`BtfTypeTable`] — registry of all types in a BTF blob
//! - [`BtfResolver`] — resolves type chains (typedef, const,
//!   volatile, restrict → base type)
//! - [`BtfDedup`] — deduplication engine that merges structurally
//!   equivalent types
//!
//! # Design
//!
//! All structures use fixed-size arrays for `#![no_std]`
//! compatibility. The type table holds up to 512 types and the
//! string table stores up to 8 KiB of name data.
//!
//! Reference: Linux `kernel/bpf/btf.c`,
//! `include/uapi/linux/btf.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Magic number identifying a BTF blob.
pub const BTF_MAGIC: u16 = 0xEB9F;

/// Current BTF format version.
pub const BTF_VERSION: u8 = 1;

/// Maximum number of types in a single BTF blob.
const MAX_TYPES: usize = 512;

/// Maximum string table size in bytes.
const MAX_STRING_TABLE: usize = 8192;

/// Maximum number of members in a struct/union.
const MAX_MEMBERS: usize = 64;

/// Maximum number of enum values.
const MAX_ENUM_VALUES: usize = 64;

/// Maximum number of datasec variables.
const MAX_DATASEC_VARS: usize = 64;

/// Maximum type resolution depth (to detect infinite loops).
const MAX_RESOLVE_DEPTH: usize = 32;

// ── BtfHeader ─────────────────────────────────────────────────────

/// On-disk / in-memory BTF header.
///
/// Describes the layout of the type and string sections within a
/// BTF blob. All offsets are relative to the end of this header.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BtfHeader {
    /// Magic number ([`BTF_MAGIC`]).
    pub magic: u16,
    /// Format version ([`BTF_VERSION`]).
    pub version: u8,
    /// Flags (currently reserved, must be 0).
    pub flags: u8,
    /// Total size of this header in bytes.
    pub hdr_len: u32,
    /// Offset of the type section from end of header.
    pub type_off: u32,
    /// Length of the type section in bytes.
    pub type_len: u32,
    /// Offset of the string section from end of header.
    pub str_off: u32,
    /// Length of the string section in bytes.
    pub str_len: u32,
}

impl BtfHeader {
    /// Create a header with default values.
    pub const fn new() -> Self {
        Self {
            magic: BTF_MAGIC,
            version: BTF_VERSION,
            flags: 0,
            hdr_len: core::mem::size_of::<Self>() as u32,
            type_off: 0,
            type_len: 0,
            str_off: 0,
            str_len: 0,
        }
    }

    /// Validate that the header has correct magic and version.
    pub const fn is_valid(&self) -> bool {
        self.magic == BTF_MAGIC && self.version == BTF_VERSION
    }
}

// ── BtfKind ───────────────────────────────────────────────────────

/// BTF type kind discriminator.
///
/// Each variant corresponds to a different category of type
/// information. The numeric values match the Linux BTF ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum BtfKind {
    /// Unknown / void type (kind 0).
    #[default]
    Void = 0,
    /// Integer type with encoding info.
    Int = 1,
    /// Pointer to another type.
    Ptr = 2,
    /// Fixed-size array of elements.
    Array = 3,
    /// Struct with named members.
    Struct = 4,
    /// Union with named members.
    Union = 5,
    /// Enumeration with named values.
    Enum = 6,
    /// Forward declaration.
    Fwd = 7,
    /// Type alias (typedef).
    Typedef = 8,
    /// Volatile qualifier.
    Volatile = 9,
    /// Const qualifier.
    Const = 10,
    /// Restrict qualifier.
    Restrict = 11,
    /// Function prototype.
    Func = 12,
    /// Function prototype with parameters.
    FuncProto = 13,
    /// Variable definition.
    Var = 14,
    /// Data section (global variables grouped together).
    Datasec = 15,
    /// Floating-point type.
    Float = 16,
    /// Decl tag annotation.
    DeclTag = 17,
    /// Type tag annotation.
    TypeTag = 18,
    /// 64-bit enumeration.
    Enum64 = 19,
}

impl BtfKind {
    /// Convert from a raw u8 value.
    pub const fn from_raw(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Ptr),
            3 => Some(Self::Array),
            4 => Some(Self::Struct),
            5 => Some(Self::Union),
            6 => Some(Self::Enum),
            7 => Some(Self::Fwd),
            8 => Some(Self::Typedef),
            9 => Some(Self::Volatile),
            10 => Some(Self::Const),
            11 => Some(Self::Restrict),
            12 => Some(Self::Func),
            13 => Some(Self::FuncProto),
            14 => Some(Self::Var),
            15 => Some(Self::Datasec),
            16 => Some(Self::Float),
            17 => Some(Self::DeclTag),
            18 => Some(Self::TypeTag),
            19 => Some(Self::Enum64),
            _ => None,
        }
    }

    /// Whether this kind is a modifier (typedef, const, volatile,
    /// restrict) that wraps another type.
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::Typedef | Self::Volatile | Self::Const | Self::Restrict | Self::TypeTag
        )
    }
}

// ── BtfIntEncoding ────────────────────────────────────────────────

/// Encoding flags for BTF integer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfIntEncoding(u8);

impl BtfIntEncoding {
    /// No special encoding (unsigned).
    pub const NONE: Self = Self(0);
    /// Signed integer.
    pub const SIGNED: Self = Self(1 << 0);
    /// Character type.
    pub const CHAR: Self = Self(1 << 1);
    /// Boolean type.
    pub const BOOL: Self = Self(1 << 2);

    /// Create from raw value.
    pub const fn from_raw(val: u8) -> Self {
        Self(val)
    }

    /// Raw value.
    pub const fn as_raw(self) -> u8 {
        self.0
    }

    /// Test if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

// ── BtfMember ─────────────────────────────────────────────────────

/// A member of a struct or union type.
#[derive(Debug, Clone, Copy)]
pub struct BtfMember {
    /// Offset into the string table for the member name.
    pub name_off: u32,
    /// Type id of this member.
    pub type_id: u32,
    /// Bit offset within the struct (or bit-field encoding).
    pub offset: u32,
}

impl BtfMember {
    /// Empty member.
    const fn empty() -> Self {
        Self {
            name_off: 0,
            type_id: 0,
            offset: 0,
        }
    }
}

// ── BtfEnumValue ──────────────────────────────────────────────────

/// A named value in an enumeration type.
#[derive(Debug, Clone, Copy)]
pub struct BtfEnumValue {
    /// Offset into the string table for the name.
    pub name_off: u32,
    /// Integer value (32-bit for Enum, low 32-bits for Enum64).
    pub val: i64,
}

impl BtfEnumValue {
    /// Empty enum value.
    const fn empty() -> Self {
        Self {
            name_off: 0,
            val: 0,
        }
    }
}

// ── BtfArrayInfo ──────────────────────────────────────────────────

/// Array type descriptor.
#[derive(Debug, Clone, Copy)]
pub struct BtfArrayInfo {
    /// Type id of the element type.
    pub elem_type: u32,
    /// Type id of the index type (usually u32).
    pub index_type: u32,
    /// Number of elements.
    pub nelems: u32,
}

impl BtfArrayInfo {
    /// Empty array info.
    const fn empty() -> Self {
        Self {
            elem_type: 0,
            index_type: 0,
            nelems: 0,
        }
    }
}

// ── BtfDatasecVar ─────────────────────────────────────────────────

/// A variable entry within a datasec type.
#[derive(Debug, Clone, Copy)]
pub struct BtfDatasecVar {
    /// Type id of the variable.
    pub type_id: u32,
    /// Offset of the variable within the section.
    pub offset: u32,
    /// Size of the variable in bytes.
    pub size: u32,
}

impl BtfDatasecVar {
    /// Empty datasec var.
    const fn empty() -> Self {
        Self {
            type_id: 0,
            offset: 0,
            size: 0,
        }
    }
}

// ── BtfKindData ───────────────────────────────────────────────────

/// Kind-specific data stored within a [`BtfType`].
#[derive(Debug, Clone, Copy)]
pub enum BtfKindData {
    /// No extra data (void, fwd, ptr, const, volatile, restrict,
    /// typedef, type_tag).
    None,
    /// Integer: size in bytes, encoding, bit offset, bit count.
    Int {
        /// Size in bytes.
        size: u32,
        /// Encoding flags.
        encoding: BtfIntEncoding,
        /// Bit offset within the storage unit.
        bit_offset: u8,
        /// Number of bits.
        bits: u8,
    },
    /// Array descriptor.
    Array(BtfArrayInfo),
    /// Struct or union members.
    Composite {
        /// Total size in bytes.
        size: u32,
        /// Members.
        members: [BtfMember; MAX_MEMBERS],
        /// Number of valid members.
        member_count: usize,
    },
    /// Enumeration values.
    Enum {
        /// Size of the underlying integer (4 or 8).
        size: u32,
        /// Enum values.
        values: [BtfEnumValue; MAX_ENUM_VALUES],
        /// Number of valid values.
        value_count: usize,
    },
    /// Function: linkage type (0 = static, 1 = global, 2 = extern).
    Func {
        /// Linkage type.
        linkage: u8,
    },
    /// Function prototype: return type and parameter types stored
    /// as composite members (name_off = param name, type_id = param
    /// type).
    FuncProto {
        /// Return type id.
        ret_type: u32,
        /// Parameter descriptors (reuses BtfMember).
        params: [BtfMember; MAX_MEMBERS],
        /// Number of parameters.
        param_count: usize,
    },
    /// Variable: linkage type.
    Var {
        /// Linkage type.
        linkage: u8,
    },
    /// Data section variables.
    Datasec {
        /// Section size in bytes.
        size: u32,
        /// Variables.
        vars: [BtfDatasecVar; MAX_DATASEC_VARS],
        /// Number of variables.
        var_count: usize,
    },
    /// Floating-point type size.
    Float {
        /// Size in bytes.
        size: u32,
    },
    /// Decl tag: component index.
    DeclTag {
        /// Component index (-1 for type itself).
        component_idx: i32,
    },
}

// ── BtfType ───────────────────────────────────────────────────────

/// A single BTF type descriptor.
#[derive(Debug, Clone, Copy)]
pub struct BtfType {
    /// Type id (1-based; 0 is void).
    pub id: u32,
    /// Kind discriminator.
    pub kind: BtfKind,
    /// Offset into the string table for the type name.
    pub name_off: u32,
    /// For pointer/typedef/volatile/const/restrict/type_tag: the
    /// target type id.
    pub ref_type: u32,
    /// Kind-specific data.
    pub data: BtfKindData,
    /// Whether this slot is in use.
    pub active: bool,
}

impl BtfType {
    /// Empty type slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            kind: BtfKind::Void,
            name_off: 0,
            ref_type: 0,
            data: BtfKindData::None,
            active: false,
        }
    }
}

// ── BtfStringTable ────────────────────────────────────────────────

/// Null-terminated string table for BTF names.
///
/// Strings are stored contiguously. The first byte is always `\0`
/// (representing the empty string at offset 0).
pub struct BtfStringTable {
    /// Raw string data.
    data: [u8; MAX_STRING_TABLE],
    /// Current write position.
    len: usize,
}

impl BtfStringTable {
    /// Create a new string table with the initial empty string.
    pub const fn new() -> Self {
        let mut data = [0u8; MAX_STRING_TABLE];
        data[0] = 0; // empty string at offset 0
        Self { data, len: 1 }
    }

    /// Add a string and return its offset.
    pub fn add(&mut self, s: &[u8]) -> Result<u32> {
        let needed = s.len() + 1; // string + null terminator
        if self.len + needed > MAX_STRING_TABLE {
            return Err(Error::OutOfMemory);
        }
        let off = self.len as u32;
        self.data[self.len..self.len + s.len()].copy_from_slice(s);
        self.data[self.len + s.len()] = 0;
        self.len += needed;
        Ok(off)
    }

    /// Look up a string by offset.
    ///
    /// Returns the slice up to (but not including) the null
    /// terminator.
    pub fn get(&self, off: u32) -> Result<&[u8]> {
        let start = off as usize;
        if start >= self.len {
            return Err(Error::InvalidArgument);
        }
        let end = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(self.len);
        Ok(&self.data[start..end])
    }

    /// Current used size in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table contains only the empty string.
    pub const fn is_empty(&self) -> bool {
        self.len <= 1
    }
}

// ── BtfTypeTable ──────────────────────────────────────────────────

/// Registry of all BTF types in a blob.
pub struct BtfTypeTable {
    /// Type entries (1-based indexing; slot 0 is unused/void).
    types: [BtfType; MAX_TYPES],
    /// Number of types added (next id = count + 1).
    count: usize,
}

impl BtfTypeTable {
    /// Create an empty type table.
    pub const fn new() -> Self {
        Self {
            types: [BtfType::empty(); MAX_TYPES],
            count: 0,
        }
    }

    /// Add a type and return its assigned id (1-based).
    pub fn add(&mut self, mut ty: BtfType) -> Result<u32> {
        if self.count >= MAX_TYPES - 1 {
            return Err(Error::OutOfMemory);
        }
        let id = (self.count + 1) as u32;
        ty.id = id;
        ty.active = true;
        self.types[id as usize] = ty;
        self.count += 1;
        Ok(id)
    }

    /// Look up a type by id.
    pub fn get(&self, id: u32) -> Result<&BtfType> {
        let idx = id as usize;
        if idx == 0 || idx > self.count {
            return Err(Error::NotFound);
        }
        if !self.types[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.types[idx])
    }

    /// Look up a type mutably by id.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut BtfType> {
        let idx = id as usize;
        if idx == 0 || idx > self.count {
            return Err(Error::NotFound);
        }
        if !self.types[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.types[idx])
    }

    /// Number of types.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ── BtfResolver ───────────────────────────────────────────────────

/// Resolves modifier chains to the underlying base type.
///
/// For a chain like `const -> volatile -> typedef -> int`, the
/// resolver follows `ref_type` links until it reaches a
/// non-modifier kind.
pub struct BtfResolver;

impl BtfResolver {
    /// Resolve a type id through modifier chains.
    ///
    /// Returns the id of the base (non-modifier) type.
    pub fn resolve(table: &BtfTypeTable, mut id: u32) -> Result<u32> {
        let mut depth = 0u32;
        loop {
            if depth >= MAX_RESOLVE_DEPTH as u32 {
                return Err(Error::InvalidArgument);
            }
            let ty = table.get(id)?;
            if !ty.kind.is_modifier() {
                return Ok(id);
            }
            if ty.ref_type == 0 {
                // Modifier pointing to void — return void.
                return Ok(0);
            }
            id = ty.ref_type;
            depth += 1;
        }
    }

    /// Get the fully resolved type, returning the BtfType reference.
    pub fn resolve_type(table: &BtfTypeTable, id: u32) -> Result<&BtfType> {
        let resolved_id = Self::resolve(table, id)?;
        if resolved_id == 0 {
            return Err(Error::NotFound);
        }
        table.get(resolved_id)
    }
}

// ── BtfDedup ──────────────────────────────────────────────────────

/// BTF deduplication engine.
///
/// Merges structurally equivalent types by computing a hash-like
/// fingerprint for each type and mapping duplicate ids to a
/// canonical representative.
pub struct BtfDedup {
    /// Mapping from type id to canonical id.
    /// `remap[i]` is the canonical id for type `i`.
    remap: [u32; MAX_TYPES],
    /// Number of unique types after dedup.
    unique_count: usize,
}

impl BtfDedup {
    /// Create a new dedup engine.
    pub const fn new() -> Self {
        Self {
            remap: [0u32; MAX_TYPES],
            unique_count: 0,
        }
    }

    /// Run deduplication over the type table.
    ///
    /// Simple structural dedup: two types are considered equal if
    /// they have the same kind, name_off, ref_type, and
    /// kind-specific scalar fields. Full deep structural dedup is
    /// left for a future optimisation.
    pub fn run(&mut self, table: &BtfTypeTable) -> usize {
        let count = table.count();
        self.unique_count = 0;

        // Identity mapping first.
        for i in 0..MAX_TYPES {
            self.remap[i] = i as u32;
        }

        // Compare each type against all earlier types.
        for i in 1..=count {
            let id_i = i as u32;
            let mut found_dup = false;

            for j in 1..i {
                let id_j = j as u32;
                if self.types_equal(table, id_i, id_j) {
                    self.remap[i] = self.remap[j];
                    found_dup = true;
                    break;
                }
            }
            if !found_dup {
                self.unique_count += 1;
            }
        }
        self.unique_count
    }

    /// Get the canonical id for a type.
    pub fn canonical(&self, id: u32) -> u32 {
        let idx = id as usize;
        if idx >= MAX_TYPES {
            return id;
        }
        self.remap[idx]
    }

    /// Number of unique types after dedup.
    pub const fn unique_count(&self) -> usize {
        self.unique_count
    }

    /// Check if two types are structurally equal (shallow).
    fn types_equal(&self, table: &BtfTypeTable, a: u32, b: u32) -> bool {
        let (Ok(ta), Ok(tb)) = (table.get(a), table.get(b)) else {
            return false;
        };
        if ta.kind != tb.kind || ta.name_off != tb.name_off {
            return false;
        }
        if ta.ref_type != tb.ref_type {
            return false;
        }
        // Compare kind-specific scalar fields.
        match (&ta.data, &tb.data) {
            (BtfKindData::None, BtfKindData::None) => true,
            (
                BtfKindData::Int {
                    size: sa,
                    encoding: ea,
                    bit_offset: boa,
                    bits: ba,
                },
                BtfKindData::Int {
                    size: sb,
                    encoding: eb,
                    bit_offset: bob,
                    bits: bb,
                },
            ) => sa == sb && ea.as_raw() == eb.as_raw() && boa == bob && ba == bb,
            (BtfKindData::Array(aa), BtfKindData::Array(ab)) => {
                aa.elem_type == ab.elem_type
                    && aa.index_type == ab.index_type
                    && aa.nelems == ab.nelems
            }
            (BtfKindData::Float { size: sa }, BtfKindData::Float { size: sb }) => sa == sb,
            _ => false,
        }
    }
}

// ── Convenience builders ──────────────────────────────────────────

/// Build a BTF integer type.
pub fn btf_int(name_off: u32, size: u32, encoding: BtfIntEncoding, bits: u8) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Int,
        name_off,
        ref_type: 0,
        data: BtfKindData::Int {
            size,
            encoding,
            bit_offset: 0,
            bits,
        },
        active: false,
    }
}

/// Build a BTF pointer type.
pub fn btf_ptr(target: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Ptr,
        name_off: 0,
        ref_type: target,
        data: BtfKindData::None,
        active: false,
    }
}

/// Build a BTF array type.
pub fn btf_array(name_off: u32, elem_type: u32, index_type: u32, nelems: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Array,
        name_off,
        ref_type: 0,
        data: BtfKindData::Array(BtfArrayInfo {
            elem_type,
            index_type,
            nelems,
        }),
        active: false,
    }
}

/// Build a BTF typedef type.
pub fn btf_typedef(name_off: u32, target: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Typedef,
        name_off,
        ref_type: target,
        data: BtfKindData::None,
        active: false,
    }
}

/// Build a BTF const-qualified type.
pub fn btf_const(target: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Const,
        name_off: 0,
        ref_type: target,
        data: BtfKindData::None,
        active: false,
    }
}

/// Build a BTF volatile-qualified type.
pub fn btf_volatile(target: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Volatile,
        name_off: 0,
        ref_type: target,
        data: BtfKindData::None,
        active: false,
    }
}

/// Build a BTF func type.
pub fn btf_func(name_off: u32, proto_type: u32, linkage: u8) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Func,
        name_off,
        ref_type: proto_type,
        data: BtfKindData::Func { linkage },
        active: false,
    }
}

/// Build a BTF float type.
pub fn btf_float(name_off: u32, size: u32) -> BtfType {
    BtfType {
        id: 0,
        kind: BtfKind::Float,
        name_off,
        ref_type: 0,
        data: BtfKindData::Float { size },
        active: false,
    }
}

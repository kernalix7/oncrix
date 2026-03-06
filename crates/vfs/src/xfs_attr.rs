// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS extended attribute (xattr) operations.
//!
//! XFS supports extended attributes in the inode's attribute fork. Small
//! attribute sets fit in a shortform layout; larger sets use a B+tree.
//!
//! # Namespaces
//!
//! XFS attributes are stored with a namespace flag encoded in the name header:
//!
//! | Namespace | Flag |
//! |-----------|------|
//! | user      | 0x00 |
//! | trusted   | 0x40 |
//! | secure    | 0x80 |
//! | system    | 0xC0 |
//!
//! # Reference
//!
//! - Linux `fs/xfs/libxfs/xfs_attr.c`, `xfs_attr_sf.c`, `xfs_attr_leaf.c`
//! - XFS Filesystem Structure v5 (xfs-docs)

use oncrix_lib::{Error, Result};

/// Maximum xattr name length.
pub const XFS_ATTR_NAME_MAX: usize = 255;
/// Maximum xattr value length (stored in leaf; larger values go to remote blocks).
pub const XFS_ATTR_VALUE_MAX: usize = 65536;
/// Maximum number of xattrs in the shortform table.
pub const SF_ATTR_MAX: usize = 64;

/// XFS attribute namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfsAttrNs {
    User,
    Trusted,
    Secure,
    System,
}

impl XfsAttrNs {
    /// Encode the namespace as the on-disk flags byte.
    pub fn to_flags(self) -> u8 {
        match self {
            XfsAttrNs::User => 0x00,
            XfsAttrNs::Trusted => 0x40,
            XfsAttrNs::Secure => 0x80,
            XfsAttrNs::System => 0xC0,
        }
    }

    /// Decode namespace from flags byte. Returns `InvalidArgument` for unknown.
    pub fn from_flags(flags: u8) -> Result<Self> {
        match flags & 0xC0 {
            0x00 => Ok(XfsAttrNs::User),
            0x40 => Ok(XfsAttrNs::Trusted),
            0x80 => Ok(XfsAttrNs::Secure),
            0xC0 => Ok(XfsAttrNs::System),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// An xattr name (fixed-size inline buffer).
#[derive(Debug, Clone, Copy)]
pub struct XfsAttrName {
    buf: [u8; XFS_ATTR_NAME_MAX],
    len: u8,
}

impl XfsAttrName {
    /// Create from a byte slice. Returns `InvalidArgument` if empty or too long.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > XFS_ATTR_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; XFS_ATTR_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            buf,
            len: name.len() as u8,
        })
    }

    /// Return name bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Name length in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// An xattr value stored inline (for values up to `XFS_ATTR_VALUE_MAX`).
///
/// For values that exceed inline storage, this holds a logical reference only.
/// Full I/O is handled by the block layer.
#[derive(Clone)]
pub struct XfsAttrValue {
    /// Inline data (first `inline_len` bytes are valid).
    data: [u8; 256],
    /// Byte length of the inline portion.
    inline_len: usize,
    /// Total value length (may exceed `data` capacity).
    total_len: usize,
    /// True if the value is stored in remote blocks.
    is_remote: bool,
}

impl XfsAttrValue {
    /// Create an inline value (must be ≤ 256 bytes for inline storage).
    pub fn inline(value: &[u8]) -> Result<Self> {
        if value.len() > XFS_ATTR_VALUE_MAX {
            return Err(Error::InvalidArgument);
        }
        let inline_len = value.len().min(256);
        let mut data = [0u8; 256];
        data[..inline_len].copy_from_slice(&value[..inline_len]);
        Ok(Self {
            data,
            inline_len,
            total_len: value.len(),
            is_remote: value.len() > 256,
        })
    }

    /// Total value length in bytes.
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// True if stored in remote blocks.
    pub fn is_remote(&self) -> bool {
        self.is_remote
    }

    /// Inline data (may be partial for large values).
    pub fn inline_data(&self) -> &[u8] {
        &self.data[..self.inline_len]
    }

    /// True if value has zero length.
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

/// A single extended attribute entry.
pub struct XfsAttr {
    /// Attribute namespace.
    pub ns: XfsAttrNs,
    /// Attribute name.
    pub name: XfsAttrName,
    /// Attribute value.
    pub value: XfsAttrValue,
}

impl XfsAttr {
    /// Create a new attribute.
    pub fn new(ns: XfsAttrNs, name: &[u8], value: &[u8]) -> Result<Self> {
        Ok(Self {
            ns,
            name: XfsAttrName::new(name)?,
            value: XfsAttrValue::inline(value)?,
        })
    }

    /// True if name and namespace match.
    pub fn matches(&self, ns: XfsAttrNs, name: &[u8]) -> bool {
        self.ns == ns && self.name.as_bytes() == name
    }
}

/// Shortform attribute fork — stores all xattrs inline in the inode.
pub struct XfsAttrFork {
    attrs: [Option<XfsAttr>; SF_ATTR_MAX],
    count: usize,
}

impl XfsAttrFork {
    /// Create an empty attribute fork.
    pub const fn new() -> Self {
        Self {
            attrs: [const { None }; SF_ATTR_MAX],
            count: 0,
        }
    }

    /// Set (create or replace) an attribute `(ns, name) → value`.
    pub fn set(&mut self, ns: XfsAttrNs, name: &[u8], value: &[u8]) -> Result<()> {
        // Try to update existing.
        for i in 0..self.count {
            if let Some(ref mut a) = self.attrs[i] {
                if a.matches(ns, name) {
                    a.value = XfsAttrValue::inline(value)?;
                    return Ok(());
                }
            }
        }
        // Insert new.
        if self.count >= SF_ATTR_MAX {
            return Err(Error::OutOfMemory);
        }
        self.attrs[self.count] = Some(XfsAttr::new(ns, name, value)?);
        self.count += 1;
        Ok(())
    }

    /// Get the value of `(ns, name)`. Returns `NotFound` if absent.
    pub fn get(&self, ns: XfsAttrNs, name: &[u8]) -> Result<&XfsAttrValue> {
        self.attrs[..self.count]
            .iter()
            .filter_map(|a| a.as_ref())
            .find(|a| a.matches(ns, name))
            .map(|a| &a.value)
            .ok_or(Error::NotFound)
    }

    /// Remove attribute `(ns, name)`. Returns `NotFound` if absent.
    pub fn remove(&mut self, ns: XfsAttrNs, name: &[u8]) -> Result<()> {
        let pos = self.attrs[..self.count]
            .iter()
            .position(|a| a.as_ref().map(|a| a.matches(ns, name)).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.attrs[idx] = self.attrs[self.count].take();
                Ok(())
            }
        }
    }

    /// List all attribute names in namespace `ns`.
    pub fn list_ns<'a>(&'a self, ns: XfsAttrNs) -> impl Iterator<Item = &'a XfsAttrName> {
        self.attrs[..self.count]
            .iter()
            .filter_map(|a| a.as_ref())
            .filter(move |a| a.ns == ns)
            .map(|a| &a.name)
    }

    /// Total attribute count.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for XfsAttrFork {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the POSIX xattr name string into (namespace, local name).
///
/// POSIX xattr names are prefixed: `"user."`, `"trusted."`, `"security."`,
/// `"system."`. This function strips the prefix and maps it to [`XfsAttrNs`].
pub fn parse_xattr_name(full_name: &[u8]) -> Result<(XfsAttrNs, &[u8])> {
    const PREFIXES: &[(&[u8], XfsAttrNs)] = &[
        (b"user.", XfsAttrNs::User),
        (b"trusted.", XfsAttrNs::Trusted),
        (b"security.", XfsAttrNs::Secure),
        (b"system.", XfsAttrNs::System),
    ];
    for (prefix, ns) in PREFIXES {
        if full_name.starts_with(prefix) {
            let local = &full_name[prefix.len()..];
            if local.is_empty() {
                return Err(Error::InvalidArgument);
            }
            return Ok((*ns, local));
        }
    }
    Err(Error::InvalidArgument)
}

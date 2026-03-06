// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sysfs binary attributes.
//!
//! Implements sysfs binary attribute support:
//! - [`BinAttribute`] — descriptor for a sysfs binary attribute file
//! - [`sysfs_create_bin_file`] / [`sysfs_remove_bin_file`] — lifecycle
//! - Read/write callbacks dispatched through the attribute table
//! - mmap support stub for firmware upload via binary attributes
//! - Firmware upload pattern via `bin_attr` (e.g., `/sys/class/firmware/`)
//!
//! # Design
//!
//! Binary attributes in sysfs are kernel objects that expose arbitrary
//! binary data to user-space. Unlike regular sysfs text attributes they
//! do not enforce any text format; the semantics are entirely defined by
//! the `read` and `write` callbacks.
//!
//! A common use-case is firmware upload: user-space writes raw firmware
//! bytes to `/sys/class/firmware/<name>/data`, and the kernel passes them
//! directly to a device driver.
//!
//! # References
//! - Linux `include/linux/sysfs.h`, `fs/sysfs/bin.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum name length for a binary attribute.
pub const SYSFS_BIN_NAME_MAX: usize = 64;

/// Maximum binary attribute data size (1 MiB).
pub const SYSFS_BIN_MAX_SIZE: usize = 1024 * 1024;

/// Maximum number of registered binary attributes.
const MAX_BIN_ATTRS: usize = 64;

// ---------------------------------------------------------------------------
// BinAttribute
// ---------------------------------------------------------------------------

/// Descriptor for a sysfs binary attribute file.
#[derive(Clone)]
pub struct BinAttribute {
    /// Attribute name (used as the filename under the kobject directory).
    pub name: [u8; SYSFS_BIN_NAME_MAX],
    /// Length of `name`.
    pub name_len: usize,
    /// File mode (permission bits, e.g. 0o640).
    pub mode: u16,
    /// Maximum size hint. 0 = no limit (use `SYSFS_BIN_MAX_SIZE`).
    pub size: usize,
    /// Whether this attribute supports mmap.
    pub mmap_supported: bool,
}

impl BinAttribute {
    /// Create a new binary attribute descriptor.
    ///
    /// Returns `Err(InvalidArgument)` if the name is too long.
    pub fn new(name: &[u8], mode: u16, size: usize) -> Result<Self> {
        if name.len() > SYSFS_BIN_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self {
            name: [0u8; SYSFS_BIN_NAME_MAX],
            name_len: name.len(),
            mode,
            size,
            mmap_supported: false,
        };
        attr.name[..name.len()].copy_from_slice(name);
        Ok(attr)
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// BinAttrData — per-attribute in-kernel data buffer
// ---------------------------------------------------------------------------

/// Registered binary attribute with its in-memory data buffer.
pub struct BinAttrData {
    /// Attribute descriptor.
    pub attr: BinAttribute,
    /// Data buffer.
    pub data: Vec<u8>,
    /// Kobject owner identifier (simplified: an integer key).
    pub kobject_id: u64,
}

impl BinAttrData {
    /// Create a new data entry for the given kobject.
    pub fn new(attr: BinAttribute, kobject_id: u64) -> Self {
        Self {
            attr,
            data: Vec::new(),
            kobject_id,
        }
    }
}

// ---------------------------------------------------------------------------
// SysfsBinRegistry
// ---------------------------------------------------------------------------

/// Global registry of sysfs binary attributes.
pub struct SysfsBinRegistry {
    attrs: [Option<BinAttrData>; MAX_BIN_ATTRS],
    count: usize,
}

impl SysfsBinRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            attrs: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn find(&self, kobject_id: u64, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.attrs[..self.count].iter().enumerate() {
            if let Some(a) = slot {
                if a.kobject_id == kobject_id && a.attr.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for SysfsBinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sysfs_create_bin_file
// ---------------------------------------------------------------------------

/// Register a binary attribute for a kobject.
///
/// Returns `Err(AlreadyExists)` if the attribute already exists.
/// Returns `Err(OutOfMemory)` if the registry is full.
pub fn sysfs_create_bin_file(
    registry: &mut SysfsBinRegistry,
    kobject_id: u64,
    attr: BinAttribute,
) -> Result<()> {
    if registry.find(kobject_id, attr.name_bytes()).is_some() {
        return Err(Error::AlreadyExists);
    }
    if registry.count >= MAX_BIN_ATTRS {
        return Err(Error::OutOfMemory);
    }
    registry.attrs[registry.count] = Some(BinAttrData::new(attr, kobject_id));
    registry.count += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// sysfs_remove_bin_file
// ---------------------------------------------------------------------------

/// Remove a binary attribute from the registry.
///
/// Returns `Err(NotFound)` if the attribute does not exist.
pub fn sysfs_remove_bin_file(
    registry: &mut SysfsBinRegistry,
    kobject_id: u64,
    name: &[u8],
) -> Result<()> {
    let idx = registry.find(kobject_id, name).ok_or(Error::NotFound)?;
    registry.attrs[idx] = None;
    if idx < registry.count - 1 {
        registry.attrs.swap(idx, registry.count - 1);
    }
    registry.count -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// bin_attr_read
// ---------------------------------------------------------------------------

/// Read from a binary attribute.
///
/// Copies bytes `[offset, offset+count)` from the attribute's data buffer
/// into `buf`. Returns the number of bytes copied.
pub fn bin_attr_read(
    registry: &SysfsBinRegistry,
    kobject_id: u64,
    name: &[u8],
    buf: &mut [u8],
    offset: usize,
) -> Result<usize> {
    let idx = registry.find(kobject_id, name).ok_or(Error::NotFound)?;
    let attr = registry.attrs[idx].as_ref().ok_or(Error::NotFound)?;

    // Check read permission.
    if attr.attr.mode & 0o400 == 0 {
        return Err(Error::PermissionDenied);
    }

    if offset >= attr.data.len() {
        return Ok(0);
    }
    let end = (offset + buf.len()).min(attr.data.len());
    let len = end - offset;
    buf[..len].copy_from_slice(&attr.data[offset..end]);
    Ok(len)
}

// ---------------------------------------------------------------------------
// bin_attr_write
// ---------------------------------------------------------------------------

/// Write to a binary attribute.
///
/// Appends or overwrites `data` starting at `offset`. Enforces the `size`
/// limit from the attribute descriptor.
pub fn bin_attr_write(
    registry: &mut SysfsBinRegistry,
    kobject_id: u64,
    name: &[u8],
    data: &[u8],
    offset: usize,
) -> Result<usize> {
    let idx = registry.find(kobject_id, name).ok_or(Error::NotFound)?;
    let attr = registry.attrs[idx].as_mut().ok_or(Error::NotFound)?;

    // Check write permission.
    if attr.attr.mode & 0o200 == 0 {
        return Err(Error::PermissionDenied);
    }

    let limit = if attr.attr.size == 0 {
        SYSFS_BIN_MAX_SIZE
    } else {
        attr.attr.size
    };
    let end = offset + data.len();
    if end > limit {
        return Err(Error::InvalidArgument);
    }

    if end > attr.data.len() {
        attr.data.resize(end, 0);
    }
    attr.data[offset..end].copy_from_slice(data);
    Ok(data.len())
}

// ---------------------------------------------------------------------------
// mmap stub
// ---------------------------------------------------------------------------

/// mmap a sysfs binary attribute (stub).
///
/// Full implementation requires integration with the mm subsystem to map
/// the attribute data into user address space. This stub validates inputs
/// and returns `Err(NotImplemented)`.
pub fn bin_attr_mmap(
    registry: &SysfsBinRegistry,
    kobject_id: u64,
    name: &[u8],
    _len: usize,
    _offset: u64,
) -> Result<u64> {
    let idx = registry.find(kobject_id, name).ok_or(Error::NotFound)?;
    let attr = registry.attrs[idx].as_ref().ok_or(Error::NotFound)?;
    if !attr.attr.mmap_supported {
        return Err(Error::NotImplemented);
    }
    Err(Error::NotImplemented)
}

// ---------------------------------------------------------------------------
// Firmware upload pattern
// ---------------------------------------------------------------------------

/// State machine for firmware upload via binary attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareUploadState {
    /// Waiting for user-space to write firmware.
    Idle,
    /// User-space is writing firmware data.
    Writing,
    /// Firmware has been written; ready for programming.
    Ready,
    /// Firmware programming in progress.
    Programming,
    /// Programming complete.
    Done,
    /// Programming failed.
    Failed,
}

/// A firmware upload context attached to a device.
pub struct FirmwareUpload {
    /// Device name.
    pub device_name: [u8; 64],
    pub device_name_len: usize,
    /// Current upload state.
    pub state: FirmwareUploadState,
    /// Firmware data accumulated during writes.
    pub firmware_data: Vec<u8>,
    /// Expected firmware size (0 = unknown).
    pub expected_size: usize,
}

impl FirmwareUpload {
    /// Create a new firmware upload context.
    pub fn new(device_name: &[u8]) -> Result<Self> {
        if device_name.len() > 64 {
            return Err(Error::InvalidArgument);
        }
        let mut ctx = Self {
            device_name: [0u8; 64],
            device_name_len: device_name.len(),
            state: FirmwareUploadState::Idle,
            firmware_data: Vec::new(),
            expected_size: 0,
        };
        ctx.device_name[..device_name.len()].copy_from_slice(device_name);
        Ok(ctx)
    }

    /// Append a firmware chunk (called from bin_attr write callback).
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<()> {
        if self.state != FirmwareUploadState::Idle && self.state != FirmwareUploadState::Writing {
            return Err(Error::Busy);
        }
        self.state = FirmwareUploadState::Writing;
        self.firmware_data.extend_from_slice(data);
        Ok(())
    }

    /// Signal that the firmware write is complete.
    pub fn finalize(&mut self) -> Result<()> {
        if self.state != FirmwareUploadState::Writing {
            return Err(Error::InvalidArgument);
        }
        if self.expected_size > 0 && self.firmware_data.len() != self.expected_size {
            return Err(Error::InvalidArgument);
        }
        self.state = FirmwareUploadState::Ready;
        Ok(())
    }

    /// Simulate programming the device (stub).
    pub fn program(&mut self) -> Result<()> {
        if self.state != FirmwareUploadState::Ready {
            return Err(Error::InvalidArgument);
        }
        self.state = FirmwareUploadState::Programming;
        // A real implementation would DMA the firmware to the device.
        self.state = FirmwareUploadState::Done;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_write_read_remove() {
        let mut reg = SysfsBinRegistry::new();
        let attr = BinAttribute::new(b"data", 0o640, 1024).unwrap();
        sysfs_create_bin_file(&mut reg, 1, attr).unwrap();

        bin_attr_write(&mut reg, 1, b"data", b"firmware_bytes", 0).unwrap();
        let mut buf = [0u8; 14];
        let n = bin_attr_read(&mut reg, 1, b"data", &mut buf, 0).unwrap();
        assert_eq!(n, 14);
        assert_eq!(&buf, b"firmware_bytes");

        sysfs_remove_bin_file(&mut reg, 1, b"data").unwrap();
        assert!(bin_attr_read(&mut reg, 1, b"data", &mut buf, 0).is_err());
    }

    #[test]
    fn test_firmware_upload() {
        let mut fw = FirmwareUpload::new(b"eth0").unwrap();
        fw.write_chunk(b"fwdata").unwrap();
        fw.finalize().unwrap();
        assert_eq!(fw.state, FirmwareUploadState::Ready);
        fw.program().unwrap();
        assert_eq!(fw.state, FirmwareUploadState::Done);
    }
}

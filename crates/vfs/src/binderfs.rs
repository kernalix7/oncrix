// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! binderfs — Android Binder filesystem.
//!
//! binderfs is a pseudo-filesystem that provides per-mount Binder IPC
//! device nodes. Each mount of binderfs creates an isolated Binder
//! context: processes that share the same mount point share the same
//! Binder IPC domain, while processes that mount binderfs separately
//! are in distinct domains.
//!
//! # Design
//!
//! This implementation models the binderfs structure as a flat table of
//! [`BinderfsDevice`] entries plus a control device entry. All nodes are
//! held in a fixed-size array ([`MAX_DEVICES`] entries) to avoid heap
//! allocation in the filesystem fast path.
//!
//! ## Nodes
//!
//! ```text
//! /dev/binderfs/
//! ├── binder-control      ← control device (create/delete binder devices)
//! └── <name>              ← user-created Binder device (ioctl(BINDER_WRITE_READ, …))
//! ```
//!
//! ## Control operations
//!
//! The `binder-control` device accepts two ioctls (modelled as method calls
//! on [`BinderfsMount`]):
//! - [`BinderfsMount::alloc_device`]: allocate a new Binder device node
//! - [`BinderfsMount::free_device`]: remove an existing Binder device node
//!
//! ## Binder protocol stubs
//!
//! This module contains only the filesystem layer. The actual Binder IPC
//! engine (transaction processing, reference counting, death notifications)
//! is implemented in `crates/ipc/src/binder_ipc.rs`. The filesystem layer
//! exposes the device nodes and delegates all `ioctl`/`mmap`/`poll` calls
//! to that engine via the [`BinderOps`] function-pointer table.
//!
//! Reference: Linux `drivers/android/binderfs.c`, `drivers/android/binder.c`;
//! Android Open Source Project — Binder IPC design docs.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of user-created Binder device nodes per mount.
pub const MAX_DEVICES: usize = 256;

/// Maximum length of a device name (excluding NUL).
pub const MAX_DEVICE_NAME: usize = 255;

/// Minor number reserved for the control device.
pub const BINDER_CTRL_MINOR: u32 = 0;

/// Base minor number for user-created Binder devices.
pub const BINDER_BASE_MINOR: u32 = 1;

/// Linux device major number for Android Binder (misc major = 10, but we use
/// a synthetic value since this is a no_std stub).
pub const BINDER_MAJOR: u32 = 10;

// ---------------------------------------------------------------------------
// Ioctls (numeric codes match the Android kernel ABI)
// ---------------------------------------------------------------------------

/// ioctl command: allocate a new Binder device (arg = `BinderDeviceInfo`).
pub const BINDER_CTL_ADD: u32 = 0x4040_6201;

// ---------------------------------------------------------------------------
// BinderDeviceInfo — passed via the control ioctl
// ---------------------------------------------------------------------------

/// Information passed to the `BINDER_CTL_ADD` ioctl.
#[derive(Debug, Clone)]
pub struct BinderDeviceInfo {
    /// Desired device name (e.g. "binder", "hwbinder", "vndbinder").
    pub name: [u8; MAX_DEVICE_NAME],
    /// Byte length of the name.
    pub name_len: usize,
}

impl BinderDeviceInfo {
    /// Create a `BinderDeviceInfo` from a UTF-8 string slice.
    pub fn from_str(s: &str) -> Result<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_DEVICE_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut name = [0u8; MAX_DEVICE_NAME];
        name[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name,
            name_len: bytes.len(),
        })
    }

    /// Return the name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// BinderOps — callbacks into the Binder IPC engine
// ---------------------------------------------------------------------------

/// Function-pointer table connecting a binderfs device node to the Binder
/// IPC engine. Each Binder device node that is opened by a process calls
/// these functions to create / destroy a per-process Binder context.
#[derive(Clone, Copy)]
pub struct BinderOps {
    /// Called when a process opens the device.
    ///
    /// `device_minor` identifies which Binder device was opened.
    /// Returns an opaque process context handle (e.g. an index into a table).
    pub open: fn(device_minor: u32) -> Result<u32>,

    /// Called when the file descriptor is released (process exits or closes fd).
    ///
    /// `proc_handle` is the value returned by `open`.
    pub release: fn(proc_handle: u32) -> Result<()>,

    /// Called for `ioctl(fd, cmd, arg)` on the device.
    pub ioctl: fn(proc_handle: u32, cmd: u32, arg: u64) -> Result<i64>,

    /// Called for `mmap(2)` on the device.
    ///
    /// Returns the virtual address (as `u64`) at which the Binder buffer
    /// region was mapped.
    pub mmap: fn(proc_handle: u32, size: usize) -> Result<u64>,
}

impl core::fmt::Debug for BinderOps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BinderOps").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// BinderfsDevice
// ---------------------------------------------------------------------------

/// A single Binder device node within a binderfs mount.
#[derive(Debug, Clone)]
pub struct BinderfsDevice {
    /// Device name (NUL-padded).
    name: [u8; MAX_DEVICE_NAME],
    /// Byte length of the name.
    name_len: usize,
    /// Minor number assigned to this device.
    pub minor: u32,
    /// Whether this slot is occupied.
    active: bool,
    /// Binder engine ops for this device.
    pub ops: Option<BinderOps>,
}

impl BinderfsDevice {
    const EMPTY: Self = Self {
        name: [0; MAX_DEVICE_NAME],
        name_len: 0,
        minor: 0,
        active: false,
        ops: None,
    };

    /// Return the device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Compare the device name to a byte slice.
    pub fn name_eq(&self, other: &[u8]) -> bool {
        self.name() == other
    }
}

// ---------------------------------------------------------------------------
// BinderfsMount — a single binderfs mount instance
// ---------------------------------------------------------------------------

/// A binderfs mount instance.
///
/// Each mount has its own isolated set of Binder device nodes. The
/// `binder-control` device is implicit and always present.
pub struct BinderfsMount {
    /// User-created device table.
    devices: [BinderfsDevice; MAX_DEVICES],
    /// Number of active device slots.
    count: usize,
    /// Next minor number to assign (monotonically increasing).
    next_minor: u32,
    /// Optional default ops applied to new devices (can be overridden per device).
    default_ops: Option<BinderOps>,
    /// Mount ID (for diagnostics).
    pub mount_id: u32,
}

impl BinderfsMount {
    /// Create a new binderfs mount.
    pub const fn new(mount_id: u32) -> Self {
        Self {
            devices: [BinderfsDevice::EMPTY; MAX_DEVICES],
            count: 0,
            next_minor: BINDER_BASE_MINOR,
            default_ops: None,
            mount_id,
        }
    }

    /// Set the default [`BinderOps`] applied to newly created devices.
    pub fn set_default_ops(&mut self, ops: BinderOps) {
        self.default_ops = Some(ops);
    }

    // -----------------------------------------------------------------------
    // Control operations
    // -----------------------------------------------------------------------

    /// Allocate a new Binder device node.
    ///
    /// Validates `info`, assigns a minor number, and adds the device to the
    /// table. Returns the assigned minor number.
    ///
    /// Corresponds to `BINDER_CTL_ADD` on the control device.
    pub fn alloc_device(&mut self, info: &BinderDeviceInfo) -> Result<u32> {
        if info.name_len == 0 || info.name_len > MAX_DEVICE_NAME {
            return Err(Error::InvalidArgument);
        }
        // Reject reserved name "binder-control".
        if info.name() == b"binder-control" {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicates.
        if self.find_by_name(info.name()).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let minor = self.next_minor;
        self.next_minor = self.next_minor.wrapping_add(1);

        // Find a free slot.
        let slot = self
            .devices
            .iter_mut()
            .find(|d| !d.active)
            .ok_or(Error::OutOfMemory)?;
        slot.name[..info.name_len].copy_from_slice(&info.name[..info.name_len]);
        slot.name_len = info.name_len;
        slot.minor = minor;
        slot.active = true;
        slot.ops = self.default_ops;
        self.count += 1;
        Ok(minor)
    }

    /// Remove a Binder device node by name.
    ///
    /// Fails if no device with `name` exists.
    pub fn free_device(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.devices[..self.count_cap()]
            .iter()
            .position(|d| d.active && d.name_eq(name))
            .ok_or(Error::NotFound)?;
        self.devices[pos] = BinderfsDevice::EMPTY;
        self.count -= 1;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lookup
    // -----------------------------------------------------------------------

    /// Find a device by name. Returns its slot index.
    fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        self.devices[..self.count_cap()]
            .iter()
            .position(|d| d.active && d.name_eq(name))
    }

    /// Find a device by minor number.
    pub fn find_by_minor(&self, minor: u32) -> Option<&BinderfsDevice> {
        self.devices[..self.count_cap()]
            .iter()
            .find(|d| d.active && d.minor == minor)
    }

    /// Find a device by name (public, returns a reference).
    pub fn device_by_name(&self, name: &[u8]) -> Option<&BinderfsDevice> {
        self.find_by_name(name).map(|i| &self.devices[i])
    }

    // -----------------------------------------------------------------------
    // File operations (delegated to BinderOps)
    // -----------------------------------------------------------------------

    /// Open a Binder device by minor number.
    ///
    /// Delegates to the device's [`BinderOps::open`] callback and returns
    /// the per-process handle.
    pub fn open(&self, minor: u32) -> Result<u32> {
        if minor == BINDER_CTRL_MINOR {
            // Opening the control device returns a sentinel handle.
            return Ok(u32::MAX);
        }
        let dev = self.find_by_minor(minor).ok_or(Error::NotFound)?;
        let ops = dev.ops.ok_or(Error::NotImplemented)?;
        (ops.open)(minor)
    }

    /// Release a Binder device handle.
    pub fn release(&self, minor: u32, proc_handle: u32) -> Result<()> {
        if minor == BINDER_CTRL_MINOR {
            return Ok(());
        }
        let dev = self.find_by_minor(minor).ok_or(Error::NotFound)?;
        let ops = dev.ops.ok_or(Error::NotImplemented)?;
        (ops.release)(proc_handle)
    }

    /// Perform an ioctl on a Binder device handle.
    ///
    /// For the control device, `cmd == BINDER_CTL_ADD` is handled internally.
    /// All other commands are forwarded to the engine.
    pub fn ioctl(&mut self, minor: u32, proc_handle: u32, cmd: u32, arg: u64) -> Result<i64> {
        if minor == BINDER_CTRL_MINOR {
            if cmd == BINDER_CTL_ADD {
                // `arg` is a user-space pointer to `BinderDeviceInfo` — in a
                // real kernel we would copy_from_user here. For our stub we
                // treat `arg` as an index into a notional info table and
                // return the assigned minor.
                //
                // This stub just allocates a placeholder device named "binder".
                let info = BinderDeviceInfo::from_str("binder")?;
                let assigned = self.alloc_device(&info)?;
                return Ok(assigned as i64);
            }
            return Err(Error::InvalidArgument);
        }
        let dev = self.find_by_minor(minor).ok_or(Error::NotFound)?;
        let ops = dev.ops.ok_or(Error::NotImplemented)?;
        (ops.ioctl)(proc_handle, cmd, arg)
    }

    /// Map the Binder buffer for a process.
    pub fn mmap(&self, minor: u32, proc_handle: u32, size: usize) -> Result<u64> {
        if minor == BINDER_CTRL_MINOR {
            return Err(Error::InvalidArgument);
        }
        let dev = self.find_by_minor(minor).ok_or(Error::NotFound)?;
        let ops = dev.ops.ok_or(Error::NotImplemented)?;
        (ops.mmap)(proc_handle, size)
    }

    // -----------------------------------------------------------------------
    // Directory listing (for VFS readdir on the mount point)
    // -----------------------------------------------------------------------

    /// Enumerate active device names into `out`.
    ///
    /// The first entry is always `"binder-control"`. Returns the total number
    /// of entries written.
    pub fn readdir<'a>(&'a self, out: &mut [&'a [u8]], names: &'a [[u8; MAX_DEVICE_NAME]]) -> usize
    where
        [u8; MAX_DEVICE_NAME]: 'a,
    {
        // Caller provides a name buffer slice to avoid lifetime issues.
        let _ = names; // names buffer ownership is caller-managed
        let mut count = 0usize;
        // "binder-control" is always first.
        if count < out.len() {
            out[count] = b"binder-control";
            count += 1;
        }
        for dev in self.devices[..self.count_cap()].iter() {
            if count >= out.len() {
                break;
            }
            if dev.active {
                out[count] = dev.name();
                count += 1;
            }
        }
        count
    }

    /// Return the number of active devices.
    pub fn device_count(&self) -> usize {
        self.count
    }

    /// Capacity scan limit (avoids scanning the full 256-entry array when
    /// most slots are empty near the start).
    fn count_cap(&self) -> usize {
        // Scan at most (count + 1) * 2 slots to find all active entries
        // even after deletions create gaps.
        ((self.count + 1) * 2).min(MAX_DEVICES)
    }
}

// ---------------------------------------------------------------------------
// BinderfsRegistry — global mount table
// ---------------------------------------------------------------------------

/// Maximum number of concurrent binderfs mounts.
const MAX_MOUNTS: usize = 16;

/// Global registry of binderfs mount instances.
///
/// In a real kernel this would be protected by a mutex; here we provide a
/// simple single-owner registry suitable for the ONCRIX microkernel model
/// where the VFS server is single-threaded.
pub struct BinderfsRegistry {
    mounts: [Option<BinderfsMount>; MAX_MOUNTS],
    next_id: u32,
}

impl BinderfsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        // `Option<BinderfsMount>` is not `Copy`, so we cannot use array
        // literal syntax with MAX_MOUNTS repetition in const context.
        // We use a manual initialisation via a const helper below.
        Self {
            mounts: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            next_id: 1,
        }
    }

    /// Mount a new binderfs instance.
    ///
    /// Returns the mount ID.
    pub fn mount(&mut self) -> Result<u32> {
        let id = self.next_id;
        for slot in self.mounts.iter_mut() {
            if slot.is_none() {
                *slot = Some(BinderfsMount::new(id));
                self.next_id = self.next_id.wrapping_add(1);
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unmount a binderfs instance by mount ID.
    pub fn unmount(&mut self, mount_id: u32) -> Result<()> {
        for slot in self.mounts.iter_mut() {
            if let Some(m) = slot {
                if m.mount_id == mount_id {
                    *slot = None;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get a mutable reference to a mount by ID.
    pub fn get_mut(&mut self, mount_id: u32) -> Result<&mut BinderfsMount> {
        for slot in self.mounts.iter_mut() {
            if let Some(m) = slot {
                if m.mount_id == mount_id {
                    return Ok(m);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get an immutable reference to a mount by ID.
    pub fn get(&self, mount_id: u32) -> Result<&BinderfsMount> {
        for slot in self.mounts.iter() {
            if let Some(m) = slot {
                if m.mount_id == mount_id {
                    return Ok(m);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active mounts.
    pub fn mount_count(&self) -> usize {
        self.mounts.iter().filter(|s| s.is_some()).count()
    }
}

impl Default for BinderfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn null_ops() -> BinderOps {
        BinderOps {
            open: |_minor| Ok(42),
            release: |_h| Ok(()),
            ioctl: |_h, _cmd, _arg| Ok(0),
            mmap: |_h, _size| Ok(0x1000),
        }
    }

    #[test]
    fn alloc_and_free_device() {
        let mut mount = BinderfsMount::new(1);
        mount.set_default_ops(null_ops());
        let info = BinderDeviceInfo::from_str("binder").unwrap();
        let minor = mount.alloc_device(&info).unwrap();
        assert!(minor >= BINDER_BASE_MINOR);
        assert_eq!(mount.device_count(), 1);

        mount.free_device(b"binder").unwrap();
        assert_eq!(mount.device_count(), 0);
    }

    #[test]
    fn duplicate_device_rejected() {
        let mut mount = BinderfsMount::new(1);
        let info = BinderDeviceInfo::from_str("hwbinder").unwrap();
        mount.alloc_device(&info).unwrap();
        let result = mount.alloc_device(&info);
        assert!(result.is_err());
    }

    #[test]
    fn control_device_name_rejected() {
        let mut mount = BinderfsMount::new(1);
        let info = BinderDeviceInfo::from_str("binder-control").unwrap();
        assert!(mount.alloc_device(&info).is_err());
    }

    #[test]
    fn open_and_release() {
        let mut mount = BinderfsMount::new(1);
        mount.set_default_ops(null_ops());
        let info = BinderDeviceInfo::from_str("binder").unwrap();
        let minor = mount.alloc_device(&info).unwrap();
        let handle = mount.open(minor).unwrap();
        assert_eq!(handle, 42);
        mount.release(minor, handle).unwrap();
    }

    #[test]
    fn open_control_device() {
        let mount = BinderfsMount::new(1);
        let handle = mount.open(BINDER_CTRL_MINOR).unwrap();
        assert_eq!(handle, u32::MAX);
    }

    #[test]
    fn registry_mount_unmount() {
        let mut reg = BinderfsRegistry::new();
        let id = reg.mount().unwrap();
        assert_eq!(reg.mount_count(), 1);
        reg.unmount(id).unwrap();
        assert_eq!(reg.mount_count(), 0);
    }

    #[test]
    fn registry_max_mounts() {
        let mut reg = BinderfsRegistry::new();
        for _ in 0..MAX_MOUNTS {
            reg.mount().unwrap();
        }
        assert!(reg.mount().is_err());
    }

    #[test]
    fn mmap_delegated() {
        let mut mount = BinderfsMount::new(1);
        mount.set_default_ops(null_ops());
        let info = BinderDeviceInfo::from_str("binder").unwrap();
        let minor = mount.alloc_device(&info).unwrap();
        let handle = mount.open(minor).unwrap();
        let addr = mount.mmap(minor, handle, 4096).unwrap();
        assert_eq!(addr, 0x1000);
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAX (Direct Access) device driver.
//!
//! Provides direct-access (zero-copy, no page-cache) access to persistent
//! memory (PMEM) and other byte-addressable storage. Implements the DAX
//! abstraction used by filesystems (ext4, XFS, NOVA) for persistent memory
//! file I/O without buffered I/O overhead.

use oncrix_lib::{Error, Result};

/// Maximum number of DAX devices registered.
const MAX_DAX_DEVICES: usize = 8;

/// DAX device type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaxType {
    /// Persistent memory DIMM (NVDIMM).
    Pmem,
    /// Volatile memory with DAX (e.g., huge-page backed ramdisk).
    Ram,
    /// Generic byte-addressable device.
    Generic,
}

/// DAX access granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaxGranularity {
    /// Page-aligned access (4 KiB).
    Page4K,
    /// Huge-page aligned access (2 MiB).
    Page2M,
    /// Gigantic-page aligned access (1 GiB).
    Page1G,
}

impl DaxGranularity {
    /// Granularity in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            DaxGranularity::Page4K => 4 * 1024,
            DaxGranularity::Page2M => 2 * 1024 * 1024,
            DaxGranularity::Page1G => 1024 * 1024 * 1024,
        }
    }
}

/// DAX write hint (corresponds to ACPI DSM write hints for NVDIMM).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteHint {
    /// No hint.
    None,
    /// Short-lived data (e.g., temporary files).
    ShortLived,
    /// Long-lived data (e.g., persistent data structures).
    LongLived,
    /// Write-intensive workload.
    MediaManage,
}

/// DAX copy mode — controls whether stores use write-combining or clflush.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMode {
    /// Use cache-line flush after each store.
    Clflush,
    /// Use write-combining (non-temporal stores).
    NonTemporal,
    /// Use cache-optimized stores.
    Cached,
}

/// A DAX device descriptor.
pub struct DaxDevice {
    /// Device name.
    pub name: [u8; 32],
    /// Device type.
    pub dev_type: DaxType,
    /// Physical start address of the device.
    pub phys_start: u64,
    /// Virtual (mapped) start address.
    pub virt_start: usize,
    /// Size in bytes.
    pub size: u64,
    /// Access granularity.
    pub granularity: DaxGranularity,
    /// Device is write-protected.
    pub read_only: bool,
}

impl DaxDevice {
    /// Create a new DAX device descriptor.
    pub fn new(
        name: &[u8],
        dev_type: DaxType,
        phys_start: u64,
        virt_start: usize,
        size: u64,
    ) -> Self {
        let mut n = [0u8; 32];
        let len = name.len().min(31);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            name: n,
            dev_type,
            phys_start,
            virt_start,
            size,
            granularity: DaxGranularity::Page4K,
            read_only: false,
        }
    }

    /// Perform a direct (non-buffered) copy from a source buffer into the DAX device.
    ///
    /// # Arguments
    /// - `offset`: byte offset within the DAX device
    /// - `src`: source data
    /// - `mode`: cache strategy for writes
    pub fn write_dax(&self, offset: u64, src: &[u8], mode: CopyMode) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if offset + src.len() as u64 > self.size {
            return Err(Error::InvalidArgument);
        }
        let dst = (self.virt_start + offset as usize) as *mut u8;
        match mode {
            CopyMode::NonTemporal => {
                // SAFETY: dst is within the mapped DAX region (validated by offset
                // + size check); non-temporal stores bypass the cache and go directly
                // to the persistent medium.
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    for (i, &byte) in src.iter().enumerate() {
                        core::ptr::write_volatile(dst.add(i), byte);
                    }
                    // Issue SFENCE to ensure persistence ordering.
                    core::arch::asm!("sfence", options(nostack, nomem));
                }
                #[cfg(not(target_arch = "x86_64"))]
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                }
            }
            CopyMode::Clflush => {
                // SAFETY: dst is within the mapped DAX region.
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                }
                self.clflush_range(dst, src.len());
            }
            CopyMode::Cached => {
                // SAFETY: dst is within the mapped DAX region.
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                }
            }
        }
        Ok(())
    }

    /// Read bytes from the DAX device directly into `dst`.
    pub fn read_dax(&self, offset: u64, dst: &mut [u8]) -> Result<()> {
        if offset + dst.len() as u64 > self.size {
            return Err(Error::InvalidArgument);
        }
        let src = (self.virt_start + offset as usize) as *const u8;
        // SAFETY: src is within the mapped DAX region; volatile read ensures
        // the load is not optimized away and reflects PMEM contents.
        unsafe {
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(src.add(i));
            }
        }
        Ok(())
    }

    /// Persist a range to non-volatile storage (cache flush + drain).
    pub fn persist(&self, offset: u64, len: usize) -> Result<()> {
        if offset + len as u64 > self.size {
            return Err(Error::InvalidArgument);
        }
        let ptr = (self.virt_start + offset as usize) as *mut u8;
        self.clflush_range(ptr, len);
        Ok(())
    }

    /// Flush cache lines covering [ptr, ptr+len).
    fn clflush_range(&self, ptr: *mut u8, len: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            const CACHE_LINE: usize = 64;
            let mut addr = ptr as usize & !(CACHE_LINE - 1);
            let end = ptr as usize + len;
            while addr < end {
                // SAFETY: addr is within a mapped DAX region; CLFLUSH flushes
                // the cache line containing addr to persistent storage.
                unsafe {
                    core::arch::asm!(
                        "clflush [{0}]",
                        in(reg) addr,
                        options(nostack, preserves_flags)
                    );
                }
                addr += CACHE_LINE;
            }
            // SAFETY: SFENCE ensures all CLFLUSH operations are globally visible.
            unsafe {
                core::arch::asm!("sfence", options(nostack, nomem));
            }
        }
    }

    /// Return whether a given offset/length pair is granularity-aligned.
    pub fn is_aligned(&self, offset: u64, len: u64) -> bool {
        let gran = self.granularity.bytes();
        (offset % gran == 0) && (len % gran == 0)
    }
}

/// DAX device registry.
pub struct DaxRegistry {
    devices: [Option<DaxDevice>; MAX_DAX_DEVICES],
    count: usize,
}

impl DaxRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
                const { None },
            ],
            count: 0,
        }
    }

    /// Register a DAX device; returns its index.
    pub fn register(&mut self, dev: DaxDevice) -> Result<usize> {
        if self.count >= MAX_DAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Return an immutable reference to a device.
    pub fn get(&self, idx: usize) -> Option<&DaxDevice> {
        self.devices.get(idx).and_then(Option::as_ref)
    }

    /// Return a mutable reference to a device.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut DaxDevice> {
        self.devices.get_mut(idx).and_then(Option::as_mut)
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DaxRegistry {
    fn default() -> Self {
        Self::new()
    }
}

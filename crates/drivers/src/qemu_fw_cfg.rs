// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! QEMU firmware configuration (fw_cfg) device driver.
//!
//! The QEMU fw_cfg device provides a mechanism for the host to pass
//! configuration data to the guest at boot time. It is accessible via:
//!
//! - **x86**: I/O ports 0x510 (selector) and 0x511 (data), or MMIO
//! - **ARM/RISC-V**: MMIO at a platform-specific base address
//!
//! The device exposes a key-value store where each entry is identified
//! by a 16-bit selector key. Standard keys include:
//!
//! - `FW_CFG_SIGNATURE` (0x00) — 4-byte magic "QEMU"
//! - `FW_CFG_ID` (0x01) — feature flags
//! - `FW_CFG_FILE_DIR` (0x19) — directory of named files
//!
//! Reference: QEMU source `hw/nvram/fw_cfg.c`; docs/specs/fw_cfg.rst.

use oncrix_lib::{Error, Result};

// ── fw_cfg I/O Port Constants (x86) ───────────────────────────────────────

/// Selector (index) port.
pub const FW_CFG_PORT_SEL: u16 = 0x510;
/// Data port (1 byte at a time).
pub const FW_CFG_PORT_DATA: u16 = 0x511;
/// DMA port (4 bytes, for DMA access control register).
pub const FW_CFG_PORT_DMA: u16 = 0x514;

// ── Standard Key Selectors ─────────────────────────────────────────────────

/// Selector: device signature ("QEMU").
pub const FW_CFG_SIGNATURE: u16 = 0x0000;
/// Selector: feature flags.
pub const FW_CFG_ID: u16 = 0x0001;
/// Selector: UUID.
pub const FW_CFG_UUID: u16 = 0x0002;
/// Selector: RAM size in bytes.
pub const FW_CFG_RAM_SIZE: u16 = 0x0003;
/// Selector: NOGRAPHIC flag.
pub const FW_CFG_NOGRAPHIC: u16 = 0x0004;
/// Selector: number of CPUs.
pub const FW_CFG_NB_CPUS: u16 = 0x0005;
/// Selector: kernel file entry.
pub const FW_CFG_KERNEL: u16 = 0x000E;
/// Selector: initrd file entry.
pub const FW_CFG_INITRD: u16 = 0x0011;
/// Selector: kernel command line.
pub const FW_CFG_CMDLINE: u16 = 0x0013;
/// Selector: file directory.
pub const FW_CFG_FILE_DIR: u16 = 0x0019;

/// Expected device signature.
pub const FW_CFG_MAGIC: &[u8; 4] = b"QEMU";

/// Feature flag: DMA interface supported.
pub const FW_CFG_FEATURE_DMA: u32 = 1 << 1;

/// Maximum files in the fw_cfg directory.
const MAX_FW_CFG_FILES: usize = 128;
/// Max filename length per QEMU fw_cfg spec.
const FW_CFG_MAX_FILE_PATH: usize = 56;

// ── fw_cfg File Entry ──────────────────────────────────────────────────────

/// A single file entry in the fw_cfg directory (big-endian on wire).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwCfgFile {
    /// Size of the file in bytes (big-endian).
    pub size_be: u32,
    /// Selector key for this file (big-endian).
    pub select_be: u16,
    /// Reserved.
    pub _reserved: u16,
    /// Null-terminated filename.
    pub name: [u8; FW_CFG_MAX_FILE_PATH],
}

impl FwCfgFile {
    /// Return the file size (converting from big-endian).
    pub fn size(&self) -> u32 {
        u32::from_be(self.size_be)
    }

    /// Return the selector key (converting from big-endian).
    pub fn selector(&self) -> u16 {
        u16::from_be(self.select_be)
    }

    /// Return the filename as a byte slice (up to the null terminator).
    pub fn name_bytes(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FW_CFG_MAX_FILE_PATH);
        &self.name[..end]
    }
}

// ── Access Mode ────────────────────────────────────────────────────────────

/// fw_cfg access mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FwCfgMode {
    /// x86 I/O port access.
    #[cfg(target_arch = "x86_64")]
    IoPort,
    /// MMIO access (ARM, RISC-V, or x86 with MMIO).
    Mmio(usize),
}

// ── I/O Port Access (x86) ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod io {
    #[inline]
    pub unsafe fn outw(port: u16, val: u16) {
        // SAFETY: caller guarantees port is a valid fw_cfg I/O port.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") val,
                options(nostack, nomem, preserves_flags),
            );
        }
    }

    #[inline]
    pub unsafe fn inb(port: u16) -> u8 {
        let val: u8;
        // SAFETY: caller guarantees port is a valid fw_cfg I/O port.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") val,
                options(nostack, nomem, preserves_flags),
            );
        }
        val
    }
}

// ── MMIO helpers ───────────────────────────────────────────────────────────

unsafe fn mmio_write16(base: usize, offset: u32, val: u16) {
    // SAFETY: caller guarantees base+offset is valid fw_cfg MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u16, val.to_be()) }
}

unsafe fn mmio_read8(base: usize, offset: u32) -> u8 {
    // SAFETY: caller guarantees base+offset is valid fw_cfg MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u8) }
}

// ── fw_cfg Driver ──────────────────────────────────────────────────────────

/// QEMU fw_cfg driver.
pub struct FwCfg {
    mode: FwCfgMode,
    features: u32,
    /// Cached file directory.
    files: [Option<FwCfgFile>; MAX_FW_CFG_FILES],
    file_count: usize,
    directory_loaded: bool,
}

impl FwCfg {
    /// Create a new fw_cfg driver instance.
    pub fn new(mode: FwCfgMode) -> Self {
        Self {
            mode,
            features: 0,
            files: [const { None }; MAX_FW_CFG_FILES],
            file_count: 0,
            directory_loaded: false,
        }
    }

    /// Select a fw_cfg entry by key.
    fn select(&self, key: u16) {
        match self.mode {
            #[cfg(target_arch = "x86_64")]
            FwCfgMode::IoPort => {
                // SAFETY: FW_CFG_PORT_SEL is a valid fw_cfg I/O port.
                unsafe { io::outw(FW_CFG_PORT_SEL, key) }
            }
            FwCfgMode::Mmio(base) => {
                // SAFETY: base is valid fw_cfg MMIO.
                unsafe { mmio_write16(base, 8, key) }
            }
        }
    }

    /// Read a single byte from the currently selected entry.
    fn read_byte(&self) -> u8 {
        match self.mode {
            #[cfg(target_arch = "x86_64")]
            FwCfgMode::IoPort => {
                // SAFETY: FW_CFG_PORT_DATA is the fw_cfg data port.
                unsafe { io::inb(FW_CFG_PORT_DATA) }
            }
            FwCfgMode::Mmio(base) => {
                // SAFETY: base is valid fw_cfg MMIO; data reg at offset 0.
                unsafe { mmio_read8(base, 0) }
            }
        }
    }

    /// Read `len` bytes from the current entry into `buf`.
    fn read_bytes(&self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.read_byte();
        }
    }

    /// Read a u32 (little-endian from sequential bytes).
    fn read_u32_le(&self) -> u32 {
        let mut bytes = [0u8; 4];
        self.read_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    /// Initialize the driver: verify signature and read features.
    pub fn init(&mut self) -> Result<()> {
        let mut sig = [0u8; 4];
        self.select(FW_CFG_SIGNATURE);
        self.read_bytes(&mut sig);
        if &sig != FW_CFG_MAGIC {
            return Err(Error::NotFound);
        }
        self.select(FW_CFG_ID);
        self.features = self.read_u32_le();
        Ok(())
    }

    /// Read a u32 from a given fw_cfg key.
    pub fn read_u32(&self, key: u16) -> u32 {
        self.select(key);
        self.read_u32_le()
    }

    /// Read up to `buf.len()` bytes from a given key.
    pub fn read_key(&self, key: u16, buf: &mut [u8]) {
        self.select(key);
        self.read_bytes(buf);
    }

    /// Read the RAM size reported by fw_cfg.
    pub fn ram_size(&self) -> u64 {
        let mut buf = [0u8; 8];
        self.select(FW_CFG_RAM_SIZE);
        self.read_bytes(&mut buf[..4]);
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64
    }

    /// Read the CPU count.
    pub fn cpu_count(&self) -> u16 {
        let mut buf = [0u8; 2];
        self.select(FW_CFG_NB_CPUS);
        self.read_bytes(&mut buf);
        u16::from_le_bytes(buf)
    }

    /// Return true if DMA access is supported.
    pub fn has_dma(&self) -> bool {
        self.features & FW_CFG_FEATURE_DMA != 0
    }

    /// Load the file directory from the device.
    pub fn load_directory(&mut self) -> Result<()> {
        self.select(FW_CFG_FILE_DIR);
        // First 4 bytes: number of entries (big-endian).
        let mut count_buf = [0u8; 4];
        self.read_bytes(&mut count_buf);
        let count = u32::from_be_bytes(count_buf) as usize;
        if count > MAX_FW_CFG_FILES {
            return Err(Error::OutOfMemory);
        }
        for i in 0..count {
            let mut entry = FwCfgFile {
                size_be: 0,
                select_be: 0,
                _reserved: 0,
                name: [0u8; FW_CFG_MAX_FILE_PATH],
            };
            let mut buf = [0u8; 4];
            self.read_bytes(&mut buf);
            entry.size_be = u32::from_le_bytes(buf);
            let mut buf2 = [0u8; 2];
            self.read_bytes(&mut buf2);
            entry.select_be = u16::from_le_bytes(buf2);
            self.read_bytes(&mut buf2); // reserved
            self.read_bytes(&mut entry.name);
            self.files[i] = Some(entry);
        }
        self.file_count = count;
        self.directory_loaded = true;
        Ok(())
    }

    /// Find a file by name in the loaded directory.
    pub fn find_file(&self, name: &[u8]) -> Option<&FwCfgFile> {
        for slot in &self.files[..self.file_count] {
            if let Some(f) = slot {
                if f.name_bytes() == name {
                    return Some(f);
                }
            }
        }
        None
    }

    /// Return the number of files in the directory.
    pub fn file_count(&self) -> usize {
        self.file_count
    }
}

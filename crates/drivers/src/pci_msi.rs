// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI MSI/MSI-X interrupt driver.
//!
//! Provides high-level management of Message Signaled Interrupts (MSI)
//! and MSI-X for PCI/PCIe devices. Wraps the HAL-level MSI primitives
//! with a per-device allocation table, vector routing, and enable/disable
//! operations suitable for driver use.
//!
//! # Architecture
//!
//! ```text
//! Driver
//!   │ request_msi() / request_msix()
//!   ▼
//! MsiDevice ──► MsiAllocator (global vector pool)
//!   │
//!   ├── MSI cap  ──► 1..32 vectors in PCI config space
//!   └── MSI-X cap ──► up to 2048 vectors via BAR-mapped table
//! ```
//!
//! # Usage
//!
//! 1. Create an [`MsiDevice`] with the device's PCI config-space base
//!    address and number of desired vectors.
//! 2. Call [`MsiDevice::enable_msi`] or [`MsiDevice::enable_msix`].
//! 3. Register interrupt handlers for the allocated vectors.
//! 4. Call [`MsiDevice::disable`] before device removal.
//!
//! Reference: PCI Local Bus Specification 3.0 §6.8,
//!            PCI Express Base Spec 5.0 §7.7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PCI capability ID for MSI.
pub const PCI_CAP_MSI: u8 = 0x05;

/// PCI capability ID for MSI-X.
pub const PCI_CAP_MSIX: u8 = 0x11;

/// Offset of the capabilities pointer in PCI config space.
const PCI_CAP_PTR_OFFSET: u8 = 0x34;

/// MSI control register offset within the MSI capability.
const MSI_CAP_CTRL_OFFSET: u8 = 0x02;

/// MSI message address low offset within the MSI capability.
const MSI_CAP_ADDR_LO_OFFSET: u8 = 0x04;

/// MSI message address high offset within the MSI capability.
const MSI_CAP_ADDR_HI_OFFSET: u8 = 0x08;

/// MSI message data offset (32-bit addressing variant).
const MSI_CAP_DATA_32_OFFSET: u8 = 0x08;

/// MSI message data offset (64-bit addressing variant).
const MSI_CAP_DATA_64_OFFSET: u8 = 0x0C;

/// MSI control: enable bit.
const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI control: 64-bit address capability bit.
const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI control: per-vector masking capability bit.
const MSI_CTRL_PVM: u16 = 1 << 8;

/// MSI control: Multiple Message Capable shift.
const MSI_CTRL_MMC_SHIFT: u32 = 1;

/// MSI control: Multiple Message Capable mask (3 bits).
const MSI_CTRL_MMC_MASK: u16 = 0b111;

/// MSI control: Multiple Message Enable shift.
const MSI_CTRL_MME_SHIFT: u32 = 4;

/// MSI control: Multiple Message Enable mask (3 bits).
const MSI_CTRL_MME_MASK: u16 = 0b111;

/// MSI-X control register offset within the MSI-X capability.
const MSIX_CAP_CTRL_OFFSET: u8 = 0x02;

/// MSI-X table offset register offset.
const MSIX_CAP_TABLE_OFFSET: u8 = 0x04;

/// MSI-X PBA offset register offset.
const MSIX_CAP_PBA_OFFSET: u8 = 0x08;

/// MSI-X control: enable bit.
const MSIX_CTRL_ENABLE: u16 = 1 << 15;

/// MSI-X control: function mask bit.
const MSIX_CTRL_FMASK: u16 = 1 << 14;

/// MSI-X control: table size mask (lower 11 bits, value is N-1).
const MSIX_CTRL_SIZE_MASK: u16 = 0x07FF;

/// MSI-X table entry size in bytes (addr_lo + addr_hi + data + ctrl).
pub const MSIX_ENTRY_SIZE: usize = 16;

/// MSI-X vector control: mask bit.
const MSIX_VEC_CTRL_MASK: u32 = 1 << 0;

/// x86 MSI message address base.
const MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// x86 MSI address: destination CPU ID shift.
const MSI_ADDR_DEST_SHIFT: u32 = 12;

/// x86 MSI data: interrupt vector mask.
const MSI_DATA_VECTOR_MASK: u32 = 0xFF;

/// Maximum MSI vectors tracked per device.
const MAX_MSI_VECTORS: usize = 32;

/// Maximum MSI-X vectors tracked per device.
const MAX_MSIX_VECTORS: usize = 64;

/// Maximum PCI MSI devices managed globally.
const MAX_MSI_DEVICES: usize = 32;

/// First usable interrupt vector number.
const VECTOR_BASE: u32 = 0x20;

/// Last usable interrupt vector number (exclusive).
const VECTOR_LIMIT: u32 = 0xF0;

/// Total usable vectors in the pool.
const VECTOR_POOL_SIZE: usize = (VECTOR_LIMIT - VECTOR_BASE) as usize;

// ---------------------------------------------------------------------------
// Interrupt Mode
// ---------------------------------------------------------------------------

/// Interrupt delivery mode for MSI messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Fixed delivery to specified APIC(s).
    #[default]
    Fixed = 0,
    /// Lowest-priority delivery.
    LowestPriority = 1,
    /// System Management Interrupt.
    Smi = 2,
    /// Non-Maskable Interrupt.
    Nmi = 4,
    /// INIT signal.
    Init = 5,
    /// External interrupt.
    ExtInt = 7,
}

// ---------------------------------------------------------------------------
// MsiVector
// ---------------------------------------------------------------------------

/// A single allocated MSI or MSI-X vector.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsiVector {
    /// Hardware interrupt vector number.
    pub vector: u32,
    /// Target CPU APIC ID.
    pub cpu: u8,
    /// Delivery mode.
    pub mode: DeliveryMode,
    /// Whether this vector entry is in use.
    pub allocated: bool,
}

impl MsiVector {
    /// Create a new unallocated vector slot.
    pub const fn new() -> Self {
        Self {
            vector: 0,
            cpu: 0,
            mode: DeliveryMode::Fixed,
            allocated: false,
        }
    }

    /// Build the 32-bit MSI message address for x86.
    ///
    /// Returns the `0xFEE_XXXXX` format address targeting `self.cpu`.
    pub fn message_address_lo(&self) -> u32 {
        MSI_ADDR_BASE | (u32::from(self.cpu) << MSI_ADDR_DEST_SHIFT)
    }

    /// Upper 32 bits of MSI message address (always 0 for x86).
    pub fn message_address_hi(&self) -> u32 {
        0
    }

    /// Build the 32-bit MSI message data word.
    pub fn message_data(&self) -> u32 {
        let vector = self.vector & MSI_DATA_VECTOR_MASK;
        let mode = (self.mode as u32) << 8;
        vector | mode
    }
}

// ---------------------------------------------------------------------------
// VectorAllocator
// ---------------------------------------------------------------------------

/// Global interrupt vector pool for MSI/MSI-X allocation.
///
/// Tracks which vectors in the range `[VECTOR_BASE, VECTOR_LIMIT)` are
/// currently in use.
pub struct VectorAllocator {
    used: [bool; VECTOR_POOL_SIZE],
}

impl VectorAllocator {
    /// Create an empty allocator.
    pub const fn new() -> Self {
        Self {
            used: [false; VECTOR_POOL_SIZE],
        }
    }

    /// Allocate `count` contiguous vectors aligned to `count` (power-of-2).
    ///
    /// Returns the first vector number, or [`Error::OutOfMemory`] if no
    /// suitable range is found.
    pub fn alloc(&mut self, count: usize) -> Result<u32> {
        if count == 0 || count > VECTOR_POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Alignment must be next power of two >= count.
        let align = count.next_power_of_two();
        let mut idx = 0;
        while idx + count <= VECTOR_POOL_SIZE {
            // Check alignment relative to pool base.
            if (VECTOR_BASE as usize + idx) % align != 0 {
                idx += 1;
                continue;
            }
            // Check availability.
            let mut avail = true;
            for j in 0..count {
                if self.used[idx + j] {
                    avail = false;
                    idx += j + 1;
                    break;
                }
            }
            if avail {
                for j in 0..count {
                    self.used[idx + j] = true;
                }
                return Ok(VECTOR_BASE + idx as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free `count` vectors starting at `first_vector`.
    pub fn free(&mut self, first_vector: u32, count: usize) -> Result<()> {
        if first_vector < VECTOR_BASE || first_vector >= VECTOR_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let idx = (first_vector - VECTOR_BASE) as usize;
        if idx + count > VECTOR_POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        for j in 0..count {
            self.used[idx + j] = false;
        }
        Ok(())
    }

    /// Return the number of free vectors remaining.
    pub fn free_count(&self) -> usize {
        self.used.iter().filter(|&&u| !u).count()
    }
}

// ---------------------------------------------------------------------------
// MsiCapability
// ---------------------------------------------------------------------------

/// Parsed MSI capability structure.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsiCapability {
    /// Byte offset of the MSI capability in PCI config space.
    pub cap_offset: u8,
    /// Raw control register value.
    pub control: u16,
    /// Whether 64-bit addressing is supported.
    pub addr64: bool,
    /// Whether per-vector masking is supported.
    pub per_vector_mask: bool,
    /// Maximum number of vectors supported (1, 2, 4, 8, 16, or 32).
    pub max_vectors: u8,
}

impl MsiCapability {
    /// Parse from a config-space capability header.
    ///
    /// `cap_offset` is the byte offset of the capability in config space.
    /// `control` is the 16-bit control register value at `cap_offset + 2`.
    pub fn parse(cap_offset: u8, control: u16) -> Self {
        let mmc = ((control >> MSI_CTRL_MMC_SHIFT) & MSI_CTRL_MMC_MASK) as u8;
        let max_vectors = 1u8 << mmc.min(5);
        Self {
            cap_offset,
            control,
            addr64: (control & MSI_CTRL_64BIT) != 0,
            per_vector_mask: (control & MSI_CTRL_PVM) != 0,
            max_vectors,
        }
    }

    /// Whether MSI is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.control & MSI_CTRL_ENABLE != 0
    }

    /// Build a control word that enables MSI with `num_vectors` (must be
    /// power-of-two, ≤ `max_vectors`).
    pub fn enable_control(&self, num_vectors: u8) -> Result<u16> {
        if !num_vectors.is_power_of_two() || num_vectors > self.max_vectors {
            return Err(Error::InvalidArgument);
        }
        let mme = (num_vectors.trailing_zeros() & 0x7) as u16;
        let ctrl = (self.control & !((MSI_CTRL_MME_MASK << MSI_CTRL_MME_SHIFT) as u16))
            | (mme << MSI_CTRL_MME_SHIFT as u16)
            | MSI_CTRL_ENABLE;
        Ok(ctrl)
    }
}

// ---------------------------------------------------------------------------
// MsixCapability
// ---------------------------------------------------------------------------

/// Parsed MSI-X capability structure.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixCapability {
    /// Byte offset of the MSI-X capability in PCI config space.
    pub cap_offset: u8,
    /// Raw control register value.
    pub control: u16,
    /// Number of MSI-X vectors (1-based; hardware stores N-1).
    pub num_vectors: u16,
    /// BAR index for the vector table.
    pub table_bar: u8,
    /// Byte offset of the vector table within the BAR.
    pub table_offset: u32,
    /// BAR index for the Pending Bit Array.
    pub pba_bar: u8,
    /// Byte offset of the PBA within the BAR.
    pub pba_offset: u32,
}

impl MsixCapability {
    /// Parse from raw control, table, and PBA register values.
    pub fn parse(cap_offset: u8, control: u16, table_reg: u32, pba_reg: u32) -> Self {
        let num_vectors = (control & MSIX_CTRL_SIZE_MASK) + 1;
        Self {
            cap_offset,
            control,
            num_vectors,
            table_bar: (table_reg & 0x7) as u8,
            table_offset: table_reg & !0x7,
            pba_bar: (pba_reg & 0x7) as u8,
            pba_offset: pba_reg & !0x7,
        }
    }

    /// Whether MSI-X is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.control & MSIX_CTRL_ENABLE != 0
    }

    /// Whether the function-level mask is set.
    pub fn is_function_masked(&self) -> bool {
        self.control & MSIX_CTRL_FMASK != 0
    }

    /// Control word with MSI-X enabled and function mask cleared.
    pub fn enable_control(&self) -> u16 {
        (self.control | MSIX_CTRL_ENABLE) & !MSIX_CTRL_FMASK
    }

    /// Control word with MSI-X disabled.
    pub fn disable_control(&self) -> u16 {
        self.control & !MSIX_CTRL_ENABLE
    }
}

// ---------------------------------------------------------------------------
// MsixTableEntry
// ---------------------------------------------------------------------------

/// A single entry in the MSI-X vector table (BAR-mapped).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MsixTableEntry {
    /// Message address lower 32 bits.
    pub msg_addr_lo: u32,
    /// Message address upper 32 bits.
    pub msg_addr_hi: u32,
    /// Message data word.
    pub msg_data: u32,
    /// Vector control (bit 0 = mask).
    pub vector_ctrl: u32,
}

impl MsixTableEntry {
    /// Create a new table entry for the given vector and CPU.
    pub fn new(vector: &MsiVector) -> Self {
        Self {
            msg_addr_lo: vector.message_address_lo(),
            msg_addr_hi: vector.message_address_hi(),
            msg_data: vector.message_data(),
            vector_ctrl: 0,
        }
    }

    /// Whether this vector entry is masked.
    pub fn is_masked(&self) -> bool {
        self.vector_ctrl & MSIX_VEC_CTRL_MASK != 0
    }

    /// Mask this vector entry.
    pub fn mask(&mut self) {
        self.vector_ctrl |= MSIX_VEC_CTRL_MASK;
    }

    /// Unmask this vector entry.
    pub fn unmask(&mut self) {
        self.vector_ctrl &= !MSIX_VEC_CTRL_MASK;
    }
}

// ---------------------------------------------------------------------------
// MsiDevice
// ---------------------------------------------------------------------------

/// Per-device MSI/MSI-X state.
///
/// Tracks the allocated vectors, capability location, and interrupt mode
/// for a single PCI device.
#[derive(Debug)]
pub struct MsiDevice {
    /// PCI bus/device/function (encoded as `bus<<16 | dev<<8 | fn`).
    pub bdf: u32,
    /// Whether MSI (vs MSI-X) is in use.
    pub use_msi: bool,
    /// MSI capability information (valid when `use_msi` is true).
    pub msi_cap: MsiCapability,
    /// MSI-X capability information (valid when `use_msi` is false).
    pub msix_cap: MsixCapability,
    /// Number of vectors currently allocated.
    pub num_vectors: usize,
    /// First allocated vector number.
    pub first_vector: u32,
    /// Per-vector entries (MSI-X shadow table).
    vectors: [MsiVector; MAX_MSIX_VECTORS],
    /// Whether any interrupts are currently enabled.
    pub enabled: bool,
}

impl MsiDevice {
    /// Create a new MSI device descriptor.
    ///
    /// `bdf` encodes the PCI address as `(bus << 16) | (dev << 8) | fn`.
    pub fn new(bdf: u32) -> Self {
        Self {
            bdf,
            use_msi: false,
            msi_cap: MsiCapability::default(),
            msix_cap: MsixCapability::default(),
            num_vectors: 0,
            first_vector: 0,
            vectors: [const { MsiVector::new() }; MAX_MSIX_VECTORS],
            enabled: false,
        }
    }

    /// Configure device for MSI with `num_vectors` vectors.
    ///
    /// Allocates vectors from the global pool, builds the MSI address/data
    /// words, and marks the device as MSI-enabled. The caller is responsible
    /// for writing the MSI control register to PCI config space.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `num_vectors` exceeds `MAX_MSI_VECTORS`
    ///   or is not a power of two.
    /// - [`Error::OutOfMemory`] if no contiguous range is available.
    pub fn setup_msi(
        &mut self,
        allocator: &mut VectorAllocator,
        msi_cap: MsiCapability,
        num_vectors: usize,
        cpu: u8,
    ) -> Result<u32> {
        if num_vectors == 0 || num_vectors > MAX_MSI_VECTORS {
            return Err(Error::InvalidArgument);
        }
        if !num_vectors.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        let first = allocator.alloc(num_vectors)?;
        self.use_msi = true;
        self.msi_cap = msi_cap;
        self.num_vectors = num_vectors;
        self.first_vector = first;
        for i in 0..num_vectors {
            self.vectors[i] = MsiVector {
                vector: first + i as u32,
                cpu,
                mode: DeliveryMode::Fixed,
                allocated: true,
            };
        }
        self.enabled = true;
        Ok(first)
    }

    /// Configure device for MSI-X with `num_vectors` vectors.
    ///
    /// Returns the first allocated vector number.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `num_vectors` is 0 or exceeds
    ///   `MAX_MSIX_VECTORS`.
    /// - [`Error::OutOfMemory`] if no range is available.
    pub fn setup_msix(
        &mut self,
        allocator: &mut VectorAllocator,
        msix_cap: MsixCapability,
        num_vectors: usize,
        cpu: u8,
    ) -> Result<u32> {
        if num_vectors == 0 || num_vectors > MAX_MSIX_VECTORS {
            return Err(Error::InvalidArgument);
        }
        let first = allocator.alloc(num_vectors)?;
        self.use_msi = false;
        self.msix_cap = msix_cap;
        self.num_vectors = num_vectors;
        self.first_vector = first;
        for i in 0..num_vectors {
            self.vectors[i] = MsiVector {
                vector: first + i as u32,
                cpu,
                mode: DeliveryMode::Fixed,
                allocated: true,
            };
        }
        self.enabled = true;
        Ok(first)
    }

    /// Disable interrupts and release vectors back to the pool.
    pub fn teardown(&mut self, allocator: &mut VectorAllocator) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        allocator.free(self.first_vector, self.num_vectors)?;
        for i in 0..self.num_vectors {
            self.vectors[i] = MsiVector::new();
        }
        self.enabled = false;
        self.num_vectors = 0;
        self.first_vector = 0;
        Ok(())
    }

    /// Get the vector entry for index `idx`.
    pub fn vector(&self, idx: usize) -> Result<&MsiVector> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vectors[idx])
    }

    /// Get a mutable reference to the vector entry for index `idx`.
    pub fn vector_mut(&mut self, idx: usize) -> Result<&mut MsiVector> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.vectors[idx])
    }

    /// Build MSI-X table entry for vector `idx` suitable for MMIO write.
    pub fn msix_table_entry(&self, idx: usize) -> Result<MsixTableEntry> {
        let vec = self.vector(idx)?;
        Ok(MsixTableEntry::new(vec))
    }

    /// PCI bus number extracted from `bdf`.
    pub fn bus(&self) -> u8 {
        (self.bdf >> 16) as u8
    }

    /// PCI device number extracted from `bdf`.
    pub fn device(&self) -> u8 {
        (self.bdf >> 8) as u8
    }

    /// PCI function number extracted from `bdf`.
    pub fn function(&self) -> u8 {
        self.bdf as u8
    }
}

// ---------------------------------------------------------------------------
// MsiRegistry
// ---------------------------------------------------------------------------

/// Global registry of MSI-capable PCI devices.
pub struct MsiRegistry {
    devices: [Option<MsiDevice>; MAX_MSI_DEVICES],
    len: usize,
}

impl MsiRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_MSI_DEVICES],
            len: 0,
        }
    }

    /// Register a new MSI device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full.
    pub fn register(&mut self, device: MsiDevice) -> Result<usize> {
        if self.len >= MAX_MSI_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.len;
        self.devices[idx] = Some(device);
        self.len += 1;
        Ok(idx)
    }

    /// Look up a device by its BDF.
    pub fn find_by_bdf(&self, bdf: u32) -> Option<&MsiDevice> {
        for i in 0..self.len {
            if let Some(ref d) = self.devices[i] {
                if d.bdf == bdf {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Look up a mutable device by its BDF.
    pub fn find_by_bdf_mut(&mut self, bdf: u32) -> Option<&mut MsiDevice> {
        for i in 0..self.len {
            if let Some(ref d) = self.devices[i] {
                if d.bdf == bdf {
                    return self.devices[i].as_mut();
                }
            }
        }
        None
    }

    /// Number of registered devices.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over registered devices.
    pub fn iter(&self) -> impl Iterator<Item = &MsiDevice> {
        self.devices[..self.len].iter().filter_map(|d| d.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Scan a PCI config-space capability list for MSI and MSI-X.
///
/// `config` is a slice of at least 256 bytes representing the standard
/// PCI type-0 configuration space. Returns a tuple of
/// `(Option<MsiCapability>, Option<MsixCapability>)`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `config` is shorter than 256 bytes.
pub fn scan_msi_capabilities(
    config: &[u8],
) -> Result<(Option<MsiCapability>, Option<MsixCapability>)> {
    if config.len() < 256 {
        return Err(Error::InvalidArgument);
    }
    // Status register bits[4] = capabilities list present.
    let status = u16::from_le_bytes([config[0x06], config[0x07]]);
    if status & (1 << 4) == 0 {
        return Ok((None, None));
    }
    let mut cap_ptr = config[PCI_CAP_PTR_OFFSET as usize] & 0xFC;
    let mut msi: Option<MsiCapability> = None;
    let mut msix: Option<MsixCapability> = None;
    // Walk capability list; PCI spec allows at most 48 caps.
    for _ in 0..48 {
        if cap_ptr < 0x40 {
            break;
        }
        let offset = cap_ptr as usize;
        if offset + 2 > config.len() {
            break;
        }
        let cap_id = config[offset];
        let next_ptr = config[offset + 1] & 0xFC;
        match cap_id {
            id if id == PCI_CAP_MSI => {
                if offset + 4 <= config.len() {
                    let ctrl = u16::from_le_bytes([config[offset + 2], config[offset + 3]]);
                    msi = Some(MsiCapability::parse(cap_ptr, ctrl));
                }
            }
            id if id == PCI_CAP_MSIX => {
                if offset + 12 <= config.len() {
                    let ctrl = u16::from_le_bytes([config[offset + 2], config[offset + 3]]);
                    let table_reg = u32::from_le_bytes([
                        config[offset + 4],
                        config[offset + 5],
                        config[offset + 6],
                        config[offset + 7],
                    ]);
                    let pba_reg = u32::from_le_bytes([
                        config[offset + 8],
                        config[offset + 9],
                        config[offset + 10],
                        config[offset + 11],
                    ]);
                    msix = Some(MsixCapability::parse(cap_ptr, ctrl, table_reg, pba_reg));
                }
            }
            _ => {}
        }
        cap_ptr = next_ptr;
    }
    Ok((msi, msix))
}

/// Write a 32-bit value to an MSI-X table entry field via MMIO.
///
/// `table_base` is the virtual address of the MSI-X table BAR region.
/// `entry` is the zero-based entry index.
/// `field_offset` is 0=addr_lo, 4=addr_hi, 8=data, 12=vector_ctrl.
///
/// # Safety
///
/// Caller must ensure `table_base` is a valid mapped MMIO region covering
/// at least `(entry + 1) * MSIX_ENTRY_SIZE` bytes.
pub unsafe fn msix_write_entry_field(
    table_base: *mut u32,
    entry: usize,
    field_offset: usize,
    val: u32,
) {
    // SAFETY: Caller guarantees valid MMIO mapping.
    let ptr = unsafe { table_base.add(entry * MSIX_ENTRY_SIZE / 4 + field_offset / 4) };
    unsafe { core::ptr::write_volatile(ptr, val) };
}

/// Read a 32-bit value from an MSI-X table entry field via MMIO.
///
/// # Safety
///
/// Same requirements as [`msix_write_entry_field`].
pub unsafe fn msix_read_entry_field(
    table_base: *const u32,
    entry: usize,
    field_offset: usize,
) -> u32 {
    // SAFETY: Caller guarantees valid MMIO mapping.
    let ptr = unsafe { table_base.add(entry * MSIX_ENTRY_SIZE / 4 + field_offset / 4) };
    unsafe { core::ptr::read_volatile(ptr) }
}

// ---------------------------------------------------------------------------
// Capability offsets (exported for drivers)
// ---------------------------------------------------------------------------

/// Byte offset within MSI capability for the control register.
pub const MSI_CTRL_REG_OFFSET: u8 = MSI_CAP_CTRL_OFFSET;

/// Byte offset within MSI capability for the message address (low).
pub const MSI_ADDR_LO_REG_OFFSET: u8 = MSI_CAP_ADDR_LO_OFFSET;

/// Byte offset within MSI capability for the message address (high, 64-bit).
pub const MSI_ADDR_HI_REG_OFFSET: u8 = MSI_CAP_ADDR_HI_OFFSET;

/// Byte offset within MSI capability for message data (32-bit mode).
pub const MSI_DATA_32_REG_OFFSET: u8 = MSI_CAP_DATA_32_OFFSET;

/// Byte offset within MSI capability for message data (64-bit mode).
pub const MSI_DATA_64_REG_OFFSET: u8 = MSI_CAP_DATA_64_OFFSET;

/// Byte offset within MSI-X capability for the control register.
pub const MSIX_CTRL_REG_OFFSET: u8 = MSIX_CAP_CTRL_OFFSET;

/// Byte offset within MSI-X capability for the table BIR/offset register.
pub const MSIX_TABLE_REG_OFFSET: u8 = MSIX_CAP_TABLE_OFFSET;

/// Byte offset within MSI-X capability for the PBA BIR/offset register.
pub const MSIX_PBA_REG_OFFSET: u8 = MSIX_CAP_PBA_OFFSET;

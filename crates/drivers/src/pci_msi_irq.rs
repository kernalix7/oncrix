// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI MSI/MSI-X interrupt management driver.
//!
//! Implements full MSI and MSI-X interrupt management for PCI/PCIe devices,
//! including capability parsing, vector allocation, per-vector masking,
//! and PBA (Pending Bit Array) access. Modelled on Linux
//! `drivers/pci/msi/msi.c` and `drivers/pci/msi/msix.c`.
//!
//! # Architecture
//!
//! ```text
//! PCI Config Space
//!   ├── MSI Capability  ─► up to 32 message vectors
//!   └── MSI-X Capability
//!         ├── Vector Table (BAR-mapped MMIO)  ─► up to 2048 entries
//!         └── Pending Bit Array (BAR-mapped MMIO)
//! ```
//!
//! # MSI Capability Layout (PCI 3.0 §6.8.1)
//!
//! | Offset | Size | Field               |
//! |--------|------|---------------------|
//! | 0x00   | 1    | Capability ID (0x05)|
//! | 0x01   | 1    | Next Pointer        |
//! | 0x02   | 2    | Message Control     |
//! | 0x04   | 4    | Message Address Lo  |
//! | 0x08   | 4    | Message Address Hi  |
//! | 0x0C   | 2    | Message Data        |
//! | 0x10   | 4    | Mask Bits (opt)     |
//! | 0x14   | 4    | Pending Bits (opt)  |
//!
//! Reference: PCI Local Bus Specification 3.0 §6.8,
//!            PCIe Base Specification 5.0 §7.7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PCI capability ID for MSI.
pub const CAP_ID_MSI: u8 = 0x05;

/// PCI capability ID for MSI-X.
pub const CAP_ID_MSIX: u8 = 0x11;

/// MSI control register offset within the capability (bytes from cap base).
pub const MSI_CTRL_OFFSET: usize = 0x02;

/// MSI message address low offset.
pub const MSI_ADDR_LO_OFFSET: usize = 0x04;

/// MSI message address high offset (valid only in 64-bit mode).
pub const MSI_ADDR_HI_OFFSET: usize = 0x08;

/// MSI message data offset (32-bit addressing).
pub const MSI_DATA_32_OFFSET: usize = 0x08;

/// MSI message data offset (64-bit addressing).
pub const MSI_DATA_64_OFFSET: usize = 0x0C;

/// MSI mask bits offset (32-bit address, PVM supported).
pub const MSI_MASK_32_OFFSET: usize = 0x0C;

/// MSI mask bits offset (64-bit address, PVM supported).
pub const MSI_MASK_64_OFFSET: usize = 0x10;

/// MSI control: enable bit.
const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI control: 64-bit capable bit.
const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI control: per-vector masking capable bit.
const MSI_CTRL_PVM: u16 = 1 << 8;

/// MSI-X control: enable bit.
const MSIX_CTRL_ENABLE: u16 = 1 << 15;

/// MSI-X control: function mask bit.
const MSIX_CTRL_FMASK: u16 = 1 << 14;

/// MSI-X control: table size field mask (lower 11 bits, value = N-1).
const MSIX_TABLE_SIZE_MASK: u16 = 0x07FF;

/// Size of one MSI-X table entry in bytes.
pub const MSIX_ENTRY_SIZE_BYTES: usize = 16;

/// x86 MSI address base.
const X86_MSI_ADDR_BASE: u32 = 0xFEE0_0000;

/// x86 MSI address: destination CPU field shift.
const X86_MSI_DEST_SHIFT: u32 = 12;

/// Maximum tracked vectors per IRQ domain.
const MAX_IRQ_VECTORS: usize = 64;

/// Maximum IRQ domains (one per MSI-capable device or group).
const MAX_IRQ_DOMAINS: usize = 32;

/// First usable CPU interrupt vector.
const VECTOR_BASE: u32 = 0x20;

/// Exclusive upper bound of usable CPU interrupt vectors.
const VECTOR_LIMIT: u32 = 0xF0;

/// Pool size.
const VECTOR_POOL_SIZE: usize = (VECTOR_LIMIT - VECTOR_BASE) as usize;

// ---------------------------------------------------------------------------
// MsiMode
// ---------------------------------------------------------------------------

/// Whether MSI or MSI-X is in use for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MsiMode {
    /// No MSI interrupts enabled (using legacy INTx).
    #[default]
    None,
    /// Standard MSI (up to 32 vectors per device).
    Msi,
    /// MSI-X (up to 2048 vectors per device, BAR-mapped table).
    Msix,
}

// ---------------------------------------------------------------------------
// IrqVector
// ---------------------------------------------------------------------------

/// A single allocated interrupt vector.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqVector {
    /// Hardware vector number (APIC interrupt vector).
    pub vector: u32,
    /// Target CPU APIC ID.
    pub cpu: u8,
    /// Whether this slot is allocated.
    pub allocated: bool,
    /// Whether this vector is currently masked.
    pub masked: bool,
    /// Whether a pending interrupt is indicated for this vector (MSI-X PBA).
    pub pending: bool,
}

impl IrqVector {
    /// Creates an unallocated vector slot.
    pub const fn new() -> Self {
        Self {
            vector: 0,
            cpu: 0,
            allocated: false,
            masked: false,
            pending: false,
        }
    }

    /// Builds the x86 MSI message address targeting `cpu`.
    pub fn msi_addr_lo(&self) -> u32 {
        X86_MSI_ADDR_BASE | (u32::from(self.cpu) << X86_MSI_DEST_SHIFT)
    }

    /// Upper 32 bits of MSI address (always 0 on x86).
    pub fn msi_addr_hi(&self) -> u32 {
        0
    }

    /// Builds the MSI message data word for this vector.
    pub fn msi_data(&self) -> u32 {
        self.vector & 0xFF
    }
}

// ---------------------------------------------------------------------------
// GlobalVectorPool
// ---------------------------------------------------------------------------

/// System-wide interrupt vector allocation pool.
///
/// Tracks which vectors in `[VECTOR_BASE, VECTOR_LIMIT)` are in use.
pub struct GlobalVectorPool {
    used: [bool; VECTOR_POOL_SIZE],
}

impl GlobalVectorPool {
    /// Creates an empty pool.
    pub const fn new() -> Self {
        Self {
            used: [false; VECTOR_POOL_SIZE],
        }
    }

    /// Allocates `count` contiguous vectors aligned to the next power-of-two.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for bad count, [`Error::OutOfMemory`]
    /// if no suitable range exists.
    pub fn alloc_contiguous(&mut self, count: usize) -> Result<u32> {
        if count == 0 || count > VECTOR_POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        let align = count.next_power_of_two();
        let mut start = 0;
        while start + count <= VECTOR_POOL_SIZE {
            if (VECTOR_BASE as usize + start) % align != 0 {
                start += 1;
                continue;
            }
            let mut fits = true;
            for j in 0..count {
                if self.used[start + j] {
                    fits = false;
                    start += j + 1;
                    break;
                }
            }
            if fits {
                for j in 0..count {
                    self.used[start + j] = true;
                }
                return Ok(VECTOR_BASE + start as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Frees `count` vectors starting at `first`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the range is out of bounds.
    pub fn free(&mut self, first: u32, count: usize) -> Result<()> {
        if first < VECTOR_BASE || first >= VECTOR_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let start = (first - VECTOR_BASE) as usize;
        if start + count > VECTOR_POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        for j in 0..count {
            self.used[start + j] = false;
        }
        Ok(())
    }

    /// Returns the number of free vectors.
    pub fn free_count(&self) -> usize {
        self.used.iter().filter(|&&u| !u).count()
    }
}

impl Default for GlobalVectorPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MsixTableEntry
// ---------------------------------------------------------------------------

/// An in-memory shadow of one MSI-X table entry.
///
/// The hardware table in MMIO BAR is written using [`write_msix_entry`].
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MsixTableEntry {
    /// Message address lower 32 bits.
    pub addr_lo: u32,
    /// Message address upper 32 bits.
    pub addr_hi: u32,
    /// Message data.
    pub data: u32,
    /// Vector control (bit 0 = mask).
    pub ctrl: u32,
}

impl MsixTableEntry {
    /// Builds an entry from an [`IrqVector`].
    pub fn from_vector(v: &IrqVector) -> Self {
        Self {
            addr_lo: v.msi_addr_lo(),
            addr_hi: v.msi_addr_hi(),
            data: v.msi_data(),
            ctrl: if v.masked { 1 } else { 0 },
        }
    }

    /// Returns `true` if the vector is masked.
    pub fn is_masked(&self) -> bool {
        self.ctrl & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// IrqDomain
// ---------------------------------------------------------------------------

/// Per-device interrupt domain — manages a set of MSI or MSI-X vectors.
pub struct IrqDomain {
    /// PCI BDF encoding: `(bus << 16) | (dev << 8) | func`.
    pub bdf: u32,
    /// Active interrupt mode.
    pub mode: MsiMode,
    /// Allocated vectors.
    vectors: [IrqVector; MAX_IRQ_VECTORS],
    /// Number of allocated vectors.
    pub num_vectors: usize,
    /// First allocated vector number.
    pub first_vector: u32,
    /// MMIO address of the MSI-X vector table (0 = N/A).
    pub msix_table_addr: u64,
    /// MMIO address of the MSI-X PBA (0 = N/A).
    pub msix_pba_addr: u64,
    /// Whether this domain is active.
    pub active: bool,
}

impl IrqDomain {
    /// Creates an inactive domain for the given BDF.
    pub fn new(bdf: u32) -> Self {
        Self {
            bdf,
            mode: MsiMode::None,
            vectors: [const { IrqVector::new() }; MAX_IRQ_VECTORS],
            num_vectors: 0,
            first_vector: 0,
            msix_table_addr: 0,
            msix_pba_addr: 0,
            active: true,
        }
    }

    /// Allocates `count` MSI vectors from `pool` and marks the domain as MSI.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`GlobalVectorPool::alloc_contiguous`].
    pub fn setup_msi(&mut self, pool: &mut GlobalVectorPool, count: usize, cpu: u8) -> Result<u32> {
        if count == 0 || count > MAX_IRQ_VECTORS {
            return Err(Error::InvalidArgument);
        }
        let first = pool.alloc_contiguous(count)?;
        self.mode = MsiMode::Msi;
        self.first_vector = first;
        self.num_vectors = count;
        for i in 0..count {
            self.vectors[i] = IrqVector {
                vector: first + i as u32,
                cpu,
                allocated: true,
                masked: false,
                pending: false,
            };
        }
        Ok(first)
    }

    /// Allocates `count` MSI-X vectors and sets the MMIO table/PBA addresses.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`GlobalVectorPool::alloc_contiguous`].
    pub fn setup_msix(
        &mut self,
        pool: &mut GlobalVectorPool,
        count: usize,
        cpu: u8,
        table_addr: u64,
        pba_addr: u64,
    ) -> Result<u32> {
        if count == 0 || count > MAX_IRQ_VECTORS {
            return Err(Error::InvalidArgument);
        }
        let first = pool.alloc_contiguous(count)?;
        self.mode = MsiMode::Msix;
        self.first_vector = first;
        self.num_vectors = count;
        self.msix_table_addr = table_addr;
        self.msix_pba_addr = pba_addr;
        for i in 0..count {
            self.vectors[i] = IrqVector {
                vector: first + i as u32,
                cpu,
                allocated: true,
                masked: true, // Start masked per spec.
                pending: false,
            };
        }
        Ok(first)
    }

    /// Masks vector at index `idx`.
    ///
    /// For MSI-X domains also issues an MMIO write to the vector table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn mask_vector(&mut self, idx: usize) -> Result<()> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        self.vectors[idx].masked = true;
        if self.mode == MsiMode::Msix && self.msix_table_addr != 0 {
            let entry = MsixTableEntry::from_vector(&self.vectors[idx]);
            // SAFETY: msix_table_addr is a valid MMIO BAR address provided by the
            // PCI subsystem. The idx bounds-check above ensures we stay in range.
            unsafe {
                write_msix_entry(self.msix_table_addr as *mut u32, idx, &entry);
            }
        }
        Ok(())
    }

    /// Unmasks vector at index `idx`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn unmask_vector(&mut self, idx: usize) -> Result<()> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        self.vectors[idx].masked = false;
        if self.mode == MsiMode::Msix && self.msix_table_addr != 0 {
            let entry = MsixTableEntry::from_vector(&self.vectors[idx]);
            // SAFETY: Same as mask_vector — MMIO address and index are valid.
            unsafe {
                write_msix_entry(self.msix_table_addr as *mut u32, idx, &entry);
            }
        }
        Ok(())
    }

    /// Reads the pending bit for MSI-X vector `idx` from the PBA.
    ///
    /// Returns `Ok(true)` if the bit is set, `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if out of range or PBA not mapped.
    pub fn read_pba_bit(&self, idx: usize) -> Result<bool> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        if self.msix_pba_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        let qword_idx = idx / 64;
        let bit_idx = idx % 64;
        let pba_ptr = self.msix_pba_addr as *const u64;
        // SAFETY: pba_addr is a valid MMIO PBA region (64-bit naturally aligned).
        // idx is bounds-checked to stay within the allocated vector count.
        let word = unsafe { pba_ptr.add(qword_idx).read_volatile() };
        Ok(word & (1u64 << bit_idx) != 0)
    }

    /// Releases all vectors back to the pool.
    pub fn teardown(&mut self, pool: &mut GlobalVectorPool) -> Result<()> {
        if self.num_vectors > 0 {
            pool.free(self.first_vector, self.num_vectors)?;
        }
        self.mode = MsiMode::None;
        self.num_vectors = 0;
        self.first_vector = 0;
        for i in 0..MAX_IRQ_VECTORS {
            self.vectors[i] = IrqVector::new();
        }
        Ok(())
    }

    /// Returns a reference to vector `idx`.
    pub fn vector(&self, idx: usize) -> Result<&IrqVector> {
        if idx >= self.num_vectors {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vectors[idx])
    }
}

// ---------------------------------------------------------------------------
// IrqDomainRegistry
// ---------------------------------------------------------------------------

/// System-wide registry of MSI/MSI-X IRQ domains.
pub struct IrqDomainRegistry {
    domains: [Option<IrqDomain>; MAX_IRQ_DOMAINS],
    count: usize,
}

impl IrqDomainRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            domains: [const { None }; MAX_IRQ_DOMAINS],
            count: 0,
        }
    }

    /// Registers an IRQ domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, domain: IrqDomain) -> Result<usize> {
        let idx = self
            .domains
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.domains[idx] = Some(domain);
        self.count += 1;
        Ok(idx)
    }

    /// Removes the domain at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is empty.
    pub fn unregister(&mut self, index: usize) -> Result<IrqDomain> {
        if index >= MAX_IRQ_DOMAINS {
            return Err(Error::InvalidArgument);
        }
        let domain = self.domains[index].take().ok_or(Error::NotFound)?;
        self.count -= 1;
        Ok(domain)
    }

    /// Looks up a domain by BDF.
    pub fn find_by_bdf(&self, bdf: u32) -> Option<&IrqDomain> {
        self.domains.iter().flatten().find(|d| d.bdf == bdf)
    }

    /// Looks up a mutable domain by BDF.
    pub fn find_by_bdf_mut(&mut self, bdf: u32) -> Option<&mut IrqDomain> {
        self.domains.iter_mut().flatten().find(|d| d.bdf == bdf)
    }

    /// Returns the number of registered domains.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no domains are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IrqDomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parses the MSI capability control register.
///
/// Returns `(max_vectors, supports_64bit, per_vector_mask)`.
pub fn parse_msi_control(ctrl: u16) -> (u8, bool, bool) {
    let mmc = ((ctrl >> 1) & 0x7) as u8;
    let max_vectors = 1u8 << mmc.min(5);
    let addr64 = ctrl & MSI_CTRL_64BIT != 0;
    let pvm = ctrl & MSI_CTRL_PVM != 0;
    (max_vectors, addr64, pvm)
}

/// Parses the MSI-X capability control register.
///
/// Returns the number of MSI-X vectors (hardware stores N-1).
pub fn parse_msix_control(ctrl: u16) -> u16 {
    (ctrl & MSIX_TABLE_SIZE_MASK) + 1
}

/// Builds an MSI control word that enables MSI with `num_vectors` vectors.
///
/// `base_ctrl` is the current control register value.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `num_vectors` is not a power of two
/// or exceeds the device's maximum.
pub fn build_msi_enable_ctrl(base_ctrl: u16, num_vectors: u8) -> Result<u16> {
    if !num_vectors.is_power_of_two() {
        return Err(Error::InvalidArgument);
    }
    let mme = (num_vectors.trailing_zeros() & 0x7) as u16;
    let ctrl = (base_ctrl & !(0x7u16 << 4)) | (mme << 4) | MSI_CTRL_ENABLE;
    Ok(ctrl)
}

/// Builds the MSI-X control word that enables MSI-X with function mask cleared.
pub fn build_msix_enable_ctrl(base_ctrl: u16) -> u16 {
    (base_ctrl | MSIX_CTRL_ENABLE) & !MSIX_CTRL_FMASK
}

/// Builds the MSI-X control word that disables MSI-X.
pub fn build_msix_disable_ctrl(base_ctrl: u16) -> u16 {
    base_ctrl & !MSIX_CTRL_ENABLE
}

/// Writes one MSI-X table entry via MMIO volatile writes.
///
/// `table_base` is the virtual address of the MSI-X table BAR region.
/// `entry_idx` is the zero-based entry index.
///
/// # Safety
///
/// `table_base` must be a valid, mapped MMIO region covering at least
/// `(entry_idx + 1) * MSIX_ENTRY_SIZE_BYTES` bytes.
pub unsafe fn write_msix_entry(table_base: *mut u32, entry_idx: usize, entry: &MsixTableEntry) {
    let words_per_entry = MSIX_ENTRY_SIZE_BYTES / 4;
    let base = unsafe { table_base.add(entry_idx * words_per_entry) };
    // SAFETY: Caller guarantees `table_base` is a valid MMIO mapping covering
    // the full entry range. Volatile writes ensure the device sees each field.
    unsafe {
        base.write_volatile(entry.addr_lo);
        base.add(1).write_volatile(entry.addr_hi);
        base.add(2).write_volatile(entry.data);
        base.add(3).write_volatile(entry.ctrl);
    }
}

/// Reads one MSI-X table entry via MMIO volatile reads.
///
/// # Safety
///
/// Same requirements as [`write_msix_entry`].
pub unsafe fn read_msix_entry(table_base: *const u32, entry_idx: usize) -> MsixTableEntry {
    let words_per_entry = MSIX_ENTRY_SIZE_BYTES / 4;
    let base = unsafe { table_base.add(entry_idx * words_per_entry) };
    // SAFETY: Caller guarantees valid MMIO mapping. Volatile reads ensure we get
    // the actual device-visible state, not a cached copy.
    unsafe {
        MsixTableEntry {
            addr_lo: base.read_volatile(),
            addr_hi: base.add(1).read_volatile(),
            data: base.add(2).read_volatile(),
            ctrl: base.add(3).read_volatile(),
        }
    }
}

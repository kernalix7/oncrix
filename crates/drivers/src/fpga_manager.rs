// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FPGA manager framework.
//!
//! Provides infrastructure for managing FPGA devices: firmware/bitstream
//! loading, state machine control, FPGA bridge management, region
//! configuration, and partial reconfiguration support.
//!
//! # Architecture
//!
//! - [`FpgaManager`] — top-level FPGA management abstraction
//! - [`FpgaBitstream`] — bitstream image descriptor
//! - [`FpgaBridge`] — bridge between FPGA fabric and SoC
//! - [`FpgaRegion`] — a reconfigurable region of the FPGA
//! - [`FpgaManagerRegistry`] — system-wide registry of FPGA managers
//!
//! Reference: Linux kernel FPGA manager framework (drivers/fpga/).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum bitstream size (16 MiB).
const MAX_BITSTREAM_SIZE: usize = 16 * 1024 * 1024;

/// Maximum bridges per manager.
const MAX_BRIDGES: usize = 8;

/// Maximum regions per manager.
const MAX_REGIONS: usize = 8;

/// Maximum number of FPGA managers in the registry.
const MAX_MANAGERS: usize = 4;

/// Maximum bitstream header size.
const MAX_HEADER_SIZE: usize = 256;

/// Timeout for FPGA operations (polling iterations).
const FPGA_TIMEOUT: u32 = 1_000_000;

// -------------------------------------------------------------------
// FpgaState
// -------------------------------------------------------------------

/// FPGA manager state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FpgaState {
    /// Unknown/uninitialized state.
    #[default]
    Unknown,
    /// FPGA is powered off.
    PowerOff,
    /// FPGA is powered on, not programmed.
    PowerUp,
    /// FPGA is in reset.
    Reset,
    /// FPGA is accepting firmware data.
    FirmwareRequest,
    /// Firmware data is being written.
    FirmwareRequestErr,
    /// FPGA is being programmed.
    WriteInit,
    /// Writing bitstream body.
    WriteBody,
    /// Finishing programming.
    WriteComplete,
    /// FPGA is operating (configured).
    Operating,
    /// Error state.
    Error,
}

// -------------------------------------------------------------------
// FpgaFlags
// -------------------------------------------------------------------

/// Flags for FPGA programming operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FpgaFlags(u32);

impl FpgaFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);
    /// Full reconfiguration.
    pub const FULL_RECONFIG: Self = Self(1 << 0);
    /// Partial reconfiguration.
    pub const PARTIAL_RECONFIG: Self = Self(1 << 1);
    /// External configuration mode.
    pub const EXTERNAL_CONFIG: Self = Self(1 << 2);
    /// Encrypted bitstream.
    pub const ENCRYPTED: Self = Self(1 << 3);
    /// Compressed bitstream.
    pub const COMPRESSED: Self = Self(1 << 4);

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if partial reconfiguration is requested.
    pub fn is_partial(self) -> bool {
        self.0 & Self::PARTIAL_RECONFIG.0 != 0
    }

    /// Returns `true` if the bitstream is encrypted.
    pub fn is_encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED.0 != 0
    }

    /// Creates flags from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

impl Default for FpgaFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// -------------------------------------------------------------------
// BitstreamFormat
// -------------------------------------------------------------------

/// FPGA bitstream format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BitstreamFormat {
    /// Raw binary bitstream.
    #[default]
    RawBinary,
    /// Xilinx .bit format.
    XilinxBit,
    /// Intel/Altera .rbf format.
    IntelRbf,
    /// Lattice bitstream.
    LatticeBit,
    /// Compressed format (vendor-specific).
    Compressed,
}

// -------------------------------------------------------------------
// FpgaBitstream
// -------------------------------------------------------------------

/// Descriptor for an FPGA bitstream image.
///
/// Contains metadata about the bitstream (size, format, checksums)
/// and a pointer to the actual data. The data itself is stored
/// externally (e.g., in a firmware buffer).
pub struct FpgaBitstream {
    /// Bitstream identifier / name hash.
    pub id: u32,
    /// Total bitstream size in bytes.
    pub size: usize,
    /// Bitstream format.
    pub format: BitstreamFormat,
    /// Programming flags.
    pub flags: FpgaFlags,
    /// Header data (vendor-specific preamble).
    pub header: [u8; MAX_HEADER_SIZE],
    /// Header length.
    pub header_len: usize,
    /// CRC-32 of the bitstream body (0 if not computed).
    pub crc32: u32,
    /// Physical address of the bitstream data.
    pub data_phys: u64,
    /// Bytes written so far during programming.
    pub bytes_written: usize,
}

impl Default for FpgaBitstream {
    fn default() -> Self {
        Self::new()
    }
}

impl FpgaBitstream {
    /// Creates an empty bitstream descriptor.
    pub const fn new() -> Self {
        Self {
            id: 0,
            size: 0,
            format: BitstreamFormat::RawBinary,
            flags: FpgaFlags::NONE,
            header: [0u8; MAX_HEADER_SIZE],
            header_len: 0,
            crc32: 0,
            data_phys: 0,
            bytes_written: 0,
        }
    }

    /// Creates a bitstream descriptor with the given parameters.
    pub fn create(id: u32, size: usize, format: BitstreamFormat, flags: FpgaFlags) -> Result<Self> {
        if size > MAX_BITSTREAM_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            id,
            size,
            format,
            flags,
            header: [0u8; MAX_HEADER_SIZE],
            header_len: 0,
            crc32: 0,
            data_phys: 0,
            bytes_written: 0,
        })
    }

    /// Sets the bitstream header data.
    pub fn set_header(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.header[..data.len()].copy_from_slice(data);
        self.header_len = data.len();
        Ok(())
    }

    /// Returns `true` if this bitstream is empty (no data).
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns the percentage of data written.
    pub fn progress_percent(&self) -> u8 {
        if self.size == 0 {
            return 0;
        }
        ((self.bytes_written * 100) / self.size) as u8
    }

    /// Returns `true` if all data has been written.
    pub fn is_complete(&self) -> bool {
        self.bytes_written >= self.size
    }
}

// -------------------------------------------------------------------
// BridgeState
// -------------------------------------------------------------------

/// State of an FPGA bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BridgeState {
    /// Bridge is disabled (fabric isolated).
    #[default]
    Disabled,
    /// Bridge is enabled (fabric connected).
    Enabled,
    /// Bridge is in freeze mode.
    Frozen,
}

// -------------------------------------------------------------------
// FpgaBridge
// -------------------------------------------------------------------

/// An FPGA bridge connecting the FPGA fabric to the SoC.
///
/// Bridges must be disabled before reconfiguration and re-enabled
/// after programming to prevent glitches on the interconnect.
pub struct FpgaBridge {
    /// Bridge identifier.
    pub id: u32,
    /// Bridge state.
    pub state: BridgeState,
    /// Name/type identifier.
    pub name_hash: u32,
    /// Associated region ID (0 = global bridge).
    pub region_id: u32,
    /// MMIO base address for bridge control.
    pub mmio_base: u64,
}

impl Default for FpgaBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl FpgaBridge {
    /// Creates a disabled bridge.
    pub const fn new() -> Self {
        Self {
            id: 0,
            state: BridgeState::Disabled,
            name_hash: 0,
            region_id: 0,
            mmio_base: 0,
        }
    }

    /// Creates a bridge with the given ID and MMIO base.
    pub const fn with_id(id: u32, mmio_base: u64) -> Self {
        Self {
            id,
            state: BridgeState::Disabled,
            name_hash: 0,
            region_id: 0,
            mmio_base,
        }
    }

    /// Returns `true` if this bridge slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.mmio_base == 0
    }

    /// Enables the bridge (connects fabric).
    pub fn enable(&mut self) -> Result<()> {
        if self.state == BridgeState::Enabled {
            return Err(Error::AlreadyExists);
        }
        // In real code: write enable bit to MMIO control register
        self.state = BridgeState::Enabled;
        Ok(())
    }

    /// Disables the bridge (isolates fabric).
    pub fn disable(&mut self) -> Result<()> {
        if self.state == BridgeState::Disabled {
            return Ok(()); // Already disabled
        }
        self.state = BridgeState::Disabled;
        Ok(())
    }

    /// Freezes the bridge (for safe partial reconfiguration).
    pub fn freeze(&mut self) -> Result<()> {
        self.state = BridgeState::Frozen;
        Ok(())
    }

    /// Unfreezes the bridge after partial reconfiguration.
    pub fn unfreeze(&mut self) -> Result<()> {
        if self.state != BridgeState::Frozen {
            return Err(Error::InvalidArgument);
        }
        self.state = BridgeState::Enabled;
        Ok(())
    }
}

// -------------------------------------------------------------------
// RegionState
// -------------------------------------------------------------------

/// State of an FPGA region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegionState {
    /// Region is unconfigured.
    #[default]
    Unconfigured,
    /// Region is being programmed.
    Programming,
    /// Region is configured and operational.
    Configured,
    /// Region programming failed.
    Error,
}

// -------------------------------------------------------------------
// FpgaRegion
// -------------------------------------------------------------------

/// A reconfigurable region of the FPGA.
///
/// Regions represent portions of the FPGA fabric that can be
/// independently programmed (partial reconfiguration). Each region
/// is associated with one or more bridges.
pub struct FpgaRegion {
    /// Region identifier.
    pub id: u32,
    /// Region state.
    pub state: RegionState,
    /// Base address in the FPGA address space.
    pub base_addr: u64,
    /// Size of the region.
    pub size: usize,
    /// Associated bridge IDs.
    pub bridge_ids: [u32; MAX_BRIDGES],
    /// Number of associated bridges.
    pub bridge_count: usize,
    /// Whether this region supports partial reconfiguration.
    pub partial_reconfig: bool,
    /// Currently loaded bitstream ID (0 = none).
    pub loaded_bitstream_id: u32,
}

impl Default for FpgaRegion {
    fn default() -> Self {
        Self::new()
    }
}

impl FpgaRegion {
    /// Creates an empty region.
    pub const fn new() -> Self {
        Self {
            id: 0,
            state: RegionState::Unconfigured,
            base_addr: 0,
            size: 0,
            bridge_ids: [0u32; MAX_BRIDGES],
            bridge_count: 0,
            partial_reconfig: false,
            loaded_bitstream_id: 0,
        }
    }

    /// Creates a region with the given parameters.
    pub fn create(id: u32, base_addr: u64, size: usize, partial: bool) -> Self {
        Self {
            id,
            state: RegionState::Unconfigured,
            base_addr,
            size,
            bridge_ids: [0u32; MAX_BRIDGES],
            bridge_count: 0,
            partial_reconfig: partial,
            loaded_bitstream_id: 0,
        }
    }

    /// Returns `true` if this region slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0
    }

    /// Associates a bridge with this region.
    pub fn add_bridge(&mut self, bridge_id: u32) -> Result<()> {
        if self.bridge_count >= MAX_BRIDGES {
            return Err(Error::OutOfMemory);
        }
        self.bridge_ids[self.bridge_count] = bridge_id;
        self.bridge_count += 1;
        Ok(())
    }

    /// Marks the region as currently being programmed.
    pub fn begin_programming(&mut self) -> Result<()> {
        if self.state == RegionState::Programming {
            return Err(Error::Busy);
        }
        self.state = RegionState::Programming;
        Ok(())
    }

    /// Marks the region as configured.
    pub fn complete_programming(&mut self, bitstream_id: u32) {
        self.state = RegionState::Configured;
        self.loaded_bitstream_id = bitstream_id;
    }

    /// Marks the region with an error.
    pub fn mark_error(&mut self) {
        self.state = RegionState::Error;
    }

    /// Resets the region to unconfigured.
    pub fn reset(&mut self) {
        self.state = RegionState::Unconfigured;
        self.loaded_bitstream_id = 0;
    }
}

// -------------------------------------------------------------------
// FpgaOps — operation callbacks
// -------------------------------------------------------------------

/// Programming status returned by write operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteStatus {
    /// Data accepted, continue writing.
    Continue,
    /// All data written, finalize.
    Done,
    /// Write error.
    Error,
}

// -------------------------------------------------------------------
// FpgaManager
// -------------------------------------------------------------------

/// FPGA manager device.
///
/// Controls the programming lifecycle of an FPGA device: initializes
/// the programming interface, transfers bitstream data, and tracks
/// the device state through the state machine. Manages bridges and
/// regions for safe reconfiguration.
pub struct FpgaManager {
    /// Manager identifier.
    pub id: u32,
    /// Current state.
    pub state: FpgaState,
    /// MMIO base address for FPGA configuration interface.
    pub mmio_base: u64,
    /// FPGA vendor (hash of vendor name).
    pub vendor_hash: u32,
    /// Bridges managed by this FPGA.
    bridges: [FpgaBridge; MAX_BRIDGES],
    /// Number of bridges.
    bridge_count: usize,
    /// Regions managed by this FPGA.
    regions: [FpgaRegion; MAX_REGIONS],
    /// Number of regions.
    region_count: usize,
    /// Current bitstream being programmed (if any).
    current_bitstream: FpgaBitstream,
    /// Whether the FPGA is currently being programmed.
    programming: bool,
    /// Number of successful programming operations.
    pub program_count: u64,
    /// Number of failed programming operations.
    pub error_count: u64,
}

impl Default for FpgaManager {
    fn default() -> Self {
        Self::empty()
    }
}

impl FpgaManager {
    /// Creates an empty/inactive manager.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: FpgaState::Unknown,
            mmio_base: 0,
            vendor_hash: 0,
            bridges: [const { FpgaBridge::new() }; MAX_BRIDGES],
            bridge_count: 0,
            regions: [const { FpgaRegion::new() }; MAX_REGIONS],
            region_count: 0,
            current_bitstream: FpgaBitstream::new(),
            programming: false,
            program_count: 0,
            error_count: 0,
        }
    }

    /// Creates a new FPGA manager at the given MMIO base.
    pub fn new(id: u32, mmio_base: u64) -> Self {
        Self {
            id,
            state: FpgaState::PowerOff,
            mmio_base,
            vendor_hash: 0,
            bridges: [const { FpgaBridge::new() }; MAX_BRIDGES],
            bridge_count: 0,
            regions: [const { FpgaRegion::new() }; MAX_REGIONS],
            region_count: 0,
            current_bitstream: FpgaBitstream::new(),
            programming: false,
            program_count: 0,
            error_count: 0,
        }
    }

    /// Returns `true` if this manager is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.mmio_base == 0
    }

    /// Initializes the FPGA manager (power up, probe hardware).
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.state = FpgaState::PowerUp;
        Ok(())
    }

    // --- Bridge management ---

    /// Registers a bridge with this manager.
    pub fn add_bridge(&mut self, bridge: FpgaBridge) -> Result<usize> {
        if self.bridge_count >= MAX_BRIDGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.bridge_count;
        self.bridges[idx] = bridge;
        self.bridge_count += 1;
        Ok(idx)
    }

    /// Disables all bridges (preparation for programming).
    pub fn disable_bridges(&mut self) -> Result<()> {
        for i in 0..self.bridge_count {
            self.bridges[i].disable()?;
        }
        Ok(())
    }

    /// Enables all bridges (after programming).
    pub fn enable_bridges(&mut self) -> Result<()> {
        for i in 0..self.bridge_count {
            self.bridges[i].enable()?;
        }
        Ok(())
    }

    /// Freezes bridges for a specific region.
    pub fn freeze_region_bridges(&mut self, region_idx: usize) -> Result<()> {
        if region_idx >= self.region_count {
            return Err(Error::NotFound);
        }
        let bcount = self.regions[region_idx].bridge_count;
        // Collect bridge IDs first to avoid borrow issues
        let mut ids = [0u32; MAX_BRIDGES];
        for i in 0..bcount {
            ids[i] = self.regions[region_idx].bridge_ids[i];
        }
        for i in 0..bcount {
            let bid = ids[i];
            for j in 0..self.bridge_count {
                if self.bridges[j].id == bid {
                    self.bridges[j].freeze()?;
                }
            }
        }
        Ok(())
    }

    /// Unfreezes bridges for a specific region.
    pub fn unfreeze_region_bridges(&mut self, region_idx: usize) -> Result<()> {
        if region_idx >= self.region_count {
            return Err(Error::NotFound);
        }
        let bcount = self.regions[region_idx].bridge_count;
        let mut ids = [0u32; MAX_BRIDGES];
        for i in 0..bcount {
            ids[i] = self.regions[region_idx].bridge_ids[i];
        }
        for i in 0..bcount {
            let bid = ids[i];
            for j in 0..self.bridge_count {
                if self.bridges[j].id == bid {
                    self.bridges[j].unfreeze()?;
                }
            }
        }
        Ok(())
    }

    /// Returns a reference to a bridge by index.
    pub fn get_bridge(&self, index: usize) -> Option<&FpgaBridge> {
        if index < self.bridge_count {
            Some(&self.bridges[index])
        } else {
            None
        }
    }

    // --- Region management ---

    /// Adds a reconfigurable region.
    pub fn add_region(&mut self, region: FpgaRegion) -> Result<usize> {
        if self.region_count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.region_count;
        self.regions[idx] = region;
        self.region_count += 1;
        Ok(idx)
    }

    /// Returns a reference to a region by index.
    pub fn get_region(&self, index: usize) -> Option<&FpgaRegion> {
        if index < self.region_count {
            Some(&self.regions[index])
        } else {
            None
        }
    }

    /// Returns the number of regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    // --- Programming lifecycle ---

    /// Begins full FPGA programming.
    ///
    /// 1. Disables all bridges
    /// 2. Transitions to write-init state
    /// 3. Prepares the FPGA for bitstream data
    pub fn begin_programming(&mut self, bitstream: FpgaBitstream) -> Result<()> {
        if self.programming {
            return Err(Error::Busy);
        }
        if bitstream.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Disable bridges for safe reconfiguration
        self.disable_bridges()?;

        self.state = FpgaState::WriteInit;
        self.current_bitstream = bitstream;
        self.current_bitstream.bytes_written = 0;
        self.programming = true;
        Ok(())
    }

    /// Writes a chunk of bitstream data.
    ///
    /// Called repeatedly with successive data chunks until the
    /// entire bitstream has been transferred.
    pub fn write_data(&mut self, chunk_size: usize) -> Result<WriteStatus> {
        if !self.programming {
            return Err(Error::InvalidArgument);
        }

        if self.state == FpgaState::WriteInit {
            self.state = FpgaState::WriteBody;
        }

        if self.state != FpgaState::WriteBody {
            return Err(Error::InvalidArgument);
        }

        self.current_bitstream.bytes_written = self
            .current_bitstream
            .bytes_written
            .saturating_add(chunk_size);

        if self.current_bitstream.is_complete() {
            self.state = FpgaState::WriteComplete;
            Ok(WriteStatus::Done)
        } else {
            Ok(WriteStatus::Continue)
        }
    }

    /// Completes the programming operation.
    ///
    /// Re-enables bridges and transitions to Operating state.
    pub fn complete_programming(&mut self) -> Result<()> {
        if self.state != FpgaState::WriteComplete {
            self.error_count = self.error_count.saturating_add(1);
            self.state = FpgaState::Error;
            self.programming = false;
            return Err(Error::InvalidArgument);
        }

        // Re-enable bridges
        self.enable_bridges()?;

        self.state = FpgaState::Operating;
        self.programming = false;
        self.program_count = self.program_count.saturating_add(1);
        Ok(())
    }

    /// Aborts an in-progress programming operation.
    pub fn abort_programming(&mut self) -> Result<()> {
        if !self.programming {
            return Err(Error::InvalidArgument);
        }
        self.state = FpgaState::Error;
        self.programming = false;
        self.error_count = self.error_count.saturating_add(1);
        // Try to re-enable bridges
        let _ = self.enable_bridges();
        Ok(())
    }

    /// Begins partial reconfiguration of a specific region.
    pub fn begin_partial_reconfig(
        &mut self,
        region_idx: usize,
        bitstream: FpgaBitstream,
    ) -> Result<()> {
        if self.programming {
            return Err(Error::Busy);
        }
        if region_idx >= self.region_count {
            return Err(Error::NotFound);
        }
        if !self.regions[region_idx].partial_reconfig {
            return Err(Error::InvalidArgument);
        }

        self.freeze_region_bridges(region_idx)?;
        self.regions[region_idx].begin_programming()?;

        self.current_bitstream = bitstream;
        self.current_bitstream.bytes_written = 0;
        self.programming = true;
        self.state = FpgaState::WriteInit;
        Ok(())
    }

    /// Completes partial reconfiguration for a region.
    pub fn complete_partial_reconfig(&mut self, region_idx: usize) -> Result<()> {
        if region_idx >= self.region_count {
            return Err(Error::NotFound);
        }

        let bitstream_id = self.current_bitstream.id;
        self.regions[region_idx].complete_programming(bitstream_id);
        self.unfreeze_region_bridges(region_idx)?;

        self.programming = false;
        self.program_count = self.program_count.saturating_add(1);
        Ok(())
    }

    /// Returns the FPGA manager state.
    pub fn manager_state(&self) -> FpgaState {
        self.state
    }

    /// Returns the current bitstream progress (0-100).
    pub fn programming_progress(&self) -> u8 {
        self.current_bitstream.progress_percent()
    }

    /// Returns `true` if the FPGA is currently operating.
    pub fn is_operating(&self) -> bool {
        self.state == FpgaState::Operating
    }
}

// -------------------------------------------------------------------
// FpgaManagerRegistry
// -------------------------------------------------------------------

/// System-wide registry of FPGA managers.
pub struct FpgaManagerRegistry {
    /// Registered manager entries (MMIO base, ID).
    managers: [(u64, u32); MAX_MANAGERS],
    /// Number of registered managers.
    count: usize,
}

impl Default for FpgaManagerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FpgaManagerRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            managers: [(0, 0); MAX_MANAGERS],
            count: 0,
        }
    }

    /// Registers an FPGA manager.
    pub fn register(&mut self, id: u32, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_MANAGERS {
            return Err(Error::OutOfMemory);
        }
        for i in 0..self.count {
            if self.managers[i].1 == id {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.managers[idx] = (mmio_base, id);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the (mmio_base, id) at the given index.
    pub fn get(&self, index: usize) -> Option<(u64, u32)> {
        if index < self.count {
            Some(self.managers[index])
        } else {
            None
        }
    }

    /// Returns the number of registered managers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no managers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

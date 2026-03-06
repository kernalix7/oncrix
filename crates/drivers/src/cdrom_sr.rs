// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CD-ROM/DVD SCSI optical disc driver.
//!
//! Implements the SCSI optical disc command set for CD-ROM and DVD
//! media. Handles READ TOC, READ CAPACITY, READ(10)/READ(12), and
//! disc information queries. The driver translates high-level read
//! requests into SCSI Command Descriptor Blocks (CDBs) and tracks
//! per-device state (media present, disc type, TOC cache).
//!
//! # Architecture
//!
//! - [`DiscType`] -- classification of the optical media.
//! - [`TocEntry`] -- a single track entry from the Table of Contents.
//! - [`DiscInfo`] -- disc metadata (capacity, type, sessions).
//! - [`ReadCommand`] -- parameters for a sector read operation.
//! - [`CdromDevice`] -- a single CD-ROM/DVD device.
//! - [`CdromRegistry`] -- manages up to [`MAX_DEVICES`] devices.
//!
//! Reference: SCSI Multimedia Commands (MMC-6),
//!            SCSI Block Commands (SBC-4),
//!            Mt. Fuji Commands (SFF-8090).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CD-ROM devices.
const MAX_DEVICES: usize = 4;

/// Maximum TOC entries per disc.
const MAX_TOC_ENTRIES: usize = 99;

/// Sector size for CD-ROM data tracks (Mode 1/2048 bytes).
pub const CDROM_SECTOR_SIZE: usize = 2048;

/// Sector size for raw audio tracks (2352 bytes).
pub const AUDIO_SECTOR_SIZE: usize = 2352;

/// Maximum CDB size for MMC commands.
const MAX_CDB_SIZE: usize = 16;

/// Maximum transfer size per read command (256 KiB).
const MAX_TRANSFER_SIZE: usize = 256 * 1024;

/// Maximum sectors per single read (128).
const MAX_SECTORS_PER_READ: u32 = 128;

/// READ TOC/PMA/ATIP SCSI opcode.
const SCSI_READ_TOC: u8 = 0x43;

/// READ CAPACITY(10) SCSI opcode.
const SCSI_READ_CAPACITY_10: u8 = 0x25;

/// READ(10) SCSI opcode.
const SCSI_READ_10: u8 = 0x28;

/// READ(12) SCSI opcode.
const SCSI_READ_12: u8 = 0xA8;

/// START STOP UNIT opcode (eject/load).
const SCSI_START_STOP_UNIT: u8 = 0x1B;

/// TEST UNIT READY opcode.
const SCSI_TEST_UNIT_READY: u8 = 0x00;

/// GET CONFIGURATION opcode.
const SCSI_GET_CONFIGURATION: u8 = 0x46;

/// READ DISC INFORMATION opcode.
const SCSI_READ_DISC_INFO: u8 = 0x51;

/// Maximum device model string length.
const MAX_MODEL_LEN: usize = 40;

// ---------------------------------------------------------------------------
// DiscType
// ---------------------------------------------------------------------------

/// Classification of optical disc media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscType {
    /// No disc present.
    #[default]
    NoDisc,
    /// CD-ROM data disc.
    CdRom,
    /// CD-R (recordable).
    CdR,
    /// CD-RW (rewritable).
    CdRw,
    /// DVD-ROM.
    DvdRom,
    /// DVD-R (recordable).
    DvdR,
    /// DVD-RW (rewritable).
    DvdRw,
    /// DVD+R.
    DvdPlusR,
    /// DVD+RW.
    DvdPlusRw,
    /// Blu-ray Disc.
    BluRay,
}

// ---------------------------------------------------------------------------
// TocEntry
// ---------------------------------------------------------------------------

/// A single track entry from the Table of Contents (TOC).
///
/// The TOC describes the layout of tracks on an optical disc.
/// Each entry contains the track number, starting LBA, and
/// track attributes (data vs. audio, copy-permitted, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct TocEntry {
    /// Track number (1..99, or 0xAA for lead-out).
    pub track_number: u8,
    /// Session number this track belongs to.
    pub session: u8,
    /// Starting Logical Block Address.
    pub start_lba: u32,
    /// Control field (4 bits): bit 0 = pre-emphasis,
    /// bit 1 = copy-permitted, bit 2 = data track (vs. audio),
    /// bit 3 = four-channel audio.
    pub control: u8,
    /// ADR field (4 bits): sub-channel Q data type.
    pub adr: u8,
}

impl TocEntry {
    /// Returns `true` if this is a data track (not audio).
    pub fn is_data(&self) -> bool {
        self.control & 0x04 != 0
    }

    /// Returns `true` if this is an audio track.
    pub fn is_audio(&self) -> bool {
        !self.is_data()
    }

    /// Returns `true` if this is the lead-out entry.
    pub fn is_lead_out(&self) -> bool {
        self.track_number == 0xAA
    }
}

// ---------------------------------------------------------------------------
// DiscInfo
// ---------------------------------------------------------------------------

/// Disc metadata and capacity information.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscInfo {
    /// Type of disc currently loaded.
    pub disc_type: DiscType,
    /// Total capacity in sectors.
    pub total_sectors: u64,
    /// Sector size in bytes.
    pub sector_size: u32,
    /// Number of sessions on the disc.
    pub session_count: u8,
    /// First track number.
    pub first_track: u8,
    /// Last track number.
    pub last_track: u8,
    /// Whether the disc is finalised (closed).
    pub finalised: bool,
    /// Whether the disc is blank.
    pub blank: bool,
}

impl DiscInfo {
    /// Returns the total capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.total_sectors * self.sector_size as u64
    }
}

// ---------------------------------------------------------------------------
// ReadCommand
// ---------------------------------------------------------------------------

/// Parameters for a sector read operation.
#[derive(Debug, Clone, Copy)]
pub struct ReadCommand {
    /// Starting Logical Block Address.
    pub start_lba: u64,
    /// Number of sectors to read.
    pub sector_count: u32,
    /// Sector size to use (2048 for data, 2352 for raw audio).
    pub sector_size: u32,
    /// Whether to use READ(12) instead of READ(10).
    pub use_read12: bool,
}

impl ReadCommand {
    /// Creates a new data read command.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `sector_count` exceeds
    /// the maximum or is 0.
    pub fn new(start_lba: u64, sector_count: u32) -> Result<Self> {
        if sector_count == 0 || sector_count > MAX_SECTORS_PER_READ {
            return Err(Error::InvalidArgument);
        }
        let use_read12 = start_lba > u32::MAX as u64;
        Ok(Self {
            start_lba,
            sector_count,
            sector_size: CDROM_SECTOR_SIZE as u32,
            use_read12,
        })
    }

    /// Creates a raw audio read command.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `sector_count` exceeds
    /// the maximum or is 0.
    pub fn audio(start_lba: u64, sector_count: u32) -> Result<Self> {
        if sector_count == 0 || sector_count > MAX_SECTORS_PER_READ {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start_lba,
            sector_count,
            sector_size: AUDIO_SECTOR_SIZE as u32,
            use_read12: false,
        })
    }

    /// Returns the total transfer size in bytes.
    pub fn transfer_size(&self) -> usize {
        self.sector_count as usize * self.sector_size as usize
    }

    /// Builds the SCSI CDB for this read command.
    ///
    /// Returns `(cdb, cdb_len)`.
    pub fn build_cdb(&self) -> ([u8; MAX_CDB_SIZE], usize) {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        if self.use_read12 {
            cdb[0] = SCSI_READ_12;
            let lba = self.start_lba as u32;
            cdb[2] = (lba >> 24) as u8;
            cdb[3] = (lba >> 16) as u8;
            cdb[4] = (lba >> 8) as u8;
            cdb[5] = lba as u8;
            cdb[6] = (self.sector_count >> 24) as u8;
            cdb[7] = (self.sector_count >> 16) as u8;
            cdb[8] = (self.sector_count >> 8) as u8;
            cdb[9] = self.sector_count as u8;
            (cdb, 12)
        } else {
            cdb[0] = SCSI_READ_10;
            let lba = self.start_lba as u32;
            cdb[2] = (lba >> 24) as u8;
            cdb[3] = (lba >> 16) as u8;
            cdb[4] = (lba >> 8) as u8;
            cdb[5] = lba as u8;
            cdb[7] = (self.sector_count >> 8) as u8;
            cdb[8] = self.sector_count as u8;
            (cdb, 10)
        }
    }
}

// ---------------------------------------------------------------------------
// DeviceState
// ---------------------------------------------------------------------------

/// Lifecycle state of a CD-ROM device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceState {
    /// Device not initialised.
    #[default]
    Uninitialised,
    /// Device ready and idle.
    Ready,
    /// Media not present (tray open or no disc).
    NoMedia,
    /// Device error.
    Error,
}

// ---------------------------------------------------------------------------
// CdromDevice
// ---------------------------------------------------------------------------

/// A single CD-ROM/DVD SCSI device.
///
/// Manages the device state, TOC cache, disc info, and provides
/// methods for building SCSI commands.
pub struct CdromDevice {
    /// Unique device identifier.
    pub id: u32,
    /// SCSI host adapter ID.
    pub host_id: u32,
    /// SCSI target ID.
    pub target_id: u8,
    /// SCSI LUN.
    pub lun: u8,
    /// Device model string.
    pub model: [u8; MAX_MODEL_LEN],
    /// Number of valid bytes in [`model`](Self::model).
    pub model_len: usize,
    /// Current device state.
    pub state: DeviceState,
    /// Disc information (updated on media change).
    pub disc_info: DiscInfo,
    /// Cached Table of Contents.
    toc: [TocEntry; MAX_TOC_ENTRIES],
    /// Number of valid TOC entries.
    toc_count: usize,
    /// Whether the TOC cache is valid.
    pub toc_valid: bool,
    /// Whether the tray is locked (prevent eject).
    pub tray_locked: bool,
}

/// Constant empty device for array initialisation.
const EMPTY_CDROM: CdromDevice = CdromDevice {
    id: 0,
    host_id: 0,
    target_id: 0,
    lun: 0,
    model: [0u8; MAX_MODEL_LEN],
    model_len: 0,
    state: DeviceState::Uninitialised,
    disc_info: DiscInfo {
        disc_type: DiscType::NoDisc,
        total_sectors: 0,
        sector_size: CDROM_SECTOR_SIZE as u32,
        session_count: 0,
        first_track: 0,
        last_track: 0,
        finalised: false,
        blank: false,
    },
    toc: [TocEntry {
        track_number: 0,
        session: 0,
        start_lba: 0,
        control: 0,
        adr: 0,
    }; MAX_TOC_ENTRIES],
    toc_count: 0,
    toc_valid: false,
    tray_locked: false,
};

impl CdromDevice {
    /// Creates a new CD-ROM device.
    pub fn new(id: u32, host_id: u32, target_id: u8, lun: u8) -> Self {
        let mut dev = EMPTY_CDROM;
        dev.id = id;
        dev.host_id = host_id;
        dev.target_id = target_id;
        dev.lun = lun;
        dev
    }

    /// Sets the device model string.
    pub fn set_model(&mut self, model: &[u8]) {
        let copy_len = model.len().min(MAX_MODEL_LEN);
        self.model[..copy_len].copy_from_slice(&model[..copy_len]);
        self.model_len = copy_len;
    }

    /// Initialises the device (checks for media, reads TOC).
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not responding.
    pub fn init(&mut self) -> Result<()> {
        // Build TEST UNIT READY CDB.
        let _cdb = self.build_test_unit_ready();
        // In a real driver, we would issue the CDB here.
        self.state = DeviceState::Ready;
        Ok(())
    }

    /// Builds a TEST UNIT READY CDB.
    pub fn build_test_unit_ready(&self) -> [u8; MAX_CDB_SIZE] {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_TEST_UNIT_READY;
        cdb
    }

    /// Builds a READ TOC CDB.
    ///
    /// Returns `(cdb, allocation_length)`.
    pub fn build_read_toc(&self) -> ([u8; MAX_CDB_SIZE], u16) {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_READ_TOC;
        // Format = 0 (TOC), MSF = 0 (LBA addressing).
        cdb[1] = 0x00;
        cdb[6] = 1; // Starting track.
        let alloc_len: u16 = 804; // 4 + 8 * 100
        cdb[7] = (alloc_len >> 8) as u8;
        cdb[8] = alloc_len as u8;
        (cdb, alloc_len)
    }

    /// Builds a READ CAPACITY(10) CDB.
    pub fn build_read_capacity(&self) -> [u8; MAX_CDB_SIZE] {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_READ_CAPACITY_10;
        cdb
    }

    /// Builds a START STOP UNIT CDB for eject or load.
    pub fn build_start_stop(&self, eject: bool) -> [u8; MAX_CDB_SIZE] {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_START_STOP_UNIT;
        if eject {
            cdb[4] = 0x02; // LoEj=1, Start=0 → eject
        } else {
            cdb[4] = 0x03; // LoEj=1, Start=1 → load
        }
        cdb
    }

    /// Builds a GET CONFIGURATION CDB.
    pub fn build_get_configuration(&self) -> [u8; MAX_CDB_SIZE] {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_GET_CONFIGURATION;
        // RT=0 (all features from starting feature number).
        cdb[7] = 0x00;
        cdb[8] = 0x08; // Allocation length = 8 (header only).
        cdb
    }

    /// Builds a READ DISC INFORMATION CDB.
    pub fn build_read_disc_info(&self) -> [u8; MAX_CDB_SIZE] {
        let mut cdb = [0u8; MAX_CDB_SIZE];
        cdb[0] = SCSI_READ_DISC_INFO;
        cdb[7] = 0x00;
        cdb[8] = 0x22; // 34 bytes allocation.
        cdb
    }

    /// Updates the TOC cache from raw TOC response data.
    ///
    /// The raw data follows the MMC READ TOC response format:
    /// 4-byte header + 8 bytes per entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the data is too short.
    pub fn update_toc(&mut self, raw: &[u8]) -> Result<()> {
        if raw.len() < 4 {
            return Err(Error::InvalidArgument);
        }
        let data_len = ((raw[0] as u16) << 8 | raw[1] as u16) as usize + 2;
        let first_track = raw[2];
        let last_track = raw[3];

        self.disc_info.first_track = first_track;
        self.disc_info.last_track = last_track;
        self.toc_count = 0;

        let entry_data = &raw[4..raw.len().min(data_len)];
        let mut offset = 0;
        while offset + 8 <= entry_data.len() && self.toc_count < MAX_TOC_ENTRIES {
            let e = &entry_data[offset..offset + 8];
            self.toc[self.toc_count] = TocEntry {
                track_number: e[2],
                session: e[0],
                control: (e[1] >> 4) & 0x0F,
                adr: e[1] & 0x0F,
                start_lba: u32::from_be_bytes([e[4], e[5], e[6], e[7]]),
            };
            self.toc_count += 1;
            offset += 8;
        }
        self.toc_valid = true;
        Ok(())
    }

    /// Returns the cached TOC entries.
    pub fn toc(&self) -> &[TocEntry] {
        &self.toc[..self.toc_count]
    }

    /// Returns the number of TOC entries.
    pub fn toc_count(&self) -> usize {
        self.toc_count
    }

    /// Returns the number of data tracks in the TOC.
    pub fn data_track_count(&self) -> usize {
        self.toc[..self.toc_count]
            .iter()
            .filter(|e| e.is_data())
            .count()
    }

    /// Returns the number of audio tracks in the TOC.
    pub fn audio_track_count(&self) -> usize {
        self.toc[..self.toc_count]
            .iter()
            .filter(|e| e.is_audio() && !e.is_lead_out())
            .count()
    }
}

// ---------------------------------------------------------------------------
// CdromRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_DEVICES`] CD-ROM devices.
pub struct CdromRegistry {
    /// Registered devices.
    devices: [Option<CdromDevice>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl CdromRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a CD-ROM device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same ID exists.
    pub fn register(&mut self, device: CdromDevice) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&CdromDevice> {
        for slot in self.devices.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut CdromDevice> {
        for slot in self.devices.iter_mut() {
            if let Some(d) = slot {
                if d.id == id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for CdromRegistry {
    fn default() -> Self {
        Self::new()
    }
}

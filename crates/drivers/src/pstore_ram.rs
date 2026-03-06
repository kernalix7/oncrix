// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Persistent store (pstore) RAM backend driver.
//!
//! Provides RAM-backed persistent storage for crash logs, console
//! output, and FTRACE data that survives warm reboots by using
//! reserved memory regions. The driver writes data into fixed-size
//! zones within the reserved region and tags each entry with a
//! header so the data can be recovered after a reset.
//!
//! # Architecture
//!
//! - [`PstoreType`] -- classification of stored data (dmesg, console,
//!   ftrace, pmsg).
//! - [`DmesgEntry`] -- a single dmesg log entry with header and data.
//! - [`RamZone`] -- a contiguous memory zone within the reserved
//!   region, dedicated to one [`PstoreType`].
//! - [`PstoreRam`] -- the main driver managing zones, writes, and
//!   recovery.
//! - [`PstoreRamRegistry`] -- manages up to [`MAX_STORES`] pstore
//!   instances.
//!
//! # Memory Layout
//!
//! ```text
//! Reserved DRAM region (e.g., last 1 MiB of RAM)
//! ┌───────────────────────────────────────────────┐
//! │  Zone 0: dmesg          (256 KiB)             │
//! │  Zone 1: console        (64 KiB)              │
//! │  Zone 2: ftrace         (64 KiB)              │
//! │  Zone 3: pmsg           (64 KiB)              │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! Reference: Linux `fs/pstore/ram.c`, `include/linux/pstore_ram.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pstore RAM instances.
const MAX_STORES: usize = 4;

/// Maximum number of zones per pstore instance.
const MAX_ZONES: usize = 8;

/// Maximum number of dmesg entries per zone.
const MAX_ENTRIES_PER_ZONE: usize = 64;

/// Maximum size of a single dmesg entry's data payload in bytes.
const MAX_ENTRY_DATA: usize = 512;

/// Entry header magic value for validation.
const ENTRY_MAGIC: u32 = 0x5053_544F; // "PSTO"

/// Zone header magic value for validation.
const ZONE_MAGIC: u32 = 0x5A4F_4E45; // "ZONE"

/// Maximum zone name length.
const MAX_ZONE_NAME_LEN: usize = 16;

/// Default dmesg zone size in bytes (256 KiB).
const DEFAULT_DMESG_SIZE: usize = 256 * 1024;

/// Default console zone size in bytes (64 KiB).
const DEFAULT_CONSOLE_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// PstoreType
// ---------------------------------------------------------------------------

/// Classification of persistent store data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PstoreType {
    /// Kernel dmesg log (crash/oops messages).
    #[default]
    Dmesg,
    /// Console output capture.
    Console,
    /// Ftrace function trace data.
    Ftrace,
    /// User-space pmsg data (Android pstore).
    Pmsg,
}

// ---------------------------------------------------------------------------
// EntryFlags
// ---------------------------------------------------------------------------

/// Flags for a dmesg entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EntryFlags(pub u32);

impl EntryFlags {
    /// Entry contains a kernel oops.
    pub const OOPS: u32 = 1 << 0;
    /// Entry contains a kernel panic.
    pub const PANIC: u32 = 1 << 1;
    /// Entry has been compressed.
    pub const COMPRESSED: u32 = 1 << 2;
    /// Entry has been read/recovered.
    pub const RECOVERED: u32 = 1 << 3;

    /// Creates new entry flags.
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns `true` if the given flag bit is set.
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

// ---------------------------------------------------------------------------
// DmesgEntry
// ---------------------------------------------------------------------------

/// A single dmesg log entry stored in a pstore zone.
///
/// Each entry has a fixed-size header followed by a variable-length
/// data payload. The header includes a magic number for validation,
/// a sequence number, timestamp, and length field.
#[derive(Clone, Copy)]
pub struct DmesgEntry {
    /// Magic number for entry validation.
    pub magic: u32,
    /// Entry sequence number (monotonically increasing).
    pub sequence: u64,
    /// Timestamp in nanoseconds since boot.
    pub timestamp_ns: u64,
    /// Type of data in this entry.
    pub entry_type: PstoreType,
    /// Entry flags.
    pub flags: EntryFlags,
    /// Length of valid data in [`data`](Self::data).
    pub data_len: usize,
    /// Data payload.
    pub data: [u8; MAX_ENTRY_DATA],
}

/// Constant empty entry for array initialisation.
const EMPTY_ENTRY: DmesgEntry = DmesgEntry {
    magic: 0,
    sequence: 0,
    timestamp_ns: 0,
    entry_type: PstoreType::Dmesg,
    flags: EntryFlags(0),
    data_len: 0,
    data: [0u8; MAX_ENTRY_DATA],
};

impl DmesgEntry {
    /// Creates a new entry with the given data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds
    /// [`MAX_ENTRY_DATA`].
    pub fn new(
        sequence: u64,
        timestamp_ns: u64,
        entry_type: PstoreType,
        flags: EntryFlags,
        data: &[u8],
    ) -> Result<Self> {
        if data.len() > MAX_ENTRY_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut entry = EMPTY_ENTRY;
        entry.magic = ENTRY_MAGIC;
        entry.sequence = sequence;
        entry.timestamp_ns = timestamp_ns;
        entry.entry_type = entry_type;
        entry.flags = flags;
        entry.data_len = data.len();
        entry.data[..data.len()].copy_from_slice(data);
        Ok(entry)
    }

    /// Returns `true` if this entry has a valid magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == ENTRY_MAGIC
    }

    /// Returns the data payload as a byte slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Marks this entry as recovered.
    pub fn mark_recovered(&mut self) {
        self.flags.0 |= EntryFlags::RECOVERED;
    }
}

impl core::fmt::Debug for DmesgEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmesgEntry")
            .field("magic", &self.magic)
            .field("sequence", &self.sequence)
            .field("timestamp_ns", &self.timestamp_ns)
            .field("entry_type", &self.entry_type)
            .field("flags", &self.flags)
            .field("data_len", &self.data_len)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// RamZone
// ---------------------------------------------------------------------------

/// A contiguous memory zone within the reserved region.
///
/// Each zone is dedicated to one [`PstoreType`] and stores entries
/// in a circular buffer fashion. When the zone is full, the oldest
/// entry is overwritten.
pub struct RamZone {
    /// Zone magic number for validation.
    pub magic: u32,
    /// Zone name.
    pub name: [u8; MAX_ZONE_NAME_LEN],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Type of data stored in this zone.
    pub zone_type: PstoreType,
    /// Physical base address of this zone in reserved memory.
    pub phys_base: u64,
    /// Size of this zone in bytes.
    pub size: usize,
    /// Entries stored in this zone.
    entries: [DmesgEntry; MAX_ENTRIES_PER_ZONE],
    /// Number of valid entries.
    entry_count: usize,
    /// Write pointer (index of next entry to write).
    write_ptr: usize,
    /// Whether the zone has wrapped around.
    pub wrapped: bool,
    /// Total number of entries ever written.
    pub total_written: u64,
}

/// Constant empty zone for array initialisation.
const EMPTY_ZONE: RamZone = RamZone {
    magic: 0,
    name: [0u8; MAX_ZONE_NAME_LEN],
    name_len: 0,
    zone_type: PstoreType::Dmesg,
    phys_base: 0,
    size: 0,
    entries: [EMPTY_ENTRY; MAX_ENTRIES_PER_ZONE],
    entry_count: 0,
    write_ptr: 0,
    wrapped: false,
    total_written: 0,
};

impl RamZone {
    /// Creates a new RAM zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or
    /// `size` is 0.
    pub fn new(name: &[u8], zone_type: PstoreType, phys_base: u64, size: usize) -> Result<Self> {
        if name.is_empty() || size == 0 {
            return Err(Error::InvalidArgument);
        }
        let copy_len = name.len().min(MAX_ZONE_NAME_LEN);
        let mut name_buf = [0u8; MAX_ZONE_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        Ok(Self {
            magic: ZONE_MAGIC,
            name: name_buf,
            name_len: copy_len,
            zone_type,
            phys_base,
            size,
            entries: [EMPTY_ENTRY; MAX_ENTRIES_PER_ZONE],
            entry_count: 0,
            write_ptr: 0,
            wrapped: false,
            total_written: 0,
        })
    }

    /// Writes an entry to this zone.
    ///
    /// If the zone is full, overwrites the oldest entry (circular).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the entry is not valid.
    pub fn write_entry(&mut self, entry: DmesgEntry) -> Result<()> {
        if !entry.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.write_ptr] = entry;
        self.write_ptr += 1;
        if self.write_ptr >= MAX_ENTRIES_PER_ZONE {
            self.write_ptr = 0;
            self.wrapped = true;
        }
        if self.entry_count < MAX_ENTRIES_PER_ZONE {
            self.entry_count += 1;
        }
        self.total_written += 1;
        Ok(())
    }

    /// Reads the entry at the given index.
    ///
    /// Index 0 is the oldest valid entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn read_entry(&self, index: usize) -> Result<&DmesgEntry> {
        if index >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let actual = if self.wrapped {
            (self.write_ptr + index) % MAX_ENTRIES_PER_ZONE
        } else {
            index
        };
        Ok(&self.entries[actual])
    }

    /// Returns the number of valid entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns `true` if this zone has a valid magic number.
    pub fn is_valid(&self) -> bool {
        self.magic == ZONE_MAGIC
    }

    /// Clears all entries in this zone.
    pub fn clear(&mut self) {
        self.entries = [EMPTY_ENTRY; MAX_ENTRIES_PER_ZONE];
        self.entry_count = 0;
        self.write_ptr = 0;
        self.wrapped = false;
    }
}

// ---------------------------------------------------------------------------
// PstoreRam
// ---------------------------------------------------------------------------

/// Persistent store RAM backend driver.
///
/// Manages a set of RAM zones for storing crash logs, console output,
/// and trace data. Each zone corresponds to a [`PstoreType`] and
/// stores entries in a circular buffer.
pub struct PstoreRam {
    /// Unique instance identifier.
    pub id: u32,
    /// Physical base address of the reserved memory region.
    pub region_base: u64,
    /// Total size of the reserved memory region in bytes.
    pub region_size: usize,
    /// RAM zones.
    zones: [RamZone; MAX_ZONES],
    /// Number of configured zones.
    zone_count: usize,
    /// Global sequence counter for entries.
    sequence: u64,
    /// Whether this instance is initialised and active.
    pub active: bool,
}

impl PstoreRam {
    /// Creates a new pstore RAM driver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `region_size` is 0.
    pub fn new(id: u32, region_base: u64, region_size: usize) -> Result<Self> {
        if region_size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            id,
            region_base,
            region_size,
            zones: [EMPTY_ZONE; MAX_ZONES],
            zone_count: 0,
            sequence: 0,
            active: false,
        })
    }

    /// Initialises the pstore with a default zone layout.
    ///
    /// Creates zones for dmesg, console, ftrace, and pmsg if the
    /// reserved region is large enough.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the region is too small.
    pub fn init(&mut self) -> Result<()> {
        let min_size = DEFAULT_DMESG_SIZE + DEFAULT_CONSOLE_SIZE * 3;
        if self.region_size < min_size {
            return Err(Error::OutOfMemory);
        }

        let mut offset = self.region_base;

        // Dmesg zone.
        let dmesg = RamZone::new(b"dmesg", PstoreType::Dmesg, offset, DEFAULT_DMESG_SIZE)?;
        self.zones[0] = dmesg;
        offset += DEFAULT_DMESG_SIZE as u64;

        // Console zone.
        let console = RamZone::new(
            b"console",
            PstoreType::Console,
            offset,
            DEFAULT_CONSOLE_SIZE,
        )?;
        self.zones[1] = console;
        offset += DEFAULT_CONSOLE_SIZE as u64;

        // Ftrace zone.
        let ftrace = RamZone::new(b"ftrace", PstoreType::Ftrace, offset, DEFAULT_CONSOLE_SIZE)?;
        self.zones[2] = ftrace;
        offset += DEFAULT_CONSOLE_SIZE as u64;

        // Pmsg zone.
        let pmsg = RamZone::new(b"pmsg", PstoreType::Pmsg, offset, DEFAULT_CONSOLE_SIZE)?;
        self.zones[3] = pmsg;

        self.zone_count = 4;
        self.active = true;
        Ok(())
    }

    /// Writes data to the pstore.
    ///
    /// Finds the appropriate zone by type and writes a new entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no zone of the given type exists,
    /// or [`Error::Busy`] if the driver is not active.
    pub fn write(
        &mut self,
        pstore_type: PstoreType,
        timestamp_ns: u64,
        flags: EntryFlags,
        data: &[u8],
    ) -> Result<u64> {
        if !self.active {
            return Err(Error::Busy);
        }
        self.sequence += 1;
        let seq = self.sequence;
        let zone = self.find_zone_mut(pstore_type).ok_or(Error::NotFound)?;
        let entry = DmesgEntry::new(seq, timestamp_ns, pstore_type, flags, data)?;
        zone.write_entry(entry)?;
        Ok(seq)
    }

    /// Reads an entry from a zone by type and index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone does not exist, or
    /// [`Error::InvalidArgument`] if the index is out of range.
    pub fn read(&self, pstore_type: PstoreType, index: usize) -> Result<&DmesgEntry> {
        let zone = self.find_zone(pstore_type).ok_or(Error::NotFound)?;
        zone.read_entry(index)
    }

    /// Returns the number of entries in a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone does not exist.
    pub fn entry_count(&self, pstore_type: PstoreType) -> Result<usize> {
        let zone = self.find_zone(pstore_type).ok_or(Error::NotFound)?;
        Ok(zone.entry_count())
    }

    /// Clears all entries in a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the zone does not exist.
    pub fn clear(&mut self, pstore_type: PstoreType) -> Result<()> {
        let zone = self.find_zone_mut(pstore_type).ok_or(Error::NotFound)?;
        zone.clear();
        Ok(())
    }

    /// Returns the number of configured zones.
    pub fn zone_count(&self) -> usize {
        self.zone_count
    }

    // -- internal ---------------------------------------------------------

    fn find_zone(&self, ptype: PstoreType) -> Option<&RamZone> {
        self.zones[..self.zone_count]
            .iter()
            .find(|z| z.zone_type == ptype)
    }

    fn find_zone_mut(&mut self, ptype: PstoreType) -> Option<&mut RamZone> {
        self.zones[..self.zone_count]
            .iter_mut()
            .find(|z| z.zone_type == ptype)
    }
}

// ---------------------------------------------------------------------------
// PstoreRamRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_STORES`] pstore RAM instances.
pub struct PstoreRamRegistry {
    /// Registered instances.
    stores: [Option<PstoreRam>; MAX_STORES],
    /// Number of registered instances.
    count: usize,
}

impl PstoreRamRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            stores: [const { None }; MAX_STORES],
            count: 0,
        }
    }

    /// Registers a pstore RAM instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if an instance with the same ID exists.
    pub fn register(&mut self, store: PstoreRam) -> Result<()> {
        for slot in self.stores.iter().flatten() {
            if slot.id == store.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.stores.iter_mut() {
            if slot.is_none() {
                *slot = Some(store);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to an instance by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&PstoreRam> {
        for slot in self.stores.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to an instance by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut PstoreRam> {
        for slot in self.stores.iter_mut() {
            if let Some(s) = slot {
                if s.id == id {
                    return Ok(s);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered instances.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no instances are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PstoreRamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

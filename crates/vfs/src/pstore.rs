// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Persistent storage crash-log filesystem (pstore).
//!
//! Provides a virtual filesystem that persists kernel crash logs, console
//! output, and panic messages to non-volatile storage. On boot, records from
//! the previous session are exposed as files under the mount point.
//!
//! # Design
//!
//! - [`PstoreBackend`] trait — storage backend (RAM / EFI variable / NVRAM).
//! - [`PstoreRecordType`] — dmesg, console, panic, pmsg, ftrace, mce.
//! - [`PstoreRecord`] — 4 KiB fixed-size record with metadata header.
//! - [`PstoreFs`] — filesystem instance managing up to 64 records.
//! - Panic hook calls `write_record` to persist the crash log.
//! - `enumerate_records` scans the backend on mount to populate the table.
//!
//! # Mount path
//!
//! ```text
//! mount -t pstore - /sys/fs/pstore
//! ```
//!
//! Files appear as `<type>-<id>` (e.g. `dmesg-0`, `console-1`).
//!
//! Reference: Linux `fs/pstore/`, `include/linux/pstore.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pstore records in the table.
pub const MAX_PSTORE_RECORDS: usize = 64;

/// Size of each pstore record payload in bytes (4 KiB).
pub const PSTORE_RECORD_SIZE: usize = 4096;

/// Size of the record header (type tag + id + timestamp + flags).
pub const PSTORE_HEADER_SIZE: usize = 32;

/// Maximum usable payload per record after the header.
pub const PSTORE_PAYLOAD_SIZE: usize = PSTORE_RECORD_SIZE - PSTORE_HEADER_SIZE;

/// Maximum length of a backend name.
pub const PSTORE_BACKEND_NAME_LEN: usize = 32;

/// Maximum number of registered backends.
pub const MAX_PSTORE_BACKENDS: usize = 4;

// ---------------------------------------------------------------------------
// PstoreRecordType
// ---------------------------------------------------------------------------

/// Type of data stored in a pstore record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PstoreRecordType {
    /// Kernel message buffer (dmesg) — most recent ring-buffer contents.
    Dmesg = 0,
    /// Serial / virtual console output during the crash.
    Console = 1,
    /// Full panic message and stack trace.
    Panic = 2,
    /// Persistent message log (`/dev/pmsg0`).
    Pmsg = 3,
    /// Ftrace ring-buffer snapshot.
    Ftrace = 4,
    /// Machine-check exception log.
    Mce = 5,
    /// Unknown / vendor-defined record.
    Unknown = 0xFF,
}

impl PstoreRecordType {
    /// Convert a u32 tag to a record type.
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Dmesg,
            1 => Self::Console,
            2 => Self::Panic,
            3 => Self::Pmsg,
            4 => Self::Ftrace,
            5 => Self::Mce,
            _ => Self::Unknown,
        }
    }

    /// Return the short name string used in file names (e.g. `"dmesg"`).
    pub fn name_str(self) -> &'static str {
        match self {
            Self::Dmesg => "dmesg",
            Self::Console => "console",
            Self::Panic => "panic",
            Self::Pmsg => "pmsg",
            Self::Ftrace => "ftrace",
            Self::Mce => "mce",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// PstoreFlags
// ---------------------------------------------------------------------------

/// Flags describing how a record was captured.
#[derive(Debug, Clone, Copy, Default)]
pub struct PstoreFlags(pub u32);

impl PstoreFlags {
    /// Set if the system was in a compressed-crash path.
    pub const COMPRESSED: u32 = 1 << 0;
    /// Set if this is the last fragment of a multi-part record.
    pub const LAST_PART: u32 = 1 << 1;
    /// Set if ECC correction was applied to the stored data.
    pub const ECC_CORRECTED: u32 = 1 << 2;

    /// Return `true` if the compressed flag is set.
    pub fn compressed(self) -> bool {
        self.0 & Self::COMPRESSED != 0
    }

    /// Return `true` if this is the final fragment.
    pub fn is_last_part(self) -> bool {
        self.0 & Self::LAST_PART != 0
    }
}

// ---------------------------------------------------------------------------
// PstoreRecord
// ---------------------------------------------------------------------------

/// A single pstore record (4 KiB fixed-size, stored in NV storage).
///
/// The first [`PSTORE_HEADER_SIZE`] bytes contain metadata; the remainder
/// is the payload (crash log text, binary data, etc.).
#[derive(Clone, Copy)]
pub struct PstoreRecord {
    /// Record type.
    pub record_type: PstoreRecordType,
    /// Unique record ID within the type namespace.
    pub id: u64,
    /// Monotonic timestamp (nanoseconds) when the record was written.
    pub timestamp_ns: u64,
    /// Payload byte count (≤ [`PSTORE_PAYLOAD_SIZE`]).
    pub payload_len: u16,
    /// Flags.
    pub flags: PstoreFlags,
    /// Payload buffer.
    pub payload: [u8; PSTORE_PAYLOAD_SIZE],
    /// Whether this slot is occupied.
    pub active: bool,
}

impl PstoreRecord {
    const fn empty() -> Self {
        Self {
            record_type: PstoreRecordType::Unknown,
            id: 0,
            timestamp_ns: 0,
            payload_len: 0,
            flags: PstoreFlags(0),
            payload: [0u8; PSTORE_PAYLOAD_SIZE],
            active: false,
        }
    }

    /// Return the payload as a byte slice.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Write `data` into the payload buffer, truncating if necessary.
    ///
    /// Returns the number of bytes actually stored.
    pub fn write_payload(&mut self, data: &[u8]) -> usize {
        let copy_len = data.len().min(PSTORE_PAYLOAD_SIZE);
        self.payload[..copy_len].copy_from_slice(&data[..copy_len]);
        self.payload_len = copy_len as u16;
        copy_len
    }
}

impl core::fmt::Debug for PstoreRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PstoreRecord")
            .field("type", &self.record_type)
            .field("id", &self.id)
            .field("payload_len", &self.payload_len)
            .field("active", &self.active)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PstoreBackend trait
// ---------------------------------------------------------------------------

/// Trait implemented by pstore storage backends.
///
/// A backend abstracts the underlying non-volatile storage: battery-backed
/// RAM, EFI variables, flash, or a simple test buffer.
pub trait PstoreBackend {
    /// Human-readable name for this backend (e.g. `"ramoops"`, `"efi"`).
    fn name(&self) -> &[u8];

    /// Total number of record slots provided by this backend.
    fn total_slots(&self) -> usize;

    /// Read one record from slot `slot_idx` into `record`.
    ///
    /// Returns `Ok(true)` if the slot contains valid data, `Ok(false)` if
    /// the slot is empty or erased.
    fn read_slot(&self, slot_idx: usize, record: &mut PstoreRecord) -> Result<bool>;

    /// Write `record` to slot `slot_idx`, erasing it first if required.
    fn write_slot(&mut self, slot_idx: usize, record: &PstoreRecord) -> Result<()>;

    /// Erase slot `slot_idx`, making it available for reuse.
    fn erase_slot(&mut self, slot_idx: usize) -> Result<()>;
}

// ---------------------------------------------------------------------------
// RamBackend — battery-backed / persistent-RAM backend
// ---------------------------------------------------------------------------

/// Simple in-DRAM pstore backend (for testing or early-boot use).
///
/// In a real system this would be placed in a memory region marked as
/// persistent across warm reboots (e.g. via `memmap=` or a reserved-memory
/// node in the device tree).
pub struct RamBackend {
    /// Name bytes.
    name: [u8; PSTORE_BACKEND_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Slot storage.
    slots: [PstoreRecord; MAX_PSTORE_RECORDS],
    /// Number of usable slots.
    slot_count: usize,
}

impl RamBackend {
    /// Create a RAM-based backend with `slot_count` slots (≤ 64).
    pub fn new(slot_count: usize) -> Result<Self> {
        if slot_count > MAX_PSTORE_RECORDS {
            return Err(Error::InvalidArgument);
        }
        const EMPTY: PstoreRecord = PstoreRecord::empty();
        let name_bytes = b"ramoops";
        let mut name = [0u8; PSTORE_BACKEND_NAME_LEN];
        name[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(Self {
            name,
            name_len: name_bytes.len(),
            slots: [EMPTY; MAX_PSTORE_RECORDS],
            slot_count,
        })
    }
}

impl PstoreBackend for RamBackend {
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn total_slots(&self) -> usize {
        self.slot_count
    }

    fn read_slot(&self, slot_idx: usize, record: &mut PstoreRecord) -> Result<bool> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        if self.slots[slot_idx].active {
            *record = self.slots[slot_idx];
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn write_slot(&mut self, slot_idx: usize, record: &PstoreRecord) -> Result<()> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[slot_idx] = *record;
        self.slots[slot_idx].active = true;
        Ok(())
    }

    fn erase_slot(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[slot_idx] = PstoreRecord::empty();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EfiBackend — EFI variable storage backend
// ---------------------------------------------------------------------------

/// EFI variable pstore backend (stub — requires platform EFI runtime calls).
///
/// In a full implementation `read_slot` / `write_slot` would call
/// `EFI_RUNTIME_SERVICES.GetVariable` / `SetVariable`. This stub
/// models the same in-memory layout as `RamBackend` for portability.
pub struct EfiBackend {
    name: [u8; PSTORE_BACKEND_NAME_LEN],
    name_len: usize,
    slots: [PstoreRecord; MAX_PSTORE_RECORDS],
    slot_count: usize,
}

impl EfiBackend {
    /// Create an EFI backend with `slot_count` variable slots.
    pub fn new(slot_count: usize) -> Result<Self> {
        if slot_count > MAX_PSTORE_RECORDS {
            return Err(Error::InvalidArgument);
        }
        const EMPTY: PstoreRecord = PstoreRecord::empty();
        let name_bytes = b"efi";
        let mut name = [0u8; PSTORE_BACKEND_NAME_LEN];
        name[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(Self {
            name,
            name_len: name_bytes.len(),
            slots: [EMPTY; MAX_PSTORE_RECORDS],
            slot_count,
        })
    }
}

impl PstoreBackend for EfiBackend {
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    fn total_slots(&self) -> usize {
        self.slot_count
    }

    fn read_slot(&self, slot_idx: usize, record: &mut PstoreRecord) -> Result<bool> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        if self.slots[slot_idx].active {
            *record = self.slots[slot_idx];
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn write_slot(&mut self, slot_idx: usize, record: &PstoreRecord) -> Result<()> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[slot_idx] = *record;
        self.slots[slot_idx].active = true;
        Ok(())
    }

    fn erase_slot(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        self.slots[slot_idx] = PstoreRecord::empty();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PstoreFs
// ---------------------------------------------------------------------------

/// Pstore filesystem instance.
///
/// On mount, `enumerate_records` is called to scan the backend and populate
/// the in-memory record table. The panic hook calls `write_record` to persist
/// crash data before the system halts/reboots.
pub struct PstoreFs {
    /// In-memory record table populated from the backend.
    records: [PstoreRecord; MAX_PSTORE_RECORDS],
    /// Number of live records.
    record_count: usize,
    /// Monotonically increasing record ID counter.
    next_id: u64,
    /// Whether the filesystem is mounted.
    pub mounted: bool,
    /// Backend slot index at which the next write will land.
    next_slot: usize,
    /// Total backend slots (set during `enumerate_records`).
    backend_slots: usize,
}

impl PstoreFs {
    /// Create a new pstore filesystem instance (unmounted).
    pub const fn new() -> Self {
        const EMPTY: PstoreRecord = PstoreRecord::empty();
        Self {
            records: [EMPTY; MAX_PSTORE_RECORDS],
            record_count: 0,
            next_id: 0,
            mounted: false,
            next_slot: 0,
            backend_slots: 0,
        }
    }

    // --- Lifecycle ----------------------------------------------------------

    /// Enumerate all records from `backend` and mount the filesystem.
    ///
    /// Reads every slot in the backend; slots that contain valid data are
    /// copied into the in-memory table. Must be called once on mount.
    pub fn enumerate_records(&mut self, backend: &dyn PstoreBackend) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        self.backend_slots = backend.total_slots();
        self.next_slot = 0;
        self.record_count = 0;

        const EMPTY: PstoreRecord = PstoreRecord::empty();
        let mut tmp = EMPTY;

        for slot in 0..self.backend_slots {
            let has_data = backend.read_slot(slot, &mut tmp)?;
            if has_data && self.record_count < MAX_PSTORE_RECORDS {
                self.records[self.record_count] = tmp;
                if tmp.id >= self.next_id {
                    self.next_id = tmp.id + 1;
                }
                self.record_count += 1;
                // Advance next_slot past the last occupied slot.
                if slot >= self.next_slot {
                    self.next_slot = (slot + 1) % self.backend_slots.max(1);
                }
            }
        }
        self.mounted = true;
        Ok(())
    }

    /// Unmount the pstore filesystem.
    pub fn umount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.mounted = false;
        Ok(())
    }

    // --- Panic hook ---------------------------------------------------------

    /// Persist a crash record to the backend (called from panic handler).
    ///
    /// Allocates the next available backend slot, writes the record,
    /// and returns the assigned record ID. This function is designed to be
    /// callable from an interrupt / panic context (no allocation, no panic).
    pub fn write_record(
        &mut self,
        backend: &mut dyn PstoreBackend,
        record_type: PstoreRecordType,
        payload: &[u8],
        timestamp_ns: u64,
        flags: PstoreFlags,
    ) -> Result<u64> {
        if self.backend_slots == 0 {
            return Err(Error::InvalidArgument);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let copy_len = payload.len().min(PSTORE_PAYLOAD_SIZE);
        let mut payload_buf = [0u8; PSTORE_PAYLOAD_SIZE];
        payload_buf[..copy_len].copy_from_slice(&payload[..copy_len]);

        let record = PstoreRecord {
            record_type,
            id,
            timestamp_ns,
            payload_len: copy_len as u16,
            flags,
            payload: payload_buf,
            active: true,
        };

        // Find a free slot in the backend (wrap around).
        let start_slot = self.next_slot;
        let mut wrote = false;
        for i in 0..self.backend_slots {
            let slot = (start_slot + i) % self.backend_slots;
            // Try to read — if the slot is empty or readable, use it.
            const EMPTY: PstoreRecord = PstoreRecord::empty();
            let mut tmp = EMPTY;
            let occupied = backend.read_slot(slot, &mut tmp).unwrap_or(false);
            if !occupied {
                backend.write_slot(slot, &record)?;
                self.next_slot = (slot + 1) % self.backend_slots;
                wrote = true;
                break;
            }
        }
        if !wrote {
            // All slots full — overwrite oldest (slot at next_slot).
            let slot = self.next_slot;
            backend.write_slot(slot, &record)?;
            self.next_slot = (slot + 1) % self.backend_slots;
        }

        // Also add to in-memory table if space exists.
        if self.record_count < MAX_PSTORE_RECORDS {
            self.records[self.record_count] = record;
            self.record_count += 1;
        }

        Ok(id)
    }

    // --- File read ----------------------------------------------------------

    /// Read a record's payload into `buf`.
    ///
    /// `record_type` and `id` identify the record. Returns the number of
    /// bytes copied.
    pub fn read_record(
        &self,
        record_type: PstoreRecordType,
        id: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        for rec in &self.records[..self.record_count] {
            if rec.active && rec.record_type == record_type && rec.id == id {
                let copy_len = (rec.payload_len as usize).min(buf.len());
                buf[..copy_len].copy_from_slice(&rec.payload[..copy_len]);
                return Ok(copy_len);
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a record by type and ID (e.g. after user-space reads and
    /// acknowledges it).
    pub fn remove_record(
        &mut self,
        backend: &mut dyn PstoreBackend,
        record_type: PstoreRecordType,
        id: u64,
    ) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        // Find and remove from in-memory table.
        let mut found_idx = None;
        for (i, rec) in self.records[..self.record_count].iter().enumerate() {
            if rec.active && rec.record_type == record_type && rec.id == id {
                found_idx = Some(i);
                break;
            }
        }
        let idx = found_idx.ok_or(Error::NotFound)?;
        // Remove by shifting remaining entries down.
        for i in idx..self.record_count - 1 {
            self.records[i] = self.records[i + 1];
        }
        self.records[self.record_count - 1] = PstoreRecord::empty();
        self.record_count -= 1;

        // Erase from backend by scanning all slots.
        for slot in 0..self.backend_slots {
            const EMPTY: PstoreRecord = PstoreRecord::empty();
            let mut tmp = EMPTY;
            if backend.read_slot(slot, &mut tmp).unwrap_or(false)
                && tmp.record_type == record_type
                && tmp.id == id
            {
                backend.erase_slot(slot)?;
                break;
            }
        }
        Ok(())
    }

    // --- Directory listing --------------------------------------------------

    /// Populate `out_types` and `out_ids` with the types and IDs of all live
    /// records.
    ///
    /// Returns the number of records written (limited by `out_types.len()`).
    pub fn list_records(
        &self,
        out_types: &mut [PstoreRecordType],
        out_ids: &mut [u64],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let limit = out_types.len().min(out_ids.len());
        let mut count = 0;
        for rec in &self.records[..self.record_count] {
            if rec.active && count < limit {
                out_types[count] = rec.record_type;
                out_ids[count] = rec.id;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Build the filename for a record into `buf` (format: `"<type>-<id>"`).
    ///
    /// Returns the number of bytes written.
    pub fn record_filename(record_type: PstoreRecordType, id: u64, buf: &mut [u8]) -> usize {
        let type_name = record_type.name_str().as_bytes();
        let copy_type = type_name.len().min(buf.len());
        buf[..copy_type].copy_from_slice(&type_name[..copy_type]);
        let mut pos = copy_type;
        if pos < buf.len() {
            buf[pos] = b'-';
            pos += 1;
        }
        // Write decimal id.
        let mut tmp = [0u8; 20];
        let mut id_pos = tmp.len();
        let mut v = id;
        if v == 0 {
            if pos < buf.len() {
                buf[pos] = b'0';
                pos += 1;
            }
        } else {
            while v > 0 {
                id_pos -= 1;
                tmp[id_pos] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            let digits = &tmp[id_pos..];
            let copy_d = digits.len().min(buf.len() - pos);
            buf[pos..pos + copy_d].copy_from_slice(&digits[..copy_d]);
            pos += copy_d;
        }
        pos
    }

    /// Number of live records.
    pub fn record_count(&self) -> usize {
        self.record_count
    }
}

impl Default for PstoreFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PstoreFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PstoreFs")
            .field("mounted", &self.mounted)
            .field("record_count", &self.record_count)
            .field("next_id", &self.next_id)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Global pstore filesystem instance.
static mut PSTORE_FS: Option<PstoreFs> = None;

/// Initialise the global pstore filesystem.
///
/// # Safety
///
/// Must be called exactly once during single-threaded kernel initialisation.
pub unsafe fn pstore_init() {
    // SAFETY: Single-threaded init; no concurrent access.
    unsafe {
        *core::ptr::addr_of_mut!(PSTORE_FS) = Some(PstoreFs::new());
    }
}

/// Obtain a shared reference to the global pstore filesystem.
pub fn pstore_get() -> Option<&'static PstoreFs> {
    // SAFETY: Read-only after init; never moved.
    unsafe { (*core::ptr::addr_of!(PSTORE_FS)).as_ref() }
}

/// Obtain a mutable reference to the global pstore filesystem.
///
/// # Safety
///
/// The caller must ensure no other reference is live.
pub unsafe fn pstore_get_mut() -> Option<&'static mut PstoreFs> {
    // SAFETY: Caller guarantees exclusive access.
    unsafe { (*core::ptr::addr_of_mut!(PSTORE_FS)).as_mut() }
}

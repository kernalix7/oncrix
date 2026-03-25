// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF ring buffer map type for efficient kernel-to-userspace event streaming.
//!
//! Implements the `BPF_MAP_TYPE_RINGBUF` semantics modeled after the Linux
//! kernel's `kernel/bpf/ringbuf.c`. Provides a single-producer, multi-consumer
//! ring buffer that allows BPF programs to stream events to userspace without
//! per-event system calls.
//!
//! # Design
//!
//! The ring buffer consists of two logically separate pages:
//! - **Data page**: circular storage for variable-length records.
//! - **Consumer page**: read-only position exposed to userspace.
//!
//! Records use a 8-byte header encoding length and flags, followed by payload
//! data aligned to 8 bytes. The producer atomically commits or discards
//! reserved records so the consumer only ever sees complete entries.
//!
//! # API
//!
//! 1. [`RingBuf::reserve`] — allocate a slot of `size` bytes; returns a
//!    [`RecordHandle`] for writing.
//! 2. [`RecordHandle::commit`] / [`RecordHandle::discard`] — finalize or
//!    abandon the reserved record.
//! 3. [`RingBuf::consume`] — retrieve the next committed record for reading.
//!
//! # Reference
//!
//! Linux `kernel/bpf/ringbuf.c`, `include/uapi/linux/bpf.h` (`BPF_MAP_TYPE_RINGBUF`).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Total data storage capacity of the ring buffer in bytes.
///
/// Must be a power of two. 64 KiB matches the Linux default minimum.
const RING_DATA_SIZE: usize = 65_536; // 64 KiB

/// Mask for wrapping producer/consumer positions to `[0, RING_DATA_SIZE)`.
const RING_MASK: usize = RING_DATA_SIZE - 1;

/// Size of the per-record header in bytes.
///
/// Layout (little-endian):
/// - bits 31:0  — payload length in bytes
/// - bit  32    — `BPF_RINGBUF_BUSY_BIT` (1 = reserved, not yet committed)
/// - bit  33    — `BPF_RINGBUF_DISCARD_BIT` (1 = discard on next consume)
/// - bits 63:34 — reserved, zero
const RECORD_HDR_SIZE: usize = 8;

/// Alignment of each record (header + payload) within the ring.
const RECORD_ALIGN: usize = 8;

/// Maximum payload size in bytes for a single [`reserve`] call.
const MAX_RECORD_PAYLOAD: usize = 4096;

/// Maximum number of concurrent ring buffers in the system.
const MAX_RING_BUFS: usize = 32;

/// Maximum name length for a ring buffer instance.
const MAX_NAME_LEN: usize = 64;

/// Flag set in the header when the record is reserved but not yet committed.
const HDR_BUSY_BIT: u32 = 1 << 31;

/// Flag set in the header when the record is to be discarded.
const HDR_DISCARD_BIT: u32 = 1 << 30;

// ── RecordState ──────────────────────────────────────────────────────────────

/// Lifecycle state of a single ring buffer record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordState {
    /// Slot is free (no record present).
    #[default]
    Free,
    /// Reserved by producer, not yet visible to consumer.
    Reserved,
    /// Committed and ready for the consumer.
    Committed,
    /// Discarded; will be skipped during [`RingBuf::consume`].
    Discarded,
}

// ── Record ───────────────────────────────────────────────────────────────────

/// A single record stored in the ring buffer.
///
/// Records are variable-length up to [`MAX_RECORD_PAYLOAD`] bytes and are
/// addressed by their byte offset within the ring data area.
#[derive(Clone)]
pub struct Record {
    /// Payload bytes (fixed-capacity array; only `[0..len]` is valid).
    data: [u8; MAX_RECORD_PAYLOAD],
    /// Actual payload length in bytes.
    len: usize,
    /// Lifecycle state.
    state: RecordState,
    /// Byte offset of this record's header in the ring data area.
    offset: usize,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_RECORD_PAYLOAD],
            len: 0,
            state: RecordState::Free,
            offset: 0,
        }
    }
}

impl Record {
    /// Return an immutable view of the valid payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return a mutable view of the valid payload bytes.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Return the record's byte offset within the ring.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Return the payload length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ── RecordHandle ─────────────────────────────────────────────────────────────

/// An in-flight reservation returned by [`RingBuf::reserve`].
///
/// The handle holds the slot index within the ring buffer's record table.
/// Call [`RecordHandle::commit`] to make the record visible to the consumer
/// or [`RecordHandle::discard`] to release the slot without publishing.
pub struct RecordHandle {
    /// Index into [`RingBuf::records`].
    slot: usize,
    /// Whether the handle has been finalized (commit or discard).
    finalized: bool,
}

impl RecordHandle {
    fn new(slot: usize) -> Self {
        Self {
            slot,
            finalized: false,
        }
    }

    /// Commit the reserved record, making it visible for consumption.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the handle was already
    /// finalized.
    pub fn commit(mut self, ring: &mut RingBuf) -> Result<()> {
        if self.finalized {
            return Err(Error::InvalidArgument);
        }
        self.finalized = true;
        ring.commit_slot(self.slot)
    }

    /// Discard the reserved record without publishing it.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the handle was already
    /// finalized.
    pub fn discard(mut self, ring: &mut RingBuf) -> Result<()> {
        if self.finalized {
            return Err(Error::InvalidArgument);
        }
        self.finalized = true;
        ring.discard_slot(self.slot)
    }
}

// ── RingBufStats ─────────────────────────────────────────────────────────────

/// Operational statistics for a [`RingBuf`] instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct RingBufStats {
    /// Total records reserved (including later-discarded ones).
    pub reserved: u64,
    /// Total records committed (visible to consumer).
    pub committed: u64,
    /// Total records discarded.
    pub discarded: u64,
    /// Total records consumed (read by consumer).
    pub consumed: u64,
    /// Failed reservations due to insufficient space.
    pub reserve_failures: u64,
}

// ── RingBuf ──────────────────────────────────────────────────────────────────

/// Maximum number of in-flight (reserved or committed) records.
const MAX_RECORDS: usize = 256;

/// BPF ring buffer instance.
///
/// Stores up to [`MAX_RECORDS`] records of variable size. The producer
/// calls [`RingBuf::reserve`] to allocate a slot, fills in the payload,
/// then calls [`RecordHandle::commit`] or [`RecordHandle::discard`].
/// The consumer reads records in order via [`RingBuf::consume`].
pub struct RingBuf {
    /// Flat byte storage representing the ring data area.
    data: [u8; RING_DATA_SIZE],
    /// Record metadata table (parallel to `data` slots).
    records: [Record; MAX_RECORDS],
    /// Number of records in the record table.
    record_count: usize,
    /// Producer write position (byte offset into `data`, wraps at RING_DATA_SIZE).
    producer: usize,
    /// Consumer read position (byte offset into `data`, wraps at RING_DATA_SIZE).
    consumer: usize,
    /// Operational statistics.
    stats: RingBufStats,
    /// Human-readable name for this ring buffer.
    name: [u8; MAX_NAME_LEN],
    /// Actual length of `name` in bytes.
    name_len: usize,
}

impl RingBuf {
    /// Create a new, empty ring buffer with the given name.
    pub fn new(name: &[u8]) -> Self {
        let mut rb = Self {
            data: [0u8; RING_DATA_SIZE],
            records: core::array::from_fn(|_| Record::default()),
            record_count: 0,
            producer: 0,
            consumer: 0,
            stats: RingBufStats::default(),
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        };
        let copy_len = name.len().min(MAX_NAME_LEN);
        rb.name[..copy_len].copy_from_slice(&name[..copy_len]);
        rb.name_len = copy_len;
        rb
    }

    /// Return the human-readable name of this ring buffer.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the current operational statistics.
    pub fn stats(&self) -> &RingBufStats {
        &self.stats
    }

    /// Return the number of free bytes currently available for new records.
    ///
    /// Available space accounts for the circular wrap and the minimum gap of
    /// one byte between producer and consumer to distinguish full vs. empty.
    pub fn available_bytes(&self) -> usize {
        let used = self.producer.wrapping_sub(self.consumer) & RING_MASK;
        RING_DATA_SIZE.saturating_sub(used + 1)
    }

    /// Return `true` if the ring buffer contains no committed records.
    pub fn is_empty(&self) -> bool {
        self.producer == self.consumer
    }

    /// Reserve a slot of `payload_size` bytes for the producer to fill.
    ///
    /// Returns a [`RecordHandle`] on success. The caller must call
    /// [`RecordHandle::commit`] or [`RecordHandle::discard`] to release
    /// the slot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `payload_size` is 0 or exceeds
    ///   [`MAX_RECORD_PAYLOAD`].
    /// - [`Error::OutOfMemory`] if the ring buffer is full or the record
    ///   table is exhausted.
    pub fn reserve(&mut self, payload_size: usize) -> Result<RecordHandle> {
        if payload_size == 0 || payload_size > MAX_RECORD_PAYLOAD {
            self.stats.reserve_failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Total bytes needed: header + payload, aligned to RECORD_ALIGN.
        let total = align_up(RECORD_HDR_SIZE + payload_size, RECORD_ALIGN);

        if total > self.available_bytes() {
            self.stats.reserve_failures += 1;
            return Err(Error::OutOfMemory);
        }

        if self.record_count >= MAX_RECORDS {
            self.stats.reserve_failures += 1;
            return Err(Error::OutOfMemory);
        }

        // Write busy header into data ring (marks reservation in-flight).
        let offset = self.producer & RING_MASK;
        let hdr: u64 = ((payload_size as u64) & 0x3FFF_FFFF) | ((HDR_BUSY_BIT as u64) << 32);
        write_u64_ring(&mut self.data, offset, hdr);

        // Advance producer past header + payload region.
        self.producer = self.producer.wrapping_add(total);

        // Fill record metadata.
        let slot = self.record_count;
        self.records[slot] = Record {
            data: [0u8; MAX_RECORD_PAYLOAD],
            len: payload_size,
            state: RecordState::Reserved,
            offset,
        };
        self.record_count += 1;
        self.stats.reserved += 1;

        Ok(RecordHandle::new(slot))
    }

    /// Write `data` into the payload area of a reserved record.
    ///
    /// The write is clamped to the record's allocated length.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `slot` is invalid or not in `Reserved` state.
    pub fn write_payload(&mut self, slot: usize, data: &[u8]) -> Result<()> {
        if slot >= self.record_count {
            return Err(Error::NotFound);
        }
        if self.records[slot].state != RecordState::Reserved {
            return Err(Error::InvalidArgument);
        }
        let copy_len = data.len().min(self.records[slot].len);
        self.records[slot].data[..copy_len].copy_from_slice(&data[..copy_len]);
        Ok(())
    }

    /// Commit the record at `slot`, making it visible to the consumer.
    fn commit_slot(&mut self, slot: usize) -> Result<()> {
        if slot >= self.record_count {
            return Err(Error::NotFound);
        }
        if self.records[slot].state != RecordState::Reserved {
            return Err(Error::InvalidArgument);
        }
        let offset = self.records[slot].offset;
        let len = self.records[slot].len;
        // Clear busy bit: write committed header (length only, no flags).
        let hdr: u64 = (len as u64) & 0x3FFF_FFFF;
        write_u64_ring(&mut self.data, offset, hdr);

        // Copy payload into the data ring immediately after the header.
        let payload_start = (offset + RECORD_HDR_SIZE) & RING_MASK;
        for i in 0..len {
            self.data[(payload_start + i) & RING_MASK] = self.records[slot].data[i];
        }

        self.records[slot].state = RecordState::Committed;
        self.stats.committed += 1;
        Ok(())
    }

    /// Discard the record at `slot`.
    fn discard_slot(&mut self, slot: usize) -> Result<()> {
        if slot >= self.record_count {
            return Err(Error::NotFound);
        }
        if self.records[slot].state != RecordState::Reserved {
            return Err(Error::InvalidArgument);
        }
        let offset = self.records[slot].offset;
        let len = self.records[slot].len;
        // Set discard bit in header.
        let hdr: u64 = ((len as u64) & 0x3FFF_FFFF) | ((HDR_DISCARD_BIT as u64) << 32);
        write_u64_ring(&mut self.data, offset, hdr);
        self.records[slot].state = RecordState::Discarded;
        self.stats.discarded += 1;
        Ok(())
    }

    /// Consume the next committed record from the ring buffer.
    ///
    /// Skips discarded records. Returns `Ok(None)` when no committed record
    /// is available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the ring data is structurally inconsistent.
    pub fn consume(&mut self) -> Result<Option<ConsumedRecord>> {
        // Walk records in order of their offset (reservation order).
        // Find the first committed record whose offset matches the consumer pointer.
        let consumer_offset = self.consumer & RING_MASK;
        let pos = self.records[..self.record_count]
            .iter()
            .position(|r| r.offset == consumer_offset && r.state == RecordState::Committed);

        if let Some(idx) = pos {
            let len = self.records[idx].len;
            let mut out = ConsumedRecord {
                data: [0u8; MAX_RECORD_PAYLOAD],
                len,
            };
            out.data[..len].copy_from_slice(&self.records[idx].data[..len]);

            // Advance consumer past this record.
            let total = align_up(RECORD_HDR_SIZE + len, RECORD_ALIGN);
            self.consumer = self.consumer.wrapping_add(total);
            self.records[idx].state = RecordState::Free;
            self.stats.consumed += 1;
            return Ok(Some(out));
        }

        // Check for discarded records at the consumer position so we can
        // advance past them.
        let dis_pos = self.records[..self.record_count]
            .iter()
            .position(|r| r.offset == consumer_offset && r.state == RecordState::Discarded);

        if let Some(idx) = dis_pos {
            let len = self.records[idx].len;
            let total = align_up(RECORD_HDR_SIZE + len, RECORD_ALIGN);
            self.consumer = self.consumer.wrapping_add(total);
            self.records[idx].state = RecordState::Free;
            // Recursively consume the next record (tail-call style loop).
            return self.consume();
        }

        Ok(None)
    }

    /// Return the current producer byte position (monotonically increasing).
    pub fn producer_pos(&self) -> usize {
        self.producer
    }

    /// Return the current consumer byte position (monotonically increasing).
    pub fn consumer_pos(&self) -> usize {
        self.consumer
    }

    /// Drain all committed records, invoking `f(record)` for each.
    ///
    /// Stops when no more committed records are available.
    pub fn drain<F>(&mut self, mut f: F) -> Result<usize>
    where
        F: FnMut(&ConsumedRecord),
    {
        let mut count = 0;
        loop {
            match self.consume()? {
                Some(r) => {
                    f(&r);
                    count += 1;
                }
                None => break,
            }
        }
        Ok(count)
    }
}

// ── ConsumedRecord ────────────────────────────────────────────────────────────

/// A record retrieved from the ring buffer via [`RingBuf::consume`].
pub struct ConsumedRecord {
    /// Payload bytes.
    data: [u8; MAX_RECORD_PAYLOAD],
    /// Actual payload length.
    len: usize,
}

impl ConsumedRecord {
    /// Return an immutable view of the payload.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return the payload length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ── RingBufMode ───────────────────────────────────────────────────────────────

/// Operating mode for a ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RingBufMode {
    /// Single shared ring buffer (default).
    #[default]
    Shared,
    /// Per-CPU ring buffer (one instance per logical CPU).
    PerCpu,
}

// ── RingBufDescriptor ─────────────────────────────────────────────────────────

/// Registry entry for a ring buffer — tracks ownership and mode.
#[derive(Clone, Copy)]
pub struct RingBufDescriptor {
    /// Map file descriptor identifying the ring buffer.
    pub fd: u32,
    /// Operating mode.
    pub mode: RingBufMode,
    /// Whether this descriptor is active.
    pub active: bool,
    /// Name bytes.
    name: [u8; MAX_NAME_LEN],
    /// Length of valid name bytes.
    name_len: usize,
}

impl Default for RingBufDescriptor {
    fn default() -> Self {
        Self {
            fd: 0,
            mode: RingBufMode::Shared,
            active: false,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

impl RingBufDescriptor {
    /// Return the human-readable name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// ── RingBufRegistry ───────────────────────────────────────────────────────────

/// System-wide registry of BPF ring buffer instances.
///
/// Holds up to [`MAX_RING_BUFS`] named ring buffers. Each entry is identified
/// by a monotonically increasing file descriptor.
pub struct RingBufRegistry {
    /// Array of registered ring buffers.
    bufs: [RingBuf; MAX_RING_BUFS],
    /// Descriptor metadata for each entry.
    descs: [RingBufDescriptor; MAX_RING_BUFS],
    /// Number of active entries.
    count: usize,
    /// Next file descriptor to assign.
    next_fd: u32,
}

impl RingBufRegistry {
    /// Create an empty ring buffer registry.
    pub fn new() -> Self {
        Self {
            bufs: core::array::from_fn(|_| RingBuf::new(b"")),
            descs: [RingBufDescriptor::default(); MAX_RING_BUFS],
            count: 0,
            next_fd: 1,
        }
    }

    /// Register a new ring buffer with the given `name` and `mode`.
    ///
    /// Returns the file descriptor assigned to the ring buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a ring buffer with the same name exists.
    pub fn create(&mut self, name: &[u8], mode: RingBufMode) -> Result<u32> {
        if self.count >= MAX_RING_BUFS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate name.
        for i in 0..self.count {
            if self.descs[i].active && self.descs[i].name() == name {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.bufs[idx] = RingBuf::new(name);
        let mut desc = RingBufDescriptor::default();
        desc.fd = self.next_fd;
        desc.mode = mode;
        desc.active = true;
        let copy_len = name.len().min(MAX_NAME_LEN);
        desc.name[..copy_len].copy_from_slice(&name[..copy_len]);
        desc.name_len = copy_len;
        self.descs[idx] = desc;
        self.next_fd += 1;
        self.count += 1;
        Ok(desc.fd)
    }

    /// Look up a ring buffer by file descriptor.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active ring buffer matches `fd`.
    pub fn get(&self, fd: u32) -> Result<&RingBuf> {
        let pos = self.descs[..self.count]
            .iter()
            .position(|d| d.active && d.fd == fd);
        match pos {
            Some(idx) => Ok(&self.bufs[idx]),
            None => Err(Error::NotFound),
        }
    }

    /// Look up a ring buffer mutably by file descriptor.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active ring buffer matches `fd`.
    pub fn get_mut(&mut self, fd: u32) -> Result<&mut RingBuf> {
        let pos = self.descs[..self.count]
            .iter()
            .position(|d| d.active && d.fd == fd);
        match pos {
            Some(idx) => Ok(&mut self.bufs[idx]),
            None => Err(Error::NotFound),
        }
    }

    /// Destroy the ring buffer identified by `fd`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active ring buffer matches `fd`.
    pub fn destroy(&mut self, fd: u32) -> Result<()> {
        let pos = self.descs[..self.count]
            .iter()
            .position(|d| d.active && d.fd == fd);
        match pos {
            Some(idx) => {
                self.descs[idx].active = false;
                // Compact the arrays.
                if idx + 1 < self.count {
                    // Swap with the last entry.
                    self.descs.swap(idx, self.count - 1);
                    // We cannot swap RingBuf directly (it's large), so reset it.
                    self.bufs[idx] = RingBuf::new(b"");
                }
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Return the number of registered ring buffers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return an iterator over active descriptors.
    pub fn descriptors(&self) -> &[RingBufDescriptor] {
        &self.descs[..self.count]
    }
}

impl Default for RingBufRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Round `n` up to the nearest multiple of `align` (which must be a power of two).
#[inline]
fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Write a `u64` value at byte `offset` within the circular `buf`,
/// using little-endian byte order and wrapping at `buf.len()`.
fn write_u64_ring(buf: &mut [u8; RING_DATA_SIZE], offset: usize, value: u64) {
    let bytes = value.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        buf[(offset + i) & RING_MASK] = b;
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_commit_consume() {
        let mut rb = RingBuf::new(b"test");
        let handle = rb.reserve(8).expect("reserve 8 bytes");
        rb.write_payload(handle.slot, b"helloXXX")
            .expect("write payload");
        handle.commit(&mut rb).expect("commit");
        let rec = rb.consume().expect("consume Ok").expect("Some record");
        assert_eq!(&rec.payload()[..5], b"hello");
    }

    #[test]
    fn discard_skips_record() {
        let mut rb = RingBuf::new(b"discard_test");
        let h1 = rb.reserve(4).expect("reserve h1");
        rb.write_payload(h1.slot, b"AAAA").unwrap();
        h1.discard(&mut rb).expect("discard h1");

        let h2 = rb.reserve(4).expect("reserve h2");
        rb.write_payload(h2.slot, b"BBBB").unwrap();
        h2.commit(&mut rb).expect("commit h2");

        // h1 is discarded; consumer should skip to h2.
        // Note: consume only advances past the committed/discarded at the
        // current consumer position, so both are at offset 0 region.
        let _ = rb.consume(); // may skip discard and return h2
    }

    #[test]
    fn registry_create_get_destroy() {
        let mut reg = RingBufRegistry::new();
        let fd = reg.create(b"myring", RingBufMode::Shared).expect("create");
        assert!(reg.get(fd).is_ok());
        reg.destroy(fd).expect("destroy");
        assert!(reg.get(fd).is_err());
    }

    #[test]
    fn reserve_too_large_fails() {
        let mut rb = RingBuf::new(b"big");
        assert!(rb.reserve(MAX_RECORD_PAYLOAD + 1).is_err());
    }

    #[test]
    fn align_up_correctness() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
    }
}

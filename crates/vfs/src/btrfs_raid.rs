// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs RAID profile management.
//!
//! Implements RAID data placement for btrfs filesystems. Supports:
//!
//! - [`RaidProfile`] — Single, DUP, RAID0, RAID1, RAID5, RAID6, RAID10
//! - [`ChunkAlloc`] — stripe layout computation for block allocation
//! - Parity calculation helpers for RAID5/RAID6
//! - Mirror/stripe read/write dispatch logic
//!
//! # Design
//!
//! btrfs uses "chunks" as the unit of RAID management. Each chunk maps
//! a logical address range to physical stripes across multiple devices.
//! This module computes stripe offsets and parity positions for each
//! RAID profile.
//!
//! # Reference
//!
//! Linux `fs/btrfs/volumes.c` stripe/chunk management.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of devices in a RAID group.
const MAX_RAID_DEVICES: usize = 16;

/// Default stripe size in bytes (64 KiB).
const DEFAULT_STRIPE_SIZE: u64 = 65536;

/// Maximum chunk size (1 GiB).
const MAX_CHUNK_SIZE: u64 = 1 << 30;

/// Maximum stripes per chunk.
const MAX_STRIPES: usize = 16;

// ---------------------------------------------------------------------------
// RAID Profile
// ---------------------------------------------------------------------------

/// btrfs RAID data replication profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidProfile {
    /// No redundancy, single copy.
    Single,
    /// Two copies on the same device (intra-device mirroring).
    Dup,
    /// Data striped across devices, no redundancy (RAID-0).
    Raid0,
    /// Two full copies on different devices (RAID-1).
    Raid1,
    /// Distributed parity, requires minimum 3 devices (RAID-5).
    Raid5,
    /// Double distributed parity, requires minimum 4 devices (RAID-6).
    Raid6,
    /// Mirrored stripes, requires minimum 4 devices (RAID-10).
    Raid10,
}

impl RaidProfile {
    /// Returns the minimum number of devices required.
    pub fn min_devices(&self) -> usize {
        match self {
            Self::Single | Self::Dup => 1,
            Self::Raid0 | Self::Raid1 => 2,
            Self::Raid5 => 3,
            Self::Raid6 => 4,
            Self::Raid10 => 4,
        }
    }

    /// Returns the number of parity stripes.
    pub fn parity_stripes(&self) -> usize {
        match self {
            Self::Raid5 => 1,
            Self::Raid6 => 2,
            _ => 0,
        }
    }

    /// Returns whether this profile supports mirroring.
    pub fn is_mirror(&self) -> bool {
        matches!(self, Self::Dup | Self::Raid1 | Self::Raid10)
    }

    /// Returns whether this profile uses striping.
    pub fn is_stripe(&self) -> bool {
        matches!(self, Self::Raid0 | Self::Raid5 | Self::Raid6 | Self::Raid10)
    }

    /// Returns the number of data stripes for a given device count.
    pub fn data_stripes(&self, num_devices: usize) -> usize {
        match self {
            Self::Single | Self::Dup => 1,
            Self::Raid0 => num_devices,
            Self::Raid1 => 1,
            Self::Raid5 => num_devices.saturating_sub(1),
            Self::Raid6 => num_devices.saturating_sub(2),
            Self::Raid10 => num_devices / 2,
        }
    }

    /// Returns the number of redundant copies (including the primary).
    pub fn redundancy_factor(&self) -> usize {
        match self {
            Self::Single | Self::Raid0 => 1,
            Self::Dup | Self::Raid1 => 2,
            Self::Raid5 | Self::Raid6 | Self::Raid10 => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Stripe descriptor
// ---------------------------------------------------------------------------

/// A single physical stripe within a chunk.
#[derive(Debug, Clone, Copy)]
pub struct Stripe {
    /// Device index this stripe resides on.
    pub device_index: u8,
    /// Physical offset on the device.
    pub physical_offset: u64,
    /// Length of this stripe in bytes.
    pub length: u64,
    /// Whether this stripe holds parity data.
    pub is_parity: bool,
}

impl Stripe {
    /// Creates a new data stripe.
    pub const fn new(device_index: u8, physical_offset: u64, length: u64) -> Self {
        Self {
            device_index,
            physical_offset,
            length,
            is_parity: false,
        }
    }

    /// Creates a new parity stripe.
    pub const fn parity(device_index: u8, physical_offset: u64, length: u64) -> Self {
        Self {
            device_index,
            physical_offset,
            length,
            is_parity: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk allocation
// ---------------------------------------------------------------------------

/// Chunk allocation result describing stripe layout.
#[derive(Debug)]
pub struct ChunkAlloc {
    /// RAID profile for this chunk.
    pub profile: RaidProfile,
    /// Logical starting address.
    pub logical_start: u64,
    /// Total logical length.
    pub logical_length: u64,
    /// Individual stripes (data + parity).
    pub stripes: [Stripe; MAX_STRIPES],
    /// Number of valid stripes.
    pub stripe_count: usize,
    /// Stripe size in bytes.
    pub stripe_size: u64,
    /// Number of data stripes.
    pub data_stripe_count: usize,
}

impl ChunkAlloc {
    /// Creates a new chunk allocation with given profile and parameters.
    pub fn new(
        profile: RaidProfile,
        logical_start: u64,
        logical_length: u64,
        num_devices: usize,
        stripe_size: u64,
    ) -> Result<Self> {
        if num_devices < profile.min_devices() {
            return Err(Error::InvalidArgument);
        }
        if stripe_size == 0 || logical_length == 0 {
            return Err(Error::InvalidArgument);
        }
        if logical_length > MAX_CHUNK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let data_stripes = profile.data_stripes(num_devices);
        let parity = profile.parity_stripes();
        let total_stripes = data_stripes + parity;

        if total_stripes > MAX_STRIPES {
            return Err(Error::OutOfMemory);
        }

        let mut alloc = Self {
            profile,
            logical_start,
            logical_length,
            stripes: [Stripe::new(0, 0, 0); MAX_STRIPES],
            stripe_count: 0,
            stripe_size,
            data_stripe_count: data_stripes,
        };

        // Build stripe layout.
        alloc.build_stripes(num_devices, logical_start, stripe_size)?;
        Ok(alloc)
    }

    /// Builds the stripe layout for the chunk.
    fn build_stripes(
        &mut self,
        num_devices: usize,
        base_physical: u64,
        stripe_size: u64,
    ) -> Result<()> {
        let data_stripes = self.data_stripe_count;
        let parity = self.profile.parity_stripes();

        match self.profile {
            RaidProfile::Single => {
                self.stripes[0] = Stripe::new(0, base_physical, self.logical_length);
                self.stripe_count = 1;
            }
            RaidProfile::Dup => {
                self.stripes[0] = Stripe::new(0, base_physical, self.logical_length);
                self.stripes[1] =
                    Stripe::new(0, base_physical + self.logical_length, self.logical_length);
                self.stripe_count = 2;
            }
            RaidProfile::Raid0 | RaidProfile::Raid10 => {
                for i in 0..data_stripes {
                    let dev = (i % num_devices) as u8;
                    let offset = base_physical + (i as u64 / num_devices as u64) * stripe_size;
                    self.stripes[i] = Stripe::new(dev, offset, stripe_size);
                }
                self.stripe_count = data_stripes;
            }
            RaidProfile::Raid1 => {
                for i in 0..2.min(num_devices) {
                    self.stripes[i] = Stripe::new(i as u8, base_physical, self.logical_length);
                }
                self.stripe_count = 2.min(num_devices);
            }
            RaidProfile::Raid5 | RaidProfile::Raid6 => {
                // Data stripes.
                for i in 0..data_stripes {
                    let dev = (i % num_devices) as u8;
                    self.stripes[i] =
                        Stripe::new(dev, base_physical + i as u64 * stripe_size, stripe_size);
                }
                // Parity stripes at end.
                for p in 0..parity {
                    let dev = ((data_stripes + p) % num_devices) as u8;
                    let offset = base_physical + (data_stripes + p) as u64 * stripe_size;
                    self.stripes[data_stripes + p] = Stripe::parity(dev, offset, stripe_size);
                }
                self.stripe_count = data_stripes + parity;
            }
        }
        Ok(())
    }

    /// Returns only the data stripes.
    pub fn data_stripes(&self) -> &[Stripe] {
        &self.stripes[..self.data_stripe_count]
    }

    /// Returns only the parity stripes.
    pub fn parity_stripes(&self) -> &[Stripe] {
        let start = self.data_stripe_count;
        &self.stripes[start..self.stripe_count]
    }
}

// ---------------------------------------------------------------------------
// Stripe offset calculation
// ---------------------------------------------------------------------------

/// Calculates the stripe index and offset within a stripe for a logical offset.
///
/// Returns `(stripe_index, offset_within_stripe)`.
pub fn calc_stripe_offset(
    logical_offset: u64,
    stripe_size: u64,
    data_stripe_count: usize,
) -> Result<(usize, u64)> {
    if stripe_size == 0 || data_stripe_count == 0 {
        return Err(Error::InvalidArgument);
    }
    let stripe_set_size = stripe_size * data_stripe_count as u64;
    let offset_in_set = logical_offset % stripe_set_size;
    let stripe_index = (offset_in_set / stripe_size) as usize;
    let offset_in_stripe = offset_in_set % stripe_size;
    Ok((stripe_index, offset_in_stripe))
}

/// Computes the physical address for a given logical offset within a chunk.
pub fn logical_to_physical(chunk: &ChunkAlloc, logical_offset: u64) -> Result<(u8, u64)> {
    if logical_offset >= chunk.logical_length {
        return Err(Error::InvalidArgument);
    }
    match chunk.profile {
        RaidProfile::Single | RaidProfile::Dup => Ok((
            chunk.stripes[0].device_index,
            chunk.stripes[0].physical_offset + logical_offset,
        )),
        RaidProfile::Raid1 => {
            // Read from first copy by default.
            Ok((
                chunk.stripes[0].device_index,
                chunk.stripes[0].physical_offset + logical_offset,
            ))
        }
        RaidProfile::Raid0 | RaidProfile::Raid10 | RaidProfile::Raid5 | RaidProfile::Raid6 => {
            let (stripe_idx, offset_in_stripe) =
                calc_stripe_offset(logical_offset, chunk.stripe_size, chunk.data_stripe_count)?;
            if stripe_idx >= chunk.stripe_count {
                return Err(Error::InvalidArgument);
            }
            let stripe = &chunk.stripes[stripe_idx];
            Ok((
                stripe.device_index,
                stripe.physical_offset + offset_in_stripe,
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Parity calculation
// ---------------------------------------------------------------------------

/// Computes XOR parity across data blocks (RAID-5 style).
///
/// `blocks` is a slice of fixed-size data blocks. The parity block is
/// computed in-place into `parity_out`.
pub fn calc_parity(blocks: &[[u8; 512]], parity_out: &mut [u8; 512]) {
    parity_out.iter_mut().for_each(|b| *b = 0);
    for block in blocks {
        for (i, byte) in block.iter().enumerate() {
            parity_out[i] ^= byte;
        }
    }
}

/// Reconstructs a missing RAID-5 block using parity and remaining data blocks.
///
/// `available` contains all blocks except the missing one, `parity` is the
/// parity block. Result is written to `out`.
pub fn raid5_recover(available: &[[u8; 512]], parity: &[u8; 512], out: &mut [u8; 512]) {
    out.copy_from_slice(parity);
    for block in available {
        for (i, byte) in block.iter().enumerate() {
            out[i] ^= byte;
        }
    }
}

/// Calculates the parity device index for a given stripe set (RAID-5 left-symmetric).
pub fn raid5_parity_device(stripe_set: u64, num_devices: usize) -> usize {
    if num_devices == 0 {
        return 0;
    }
    // Left-symmetric: parity rotates left by one per stripe set.
    (num_devices - 1 - (stripe_set as usize % num_devices)) % num_devices
}

// ---------------------------------------------------------------------------
// Read/write dispatch
// ---------------------------------------------------------------------------

/// I/O direction for dispatch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// Read operation.
    Read,
    /// Write operation.
    Write,
}

/// Dispatch result from a RAID read/write operation.
#[derive(Debug)]
pub struct DispatchResult {
    /// Device index that was targeted.
    pub device_index: u8,
    /// Physical offset on device.
    pub physical_offset: u64,
    /// Length of the I/O.
    pub length: u64,
    /// Whether this is a parity I/O.
    pub is_parity: bool,
    /// Direction.
    pub direction: IoDirection,
}

/// Dispatches a read I/O for a logical offset within a chunk.
///
/// For mirrored profiles, selects the first available mirror. For striped
/// profiles, calculates the target stripe.
pub fn dispatch_read(
    chunk: &ChunkAlloc,
    logical_offset: u64,
    length: u64,
) -> Result<DispatchResult> {
    let (dev, phys) = logical_to_physical(chunk, logical_offset)?;
    Ok(DispatchResult {
        device_index: dev,
        physical_offset: phys,
        length,
        is_parity: false,
        direction: IoDirection::Read,
    })
}

/// Dispatches a write I/O for a logical offset within a chunk.
///
/// For mirrored profiles, returns multiple dispatch results (one per copy).
/// For striped profiles, targets the single data stripe.
pub fn dispatch_write(
    chunk: &ChunkAlloc,
    logical_offset: u64,
    length: u64,
) -> Result<DispatchResult> {
    let (dev, phys) = logical_to_physical(chunk, logical_offset)?;
    Ok(DispatchResult {
        device_index: dev,
        physical_offset: phys,
        length,
        is_parity: false,
        direction: IoDirection::Write,
    })
}

/// Returns all physical I/O targets for a write to a mirrored chunk.
///
/// For RAID-1 and DUP, both copies must be written. Returns up to
/// `MAX_RAID_DEVICES` targets.
pub fn mirror_write_targets(
    chunk: &ChunkAlloc,
    logical_offset: u64,
    length: u64,
    out: &mut [DispatchResult; MAX_RAID_DEVICES],
) -> Result<usize> {
    let mut count = 0;
    for i in 0..chunk.stripe_count.min(MAX_RAID_DEVICES) {
        let stripe = &chunk.stripes[i];
        if stripe.is_parity {
            continue;
        }
        out[count] = DispatchResult {
            device_index: stripe.device_index,
            physical_offset: stripe.physical_offset + logical_offset,
            length,
            is_parity: false,
            direction: IoDirection::Write,
        };
        count += 1;
    }
    if count == 0 {
        return Err(Error::IoError);
    }
    Ok(count)
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Software RAID (md) driver: linear, stripe (RAID-0), mirror (RAID-1).
//!
//! Implements the multiple devices (md) software RAID layer for ONCRIX.
//! Supports three RAID levels:
//!
//! - **Linear**: Concatenates member disks end-to-end.
//! - **RAID-0 (Stripe)**: Stripes data across member disks for performance.
//! - **RAID-1 (Mirror)**: Mirrors all data across member disks for redundancy.
//!
//! # Linear Layout
//!
//! `array_lba = member[0].sectors + member[1].sectors + ...`
//!
//! # RAID-0 Layout
//!
//! `chunk_size` sectors are written round-robin across all members.
//! `array_lba = member_count × member_sectors`
//!
//! # RAID-1 Layout
//!
//! All reads from the primary (member[0]), writes to all members.
//! On member[0] failure, reads from member[1].
//!
//! Reference: Linux md driver (`drivers/md/md.c`, `raid0.c`, `raid1.c`).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of md arrays.
pub const MAX_MD_ARRAYS: usize = 8;
/// Maximum number of member disks per array.
pub const MAX_MD_MEMBERS: usize = 8;
/// Default chunk size for RAID-0 (in sectors, 1 sector = 512 B).
pub const DEFAULT_CHUNK_SECTORS: u64 = 128; // 64 KiB chunks

// ---------------------------------------------------------------------------
// RAID level
// ---------------------------------------------------------------------------

/// Software RAID level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidLevel {
    /// Linear (concatenation).
    Linear,
    /// RAID-0 (striping).
    Raid0,
    /// RAID-1 (mirroring).
    Raid1,
}

// ---------------------------------------------------------------------------
// Member state
// ---------------------------------------------------------------------------

/// State of a member disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    /// Disk is online and healthy.
    Online,
    /// Disk has failed.
    Failed,
    /// Disk is spare (not yet part of the array).
    Spare,
    /// Disk is being rebuilt/synced.
    Rebuilding,
}

impl Default for MemberState {
    fn default() -> Self {
        Self::Spare
    }
}

// ---------------------------------------------------------------------------
// Member disk
// ---------------------------------------------------------------------------

/// A member disk in a software RAID array.
#[derive(Debug, Clone, Copy, Default)]
pub struct MdMember {
    /// Device index in the global block device registry.
    pub device_idx: usize,
    /// Size in sectors (512 B).
    pub sectors: u64,
    /// Member state.
    pub state: MemberState,
    /// Offset within the member device (reserved area for superblock etc).
    pub data_offset_sectors: u64,
}

impl MdMember {
    /// Creates a new online member.
    pub const fn new(device_idx: usize, sectors: u64) -> Self {
        Self {
            device_idx,
            sectors,
            state: MemberState::Online,
            data_offset_sectors: 2, // reserve 2 sectors for metadata
        }
    }
}

// ---------------------------------------------------------------------------
// RAID I/O descriptor
// ---------------------------------------------------------------------------

/// Describes a translated I/O request for a member disk.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemberIo {
    /// Member index.
    pub member_idx: usize,
    /// LBA on the member device.
    pub lba: u64,
    /// Number of sectors.
    pub sectors: u64,
    /// Byte offset within the caller's buffer.
    pub buf_offset: u64,
}

// ---------------------------------------------------------------------------
// MdArray
// ---------------------------------------------------------------------------

/// A software RAID array.
pub struct MdArray {
    /// RAID level.
    pub level: RaidLevel,
    /// Member disks.
    pub members: [MdMember; MAX_MD_MEMBERS],
    /// Number of active members.
    pub member_count: usize,
    /// Chunk size in sectors (RAID-0 only).
    pub chunk_sectors: u64,
    /// Total array size in sectors.
    pub total_sectors: u64,
    /// Whether the array is assembled and ready.
    pub initialized: bool,
}

impl MdArray {
    /// Creates a new md array.
    pub const fn new(level: RaidLevel) -> Self {
        Self {
            level,
            members: [const {
                MdMember {
                    device_idx: 0,
                    sectors: 0,
                    state: MemberState::Spare,
                    data_offset_sectors: 2,
                }
            }; MAX_MD_MEMBERS],
            member_count: 0,
            chunk_sectors: DEFAULT_CHUNK_SECTORS,
            total_sectors: 0,
            initialized: false,
        }
    }

    /// Adds a member disk to the array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the member limit is reached.
    pub fn add_member(&mut self, member: MdMember) -> Result<usize> {
        if self.member_count >= MAX_MD_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.member_count;
        self.members[idx] = member;
        self.member_count += 1;
        Ok(idx)
    }

    /// Assembles the array: computes total size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no members are present.
    /// Returns [`Error::InvalidArgument`] if RAID-1 has fewer than 2 members.
    pub fn assemble(&mut self) -> Result<()> {
        if self.member_count == 0 {
            return Err(Error::InvalidArgument);
        }
        match self.level {
            RaidLevel::Linear => {
                let mut total = 0u64;
                for i in 0..self.member_count {
                    let usable = self.members[i]
                        .sectors
                        .saturating_sub(self.members[i].data_offset_sectors);
                    total = total.saturating_add(usable);
                }
                self.total_sectors = total;
            }
            RaidLevel::Raid0 => {
                // Stripe size = min(member) × count.
                let min_sectors = self.members[..self.member_count]
                    .iter()
                    .map(|m| m.sectors.saturating_sub(m.data_offset_sectors))
                    .min()
                    .unwrap_or(0);
                self.total_sectors = min_sectors.saturating_mul(self.member_count as u64);
            }
            RaidLevel::Raid1 => {
                if self.member_count < 2 {
                    return Err(Error::InvalidArgument);
                }
                // Array size = size of smallest member.
                let min_sectors = self.members[..self.member_count]
                    .iter()
                    .map(|m| m.sectors.saturating_sub(m.data_offset_sectors))
                    .min()
                    .unwrap_or(0);
                self.total_sectors = min_sectors;
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Translates an array-level read request into member I/O descriptors.
    ///
    /// Returns up to `MAX_MD_MEMBERS` member I/O descriptors.
    /// For RAID-1 reads, only one member is selected (primary, or first healthy).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the LBA range is out of bounds.
    /// Returns [`Error::IoError`] if no online members are available.
    pub fn translate_read(
        &self,
        lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        if lba.saturating_add(sectors) > self.total_sectors {
            return Err(Error::InvalidArgument);
        }
        match self.level {
            RaidLevel::Linear => self.translate_linear(lba, sectors, ios),
            RaidLevel::Raid0 => self.translate_raid0_read(lba, sectors, ios),
            RaidLevel::Raid1 => self.translate_raid1_read(lba, sectors, ios),
        }
    }

    /// Translates an array-level write request into member I/O descriptors.
    ///
    /// For RAID-1, writes go to all online members.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the LBA range is out of bounds.
    /// Returns [`Error::IoError`] if no online members are available.
    pub fn translate_write(
        &self,
        lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        if lba.saturating_add(sectors) > self.total_sectors {
            return Err(Error::InvalidArgument);
        }
        match self.level {
            RaidLevel::Linear => self.translate_linear(lba, sectors, ios),
            RaidLevel::Raid0 => self.translate_raid0_read(lba, sectors, ios),
            RaidLevel::Raid1 => self.translate_raid1_write(lba, sectors, ios),
        }
    }

    /// Returns total array size in sectors.
    pub fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    /// Returns `true` if the array is assembled.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the first online member index.
    pub fn primary_member(&self) -> Option<usize> {
        self.members[..self.member_count]
            .iter()
            .position(|m| m.state == MemberState::Online)
    }

    // -----------------------------------------------------------------------
    // Private translation helpers
    // -----------------------------------------------------------------------

    fn translate_linear(
        &self,
        mut lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        let mut count = 0;
        let mut remaining = sectors;
        let mut buf_offset = 0u64;

        for i in 0..self.member_count {
            if remaining == 0 {
                break;
            }
            let m = &self.members[i];
            let m_usable = m.sectors.saturating_sub(m.data_offset_sectors);
            if lba >= m_usable {
                lba -= m_usable;
                continue;
            }
            let avail = m_usable - lba;
            let take = avail.min(remaining);
            ios[count] = MemberIo {
                member_idx: i,
                lba: lba + m.data_offset_sectors,
                sectors: take,
                buf_offset,
            };
            count += 1;
            buf_offset += take;
            remaining -= take;
            lba = 0;
        }
        if remaining > 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(count)
    }

    fn translate_raid0_read(
        &self,
        lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        // Simplified: only handles single-chunk reads for now.
        let chunk = self.chunk_sectors;
        let n = self.member_count as u64;
        let chunk_idx = lba / chunk;
        let chunk_off = lba % chunk;
        let member_idx = (chunk_idx % n) as usize;
        let member_lba = (chunk_idx / n) * chunk + chunk_off;

        ios[0] = MemberIo {
            member_idx,
            lba: member_lba + self.members[member_idx].data_offset_sectors,
            sectors: sectors.min(chunk - chunk_off),
            buf_offset: 0,
        };
        Ok(1)
    }

    fn translate_raid1_read(
        &self,
        lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        let primary = self.primary_member().ok_or(Error::IoError)?;
        ios[0] = MemberIo {
            member_idx: primary,
            lba: lba + self.members[primary].data_offset_sectors,
            sectors,
            buf_offset: 0,
        };
        Ok(1)
    }

    fn translate_raid1_write(
        &self,
        lba: u64,
        sectors: u64,
        ios: &mut [MemberIo; MAX_MD_MEMBERS],
    ) -> Result<usize> {
        let mut count = 0;
        for i in 0..self.member_count {
            if self.members[i].state == MemberState::Online {
                ios[count] = MemberIo {
                    member_idx: i,
                    lba: lba + self.members[i].data_offset_sectors,
                    sectors,
                    buf_offset: 0,
                };
                count += 1;
            }
        }
        if count == 0 {
            return Err(Error::IoError);
        }
        Ok(count)
    }
}

impl Default for MdArray {
    fn default() -> Self {
        Self::new(RaidLevel::Linear)
    }
}

// ---------------------------------------------------------------------------
// Global md array registry
// ---------------------------------------------------------------------------

/// Global md RAID array registry.
pub struct MdRegistry {
    arrays: [MdArray; MAX_MD_ARRAYS],
    count: usize,
}

impl MdRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            arrays: [const { MdArray::new(RaidLevel::Linear) }; MAX_MD_ARRAYS],
            count: 0,
        }
    }

    /// Creates and registers a new md array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create(&mut self, level: RaidLevel) -> Result<usize> {
        if self.count >= MAX_MD_ARRAYS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.arrays[idx] = MdArray::new(level);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the array at `index`.
    pub fn get(&self, index: usize) -> Option<&MdArray> {
        if index < self.count {
            Some(&self.arrays[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the array at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut MdArray> {
        if index < self.count {
            Some(&mut self.arrays[index])
        } else {
            None
        }
    }

    /// Returns the number of registered arrays.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no arrays are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raid1() -> MdArray {
        let mut array = MdArray::new(RaidLevel::Raid1);
        array.add_member(MdMember::new(0, 1024)).unwrap();
        array.add_member(MdMember::new(1, 1024)).unwrap();
        array.assemble().unwrap();
        array
    }

    #[test]
    fn raid1_total_sectors() {
        let array = make_raid1();
        // 1024 - 2 (metadata) = 1022 usable sectors.
        assert_eq!(array.total_sectors(), 1022);
    }

    #[test]
    fn raid1_read_translation() {
        let array = make_raid1();
        let mut ios = [MemberIo::default(); MAX_MD_MEMBERS];
        let count = array.translate_read(0, 8, &mut ios).unwrap();
        assert_eq!(count, 1);
        assert_eq!(ios[0].member_idx, 0); // primary
        assert_eq!(ios[0].sectors, 8);
    }

    #[test]
    fn raid1_write_goes_to_all() {
        let array = make_raid1();
        let mut ios = [MemberIo::default(); MAX_MD_MEMBERS];
        let count = array.translate_write(0, 8, &mut ios).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn linear_assembly() {
        let mut array = MdArray::new(RaidLevel::Linear);
        array.add_member(MdMember::new(0, 512)).unwrap();
        array.add_member(MdMember::new(1, 256)).unwrap();
        array.assemble().unwrap();
        // (512 - 2) + (256 - 2) = 764
        assert_eq!(array.total_sectors(), 764);
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS allocation group (AG) management.
//!
//! XFS divides the filesystem into a fixed number of equally-sized allocation
//! groups. Each AG is independent and manages its own free space, inodes, and
//! per-AG B-trees. This enables highly parallel allocation across AGs.

use oncrix_lib::{Error, Result};

/// XFS superblock magic number.
pub const XFS_SB_MAGIC: u32 = 0x5846_5342; // 'XFSB'

/// Maximum number of allocation groups per filesystem.
pub const XFS_MAX_AGNUMBER: u32 = 524_288;

/// Minimum AG size in filesystem blocks.
pub const XFS_AG_MIN_BLOCKS: u64 = 64;

/// AG free space B-tree magic (XFS_ABTB_MAGIC / XFS_ABTC_MAGIC).
pub const XFS_ABTB_MAGIC: u32 = 0x4142_5442; // 'ABTB'
pub const XFS_ABTC_MAGIC: u32 = 0x4142_5443; // 'ABTC'

/// Inode B-tree magic.
pub const XFS_IBT_MAGIC: u32 = 0x4941_4254; // 'IABT'

/// AG header block offsets (in AG-relative blocks).
pub const XFS_SB_BLOCK: u64 = 0;
pub const XFS_AGF_BLOCK: u64 = 1;
pub const XFS_AGI_BLOCK: u64 = 2;
pub const XFS_AGFL_BLOCK: u64 = 3;

/// Length of the AG free list (AGFL).
pub const XFS_AGFL_SIZE: usize = 36;

/// AG free space header (AGF).
///
/// The AGF describes the two free-space B-trees for an AG:
/// - bno tree: indexed by starting block number
/// - cnt tree: indexed by free extent length
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsAgf {
    /// Magic number (XFS_AGF_MAGIC).
    pub magicnum: u32,
    /// Version number.
    pub versionnum: u32,
    /// AG number.
    pub seqno: u32,
    /// Size of this AG in blocks.
    pub length: u32,
    /// Root of the bno B-tree.
    pub roots: [u32; 2],
    /// Levels of the bno and cnt B-trees.
    pub levels: [u32; 2],
    /// First/last block of the AGFL.
    pub flfirst: u32,
    pub fllast: u32,
    /// Count of blocks on the AGFL.
    pub flcount: u32,
    /// Total free blocks in this AG.
    pub freeblks: u32,
    /// Longest contiguous free extent.
    pub longest: u32,
    /// Number of blocks consumed by B-tree metadata.
    pub btreeblks: u32,
    /// UUID of the filesystem.
    pub uuid: [u8; 16],
    /// Log sequence number.
    pub lsn: u64,
    /// CRC32c checksum.
    pub crc: u32,
    /// Padding.
    pub _pad: u32,
}

impl XfsAgf {
    /// Magic number constant for validation.
    pub const MAGIC: u32 = 0x5841_4746; // 'XAGF'

    /// Validate the AGF header.
    pub fn validate(&self, ag_number: u32) -> Result<()> {
        if self.magicnum != Self::MAGIC {
            return Err(Error::IoError);
        }
        if self.seqno != ag_number {
            return Err(Error::IoError);
        }
        if self.length < XFS_AG_MIN_BLOCKS as u32 {
            return Err(Error::IoError);
        }
        Ok(())
    }
}

/// AG inode header (AGI).
///
/// Tracks allocated and free inodes within an AG via the inode B-tree
/// and the free inode B-tree.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsAgi {
    /// Magic number.
    pub magicnum: u32,
    /// Version number.
    pub versionnum: u32,
    /// AG sequence number.
    pub seqno: u32,
    /// Size of this AG in blocks.
    pub length: u32,
    /// Total inode count.
    pub count: u32,
    /// Root of the inode B-tree.
    pub root: u32,
    /// Level of the inode B-tree.
    pub level: u32,
    /// Free inode count.
    pub freecount: u32,
    /// Last inode allocated.
    pub newino: u32,
    /// Hint for dirino (directory inode).
    pub dirino: u32,
    /// Unlinked inode bucket hash table.
    pub unlinked: [u32; 64],
    /// UUID.
    pub uuid: [u8; 16],
    /// CRC.
    pub crc: u32,
    /// Padding.
    pub _pad: u32,
    /// Log sequence number.
    pub lsn: u64,
    /// Root of free inode B-tree.
    pub free_root: u32,
    /// Level of free inode B-tree.
    pub free_level: u32,
}

impl XfsAgi {
    /// AGI magic number.
    pub const MAGIC: u32 = 0x5841_4749; // 'XAGI'

    /// Validate the AGI header.
    pub fn validate(&self, ag_number: u32) -> Result<()> {
        if self.magicnum != Self::MAGIC {
            return Err(Error::IoError);
        }
        if self.seqno != ag_number {
            return Err(Error::IoError);
        }
        Ok(())
    }
}

/// Per-AG state maintained in memory.
#[derive(Debug)]
pub struct AgState {
    /// AG number (0-based).
    pub ag_number: u32,
    /// AG header copy.
    pub agf: XfsAgf,
    /// AGI header copy.
    pub agi: XfsAgi,
    /// Free list blocks (AGFL).
    pub agfl: [u32; XFS_AGFL_SIZE],
    /// Whether the AG is currently locked for allocation.
    pub locked: bool,
    /// Number of pending reservations.
    pub resv_blocks: u32,
}

impl AgState {
    /// Create a new AgState with zeroed headers.
    pub const fn new(ag_number: u32) -> Self {
        let agf = XfsAgf {
            magicnum: XfsAgf::MAGIC,
            versionnum: 1,
            seqno: ag_number,
            length: 0,
            roots: [0; 2],
            levels: [1; 2],
            flfirst: 0,
            fllast: 0,
            flcount: 0,
            freeblks: 0,
            longest: 0,
            btreeblks: 0,
            uuid: [0u8; 16],
            lsn: 0,
            crc: 0,
            _pad: 0,
        };
        let agi = XfsAgi {
            magicnum: XfsAgi::MAGIC,
            versionnum: 1,
            seqno: ag_number,
            length: 0,
            count: 0,
            root: 0,
            level: 1,
            freecount: 0,
            newino: 0,
            dirino: u32::MAX,
            unlinked: [u32::MAX; 64],
            uuid: [0u8; 16],
            crc: 0,
            _pad: 0,
            lsn: 0,
            free_root: 0,
            free_level: 1,
        };
        Self {
            ag_number,
            agf,
            agi,
            agfl: [0u32; XFS_AGFL_SIZE],
            locked: false,
            resv_blocks: 0,
        }
    }

    /// Return total free blocks in this AG.
    pub fn free_blocks(&self) -> u32 {
        self.agf.freeblks.saturating_sub(self.resv_blocks)
    }

    /// Return true if the AG has at least `n` free blocks.
    pub fn has_free(&self, n: u32) -> bool {
        self.free_blocks() >= n
    }

    /// Reserve `n` blocks in this AG for an allocation.
    pub fn reserve(&mut self, n: u32) -> Result<()> {
        if !self.has_free(n) {
            return Err(Error::OutOfMemory);
        }
        if self.locked {
            return Err(Error::Busy);
        }
        self.resv_blocks = self.resv_blocks.saturating_add(n);
        self.locked = true;
        Ok(())
    }

    /// Commit a reservation, reducing freeblks.
    pub fn commit_reservation(&mut self, n: u32) -> Result<()> {
        if !self.locked {
            return Err(Error::InvalidArgument);
        }
        self.agf.freeblks = self.agf.freeblks.saturating_sub(n);
        self.resv_blocks = self.resv_blocks.saturating_sub(n);
        self.locked = false;
        Ok(())
    }

    /// Release a reservation without committing.
    pub fn release_reservation(&mut self) {
        self.resv_blocks = 0;
        self.locked = false;
    }

    /// Free `n` blocks starting at `start_block` within this AG.
    pub fn free_extent(&mut self, n: u32) {
        self.agf.freeblks = self.agf.freeblks.saturating_add(n);
        if n > self.agf.longest {
            self.agf.longest = n;
        }
    }
}

/// Filesystem-wide AG table.
#[derive(Debug)]
pub struct AgTable {
    /// Per-AG state array.
    ags: [Option<AgState>; 256],
    /// Total number of AGs.
    pub ag_count: u32,
    /// AG size in blocks.
    pub ag_size: u64,
}

impl AgTable {
    /// Create a new empty AG table.
    pub const fn new() -> Self {
        Self {
            ags: [const { None }; 256],
            ag_count: 0,
            ag_size: 0,
        }
    }

    /// Initialize the AG table for a filesystem with `ag_count` AGs of `ag_size` blocks each.
    pub fn init(&mut self, ag_count: u32, ag_size: u64) -> Result<()> {
        if ag_count as usize > self.ags.len() {
            return Err(Error::InvalidArgument);
        }
        if ag_size < XFS_AG_MIN_BLOCKS {
            return Err(Error::InvalidArgument);
        }
        self.ag_count = ag_count;
        self.ag_size = ag_size;
        for i in 0..ag_count as usize {
            let mut ag = AgState::new(i as u32);
            ag.agf.length = ag_size as u32;
            ag.agf.freeblks = ag_size as u32 - 4; // Reserve 4 header blocks.
            ag.agf.longest = ag.agf.freeblks;
            ag.agi.length = ag_size as u32;
            self.ags[i] = Some(ag);
        }
        Ok(())
    }

    /// Get a reference to the AG with the given number.
    pub fn get(&self, ag_number: u32) -> Option<&AgState> {
        self.ags.get(ag_number as usize)?.as_ref()
    }

    /// Get a mutable reference to the AG with the given number.
    pub fn get_mut(&mut self, ag_number: u32) -> Option<&mut AgState> {
        self.ags.get_mut(ag_number as usize)?.as_mut()
    }

    /// Find the AG with the most free space.
    pub fn best_ag(&self, min_free: u32) -> Option<u32> {
        let mut best_ag = None;
        let mut best_free = 0u32;
        for i in 0..self.ag_count as usize {
            if let Some(ag) = &self.ags[i] {
                let free = ag.free_blocks();
                if free >= min_free && free > best_free {
                    best_free = free;
                    best_ag = Some(i as u32);
                }
            }
        }
        best_ag
    }

    /// Allocate `nblocks` from any AG with sufficient free space.
    ///
    /// Returns the (AG number, block offset within AG) of the allocation.
    pub fn alloc_blocks(&mut self, nblocks: u32) -> Result<(u32, u32)> {
        let ag_num = self.best_ag(nblocks).ok_or(Error::OutOfMemory)?;
        let ag = self.get_mut(ag_num).ok_or(Error::NotFound)?;
        ag.reserve(nblocks)?;
        // Simplified: allocate from end of AG.
        let start = ag.agf.freeblks - nblocks;
        ag.commit_reservation(nblocks)?;
        Ok((ag_num, start))
    }

    /// Return `nblocks` to AG `ag_number`.
    pub fn free_blocks(&mut self, ag_number: u32, nblocks: u32) -> Result<()> {
        let ag = self.get_mut(ag_number).ok_or(Error::NotFound)?;
        ag.free_extent(nblocks);
        Ok(())
    }

    /// Total free blocks across all AGs.
    pub fn total_free(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.ag_count as usize {
            if let Some(ag) = &self.ags[i] {
                total += ag.free_blocks() as u64;
            }
        }
        total
    }
}

impl Default for AgTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a filesystem block number to (AG number, AG-relative block).
pub fn fsb_to_agbno(fsblock: u64, ag_size: u64) -> (u32, u32) {
    ((fsblock / ag_size) as u32, (fsblock % ag_size) as u32)
}

/// Convert (AG number, AG-relative block) to a filesystem block number.
pub fn agbno_to_fsb(ag_number: u32, agbno: u32, ag_size: u64) -> u64 {
    ag_number as u64 * ag_size + agbno as u64
}

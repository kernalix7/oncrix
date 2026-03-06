// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS node page management.
//!
//! In F2FS every inode and indirect-block is a "node page".  This module
//! implements the node-page structure, the node information block (NID →
//! block-address mapping), and the in-memory node cache used by the
//! node-block allocator.

use oncrix_lib::{Error, Result};

/// Node ID type (24-bit in the spec, u32 here for alignment).
pub type Nid = u32;

/// Block address type.
pub type BlkAddr = u32;

/// Sentinel block address meaning "not allocated".
pub const NULL_ADDR: BlkAddr = 0;
/// Sentinel block address meaning "new allocation pending".
pub const NEW_ADDR: BlkAddr = 0xffff_ffff;

/// Size of an F2FS node page in bytes.
pub const NODE_PAGE_SIZE: usize = 4096;

/// Number of direct block pointers in an inode node.
pub const DEF_ADDRS_PER_INODE: usize = 923;
/// Number of block pointers in a direct-node page.
pub const DEF_ADDRS_PER_BLOCK: usize = 1018;
/// Number of NID pointers in an indirect-node page.
pub const DEF_NIDS_PER_BLOCK: usize = 1018;

/// F2FS node types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Inode node: contains inode metadata + direct block pointers.
    Inode,
    /// Direct node: one level of indirection, contains block pointers.
    Direct,
    /// Indirect node: contains NID pointers to child nodes.
    Indirect,
    /// Double-indirect node.
    DoubleIndirect,
}

/// Footer appended to every F2FS node page.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NodeFooter {
    /// NID of this node.
    pub nid: Nid,
    /// Inode NID (same as `nid` for inode nodes; inode's NID for others).
    pub ino: Nid,
    /// Logical offset of this node within the inode's node chain.
    pub flag: u32,
    /// CP version at time of write.
    pub cp_ver: u64,
    /// NID of the next node in the chain (0 = none).
    pub next_blkaddr: BlkAddr,
}

impl NodeFooter {
    /// Create a footer for an inode node.
    pub fn for_inode(nid: Nid, cp_ver: u64) -> Self {
        Self {
            nid,
            ino: nid,
            flag: 0,
            cp_ver,
            next_blkaddr: NULL_ADDR,
        }
    }
}

/// On-disk / in-memory representation of a direct node page.
#[derive(Clone)]
pub struct DirectNode {
    /// Block address array.
    pub addr: [BlkAddr; DEF_ADDRS_PER_BLOCK],
    pub footer: NodeFooter,
}

impl DirectNode {
    /// Create an empty direct node.
    pub fn new(nid: Nid, ino: Nid, cp_ver: u64) -> Self {
        Self {
            addr: [NULL_ADDR; DEF_ADDRS_PER_BLOCK],
            footer: NodeFooter {
                nid,
                ino,
                flag: 1,
                cp_ver,
                next_blkaddr: NULL_ADDR,
            },
        }
    }

    /// Get the block address at slot `idx`.
    pub fn get_addr(&self, idx: usize) -> Result<BlkAddr> {
        if idx >= DEF_ADDRS_PER_BLOCK {
            return Err(Error::InvalidArgument);
        }
        Ok(self.addr[idx])
    }

    /// Set the block address at slot `idx`.
    pub fn set_addr(&mut self, idx: usize, addr: BlkAddr) -> Result<()> {
        if idx >= DEF_ADDRS_PER_BLOCK {
            return Err(Error::InvalidArgument);
        }
        self.addr[idx] = addr;
        Ok(())
    }

    /// Count allocated blocks in this node.
    pub fn alloc_count(&self) -> usize {
        self.addr
            .iter()
            .filter(|&&a| a != NULL_ADDR && a != NEW_ADDR)
            .count()
    }
}

/// Node Information Block entry: maps NID → physical block address.
#[derive(Debug, Clone, Copy)]
pub struct NatEntry {
    /// Physical block address of the node page. `NULL_ADDR` = free.
    pub block_addr: BlkAddr,
    /// Inode NID that owns this node (same as NID for inode nodes).
    pub ino: Nid,
    /// Version counter for stale detection.
    pub version: u8,
}

impl NatEntry {
    /// An empty / free NAT entry.
    pub const fn free() -> Self {
        Self {
            block_addr: NULL_ADDR,
            ino: 0,
            version: 0,
        }
    }

    /// Whether this entry is free.
    pub fn is_free(&self) -> bool {
        self.block_addr == NULL_ADDR
    }
}

/// Maximum number of NAT entries in the in-memory cache.
pub const NAT_CACHE_SIZE: usize = 4096;

/// In-memory NAT cache: indexed by NID.
pub struct NatCache {
    entries: [NatEntry; NAT_CACHE_SIZE],
    /// Bitmap of dirty entries that need to be flushed to the NAT area.
    dirty: [u64; NAT_CACHE_SIZE / 64],
}

impl NatCache {
    /// Create an empty NAT cache (all entries free).
    pub fn new() -> Self {
        Self {
            entries: [NatEntry::free(); NAT_CACHE_SIZE],
            dirty: [0u64; NAT_CACHE_SIZE / 64],
        }
    }

    fn mark_dirty(&mut self, nid: Nid) {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        self.dirty[idx / 64] |= 1u64 << (idx % 64);
    }

    fn clear_dirty(&mut self, nid: Nid) {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        self.dirty[idx / 64] &= !(1u64 << (idx % 64));
    }

    /// Look up a NID in the cache.
    pub fn lookup(&self, nid: Nid) -> Option<&NatEntry> {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        let entry = &self.entries[idx];
        if entry.ino == nid || entry.block_addr == NULL_ADDR {
            Some(entry)
        } else {
            // Collision — would need a secondary lookup in production.
            None
        }
    }

    /// Insert or update a NAT entry.
    pub fn set(&mut self, nid: Nid, entry: NatEntry) {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        self.entries[idx] = entry;
        self.mark_dirty(nid);
    }

    /// Free a NAT entry (mark as unused).
    pub fn free(&mut self, nid: Nid) {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        self.entries[idx] = NatEntry::free();
        self.mark_dirty(nid);
    }

    /// Flush a single dirty entry (simulate write-back to NAT area).
    ///
    /// Returns the entry that was flushed, or `None` if not dirty.
    pub fn flush_one(&mut self, nid: Nid) -> Option<NatEntry> {
        let idx = (nid as usize) % NAT_CACHE_SIZE;
        let word = self.dirty[idx / 64];
        if word & (1u64 << (idx % 64)) != 0 {
            self.clear_dirty(nid);
            Some(self.entries[idx])
        } else {
            None
        }
    }

    /// Count dirty entries.
    pub fn dirty_count(&self) -> u32 {
        self.dirty.iter().map(|w| w.count_ones()).sum()
    }
}

impl Default for NatCache {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory inode node (simplified: tracks the direct block pointer array).
pub struct InodeNode {
    /// Inode NID.
    pub nid: Nid,
    /// Direct block address array (first 923 slots are inline in the inode).
    pub addrs: [BlkAddr; DEF_ADDRS_PER_INODE],
    /// NID of the first direct-node page (for files > DEF_ADDRS_PER_INODE blocks).
    pub direct_nid: [Nid; 2],
    /// NID of indirect-node pages.
    pub indirect_nid: [Nid; 2],
    /// NID of the double-indirect node.
    pub double_indirect_nid: Nid,
    /// File size in bytes.
    pub size: u64,
    /// Number of blocks allocated.
    pub blocks: u64,
    pub footer: NodeFooter,
}

impl InodeNode {
    /// Create an empty inode node.
    pub fn new(nid: Nid, cp_ver: u64) -> Self {
        Self {
            nid,
            addrs: [NULL_ADDR; DEF_ADDRS_PER_INODE],
            direct_nid: [0; 2],
            indirect_nid: [0; 2],
            double_indirect_nid: 0,
            size: 0,
            blocks: 0,
            footer: NodeFooter::for_inode(nid, cp_ver),
        }
    }

    /// Get the block address for a logical file block within the inline range.
    pub fn get_direct_addr(&self, lblock: usize) -> Result<BlkAddr> {
        if lblock >= DEF_ADDRS_PER_INODE {
            return Err(Error::InvalidArgument);
        }
        Ok(self.addrs[lblock])
    }

    /// Set the block address for a logical file block.
    pub fn set_direct_addr(&mut self, lblock: usize, addr: BlkAddr) -> Result<()> {
        if lblock >= DEF_ADDRS_PER_INODE {
            return Err(Error::InvalidArgument);
        }
        self.addrs[lblock] = addr;
        Ok(())
    }
}

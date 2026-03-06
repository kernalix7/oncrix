// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! JFFS2 — Journalling Flash File System, version 2.
//!
//! JFFS2 is a log-structured filesystem designed for NOR/NAND flash memory.
//! It has no fixed on-disk layout; instead, all data is stored as a sequence
//! of typed nodes written sequentially within erase blocks.
//!
//! # Node types
//!
//! | Type | Meaning |
//! |------|---------|
//! | `DIRENT` | Directory entry (name → ino mapping) |
//! | `INODE` | Inode data node (file data or metadata) |
//! | `CLEANMARKER` | Empty erased block marker |
//! | `PADDING` | Alignment padding |
//! | `SUMMARY` | Block summary (fast mount) |
//!
//! # Design
//!
//! - [`Jffs2InodeNode`] — file inode data node
//! - [`Jffs2DirentNode`] — directory entry node
//! - [`Jffs2EraseBlock`] — erase block with node list and wear state
//! - `jffs2_scan_eraseblock` — parse all nodes in an erase block
//! - `jffs2_read_inode` — reconstruct inode from nodes across blocks
//!
//! # References
//!
//! - Linux `fs/jffs2/`
//! - JFFS2 Design Notes (David Woodhouse, 2001)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// JFFS2 magic bitmask (little-endian).
pub const JFFS2_MAGIC: u16 = 0x1985;

/// Old JFFS2 magic (some implementations).
pub const JFFS2_OLD_MAGIC: u16 = 0x1984;

/// Node type: inode data.
pub const JFFS2_NODETYPE_INODE: u16 = 0xE001;

/// Node type: directory entry.
pub const JFFS2_NODETYPE_DIRENT: u16 = 0xE002;

/// Node type: clean marker.
pub const JFFS2_NODETYPE_CLEANMARKER: u16 = 0x2003;

/// Node type: padding.
pub const JFFS2_NODETYPE_PADDING: u16 = 0x2004;

/// Node type: summary.
pub const JFFS2_NODETYPE_SUMMARY: u16 = 0xE00F;

/// Maximum nodes per erase block in our representation.
const MAX_NODES_PER_BLOCK: usize = 64;

/// Maximum name length in a dirent node.
const MAX_DIRENT_NAME: usize = 256;

/// Maximum simultaneous erase blocks tracked.
const MAX_ERASE_BLOCKS: usize = 128;

/// Typical NOR flash erase block size (128 KiB).
pub const JFFS2_ERASE_SIZE: u32 = 128 * 1024;

/// Maximum data per inode node (compressed or raw).
const MAX_INODE_DATA: usize = 4096;

// ---------------------------------------------------------------------------
// Node structures
// ---------------------------------------------------------------------------

/// Common JFFS2 unknown node header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Jffs2UnknownNode {
    /// Magic (0x1985).
    pub magic: u16,
    /// Node type.
    pub nodetype: u16,
    /// Total length of the node including data.
    pub totlen: u32,
    /// CRC32 of the common header fields.
    pub hdr_crc: u32,
}

/// JFFS2 inode data node.
#[derive(Clone, Debug)]
pub struct Jffs2InodeNode {
    /// Inode number this data belongs to.
    pub ino: u32,
    /// Version number (newer = higher priority).
    pub version: u32,
    /// POSIX mode bits.
    pub mode: u32,
    /// Owner UID.
    pub uid: u16,
    /// Owner GID.
    pub gid: u16,
    /// Inode size in bytes.
    pub isize: u32,
    /// Access time.
    pub atime: u32,
    /// Modification time.
    pub mtime: u32,
    /// Change time.
    pub ctime: u32,
    /// Offset within the file this node's data covers.
    pub offset: u32,
    /// Compressed data length.
    pub csize: u32,
    /// Uncompressed data length.
    pub dsize: u32,
    /// Compression type (0 = none, 6 = zlib, 7 = lzo).
    pub compr: u8,
    /// User-space compression type hint.
    pub usercompr: u8,
    /// Node flags.
    pub flags: u16,
    /// Data payload (up to `MAX_INODE_DATA` bytes).
    pub data: [u8; MAX_INODE_DATA],
    /// Valid bytes in `data`.
    pub data_len: usize,
}

impl Jffs2InodeNode {
    /// Create an empty inode node.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            version: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            isize: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            offset: 0,
            csize: 0,
            dsize: 0,
            compr: 0,
            usercompr: 0,
            flags: 0,
            data: [0u8; MAX_INODE_DATA],
            data_len: 0,
        }
    }

    /// Return the data bytes for this node.
    pub fn data_bytes(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

/// JFFS2 directory entry node.
#[derive(Clone, Debug)]
pub struct Jffs2DirentNode {
    /// Parent directory inode number.
    pub pino: u32,
    /// Version number.
    pub version: u32,
    /// Inode number of the named file (0 = deletion record).
    pub ino: u32,
    /// Last modification time.
    pub mctime: u32,
    /// Length of the name.
    pub nsize: u8,
    /// File type bits (DT_REG, DT_DIR, etc.).
    pub dtype: u8,
    /// Entry name.
    pub name: [u8; MAX_DIRENT_NAME],
}

impl Jffs2DirentNode {
    /// Create an empty dirent node.
    pub const fn empty() -> Self {
        Self {
            pino: 0,
            version: 0,
            ino: 0,
            mctime: 0,
            nsize: 0,
            dtype: 0,
            name: [0u8; MAX_DIRENT_NAME],
        }
    }

    /// Return the name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.nsize as usize]
    }

    /// Return `true` if this is a deletion record.
    pub fn is_unlink(&self) -> bool {
        self.ino == 0
    }
}

// ---------------------------------------------------------------------------
// Node union (for storage in the block list)
// ---------------------------------------------------------------------------

/// Type tag for a node stored in an erase block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Inode,
    Dirent,
    Cleanmarker,
    Padding,
    Unknown,
}

/// Enumerated node entry stored per block.
#[derive(Clone, Copy, Debug)]
pub struct BlockNode {
    /// Kind of this node.
    pub kind: NodeKind,
    /// Byte offset within the erase block.
    pub offset: u32,
    /// Total node length (including header).
    pub totlen: u32,
    /// Inode number (valid when `kind == NodeKind::Inode`).
    pub ino: u32,
    /// Version (valid for Inode and Dirent).
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Jffs2EraseBlock
// ---------------------------------------------------------------------------

/// One JFFS2 erase block and its scanned node list.
pub struct Jffs2EraseBlock {
    /// Physical offset of this block within the flash.
    pub phys_offset: u64,
    /// Total size of this erase block in bytes.
    pub size: u32,
    /// Number of times this block has been erased (wear count).
    pub erase_count: u32,
    /// Whether this block has been cleanmarked (erased + ready).
    pub clean: bool,
    /// Whether this block is actively being written.
    pub dirty: bool,
    /// Nodes found during scanning.
    nodes: [BlockNode; MAX_NODES_PER_BLOCK],
    /// Number of valid nodes.
    node_count: usize,
    /// Free bytes remaining in this block.
    pub free_bytes: u32,
    /// Dirty bytes (obsolete nodes) in this block.
    pub dirty_bytes: u32,
}

impl Jffs2EraseBlock {
    /// Create an empty erase block descriptor.
    pub const fn new(phys_offset: u64, size: u32) -> Self {
        const EMPTY_NODE: BlockNode = BlockNode {
            kind: NodeKind::Unknown,
            offset: 0,
            totlen: 0,
            ino: 0,
            version: 0,
        };
        Self {
            phys_offset,
            size,
            erase_count: 0,
            clean: false,
            dirty: false,
            nodes: [EMPTY_NODE; MAX_NODES_PER_BLOCK],
            node_count: 0,
            free_bytes: size,
            dirty_bytes: 0,
        }
    }

    /// Add a scanned node to this block's node list.
    fn add_node(&mut self, node: BlockNode) -> Result<()> {
        if self.node_count >= MAX_NODES_PER_BLOCK {
            return Err(Error::OutOfMemory);
        }
        self.free_bytes = self.free_bytes.saturating_sub(node.totlen);
        self.nodes[self.node_count] = node;
        self.node_count += 1;
        Ok(())
    }

    /// Return all nodes of kind `Inode` for `ino`.
    pub fn inode_nodes_for(&self, ino: u32) -> impl Iterator<Item = &BlockNode> {
        self.nodes[..self.node_count]
            .iter()
            .filter(move |n| n.kind == NodeKind::Inode && n.ino == ino)
    }

    /// Return the node count.
    pub fn node_count(&self) -> usize {
        self.node_count
    }
}

// ---------------------------------------------------------------------------
// Scan and read functions
// ---------------------------------------------------------------------------

/// Scan an erase block's raw data and populate `block.nodes`.
///
/// `data` is the raw byte content of the erase block.
/// Returns the number of valid nodes found.
pub fn jffs2_scan_eraseblock(block: &mut Jffs2EraseBlock, data: &[u8]) -> Result<usize> {
    let mut pos = 0usize;
    let block_len = data.len().min(block.size as usize);

    while pos + 8 <= block_len {
        let magic = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if magic != JFFS2_MAGIC && magic != JFFS2_OLD_MAGIC {
            pos += 4; // Skip 4 bytes and re-check (flash noise).
            continue;
        }
        let nodetype = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        let totlen =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        if totlen < 8 || pos + totlen as usize > block_len {
            break; // Truncated node.
        }

        let kind = match nodetype {
            JFFS2_NODETYPE_INODE => NodeKind::Inode,
            JFFS2_NODETYPE_DIRENT => NodeKind::Dirent,
            JFFS2_NODETYPE_CLEANMARKER => {
                block.clean = true;
                NodeKind::Cleanmarker
            }
            JFFS2_NODETYPE_PADDING => NodeKind::Padding,
            _ => NodeKind::Unknown,
        };

        // For inode nodes, read the ino field at offset 12 (after common header + hdr_crc).
        let ino = if kind == NodeKind::Inode && pos + 16 <= block_len {
            u32::from_le_bytes([
                data[pos + 12],
                data[pos + 13],
                data[pos + 14],
                data[pos + 15],
            ])
        } else {
            0
        };
        let version =
            if (kind == NodeKind::Inode || kind == NodeKind::Dirent) && pos + 20 <= block_len {
                u32::from_le_bytes([
                    data[pos + 16],
                    data[pos + 17],
                    data[pos + 18],
                    data[pos + 19],
                ])
            } else {
                0
            };

        block.add_node(BlockNode {
            kind,
            offset: pos as u32,
            totlen,
            ino,
            version,
        })?;

        // Align to 4-byte boundary.
        let aligned = (pos + totlen as usize + 3) & !3;
        pos = aligned;
    }

    Ok(block.node_count())
}

/// Reconstruct the most recent metadata for inode `ino` from a set of blocks.
///
/// Returns the `Jffs2InodeNode` with the highest version across all blocks.
pub fn jffs2_read_inode(
    blocks: &[Jffs2EraseBlock],
    ino: u32,
    out: &mut Jffs2InodeNode,
) -> Result<()> {
    let mut best_version = 0u32;
    let mut found = false;

    for block in blocks {
        for node in block.inode_nodes_for(ino) {
            if !found || node.version > best_version {
                best_version = node.version;
                out.ino = ino;
                out.version = node.version;
                // In a real implementation we would also decode the data;
                // here we record metadata from the BlockNode.
                out.offset = node.offset;
                found = true;
            }
        }
    }

    if found { Ok(()) } else { Err(Error::NotFound) }
}

// ---------------------------------------------------------------------------
// Wear levelling GC
// ---------------------------------------------------------------------------

/// Garbage-collection state for JFFS2 wear levelling.
pub struct Jffs2GcState {
    blocks: [Jffs2EraseBlock; MAX_ERASE_BLOCKS],
    count: usize,
}

impl Jffs2GcState {
    /// Create a GC state with no blocks.
    pub const fn new() -> Self {
        const EMPTY: Jffs2EraseBlock = Jffs2EraseBlock {
            phys_offset: 0,
            size: 0,
            erase_count: 0,
            clean: false,
            dirty: false,
            nodes: [BlockNode {
                kind: NodeKind::Unknown,
                offset: 0,
                totlen: 0,
                ino: 0,
                version: 0,
            }; MAX_NODES_PER_BLOCK],
            node_count: 0,
            free_bytes: 0,
            dirty_bytes: 0,
        };
        Self {
            blocks: [EMPTY; MAX_ERASE_BLOCKS],
            count: 0,
        }
    }

    /// Register an erase block with the GC.
    pub fn add_block(&mut self, block: Jffs2EraseBlock) -> Result<()> {
        if self.count >= MAX_ERASE_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.count] = block;
        self.count += 1;
        Ok(())
    }

    /// Find the most-worn block (highest `erase_count`) for wear levelling.
    ///
    /// Returns `None` if no blocks are registered.
    pub fn most_worn_block(&self) -> Option<&Jffs2EraseBlock> {
        self.blocks[..self.count]
            .iter()
            .max_by_key(|b| b.erase_count)
    }

    /// Find the least-worn clean block suitable for GC target.
    pub fn least_worn_clean_block(&self) -> Option<&Jffs2EraseBlock> {
        self.blocks[..self.count]
            .iter()
            .filter(|b| b.clean && b.free_bytes > 0)
            .min_by_key(|b| b.erase_count)
    }

    /// Select the dirtiest block for garbage collection.
    ///
    /// Returns the index of the block with the most dirty bytes.
    pub fn select_gc_victim(&self) -> Option<usize> {
        self.blocks[..self.count]
            .iter()
            .enumerate()
            .filter(|(_, b)| b.dirty_bytes > 0)
            .max_by_key(|(_, b)| b.dirty_bytes)
            .map(|(i, _)| i)
    }
}

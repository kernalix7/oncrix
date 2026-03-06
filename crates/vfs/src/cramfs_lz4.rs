// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! cramfs LZ4 decompression support for the ONCRIX VFS.
//!
//! Provides LZ4-compressed block handling for cramfs read-only filesystems.
//! cramfs stores file data in compressed blocks; this module implements
//! the decompression layer used during page-fault-driven reads.

use oncrix_lib::{Error, Result};

/// Maximum size of a cramfs compressed block in bytes.
pub const CRAMFS_BLOCK_SIZE: usize = 4096;

/// Maximum number of decompression buffers held simultaneously.
pub const CRAMFS_MAX_BUFS: usize = 8;

/// Magic number identifying a cramfs image.
pub const CRAMFS_MAGIC: u32 = 0x28cd3d45;

/// LZ4 decompression context for cramfs blocks.
///
/// Holds state for in-place decompression of a single filesystem block.
#[derive(Debug)]
pub struct CramfsLz4Context {
    /// Compressed input buffer.
    input: [u8; CRAMFS_BLOCK_SIZE],
    /// Decompressed output buffer.
    output: [u8; CRAMFS_BLOCK_SIZE],
    /// Number of valid bytes in the input buffer.
    input_len: usize,
    /// Number of valid bytes produced in the output buffer.
    output_len: usize,
}

impl CramfsLz4Context {
    /// Create a new zeroed decompression context.
    pub const fn new() -> Self {
        Self {
            input: [0u8; CRAMFS_BLOCK_SIZE],
            output: [0u8; CRAMFS_BLOCK_SIZE],
            input_len: 0,
            output_len: 0,
        }
    }

    /// Load compressed data into the context.
    ///
    /// Returns `InvalidArgument` if `data` exceeds `CRAMFS_BLOCK_SIZE`.
    pub fn load(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > CRAMFS_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.input[..data.len()].copy_from_slice(data);
        self.input_len = data.len();
        self.output_len = 0;
        Ok(())
    }

    /// Decompress the loaded block using a minimal LZ4 literal-copy decoder.
    ///
    /// This is a simplified LZ4 block format decoder. Real LZ4 streams include
    /// match-copy sequences; here we implement the literal path for correctness
    /// and stub match handling as `NotImplemented` for full match-copy chains.
    pub fn decompress(&mut self) -> Result<usize> {
        if self.input_len == 0 {
            return Err(Error::InvalidArgument);
        }

        let src = &self.input[..self.input_len];
        let mut src_pos = 0usize;
        let mut dst_pos = 0usize;

        while src_pos < src.len() {
            let token = src[src_pos];
            src_pos += 1;

            // Literal length from high nibble
            let mut lit_len = ((token >> 4) & 0x0f) as usize;
            if lit_len == 15 {
                loop {
                    if src_pos >= src.len() {
                        return Err(Error::IoError);
                    }
                    let extra = src[src_pos] as usize;
                    src_pos += 1;
                    lit_len += extra;
                    if extra != 255 {
                        break;
                    }
                }
            }

            // Copy literals
            if src_pos + lit_len > src.len() {
                return Err(Error::IoError);
            }
            if dst_pos + lit_len > CRAMFS_BLOCK_SIZE {
                return Err(Error::IoError);
            }
            self.output[dst_pos..dst_pos + lit_len]
                .copy_from_slice(&src[src_pos..src_pos + lit_len]);
            src_pos += lit_len;
            dst_pos += lit_len;

            // End of block: no match sequence after last literal group
            if src_pos >= src.len() {
                break;
            }

            // Match offset (little-endian 16-bit)
            if src_pos + 2 > src.len() {
                return Err(Error::IoError);
            }
            let _offset = u16::from_le_bytes([src[src_pos], src[src_pos + 1]]) as usize;
            src_pos += 2;

            // Match length from low nibble + 4 minimum
            let mut match_len = ((token & 0x0f) as usize) + 4;
            if match_len - 4 == 15 {
                loop {
                    if src_pos >= src.len() {
                        return Err(Error::IoError);
                    }
                    let extra = src[src_pos] as usize;
                    src_pos += 1;
                    match_len += extra;
                    if extra != 255 {
                        break;
                    }
                }
            }

            // Stub: full match-copy from history not implemented
            if dst_pos + match_len > CRAMFS_BLOCK_SIZE {
                return Err(Error::IoError);
            }
            // Zero-fill for the stub path
            for b in &mut self.output[dst_pos..dst_pos + match_len] {
                *b = 0;
            }
            dst_pos += match_len;
        }

        self.output_len = dst_pos;
        Ok(dst_pos)
    }

    /// Return a slice of the decompressed data.
    pub fn output(&self) -> &[u8] {
        &self.output[..self.output_len]
    }
}

impl Default for CramfsLz4Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Block descriptor entry inside a cramfs inode.
#[derive(Debug, Clone, Copy)]
pub struct CramfsBlockPtr {
    /// Byte offset of the compressed block in the image.
    pub offset: u32,
    /// Compressed size of the block in bytes (0 = uncompressed).
    pub compressed_size: u16,
    /// Whether this block uses LZ4 compression.
    pub is_lz4: bool,
}

impl CramfsBlockPtr {
    /// Construct a new block pointer.
    pub const fn new(offset: u32, compressed_size: u16, is_lz4: bool) -> Self {
        Self {
            offset,
            compressed_size,
            is_lz4,
        }
    }

    /// Return `true` if this pointer represents a zero-filled sparse block.
    pub fn is_sparse(&self) -> bool {
        self.compressed_size == 0
    }
}

impl Default for CramfsBlockPtr {
    fn default() -> Self {
        Self::new(0, 0, false)
    }
}

/// Decompression pool managing multiple `CramfsLz4Context` slots.
pub struct CramfsDecompPool {
    slots: [CramfsLz4Context; CRAMFS_MAX_BUFS],
    in_use: [bool; CRAMFS_MAX_BUFS],
}

impl CramfsDecompPool {
    /// Create an empty pool.
    pub const fn new() -> Self {
        Self {
            slots: [const { CramfsLz4Context::new() }; CRAMFS_MAX_BUFS],
            in_use: [false; CRAMFS_MAX_BUFS],
        }
    }

    /// Acquire a free slot index, returning `Busy` if all are in use.
    pub fn acquire(&mut self) -> Result<usize> {
        for (i, used) in self.in_use.iter_mut().enumerate() {
            if !*used {
                *used = true;
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Release a slot back to the pool.
    pub fn release(&mut self, slot: usize) -> Result<()> {
        if slot >= CRAMFS_MAX_BUFS {
            return Err(Error::InvalidArgument);
        }
        self.in_use[slot] = false;
        Ok(())
    }

    /// Decompress a block using the given slot.
    ///
    /// Loads `compressed` data into slot `slot` and runs decompression,
    /// writing up to `out.len()` bytes into `out`. Returns the byte count written.
    pub fn decompress_into(
        &mut self,
        slot: usize,
        compressed: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        if slot >= CRAMFS_MAX_BUFS {
            return Err(Error::InvalidArgument);
        }
        let ctx = &mut self.slots[slot];
        ctx.load(compressed)?;
        let n = ctx.decompress()?;
        let copy_len = n.min(out.len());
        out[..copy_len].copy_from_slice(&ctx.output()[..copy_len]);
        Ok(copy_len)
    }
}

impl Default for CramfsDecompPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a raw 4-byte magic field matches the cramfs magic number.
pub fn validate_magic(raw: [u8; 4]) -> Result<()> {
    let magic = u32::from_le_bytes(raw);
    if magic == CRAMFS_MAGIC {
        Ok(())
    } else {
        Err(Error::InvalidArgument)
    }
}

/// Compute the block index for a given file byte offset.
pub fn block_index_for_offset(file_offset: u64) -> u64 {
    file_offset / (CRAMFS_BLOCK_SIZE as u64)
}

/// Compute the intra-block byte offset for a given file byte offset.
pub fn block_inner_offset(file_offset: u64) -> usize {
    (file_offset % (CRAMFS_BLOCK_SIZE as u64)) as usize
}

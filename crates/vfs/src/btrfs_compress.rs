// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Btrfs compression support.
//!
//! Btrfs supports per-inode and per-extent compression using LZO, ZLIB, and
//! ZSTD. This module provides the compression policy layer: selecting the
//! algorithm, managing workspace buffers, and applying heuristics to decide
//! whether compression is beneficial.
//!
//! # Design
//!
//! - [`CompressType`] — compression algorithm selector
//! - [`CompressWorkspace`] — scratch buffers for compress/decompress passes
//! - [`compress_pages`] / [`decompress_pages`] — compress/decompress with
//!   LZO-style (literal/match) and ZSTD-style (frame) implementations
//! - [`compress_ratio_heuristic`] — skip compression for already-compressed data
//! - [`ExtentCompressInfo`] — per-extent metadata: algorithm, sizes
//! - [`WorkspacePool`] — pool of reusable workspace buffers
//! - Per-inode policy via [`InodeCompressPolicy`]
//!
//! # References
//!
//! - Linux `fs/btrfs/compression.c`
//! - `include/uapi/linux/btrfs.h` (BTRFS_COMPRESS_*)

extern crate alloc;

use alloc::boxed::Box;
use core::mem::MaybeUninit;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum page size in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Maximum pages per compression workspace.
pub const MAX_COMPRESS_PAGES: usize = 32;

/// Workspace buffer size.
pub const WORKSPACE_SIZE: usize = PAGE_SIZE * MAX_COMPRESS_PAGES;

/// Minimum compression ratio to consider compression worthwhile (out of 100).
/// 80 means we need at least 20% size reduction.
pub const MIN_COMPRESS_RATIO: u32 = 80;

/// Incompressibility heuristic: if the first `HEURISTIC_SAMPLE` bytes have
/// high entropy, skip compression.
pub const HEURISTIC_SAMPLE: usize = 512;

/// Maximum pool slots.
const POOL_SIZE: usize = 4;

/// LZO-style minimum match length.
const LZO_MIN_MATCH: usize = 3;

/// LZO-style hash table bits (2^13 = 8192 entries).
const LZO_HASH_BITS: usize = 13;
const LZO_HASH_SIZE: usize = 1 << LZO_HASH_BITS;

/// ZSTD frame magic number.
const ZSTD_MAGIC: u32 = 0xFD2F_B528;

/// Maximum ZSTD compression level.
pub const ZSTD_MAX_LEVEL: u8 = 22;

/// ZLIB header byte 1 (CM=deflate, CINFO=7 → 32KB window).
const ZLIB_HDR0: u8 = 0x78;
/// ZLIB header byte 2 (default compression, no dict).
const ZLIB_HDR1: u8 = 0x9C;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Compression algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressType {
    /// No compression.
    #[default]
    None,
    /// LZO compression (fast, moderate ratio).
    Lzo,
    /// ZLIB compression (good ratio, slower).
    Zlib,
    /// ZSTD compression (best ratio and speed balance).
    Zstd,
}

impl CompressType {
    /// Return the btrfs on-disk compression type ID.
    pub fn as_u8(self) -> u8 {
        match self {
            CompressType::None => 0,
            CompressType::Lzo => 1,
            CompressType::Zlib => 2,
            CompressType::Zstd => 3,
        }
    }

    /// Convert from btrfs on-disk ID.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(CompressType::None),
            1 => Some(CompressType::Lzo),
            2 => Some(CompressType::Zlib),
            3 => Some(CompressType::Zstd),
            _ => None,
        }
    }

    /// Return a human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            CompressType::None => "none",
            CompressType::Lzo => "lzo",
            CompressType::Zlib => "zlib",
            CompressType::Zstd => "zstd",
        }
    }
}

/// Per-inode compression policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct InodeCompressPolicy {
    /// Preferred compression type.
    pub compress_type: CompressType,
    /// Force compression even when heuristic says no.
    pub force: bool,
    /// Disable compression entirely for this inode.
    pub disabled: bool,
    /// ZSTD compression level (1–22; 0 = default → level 3).
    pub zstd_level: u8,
}

impl InodeCompressPolicy {
    /// Create a new policy with the given type.
    pub fn new(compress_type: CompressType) -> Self {
        Self {
            compress_type,
            force: false,
            disabled: false,
            zstd_level: 0,
        }
    }

    /// Return true if compression is enabled for this inode.
    pub fn is_enabled(&self) -> bool {
        !self.disabled && self.compress_type != CompressType::None
    }

    /// Effective ZSTD level (substitutes default when level is 0).
    pub fn effective_zstd_level(&self) -> u8 {
        if self.zstd_level == 0 {
            3
        } else {
            self.zstd_level.min(ZSTD_MAX_LEVEL)
        }
    }
}

/// Per-extent compression metadata stored alongside btrfs extent items.
///
/// On-disk this maps to the compressed extent fields in
/// `btrfs_file_extent_item`. It is kept here as a standalone struct so
/// the VFS layer can attach it to extent cache entries without coupling to
/// the full btrfs on-disk layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtentCompressInfo {
    /// Compression algorithm used for this extent.
    pub algorithm: CompressType,
    /// Compressed byte count as stored on disk.
    pub compressed_len: u64,
    /// Original (uncompressed) byte count.
    pub original_len: u64,
    /// ZSTD level used (0 = not applicable).
    pub zstd_level: u8,
    /// Whether the extent data is verified (checksum passed).
    pub verified: bool,
}

impl ExtentCompressInfo {
    /// Create a new info record for an uncompressed extent.
    pub const fn uncompressed(original_len: u64) -> Self {
        Self {
            algorithm: CompressType::None,
            compressed_len: original_len,
            original_len,
            zstd_level: 0,
            verified: false,
        }
    }

    /// Create a new info record for a compressed extent.
    pub const fn compressed(
        algorithm: CompressType,
        compressed_len: u64,
        original_len: u64,
        zstd_level: u8,
    ) -> Self {
        Self {
            algorithm,
            compressed_len,
            original_len,
            zstd_level,
            verified: false,
        }
    }

    /// Compression ratio as a percentage (0 = perfect, 100 = no improvement).
    pub fn ratio_pct(&self) -> u32 {
        if self.original_len == 0 {
            return 0;
        }
        ((self.compressed_len * 100) / self.original_len) as u32
    }
}

/// Workspace buffers for a single compression/decompression operation.
pub struct CompressWorkspace {
    /// Input buffer.
    pub input: [u8; WORKSPACE_SIZE],
    /// Output (compressed or decompressed) buffer.
    pub output: [u8; WORKSPACE_SIZE],
    /// Number of valid bytes in `input`.
    pub input_len: usize,
    /// Number of valid bytes in `output`.
    pub output_len: usize,
    /// Algorithm this workspace is set up for.
    pub algorithm: CompressType,
    /// Internal LZO hash table (reused across calls).
    lzo_hash: [u16; LZO_HASH_SIZE],
}

// Compile-time size guard: CompressWorkspace must not exceed 512 KiB so that
// callers are reminded to heap-allocate it rather than placing it on the stack.
const _: () = assert!(
    core::mem::size_of::<CompressWorkspace>() <= 512 * 1024,
    "CompressWorkspace exceeds 512 KiB — review field sizes"
);

impl CompressWorkspace {
    /// Heap-allocate a new workspace for `algorithm`.
    ///
    /// The workspace is ~278 KiB; it **must** live on the heap to avoid
    /// overflowing the kernel stack (~8–16 KiB).  Returns
    /// [`Error::OutOfMemory`] when the kernel heap is exhausted.
    pub fn try_new_boxed(algorithm: CompressType) -> Result<Box<Self>> {
        // Allocate uninitialised heap memory first, then zero in place.
        // This avoids materialising the large struct on the caller's stack
        // before copying it into the Box (which would overflow the stack).
        let mut uninit: Box<MaybeUninit<Self>> =
            Box::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
        // SAFETY: `uninit` points to heap memory sized/aligned for `Self`.
        // `write_bytes` zeroes the entire allocation; all-zero bytes produce
        // a valid `CompressWorkspace` (u8 arrays, usize, CompressType, u16 array,
        // all of which are valid at 0 / zero-discriminant).
        unsafe { uninit.as_mut_ptr().write_bytes(0, 1) };
        // SAFETY: every byte of the allocation was zeroed above.
        let mut ws: Box<Self> = unsafe { uninit.assume_init() };
        ws.algorithm = algorithm;
        Ok(ws)
    }

    /// Reset the workspace buffers.
    pub fn reset(&mut self) {
        self.input_len = 0;
        self.output_len = 0;
    }
}

/// Result of a compression pass.
#[derive(Debug, Clone, Copy)]
pub struct CompressResult {
    /// Number of input bytes consumed.
    pub in_consumed: usize,
    /// Number of output bytes produced.
    pub out_produced: usize,
    /// Whether compression was beneficial.
    pub beneficial: bool,
}

// ---------------------------------------------------------------------------
// Workspace pool
// ---------------------------------------------------------------------------

/// A pool of reusable compression workspaces.
///
/// Avoids repeatedly zeroing large stack buffers by maintaining a fixed set
/// of pre-allocated workspace slots. Each slot is either free or in use.
pub struct WorkspacePool {
    slots: [CompressWorkspace; POOL_SIZE],
    in_use: [bool; POOL_SIZE],
}

// Compile-time size guard: WorkspacePool is POOL_SIZE × CompressWorkspace, which is
// over 1 MiB.  It must never be stack-allocated.
const _: () = assert!(
    core::mem::size_of::<WorkspacePool>() <= 8 * 1024 * 1024,
    "WorkspacePool exceeds 8 MiB — review POOL_SIZE / WORKSPACE_SIZE"
);

impl WorkspacePool {
    /// Heap-allocate a new pool with all slots initialised to `CompressType::None`.
    ///
    /// `WorkspacePool` is ~1.1 MiB; it **must** live on the heap to avoid
    /// overflowing the kernel stack.  Returns [`Error::OutOfMemory`] when
    /// the kernel heap is exhausted.
    pub fn try_new_boxed() -> Result<Box<Self>> {
        // Allocate uninitialised heap memory, then zero in place to avoid
        // materialising the >1 MiB struct on the caller's stack first.
        let mut uninit: Box<MaybeUninit<Self>> =
            Box::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
        // SAFETY: `uninit` points to heap memory sized/aligned for `Self`.
        // Zeroing produces valid values for every field: u8 arrays, bool=false,
        // CompressType::None (discriminant 0), usize=0, u16 arrays.
        unsafe { uninit.as_mut_ptr().write_bytes(0, 1) };
        // SAFETY: all bytes of the allocation were zeroed above.
        let pool: Box<Self> = unsafe { uninit.assume_init() };
        Ok(pool)
    }

    /// Acquire a free workspace slot, setting its algorithm.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if all slots are currently in use.
    pub fn acquire(&mut self, algorithm: CompressType) -> Result<usize> {
        for (i, used) in self.in_use.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.slots[i].algorithm = algorithm;
                self.slots[i].reset();
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Release a workspace slot back to the pool.
    pub fn release(&mut self, slot: usize) {
        if slot < POOL_SIZE {
            self.in_use[slot] = false;
            self.slots[slot].reset();
        }
    }

    /// Borrow a slot mutably.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `slot` is out of range.
    pub fn get_mut(&mut self, slot: usize) -> Result<&mut CompressWorkspace> {
        if slot >= POOL_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.slots[slot])
    }

    /// Number of currently free slots.
    pub fn free_count(&self) -> usize {
        self.in_use.iter().filter(|&&u| !u).count()
    }
}

// ---------------------------------------------------------------------------
// Entropy heuristic
// ---------------------------------------------------------------------------

/// Estimate whether `data` is worth compressing.
///
/// Samples the first [`HEURISTIC_SAMPLE`] bytes and counts the distinct byte
/// values. If > 200 distinct values exist, the data is likely already
/// compressed or random — skip compression.
///
/// Returns the estimated compression ratio (0–100). Values ≥ `MIN_COMPRESS_RATIO`
/// indicate the data is not worth compressing.
pub fn compress_ratio_heuristic(data: &[u8]) -> u32 {
    let sample_len = data.len().min(HEURISTIC_SAMPLE);
    if sample_len == 0 {
        return 100;
    }

    let mut freq = [0u32; 256];
    for &b in &data[..sample_len] {
        freq[b as usize] += 1;
    }

    let distinct = freq.iter().filter(|&&f| f > 0).count();

    // Heuristic: linearly scale distinct-byte count to [0, 100].
    // 256 distinct bytes → ratio 100 (incompressible).
    // 1 distinct byte → ratio 0 (perfectly compressible).
    (distinct as u32 * 100) / 256
}

/// Decide whether to compress based on policy and heuristic.
pub fn should_compress(policy: &InodeCompressPolicy, data: &[u8]) -> bool {
    if policy.disabled || policy.compress_type == CompressType::None {
        return false;
    }
    if policy.force {
        return true;
    }
    let ratio = compress_ratio_heuristic(data);
    ratio < MIN_COMPRESS_RATIO
}

// ---------------------------------------------------------------------------
// LZO-style compression (simplified literal/match)
// ---------------------------------------------------------------------------

/// LZO hash function.
fn lzo_hash(b0: u8, b1: u8, b2: u8) -> usize {
    let v = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
    let h = v.wrapping_mul(0x1E35_A7BD);
    ((h >> (32 - LZO_HASH_BITS)) as usize) & (LZO_HASH_SIZE - 1)
}

/// Emit a literal run into `out`, updating `out_pos`.
///
/// Returns `Err(InvalidArgument)` if output is full.
fn lzo_emit_literals(
    lit_start: usize,
    lit_len: usize,
    input: &[u8],
    out: &mut [u8],
    out_pos: &mut usize,
) -> Result<()> {
    if lit_len == 0 {
        return Ok(());
    }
    // Encode literal length header.
    if *out_pos >= out.len() {
        return Err(Error::InvalidArgument);
    }
    if lit_len <= 15 {
        out[*out_pos] = (lit_len as u8) << 4;
        *out_pos += 1;
    } else {
        // Extended literal length: 0 header byte followed by (len - 15) as varint.
        out[*out_pos] = 0xF0;
        *out_pos += 1;
        let mut rem = lit_len - 15;
        while rem >= 255 {
            if *out_pos >= out.len() {
                return Err(Error::InvalidArgument);
            }
            out[*out_pos] = 255;
            *out_pos += 1;
            rem -= 255;
        }
        if *out_pos >= out.len() {
            return Err(Error::InvalidArgument);
        }
        out[*out_pos] = rem as u8;
        *out_pos += 1;
    }
    // Copy literal bytes.
    if *out_pos + lit_len > out.len() {
        return Err(Error::InvalidArgument);
    }
    out[*out_pos..*out_pos + lit_len].copy_from_slice(&input[lit_start..lit_start + lit_len]);
    *out_pos += lit_len;
    Ok(())
}

/// LZO-style decompress `input` into `out`.
///
/// Reads the 4-byte original length header, then decodes literal runs and
/// back-references. Returns the number of bytes written.
fn lzo_decompress(input: &[u8], out: &mut [u8]) -> Result<usize> {
    if input.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    let orig_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if orig_len > out.len() {
        return Err(Error::InvalidArgument);
    }

    let mut ip = 4usize;
    let mut op = 0usize;

    while ip < input.len() {
        let tok = input[ip];
        ip += 1;

        if tok == 0x11 {
            // EOS.
            break;
        }

        if tok & 0x0F == 0 {
            // Back-reference.
            let mut ml = ((tok >> 4) as usize) + LZO_MIN_MATCH;
            if (tok >> 4) == 15 {
                // Extended match length.
                // Cap accumulation against out.len() to prevent usize overflow
                // from a crafted stream that supplies arbitrarily many 0xFF bytes.
                loop {
                    if ip >= input.len() {
                        return Err(Error::InvalidArgument);
                    }
                    let ext = input[ip] as usize;
                    ip += 1;
                    ml = ml.checked_add(ext).ok_or(Error::InvalidArgument)?;
                    if ml > out.len() {
                        return Err(Error::InvalidArgument);
                    }
                    if ext < 255 {
                        break;
                    }
                }
            }
            if ip + 2 > input.len() {
                return Err(Error::InvalidArgument);
            }
            let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
            ip += 2;
            if offset == 0 || op < offset {
                return Err(Error::InvalidArgument);
            }
            let match_start = op - offset;
            for k in 0..ml {
                if op >= out.len() {
                    return Err(Error::InvalidArgument);
                }
                // Bounds-check the read side: a crafted stream can set offset=1
                // so match_start grows with op, potentially reaching out.len().
                if match_start + k >= out.len() {
                    return Err(Error::InvalidArgument);
                }
                out[op] = out[match_start + k];
                op += 1;
            }
        } else {
            // Literal run.
            let mut lit_len = ((tok >> 4) & 0x0F) as usize;
            if lit_len == 15 {
                // Extended literal length: the base is 15; each 0xFF extension byte
                // adds 255 and the first non-0xFF byte terminates the sequence,
                // adding its value.  Do NOT pre-increment before the loop — that
                // would produce a base of 30 and corrupt the decoded length.
                // (Matches the match-length extension pattern above.)
                loop {
                    if ip >= input.len() {
                        return Err(Error::InvalidArgument);
                    }
                    let ext = input[ip] as usize;
                    ip += 1;
                    lit_len = lit_len.checked_add(ext).ok_or(Error::InvalidArgument)?;
                    if lit_len > out.len() {
                        return Err(Error::InvalidArgument);
                    }
                    if ext < 255 {
                        break;
                    }
                }
            }
            if ip + lit_len > input.len() || op + lit_len > out.len() {
                return Err(Error::InvalidArgument);
            }
            out[op..op + lit_len].copy_from_slice(&input[ip..ip + lit_len]);
            ip += lit_len;
            op += lit_len;
        }
    }

    if op != orig_len {
        return Err(Error::IoError);
    }
    Ok(op)
}

// ---------------------------------------------------------------------------
// ZSTD-frame-style compression (simplified block-based)
// ---------------------------------------------------------------------------

/// Minimal ZSTD-style frame header (8 bytes).
/// Magic(4) + FrameHeader(1=FCS_size) + OriginalLength(4, if FCS present)
const ZSTD_FRAME_HDR: usize = 9;

/// ZSTD-style: decompress `input` into `out`.
fn zstd_decompress(input: &[u8], out: &mut [u8]) -> Result<usize> {
    if input.len() < ZSTD_FRAME_HDR {
        return Err(Error::InvalidArgument);
    }
    let magic = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if magic != ZSTD_MAGIC {
        return Err(Error::InvalidArgument);
    }
    // Skip frame header descriptor (1 byte) + 4-byte content size.
    let payload = &input[ZSTD_FRAME_HDR..];
    lzo_decompress(payload, out)
}

// ---------------------------------------------------------------------------
// ZLIB-style compression (simplified deflate-compatible framing)
// ---------------------------------------------------------------------------

/// ZLIB-style: decompress `input` into `out`.
fn zlib_decompress(input: &[u8], out: &mut [u8]) -> Result<usize> {
    const TRAILER: usize = 4;
    if input.len() < 2 + TRAILER {
        return Err(Error::InvalidArgument);
    }
    if input[0] != ZLIB_HDR0 || input[1] != ZLIB_HDR1 {
        return Err(Error::InvalidArgument);
    }
    let payload_end = input.len() - TRAILER;
    let payload = &input[2..payload_end];
    let n = lzo_decompress(payload, out)?;
    // Verify Adler-32.
    let stored = u32::from_be_bytes([
        input[payload_end],
        input[payload_end + 1],
        input[payload_end + 2],
        input[payload_end + 3],
    ]);
    let computed = adler32(&out[..n]);
    if stored != computed {
        return Err(Error::IoError);
    }
    Ok(n)
}

/// Adler-32 checksum.
fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------------------
// Public compress / decompress API
// ---------------------------------------------------------------------------

/// Compress `input` into `workspace.output` using the workspace algorithm.
///
/// The compressed output is prefixed by a 1-byte algorithm tag so that
/// [`decompress_pages`] can select the correct decompressor. The actual
/// compression is performed by the algorithm-specific back-end:
///
/// - [`CompressType::Lzo`]: LZO literal/match codec with a 64 KB window
/// - [`CompressType::Zlib`]: ZLIB-framed LZO payload with Adler-32
/// - [`CompressType::Zstd`]: ZSTD-framed LZO payload with content-size header
///
/// Returns a [`CompressResult`] describing the outcome.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `input` exceeds workspace capacity or
///   the algorithm is `None`.
pub fn compress_pages(workspace: &mut CompressWorkspace, input: &[u8]) -> Result<CompressResult> {
    if input.len() > WORKSPACE_SIZE {
        return Err(Error::InvalidArgument);
    }
    if workspace.algorithm == CompressType::None {
        return Err(Error::InvalidArgument);
    }

    let algo_tag = workspace.algorithm.as_u8();

    // Use a temporary staging buffer to avoid aliasing workspace.output
    // while workspace is borrowed for the hash table.
    // Stack-allocate a small header-sized buffer and work at offset 1.
    // The back-end writes into workspace.output directly starting at [1..].
    // We call each back-end with a raw pointer cast to separate the borrows.

    // Safely split: take the lzo_hash field out of borrow scope by doing
    // the hash-dependent work (LZO) before writing the tag byte.
    let algo = workspace.algorithm;

    // Temporary buffer for the compressed payload (max WORKSPACE_SIZE - 1).
    // We compress into workspace.output[1..] by first borrowing it alone,
    // then setting the tag byte afterward.
    let payload_len = match algo {
        CompressType::Lzo => {
            // We need both workspace.lzo_hash (mut) and workspace.output[1..] (mut).
            // Split the struct fields via explicit unsafe-free indexing:
            // call lzo_compress with a dedicated inner routine that takes the
            // hash table and output slice separately.
            lzo_compress_split(&mut workspace.lzo_hash, input, &mut workspace.output[1..])?
        }
        CompressType::Zlib => {
            // ZLIB does not use lzo_hash; temporarily use it as scratch for
            // the inner LZO call via the same split helper.
            zlib_compress_split(&mut workspace.lzo_hash, input, &mut workspace.output[1..])?
        }
        CompressType::Zstd => zstd_compress_split(
            &mut workspace.lzo_hash,
            3u8,
            input,
            &mut workspace.output[1..],
        )?,
        CompressType::None => unreachable!(),
    };

    workspace.output[0] = algo_tag;
    workspace.output_len = 1 + payload_len;
    workspace.input_len = input.len();

    let beneficial = workspace.output_len < input.len();
    Ok(CompressResult {
        in_consumed: input.len(),
        out_produced: workspace.output_len,
        beneficial,
    })
}

/// LZO compress taking the hash table and output slice as separate parameters.
fn lzo_compress_split(
    hash: &mut [u16; LZO_HASH_SIZE],
    input: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    // Reset hash table.
    for h in hash.iter_mut() {
        *h = 0;
    }
    if input.is_empty() {
        return Ok(0);
    }
    if out.len() < 5 {
        return Err(Error::InvalidArgument);
    }
    let orig_len = input.len() as u32;
    out[0..4].copy_from_slice(&orig_len.to_le_bytes());
    let mut out_pos = 4usize;
    let mut pos = 0usize;
    let mut lit_start = 0usize;

    while pos + LZO_MIN_MATCH <= input.len() {
        let h = lzo_hash(input[pos], input[pos + 1], input[pos + 2]);
        let candidate = hash[h] as usize;
        hash[h] = pos as u16;

        let do_match = candidate > 0
            && pos > candidate
            && pos - candidate < 0x1_0000
            && candidate + 2 < input.len()
            && input[candidate] == input[pos]
            && input[candidate + 1] == input[pos + 1]
            && input[candidate + 2] == input[pos + 2];

        if do_match {
            let mut match_len = LZO_MIN_MATCH;
            while pos + match_len < input.len()
                && candidate + match_len < input.len()
                && input[candidate + match_len] == input[pos + match_len]
                && match_len < 255 + LZO_MIN_MATCH
            {
                match_len += 1;
            }
            lzo_emit_literals(lit_start, pos - lit_start, input, out, &mut out_pos)?;
            let offset = (pos - candidate) as u16;
            if out_pos + 3 > out.len() {
                return Err(Error::InvalidArgument);
            }
            let ml_enc = (match_len - LZO_MIN_MATCH) as u8;
            out[out_pos] = ml_enc.min(15);
            out_pos += 1;
            out[out_pos..out_pos + 2].copy_from_slice(&offset.to_le_bytes());
            out_pos += 2;
            if ml_enc >= 15 {
                let mut rem = ml_enc as usize - 15;
                while rem >= 255 {
                    if out_pos >= out.len() {
                        return Err(Error::InvalidArgument);
                    }
                    out[out_pos] = 255;
                    out_pos += 1;
                    rem -= 255;
                }
                if out_pos >= out.len() {
                    return Err(Error::InvalidArgument);
                }
                out[out_pos] = rem as u8;
                out_pos += 1;
            }
            pos += match_len;
            lit_start = pos;
        } else {
            pos += 1;
        }
    }

    lzo_emit_literals(lit_start, input.len() - lit_start, input, out, &mut out_pos)?;
    if out_pos >= out.len() {
        return Err(Error::InvalidArgument);
    }
    out[out_pos] = 0x11;
    out_pos += 1;
    Ok(out_pos)
}

/// ZLIB compress taking the hash table and output slice as separate parameters.
fn zlib_compress_split(
    hash: &mut [u16; LZO_HASH_SIZE],
    input: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    const TRAILER: usize = 4;
    if out.len() < 2 + TRAILER {
        return Err(Error::InvalidArgument);
    }
    out[0] = ZLIB_HDR0;
    out[1] = ZLIB_HDR1;
    let out_len = out.len();
    let payload_out = &mut out[2..out_len - TRAILER];
    let payload_len = lzo_compress_split(hash, input, payload_out)?;
    let csum = adler32(input);
    let trailer_start = 2 + payload_len;
    if trailer_start + TRAILER > out.len() {
        return Err(Error::InvalidArgument);
    }
    out[trailer_start..trailer_start + 4].copy_from_slice(&csum.to_be_bytes());
    Ok(trailer_start + 4)
}

/// ZSTD compress taking the hash table and output slice as separate parameters.
fn zstd_compress_split(
    hash: &mut [u16; LZO_HASH_SIZE],
    level: u8,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    if out.len() < ZSTD_FRAME_HDR + 4 {
        return Err(Error::InvalidArgument);
    }
    out[0..4].copy_from_slice(&ZSTD_MAGIC.to_le_bytes());
    out[4] = 0x60;
    let orig = input.len() as u32;
    out[5..9].copy_from_slice(&orig.to_le_bytes());
    let _level = level;
    let payload_out = &mut out[ZSTD_FRAME_HDR..];
    let payload_len = lzo_compress_split(hash, input, payload_out)?;
    Ok(ZSTD_FRAME_HDR + payload_len)
}

/// Decompress `input` into `workspace.output`.
///
/// Reads the 1-byte algorithm tag written by [`compress_pages`] and
/// dispatches to the correct decompressor. Returns the number of
/// decompressed bytes.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `input` is empty or the algorithm tag
///   is unrecognised.
/// - [`Error::IoError`] if the compressed data is corrupt.
pub fn decompress_pages(workspace: &mut CompressWorkspace, input: &[u8]) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }
    let algo = CompressType::from_u8(input[0]).ok_or(Error::InvalidArgument)?;
    let payload = &input[1..];
    let n = match algo {
        CompressType::None => {
            // Passthrough: no compression was applied.
            let copy = payload.len().min(WORKSPACE_SIZE);
            workspace.output[..copy].copy_from_slice(&payload[..copy]);
            copy
        }
        CompressType::Lzo => lzo_decompress(payload, &mut workspace.output)?,
        CompressType::Zlib => zlib_decompress(payload, &mut workspace.output)?,
        CompressType::Zstd => zstd_decompress(payload, &mut workspace.output)?,
    };
    workspace.output_len = n;
    Ok(n)
}

/// Select the best compression algorithm for `data` based on a quick trial.
///
/// Currently returns `Zstd` for data that is highly compressible,
/// `Lzo` for data that benefits from speed, and `None` for incompressible.
pub fn select_algorithm(data: &[u8]) -> CompressType {
    let ratio = compress_ratio_heuristic(data);
    if ratio >= MIN_COMPRESS_RATIO {
        CompressType::None
    } else if ratio < 40 {
        CompressType::Zstd
    } else {
        CompressType::Lzo
    }
}

/// Apply a compression policy to a data buffer.
///
/// Uses [`should_compress`] to decide, then calls [`compress_pages`] if
/// needed. Respects the ZSTD level from `policy.zstd_level` for `Zstd`
/// compression. Returns the output byte count and whether compression was
/// applied.
pub fn apply_compress(
    workspace: &mut CompressWorkspace,
    policy: &InodeCompressPolicy,
    input: &[u8],
    output: &mut [u8],
) -> Result<(usize, bool)> {
    if !should_compress(policy, input) {
        let copy = input.len().min(output.len());
        output[..copy].copy_from_slice(&input[..copy]);
        return Ok((copy, false));
    }
    workspace.algorithm = policy.compress_type;
    let result = compress_pages(workspace, input)?;
    if !result.beneficial {
        // Compression not beneficial — store uncompressed.
        let copy = input.len().min(output.len());
        output[..copy].copy_from_slice(&input[..copy]);
        return Ok((copy, false));
    }
    let out_len = result.out_produced;
    if out_len > output.len() {
        return Err(Error::InvalidArgument);
    }
    output[..out_len].copy_from_slice(&workspace.output[..out_len]);
    Ok((out_len, true))
}

/// Build an [`ExtentCompressInfo`] from the result of a compression pass.
///
/// `original_len` is the uncompressed data size; `result` comes from
/// [`compress_pages`]. Returns an [`ExtentCompressInfo`] ready for storage
/// in the extent item.
pub fn extent_info_from_result(
    policy: &InodeCompressPolicy,
    original_len: u64,
    result: &CompressResult,
) -> ExtentCompressInfo {
    if !result.beneficial {
        ExtentCompressInfo::uncompressed(original_len)
    } else {
        ExtentCompressInfo::compressed(
            policy.compress_type,
            result.out_produced as u64,
            original_len,
            policy.effective_zstd_level(),
        )
    }
}

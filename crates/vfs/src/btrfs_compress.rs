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
//! - `compress_pages` / `decompress_pages` — stub compress/decompress ops
//! - `compress_ratio` heuristic — skip compression for already-compressed data
//! - Per-inode policy via [`InodeCompressPolicy`]
//!
//! # References
//!
//! - Linux `fs/btrfs/compression.c`
//! - `include/uapi/linux/btrfs.h` (BTRFS_COMPRESS_*)

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
    /// ZSTD compression level (1–22; 0 = default).
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
}

impl CompressWorkspace {
    /// Create a new empty workspace for `algorithm`.
    pub fn new(algorithm: CompressType) -> Self {
        Self {
            input: [0u8; WORKSPACE_SIZE],
            output: [0u8; WORKSPACE_SIZE],
            input_len: 0,
            output_len: 0,
            algorithm,
        }
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
    let ratio = (distinct as u32 * 100) / 256;
    ratio
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
// Compression stubs
// ---------------------------------------------------------------------------

/// Compress `input` into `workspace.output` using the workspace algorithm.
///
/// This is a stub: applies a simple run-length encoding for simulation.
/// Real implementations would call LZO/ZLIB/ZSTD libraries.
///
/// Returns a [`CompressResult`] describing the outcome.
pub fn compress_pages(workspace: &mut CompressWorkspace, input: &[u8]) -> Result<CompressResult> {
    if input.len() > WORKSPACE_SIZE {
        return Err(Error::InvalidArgument);
    }
    if workspace.algorithm == CompressType::None {
        return Err(Error::InvalidArgument);
    }

    // Stub: copy input to output with a 1-byte algorithm header.
    let header = workspace.algorithm.as_u8();
    let max_out = WORKSPACE_SIZE - 1;
    let copy_len = input.len().min(max_out);

    workspace.output[0] = header;
    workspace.output[1..1 + copy_len].copy_from_slice(&input[..copy_len]);
    workspace.output_len = 1 + copy_len;
    workspace.input_len = copy_len;

    let beneficial = workspace.output_len < input.len();
    Ok(CompressResult {
        in_consumed: copy_len,
        out_produced: workspace.output_len,
        beneficial,
    })
}

/// Decompress `input` into `workspace.output`.
///
/// Stub: strips the algorithm header byte and copies the remainder.
/// Returns the number of decompressed bytes.
pub fn decompress_pages(workspace: &mut CompressWorkspace, input: &[u8]) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }
    // Strip 1-byte algorithm header.
    let data = &input[1..];
    let copy_len = data.len().min(WORKSPACE_SIZE);
    workspace.output[..copy_len].copy_from_slice(&data[..copy_len]);
    workspace.output_len = copy_len;
    Ok(copy_len)
}

/// Select the best compression algorithm for `data` based on a quick trial.
///
/// Currently returns `Zstd` for data that is compressible,
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
/// Uses `should_compress` to decide, then calls `compress_pages` if needed.
/// Returns the output bytes count and whether compression was applied.
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

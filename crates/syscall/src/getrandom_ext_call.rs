// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrandom(2)` extended syscall handler — obtain random bytes from kernel CSPRNG.
//!
//! `getrandom` fills a user-space buffer with cryptographically secure random bytes
//! from the kernel's CSPRNG.  The `GRND_NONBLOCK` flag prevents blocking when
//! the CSPRNG has not yet been seeded; `GRND_RANDOM` selects the `getrandom`
//! pool (similar to `/dev/random`).  `GRND_INSECURE` was added in Linux 5.6
//! to obtain best-effort random data without blocking even before seeding.
//!
//! # POSIX reference
//!
//! Linux-specific: `getrandom(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Use the `getrandom` pool (like `/dev/random`).
pub const GRND_RANDOM: u32 = 0x0002;
/// Do not block if the CSPRNG has not been seeded yet.
pub const GRND_NONBLOCK: u32 = 0x0001;
/// Return best-effort data without blocking (Linux 5.6+).
pub const GRND_INSECURE: u32 = 0x0004;

/// All valid flags.
const VALID_FLAGS: u32 = GRND_RANDOM | GRND_NONBLOCK | GRND_INSECURE;

/// Maximum number of bytes returned in a single call.
pub const GETRANDOM_MAX_BYTES: usize = 33_554_431;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which entropy source to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropySource {
    /// Default pool (like `/dev/urandom` once seeded).
    Default,
    /// `/dev/random` semantics (blocks until high-quality entropy available).
    Blocking,
    /// Best-effort without blocking (insecure before seeding).
    Insecure,
}

impl Default for EntropySource {
    fn default() -> Self {
        Self::Default
    }
}

/// Parsed `getrandom` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetrandomFlags {
    /// Which entropy source to use.
    pub source: EntropySource,
    /// Do not block even if the source would normally wait.
    pub nonblock: bool,
}

impl GetrandomFlags {
    /// Create a default value (default pool, may block).
    pub const fn new() -> Self {
        Self {
            source: EntropySource::Default,
            nonblock: false,
        }
    }

    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set or if
    /// `GRND_RANDOM` and `GRND_INSECURE` are both set (mutually exclusive).
    pub fn from_raw(flags: u32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        // GRND_RANDOM and GRND_INSECURE are mutually exclusive.
        if flags & GRND_RANDOM != 0 && flags & GRND_INSECURE != 0 {
            return Err(Error::InvalidArgument);
        }
        let source = if flags & GRND_INSECURE != 0 {
            EntropySource::Insecure
        } else if flags & GRND_RANDOM != 0 {
            EntropySource::Blocking
        } else {
            EntropySource::Default
        };
        Ok(Self {
            source,
            nonblock: flags & GRND_NONBLOCK != 0,
        })
    }
}

/// Validated `getrandom` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetrandomRequest {
    /// User-space pointer to the output buffer.
    pub buf: usize,
    /// Number of bytes requested.
    pub buflen: usize,
    /// Parsed flags.
    pub flags: GetrandomFlags,
}

impl GetrandomRequest {
    /// Construct a new request.
    pub const fn new(buf: usize, buflen: usize, flags: GetrandomFlags) -> Self {
        Self { buf, buflen, flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `getrandom(2)` (extended variant with additional validation).
///
/// Validates arguments and returns a structured request.  The kernel fills
/// `buf` with random bytes according to the selected source.
///
/// # Arguments
///
/// - `buf`    — user-space pointer to the output buffer
/// - `buflen` — number of bytes to fill (0 < buflen <= `GETRANDOM_MAX_BYTES`)
/// - `flags`  — combination of `GRND_*` flags
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | Null buffer, zero length, unknown/conflicting flags |
/// | `WouldBlock`      | `GRND_NONBLOCK` and CSPRNG not yet seeded        |
pub fn do_getrandom_ext(buf: usize, buflen: usize, flags: u32) -> Result<GetrandomRequest> {
    if buf == 0 {
        return Err(Error::InvalidArgument);
    }
    if buflen == 0 || buflen > GETRANDOM_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }
    let parsed = GetrandomFlags::from_raw(flags)?;
    Ok(GetrandomRequest::new(buf, buflen, parsed))
}

/// Return `true` if the call should not block.
pub fn is_nonblocking(flags: &GetrandomFlags) -> bool {
    flags.nonblock
}

/// Return `true` if high-quality (blocking) entropy is requested.
pub fn is_blocking_source(flags: &GetrandomFlags) -> bool {
    matches!(flags.source, EntropySource::Blocking)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_request_ok() {
        let req = do_getrandom_ext(0x1000, 32, 0).unwrap();
        assert_eq!(req.buflen, 32);
        assert_eq!(req.flags.source, EntropySource::Default);
    }

    #[test]
    fn nonblock_ok() {
        let req = do_getrandom_ext(0x1000, 16, GRND_NONBLOCK).unwrap();
        assert!(req.flags.nonblock);
    }

    #[test]
    fn insecure_ok() {
        let req = do_getrandom_ext(0x1000, 16, GRND_INSECURE).unwrap();
        assert_eq!(req.flags.source, EntropySource::Insecure);
    }

    #[test]
    fn random_and_insecure_rejected() {
        assert_eq!(
            do_getrandom_ext(0x1000, 16, GRND_RANDOM | GRND_INSECURE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_buffer_rejected() {
        assert_eq!(do_getrandom_ext(0, 16, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_length_rejected() {
        assert_eq!(do_getrandom_ext(0x1000, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn oversized_length_rejected() {
        assert_eq!(
            do_getrandom_ext(0x1000, GETRANDOM_MAX_BYTES + 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn blocking_source_detection() {
        let flags = GetrandomFlags::from_raw(GRND_RANDOM).unwrap();
        assert!(is_blocking_source(&flags));
        assert!(!is_nonblocking(&flags));
    }
}

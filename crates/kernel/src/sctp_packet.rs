// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCTP packet CRC32c checksum and stateless structural validator.
//!
//! This tableless `no_std` module validates the RFC 9260 packet checksum and
//! chunk chain without association state, allocation, or response generation.
//!
//! SCTP serializes its CRC32c field as little-endian (`__le32` in Linux),
//! while ports, verification tags, chunk lengths, and other integer fields
//! remain in network byte order. CRC reflection and field serialization are
//! separate concerns.

use crate::sctp::{SctpChunkType, parse_sctp_header};
use oncrix_lib::{Error, Result};

#[path = "sctp_packet_shape.rs"]
mod shape;

#[path = "sctp_packet_params.rs"]
mod params;

const CRC32C_POLY: u32 = 0x82F6_3B78;
const SCTP_HEADER_LEN: usize = 12;
const CHUNK_HEADER_LEN: usize = 4;
const CHUNK_DATA: u8 = 0;
const CHUNK_INIT: u8 = 1;
const CHUNK_INIT_ACK: u8 = 2;
const CHUNK_ABORT: u8 = 6;
const CHUNK_SHUTDOWN: u8 = 7;
const CHUNK_SHUTDOWN_ACK: u8 = 8;
const CHUNK_COOKIE_ECHO: u8 = 10;
const CHUNK_SHUTDOWN_COMPLETE: u8 = 14;
const SCTP_CHECKSUM_RANGE: core::ops::Range<usize> = 8..12;

/// Round `len` up to a four-byte boundary, rejecting arithmetic overflow.
const fn pad4(len: usize) -> Option<usize> {
    match len.checked_add(3) {
        Some(rounded) => Some(rounded & !3),
        None => None,
    }
}

#[inline]
fn crc32c_step(crc: u32, byte: u8) -> u32 {
    let mut crc = crc ^ u32::from(byte);
    let mut bit = 0;
    while bit < 8 {
        crc = if crc & 1 != 0 {
            (crc >> 1) ^ CRC32C_POLY
        } else {
            crc >> 1
        };
        bit += 1;
    }
    crc
}

/// Compute a tableless reflected CRC32c (Castagnoli) checksum.
///
/// Uses polynomial `0x82F6_3B78`, initial register `!0`, and final complement.
/// The returned value is host order; protocol serialization is separate.
#[cfg(test)]
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0;
    for &byte in data {
        crc = crc32c_step(crc, byte);
    }
    !crc
}

fn sctp_packet_crc32c(packet: &[u8]) -> u32 {
    let mut crc = !0;
    for (index, &byte) in packet.iter().enumerate() {
        let input = if SCTP_CHECKSUM_RANGE.contains(&index) {
            0
        } else {
            byte
        };
        crc = crc32c_step(crc, input);
    }
    !crc
}

/// Validate an SCTP packet without association state or response generation.
///
/// The gate verifies the little-endian CRC32c field, nonzero ports, complete
/// chunk framing and padding, unknown-chunk action bits, INIT invariants, and
/// the RFC 9260 no-bundling rule for INIT-family chunks.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] for any malformed or inadmissible packet.
pub(crate) fn validate_sctp_packet(packet: &[u8]) -> Result<()> {
    let (header, _chunks) = parse_sctp_header(packet)?;

    let wire_checksum = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
    if wire_checksum != sctp_packet_crc32c(packet) {
        return Err(Error::InvalidArgument);
    }
    if header.src_port == 0 || header.dst_port == 0 {
        return Err(Error::InvalidArgument);
    }

    validate_chunk_chain(packet, header.verification_tag)
}

fn validate_chunk_chain(packet: &[u8], verification_tag: u32) -> Result<()> {
    let mut offset = SCTP_HEADER_LEN;
    let mut chunk_count = 0usize;
    let mut has_singleton = false;
    let mut has_data = false;
    let mut has_abort = false;
    let mut has_shutdown_family = false;

    while offset < packet.len() {
        if packet.len() - offset < CHUNK_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }

        let raw_type = packet[offset];
        let declared_len =
            usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        if declared_len < CHUNK_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }

        let declared_end = offset
            .checked_add(declared_len)
            .ok_or(Error::InvalidArgument)?;
        if declared_end > packet.len() {
            return Err(Error::InvalidArgument);
        }

        let padded_len = pad4(declared_len).ok_or(Error::InvalidArgument)?;
        let padded_end = offset
            .checked_add(padded_len)
            .ok_or(Error::InvalidArgument)?;
        if padded_end > packet.len() {
            return Err(Error::InvalidArgument);
        }

        match SctpChunkType::from_raw(raw_type) {
            Ok(chunk_type) => {
                if raw_type == CHUNK_COOKIE_ECHO && chunk_count != 0 {
                    return Err(Error::InvalidArgument);
                }
                shape::validate(chunk_type, &packet[offset..declared_end], verification_tag)?;
                has_singleton |= is_singleton_chunk(raw_type);
                has_data |= raw_type == CHUNK_DATA;
                has_abort |= raw_type == CHUNK_ABORT;
                has_shutdown_family |= matches!(raw_type, CHUNK_SHUTDOWN | CHUNK_SHUTDOWN_ACK);
            }
            Err(_) if raw_type & 0x80 == 0 => return Err(Error::InvalidArgument),
            Err(_) => {}
        }

        chunk_count = chunk_count.saturating_add(1);
        offset = padded_end;
    }

    if chunk_count == 0
        || (has_singleton && chunk_count != 1)
        || (has_data && (has_abort || has_shutdown_family))
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

const fn is_singleton_chunk(raw_type: u8) -> bool {
    matches!(
        raw_type,
        CHUNK_INIT | CHUNK_INIT_ACK | CHUNK_SHUTDOWN_COMPLETE
    )
}

#[cfg(test)]
#[path = "sctp_packet_test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "sctp_packet_crc_tests.rs"]
mod crc_tests;

#[cfg(test)]
#[path = "sctp_packet_framing_tests.rs"]
mod framing_tests;

#[cfg(test)]
#[path = "sctp_packet_init_tests.rs"]
mod init_tests;

#[cfg(test)]
#[path = "sctp_packet_shape_tests.rs"]
mod shape_tests;

#[cfg(test)]
#[path = "sctp_packet_parameter_tests.rs"]
mod parameter_tests;

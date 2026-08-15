// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCTP packet CRC32c (Castagnoli) checksum.
//!
//! Standalone, tableless, `no_std` implementation of the CRC32c checksum
//! that SCTP uses to protect every packet (RFC 4960 §6.8, RFC 3309). This
//! module intentionally lives beside [`crate::sctp`] rather than inside it,
//! so the frozen protocol module does not grow.
//!
//! # Algorithm
//!
//! Reflected Castagnoli CRC32c: reversed polynomial `0x82F6_3B78`, initial
//! register `!0`, an LSB-first (right-shifting) bit loop, and a final `!crc`
//! complement. No lookup table, no allocation, no `unsafe`.
//!
//! # SCTP wire-format exception
//!
//! The SCTP common header carries the checksum in bytes 8..12. On the wire
//! that field is serialized **little-endian**: Linux types it as `__le32`
//! (`struct sctphdr.checksum`) and [`sctp_compute_cksum`] returns
//! `cpu_to_le32(...)`. This is a property of the header field's declared
//! type, *not* of CRC reflection — the reflected bit loop computes a plain
//! `u32`; how that `u32` is placed on the wire is a separate serialization
//! decision. Every other SCTP integer field (ports, verification tag,
//! chunk lengths) remains in network (big-endian) byte order.
//!
//! When computing a packet checksum the four checksum bytes (indices 8..12)
//! are treated as zero, as required by RFC 3309, without copying or mutating
//! the caller's buffer.

/// Reflected Castagnoli polynomial (CRC32c).
const CRC32C_POLY: u32 = 0x82F6_3B78;

/// Byte range of the checksum field within the SCTP common header.
const SCTP_CHECKSUM_RANGE: core::ops::Range<usize> = 8..12;

/// Fold a single input byte into the running reflected CRC32c register.
///
/// This is the shared algorithmic seam: both [`crc32c`] and
/// [`sctp_packet_crc32c`] drive their bytes through it, so there is one
/// implementation of the bit loop and no test-only dead code.
#[inline]
fn crc32c_step(crc: u32, byte: u8) -> u32 {
    let mut crc = crc ^ byte as u32;
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

/// Compute the CRC32c (Castagnoli) checksum of `data`.
///
/// Uses the reflected polynomial `0x82F6_3B78`, initial register `!0`, an
/// LSB-first bit loop, and a final `!crc` complement — matching RFC 3309
/// and the Linux `crc32c` implementation. The returned value is a plain
/// host-order `u32`; callers that place it on the wire are responsible for
/// the byte order their protocol requires.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &byte in data {
        crc = crc32c_step(crc, byte);
    }
    !crc
}

/// Compute the SCTP packet CRC32c over `packet`, treating the checksum
/// field (bytes 8..12) as zero.
///
/// RFC 3309 requires the checksum field to be logically zero while the
/// checksum is computed. This feeds `0` for indices 8..12 without copying
/// or mutating `packet`, so a caller may pass a buffer that still holds a
/// stale or garbage checksum and receive the correct result.
///
/// The returned `u32` is host-order. To serialize it into the SCTP header
/// (a `__le32` field) use [`u32::to_le_bytes`].
pub fn sctp_packet_crc32c(packet: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for (index, &byte) in packet.iter().enumerate() {
        let fed = if SCTP_CHECKSUM_RANGE.contains(&index) {
            0
        } else {
            byte
        };
        crc = crc32c_step(crc, fed);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-byte SCTP INIT packet. Common header (12 bytes) followed by a
    /// 20-byte INIT chunk. Checksum field (bytes 8..12) holds the real
    /// little-endian checksum `[0x12, 0xF6, 0xF6, 0xE9]`.
    const SCTP_INIT_PACKET: [u8; 32] = [
        // Common header: src port 0x1388, dst port 0x0050
        0x13, 0x88, 0x00, 0x50, //
        // Verification tag 0x00000000 (INIT)
        0x00, 0x00, 0x00, 0x00, //
        // Checksum (__le32): 0xE9F6F612 little-endian on the wire
        0x12, 0xF6, 0xF6, 0xE9, //
        // INIT chunk: type 1, flags 0, length 20
        0x01, 0x00, 0x00, 0x14, //
        // Initiate tag 0xDEADBEEF
        0xDE, 0xAD, 0xBE, 0xEF, //
        // a_rwnd 0x00010000
        0x00, 0x01, 0x00, 0x00, //
        // outbound streams 2, inbound streams 2
        0x00, 0x02, 0x00, 0x02, //
        // initial TSN 0x715B5A94 (pseudo-random per RFC 4960 §5.3.1)
        0x71, 0x5B, 0x5A, 0x94,
    ];

    #[test]
    fn crc32c_empty_input_is_zero() {
        // Given an empty slice / When CRC32c is computed / Then the KAT holds.
        assert_eq!(crc32c(&[]), 0x0000_0000);
    }

    #[test]
    fn crc32c_check_string_matches_kat() {
        // Given the canonical "123456789" check vector.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32c_thirty_two_zero_bytes() {
        // Given 32 zero bytes.
        assert_eq!(crc32c(&[0x00u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn crc32c_thirty_two_ff_bytes() {
        // Given 32 0xFF bytes.
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn crc32c_ascending_and_descending_bytes() {
        // Given 0x00..=0x1F ascending.
        let mut ascending = [0u8; 32];
        for (i, b) in ascending.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(crc32c(&ascending), 0x46DD_794E);

        // And 0x1F..=0x00 descending.
        let mut descending = [0u8; 32];
        for (i, b) in descending.iter_mut().enumerate() {
            *b = (31 - i) as u8;
        }
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }

    #[test]
    fn sctp_packet_crc32c_zeros_checksum_field() {
        // Given the INIT packet with its real little-endian checksum field,
        // When the packet CRC is computed (bytes 8..12 fed as zero),
        // Then it equals the pinned value.
        assert_eq!(sctp_packet_crc32c(&SCTP_INIT_PACKET), 0xE9F6_F612);

        // And the on-wire checksum field is little-endian 0xE9F6F612.
        assert_eq!(&SCTP_INIT_PACKET[8..12], &[0x12, 0xF6, 0xF6, 0xE9]);
        assert_eq!(0xE9F6_F612u32.to_le_bytes(), [0x12, 0xF6, 0xF6, 0xE9]);

        // And garbage in bytes 8..12 does not change the result.
        let mut garbled = SCTP_INIT_PACKET;
        garbled[8] = 0xAA;
        garbled[9] = 0xBB;
        garbled[10] = 0xCC;
        garbled[11] = 0xDD;
        assert_eq!(sctp_packet_crc32c(&garbled), 0xE9F6_F612);
    }
}

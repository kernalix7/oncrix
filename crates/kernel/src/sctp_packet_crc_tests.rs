// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Known-answer tests for SCTP CRC32c computation.

use super::test_support::SCTP_INIT_PACKET;
use super::{crc32c, sctp_packet_crc32c};

#[test]
fn crc32c_empty_input_is_zero() {
    assert_eq!(crc32c(&[]), 0x0000_0000);
}

#[test]
fn crc32c_check_string_matches_kat() {
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
}

#[test]
fn crc32c_thirty_two_zero_bytes() {
    assert_eq!(crc32c(&[0x00u8; 32]), 0x8A91_36AA);
}

#[test]
fn crc32c_thirty_two_ff_bytes() {
    assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
}

#[test]
fn crc32c_ascending_and_descending_bytes() {
    let mut ascending = [0u8; 32];
    for (index, byte) in ascending.iter_mut().enumerate() {
        *byte = index as u8;
    }
    assert_eq!(crc32c(&ascending), 0x46DD_794E);

    let mut descending = [0u8; 32];
    for (index, byte) in descending.iter_mut().enumerate() {
        *byte = (31 - index) as u8;
    }
    assert_eq!(crc32c(&descending), 0x113F_DB5C);
}

#[test]
fn sctp_packet_crc32c_zeros_checksum_field() {
    assert_eq!(sctp_packet_crc32c(&SCTP_INIT_PACKET), 0xE9F6_F612);
    assert_eq!(&SCTP_INIT_PACKET[8..12], &[0x12, 0xF6, 0xF6, 0xE9]);
    assert_eq!(0xE9F6_F612u32.to_le_bytes(), [0x12, 0xF6, 0xF6, 0xE9]);

    let mut garbled = SCTP_INIT_PACKET;
    garbled[8..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(sctp_packet_crc32c(&garbled), 0xE9F6_F612);
}

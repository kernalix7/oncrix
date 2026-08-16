// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCTP packet checksum, framing, length, and padding tests.

use super::test_support::{
    SCTP_INIT_PACKET, SKIPPABLE_UNKNOWN_CHUNK_8, VALID_DATA_CHUNK, chunk_packet, seal,
};
use super::{sctp_packet_crc32c, validate_sctp_packet};
use oncrix_lib::Error;

fn declared_length_packet(declared: u16) -> [u8; 20] {
    let mut packet = [0u8; 20];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x80;
    packet[14..16].copy_from_slice(&declared.to_be_bytes());
    seal(packet)
}

fn two_chunk_packet(first: &[u8; 8], second: &[u8; 8]) -> [u8; 28] {
    let mut packet = [0u8; 28];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12..20].copy_from_slice(first);
    packet[20..28].copy_from_slice(second);
    seal(packet)
}

fn data_control_packet<const N: usize>(first: &[u8], second: &[u8]) -> [u8; N] {
    assert_eq!(N, 12 + first.len() + second.len());
    let mut packet = [0u8; N];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12..12 + first.len()].copy_from_slice(first);
    let second_start = 12 + first.len();
    packet[second_start..second_start + second.len()].copy_from_slice(second);
    seal(packet)
}

#[test]
fn accepts_literal_le_init_packet() {
    assert!(validate_sctp_packet(&SCTP_INIT_PACKET).is_ok());
}

#[test]
fn rejects_corrupt_checksum() {
    let mut packet = SCTP_INIT_PACKET;
    packet[8] ^= 0xFF;
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_big_endian_serialized_checksum() {
    let mut packet = SCTP_INIT_PACKET;
    packet[8..12].copy_from_slice(&0xE9F6_F612u32.to_be_bytes());
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_zero_source_port() {
    let mut packet = chunk_packet::<20>(&SKIPPABLE_UNKNOWN_CHUNK_8, 0x1122_3344);
    packet[0..2].copy_from_slice(&0u16.to_be_bytes());
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_zero_destination_port() {
    let mut packet = chunk_packet::<20>(&SKIPPABLE_UNKNOWN_CHUNK_8, 0x1122_3344);
    packet[2..4].copy_from_slice(&0u16.to_be_bytes());
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_header_only_packet() {
    let mut packet = [0u8; 12];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    let crc = sctp_packet_crc32c(&packet);
    packet[8..12].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_truncated_header() {
    assert_eq!(validate_sctp_packet(&[0u8; 8]), Err(Error::InvalidArgument));
}

#[test]
fn rejects_chunk_length_zero() {
    assert_eq!(
        validate_sctp_packet(&declared_length_packet(0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_chunk_lengths_one_through_three() {
    for declared in 1u16..=3 {
        assert_eq!(
            validate_sctp_packet(&declared_length_packet(declared)),
            Err(Error::InvalidArgument),
            "declared length {declared} must reject",
        );
    }
}

#[test]
fn rejects_declared_length_overrun() {
    let mut chunk = SKIPPABLE_UNKNOWN_CHUNK_8;
    chunk[3] = 0x0C;
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<20>(&chunk, 0x1122_3344)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_final_omitted_padding() {
    let mut packet = [0u8; 18];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x80;
    packet[14..16].copy_from_slice(&6u16.to_be_bytes());
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_final_partial_padding() {
    let mut packet = [0u8; 19];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x80;
    packet[14..16].copy_from_slice(&6u16.to_be_bytes());
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn accepts_full_nonzero_padding() {
    let mut packet = [0u8; 20];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x80;
    packet[14..16].copy_from_slice(&6u16.to_be_bytes());
    packet[16..20].copy_from_slice(&[0x99, 0x88, 0xFF, 0xFF]);
    assert!(validate_sctp_packet(&seal(packet)).is_ok());
}

#[test]
fn accepts_aligned_skippable_unknown_chunk() {
    let chunk = [0x80, 0x00, 0x00, 0x08, 0x11, 0x22, 0x00, 0x00];
    assert!(validate_sctp_packet(&chunk_packet::<20>(&chunk, 0x1122_3344)).is_ok());
}

#[test]
fn accepts_between_chunk_padding_walk() {
    let mut packet = [0u8; 28];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12..20].copy_from_slice(&[0x80, 0x00, 0x00, 0x06, 0xAA, 0xBB, 0, 0]);
    packet[20..28].copy_from_slice(&[0x80, 0x00, 0x00, 0x08, 0, 0, 0, 0]);
    assert!(validate_sctp_packet(&seal(packet)).is_ok());
}

#[test]
fn rejects_cookie_echo_after_another_chunk() {
    let cookie_echo = [10, 0, 0, 5, 0xAA, 0, 0, 0];
    assert_eq!(
        validate_sctp_packet(&two_chunk_packet(&SKIPPABLE_UNKNOWN_CHUNK_8, &cookie_echo,)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn accepts_cookie_echo_first_with_following_chunk() {
    let cookie_echo = [10, 0, 0, 5, 0xAA, 0, 0, 0];
    assert!(
        validate_sctp_packet(&two_chunk_packet(&cookie_echo, &SKIPPABLE_UNKNOWN_CHUNK_8,)).is_ok()
    );
}

#[test]
fn rejects_data_followed_by_abort() {
    assert_eq!(
        validate_sctp_packet(&data_control_packet::<36>(&VALID_DATA_CHUNK, &[6, 0, 0, 4],)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_abort_followed_by_data() {
    assert_eq!(
        validate_sctp_packet(&data_control_packet::<36>(&[6, 0, 0, 4], &VALID_DATA_CHUNK,)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_data_bundled_with_shutdown_family_in_both_orders() {
    let shutdown = [7, 0, 0, 8, 0, 0, 0, 1];
    let shutdown_ack = [8, 0, 0, 4];
    let rejected = [
        validate_sctp_packet(&data_control_packet::<40>(&VALID_DATA_CHUNK, &shutdown)).is_err(),
        validate_sctp_packet(&data_control_packet::<40>(&shutdown, &VALID_DATA_CHUNK)).is_err(),
        validate_sctp_packet(&data_control_packet::<36>(&VALID_DATA_CHUNK, &shutdown_ack)).is_err(),
        validate_sctp_packet(&data_control_packet::<36>(&shutdown_ack, &VALID_DATA_CHUNK)).is_err(),
    ];
    assert_eq!(rejected, [true; 4]);
}

#[test]
fn accepts_chunk_larger_than_516_bytes() {
    let mut packet = [0u8; 532];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x80;
    packet[14..16].copy_from_slice(&520u16.to_be_bytes());
    assert!(validate_sctp_packet(&seal(packet)).is_ok());
}

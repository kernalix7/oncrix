// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCTP unknown-chunk action and INIT-family validation tests.

use super::test_support::{
    SKIPPABLE_UNKNOWN_CHUNK_8, VALID_INIT_ACK_CHUNK, VALID_INIT_CHUNK, chunk_packet, seal,
};
use super::validate_sctp_packet;
use oncrix_lib::Error;

fn unknown_type_packet(raw_type: u8) -> [u8; 20] {
    let mut chunk = SKIPPABLE_UNKNOWN_CHUNK_8;
    chunk[0] = raw_type;
    chunk_packet(&chunk, 0x1122_3344)
}

fn unknown_then_skippable_packet(raw_type: u8) -> [u8; 28] {
    let mut packet = [0u8; 28];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = raw_type;
    packet[14..16].copy_from_slice(&8u16.to_be_bytes());
    packet[20..28].copy_from_slice(&SKIPPABLE_UNKNOWN_CHUNK_8);
    seal(packet)
}

fn init_family_packet(chunk_type: u8, verification_tag: u32, initiate_tag: u32) -> [u8; 32] {
    let mut chunk = VALID_INIT_CHUNK;
    chunk[0] = chunk_type;
    chunk[4..8].copy_from_slice(&initiate_tag.to_be_bytes());
    chunk_packet(&chunk, verification_tag)
}

#[test]
fn rejects_unknown_chunk_action_00() {
    assert_eq!(
        validate_sctp_packet(&unknown_type_packet(0x0F)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_unknown_chunk_action_01() {
    assert_eq!(
        validate_sctp_packet(&unknown_type_packet(0x4F)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn skips_unknown_chunk_action_10() {
    assert!(validate_sctp_packet(&unknown_then_skippable_packet(0x8F)).is_ok());
}

#[test]
fn skips_unknown_chunk_action_11() {
    assert!(validate_sctp_packet(&unknown_then_skippable_packet(0xCF)).is_ok());
}

#[test]
fn rejects_init_with_nonzero_verification_tag() {
    let packet = init_family_packet(0x01, 1, 0xDEAD_BEEF);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_init_with_short_length() {
    let mut packet = [0u8; 32];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[12] = 0x01;
    packet[14..16].copy_from_slice(&16u16.to_be_bytes());
    packet[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_init_with_zero_initiate_tag() {
    let packet = init_family_packet(0x01, 0, 0);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_init_with_zero_outbound_streams() {
    let mut chunk = VALID_INIT_CHUNK;
    chunk[12..14].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<32>(&chunk, 0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_init_with_zero_inbound_streams() {
    let mut chunk = VALID_INIT_CHUNK;
    chunk[14..16].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<32>(&chunk, 0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_init_with_arwnd_below_1500() {
    let mut chunk = VALID_INIT_CHUNK;
    chunk[8..12].copy_from_slice(&1499u32.to_be_bytes());
    chunk[16..20].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<32>(&chunk, 0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn accepts_init_with_arwnd_1500_and_initial_tsn_zero() {
    let mut chunk = VALID_INIT_CHUNK;
    chunk[8..12].copy_from_slice(&1500u32.to_be_bytes());
    chunk[16..20].copy_from_slice(&0u32.to_be_bytes());
    assert!(validate_sctp_packet(&chunk_packet::<32>(&chunk, 0)).is_ok());
}

#[test]
fn rejects_init_ack_with_arwnd_below_1500() {
    let mut chunk = VALID_INIT_ACK_CHUNK;
    chunk[8..12].copy_from_slice(&1499u32.to_be_bytes());
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<40>(&chunk, 1)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn accepts_init_ack_with_arwnd_1500_and_nonzero_verification_tag() {
    let mut chunk = VALID_INIT_ACK_CHUNK;
    chunk[8..12].copy_from_slice(&1500u32.to_be_bytes());
    assert!(validate_sctp_packet(&chunk_packet::<40>(&chunk, 1)).is_ok());
}

#[test]
fn rejects_init_ack_with_zero_verification_tag() {
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<40>(&VALID_INIT_ACK_CHUNK, 0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_init_with_malformed_optional_parameter() {
    let mut chunk = [0u8; 24];
    chunk[..20].copy_from_slice(&VALID_INIT_CHUNK);
    chunk[2..4].copy_from_slice(&24u16.to_be_bytes());
    chunk[20..24].copy_from_slice(&[0, 5, 0, 3]);
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<36>(&chunk, 0)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn rejects_bundled_init() {
    let mut packet = [0u8; 40];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[12..32].copy_from_slice(&VALID_INIT_CHUNK);
    packet[32..40].copy_from_slice(&SKIPPABLE_UNKNOWN_CHUNK_8);
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_bundled_init_ack() {
    let mut packet = [0u8; 48];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12..40].copy_from_slice(&VALID_INIT_ACK_CHUNK);
    packet[40..48].copy_from_slice(&SKIPPABLE_UNKNOWN_CHUNK_8);
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn rejects_bundled_shutdown_complete() {
    let mut packet = [0u8; 24];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    packet[12] = 0x0E;
    packet[14..16].copy_from_slice(&4u16.to_be_bytes());
    packet[16..24].copy_from_slice(&SKIPPABLE_UNKNOWN_CHUNK_8);
    let packet = seal(packet);
    assert_eq!(validate_sctp_packet(&packet), Err(Error::InvalidArgument));
}

#[test]
fn accepts_lone_init_ack() {
    assert!(validate_sctp_packet(&chunk_packet::<40>(&VALID_INIT_ACK_CHUNK, 0x1122_3344)).is_ok());
}

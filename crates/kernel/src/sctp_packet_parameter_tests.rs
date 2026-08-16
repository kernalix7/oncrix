// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RFC 9260 INIT-family parameter admission tests.

use super::test_support::{VALID_INIT_ACK_CHUNK, VALID_INIT_CHUNK};
use super::{sctp_packet_crc32c, validate_sctp_packet};
use oncrix_lib::{Error, Result};

const COOKIE: [u8; 8] = [0, 7, 0, 5, 0xAA, 0, 0, 0];
const IPV4: [u8; 8] = [0, 5, 0, 8, 192, 0, 2, 1];
const IPV6: [u8; 20] = [0, 6, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ECN: [u8; 4] = [0x80, 0, 0, 4];

fn validate_parameter_packet(base: &[u8], parameters: &[u8], tag: u32) -> Result<()> {
    let chunk_len = 20 + parameters.len();
    let packet_len = 12 + ((chunk_len + 3) & !3);
    let mut packet = [0u8; 128];
    packet[0..2].copy_from_slice(&0x1388u16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0050u16.to_be_bytes());
    packet[4..8].copy_from_slice(&tag.to_be_bytes());
    packet[12..32].copy_from_slice(&base[..20]);
    let wire_chunk_len = u16::try_from(chunk_len).expect("test chunk length fits u16");
    packet[14..16].copy_from_slice(&wire_chunk_len.to_be_bytes());
    packet[32..32 + parameters.len()].copy_from_slice(parameters);
    let crc = sctp_packet_crc32c(&packet[..packet_len]);
    packet[8..12].copy_from_slice(&crc.to_le_bytes());
    validate_sctp_packet(&packet[..packet_len])
}

fn validate_init(parameters: &[u8]) -> Result<()> {
    validate_parameter_packet(&VALID_INIT_CHUNK, parameters, 0)
}

fn validate_init_ack(extra: &[u8]) -> Result<()> {
    let mut parameters = [0u8; 96];
    parameters[..COOKIE.len()].copy_from_slice(&COOKIE);
    parameters[COOKIE.len()..COOKIE.len() + extra.len()].copy_from_slice(extra);
    validate_parameter_packet(
        &VALID_INIT_ACK_CHUNK,
        &parameters[..COOKIE.len() + extra.len()],
        1,
    )
}

#[test]
fn init_and_init_ack_accept_valid_repeatable_addresses() {
    let mut addresses = [0u8; 56];
    addresses[..8].copy_from_slice(&IPV4);
    addresses[8..16].copy_from_slice(&IPV4);
    addresses[16..36].copy_from_slice(&IPV6);
    addresses[36..56].copy_from_slice(&IPV6);
    assert!(validate_init(&addresses).is_ok());
    assert!(validate_init_ack(&addresses).is_ok());
}

#[test]
fn init_and_init_ack_reject_malformed_address_widths() {
    for parameter in [
        &[0, 5, 0, 7, 192, 0, 2][..],
        &[0, 6, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
    ] {
        assert_eq!(validate_init(parameter), Err(Error::InvalidArgument));
        assert_eq!(validate_init_ack(parameter), Err(Error::InvalidArgument));
    }
}

#[test]
fn init_validates_cookie_preservative_width_and_uniqueness() {
    let valid = [0, 9, 0, 8, 0, 0, 0, 1];
    assert!(validate_init(&valid).is_ok());
    assert_eq!(
        validate_init(&[0, 9, 0, 7, 0, 0, 1]),
        Err(Error::InvalidArgument),
    );
    let duplicate = [0, 9, 0, 8, 0, 0, 0, 1, 0, 9, 0, 8, 0, 0, 0, 2];
    assert_eq!(validate_init(&duplicate), Err(Error::InvalidArgument));
}

#[test]
fn init_validates_supported_address_types_shape_and_uniqueness() {
    assert!(validate_init(&[0, 12, 0, 6, 0, 5]).is_ok());
    for malformed in [&[0, 12, 0, 5, 0][..], &[0, 12, 0, 7, 0, 5, 0][..]] {
        assert_eq!(validate_init(malformed), Err(Error::InvalidArgument));
    }
    let duplicate = [0, 12, 0, 6, 0, 5, 0, 0, 0, 12, 0, 6, 0, 6];
    assert_eq!(validate_init(&duplicate), Err(Error::InvalidArgument));
}

#[test]
fn init_and_init_ack_validate_ecn_width_and_uniqueness() {
    assert!(validate_init(&ECN).is_ok());
    assert!(validate_init_ack(&ECN).is_ok());
    let malformed = [0x80, 0, 0, 5, 0];
    assert_eq!(validate_init(&malformed), Err(Error::InvalidArgument));
    assert_eq!(validate_init_ack(&malformed), Err(Error::InvalidArgument));
    let duplicate = [0x80, 0, 0, 4, 0x80, 0, 0, 4];
    assert_eq!(validate_init(&duplicate), Err(Error::InvalidArgument));
    assert_eq!(validate_init_ack(&duplicate), Err(Error::InvalidArgument));
}

#[test]
fn init_family_rejects_host_name() {
    let host_name = [0, 11, 0, 5, b'x'];
    assert_eq!(validate_init(&host_name), Err(Error::InvalidArgument));
    assert_eq!(validate_init_ack(&host_name), Err(Error::InvalidArgument));
}

#[test]
fn init_rejects_cookie_and_unrecognized_parameter() {
    assert_eq!(validate_init(&COOKIE), Err(Error::InvalidArgument));
    assert_eq!(validate_init(&[0, 8, 0, 4]), Err(Error::InvalidArgument));
}

#[test]
fn init_ack_rejects_cookie_preservative_and_supported_address_types() {
    assert_eq!(
        validate_init_ack(&[0, 9, 0, 8, 0, 0, 0, 1]),
        Err(Error::InvalidArgument),
    );
    assert_eq!(
        validate_init_ack(&[0, 12, 0, 6, 0, 5]),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn init_ack_accepts_repeatable_unrecognized_parameter() {
    let containers = [0, 8, 0, 8, 0x12, 0x34, 0, 4, 0, 8, 0, 8, 0x92, 0x34, 0, 4];
    assert!(validate_init_ack(&containers).is_ok());
}

#[test]
fn init_ack_rejects_empty_or_truncated_unrecognized_parameter() {
    for parameter in [
        &[0, 8, 0, 4][..],
        &[0, 8, 0, 5, 0][..],
        &[0, 8, 0, 6, 0, 5][..],
        &[0, 8, 0, 7, 0, 5, 0][..],
    ] {
        assert_eq!(validate_init_ack(parameter), Err(Error::InvalidArgument));
    }
}

#[test]
fn init_ack_rejects_malformed_nested_unrecognized_parameter() {
    for parameter in [
        &[0, 8, 0, 8, 0, 5, 0, 8][..],
        &[0, 8, 0, 10, 0, 5, 0, 5, 0xAA, 0][..],
        &[0, 8, 0, 9, 0, 5, 0, 4, 0][..],
        &[0, 8, 0, 12, 0x12, 0x34, 0, 5, 0xAA, 0, 0, 0][..],
        &[0, 8, 0, 12, 0, 5, 0, 4, 0, 6, 0, 4][..],
    ] {
        assert_eq!(validate_init_ack(parameter), Err(Error::InvalidArgument));
    }
}

#[test]
fn init_family_stops_or_continues_for_unknown_parameter_actions() {
    for parameter_type in [0x0010u16, 0x4010] {
        let raw = parameter_type.to_be_bytes();
        let parameter = [raw[0], raw[1], 0, 4];
        assert!(validate_init(&parameter).is_ok());
        assert!(validate_init_ack(&parameter).is_ok());
    }
    for parameter_type in [0x8010u16, 0xC010] {
        let raw = parameter_type.to_be_bytes();
        let parameter = [raw[0], raw[1], 0, 4];
        assert!(validate_init(&parameter).is_ok());
        assert!(validate_init_ack(&parameter).is_ok());
    }
}

#[test]
fn unknown_stop_ignores_trailing_malformed_parameter() {
    for parameter_type in [0x0010u16, 0x4010] {
        let raw = parameter_type.to_be_bytes();
        let parameters = [raw[0], raw[1], 0, 4, 0, 5, 0, 3];
        assert!(validate_init(&parameters).is_ok());
        assert!(validate_init_ack(&parameters).is_ok());
    }
}

#[test]
fn unknown_continue_checks_trailing_malformed_parameter() {
    for parameter_type in [0x8010u16, 0xC010] {
        let raw = parameter_type.to_be_bytes();
        let parameters = [raw[0], raw[1], 0, 4, 0, 5, 0, 3];
        assert_eq!(validate_init(&parameters), Err(Error::InvalidArgument));
        assert_eq!(validate_init_ack(&parameters), Err(Error::InvalidArgument));
    }
}

#[test]
fn init_ack_stop_requires_preceding_state_cookie() {
    assert_eq!(
        validate_parameter_packet(&VALID_INIT_ACK_CHUNK, &[0, 0x10, 0, 4], 1),
        Err(Error::InvalidArgument),
    );
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

const SOURCE: [u8; 4] = [192, 0, 2, 1];
const DESTINATION: [u8; 4] = [198, 51, 100, 2];

fn base_segment(checksum: u16) -> [u8; 20] {
    let checksum = checksum.to_be_bytes();
    [
        0x30,
        0x39,
        0x00,
        0x50,
        0x01,
        0x02,
        0x03,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x50,
        0x12,
        0x37,
        0xBB,
        checksum[0],
        checksum[1],
        0x00,
        0x00,
    ]
}

#[test]
fn accepts_even_vector_with_checksum_5751() {
    // Given
    let segment = base_segment(0x5751);
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_ok());
}

#[test]
fn accepts_odd_vector_with_checksum_ac4f() {
    // Given
    let mut segment = [0u8; 21];
    segment[..20].copy_from_slice(&base_segment(0xAC4F));
    segment[20] = 0xAB;
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_ok());
}

#[test]
fn accepts_valid_zero_checksum_field_with_payload_word_574f() {
    // Given
    let mut segment = [0u8; 22];
    segment[..20].copy_from_slice(&base_segment(0x0000));
    segment[20..].copy_from_slice(&[0x57, 0x4F]);
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_ok());
}

#[test]
fn rejects_vector_summed_with_udp_protocol() {
    // Given
    let segment = base_segment(0x5746);
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn accepts_mss_vector_with_checksum_3f95() {
    // Given
    let mut segment = [0u8; 24];
    segment[..20].copy_from_slice(&base_segment(0x3F95));
    segment[12] = 0x60;
    segment[20..].copy_from_slice(&[0x02, 0x04, 0x05, 0xB4]);
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_ok());
}

#[test]
fn rejects_payload_corruption() {
    // Given
    let mut segment = [0u8; 21];
    segment[..20].copy_from_slice(&base_segment(0xAC4F));
    segment[20] = 0xAA;
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_source_address_corruption() {
    // Given
    let segment = base_segment(0x5751);
    let corrupted_source = [192, 0, 2, 2];
    // When
    let result = verify_tcp_checksum(corrupted_source, DESTINATION, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_destination_address_corruption() {
    // Given
    let segment = base_segment(0x5751);
    let corrupted_destination = [198, 51, 100, 3];
    // When
    let result = verify_tcp_checksum(SOURCE, corrupted_destination, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_truncated_valid_vector() {
    // Given
    let mut segment = [0u8; 24];
    segment[..20].copy_from_slice(&base_segment(0x3F95));
    segment[12] = 0x60;
    segment[20..].copy_from_slice(&[0x02, 0x04, 0x05, 0xB4]);
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment[..23]);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_segment_shorter_than_tcp_header() {
    // Given
    let segment = [0u8; 19];
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_segment_longer_than_ipv4_length_field() {
    // Given
    let segment = [0u8; (u16::MAX as usize) + 1];
    // When
    let result = verify_tcp_checksum(SOURCE, DESTINATION, &segment);
    // Then
    assert!(result.is_err());
}

#[test]
fn rejects_invalid_segment_with_large_checksum_sum() {
    // Given
    let mut segment = [0xFFu8; 20];
    segment[12] = 0xFF;
    segment[13] = 0xF2;
    // When
    let result = verify_tcp_checksum([0xFF; 4], [0xFF; 4], &segment);
    // Then
    assert!(result.is_err());
}

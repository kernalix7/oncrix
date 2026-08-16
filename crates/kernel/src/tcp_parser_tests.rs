// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn packet<const N: usize>(data_offset: u8, flags: u8) -> [u8; N] {
    let mut data = [0u8; N];
    data[0..2].copy_from_slice(&1234u16.to_be_bytes());
    data[2..4].copy_from_slice(&80u16.to_be_bytes());
    data[12] = data_offset << 4;
    data[13] = flags;
    data
}

#[test]
fn accepts_exact_minimum_header_when_no_options_are_present() {
    // Given
    let data = packet::<20>(5, 0);
    // When
    let parsed = parse_tcp(&data);
    // Then
    let (_, payload) = parsed.ok().unwrap();
    assert!(payload.is_empty());
}

#[test]
fn accepts_maximum_data_offset_when_segment_contains_full_header() {
    // Given
    let data = packet::<60>(15, 0);
    // When
    let parsed = parse_tcp(&data);
    // Then
    let (header, payload) = parsed.ok().unwrap();
    assert_eq!(header.header_len(), 60);
    assert!(payload.is_empty());
}

#[test]
fn rejects_segment_shorter_than_minimum_header() {
    // Given
    let data = [0u8; 19];
    // When
    let parsed = parse_tcp(&data);
    // Then
    assert!(parsed.is_err());
}

#[test]
fn rejects_data_offset_below_five_words() {
    // Given
    let data = packet::<20>(4, 0);
    // When
    let parsed = parse_tcp(&data);
    // Then
    assert!(parsed.is_err());
}

#[test]
fn rejects_header_length_beyond_segment() {
    // Given
    let data = packet::<20>(6, 0);
    // When
    let parsed = parse_tcp(&data);
    // Then
    assert!(parsed.is_err());
}

#[test]
fn accepts_zero_source_and_destination_ports_structurally() {
    // Given
    let data = [0x00, 0x00, 0x00, 0x00];
    let mut segment = packet::<20>(5, 0);
    segment[..4].copy_from_slice(&data);
    // When
    let parsed = parse_tcp(&segment);
    // Then
    let (header, _) = parsed.ok().unwrap();
    assert_eq!((header.source_port, header.dest_port), (0, 0));
}

#[test]
fn ignores_reserved_header_bits() {
    // Given
    let mut data = packet::<20>(5, TCP_ACK as u8);
    data[12] |= 0x0F;
    // When
    let parsed = parse_tcp(&data);
    // Then
    let (header, _) = parsed.ok().unwrap();
    assert_eq!(header.flags(), TCP_ACK);
}

#[test]
fn accepts_syn_and_fin_combination_structurally() {
    // Given
    let data = packet::<20>(5, (TCP_SYN | TCP_FIN) as u8);

    // When
    let parsed = parse_tcp(&data);

    // Then
    let (header, _) = parsed.ok().unwrap();
    assert!(header.syn() && header.fin());
}

#[test]
fn flags_include_ece_and_cwr_control_bits() {
    // Given
    let data = packet::<20>(5, 0xC0 | TCP_SYN as u8);

    // When
    let parsed = parse_tcp(&data);

    // Then
    let (header, _) = parsed.ok().unwrap();
    assert_eq!(header.flags(), 0xC0 | TCP_SYN);
}

#[test]
fn rejects_nonzero_padding_after_end_of_option_list() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[0, 1, 0, 0]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_err());
}

#[test]
fn rejects_generic_option_missing_length_byte() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[1, 1, 1, 30]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_err());
}

#[test]
fn rejects_generic_option_lengths_below_two() {
    for option_length in [0, 1] {
        // Given
        let mut data = packet::<24>(6, 0);
        data[20..24].copy_from_slice(&[30, option_length, 0, 0]);

        // When
        let parsed = parse_tcp(&data);

        // Then
        assert!(parsed.is_err());
    }
}

#[test]
fn rejects_option_extending_beyond_declared_header() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[30, 5, 0, 0]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_err());
}

#[test]
fn rejects_mss_option_with_wrong_length() {
    // Given
    let mut data = packet::<24>(6, TCP_SYN as u8);
    data[20..24].copy_from_slice(&[2, 3, 0, 0]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_err());
}

#[test]
fn accepts_zero_padding_after_end_of_option_list() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[0, 0, 0, 0]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_ok());
}

#[test]
fn accepts_nop_options() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[1, 1, 1, 1]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_ok());
}

#[test]
fn accepts_well_formed_unknown_option() {
    // Given
    let mut data = packet::<24>(6, 0);
    data[20..24].copy_from_slice(&[30, 4, 0xAA, 0x55]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_ok());
}

#[test]
fn accepts_well_formed_mss_option_on_syn() {
    // Given
    let mut data = packet::<24>(6, TCP_SYN as u8);
    data[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_ok());
}

#[test]
fn ignores_well_formed_mss_option_on_non_syn() {
    // Given
    let mut data = packet::<24>(6, TCP_ACK as u8);
    data[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]);

    // When
    let parsed = parse_tcp(&data);

    // Then
    assert!(parsed.is_ok());
}

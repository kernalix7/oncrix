// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RFC 9260 known-chunk shape validation tests.

use super::test_support::{VALID_DATA_CHUNK, VALID_INIT_ACK_CHUNK, chunk_packet};
use super::validate_sctp_packet;
use oncrix_lib::Error;

fn rejects<const N: usize>(chunk: &[u8], tag: u32) {
    assert_eq!(
        validate_sctp_packet(&chunk_packet::<N>(chunk, tag)),
        Err(Error::InvalidArgument),
    );
}

#[test]
fn data_requires_fixed_fields_and_user_data() {
    let mut empty_data = [0u8; 16];
    empty_data.copy_from_slice(&VALID_DATA_CHUNK[..16]);
    empty_data[2..4].copy_from_slice(&16u16.to_be_bytes());
    rejects::<28>(&empty_data, 1);
    assert!(validate_sctp_packet(&chunk_packet::<32>(&VALID_DATA_CHUNK, 1)).is_ok());
}

#[test]
fn fixed_length_chunks_require_exact_lengths() {
    rejects::<20>(&[7, 0, 0, 5, 0, 0, 0, 0], 1);
    assert!(validate_sctp_packet(&chunk_packet::<20>(&[7, 0, 0, 8, 0, 0, 0, 0], 1)).is_ok());
    for chunk_type in [8u8, 11, 14] {
        rejects::<20>(&[chunk_type, 0, 0, 5, 0, 0, 0, 0], 1);
        assert!(validate_sctp_packet(&chunk_packet::<16>(&[chunk_type, 0, 0, 4], 1)).is_ok());
    }
}

#[test]
fn cookie_echo_requires_nonempty_cookie() {
    rejects::<16>(&[10, 0, 0, 4], 1);
    assert!(validate_sctp_packet(&chunk_packet::<20>(&[10, 0, 0, 5, 0xAA], 1)).is_ok());
}

#[test]
fn sack_length_matches_gap_and_duplicate_counts() {
    let mut sack = [0u8; 24];
    sack[0] = 3;
    sack[2..4].copy_from_slice(&16u16.to_be_bytes());
    assert!(validate_sctp_packet(&chunk_packet::<28>(&sack[..16], 1)).is_ok());
    sack[12..14].copy_from_slice(&1u16.to_be_bytes());
    rejects::<28>(&sack[..16], 1);
    sack[2..4].copy_from_slice(&20u16.to_be_bytes());
    assert!(validate_sctp_packet(&chunk_packet::<32>(&sack[..20], 1)).is_ok());
    sack[14..16].copy_from_slice(&1u16.to_be_bytes());
    rejects::<32>(&sack[..20], 1);
    sack[2..4].copy_from_slice(&24u16.to_be_bytes());
    assert!(validate_sctp_packet(&chunk_packet::<36>(&sack, 1)).is_ok());
}

#[test]
fn heartbeat_requires_one_heartbeat_info_parameter() {
    for chunk_type in [4u8, 5] {
        rejects::<16>(&[chunk_type, 0, 0, 4], 1);
        rejects::<20>(&[chunk_type, 0, 0, 8, 0, 2, 0, 4], 1);
        assert!(
            validate_sctp_packet(&chunk_packet::<20>(&[chunk_type, 0, 0, 8, 0, 1, 0, 4], 1,))
                .is_ok()
        );
        rejects::<24>(&[chunk_type, 0, 0, 12, 0, 1, 0, 4, 0, 1, 0, 4], 1);
    }
}

#[test]
fn abort_accepts_empty_or_complete_causes() {
    assert!(validate_sctp_packet(&chunk_packet::<16>(&[6, 0, 0, 4], 1)).is_ok());
    assert!(validate_sctp_packet(&chunk_packet::<20>(&[6, 0, 0, 8, 0, 1, 0, 4], 1)).is_ok());
    rejects::<20>(&[6, 0, 0, 8, 0, 1, 0, 3], 1);
}

#[test]
fn error_requires_at_least_one_complete_cause() {
    rejects::<16>(&[9, 0, 0, 4], 1);
    assert!(validate_sctp_packet(&chunk_packet::<20>(&[9, 0, 0, 8, 0, 1, 0, 4], 1)).is_ok());
    rejects::<20>(&[9, 0, 0, 8, 0, 1, 0, 3], 1);
}

#[test]
fn init_ack_requires_exactly_one_state_cookie() {
    let mut missing = VALID_INIT_ACK_CHUNK;
    missing[2..4].copy_from_slice(&20u16.to_be_bytes());
    rejects::<32>(&missing[..20], 1);

    let mut wrong_type = VALID_INIT_ACK_CHUNK;
    wrong_type[20..22].copy_from_slice(&16u16.to_be_bytes());
    rejects::<40>(&wrong_type, 1);

    let mut duplicate = [0u8; 36];
    duplicate[..28].copy_from_slice(&VALID_INIT_ACK_CHUNK);
    duplicate[2..4].copy_from_slice(&36u16.to_be_bytes());
    duplicate[28..36].copy_from_slice(&[0, 7, 0, 8, 1, 2, 3, 4]);
    rejects::<48>(&duplicate, 1);
}

#[test]
fn init_ack_rejects_zero_outbound_streams() {
    let mut chunk = VALID_INIT_ACK_CHUNK;
    chunk[12..14].copy_from_slice(&0u16.to_be_bytes());
    rejects::<40>(&chunk, 1);
}

#[test]
fn init_ack_rejects_zero_inbound_streams() {
    let mut chunk = VALID_INIT_ACK_CHUNK;
    chunk[14..16].copy_from_slice(&0u16.to_be_bytes());
    rejects::<40>(&chunk, 1);
}

#[test]
fn init_ack_rejects_malformed_state_cookie() {
    let mut malformed = VALID_INIT_ACK_CHUNK;
    malformed[22..24].copy_from_slice(&3u16.to_be_bytes());
    rejects::<40>(&malformed, 1);
}

#[test]
fn init_ack_rejects_empty_state_cookie_value() {
    let mut empty = VALID_INIT_ACK_CHUNK;
    empty[2..4].copy_from_slice(&24u16.to_be_bytes());
    empty[22..24].copy_from_slice(&4u16.to_be_bytes());
    rejects::<36>(&empty[..24], 1);
}

#[test]
fn tlv_walker_rejects_short_overrun_partial_padding_and_trailing_bytes() {
    let cases: [&[u8]; 4] = [
        &[6, 0, 0, 8, 0, 1, 0, 3],
        &[6, 0, 0, 8, 0, 1, 0, 9],
        &[6, 0, 0, 10, 0, 1, 0, 5, 0xAA, 0],
        &[6, 0, 0, 9, 0, 1, 0, 4, 0xAA],
    ];
    rejects::<20>(cases[0], 1);
    rejects::<20>(cases[1], 1);
    rejects::<24>(cases[2], 1);
    rejects::<24>(cases[3], 1);
}

#[test]
fn tlv_walker_accepts_exact_end_or_full_final_padding() {
    assert!(validate_sctp_packet(&chunk_packet::<24>(&[6, 0, 0, 9, 0, 1, 0, 5, 0xAA], 1)).is_ok());
    assert!(
        validate_sctp_packet(&chunk_packet::<24>(
            &[6, 0, 0, 12, 0, 1, 0, 5, 0xAA, 0, 0, 0],
            1,
        ))
        .is_ok()
    );
}

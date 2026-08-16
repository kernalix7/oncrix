// Copyright 2026 ONCRIX Contributors
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{P9MessageType, P9Qid, P9QidType, Plan9Message};
use oncrix_lib::Error;

#[test]
fn characterization_header_rejects_lengths_below_wire_minimum() {
    // Given
    let frames: [&[u8]; 7] = [
        &[],
        &[0],
        &[0, 0],
        &[0, 0, 0],
        &[0, 0, 0, 0],
        &[0, 0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 0],
    ];

    // When / Then
    for frame in frames {
        assert_eq!(
            Plan9Message::parse_header(frame),
            Err(Error::InvalidArgument)
        );
    }
}

#[test]
fn characterization_header_accepts_exact_seven_byte_frame() {
    // Given
    let frame = [7, 0, 0, 0, 100, 0x34, 0x12];

    // When
    let parsed = Plan9Message::parse_header(&frame);

    // Then
    assert_eq!(parsed, Ok((P9MessageType::Tversion, 0x1234, 7)));
}

#[test]
fn characterization_header_rejects_declared_size_mismatch() {
    // Given
    let frame = [8, 0, 0, 0, 100, 0, 0];

    // When
    let parsed = Plan9Message::parse_header(&frame);

    // Then
    assert_eq!(parsed, Err(Error::InvalidArgument));
}

#[test]
fn characterization_header_rejects_unknown_message_type() {
    // Given
    let frame = [7, 0, 0, 0, 0, 0, 0];

    // When
    let parsed = Plan9Message::parse_header(&frame);

    // Then
    assert_eq!(parsed, Err(Error::InvalidArgument));
}

#[test]
fn characterization_counted_string_returns_borrowed_payload() {
    // Given
    let frame = [3, 0, b'n', b'i', b'n', 0xAA];

    // When
    let parsed = Plan9Message::read_string(&frame, 0);

    // Then
    let (value, next) = parsed.unwrap();
    assert_eq!(value, b"nin");
    assert_eq!(next, 5);
    assert!(core::ptr::eq(value, &frame[2..5]));
}

#[test]
fn characterization_counted_string_rejects_truncated_payload() {
    // Given
    let frame = [4, 0, b'n', b'i', b'n'];

    // When
    let parsed = Plan9Message::read_string(&frame, 0);

    // Then
    assert_eq!(parsed, Err(Error::InvalidArgument));
}

#[test]
fn characterization_qid_rejects_twelve_byte_frame() {
    // Given
    let frame = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // When
    let parsed = P9Qid::from_bytes(&frame, 0);

    // Then
    assert_eq!(parsed, Err(Error::InvalidArgument));
}

#[test]
fn characterization_qid_roundtrips_at_zero_offset() {
    // Given
    let frame = [
        0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
    ];
    let mut encoded = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // When
    let (qid, consumed) = P9Qid::from_bytes(&frame, 0).unwrap();
    let written = qid.to_bytes(&mut encoded, 0);

    // Then
    assert_eq!(consumed, P9Qid::WIRE_SIZE);
    assert_eq!(written, Ok(P9Qid::WIRE_SIZE));
    assert_eq!(encoded, frame);
}

#[test]
fn characterization_qid_roundtrips_at_nonzero_offset() {
    // Given
    let frame = [
        0xFE, 0x02, 0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xEF,
    ];
    let mut encoded = [0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xEF];

    // When
    let (qid, consumed) = P9Qid::from_bytes(&frame, 1).unwrap();
    let written = qid.to_bytes(&mut encoded, 1);

    // Then
    assert_eq!(consumed, P9Qid::WIRE_SIZE);
    assert_eq!(written, Ok(P9Qid::WIRE_SIZE));
    assert_eq!(encoded, frame);
}

#[test]
fn offset_overflow_read_u32_rejects_maximum_offset() {
    assert_eq!(
        Plan9Message::read_u32(&[], usize::MAX),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_read_u32_rejects_near_maximum_offset() {
    assert_eq!(
        Plan9Message::read_u32(&[], usize::MAX - 2),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_read_u64_rejects_maximum_offset() {
    assert_eq!(
        Plan9Message::read_u64(&[], usize::MAX),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_read_u64_rejects_near_maximum_offset() {
    assert_eq!(
        Plan9Message::read_u64(&[], usize::MAX - 4),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_read_string_rejects_maximum_offset() {
    assert_eq!(
        Plan9Message::read_string(&[], usize::MAX),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_read_string_rejects_near_maximum_offset() {
    assert_eq!(
        Plan9Message::read_string(&[], usize::MAX - 1),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_qid_decode_rejects_overflowing_offset() {
    assert_eq!(
        P9Qid::from_bytes(&[], usize::MAX - 6),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn offset_overflow_qid_encode_rejects_overflowing_offset() {
    let qid = P9Qid::new(P9QidType::FILE, 0, 0);
    let mut frame = [];

    assert_eq!(
        qid.to_bytes(&mut frame, usize::MAX - 6),
        Err(Error::InvalidArgument)
    );
}

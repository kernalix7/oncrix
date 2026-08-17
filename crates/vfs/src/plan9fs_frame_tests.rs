// Copyright 2026 ONCRIX Contributors
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::session_tests::{assert_poisoned, attached, reply, tag, versioned};
use super::{
    NOFID, NOTAG, P9MessageType, P9OpenMode, P9Qid, P9QidType, Plan9Message, Plan9Session,
    SessionState,
};
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
fn characterization_header_rejects_declared_size_smaller_than_received() {
    // Given / When / Then
    let frame = [7, 0, 0, 0, 100, 0, 0, 0xAA];
    assert_eq!(
        Plan9Message::parse_header(&frame),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn frame_limit_persists_across_reset() {
    // Given / When / Then
    let mut message = Plan9Message::new();
    message.set_limit(8).unwrap();
    message.reset(P9MessageType::Tversion, 1);
    assert_eq!(message.put_u16(1), Err(Error::InvalidArgument));
    message.reset(P9MessageType::Tattach, 2);
    assert_eq!(message.put_u16(1), Err(Error::InvalidArgument));
}

#[test]
fn failed_puts_leave_message_position_unchanged() {
    // Given / When / Then
    let mut message = Plan9Message::new();
    message.set_limit(9).unwrap();
    message.reset(P9MessageType::Tversion, 1);
    assert_eq!(message.put_string(b"x"), Err(Error::InvalidArgument));
    message.put_u16(0x1234).unwrap();
    assert_eq!(message.finalize(), &[9, 0, 0, 0, 100, 1, 0, 0x34, 0x12]);
}

#[test]
fn terminal_fid_retirement_clears_only_matching_root() {
    // Given / When / Then
    let mut session = attached();
    let fid = session.root_fid();
    let slot = session.fid_table.lookup(fid).unwrap();
    let entry = session.fid_table.get_mut(slot).unwrap();
    entry.qid = P9Qid::new(P9QidType::DIR, 9, 9);
    entry.mode = P9OpenMode::OWRITE;
    entry.offset = 99;
    entry.iounit = 77;
    entry.path[0] = b'x';
    entry.path_len = 1;
    let clunk_tag = tag(session.build_tclunk(fid).unwrap());
    let response = reply(P9MessageType::Rclunk, clunk_tag, &[]);
    session.handle_rclunk(&response).unwrap();
    assert_eq!(session.root_fid(), NOFID);
    let (reused, _) = session.fid_table.alloc().unwrap();
    let entry = session.fid_table.get(reused).unwrap();
    assert_eq!(
        (entry.mode, entry.offset, entry.iounit),
        (P9OpenMode::OREAD, 0, 0)
    );
    assert_eq!(entry.qid, P9Qid::new(P9QidType::FILE, 0, 0));
    assert_eq!((entry.path[0], entry.path_len), (0, 0));

    let mut non_root = attached();
    let root = non_root.root_fid();
    let (request, fid) = non_root.build_twalk(root, &[]).unwrap();
    let walk_tag = tag(request);
    non_root
        .handle_rwalk(&reply(P9MessageType::Rwalk, walk_tag, &[0, 0]))
        .unwrap();
    let clunk_tag = tag(non_root.build_tclunk(fid).unwrap());
    non_root
        .handle_rclunk(&reply(P9MessageType::Rclunk, clunk_tag, &[]))
        .unwrap();
    assert_eq!(non_root.root_fid(), root);

    let mut removed = attached();
    let fid = removed.root_fid();
    let remove_tag = tag(removed.build_tremove(fid).unwrap());
    let response = reply(P9MessageType::Rremove, remove_tag, &[]);
    removed.handle_rremove(&response).unwrap();
    assert_eq!(removed.root_fid(), NOFID);
    let mut denied = attached();
    let fid = denied.root_fid();
    let remove_tag = tag(denied.build_tremove(fid).unwrap());
    let response = reply(P9MessageType::Rlerror, remove_tag, &13u32.to_le_bytes());
    let result = denied.handle_rremove(&response);
    assert_eq!(result, Err(Error::PermissionDenied));
    assert_eq!(denied.root_fid(), NOFID);
}

#[test]
fn lifecycle_second_builder_is_busy_without_mutation() {
    // Given / When / Then
    let mut negotiation = Plan9Session::new();
    negotiation.build_tversion().unwrap();
    assert_eq!(negotiation.build_tversion().map(|_| ()), Err(Error::Busy));
    let mut session = versioned();
    session.build_tattach(7, b"").unwrap();
    let root = session.root_fid();
    let count = session.fid_table().active_count();
    assert_eq!(session.build_tattach(7, b"").map(|_| ()), Err(Error::Busy));
    assert_eq!(session.build_twalk(root, &[]).map(|_| ()), Err(Error::Busy));
    assert_eq!(
        (session.root_fid(), session.fid_table().active_count()),
        (root, count)
    );
}

#[test]
fn abort_connection_invalidates_pending_and_fids() {
    // Given / When / Then
    let mut session = attached();
    let fid = session.root_fid();
    session.build_tclunk(fid).unwrap();
    session.abort_connection();
    assert_poisoned(&session);
    assert_eq!(
        session.build_tclunk(fid).map(|_| ()),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn lifecycle_malformed_matching_terminal_poisons_negotiation() {
    // Given / When / Then
    let mut session = Plan9Session::new();
    session.build_tversion().unwrap();
    assert!(
        session
            .handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &[0]))
            .is_err()
    );
    assert_eq!(session.state(), SessionState::Error);
    assert_eq!(
        session.build_tversion().map(|_| ()),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn lifecycle_stale_reply_cannot_complete_newer_request() {
    // Given / When / Then
    let mut session = attached();
    let fid = session.root_fid();
    let old_tag = tag(session.build_tstat(fid).unwrap());
    let old_reply = reply(P9MessageType::Rstat, old_tag, &[]);
    session.finalize_unhandled_response(&old_reply).unwrap();
    let new_tag = tag(session.build_tstat(fid).unwrap());
    assert!(session.finalize_unhandled_response(&old_reply).is_err());
    let new_reply = reply(P9MessageType::Rstat, new_tag, &[]);
    assert!(session.finalize_unhandled_response(&new_reply).is_ok());
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
fn offset_overflow_integer_reads_reject_maximum_and_near_maximum() {
    // Given / When / Then
    for offset in [usize::MAX, usize::MAX - 2] {
        assert_eq!(
            Plan9Message::read_u32(&[], offset),
            Err(Error::InvalidArgument)
        );
    }
    for offset in [usize::MAX, usize::MAX - 4] {
        assert_eq!(
            Plan9Message::read_u64(&[], offset),
            Err(Error::InvalidArgument)
        );
    }
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

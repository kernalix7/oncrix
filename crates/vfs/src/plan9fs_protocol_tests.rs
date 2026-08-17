// Copyright 2026 ONCRIX Contributors
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::session_tests::{
    QID, ROPEN, RWALK_ONE, VERSION_256, assert_poisoned, attached, opened, tag as request_tag,
    versioned, walked,
};
use super::{
    NOTAG, P9MessageType, P9OpenMode, P9RawRequest, P9WalkResult, Plan9Session, SessionState,
};
use oncrix_lib::Error;
use std::vec::Vec;

#[derive(Clone, Copy)]
enum Handler {
    V,
    A,
    W,
    O,
    C,
}

const HANDLERS: [Handler; 5] = [Handler::V, Handler::A, Handler::W, Handler::O, Handler::C];

type Pending = (Plan9Session, Handler, u32, u16, u8);

fn wire(kind: u8, tag: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from([0, 0, 0, 0, kind]);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(payload);
    let size = (frame.len() as u32).to_le_bytes();
    frame[..4].copy_from_slice(&size);
    frame
}

fn pending(handler: Handler) -> Pending {
    match handler {
        Handler::V => {
            let mut session = Plan9Session::new();
            session.build_tversion().unwrap();
            (session, handler, 0, NOTAG, P9MessageType::Rversion as u8)
        }
        Handler::A => {
            let mut session = versioned();
            let tag = request_tag(session.build_tattach(7, b"").unwrap());
            let fid = session.root_fid();
            (session, handler, fid, tag, P9MessageType::Rattach as u8)
        }
        Handler::W => {
            let mut session = attached();
            let root = session.root_fid();
            let (request, fid) = session.build_twalk(root, &[b"x"]).unwrap();
            let tag = request_tag(request);
            (session, handler, fid, tag, P9MessageType::Rwalk as u8)
        }
        Handler::O => {
            let (mut session, fid) = walked();
            let tag = request_tag(session.build_topen(fid, P9OpenMode::OREAD).unwrap());
            (session, handler, fid, tag, P9MessageType::Ropen as u8)
        }
        Handler::C => {
            let mut session = attached();
            let fid = session.root_fid();
            let tag = request_tag(session.build_tclunk(fid).unwrap());
            (session, handler, fid, tag, P9MessageType::Rclunk as u8)
        }
    }
}

fn finish(request: &mut Pending, tag_offset: u16, kind: Option<u8>) -> Result<(), Error> {
    let payload = match request.1 {
        Handler::V => &VERSION_256[..],
        Handler::A => &QID[..],
        Handler::W => &RWALK_ONE[..],
        Handler::O => &ROPEN[..],
        Handler::C => &[][..],
    };
    let tag = request.3.wrapping_add(tag_offset);
    let reply = wire(kind.unwrap_or(request.4), tag, payload);
    match request.1 {
        Handler::V => request.0.handle_rversion(&reply),
        Handler::A => request.0.handle_rattach(&reply).map(|_| ()),
        Handler::W => request.0.handle_rwalk(&reply).map(|_| ()),
        Handler::O => request.0.handle_ropen(&reply).map(|_| ()),
        Handler::C => request.0.handle_rclunk(&reply),
    }
}

#[test]
fn protocol_wrong_tags_preserve_pending_requests() {
    // Given / When / Then
    for handler in HANDLERS {
        let mut request = pending(handler);
        assert_eq!(finish(&mut request, 1, None), Err(Error::InvalidArgument));
        assert_eq!(finish(&mut request, 0, None), Ok(()));
        assert_eq!(finish(&mut request, 0, None), Err(Error::InvalidArgument));
    }
}

#[test]
fn protocol_wrong_handler_preserves_pending_request() {
    // Given / When / Then
    let mut request = pending(Handler::O);
    let frame = wire(P9MessageType::Rclunk as u8, request.3, &[]);
    assert_eq!(request.0.handle_rclunk(&frame), Err(Error::InvalidArgument));
    assert_eq!(finish(&mut request, 0, None), Ok(()));
}

#[test]
fn protocol_matching_wrong_response_type_poisons_connection() {
    // Given / When / Then
    let mut request = pending(Handler::A);
    let result = finish(&mut request, 0, Some(P9MessageType::Rwalk as u8));
    assert_eq!(result, Err(Error::InvalidArgument));
    assert_poisoned(&request.0);
}

#[test]
fn protocol_literal_rlerror_errno_and_payload_rules() {
    // Given / When / Then
    for (errno, expected) in [(13, Error::PermissionDenied), (u32::MAX, Error::IoError)] {
        let mut request = pending(Handler::A);
        let result = request
            .0
            .handle_rattach(&wire(7, request.3, &errno.to_le_bytes()));
        assert_eq!(result, Err(expected));
        assert_eq!(request.0.state(), SessionState::Versioned);
    }
    let mut trailing = pending(Handler::A);
    let result = trailing
        .0
        .handle_rattach(&wire(7, trailing.3, &[13, 0, 0, 0, 0]));
    assert_eq!(result, Err(Error::InvalidArgument));
    assert_poisoned(&trailing.0);
    let mut version = pending(Handler::V);
    let result = version
        .0
        .handle_rversion(&wire(7, NOTAG, &13u32.to_le_bytes()));
    assert_eq!(result, Err(Error::PermissionDenied));
    assert_eq!(version.0.state(), SessionState::Disconnected);
    assert!(version.0.build_tversion().is_ok());
    let mut malformed_version = pending(Handler::V);
    let result = malformed_version
        .0
        .handle_rversion(&wire(7, NOTAG, &[13, 0, 0]));
    assert_eq!(result, Err(Error::InvalidArgument));
    assert_poisoned(&malformed_version.0);
    let mut legacy = pending(Handler::A);
    let frame = wire(P9MessageType::Rerror as u8, legacy.3, &[]);
    assert_eq!(legacy.0.handle_rattach(&frame), Err(Error::InvalidArgument));
    assert_poisoned(&legacy.0);
    let mut clunk = pending(Handler::C);
    let result = clunk
        .0
        .handle_rclunk(&wire(7, clunk.3, &13u32.to_le_bytes()));
    assert_eq!(result, Err(Error::PermissionDenied));
    assert_eq!(clunk.0.fid_table().lookup(clunk.2), Err(Error::NotFound));
    assert_eq!(clunk.0.root_fid(), super::NOFID);
}

#[test]
fn protocol_raw_responses_borrow_payload_and_retire_context() {
    // Given / When / Then
    let (mut read, fid) = opened(P9OpenMode::OREAD);
    let tag = request_tag(read.build_tread(fid, 0, 3).unwrap());
    let frame = wire(P9MessageType::Rread as u8, tag, b"read");
    let response = read.finalize_unhandled_response(&frame).unwrap();
    assert_eq!(response.request, P9RawRequest::Read { fid, count: 3 });
    assert_eq!(response.payload, b"read");
    assert_eq!(
        read.finalize_unhandled_response(&frame),
        Err(Error::InvalidArgument)
    );
    let (mut write, fid) = opened(P9OpenMode::OWRITE);
    let tag = request_tag(write.build_twrite(fid, 0, b"abc").unwrap());
    let frame = wire(P9MessageType::Rwrite as u8, tag, b"written");
    let response = write.finalize_unhandled_response(&frame).unwrap();
    assert_eq!(response.request, P9RawRequest::Write { fid, count: 3 });
    assert_eq!(response.response_type, P9MessageType::Rwrite);
    assert_eq!(response.payload, b"written");
    let mut stat = attached();
    let fid = stat.root_fid();
    let tag = request_tag(stat.build_tstat(fid).unwrap());
    let frame = wire(P9MessageType::Rstat as u8, tag, b"stat");
    let response = stat.finalize_unhandled_response(&frame).unwrap();
    assert_eq!(response.request, P9RawRequest::Stat { fid });
    assert_eq!(response.response_type, P9MessageType::Rstat);
    assert_eq!(response.payload, b"stat");
    let tag = request_tag(stat.build_tstat(fid).unwrap());
    let denied = wire(7, tag, &13u32.to_le_bytes());
    assert_eq!(
        stat.finalize_unhandled_response(&denied),
        Err(Error::PermissionDenied)
    );
    assert_eq!(stat.state(), SessionState::Attached);
}

#[test]
fn protocol_walk_reply_cardinality_and_commit_rules() {
    // Given / When / Then
    let mut more = attached();
    let root = more.root_fid();
    let tag = request_tag(more.build_twalk(root, &[b"x"]).unwrap().0);
    let mut payload = Vec::from([2, 0]);
    payload.extend_from_slice(&QID);
    payload.extend_from_slice(&QID);
    assert!(
        more.handle_rwalk(&wire(P9MessageType::Rwalk as u8, tag, &payload))
            .is_err()
    );
    assert_poisoned(&more);
    let mut zero = attached();
    let root = zero.root_fid();
    let tag = request_tag(zero.build_twalk(root, &[b"x"]).unwrap().0);
    assert!(
        zero.handle_rwalk(&wire(P9MessageType::Rwalk as u8, tag, &[0, 0]))
            .is_err()
    );
    assert_poisoned(&zero);
}

#[test]
fn protocol_zero_name_clone_copies_complete_metadata() {
    // Given / When / Then
    let mut clone = attached();
    let root = clone.root_fid();
    let root_slot = clone.fid_table().lookup(root).unwrap();
    let source = clone.fid_table.get_mut(root_slot).unwrap();
    source.mode = P9OpenMode::OWRITE;
    source.qid.qtype = super::P9QidType::FILE;
    source.offset = 17;
    source.iounit = 19;
    source.path[..3].copy_from_slice(b"src");
    source.path_len = 3;
    let source_before = std::format!("{source:?}");
    let mut expected = source.clone();
    let (request, dst) = clone.build_twalk(root, &[]).unwrap();
    let tag = request_tag(request);
    let result = clone
        .handle_rwalk(&wire(P9MessageType::Rwalk as u8, tag, &[0, 0]))
        .unwrap();
    assert_eq!(
        result,
        P9WalkResult::Cloned {
            source: root,
            destination: dst
        }
    );
    let dst_slot = clone.fid_table().lookup(dst).unwrap();
    let source = clone.fid_table().get(root_slot).unwrap();
    let destination = clone.fid_table().get(dst_slot).unwrap();
    expected.fid = dst;
    assert_eq!(std::format!("{source:?}"), source_before);
    assert_eq!(
        std::format!("{destination:?}"),
        std::format!("{expected:?}")
    );
}

#[test]
fn protocol_partial_walk_releases_destination_and_preserves_source() {
    // Given / When / Then
    let mut session = attached();
    let root = session.root_fid();
    let (request, dst) = session.build_twalk(root, &[b"x", b"y"]).unwrap();
    let tag = request_tag(request);
    let result = session
        .handle_rwalk(&wire(P9MessageType::Rwalk as u8, tag, &RWALK_ONE))
        .unwrap();
    assert!(matches!(
        result,
        P9WalkResult::Partial { source, count: 1, qids }
            if source == root && qids[0].qtype == super::P9QidType::FILE
    ));
    assert_eq!(session.fid_table().lookup(dst), Err(Error::NotFound));
    assert!(session.fid_table().lookup(root).is_ok());
}

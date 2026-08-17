// Copyright 2026 ONCRIX Contributors
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::{
    FidState, NOFID, NOTAG, P9MessageType, P9OpenMode, P9QidType, P9WalkResult, Plan9Session,
    SessionState,
};
use oncrix_lib::Error;
use std::vec::Vec;

pub(super) const VERSION_256: [u8; 14] = [
    0, 1, 0, 0, 8, 0, b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
];
pub(super) const QID: [u8; 13] = [0x80, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
pub(super) const RWALK_ONE: [u8; 15] = [1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
pub(super) const ROPEN: [u8; 17] = [0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub(super) fn reply(kind: P9MessageType, tag: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from([0, 0, 0, 0, kind as u8]);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(payload);
    let size = (frame.len() as u32).to_le_bytes();
    frame[..4].copy_from_slice(&size);
    frame
}

pub(super) fn tag(request: &[u8]) -> u16 {
    u16::from_le_bytes([request[5], request[6]])
}

pub(super) fn versioned() -> Plan9Session {
    let mut session = Plan9Session::new();
    session.build_tversion().unwrap();
    session
        .handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &VERSION_256))
        .unwrap();
    session
}

pub(super) fn attached() -> Plan9Session {
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    session
        .handle_rattach(&reply(P9MessageType::Rattach, tag, &QID))
        .unwrap();
    session
}

pub(super) fn walked() -> (Plan9Session, u32) {
    let mut session = attached();
    let root = session.root_fid();
    let (request, fid) = session.build_twalk(root, &[b"x"]).unwrap();
    let tag = tag(request);
    let result = session
        .handle_rwalk(&reply(P9MessageType::Rwalk, tag, &RWALK_ONE))
        .unwrap();
    assert!(matches!(
        result,
        P9WalkResult::Full { source, destination, count: 1, qids }
            if source == root && destination == fid && qids[0].qtype == P9QidType::FILE
    ));
    (session, fid)
}

pub(super) fn opened(mode: P9OpenMode) -> (Plan9Session, u32) {
    let (mut session, fid) = walked();
    let tag = tag(session.build_topen(fid, mode).unwrap());
    let (_, iounit) = session
        .handle_ropen(&reply(P9MessageType::Ropen, tag, &ROPEN))
        .unwrap();
    assert_eq!(iounit, 256);
    (session, fid)
}

pub(super) fn fid_state(session: &Plan9Session, fid: u32) -> FidState {
    let slot = session.fid_table().lookup(fid).unwrap();
    session.fid_table().get(slot).unwrap().state
}

pub(super) fn assert_poisoned(session: &Plan9Session) {
    assert_eq!(session.state(), SessionState::Error);
    assert_eq!(session.root_fid(), NOFID);
    assert_eq!(session.fid_table().active_count(), 0);
}

#[test]
fn session_red_rversion_order_is_enforced() {
    // Given / When / Then
    let mut first_session = Plan9Session::new();
    let first = first_session.handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &VERSION_256));
    let mut second_session = Plan9Session::new();
    second_session.build_tversion().unwrap();
    let second = second_session.build_tversion().map(|frame| frame.len());
    assert!(
        matches!(first, Err(Error::InvalidArgument))
            && first_session.state() == SessionState::Disconnected
            && second == Err(Error::Busy)
    );
}

#[test]
fn session_red_msize_offer_is_enforced_without_mutation() {
    // Given / When / Then
    let mut session = Plan9Session::new();
    session.build_tversion().unwrap();
    let mut version = VERSION_256;
    version[..4].copy_from_slice(&8193u32.to_le_bytes());
    let result = session.handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &version));
    assert!(matches!(result, Err(Error::InvalidArgument)) && session.msize() == 8192);
}

#[test]
fn session_red_inbound_negotiated_msize_is_checked_before_dispatch() {
    // Given / When / Then
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    let result = session.handle_rattach(&reply(P9MessageType::Rerror, tag, &[0xA5; 250]));
    assert_eq!(result, Err(Error::InvalidArgument));
    assert_poisoned(&session);
}

#[test]
fn session_red_oversized_tattach_does_not_leak_root_fid() {
    // Given / When / Then
    let mut session = versioned();
    let result = session
        .build_tattach(7, &[b'a'; 256])
        .map(|frame| frame.len());
    assert!(
        result == Err(Error::InvalidArgument)
            && session.root_fid() == NOFID
            && session.fid_table().active_count() == 0
    );
}

#[test]
fn session_red_oversized_twalk_does_not_leak_destination_fid() {
    // Given / When / Then
    let mut session = attached();
    let root = session.root_fid();
    let result = session
        .build_twalk(root, &[&[b'w'; 240]])
        .map(|(frame, _)| frame.len());
    assert!(result == Err(Error::InvalidArgument) && session.fid_table().active_count() == 1);
}

#[test]
fn session_red_tread_count_fits_negotiated_msize() {
    // Given / When / Then
    let (mut session, fid) = opened(P9OpenMode::OREAD);
    let slot = session.fid_table().lookup(fid).unwrap();
    assert_eq!(session.fid_table().get(slot).unwrap().iounit, 256);
    let frame = session.build_tread(fid, 0, u32::MAX).unwrap();
    let count = u32::from_le_bytes([frame[19], frame[20], frame[21], frame[22]]);
    assert_eq!(count, 245);
}

#[test]
fn session_red_twrite_frame_and_count_fit_negotiated_msize() {
    // Given / When / Then
    let (mut session, fid) = opened(P9OpenMode::OWRITE);
    let data = [0xA5; 300];
    let frame = session.build_twrite(fid, 0, &data).unwrap();
    let count = u32::from_le_bytes([frame[19], frame[20], frame[21], frame[22]]) as usize;
    assert!(frame.len() == 256 && count == 233 && frame[23..] == data[..count]);
}

#[test]
fn session_exact_and_overflow_variable_request_boundaries() {
    // Given / When / Then
    let mut attach = versioned();
    assert_eq!(attach.build_tattach(7, &[b'a'; 233]).unwrap().len(), 256);
    let mut attach_over = versioned();
    let result = attach_over
        .build_tattach(7, &[b'a'; 234])
        .map(|frame| frame.len());
    assert_eq!(result, Err(Error::InvalidArgument));
    let mut walk = attached();
    let root = walk.root_fid();
    assert_eq!(
        walk.build_twalk(root, &[&[b'w'; 237]]).unwrap().0.len(),
        256
    );
    let mut walk_over = attached();
    let root = walk_over.root_fid();
    let result = walk_over
        .build_twalk(root, &[&[b'w'; 238]])
        .map(|value| value.0.len());
    assert_eq!(result, Err(Error::InvalidArgument));
    let (mut open, fid) = opened(P9OpenMode::OREAD);
    let result = open.build_twalk(fid, &[]).map(|_| ());
    assert_eq!(result, Err(Error::InvalidArgument));
}

#[test]
fn session_walk_and_open_require_legal_fid_states() {
    // Given / When / Then
    let mut walk = attached();
    let root = walk.root_fid();
    let slot = walk.fid_table.lookup(root).unwrap();
    walk.fid_table.get_mut(slot).unwrap().qid.qtype = P9QidType::FILE;
    let result = walk.build_twalk(root, &[b"x"]).map(|_| ());
    assert!(result == Err(Error::InvalidArgument) && walk.fid_table().active_count() == 1);
    let mut allocated = attached();
    let (_, fid) = allocated.fid_table.alloc().unwrap();
    let result = allocated.build_topen(fid, P9OpenMode::OREAD).map(|_| ());
    assert!(
        result == Err(Error::InvalidArgument) && fid_state(&allocated, fid) == FidState::Allocated
    );
    let (mut open, fid) = opened(P9OpenMode::OREAD);
    let result = open.build_topen(fid, P9OpenMode::OREAD).map(|_| ());
    assert_eq!(result, Err(Error::InvalidArgument));
}

#[test]
fn session_iounit_caps_io_and_open_error_preserves_fid() {
    // Given / When / Then
    let (mut session, fid) = walked();
    let open_tag = tag(session.build_topen(fid, P9OpenMode::OREAD).unwrap());
    let mut payload = Vec::from(QID);
    payload.extend_from_slice(&10u32.to_le_bytes());
    assert_eq!(
        session
            .handle_ropen(&reply(P9MessageType::Ropen, open_tag, &payload))
            .unwrap()
            .1,
        10
    );
    let frame = session.build_tread(fid, 0, 100).unwrap();
    assert_eq!(
        u32::from_le_bytes([frame[19], frame[20], frame[21], frame[22]]),
        10
    );
    let (mut denied, fid) = walked();
    let tag = tag(denied.build_topen(fid, P9OpenMode::OREAD).unwrap());
    assert_eq!(
        denied.handle_ropen(&reply(P9MessageType::Rlerror, tag, &13u32.to_le_bytes())),
        Err(Error::PermissionDenied),
    );
    assert_eq!(fid_state(&denied, fid), FidState::Attached);
}

#[test]
fn session_red_preversion_fid_builders_reject_without_mutation() {
    // Given / When / Then
    let mut session = Plan9Session::new();
    let (_, fid) = session.fid_table.alloc().unwrap();
    let clunk = session.build_tclunk(fid).map(|_| ());
    let remove = session.build_tremove(fid).map(|_| ());
    let stat = session.build_tstat(fid).map(|_| ());
    assert!(
        clunk == Err(Error::InvalidArgument)
            && remove == Err(Error::InvalidArgument)
            && stat == Err(Error::InvalidArgument)
            && session.fid_table().active_count() == 1
    );
}

#[test]
fn session_red_malformed_rattach_poisons_connection() {
    // Given / When / Then
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    assert_eq!(fid_state(&session, session.root_fid()), FidState::Allocated);
    let result = session.handle_rattach(&reply(P9MessageType::Rattach, tag, &[0]));
    assert!(result.is_err());
    assert_poisoned(&session);
}

#[test]
fn session_red_malformed_rwalk_poisons_connection() {
    // Given / When / Then
    let mut session = attached();
    let root = session.root_fid();
    let (request, _fid) = session.build_twalk(root, &[b"x"]).unwrap();
    let tag = tag(request);
    let result = session.handle_rwalk(&reply(P9MessageType::Rwalk, tag, &[1, 0, 0]));
    assert!(result.is_err());
    assert_poisoned(&session);
}

#[test]
fn session_red_malformed_ropen_poisons_connection() {
    // Given / When / Then
    let (mut session, fid) = walked();
    let tag = tag(session.build_topen(fid, P9OpenMode::OREAD).unwrap());
    let result = session.handle_ropen(&reply(P9MessageType::Ropen, tag, &[0]));
    assert!(result.is_err());
    assert_poisoned(&session);
}

#[test]
fn session_red_malformed_rclunk_poisons_connection() {
    // Given / When / Then
    let mut session = attached();
    let fid = session.root_fid();
    let tag = tag(session.build_tclunk(fid).unwrap());
    let mut malformed = reply(P9MessageType::Rclunk, tag, &[]);
    malformed[0] = 8;
    let result = session.handle_rclunk(&malformed);
    assert!(result.is_err());
    assert_poisoned(&session);
    assert_eq!(session.fid_table().lookup(fid), Err(Error::NotFound));
}

// Copyright 2026 ONCRIX Contributors
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::{FidState, NOFID, NOTAG, P9MessageType, P9OpenMode, Plan9Session, SessionState};
use oncrix_lib::Error;
use std::vec::Vec;

const VERSION_256: [u8; 14] = [
    0, 1, 0, 0, 8, 0, b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
];
const VERSION_8192: [u8; 14] = [
    0, 32, 0, 0, 8, 0, b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
];
const VERSION_8193: [u8; 14] = [
    1, 32, 0, 0, 8, 0, b'9', b'P', b'2', b'0', b'0', b'0', b'.', b'L',
];
const QID: [u8; 13] = [0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
const RWALK_ONE: [u8; 15] = [1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
const ROPEN: [u8; 17] = [0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const HANDLERS: [u8; 5] = [0, 1, 2, 3, 4];

fn reply(kind: P9MessageType, tag: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::from([0, 0, 0, 0, kind as u8]);
    frame.extend_from_slice(&tag.to_le_bytes());
    frame.extend_from_slice(payload);
    let size = (frame.len() as u32).to_le_bytes();
    frame[..4].copy_from_slice(&size);
    frame
}

fn tag(request: &[u8]) -> u16 {
    u16::from_le_bytes([request[5], request[6]])
}

fn versioned() -> Plan9Session {
    let mut session = Plan9Session::new();
    session.build_tversion().unwrap();
    session
        .handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &VERSION_256))
        .unwrap();
    session
}

fn attached() -> Plan9Session {
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    session
        .handle_rattach(&reply(P9MessageType::Rattach, tag, &QID))
        .unwrap();
    session
}

fn walked() -> (Plan9Session, u32) {
    let mut session = attached();
    let root = session.root_fid();
    let (request, fid) = session.build_twalk(root, &[b"x"]).unwrap();
    let tag = tag(request);
    session
        .handle_rwalk(&reply(P9MessageType::Rwalk, tag, &RWALK_ONE), fid)
        .unwrap();
    (session, fid)
}

fn opened(mode: P9OpenMode) -> (Plan9Session, u32) {
    let (mut session, fid) = walked();
    let tag = tag(session.build_topen(fid, mode).unwrap());
    session
        .handle_ropen(&reply(P9MessageType::Ropen, tag, &ROPEN), fid, mode)
        .unwrap();
    (session, fid)
}

fn fid_state(session: &Plan9Session, fid: u32) -> FidState {
    let slot = session.fid_table().lookup(fid).unwrap();
    session.fid_table().get(slot).unwrap().state
}

fn handler_result(handler: u8, matching: bool, extra: bool) -> Result<(), Error> {
    let mut session = Plan9Session::new();
    session.state = match handler {
        0 => SessionState::Negotiating,
        1 => SessionState::Versioned,
        2..=4 => SessionState::Attached,
        _ => unreachable!(),
    };
    session.pending_tag = if handler == 0 { NOTAG } else { 7 };
    let fid = if handler == 0 {
        NOFID
    } else {
        let (slot, fid) = session.fid_table.alloc().unwrap();
        session.fid_table.get_mut(slot).unwrap().state = FidState::Attached;
        session.root_fid = fid;
        fid
    };
    let (kind, payload) = match handler {
        0 => (P9MessageType::Rversion, &VERSION_8192[..]),
        1 => (P9MessageType::Rattach, &QID[..]),
        2 => (P9MessageType::Rwalk, &RWALK_ONE[..]),
        3 => (P9MessageType::Ropen, &ROPEN[..]),
        4 => (P9MessageType::Rclunk, &[][..]),
        _ => unreachable!(),
    };
    let tag = session.pending_tag.wrapping_add(u16::from(!matching));
    let mut response = reply(kind, tag, payload);
    if extra {
        response.push(0xEE);
        response[0] += 1;
    }
    match handler {
        0 => session.handle_rversion(&response),
        1 => session.handle_rattach(&response).map(|_| ()),
        2 => session.handle_rwalk(&response, fid).map(|_| ()),
        3 => session
            .handle_ropen(&response, fid, P9OpenMode::OREAD)
            .map(|_| ()),
        4 => session.handle_rclunk(&response, fid),
        _ => unreachable!(),
    }
}

fn handler_results(matching: bool, extra: bool) -> [Result<(), Error>; 5] {
    HANDLERS.map(|handler| handler_result(handler, matching, extra))
}

#[test]
fn session_red_rversion_order_is_enforced() {
    // Given / When / Then
    let mut first_session = Plan9Session::new();
    let first =
        first_session.handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &VERSION_8192));
    let mut second_session = Plan9Session::new();
    second_session.build_tversion().unwrap();
    let second = second_session.build_tversion().map(|frame| frame.len());
    assert!(
        matches!(first, Err(Error::InvalidArgument))
            && first_session.state() == SessionState::Disconnected
            && second == Err(Error::InvalidArgument)
    );
}

#[test]
fn session_red_msize_offer_is_enforced_without_mutation() {
    // Given / When / Then
    let mut session = Plan9Session::new();
    session.build_tversion().unwrap();
    let result = session.handle_rversion(&reply(P9MessageType::Rversion, NOTAG, &VERSION_8193));
    assert!(matches!(result, Err(Error::InvalidArgument)) && session.msize() == 8192);
}

#[test]
fn session_red_inbound_negotiated_msize_is_checked_before_dispatch() {
    // Given / When / Then
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    let result = session.handle_rattach(&reply(P9MessageType::Rerror, tag, &[0xA5; 250]));
    assert!(
        matches!(result, Err(Error::InvalidArgument)) && session.state() == SessionState::Versioned
    );
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
    let frame = session.build_tread(fid, 0, u32::MAX).unwrap();
    let count = u32::from_le_bytes([frame[19], frame[20], frame[21], frame[22]]);
    assert!(count <= 245);
}

#[test]
fn session_red_twrite_frame_and_count_fit_negotiated_msize() {
    // Given / When / Then
    let (mut session, fid) = opened(P9OpenMode::OWRITE);
    let data = [0xA5; 300];
    let frame = session.build_twrite(fid, 0, &data).unwrap();
    let count = u32::from_le_bytes([frame[19], frame[20], frame[21], frame[22]]) as usize;
    assert!(frame.len() <= 256 && count <= 233 && frame[23..] == data[..count]);
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
fn session_red_success_handlers_require_exact_payloads() {
    // Given / When / Then
    assert!(handler_results(true, true).iter().all(Result::is_err));
}

#[test]
fn session_red_wrong_tags_are_rejected_by_every_handler() {
    // Given / When / Then
    assert_eq!(
        handler_results(false, false),
        [Err(Error::InvalidArgument); 5]
    );
}

#[test]
fn session_red_malformed_rattach_rolls_back_provisional_root() {
    // Given / When / Then
    let mut session = versioned();
    let tag = tag(session.build_tattach(7, b"").unwrap());
    assert_eq!(fid_state(&session, session.root_fid()), FidState::Allocated);
    let result = session.handle_rattach(&reply(P9MessageType::Rattach, tag, &[0]));
    assert!(
        result.is_err() && session.root_fid() == NOFID && session.fid_table().active_count() == 0
    );
}

#[test]
fn session_red_malformed_rwalk_rolls_back_destination() {
    // Given / When / Then
    let mut session = attached();
    let root = session.root_fid();
    let (request, fid) = session.build_twalk(root, &[b"x"]).unwrap();
    let tag = tag(request);
    let result = session.handle_rwalk(&reply(P9MessageType::Rwalk, tag, &[1, 0, 0]), fid);
    assert!(
        result.is_err()
            && session.state() == SessionState::Attached
            && session.fid_table().lookup(fid) == Err(Error::NotFound)
    );
}

#[test]
fn session_red_malformed_ropen_preserves_fid() {
    // Given / When / Then
    let (mut session, fid) = walked();
    let tag = tag(session.build_topen(fid, P9OpenMode::OREAD).unwrap());
    let result = session.handle_ropen(
        &reply(P9MessageType::Ropen, tag, &[0]),
        fid,
        P9OpenMode::OREAD,
    );
    assert!(result.is_err() && fid_state(&session, fid) == FidState::Attached);
}

#[test]
fn session_red_malformed_rclunk_preserves_fid() {
    // Given / When / Then
    let mut session = attached();
    let fid = session.root_fid();
    let tag = tag(session.build_tclunk(fid).unwrap());
    let mut malformed = reply(P9MessageType::Rclunk, tag, &[]);
    malformed[0] = 8;
    let result = session.handle_rclunk(&malformed, fid);
    assert!(result.is_err() && fid_state(&session, fid) == FidState::Attached);
}

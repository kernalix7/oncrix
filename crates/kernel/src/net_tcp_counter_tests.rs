// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::net_tcp_test_support::*;
use super::*;

#[test]
fn tcp_valid_segment_increments_admitted_only() {
    let segment = valid_tcp_segment();
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    let mut stack = tcp_stack();
    assert_eq!(stack.process_packet(&frame[..len], &mut [0u8; 128]), Ok(0));
    assert_eq!(stack.tcp_admitted(), 1);
    assert_eq!(stack.tcp_dropped(), 0);
}

#[test]
fn tcp_corrupt_segment_increments_dropped_only() {
    let mut segment = valid_tcp_segment();
    segment[4] ^= 1;
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    let mut stack = tcp_stack();
    assert_eq!(stack.process_packet(&frame[..len], &mut [0u8; 128]), Ok(0));
    assert_eq!(stack.tcp_admitted(), 0);
    assert_eq!(stack.tcp_dropped(), 1);
}

#[test]
fn tcp_fragment_increments_dropped_only() {
    let segment = valid_tcp_segment();
    let (frame, len) = ip_frame(PROTO_TCP, 0x2000, &segment);
    let mut stack = tcp_stack();
    assert_eq!(stack.process_packet(&frame[..len], &mut [0u8; 128]), Ok(0));
    assert_eq!(stack.tcp_admitted(), 0);
    assert_eq!(stack.tcp_dropped(), 1);
}

#[test]
fn tcp_counters_saturate() {
    let valid = valid_tcp_segment();
    let mut corrupt = valid;
    corrupt[4] ^= 1;
    let (valid_frame, valid_len) = ip_frame(PROTO_TCP, 0, &valid);
    let (corrupt_frame, corrupt_len) = ip_frame(PROTO_TCP, 0, &corrupt);
    let mut stack = tcp_stack();
    stack.tcp_admitted = u64::MAX;
    stack.tcp_dropped = u64::MAX;
    assert_eq!(
        stack.process_packet(&valid_frame[..valid_len], &mut [0u8; 128]),
        Ok(0)
    );
    assert_eq!(
        stack.process_packet(&corrupt_frame[..corrupt_len], &mut [0u8; 128]),
        Ok(0)
    );
    assert_eq!(stack.tcp_admitted(), u64::MAX);
    assert_eq!(stack.tcp_dropped(), u64::MAX);
}

#[test]
fn tcp_bad_ipv4_checksum_does_not_touch_counters() {
    let segment = valid_tcp_segment();
    let (mut frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    frame[ETHER_HEADER_LEN + 8] ^= 1;
    let mut stack = tcp_stack();
    assert_eq!(stack.process_packet(&frame[..len], &mut [0u8; 128]), Ok(0));
    assert_eq!((stack.tcp_admitted(), stack.tcp_dropped()), (0, 0));
}

#[test]
fn tcp_wrong_destination_does_not_touch_counters() {
    let segment = valid_tcp_segment();
    let (mut frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    retarget_ipv4(&mut frame, [10, 0, 0, 9]);
    let mut stack = tcp_stack();
    assert_eq!(stack.process_packet(&frame[..len], &mut [0u8; 128]), Ok(0));
    assert_eq!((stack.tcp_admitted(), stack.tcp_dropped()), (0, 0));
}

#[test]
fn tcp_ethernet_parse_error_does_not_touch_counters() {
    let mut stack = tcp_stack();
    assert_eq!(
        stack.process_packet(&[0u8; 13], &mut [0u8; 128]),
        Err(Error::InvalidArgument)
    );
    assert_eq!((stack.tcp_admitted(), stack.tcp_dropped()), (0, 0));
}

#[test]
fn tcp_ipv4_parse_error_does_not_touch_counters() {
    let segment = valid_tcp_segment();
    let (mut frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    frame[ETHER_HEADER_LEN] = 0x44;
    let mut stack = tcp_stack();
    assert_eq!(
        stack.process_packet(&frame[..len], &mut [0u8; 128]),
        Err(Error::InvalidArgument)
    );
    assert_eq!((stack.tcp_admitted(), stack.tcp_dropped()), (0, 0));
}

#[test]
fn tcp_unsupported_protocol_does_not_touch_counters() {
    let segment = valid_tcp_segment();
    let (frame, len) = ip_frame(99, 0, &segment);
    let mut stack = tcp_stack();
    assert_eq!(
        stack.process_packet(&frame[..len], &mut [0u8; 128]),
        Err(Error::NotImplemented)
    );
    assert_eq!((stack.tcp_admitted(), stack.tcp_dropped()), (0, 0));
}

#[test]
fn tcp_valid_then_invalid_update_independent_counters() {
    let valid = valid_tcp_segment();
    let mut corrupt = valid;
    corrupt[4] ^= 1;
    let (valid_frame, valid_len) = ip_frame(PROTO_TCP, 0, &valid);
    let (corrupt_frame, corrupt_len) = ip_frame(PROTO_TCP, 0, &corrupt);
    let mut stack = tcp_stack();
    assert_eq!(
        stack.process_packet(&valid_frame[..valid_len], &mut [0u8; 128]),
        Ok(0)
    );
    assert_eq!(
        stack.process_packet(&corrupt_frame[..corrupt_len], &mut [0u8; 128]),
        Ok(0)
    );
    assert_eq!(stack.tcp_admitted(), 1);
    assert_eq!(stack.tcp_dropped(), 1);
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::net_tcp_test_support::*;
use super::*;

fn assert_silent_drop(frame: &[u8]) {
    let mut reply = [0xA5; 128];
    assert_eq!(tcp_stack().process_packet(frame, &mut reply), Ok(0));
    assert_eq!(reply, [0xA5; 128]);
}

#[test]
fn tcp_direct_valid_segment_is_admitted() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0), &valid_tcp_segment()),
        Ok(())
    );
}

#[test]
fn tcp_direct_short_segment_is_rejected() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0), &[0u8; 19]),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_malformed_option_is_rejected() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0), &malformed_option_segment()),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_corrupt_checksum_is_rejected() {
    let mut segment = valid_tcp_segment();
    segment[4] ^= 1;
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0), &segment),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_wrong_pseudo_header_addresses_are_rejected() {
    let segment = valid_tcp_segment();
    let mut wrong_source = ip_header(0);
    wrong_source.src_addr = [10, 0, 0, 9];
    assert_eq!(
        tcp_stack().handle_tcp_packet(&wrong_source, &segment),
        Err(Error::InvalidArgument)
    );
    let mut wrong_destination = ip_header(0);
    wrong_destination.dst_addr = [10, 0, 0, 9];
    assert_eq!(
        tcp_stack().handle_tcp_packet(&wrong_destination, &segment),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_more_fragments_is_rejected() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0x2000), &valid_tcp_segment()),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_nonzero_fragment_offset_is_rejected() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(1), &valid_tcp_segment()),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn tcp_direct_do_not_fragment_is_admitted() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0x4000), &valid_tcp_segment()),
        Ok(())
    );
}

#[test]
fn tcp_direct_reserved_ipv4_flag_is_admitted() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0x8000), &valid_tcp_segment()),
        Ok(())
    );
}

#[test]
fn tcp_direct_zero_ports_are_structurally_admitted() {
    assert_eq!(
        tcp_stack().handle_tcp_packet(&ip_header(0), &tcp_segment_with_ports(0, 0)),
        Ok(())
    );
}

#[test]
fn tcp_protocol_6_is_distinct_from_unsupported_protocol() {
    let segment = valid_tcp_segment();
    let mut reply = [0xA5; 128];
    let mut stack = tcp_stack();
    let (tcp_frame, tcp_len) = ip_frame(PROTO_TCP, 0, &segment);
    assert_eq!(
        stack.process_packet(&tcp_frame[..tcp_len], &mut reply),
        Ok(0)
    );
    let (unknown_frame, unknown_len) = ip_frame(99, 0, &segment);
    assert_eq!(
        stack.process_packet(&unknown_frame[..unknown_len], &mut reply),
        Err(Error::NotImplemented)
    );
}

#[test]
fn tcp_valid_boundary_segment_preserves_reply_buffer() {
    let segment = valid_tcp_segment();
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    let mut reply = [0xA5; 128];
    assert_eq!(tcp_stack().process_packet(&frame[..len], &mut reply), Ok(0));
    assert_eq!(reply, [0xA5; 128]);
}

#[test]
fn tcp_mss_boundary_segment_preserves_reply_buffer() {
    let segment = mss_tcp_segment();
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    let mut reply = [0xA5; 128];
    assert_eq!(tcp_stack().process_packet(&frame[..len], &mut reply), Ok(0));
    assert_eq!(reply, [0xA5; 128]);
}

#[test]
fn tcp_malformed_boundary_segment_is_silently_dropped() {
    let segment = malformed_option_segment();
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    assert_silent_drop(&frame[..len]);
}

#[test]
fn tcp_corrupt_checksum_boundary_segment_is_silently_dropped() {
    let mut segment = valid_tcp_segment();
    segment[4] ^= 1;
    let (frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    assert_silent_drop(&frame[..len]);
}

#[test]
fn tcp_fragment_boundary_segments_are_silently_dropped() {
    let segment = valid_tcp_segment();
    for flags_frag in [0x2000, 1] {
        let (frame, len) = ip_frame(PROTO_TCP, flags_frag, &segment);
        assert_silent_drop(&frame[..len]);
    }
}

#[test]
fn tcp_boundary_excludes_bytes_after_ipv4_total_len() {
    let segment = valid_tcp_segment();
    let (mut frame, len) = ip_frame(PROTO_TCP, 0, &segment);
    frame[len..len + 4].copy_from_slice(&[0xFF; 4]);
    assert_eq!(
        tcp_stack().process_packet(&frame[..len + 4], &mut [0xA5; 128]),
        Ok(0)
    );
}

#[test]
fn tcp_fragment_gate_does_not_change_gre_fragment_admission() {
    let segment = valid_tcp_segment();
    let mut stack = tcp_stack();
    let mut reply = [0xA5; 128];
    let (tcp_frame, tcp_len) = ip_frame(PROTO_TCP, 0x2000, &segment);
    assert_eq!(
        stack.process_packet(&tcp_frame[..tcp_len], &mut reply),
        Ok(0)
    );
    let (gre_frame, gre_len) = ip_frame(PROTO_GRE, 0x2000, &[0, 0, 8, 0]);
    assert_eq!(
        stack.process_packet(&gre_frame[..gre_len], &mut reply),
        Ok(0)
    );
    assert_eq!(stack.gre_admitted(), 1);
    assert_eq!(stack.gre_dropped(), 0);
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

const LOCAL_MAC: [u8; 6] = [0xAA; 6];
const SOURCE_MAC: [u8; 6] = [0xBB; 6];
const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
const SOURCE_IP: [u8; 4] = [10, 0, 0, 1];
const SCTP_INIT_PACKET: [u8; 32] = [
    0x13, 0x88, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x12, 0xF6, 0xF6, 0xE9, 0x01, 0x00, 0x00, 0x14,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x71, 0x5B, 0x5A, 0x94,
];

fn sctp_stack() -> NetworkStack {
    NetworkStack::new(LOCAL_MAC, LOCAL_IP, SOURCE_IP, [255, 255, 255, 0])
}

fn ip_header(flags_frag: u16, protocol: u8) -> Ipv4Header {
    Ipv4Header {
        version_ihl: 0x45,
        tos: 0,
        total_len: (IPV4_HEADER_MIN_LEN + SCTP_INIT_PACKET.len()) as u16,
        id: 0,
        flags_frag,
        ttl: 64,
        protocol,
        checksum: 0,
        src_addr: SOURCE_IP,
        dst_addr: LOCAL_IP,
    }
}

fn ip_frame(protocol: u8, flags_frag: u16, payload: &[u8]) -> ([u8; 128], usize) {
    let mut frame = [0u8; 128];
    assert_eq!(
        write_ether(&mut frame, &LOCAL_MAC, &SOURCE_MAC, ETHER_TYPE_IPV4),
        Ok(ETHER_HEADER_LEN)
    );
    let mut ip = ip_header(flags_frag, protocol);
    ip.total_len = (IPV4_HEADER_MIN_LEN + payload.len()) as u16;
    assert_eq!(
        write_ipv4(&mut frame[ETHER_HEADER_LEN..], &ip),
        Ok(IPV4_HEADER_MIN_LEN)
    );
    let payload_offset = ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN;
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    (frame, payload_offset + payload.len())
}

#[test]
fn sctp_direct_valid_packet_is_admitted() {
    let stack = sctp_stack();
    assert_eq!(
        stack.handle_sctp_packet(&ip_header(0, PROTO_SCTP), &SCTP_INIT_PACKET),
        Ok(())
    );
}

#[test]
fn sctp_direct_corrupt_packet_is_rejected() {
    let stack = sctp_stack();
    let mut packet = SCTP_INIT_PACKET;
    packet[8] ^= 1;
    assert_eq!(
        stack.handle_sctp_packet(&ip_header(0, PROTO_SCTP), &packet),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn sctp_direct_more_fragments_and_offset_are_rejected() {
    let stack = sctp_stack();
    assert_eq!(
        stack.handle_sctp_packet(&ip_header(0x2000, PROTO_SCTP), &SCTP_INIT_PACKET),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        stack.handle_sctp_packet(&ip_header(1, PROTO_SCTP), &SCTP_INIT_PACKET),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn sctp_direct_do_not_fragment_is_admitted() {
    let stack = sctp_stack();
    assert_eq!(
        stack.handle_sctp_packet(&ip_header(0x4000, PROTO_SCTP), &SCTP_INIT_PACKET),
        Ok(())
    );
}

#[test]
fn sctp_protocol_132_is_distinct_from_unsupported_protocol() {
    let mut stack = sctp_stack();
    let mut reply = [0u8; 128];
    let (sctp_frame, sctp_len) = ip_frame(PROTO_SCTP, 0, &SCTP_INIT_PACKET);
    assert_eq!(
        stack.process_packet(&sctp_frame[..sctp_len], &mut reply),
        Ok(0)
    );
    let (unknown_frame, unknown_len) = ip_frame(99, 0, &SCTP_INIT_PACKET);
    assert_eq!(
        stack.process_packet(&unknown_frame[..unknown_len], &mut reply),
        Err(Error::NotImplemented)
    );
}

#[test]
fn sctp_corrupt_boundary_packet_is_silently_dropped() {
    let mut stack = sctp_stack();
    let mut packet = SCTP_INIT_PACKET;
    packet[8] ^= 1;
    let (frame, len) = ip_frame(PROTO_SCTP, 0, &packet);
    let mut reply = [0u8; 128];
    assert_eq!(stack.process_packet(&frame[..len], &mut reply), Ok(0));
}

#[test]
fn sctp_valid_boundary_packet_increments_admitted_only() {
    let mut stack = sctp_stack();
    let (frame, len) = ip_frame(PROTO_SCTP, 0, &SCTP_INIT_PACKET);
    let mut reply = [0u8; 128];
    assert_eq!(stack.process_packet(&frame[..len], &mut reply), Ok(0));
    assert_eq!(stack.sctp_admitted(), 1);
    assert_eq!(stack.sctp_dropped(), 0);
}

#[test]
fn sctp_corrupt_boundary_packet_increments_dropped_only() {
    let mut stack = sctp_stack();
    let mut packet = SCTP_INIT_PACKET;
    packet[8] ^= 1;
    let (frame, len) = ip_frame(PROTO_SCTP, 0, &packet);
    let mut reply = [0u8; 128];
    assert_eq!(stack.process_packet(&frame[..len], &mut reply), Ok(0));
    assert_eq!(stack.sctp_admitted(), 0);
    assert_eq!(stack.sctp_dropped(), 1);
}

#[test]
fn sctp_fragment_boundary_packet_increments_dropped_only() {
    let mut stack = sctp_stack();
    let (frame, len) = ip_frame(PROTO_SCTP, 0x2000, &SCTP_INIT_PACKET);
    let mut reply = [0u8; 128];
    assert_eq!(stack.process_packet(&frame[..len], &mut reply), Ok(0));
    assert_eq!(stack.sctp_admitted(), 0);
    assert_eq!(stack.sctp_dropped(), 1);
}

#[test]
fn sctp_fragment_gate_does_not_change_gre_fragment_admission() {
    let mut stack = sctp_stack();
    let mut reply = [0u8; 128];
    let (sctp_frame, sctp_len) = ip_frame(PROTO_SCTP, 0x2000, &SCTP_INIT_PACKET);
    assert_eq!(
        stack.process_packet(&sctp_frame[..sctp_len], &mut reply),
        Ok(0)
    );

    let gre_packet = [0x00, 0x00, 0x08, 0x00];
    let (gre_frame, gre_len) = ip_frame(PROTO_GRE, 0x2000, &gre_packet);
    assert_eq!(
        stack.process_packet(&gre_frame[..gre_len], &mut reply),
        Ok(0)
    );
    assert_eq!(stack.sctp_dropped(), 1);
    assert_eq!(stack.gre_admitted(), 1);
    assert_eq!(stack.gre_dropped(), 0);
}

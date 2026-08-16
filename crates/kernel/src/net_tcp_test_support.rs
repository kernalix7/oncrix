// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) const LOCAL_MAC: [u8; 6] = [0xAA; 6];
pub(super) const SOURCE_MAC: [u8; 6] = [0xBB; 6];
pub(super) const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
pub(super) const SOURCE_IP: [u8; 4] = [10, 0, 0, 1];

pub(super) fn tcp_stack() -> NetworkStack {
    NetworkStack::new(LOCAL_MAC, LOCAL_IP, SOURCE_IP, [255, 255, 255, 0])
}

pub(super) fn ip_header(flags_frag: u16) -> Ipv4Header {
    Ipv4Header {
        version_ihl: 0x45,
        tos: 0,
        total_len: 40,
        id: 0x1234,
        flags_frag,
        ttl: 64,
        protocol: PROTO_TCP,
        checksum: 0,
        src_addr: SOURCE_IP,
        dst_addr: LOCAL_IP,
    }
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [byte] = words.remainder() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

pub(super) fn set_tcp_checksum(segment: &mut [u8], source: [u8; 4], destination: [u8; 4]) {
    segment[16] = 0;
    segment[17] = 0;
    let mut sum = add_words(0, &source);
    sum = add_words(sum, &destination);
    sum += u32::from(PROTO_TCP) + segment.len() as u32;
    let checksum = finish_checksum(add_words(sum, segment)).to_be_bytes();
    segment[16..18].copy_from_slice(&checksum);
}

pub(super) fn tcp_segment_with_ports(source_port: u16, destination_port: u16) -> [u8; 20] {
    let mut segment = [0u8; 20];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&0x1020_3040u32.to_be_bytes());
    segment[12] = 0x50;
    segment[13] = 0x02;
    segment[14..16].copy_from_slice(&4096u16.to_be_bytes());
    set_tcp_checksum(&mut segment, SOURCE_IP, LOCAL_IP);
    segment
}

pub(super) fn valid_tcp_segment() -> [u8; 20] {
    tcp_segment_with_ports(5000, 80)
}

pub(super) fn mss_tcp_segment() -> [u8; 24] {
    let mut segment = [0u8; 24];
    segment[..20].copy_from_slice(&valid_tcp_segment());
    segment[12] = 0x60;
    segment[20..24].copy_from_slice(&[2, 4, 0x05, 0xB4]);
    set_tcp_checksum(&mut segment, SOURCE_IP, LOCAL_IP);
    segment
}

pub(super) fn malformed_option_segment() -> [u8; 24] {
    let mut segment = mss_tcp_segment();
    segment[21] = 3;
    set_tcp_checksum(&mut segment, SOURCE_IP, LOCAL_IP);
    segment
}

pub(super) fn ip_frame(protocol: u8, flags_frag: u16, payload: &[u8]) -> ([u8; 128], usize) {
    let mut frame = [0u8; 128];
    assert_eq!(
        write_ether(&mut frame, &LOCAL_MAC, &SOURCE_MAC, ETHER_TYPE_IPV4),
        Ok(ETHER_HEADER_LEN)
    );
    let mut ip = ip_header(flags_frag);
    ip.protocol = protocol;
    ip.total_len = (IPV4_HEADER_MIN_LEN + payload.len()) as u16;
    assert_eq!(
        write_ipv4(&mut frame[ETHER_HEADER_LEN..], &ip),
        Ok(IPV4_HEADER_MIN_LEN)
    );
    let payload_offset = ETHER_HEADER_LEN + IPV4_HEADER_MIN_LEN;
    frame[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    (frame, payload_offset + payload.len())
}

pub(super) fn retarget_ipv4(frame: &mut [u8; 128], destination: [u8; 4]) {
    let ip_offset = ETHER_HEADER_LEN;
    frame[ip_offset + 16..ip_offset + 20].copy_from_slice(&destination);
    frame[ip_offset + 10] = 0;
    frame[ip_offset + 11] = 0;
    let checksum = finish_checksum(add_words(
        0,
        &frame[ip_offset..ip_offset + IPV4_HEADER_MIN_LEN],
    ))
    .to_be_bytes();
    frame[ip_offset + 10..ip_offset + 12].copy_from_slice(&checksum);
}

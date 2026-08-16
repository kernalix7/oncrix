// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Checked RFC 9260 TLV walking and INIT-family parameter policy.

use oncrix_lib::{Error, Result};

const TLV_HEADER_LEN: usize = 4;
const INIT_FIXED_LEN: usize = 20;
const IPV4_ADDRESS: u16 = 5;
const IPV6_ADDRESS: u16 = 6;
const STATE_COOKIE: u16 = 7;
const UNRECOGNIZED_PARAMETER: u16 = 8;
const COOKIE_PRESERVATIVE: u16 = 9;
const HOST_NAME_ADDRESS: u16 = 11;
const SUPPORTED_ADDRESS_TYPES: u16 = 12;
const ECN_CAPABLE: u16 = 0x8000;
const SEEN_COOKIE: u8 = 1 << 0;
const SEEN_COOKIE_PRESERVATIVE: u8 = 1 << 1;
const SEEN_SUPPORTED_ADDRESS_TYPES: u8 = 1 << 2;
const SEEN_ECN: u8 = 1 << 3;

pub(super) enum WalkControl {
    Continue,
    Stop,
}

const fn pad4(len: usize) -> Option<usize> {
    match len.checked_add(3) {
        Some(rounded) => Some(rounded & !3),
        None => None,
    }
}

fn tlv_header(input: &[u8]) -> Result<(u16, usize)> {
    if input.len() < TLV_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    let parameter_type = u16::from_be_bytes([input[0], input[1]]);
    let len = usize::from(u16::from_be_bytes([input[2], input[3]]));
    if len < TLV_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok((parameter_type, len))
}

pub(super) fn walk_tlvs<F>(body: &[u8], mut validate_tlv: F) -> Result<usize>
where
    F: FnMut(u16, &[u8]) -> Result<WalkControl>,
{
    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < body.len() {
        let (parameter_type, tlv_len) = tlv_header(&body[offset..])?;
        let end = offset.checked_add(tlv_len).ok_or(Error::InvalidArgument)?;
        if end > body.len() {
            return Err(Error::InvalidArgument);
        }
        count = count.checked_add(1).ok_or(Error::InvalidArgument)?;
        if matches!(
            validate_tlv(parameter_type, &body[offset..end])?,
            WalkControl::Stop
        ) {
            return Ok(count);
        }
        if end == body.len() {
            break;
        }
        let padded_len = pad4(tlv_len).ok_or(Error::InvalidArgument)?;
        offset = offset
            .checked_add(padded_len)
            .ok_or(Error::InvalidArgument)?;
        if offset > body.len() {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(count)
}

fn mark_once(seen: &mut u8, bit: u8) -> Result<WalkControl> {
    if *seen & bit != 0 {
        return Err(Error::InvalidArgument);
    }
    *seen |= bit;
    Ok(WalkControl::Continue)
}

const fn unknown_control(parameter_type: u16) -> WalkControl {
    if parameter_type & 0x8000 == 0 {
        WalkControl::Stop
    } else {
        WalkControl::Continue
    }
}

fn validate_init_parameter(parameter_type: u16, tlv: &[u8], seen: &mut u8) -> Result<WalkControl> {
    let len = tlv.len();
    match parameter_type {
        IPV4_ADDRESS if len == 8 => Ok(WalkControl::Continue),
        IPV6_ADDRESS if len == 20 => Ok(WalkControl::Continue),
        COOKIE_PRESERVATIVE if len == 8 => mark_once(seen, SEEN_COOKIE_PRESERVATIVE),
        SUPPORTED_ADDRESS_TYPES if len >= 6 && len & 1 == 0 => {
            mark_once(seen, SEEN_SUPPORTED_ADDRESS_TYPES)
        }
        ECN_CAPABLE if len == 4 => mark_once(seen, SEEN_ECN),
        IPV4_ADDRESS
        | IPV6_ADDRESS
        | COOKIE_PRESERVATIVE
        | SUPPORTED_ADDRESS_TYPES
        | ECN_CAPABLE
        | HOST_NAME_ADDRESS
        | STATE_COOKIE
        | UNRECOGNIZED_PARAMETER => Err(Error::InvalidArgument),
        _ => Ok(unknown_control(parameter_type)),
    }
}

fn validate_single_nested_parameter(tlv: &[u8]) -> Result<WalkControl> {
    if tlv.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    let value = &tlv[TLV_HEADER_LEN..];
    let (_, nested_len) = tlv_header(value)?;
    if nested_len != value.len() {
        return Err(Error::InvalidArgument);
    }
    let count = walk_tlvs(value, |_, _| Ok(WalkControl::Continue))?;
    if count != 1 {
        return Err(Error::InvalidArgument);
    }
    Ok(WalkControl::Continue)
}

fn validate_init_ack_parameter(
    parameter_type: u16,
    tlv: &[u8],
    seen: &mut u8,
) -> Result<WalkControl> {
    let len = tlv.len();
    match parameter_type {
        STATE_COOKIE if len >= 5 => mark_once(seen, SEEN_COOKIE),
        IPV4_ADDRESS if len == 8 => Ok(WalkControl::Continue),
        IPV6_ADDRESS if len == 20 => Ok(WalkControl::Continue),
        UNRECOGNIZED_PARAMETER => validate_single_nested_parameter(tlv),
        ECN_CAPABLE if len == 4 => mark_once(seen, SEEN_ECN),
        STATE_COOKIE
        | IPV4_ADDRESS
        | IPV6_ADDRESS
        | ECN_CAPABLE
        | HOST_NAME_ADDRESS
        | COOKIE_PRESERVATIVE
        | SUPPORTED_ADDRESS_TYPES => Err(Error::InvalidArgument),
        _ => Ok(unknown_control(parameter_type)),
    }
}

pub(super) fn validate_init_parameters(chunk: &[u8]) -> Result<()> {
    let mut seen = 0u8;
    walk_tlvs(&chunk[INIT_FIXED_LEN..], |parameter_type, tlv| {
        validate_init_parameter(parameter_type, tlv, &mut seen)
    })?;
    Ok(())
}

pub(super) fn validate_init_ack_parameters(chunk: &[u8]) -> Result<()> {
    let mut seen = 0u8;
    walk_tlvs(&chunk[INIT_FIXED_LEN..], |parameter_type, tlv| {
        validate_init_ack_parameter(parameter_type, tlv, &mut seen)
    })?;
    if seen & SEEN_COOKIE == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

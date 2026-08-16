// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Allocation-free RFC 9260 known-chunk shape validation.

use crate::sctp::SctpChunkType;
use oncrix_lib::{Error, Result};

use super::params::{
    WalkControl, validate_init_ack_parameters, validate_init_parameters, walk_tlvs,
};

const CHUNK_HEADER_LEN: usize = 4;
const INIT_FIXED_LEN: usize = 20;
const HEARTBEAT_INFO: u16 = 1;

fn validate_init_fields(chunk: &[u8]) -> Result<()> {
    let initiate_tag = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
    let outbound_streams = u16::from_be_bytes([chunk[12], chunk[13]]);
    let inbound_streams = u16::from_be_bytes([chunk[14], chunk[15]]);
    if initiate_tag == 0 || outbound_streams == 0 || inbound_streams == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn validate_sack(chunk: &[u8]) -> Result<()> {
    if chunk.len() < 16 {
        return Err(Error::InvalidArgument);
    }
    let gap_count = usize::from(u16::from_be_bytes([chunk[12], chunk[13]]));
    let duplicate_count = usize::from(u16::from_be_bytes([chunk[14], chunk[15]]));
    let variable_count = gap_count
        .checked_add(duplicate_count)
        .ok_or(Error::InvalidArgument)?;
    let variable_len = variable_count
        .checked_mul(4)
        .ok_or(Error::InvalidArgument)?;
    let expected_len = 16usize
        .checked_add(variable_len)
        .ok_or(Error::InvalidArgument)?;
    if chunk.len() != expected_len {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn validate_heartbeat(chunk: &[u8]) -> Result<()> {
    if chunk.len() < 8 {
        return Err(Error::InvalidArgument);
    }
    let count = walk_tlvs(&chunk[CHUNK_HEADER_LEN..], |parameter_type, _| {
        if parameter_type != HEARTBEAT_INFO {
            return Err(Error::InvalidArgument);
        }
        Ok(WalkControl::Continue)
    })?;
    if count != 1 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

pub(super) fn validate(
    chunk_type: SctpChunkType,
    chunk: &[u8],
    verification_tag: u32,
) -> Result<()> {
    match chunk_type {
        SctpChunkType::Data if chunk.len() >= 17 => Ok(()),
        SctpChunkType::Data => Err(Error::InvalidArgument),
        SctpChunkType::Init if chunk.len() >= INIT_FIXED_LEN && verification_tag == 0 => {
            validate_init_fields(chunk)?;
            let advertised_receiver_window =
                u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
            if advertised_receiver_window < 1500 {
                return Err(Error::InvalidArgument);
            }
            validate_init_parameters(chunk)?;
            Ok(())
        }
        SctpChunkType::Init => Err(Error::InvalidArgument),
        SctpChunkType::InitAck if chunk.len() >= 24 && verification_tag != 0 => {
            validate_init_fields(chunk)?;
            let advertised_receiver_window =
                u32::from_be_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
            if advertised_receiver_window < 1500 {
                return Err(Error::InvalidArgument);
            }
            validate_init_ack_parameters(chunk)?;
            Ok(())
        }
        SctpChunkType::InitAck => Err(Error::InvalidArgument),
        SctpChunkType::Sack => validate_sack(chunk),
        SctpChunkType::Heartbeat | SctpChunkType::HeartbeatAck => validate_heartbeat(chunk),
        SctpChunkType::Abort => {
            walk_tlvs(&chunk[CHUNK_HEADER_LEN..], |_, _| Ok(WalkControl::Continue))?;
            Ok(())
        }
        SctpChunkType::Error => {
            let count = walk_tlvs(&chunk[CHUNK_HEADER_LEN..], |_, _| Ok(WalkControl::Continue))?;
            if count == 0 {
                return Err(Error::InvalidArgument);
            }
            Ok(())
        }
        SctpChunkType::Shutdown if chunk.len() == 8 => Ok(()),
        SctpChunkType::Shutdown => Err(Error::InvalidArgument),
        SctpChunkType::ShutdownAck if chunk.len() == 4 => Ok(()),
        SctpChunkType::ShutdownAck => Err(Error::InvalidArgument),
        SctpChunkType::CookieEcho if chunk.len() >= 5 => Ok(()),
        SctpChunkType::CookieEcho => Err(Error::InvalidArgument),
        SctpChunkType::CookieAck if chunk.len() == 4 => Ok(()),
        SctpChunkType::CookieAck => Err(Error::InvalidArgument),
        SctpChunkType::ShutdownComplete if chunk.len() == 4 => Ok(()),
        SctpChunkType::ShutdownComplete => Err(Error::InvalidArgument),
    }
}

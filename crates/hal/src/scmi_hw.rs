// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SCMI (System Control and Management Interface) hardware abstraction.
//!
//! SCMI (ARM SCMI specification DEN0056) defines a protocol for the AP to
//! communicate with a platform firmware agent (SCP, ATF BL31, etc.) to
//! request power, performance, clocks, sensors, and reset management.
//!
//! This module implements the transport layer over a shared-memory doorbell,
//! plus helpers for the most common SCMI protocols.

use oncrix_lib::{Error, Result};

/// SCMI shared memory layout size (one page typical).
pub const SCMI_SHMEM_SIZE: usize = 4096;
/// Maximum SCMI message payload in bytes.
pub const SCMI_MAX_PAYLOAD: usize = 128;

/// SCMI protocol IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ScmiProtocol {
    /// Base protocol.
    Base = 0x10,
    /// Power domain management.
    Power = 0x11,
    /// System power management.
    System = 0x12,
    /// Performance domain management.
    Perf = 0x13,
    /// Clock management.
    Clock = 0x14,
    /// Sensor management.
    Sensor = 0x15,
    /// Reset domain management.
    Reset = 0x16,
    /// Voltage domain management.
    Voltage = 0x17,
}

/// SCMI message header (packed into a 32-bit word).
#[derive(Debug, Clone, Copy, Default)]
pub struct ScmiHeader {
    /// Protocol ID.
    pub protocol_id: u8,
    /// Message type (0 = command, 1 = delayed response, 2 = notification).
    pub msg_type: u8,
    /// Message ID within the protocol.
    pub message_id: u8,
    /// Sequence token for matching responses.
    pub token: u8,
}

impl ScmiHeader {
    /// Encodes the header as a 32-bit word.
    pub fn encode(self) -> u32 {
        ((self.token as u32) << 18)
            | ((self.protocol_id as u32) << 10)
            | ((self.msg_type as u32) << 8)
            | (self.message_id as u32)
    }

    /// Decodes a 32-bit word into a header.
    pub fn decode(word: u32) -> Self {
        Self {
            token: ((word >> 18) & 0x3FF) as u8,
            protocol_id: ((word >> 10) & 0xFF) as u8,
            msg_type: ((word >> 8) & 0x3) as u8,
            message_id: (word & 0xFF) as u8,
        }
    }
}

/// SCMI shared memory channel header (ARM SCMI spec layout).
#[repr(C)]
struct ScmiShmem {
    /// Reserved/flags word.
    reserved: u32,
    /// Channel status flags.
    channel_status: u32,
    /// Reserved for implementation.
    _impl_reserved: [u32; 2],
    /// Message flags.
    flags: u32,
    /// Length of message + header in bytes.
    length: u32,
    /// Message header (encoded).
    msg_header: u32,
    /// Message payload (variable length).
    msg_payload: [u8; SCMI_MAX_PAYLOAD],
}

// SCMI channel_status bits.
const SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR: u32 = 1 << 1;
const SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE: u32 = 1 << 0;

/// SCMI transport over a shared-memory doorbell.
pub struct ScmiTransport {
    /// Physical address of the shared memory channel.
    shmem_paddr: u64,
    /// Doorbell register address (write to ring).
    doorbell_paddr: u64,
    /// Next sequence token.
    next_token: u8,
}

impl ScmiTransport {
    /// Creates a new SCMI transport.
    ///
    /// # Arguments
    ///
    /// * `shmem_paddr` — Physical address of the shared memory channel (must be mapped).
    /// * `doorbell_paddr` — Physical address of the doorbell register.
    pub const fn new(shmem_paddr: u64, doorbell_paddr: u64) -> Self {
        Self {
            shmem_paddr,
            next_token: 0,
            doorbell_paddr,
        }
    }

    /// Waits for the channel to become free (busy-polls, limited iterations).
    pub fn wait_free(&self) -> Result<()> {
        let shmem = self.shmem_ptr();
        for _ in 0..10_000u32 {
            // SAFETY: shmem_paddr is a valid mapped shared-memory page.
            let status = unsafe { core::ptr::read_volatile(&(*shmem).channel_status) };
            if (status & SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR) != 0 {
                return Err(Error::IoError);
            }
            if (status & SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Sends an SCMI command and waits for the response.
    ///
    /// # Arguments
    ///
    /// * `protocol` — SCMI protocol ID.
    /// * `message_id` — Message ID within the protocol.
    /// * `payload` — Command payload bytes.
    /// * `response` — Buffer for response payload.
    pub fn command(
        &mut self,
        protocol: ScmiProtocol,
        message_id: u8,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<()> {
        if payload.len() > SCMI_MAX_PAYLOAD || response.len() > SCMI_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        self.wait_free()?;
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        let hdr = ScmiHeader {
            protocol_id: protocol as u8,
            msg_type: 0,
            message_id,
            token,
        };
        let shmem = self.shmem_ptr_mut();
        // SAFETY: shmem_paddr is a valid mapped shared-memory channel page.
        unsafe {
            core::ptr::write_volatile(&mut (*shmem).msg_header, hdr.encode());
            core::ptr::write_volatile(&mut (*shmem).length, (payload.len() + 4) as u32);
            core::ptr::write_volatile(&mut (*shmem).flags, 0);
            for (i, &b) in payload.iter().enumerate() {
                core::ptr::write_volatile(&mut (*shmem).msg_payload[i], b);
            }
            // Clear channel-free bit to mark channel busy.
            core::ptr::write_volatile(&mut (*shmem).channel_status, 0);
        }
        // Ring doorbell.
        self.ring_doorbell();
        // Wait for response.
        self.wait_free()?;
        // Copy response payload.
        // SAFETY: same shared-memory guarantee.
        let resp_len = unsafe {
            let raw_len = core::ptr::read_volatile(&(*shmem).length) as usize;
            raw_len.saturating_sub(4).min(response.len())
        };
        for i in 0..resp_len {
            // SAFETY: shared-memory is valid.
            response[i] = unsafe { core::ptr::read_volatile(&(*shmem).msg_payload[i]) };
        }
        Ok(())
    }

    /// Returns the number of registered clock domains (SCMI Clock protocol).
    pub fn clock_num_domains(&mut self) -> Result<u32> {
        let mut resp = [0u8; 8];
        self.command(ScmiProtocol::Clock, 0x00, &[], &mut resp)?;
        // Response word 0 is status, word 1 is num_clocks.
        Ok(u32::from_le_bytes([resp[4], resp[5], resp[6], resp[7]]))
    }

    /// Enables or disables a clock domain.
    pub fn clock_enable(&mut self, domain: u32, enable: bool) -> Result<()> {
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&domain.to_le_bytes());
        payload[4..8].copy_from_slice(&(enable as u32).to_le_bytes());
        let mut resp = [0u8; 4];
        self.command(ScmiProtocol::Clock, 0x07, &payload, &mut resp)
    }

    /// Sets a performance level for a performance domain.
    pub fn perf_set_level(&mut self, domain: u32, level: u32) -> Result<()> {
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&domain.to_le_bytes());
        payload[4..8].copy_from_slice(&level.to_le_bytes());
        let mut resp = [0u8; 4];
        self.command(ScmiProtocol::Perf, 0x07, &payload, &mut resp)
    }

    // ---- private helpers ----

    fn shmem_ptr(&self) -> *const ScmiShmem {
        self.shmem_paddr as *const ScmiShmem
    }

    fn shmem_ptr_mut(&self) -> *mut ScmiShmem {
        self.shmem_paddr as *mut ScmiShmem
    }

    fn ring_doorbell(&self) {
        let ptr = self.doorbell_paddr as *mut u32;
        // SAFETY: doorbell_paddr is a valid mapped MMIO register.
        unsafe { core::ptr::write_volatile(ptr, 1) };
    }
}

impl Default for ScmiTransport {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Returns the protocol name string for logging.
pub fn protocol_name(proto: ScmiProtocol) -> &'static str {
    match proto {
        ScmiProtocol::Base => "base",
        ScmiProtocol::Power => "power",
        ScmiProtocol::System => "system",
        ScmiProtocol::Perf => "perf",
        ScmiProtocol::Clock => "clock",
        ScmiProtocol::Sensor => "sensor",
        ScmiProtocol::Reset => "reset",
        ScmiProtocol::Voltage => "voltage",
    }
}

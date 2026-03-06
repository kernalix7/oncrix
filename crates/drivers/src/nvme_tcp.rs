// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe over TCP (NVMe-oF TCP) transport initiator.
//!
//! Implements the NVMe over Fabrics TCP transport as specified in
//! NVMe/TCP Transport Binding Specification 1.0. Provides capsule
//! command/response handling, queue pair management, and PDU framing
//! for connecting to remote NVMe-oF targets over a TCP/IP network.
//!
//! # Architecture
//!
//! - [`NvmeTcpPdu`] — Protocol Data Unit (header + optional data)
//! - [`NvmeTcpCapsuleCmd`] — Capsule command sent to the target
//! - [`NvmeTcpCapsuleResp`] — Capsule response from the target
//! - [`NvmeTcpQueuePair`] — Submission/completion queue over TCP
//! - [`NvmeTcpConnection`] — TCP connection to a remote controller
//! - [`NvmeTcpController`] — NVMe-oF TCP controller abstraction
//!
//! Reference: NVMe/TCP Transport Binding Specification 1.0.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum PDU data size.
const MAX_PDU_DATA_SIZE: usize = 4096;

/// Maximum number of queue pairs per controller.
const MAX_QUEUE_PAIRS: usize = 8;

/// Maximum number of outstanding commands per queue.
const MAX_QUEUE_DEPTH: usize = 64;

/// Maximum number of TCP controllers.
const MAX_CONTROLLERS: usize = 4;

/// Maximum NQN (NVMe Qualified Name) length.
const MAX_NQN_LEN: usize = 223;

/// Default NVMe-oF TCP port.
const NVME_TCP_DEFAULT_PORT: u16 = 4420;

/// NVMe-oF TCP header digest size (CRC-32C).
const HEADER_DIGEST_SIZE: usize = 4;

/// NVMe-oF TCP data digest size (CRC-32C).
const DATA_DIGEST_SIZE: usize = 4;

/// NVMe command capsule size (SQE = 64 bytes).
const NVME_CMD_SIZE: usize = 64;

/// NVMe completion entry size (CQE = 16 bytes).
const NVME_CQE_SIZE: usize = 16;

// -------------------------------------------------------------------
// PduType
// -------------------------------------------------------------------

/// NVMe/TCP PDU types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PduType {
    /// ICReq — Initialize Connection Request.
    #[default]
    IcReq,
    /// ICResp — Initialize Connection Response.
    IcResp,
    /// H2CTermReq — Host to Controller Termination Request.
    H2CTermReq,
    /// C2HTermReq — Controller to Host Termination Request.
    C2HTermReq,
    /// CapsuleCmd — Command capsule (host to controller).
    CapsuleCmd,
    /// CapsuleResp — Response capsule (controller to host).
    CapsuleResp,
    /// H2CData — Host to Controller data transfer.
    H2CData,
    /// C2HData — Controller to Host data transfer.
    C2HData,
    /// R2T — Ready to Transfer (controller requests data).
    R2T,
}

impl PduType {
    /// Returns the wire PDU type byte.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::IcReq => 0x00,
            Self::IcResp => 0x01,
            Self::H2CTermReq => 0x02,
            Self::C2HTermReq => 0x03,
            Self::CapsuleCmd => 0x04,
            Self::CapsuleResp => 0x05,
            Self::H2CData => 0x06,
            Self::C2HData => 0x07,
            Self::R2T => 0x09,
        }
    }

    /// Parses a PDU type from a wire byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(Self::IcReq),
            0x01 => Ok(Self::IcResp),
            0x02 => Ok(Self::H2CTermReq),
            0x03 => Ok(Self::C2HTermReq),
            0x04 => Ok(Self::CapsuleCmd),
            0x05 => Ok(Self::CapsuleResp),
            0x06 => Ok(Self::H2CData),
            0x07 => Ok(Self::C2HData),
            0x09 => Ok(Self::R2T),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// PduFlags
// -------------------------------------------------------------------

/// NVMe/TCP PDU header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduFlags(u8);

impl PduFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Header digest present.
    pub const HDGST: Self = Self(1 << 0);
    /// Data digest present.
    pub const DDGST: Self = Self(1 << 1);
    /// Data present (for CapsuleCmd).
    pub const DATA_PRESENT: Self = Self(1 << 2);
    /// Last PDU in a sequence.
    pub const LAST_PDU: Self = Self(1 << 3);

    /// Returns the raw flag bits.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Returns `true` if header digest is enabled.
    pub fn has_hdgst(self) -> bool {
        self.0 & Self::HDGST.0 != 0
    }

    /// Returns `true` if data digest is enabled.
    pub fn has_ddgst(self) -> bool {
        self.0 & Self::DDGST.0 != 0
    }

    /// Creates flags from raw bits.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

impl Default for PduFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// -------------------------------------------------------------------
// NvmeTcpPduHeader
// -------------------------------------------------------------------

/// Common header for all NVMe/TCP PDUs (8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeTcpPduHeader {
    /// PDU type.
    pub pdu_type: u8,
    /// Flags.
    pub flags: u8,
    /// Header length (including the common header).
    pub hlen: u8,
    /// PDU data offset (where inline data starts).
    pub pdo: u8,
    /// Total PDU length including header and all data.
    pub plen: u32,
}

impl NvmeTcpPduHeader {
    /// Creates a new PDU header.
    pub fn new(pdu_type: PduType, flags: PduFlags, hlen: u8, plen: u32) -> Self {
        Self {
            pdu_type: pdu_type.to_byte(),
            flags: flags.bits(),
            hlen,
            pdo: hlen, // data starts right after header
            plen,
        }
    }

    /// Returns the parsed PDU type.
    pub fn get_type(&self) -> Result<PduType> {
        PduType::from_byte(self.pdu_type)
    }

    /// Returns the parsed flags.
    pub fn get_flags(&self) -> PduFlags {
        PduFlags::from_bits(self.flags)
    }

    /// Returns the data portion length.
    pub fn data_len(&self) -> usize {
        if self.plen as usize > self.hlen as usize {
            self.plen as usize - self.hlen as usize
        } else {
            0
        }
    }
}

// -------------------------------------------------------------------
// IcReqPdu / IcRespPdu
// -------------------------------------------------------------------

/// ICReq (Initialize Connection Request) PDU.
///
/// Sent by the host to establish a TCP connection to the controller.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IcReqPdu {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// PDU format version (currently 0).
    pub pfv: u16,
    /// Host PDU data alignment (in 4-byte units, 0 = no alignment).
    pub hpda: u8,
    /// Digest types supported/requested (bit 0 = HDGST, bit 1 = DDGST).
    pub dgst: u8,
    /// Maximum host-to-controller data length.
    pub maxr2t: u32,
    /// Reserved bytes.
    pub _reserved: [u8; 112],
}

impl Default for IcReqPdu {
    fn default() -> Self {
        Self {
            header: NvmeTcpPduHeader::default(),
            pfv: 0,
            hpda: 0,
            dgst: 0,
            maxr2t: 0,
            _reserved: [0u8; 112],
        }
    }
}

impl IcReqPdu {
    /// Creates an ICReq PDU with default settings.
    pub fn new(hdgst: bool, ddgst: bool) -> Self {
        let mut dgst = 0u8;
        if hdgst {
            dgst |= 1;
        }
        if ddgst {
            dgst |= 2;
        }
        Self {
            header: NvmeTcpPduHeader::new(PduType::IcReq, PduFlags::NONE, 128, 128),
            pfv: 0,
            hpda: 0,
            dgst,
            maxr2t: MAX_QUEUE_DEPTH as u32,
            _reserved: [0u8; 112],
        }
    }
}

/// ICResp (Initialize Connection Response) PDU.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IcRespPdu {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// PDU format version.
    pub pfv: u16,
    /// Controller PDU data alignment.
    pub cpda: u8,
    /// Negotiated digest types.
    pub dgst: u8,
    /// Maximum data capsule size.
    pub maxdata: u32,
    /// Reserved bytes.
    pub _reserved: [u8; 112],
}

impl Default for IcRespPdu {
    fn default() -> Self {
        Self {
            header: NvmeTcpPduHeader::default(),
            pfv: 0,
            cpda: 0,
            dgst: 0,
            maxdata: 0,
            _reserved: [0u8; 112],
        }
    }
}

impl IcRespPdu {
    /// Returns `true` if header digest was negotiated.
    pub fn hdgst_enabled(&self) -> bool {
        self.dgst & 1 != 0
    }

    /// Returns `true` if data digest was negotiated.
    pub fn ddgst_enabled(&self) -> bool {
        self.dgst & 2 != 0
    }
}

// -------------------------------------------------------------------
// NvmeTcpCapsuleCmd
// -------------------------------------------------------------------

/// Capsule command PDU — wraps an NVMe SQE for TCP transport.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeTcpCapsuleCmd {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// NVMe command (SQE, 64 bytes).
    pub sqe: [u8; NVME_CMD_SIZE],
}

impl Default for NvmeTcpCapsuleCmd {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeTcpCapsuleCmd {
    /// Creates an empty capsule command.
    pub fn new() -> Self {
        let hlen = 8 + NVME_CMD_SIZE as u8; // header + SQE
        Self {
            header: NvmeTcpPduHeader::new(PduType::CapsuleCmd, PduFlags::NONE, hlen, hlen as u32),
            sqe: [0u8; NVME_CMD_SIZE],
        }
    }

    /// Creates a capsule command with inline data.
    pub fn with_data_len(data_len: usize) -> Self {
        let hlen = (8 + NVME_CMD_SIZE) as u8;
        let plen = hlen as u32 + data_len as u32;
        let flags = if data_len > 0 {
            PduFlags::DATA_PRESENT
        } else {
            PduFlags::NONE
        };
        Self {
            header: NvmeTcpPduHeader::new(PduType::CapsuleCmd, flags, hlen, plen),
            sqe: [0u8; NVME_CMD_SIZE],
        }
    }

    /// Sets the opcode in the SQE (byte 0).
    pub fn set_opcode(&mut self, opcode: u8) {
        self.sqe[0] = opcode;
    }

    /// Sets the command ID in the SQE (bytes 2-3, little-endian).
    pub fn set_cid(&mut self, cid: u16) {
        self.sqe[2] = cid as u8;
        self.sqe[3] = (cid >> 8) as u8;
    }

    /// Sets the namespace ID in the SQE (bytes 4-7, little-endian).
    pub fn set_nsid(&mut self, nsid: u32) {
        self.sqe[4] = nsid as u8;
        self.sqe[5] = (nsid >> 8) as u8;
        self.sqe[6] = (nsid >> 16) as u8;
        self.sqe[7] = (nsid >> 24) as u8;
    }
}

// -------------------------------------------------------------------
// NvmeTcpCapsuleResp
// -------------------------------------------------------------------

/// Capsule response PDU — wraps an NVMe CQE for TCP transport.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmeTcpCapsuleResp {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// NVMe completion entry (CQE, 16 bytes).
    pub cqe: [u8; NVME_CQE_SIZE],
}

impl NvmeTcpCapsuleResp {
    /// Returns the status field from the CQE (bytes 14-15).
    pub fn status(&self) -> u16 {
        (self.cqe[14] as u16) | ((self.cqe[15] as u16) << 8)
    }

    /// Returns `true` if status indicates success (status code = 0).
    pub fn is_success(&self) -> bool {
        // Status field bits [15:1] = status code, bit [0] = phase tag
        (self.status() >> 1) == 0
    }

    /// Returns the command ID from the CQE (bytes 12-13).
    pub fn command_id(&self) -> u16 {
        (self.cqe[12] as u16) | ((self.cqe[13] as u16) << 8)
    }

    /// Returns the SQ head pointer from the CQE (bytes 8-9).
    pub fn sq_head(&self) -> u16 {
        (self.cqe[8] as u16) | ((self.cqe[9] as u16) << 8)
    }
}

// -------------------------------------------------------------------
// H2CDataPdu / C2HDataPdu
// -------------------------------------------------------------------

/// H2CData PDU — host-to-controller data transfer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct H2CDataPdu {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// Command capsule tag (links to the originating capsule cmd).
    pub cccid: u16,
    /// Transfer tag from the R2T.
    pub ttag: u16,
    /// Data offset within the overall transfer.
    pub data_offset: u32,
    /// Data length in this PDU.
    pub data_length: u32,
    /// Reserved.
    pub _reserved: u32,
}

impl H2CDataPdu {
    /// Creates an H2CData PDU header.
    pub fn new(cccid: u16, ttag: u16, data_offset: u32, data_length: u32) -> Self {
        let hlen = 24u8; // common header (8) + specific fields (16)
        let plen = hlen as u32 + data_length;
        Self {
            header: NvmeTcpPduHeader::new(PduType::H2CData, PduFlags::LAST_PDU, hlen, plen),
            cccid,
            ttag,
            data_offset,
            data_length,
            _reserved: 0,
        }
    }
}

/// C2HData PDU — controller-to-host data transfer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct C2HDataPdu {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// Command capsule tag.
    pub cccid: u16,
    /// Reserved.
    pub _reserved0: u16,
    /// Data offset within the overall transfer.
    pub data_offset: u32,
    /// Data length in this PDU.
    pub data_length: u32,
    /// Reserved.
    pub _reserved1: u32,
}

impl C2HDataPdu {
    /// Returns `true` if this is the last data PDU in the sequence.
    pub fn is_last(&self) -> bool {
        PduFlags::from_bits(self.header.flags).0 & PduFlags::LAST_PDU.0 != 0
    }
}

// -------------------------------------------------------------------
// R2TPdu
// -------------------------------------------------------------------

/// R2T (Ready to Transfer) PDU — controller requests data from host.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct R2TPdu {
    /// Common PDU header.
    pub header: NvmeTcpPduHeader,
    /// Command capsule tag.
    pub cccid: u16,
    /// Transfer tag (used by host in H2CData).
    pub ttag: u16,
    /// Requested data offset.
    pub r2t_offset: u32,
    /// Requested data length.
    pub r2t_length: u32,
    /// Reserved.
    pub _reserved: u32,
}

// -------------------------------------------------------------------
// QueuePairState
// -------------------------------------------------------------------

/// State of a TCP queue pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueuePairState {
    /// Queue not initialized.
    #[default]
    Idle,
    /// Connection initializing (ICReq/ICResp exchange).
    Connecting,
    /// Queue is live and ready for I/O.
    Live,
    /// Queue is being drained before disconnect.
    Draining,
    /// Queue has been disconnected.
    Disconnected,
    /// Queue encountered a fatal error.
    Error,
}

// -------------------------------------------------------------------
// CommandSlot
// -------------------------------------------------------------------

/// Tracks an outstanding command on a queue pair.
#[derive(Debug, Clone, Copy)]
struct CommandSlot {
    /// Command ID.
    cid: u16,
    /// Whether this slot is in use.
    active: bool,
    /// Opcode of the submitted command.
    opcode: u8,
    /// Data length for data transfer commands.
    data_len: u32,
    /// Bytes transferred so far.
    bytes_done: u32,
}

impl Default for CommandSlot {
    fn default() -> Self {
        Self {
            cid: 0,
            active: false,
            opcode: 0,
            data_len: 0,
            bytes_done: 0,
        }
    }
}

// -------------------------------------------------------------------
// NvmeTcpQueuePair
// -------------------------------------------------------------------

/// A single NVMe-oF TCP queue pair.
///
/// Manages a submission queue (host→controller) and completion
/// queue (controller→host) over a TCP connection, with PDU
/// framing and digest support.
pub struct NvmeTcpQueuePair {
    /// Queue pair ID (0 = admin, 1+ = I/O).
    pub qid: u16,
    /// Queue depth.
    pub depth: u16,
    /// Current state.
    pub state: QueuePairState,
    /// Whether header digest is enabled.
    pub hdgst: bool,
    /// Whether data digest is enabled.
    pub ddgst: bool,
    /// Next command ID to allocate.
    next_cid: u16,
    /// Outstanding commands.
    commands: [CommandSlot; MAX_QUEUE_DEPTH],
    /// Number of outstanding commands.
    outstanding: usize,
    /// SQ head pointer (mirrored from CQE).
    sq_head: u16,
}

impl Default for NvmeTcpQueuePair {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeTcpQueuePair {
    /// Creates an idle queue pair.
    pub const fn new() -> Self {
        Self {
            qid: 0,
            depth: MAX_QUEUE_DEPTH as u16,
            state: QueuePairState::Idle,
            hdgst: false,
            ddgst: false,
            next_cid: 1,
            commands: [CommandSlot {
                cid: 0,
                active: false,
                opcode: 0,
                data_len: 0,
                bytes_done: 0,
            }; MAX_QUEUE_DEPTH],
            outstanding: 0,
            sq_head: 0,
        }
    }

    /// Allocates a command ID.
    pub fn alloc_cid(&mut self) -> Result<u16> {
        if self.outstanding >= MAX_QUEUE_DEPTH {
            return Err(Error::Busy);
        }
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == 0 {
            self.next_cid = 1;
        }
        // Find a free slot
        for slot in self.commands.iter_mut() {
            if !slot.active {
                slot.cid = cid;
                slot.active = true;
                slot.bytes_done = 0;
                self.outstanding += 1;
                return Ok(cid);
            }
        }
        Err(Error::Busy)
    }

    /// Completes a command by CID.
    pub fn complete_cid(&mut self, cid: u16) -> Result<()> {
        for slot in self.commands.iter_mut() {
            if slot.active && slot.cid == cid {
                slot.active = false;
                self.outstanding = self.outstanding.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Builds a CapsuleCmd PDU for an NVMe read command.
    pub fn build_read_cmd(
        &mut self,
        nsid: u32,
        lba: u64,
        block_count: u16,
    ) -> Result<NvmeTcpCapsuleCmd> {
        let cid = self.alloc_cid()?;
        let data_len = (block_count as usize) * 512;
        let mut capsule = NvmeTcpCapsuleCmd::with_data_len(data_len);
        capsule.set_opcode(0x02); // NVM Read
        capsule.set_cid(cid);
        capsule.set_nsid(nsid);
        // CDW10/CDW11 = starting LBA (little-endian, bytes 40-47)
        capsule.sqe[40] = lba as u8;
        capsule.sqe[41] = (lba >> 8) as u8;
        capsule.sqe[42] = (lba >> 16) as u8;
        capsule.sqe[43] = (lba >> 24) as u8;
        capsule.sqe[44] = (lba >> 32) as u8;
        capsule.sqe[45] = (lba >> 40) as u8;
        capsule.sqe[46] = (lba >> 48) as u8;
        capsule.sqe[47] = (lba >> 56) as u8;
        // CDW12 = NLB (number of logical blocks - 1)
        let nlb = block_count.saturating_sub(1);
        capsule.sqe[48] = nlb as u8;
        capsule.sqe[49] = (nlb >> 8) as u8;

        // Track data length
        for slot in self.commands.iter_mut() {
            if slot.active && slot.cid == cid {
                slot.opcode = 0x02;
                slot.data_len = data_len as u32;
                break;
            }
        }

        Ok(capsule)
    }

    /// Builds a CapsuleCmd PDU for an NVMe write command.
    pub fn build_write_cmd(
        &mut self,
        nsid: u32,
        lba: u64,
        block_count: u16,
    ) -> Result<NvmeTcpCapsuleCmd> {
        let cid = self.alloc_cid()?;
        let data_len = (block_count as usize) * 512;
        let mut capsule = NvmeTcpCapsuleCmd::with_data_len(data_len);
        capsule.set_opcode(0x01); // NVM Write
        capsule.set_cid(cid);
        capsule.set_nsid(nsid);
        capsule.sqe[40] = lba as u8;
        capsule.sqe[41] = (lba >> 8) as u8;
        capsule.sqe[42] = (lba >> 16) as u8;
        capsule.sqe[43] = (lba >> 24) as u8;
        capsule.sqe[44] = (lba >> 32) as u8;
        capsule.sqe[45] = (lba >> 40) as u8;
        capsule.sqe[46] = (lba >> 48) as u8;
        capsule.sqe[47] = (lba >> 56) as u8;
        let nlb = block_count.saturating_sub(1);
        capsule.sqe[48] = nlb as u8;
        capsule.sqe[49] = (nlb >> 8) as u8;

        for slot in self.commands.iter_mut() {
            if slot.active && slot.cid == cid {
                slot.opcode = 0x01;
                slot.data_len = data_len as u32;
                break;
            }
        }

        Ok(capsule)
    }

    /// Processes a CapsuleResp PDU.
    pub fn process_response(&mut self, resp: &NvmeTcpCapsuleResp) -> Result<()> {
        let cid = resp.command_id();
        self.sq_head = resp.sq_head();
        self.complete_cid(cid)
    }

    /// Returns the number of outstanding commands.
    pub fn outstanding_count(&self) -> usize {
        self.outstanding
    }

    /// Returns `true` if the queue can accept more commands.
    pub fn has_capacity(&self) -> bool {
        self.outstanding < MAX_QUEUE_DEPTH
    }
}

// -------------------------------------------------------------------
// ConnectionState
// -------------------------------------------------------------------

/// State of the TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Not connected.
    #[default]
    Disconnected,
    /// TCP connection established, ICReq sent.
    IcReqSent,
    /// ICResp received, connection ready.
    Connected,
    /// Disconnecting.
    Closing,
    /// Connection error.
    Error,
}

// -------------------------------------------------------------------
// NvmeTcpConnection
// -------------------------------------------------------------------

/// Manages the TCP-level connection to a remote NVMe-oF target.
pub struct NvmeTcpConnection {
    /// Remote target IP address (as a u32, network byte order).
    pub remote_addr: u32,
    /// Remote port.
    pub remote_port: u16,
    /// Local port (ephemeral).
    pub local_port: u16,
    /// Connection state.
    pub state: ConnectionState,
    /// Negotiated maximum data size.
    pub max_data_size: u32,
    /// Whether header digest is negotiated.
    pub hdgst: bool,
    /// Whether data digest is negotiated.
    pub ddgst: bool,
    /// PDU format version.
    pub pfv: u16,
}

impl Default for NvmeTcpConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeTcpConnection {
    /// Creates a new disconnected connection.
    pub const fn new() -> Self {
        Self {
            remote_addr: 0,
            remote_port: NVME_TCP_DEFAULT_PORT,
            local_port: 0,
            state: ConnectionState::Disconnected,
            max_data_size: MAX_PDU_DATA_SIZE as u32,
            hdgst: false,
            ddgst: false,
            pfv: 0,
        }
    }

    /// Builds an ICReq PDU for this connection.
    pub fn build_ic_req(&self) -> IcReqPdu {
        IcReqPdu::new(self.hdgst, self.ddgst)
    }

    /// Processes an ICResp PDU, updating negotiated parameters.
    pub fn process_ic_resp(&mut self, resp: &IcRespPdu) -> Result<()> {
        if resp.header.pdu_type != PduType::IcResp.to_byte() {
            return Err(Error::InvalidArgument);
        }
        self.hdgst = resp.hdgst_enabled();
        self.ddgst = resp.ddgst_enabled();
        self.max_data_size = resp.maxdata;
        self.pfv = resp.pfv;
        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Initiates connection (sets state to IcReqSent).
    pub fn connect(&mut self, remote_addr: u32, remote_port: u16) -> Result<()> {
        if self.state != ConnectionState::Disconnected {
            return Err(Error::Busy);
        }
        self.remote_addr = remote_addr;
        self.remote_port = remote_port;
        self.state = ConnectionState::IcReqSent;
        Ok(())
    }

    /// Disconnects the connection.
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnected;
        self.remote_addr = 0;
    }

    /// Returns `true` if the connection is live.
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }
}

// -------------------------------------------------------------------
// ControllerState
// -------------------------------------------------------------------

/// NVMe-oF TCP controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ControllerState {
    /// Controller not initialized.
    #[default]
    New,
    /// Controller connect sent.
    Connecting,
    /// Controller is live.
    Live,
    /// Controller is being reset.
    Resetting,
    /// Controller is deleting.
    Deleting,
    /// Controller in error state.
    Dead,
}

// -------------------------------------------------------------------
// NvmeTcpController
// -------------------------------------------------------------------

/// NVMe-oF TCP controller abstraction.
///
/// Represents a connection to a remote NVMe-oF target controller,
/// managing the admin queue, I/O queues, and NQN identity.
pub struct NvmeTcpController {
    /// Controller ID (assigned by the target).
    pub cntlid: u16,
    /// Controller state.
    pub state: ControllerState,
    /// Target NQN.
    pub nqn: [u8; MAX_NQN_LEN],
    /// NQN length.
    pub nqn_len: usize,
    /// TCP connection.
    pub connection: NvmeTcpConnection,
    /// Admin queue pair (qid = 0).
    pub admin_qp: NvmeTcpQueuePair,
    /// I/O queue pairs (qid = 1..N).
    io_qps: [NvmeTcpQueuePair; MAX_QUEUE_PAIRS],
    /// Number of configured I/O queue pairs.
    io_qp_count: usize,
    /// Keep-alive timeout in milliseconds (0 = disabled).
    pub kato_ms: u32,
    /// Maximum data transfer size (controller-reported).
    pub mdts: u32,
}

impl Default for NvmeTcpController {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeTcpController {
    /// Creates a new controller (not yet connected).
    pub fn new() -> Self {
        Self {
            cntlid: 0xFFFF, // unassigned
            state: ControllerState::New,
            nqn: [0u8; MAX_NQN_LEN],
            nqn_len: 0,
            connection: NvmeTcpConnection::new(),
            admin_qp: NvmeTcpQueuePair::new(),
            io_qps: [const { NvmeTcpQueuePair::new() }; MAX_QUEUE_PAIRS],
            io_qp_count: 0,
            kato_ms: 0,
            mdts: 0,
        }
    }

    /// Sets the target NQN.
    pub fn set_nqn(&mut self, nqn: &[u8]) -> Result<()> {
        if nqn.len() > MAX_NQN_LEN {
            return Err(Error::InvalidArgument);
        }
        self.nqn[..nqn.len()].copy_from_slice(nqn);
        self.nqn_len = nqn.len();
        Ok(())
    }

    /// Initiates a connection to the target.
    pub fn connect(&mut self, remote_addr: u32, remote_port: u16) -> Result<()> {
        self.connection.connect(remote_addr, remote_port)?;
        self.state = ControllerState::Connecting;
        self.admin_qp.state = QueuePairState::Connecting;
        Ok(())
    }

    /// Completes the connection after ICResp processing.
    pub fn complete_connect(&mut self, cntlid: u16) -> Result<()> {
        if self.state != ControllerState::Connecting {
            return Err(Error::InvalidArgument);
        }
        self.cntlid = cntlid;
        self.state = ControllerState::Live;
        self.admin_qp.state = QueuePairState::Live;
        self.admin_qp.hdgst = self.connection.hdgst;
        self.admin_qp.ddgst = self.connection.ddgst;
        Ok(())
    }

    /// Creates an I/O queue pair.
    pub fn create_io_queue(&mut self, depth: u16) -> Result<u16> {
        if self.io_qp_count >= MAX_QUEUE_PAIRS {
            return Err(Error::OutOfMemory);
        }
        let qid = (self.io_qp_count + 1) as u16; // QID 0 is admin
        let qp = &mut self.io_qps[self.io_qp_count];
        qp.qid = qid;
        qp.depth = depth;
        qp.state = QueuePairState::Live;
        qp.hdgst = self.connection.hdgst;
        qp.ddgst = self.connection.ddgst;
        self.io_qp_count += 1;
        Ok(qid)
    }

    /// Returns a reference to an I/O queue pair by QID.
    pub fn get_io_queue(&self, qid: u16) -> Option<&NvmeTcpQueuePair> {
        if qid == 0 || qid as usize > self.io_qp_count {
            return None;
        }
        Some(&self.io_qps[qid as usize - 1])
    }

    /// Returns a mutable reference to an I/O queue pair by QID.
    pub fn get_io_queue_mut(&mut self, qid: u16) -> Option<&mut NvmeTcpQueuePair> {
        if qid == 0 || qid as usize > self.io_qp_count {
            return None;
        }
        Some(&mut self.io_qps[qid as usize - 1])
    }

    /// Disconnects the controller and all queues.
    pub fn disconnect(&mut self) {
        self.state = ControllerState::Deleting;
        self.admin_qp.state = QueuePairState::Disconnected;
        for i in 0..self.io_qp_count {
            self.io_qps[i].state = QueuePairState::Disconnected;
        }
        self.connection.disconnect();
        self.state = ControllerState::Dead;
    }

    /// Returns `true` if the controller is live and ready for I/O.
    pub fn is_live(&self) -> bool {
        self.state == ControllerState::Live
    }

    /// Returns the number of configured I/O queue pairs.
    pub fn io_queue_count(&self) -> usize {
        self.io_qp_count
    }
}

// -------------------------------------------------------------------
// NvmeTcpControllerRegistry
// -------------------------------------------------------------------

/// System-wide registry of NVMe-oF TCP controllers.
pub struct NvmeTcpControllerRegistry {
    /// Registered controllers.
    controllers: [Option<NvmeTcpController>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for NvmeTcpControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeTcpControllerRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            controllers: [None, None, None, None],
            count: 0,
        }
    }

    /// Registers a new controller.
    pub fn register(&mut self, ctrl: NvmeTcpController) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.controllers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(ctrl);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a controller by index.
    pub fn get(&self, index: usize) -> Option<&NvmeTcpController> {
        if index < MAX_CONTROLLERS {
            self.controllers[index].as_ref()
        } else {
            None
        }
    }

    /// Returns a mutable reference to a controller by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut NvmeTcpController> {
        if index < MAX_CONTROLLERS {
            self.controllers[index].as_mut()
        } else {
            None
        }
    }

    /// Removes a controller by index.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CONTROLLERS || self.controllers[index].is_none() {
            return Err(Error::NotFound);
        }
        self.controllers[index] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TCP connection state machine for the ONCRIX network stack.
//!
//! Implements RFC 793 TCP segment parsing, a per-connection state
//! machine covering the full connection lifecycle (SYN, ESTABLISHED,
//! FIN), send/receive buffering, and a connection table for
//! demultiplexing incoming segments by 4-tuple.
//!
//! All sequence-number arithmetic uses [`u32::wrapping_add`] and
//! [`u32::wrapping_sub`] to correctly handle 32-bit wrap-around as
//! required by RFC 793 section 3.3.

use crate::crypto::Hmac256;
use crate::random_kern::RandomSubsystem;
use oncrix_lib::{Error, Result};

// =========================================================================
// Kernel CSPRNG singleton
// =========================================================================
//
// The TCP stack needs unpredictable random material for two security
// properties:
//
//   * Initial Sequence Number selection (RFC 6528), to defeat off-path
//     blind injection / RST / connection-spoofing attacks.
//   * The per-boot TCP Fast Open cookie secret (RFC 7413), so that
//     anti-spoofing cookies are unforgeable.
//
// No kernel-global CSPRNG accessor exists in-crate, so one is provided
// here. It wraps the ChaCha20 [`RandomSubsystem`] behind a spinlock and
// is lazily seeded from a hardware entropy source on first use.

/// Lazily-seeded kernel-global CSPRNG, guarded by a spinlock.
///
/// `SeqCst` on the lock flag pairs with the data writes to `RNG` so a
/// thread that observes the lock released also observes the seeded RNG.
static RNG_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The global ChaCha20 CSPRNG instance.
///
/// Access is serialized exclusively through [`with_kernel_rng`], which
/// holds [`RNG_LOCK`]; no other code may reference this static.
static mut RNG: RandomSubsystem = RandomSubsystem::new();

/// Read a hardware-derived 64-bit entropy word.
///
/// Prefers the on-die RNG (`RDSEED`, then `RDRAND`) when the CPU
/// advertises it via CPUID, mixing in the timestamp counter regardless.
/// Falls back to `RDTSC` alone on CPUs without an on-die RNG or on
/// non-x86 targets.  This is best-effort boot entropy used to seed the
/// CSPRNG; the CSPRNG (ChaCha20) provides the cryptographic strength.
fn hw_entropy_word() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let tsc = {
            let lo: u32;
            let hi: u32;
            // SAFETY: `rdtsc` is always available on x86_64, reads only
            // the timestamp counter, and has no memory side effects.
            unsafe {
                core::arch::asm!(
                    "rdtsc",
                    out("eax") lo,
                    out("edx") hi,
                    options(nomem, nostack, preserves_flags),
                );
            }
            ((hi as u64) << 32) | (lo as u64)
        };

        let mut word = tsc;
        if let Some(hw) = x86_rdseed_or_rdrand() {
            word ^= hw;
        }
        word
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // No hardware entropy source on this target; the caller mixes
        // several of these words together as a weak fallback seed.
        0x9E37_79B9_7F4A_7C15
    }
}

/// Attempt to read a 64-bit value from the x86 on-die RNG.
///
/// Returns `Some(value)` if CPUID reports `RDSEED` (EBX bit 18 of leaf
/// 7) or `RDRAND` (ECX bit 30 of leaf 1) and the instruction signals
/// success, otherwise `None`.
#[cfg(target_arch = "x86_64")]
fn x86_rdseed_or_rdrand() -> Option<u64> {
    let (rdseed, rdrand) = x86_rng_support();

    if rdseed {
        // Retry a bounded number of times; RDSEED may transiently fail
        // when the entropy source is momentarily exhausted.
        for _ in 0..32 {
            let val: u64;
            let ok: u8;
            // SAFETY: `rdseed` is gated on the CPUID feature bit above;
            // it writes a 64-bit result and sets CF (captured via setc)
            // to indicate success, with no memory side effects.
            unsafe {
                core::arch::asm!(
                    "rdseed {v}",
                    "setc {c}",
                    v = out(reg) val,
                    c = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return Some(val);
            }
        }
    }

    if rdrand {
        for _ in 0..32 {
            let val: u64;
            let ok: u8;
            // SAFETY: `rdrand` is gated on the CPUID feature bit above;
            // it writes a 64-bit result and sets CF (captured via setc)
            // to indicate success, with no memory side effects.
            unsafe {
                core::arch::asm!(
                    "rdrand {v}",
                    "setc {c}",
                    v = out(reg) val,
                    c = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return Some(val);
            }
        }
    }

    None
}

/// Execute CPUID for `leaf`/`subleaf`, returning `(eax, ebx, ecx, edx)`.
///
/// EBX is reserved by LLVM as the PIC base register, so it is saved and
/// restored around the instruction via a scratch register and `xchg`.
#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is supported on every x86_64 CPU and has no memory
    // side effects. EBX is swapped into a scratch register before the
    // instruction and swapped back afterwards so LLVM's reserved PIC
    // base register is preserved.
    unsafe {
        core::arch::asm!(
            "xchg {ebx_tmp:r}, rbx",
            "cpuid",
            "xchg {ebx_tmp:r}, rbx",
            ebx_tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Query CPUID for on-die RNG support, returning `(rdseed, rdrand)`.
#[cfg(target_arch = "x86_64")]
fn x86_rng_support() -> (bool, bool) {
    // RDRAND: CPUID leaf 1, ECX bit 30.
    let (_, _, ecx1, _) = cpuid(1, 0);
    let rdrand = ecx1 & (1 << 30) != 0;

    // RDSEED: CPUID leaf 7, sub-leaf 0, EBX bit 18.
    let (max_leaf, ..) = cpuid(0, 0);
    let rdseed = if max_leaf >= 7 {
        let (_, ebx7, _, _) = cpuid(7, 0);
        ebx7 & (1 << 18) != 0
    } else {
        false
    };

    (rdseed, rdrand)
}

/// Acquire the CSPRNG lock, lazily seed the RNG, and run `f`.
///
/// On first use (and again if the pool ever falls below threshold) the
/// entropy pool is filled from [`hw_entropy_word`] until the ChaCha20
/// CRNG seeds, so callers never observe an unseeded generator.
fn with_kernel_rng<T>(f: impl FnOnce(&mut RandomSubsystem) -> T) -> T {
    use core::sync::atomic::Ordering;

    // Spin until we own the lock.
    while RNG_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    // SAFETY: RNG_LOCK is held, granting exclusive access to RNG for the
    // duration of this critical section. The reference does not escape.
    let rng = unsafe { &mut *core::ptr::addr_of_mut!(RNG) };

    if !rng.is_seeded() {
        // Mix hardware entropy until the ChaCha20 CRNG auto-seeds.
        // Each word is credited 32 bits; the pool needs 256 bits.
        for _ in 0..64 {
            if rng.is_seeded() {
                break;
            }
            rng.add_entropy(hw_entropy_word(), 32);
        }
    }

    let result = f(rng);

    RNG_LOCK.store(false, Ordering::Release);
    result
}

/// Fill `out` with random bytes from the kernel CSPRNG.
///
/// Returns `true` on success.  On the (practically unreachable) failure
/// to seed, `out` is left untouched and `false` is returned so the
/// caller can fail closed rather than use predictable bytes.
pub(crate) fn kernel_random_bytes(out: &mut [u8]) -> bool {
    with_kernel_rng(|rng| rng.get_random_bytes(out).is_ok())
}

// =========================================================================
// Initial Sequence Number selection (RFC 6528)
// =========================================================================

/// Per-boot secret keying the ISN generator, drawn from the CSPRNG.
static ISN_SECRET_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether [`ISN_SECRET`] has been initialized from the CSPRNG.
static ISN_SECRET_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// 32-byte secret mixed into every ISN via HMAC-SHA256.
///
/// Initialized once from the CSPRNG; only [`isn_secret`] touches it.
static mut ISN_SECRET: [u8; 32] = [0u8; 32];

/// Return a reference to the per-boot ISN secret, seeding it on first
/// use from the kernel CSPRNG.
fn isn_secret() -> [u8; 32] {
    use core::sync::atomic::Ordering;

    if !ISN_SECRET_READY.load(Ordering::Acquire) {
        while ISN_SECRET_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        if !ISN_SECRET_READY.load(Ordering::Relaxed) {
            let mut key = [0u8; 32];
            if kernel_random_bytes(&mut key) {
                // SAFETY: the ISN_SECRET_LOCK is held, so this is the
                // only writer; the value is published via the Release
                // store to ISN_SECRET_READY below.
                unsafe {
                    *core::ptr::addr_of_mut!(ISN_SECRET) = key;
                }
                ISN_SECRET_READY.store(true, Ordering::Release);
            } else {
                // CSPRNG not yet seeded (practically unreachable). Do NOT
                // publish an all-zero key — a zero-keyed HMAC ISN would be
                // attacker-predictable. Return a best-effort hardware-entropy
                // key for THIS call without latching, so a later call upgrades
                // to the real CSPRNG key (self-healing).
                ISN_SECRET_LOCK.store(false, Ordering::Release);
                let mut k = [0u8; 32];
                for chunk in k.chunks_mut(8) {
                    let w = hw_entropy_word().to_le_bytes();
                    chunk.copy_from_slice(&w[..chunk.len()]);
                }
                return k;
            }
        }
        ISN_SECRET_LOCK.store(false, Ordering::Release);
    }

    // SAFETY: once ISN_SECRET_READY is observed true the secret is
    // immutable for the rest of the boot, so this read races with no
    // writer (the only failure path returns early above without latching).
    unsafe { *core::ptr::addr_of!(ISN_SECRET) }
}

/// Read a monotonic 4-microsecond timer value for the ISN base `M`.
///
/// RFC 6528 specifies adding a timer ticking roughly every 4 µs so that
/// sequence numbers for successive connections on the same 4-tuple do
/// not collide.  Derived from the TSC; the exact rate is not critical.
fn isn_timer() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        // SAFETY: `rdtsc` is always available on x86_64 and only reads
        // the timestamp counter.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        let tsc = ((hi as u64) << 32) | (lo as u64);
        // Approximate a ~4 µs tick assuming a multi-GHz TSC by shifting
        // off the low bits; truncate to 32 bits per RFC 793 sequence
        // space.
        (tsc >> 12) as u32
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// Compute an Initial Sequence Number for the given 4-tuple per RFC 6528.
///
/// `ISN = M + HMAC-SHA256(secret, local_ip ++ local_port ++ remote_ip
/// ++ remote_port)[:4]`, where `M` is a 4-µs timer and `secret` is a
/// per-boot CSPRNG-derived key.  This makes the ISN unpredictable to
/// off-path attackers (defeating blind injection / RST / spoofing)
/// while keeping it monotone per 4-tuple to avoid old-segment confusion.
fn generate_isn(local_ip: [u8; 4], local_port: u16, remote_ip: [u8; 4], remote_port: u16) -> u32 {
    let secret = isn_secret();
    let mut mac = Hmac256::new(&secret);
    mac.update(&local_ip);
    mac.update(&local_port.to_be_bytes());
    mac.update(&remote_ip);
    mac.update(&remote_port.to_be_bytes());
    let tag = mac.finalize();
    let hashed = u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]]);
    isn_timer().wrapping_add(hashed)
}

// =========================================================================
// TCP flag constants
// =========================================================================

/// TCP FIN flag — sender has finished sending data.
pub const TCP_FIN: u16 = 0x01;

/// TCP SYN flag — synchronise sequence numbers.
pub const TCP_SYN: u16 = 0x02;

/// TCP RST flag — reset the connection.
pub const TCP_RST: u16 = 0x04;

/// TCP PSH flag — push buffered data to receiver.
pub const TCP_PSH: u16 = 0x08;

/// TCP ACK flag — acknowledgement field is significant.
pub const TCP_ACK: u16 = 0x10;

/// TCP URG flag — urgent pointer field is significant.
pub const TCP_URG: u16 = 0x20;

/// Minimum TCP header size in bytes (no options).
const TCP_HEADER_MIN_LEN: usize = 20;

/// Maximum number of bytes in the send buffer.
const SEND_BUF_SIZE: usize = 4096;

/// Maximum number of bytes in the receive buffer.
const RECV_BUF_SIZE: usize = 4096;

/// Maximum number of concurrent TCP connections.
const TCP_TABLE_SIZE: usize = 32;

// =========================================================================
// TcpHeader
// =========================================================================

/// Parsed TCP segment header (RFC 793).
///
/// Fields are stored in host byte order after parsing.  The
/// `data_offset_flags` field packs the data offset (upper 4 bits),
/// reserved bits, and 6 control flags into a single `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TcpHeader {
    /// Source port number.
    pub source_port: u16,
    /// Destination port number.
    pub dest_port: u16,
    /// Sequence number.
    pub seq_num: u32,
    /// Acknowledgement number.
    pub ack_num: u32,
    /// Data offset (upper 4 bits), reserved (6 bits), flags
    /// (lower 6 bits).
    pub data_offset_flags: u16,
    /// Receive window size.
    pub window_size: u16,
    /// Checksum over pseudo-header, TCP header, and payload.
    pub checksum: u16,
    /// Urgent pointer (valid only when URG flag is set).
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Return the data offset in 32-bit words.
    pub fn data_offset(&self) -> u8 {
        (self.data_offset_flags >> 12) as u8
    }

    /// Return the header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.data_offset() as usize) * 4
    }

    /// Return `true` if the SYN flag is set.
    pub fn syn(&self) -> bool {
        (self.data_offset_flags & TCP_SYN) != 0
    }

    /// Return `true` if the ACK flag is set.
    pub fn ack(&self) -> bool {
        (self.data_offset_flags & TCP_ACK) != 0
    }

    /// Return `true` if the FIN flag is set.
    pub fn fin(&self) -> bool {
        (self.data_offset_flags & TCP_FIN) != 0
    }

    /// Return `true` if the RST flag is set.
    pub fn rst(&self) -> bool {
        (self.data_offset_flags & TCP_RST) != 0
    }

    /// Return `true` if the PSH flag is set.
    pub fn psh(&self) -> bool {
        (self.data_offset_flags & TCP_PSH) != 0
    }

    /// Return the raw 6-bit flags portion.
    pub fn flags(&self) -> u16 {
        self.data_offset_flags & 0x3F
    }
}

// =========================================================================
// parse_tcp
// =========================================================================

/// Parse a TCP header and payload from raw bytes.
///
/// Returns the parsed [`TcpHeader`] and a slice referencing the
/// payload (everything after the header, as indicated by the data
/// offset field).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if:
/// - `data` is shorter than the minimum TCP header (20 bytes).
/// - The data offset indicates a header longer than the available
///   data.
/// - The data offset is less than 5 (the minimum valid value).
pub fn parse_tcp(data: &[u8]) -> Result<(TcpHeader, &[u8])> {
    if data.len() < TCP_HEADER_MIN_LEN {
        return Err(Error::InvalidArgument);
    }

    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let dest_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset_flags = u16::from_be_bytes([data[12], data[13]]);
    let window_size = u16::from_be_bytes([data[14], data[15]]);
    let checksum = u16::from_be_bytes([data[16], data[17]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    let header = TcpHeader {
        source_port,
        dest_port,
        seq_num,
        ack_num,
        data_offset_flags,
        window_size,
        checksum,
        urgent_ptr,
    };

    let offset = header.data_offset();
    if offset < 5 {
        return Err(Error::InvalidArgument);
    }
    let hdr_len = (offset as usize) * 4;
    if data.len() < hdr_len {
        return Err(Error::InvalidArgument);
    }

    Ok((header, &data[hdr_len..]))
}

// =========================================================================
// TcpState
// =========================================================================

/// TCP connection state as defined in RFC 793 section 3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection exists.
    Closed,
    /// Waiting for an incoming SYN.
    Listen,
    /// SYN sent; waiting for SYN+ACK.
    SynSent,
    /// SYN received; SYN+ACK sent; waiting for ACK.
    SynReceived,
    /// Connection open; data transfer in progress.
    Established,
    /// FIN sent; waiting for ACK of FIN.
    FinWait1,
    /// FIN acknowledged; waiting for remote FIN.
    FinWait2,
    /// Remote side has closed; waiting for local close.
    CloseWait,
    /// Both sides have sent FIN; waiting for final ACK.
    Closing,
    /// FIN sent from CloseWait; waiting for ACK.
    LastAck,
    /// Waiting for enough time to ensure remote received ACK.
    TimeWait,
}

// =========================================================================
// TcpAction
// =========================================================================

/// Action the caller must take after processing a TCP event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAction {
    /// Send a TCP segment with the given parameters.
    SendSegment {
        /// TCP flags to set on the outgoing segment.
        flags: u16,
        /// Sequence number.
        seq: u32,
        /// Acknowledgement number.
        ack: u32,
        /// Number of payload bytes to send from the send buffer.
        payload_len: usize,
    },
    /// No action required.
    Nothing,
    /// The connection has been fully established.
    ConnectionEstablished,
    /// The connection has been fully closed.
    ConnectionClosed,
}

// =========================================================================
// TcpConnection
// =========================================================================

/// A single TCP connection with send/receive buffers.
///
/// Tracks the connection state machine, sequence numbers, window
/// sizes, and provides methods for the three-way handshake, data
/// transfer, and graceful close.
pub struct TcpConnection {
    /// Current connection state.
    pub state: TcpState,
    /// Local port number.
    pub local_port: u16,
    /// Remote port number.
    pub remote_port: u16,
    /// Local IPv4 address.
    pub local_ip: [u8; 4],
    /// Remote IPv4 address.
    pub remote_ip: [u8; 4],
    /// SND.NXT — next sequence number to send.
    pub send_next: u32,
    /// SND.UNA — oldest unacknowledged sequence number.
    pub send_unack: u32,
    /// Send window advertised by the remote peer.
    pub send_window: u16,
    /// RCV.NXT — next expected sequence number from the remote.
    pub recv_next: u32,
    /// Receive window we advertise to the remote peer.
    pub recv_window: u16,
    /// Outgoing data buffer.
    send_buf: [u8; SEND_BUF_SIZE],
    /// Number of valid bytes in `send_buf`.
    send_len: usize,
    /// Incoming data buffer.
    recv_buf: [u8; RECV_BUF_SIZE],
    /// Number of valid bytes in `recv_buf`.
    recv_len: usize,
}

impl Default for TcpConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnection {
    /// Create a new TCP connection in the `Closed` state.
    pub const fn new() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            local_ip: [0; 4],
            remote_ip: [0; 4],
            send_next: 0,
            send_unack: 0,
            send_window: 0,
            recv_next: 0,
            recv_window: RECV_BUF_SIZE as u16,
            send_buf: [0; SEND_BUF_SIZE],
            send_len: 0,
            recv_buf: [0; RECV_BUF_SIZE],
            recv_len: 0,
        }
    }

    /// Initiate an active open (client-side connect).
    ///
    /// Transitions from `Closed` to `SynSent`.  The caller must
    /// transmit the resulting SYN segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in the `Closed` state.
    pub fn connect(&mut self, remote_ip: [u8; 4], remote_port: u16) -> Result<TcpAction> {
        if self.state != TcpState::Closed {
            return Err(Error::InvalidArgument);
        }

        self.remote_ip = remote_ip;
        self.remote_port = remote_port;

        // Choose an unpredictable Initial Sequence Number (RFC 6528) to
        // defeat off-path blind injection / RST / spoofing attacks. The
        // SYN occupies one sequence number, so SND.UNA = ISN and
        // SND.NXT = ISN + 1 once it is sent.
        let isn = generate_isn(self.local_ip, self.local_port, remote_ip, remote_port);
        self.send_unack = isn;
        self.send_next = isn.wrapping_add(1);
        self.state = TcpState::SynSent;

        Ok(TcpAction::SendSegment {
            flags: TCP_SYN,
            seq: isn,
            ack: 0,
            payload_len: 0,
        })
    }

    /// Begin listening for incoming connections on `local_port`.
    ///
    /// Transitions from `Closed` to `Listen`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in the `Closed` state.
    pub fn listen(&mut self, local_port: u16) -> Result<()> {
        if self.state != TcpState::Closed {
            return Err(Error::InvalidArgument);
        }
        self.local_port = local_port;
        self.state = TcpState::Listen;
        Ok(())
    }

    /// Accept an incoming SYN on a listening socket.
    ///
    /// Transitions from `Listen` to `SynReceived` and prepares
    /// a SYN+ACK for the caller to transmit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in the `Listen` state or the header does not carry SYN.
    pub fn accept_syn(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if self.state != TcpState::Listen {
            return Err(Error::InvalidArgument);
        }
        if !header.syn() {
            return Err(Error::InvalidArgument);
        }

        self.remote_port = header.source_port;
        self.recv_next = header.seq_num.wrapping_add(1);
        self.send_window = header.window_size;

        // Choose an unpredictable Initial Sequence Number (RFC 6528) for
        // our side of the connection. The SYN+ACK occupies one sequence
        // number, so SND.UNA = ISN and SND.NXT = ISN + 1 once sent.
        let isn = generate_isn(
            self.local_ip,
            self.local_port,
            self.remote_ip,
            header.source_port,
        );
        self.send_unack = isn;
        self.send_next = isn.wrapping_add(1);
        self.state = TcpState::SynReceived;

        Ok(TcpAction::SendSegment {
            flags: TCP_SYN | TCP_ACK,
            seq: isn,
            ack: self.recv_next,
            payload_len: 0,
        })
    }

    /// Process an incoming TCP segment through the state machine.
    ///
    /// This is the main entry point for segment processing.  The
    /// returned [`TcpAction`] tells the caller what segment (if
    /// any) to send in response.
    ///
    /// # State transitions
    ///
    /// | Current state  | Segment          | Next state    |
    /// |---------------|------------------|---------------|
    /// | SynSent       | SYN+ACK          | Established   |
    /// | SynReceived   | ACK              | Established   |
    /// | Established   | data             | Established   |
    /// | Established   | FIN              | CloseWait     |
    /// | FinWait1      | ACK              | FinWait2      |
    /// | FinWait1      | FIN+ACK          | TimeWait      |
    /// | FinWait2      | FIN              | TimeWait      |
    /// | LastAck       | ACK              | Closed        |
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for segments that are
    /// invalid in the current state (e.g., RST received, or
    /// unexpected flags).
    pub fn process_segment(&mut self, header: &TcpHeader, payload: &[u8]) -> Result<TcpAction> {
        // RST handling. A bare RST flag is attacker-forgeable off-path, so
        // it cannot be honoured unconditionally (RFC 5961 §3, blind reset
        // protection).
        //
        // In synchronised states (ESTABLISHED and later) the RST is
        // accepted only when its sequence number is exactly RCV.NXT;
        // anything else is silently dropped rather than aborting the
        // connection. In non-synchronised states (SYN-SENT, SYN-RECEIVED)
        // there is no established receive sequence to validate against, so
        // the legacy abort behaviour is retained.
        if header.rst() {
            let synchronised = matches!(
                self.state,
                TcpState::Established
                    | TcpState::FinWait1
                    | TcpState::FinWait2
                    | TcpState::CloseWait
                    | TcpState::Closing
                    | TcpState::LastAck
                    | TcpState::TimeWait
            );
            if synchronised && header.seq_num != self.recv_next {
                // Out-of-window RST: drop it, keep the connection open.
                return Ok(TcpAction::Nothing);
            }
            self.state = TcpState::Closed;
            return Ok(TcpAction::ConnectionClosed);
        }

        match self.state {
            TcpState::SynSent => self.process_syn_sent(header),
            TcpState::SynReceived => self.process_syn_received(header),
            TcpState::Established => self.process_established(header, payload),
            TcpState::FinWait1 => self.process_fin_wait1(header),
            TcpState::FinWait2 => self.process_fin_wait2(header),
            TcpState::LastAck => self.process_last_ack(header),
            TcpState::Closing => self.process_closing(header),
            TcpState::CloseWait | TcpState::Listen | TcpState::Closed | TcpState::TimeWait => {
                Err(Error::InvalidArgument)
            }
        }
    }

    /// Initiate an active close by sending FIN.
    ///
    /// Transitions from `Established` to `FinWait1`, or from
    /// `CloseWait` to `LastAck`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in `Established` or `CloseWait` state.
    pub fn close(&mut self) -> Result<TcpAction> {
        match self.state {
            TcpState::Established => {
                self.state = TcpState::FinWait1;
                let seq = self.send_next;
                self.send_next = self.send_next.wrapping_add(1);
                Ok(TcpAction::SendSegment {
                    flags: TCP_FIN | TCP_ACK,
                    seq,
                    ack: self.recv_next,
                    payload_len: 0,
                })
            }
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                let seq = self.send_next;
                self.send_next = self.send_next.wrapping_add(1);
                Ok(TcpAction::SendSegment {
                    flags: TCP_FIN | TCP_ACK,
                    seq,
                    ack: self.recv_next,
                    payload_len: 0,
                })
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Buffer outgoing data for transmission.
    ///
    /// Copies as many bytes from `data` as will fit into the send
    /// buffer and returns the number of bytes actually buffered.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in the `Established` state.
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != TcpState::Established {
            return Err(Error::InvalidArgument);
        }
        let available = SEND_BUF_SIZE.saturating_sub(self.send_len);
        let count = if data.len() < available {
            data.len()
        } else {
            available
        };
        if count > 0 {
            self.send_buf[self.send_len..self.send_len + count].copy_from_slice(&data[..count]);
            self.send_len += count;
        }
        Ok(count)
    }

    /// Read received data from the receive buffer.
    ///
    /// Copies up to `buf.len()` bytes from the receive buffer into
    /// `buf` and returns the number of bytes actually read.  Read
    /// bytes are removed from the front of the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the connection is not
    /// in a state that permits reading (`Established` or
    /// `CloseWait`).
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.state != TcpState::Established && self.state != TcpState::CloseWait {
            return Err(Error::InvalidArgument);
        }
        let count = if buf.len() < self.recv_len {
            buf.len()
        } else {
            self.recv_len
        };
        if count > 0 {
            buf[..count].copy_from_slice(&self.recv_buf[..count]);
            // Shift remaining data forward.
            let remaining = self.recv_len - count;
            if remaining > 0 {
                let mut i = 0;
                while i < remaining {
                    self.recv_buf[i] = self.recv_buf[count + i];
                    i += 1;
                }
            }
            self.recv_len = remaining;
        }
        Ok(count)
    }

    // -- private state handlers -------------------------------------------

    /// Handle segment in SynSent state.
    fn process_syn_sent(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if !header.syn() || !header.ack() {
            return Err(Error::InvalidArgument);
        }

        self.recv_next = header.seq_num.wrapping_add(1);
        self.send_unack = header.ack_num;
        self.send_window = header.window_size;
        self.state = TcpState::Established;

        Ok(TcpAction::SendSegment {
            flags: TCP_ACK,
            seq: self.send_next,
            ack: self.recv_next,
            payload_len: 0,
        })
    }

    /// Handle segment in SynReceived state.
    fn process_syn_received(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if !header.ack() {
            return Err(Error::InvalidArgument);
        }

        self.send_unack = header.ack_num;
        self.send_window = header.window_size;
        self.state = TcpState::Established;

        Ok(TcpAction::ConnectionEstablished)
    }

    /// Handle segment in Established state.
    ///
    /// Performs RFC 793 §3.9 acceptance checks against attacker-controlled
    /// sequence and acknowledgement numbers before mutating any connection
    /// state:
    ///
    /// * The ACK field updates `SND.UNA`/`SND.WND` only when it is in the
    ///   half-open range `SND.UNA <= ACK <= SND.NXT` (wrap-aware), so a
    ///   forged ACK cannot rewind the unacknowledged pointer or inflate the
    ///   send window.
    /// * Payload is buffered, and `RCV.NXT` advanced, only for the strictly
    ///   in-order segment (`SEG.SEQ == RCV.NXT`).  This stack carries no
    ///   reassembly queue, so a segment left of the window, beyond the
    ///   window, or merely out of order is dropped — defeating off-path
    ///   data injection and stream desynchronisation.
    /// * A FIN consumes its sequence number only when the segment that
    ///   carries it is itself in order, so a forged out-of-window FIN
    ///   cannot tear the connection down.
    fn process_established(&mut self, header: &TcpHeader, payload: &[u8]) -> Result<TcpAction> {
        // Gate the ACK: accept only SND.UNA <= ACK <= SND.NXT in wrap
        // arithmetic. `ack_in_window` is the distance from SND.UNA to the
        // acked byte; it must not exceed the in-flight window
        // (SND.NXT - SND.UNA). A forged ACK outside this range is ignored.
        if header.ack() {
            let ack_in_window = header.ack_num.wrapping_sub(self.send_unack);
            let send_window = self.send_next.wrapping_sub(self.send_unack);
            if ack_in_window <= send_window {
                self.send_unack = header.ack_num;
                self.send_window = header.window_size;
            }
        }

        // Accept payload only when it begins exactly at RCV.NXT (in order).
        // The wrap-aware distance from RCV.NXT to the segment's first byte
        // is zero only for the in-order segment; a non-zero offset means the
        // segment is old (left of the window) or ahead of it, and it is
        // dropped (this stack keeps no reassembly queue).
        let in_order = header.seq_num.wrapping_sub(self.recv_next) == 0;

        // Buffer incoming data only for the in-order segment.
        let mut accepted = 0usize;
        if in_order && !payload.is_empty() {
            let available = RECV_BUF_SIZE.saturating_sub(self.recv_len);
            accepted = payload.len().min(available);
            if accepted > 0 {
                self.recv_buf[self.recv_len..self.recv_len + accepted]
                    .copy_from_slice(&payload[..accepted]);
                self.recv_len += accepted;
                self.recv_next = self.recv_next.wrapping_add(accepted as u32);
            }
        }

        // Handle FIN — remote is closing. Only an in-order FIN whose data
        // (if any) was fully accepted occupies the next sequence number;
        // otherwise the FIN sits beyond a gap and must not be consumed.
        if header.fin() && in_order && accepted == payload.len() {
            self.recv_next = self.recv_next.wrapping_add(1);
            self.state = TcpState::CloseWait;
            return Ok(TcpAction::SendSegment {
                flags: TCP_ACK,
                seq: self.send_next,
                ack: self.recv_next,
                payload_len: 0,
            });
        }

        // ACK any in-order data we accepted, or send a duplicate ACK for a
        // non-empty out-of-window segment so the peer can recover.
        if !payload.is_empty() {
            return Ok(TcpAction::SendSegment {
                flags: TCP_ACK,
                seq: self.send_next,
                ack: self.recv_next,
                payload_len: 0,
            });
        }

        Ok(TcpAction::Nothing)
    }

    /// Handle segment in FinWait1 state.
    fn process_fin_wait1(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if header.fin() && header.ack() {
            // Simultaneous close or FIN+ACK.
            self.send_unack = header.ack_num;
            self.recv_next = header.seq_num.wrapping_add(1);
            self.state = TcpState::TimeWait;
            return Ok(TcpAction::SendSegment {
                flags: TCP_ACK,
                seq: self.send_next,
                ack: self.recv_next,
                payload_len: 0,
            });
        }

        if header.ack() {
            self.send_unack = header.ack_num;
            self.state = TcpState::FinWait2;
            return Ok(TcpAction::Nothing);
        }

        if header.fin() {
            // Simultaneous close — no ACK for our FIN yet.
            self.recv_next = header.seq_num.wrapping_add(1);
            self.state = TcpState::Closing;
            return Ok(TcpAction::SendSegment {
                flags: TCP_ACK,
                seq: self.send_next,
                ack: self.recv_next,
                payload_len: 0,
            });
        }

        Err(Error::InvalidArgument)
    }

    /// Handle segment in FinWait2 state.
    fn process_fin_wait2(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if !header.fin() {
            return Err(Error::InvalidArgument);
        }

        self.recv_next = header.seq_num.wrapping_add(1);
        self.state = TcpState::TimeWait;

        Ok(TcpAction::SendSegment {
            flags: TCP_ACK,
            seq: self.send_next,
            ack: self.recv_next,
            payload_len: 0,
        })
    }

    /// Handle segment in LastAck state.
    fn process_last_ack(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if !header.ack() {
            return Err(Error::InvalidArgument);
        }
        self.send_unack = header.ack_num;
        self.state = TcpState::Closed;
        Ok(TcpAction::ConnectionClosed)
    }

    /// Handle segment in Closing state.
    fn process_closing(&mut self, header: &TcpHeader) -> Result<TcpAction> {
        if !header.ack() {
            return Err(Error::InvalidArgument);
        }
        self.send_unack = header.ack_num;
        self.state = TcpState::TimeWait;
        Ok(TcpAction::Nothing)
    }
}

// =========================================================================
// TcpTable
// =========================================================================

/// Connection lookup table holding up to [`TCP_TABLE_SIZE`] (32)
/// concurrent TCP connections.
///
/// Connections are identified by the 4-tuple (local IP, local port,
/// remote IP, remote port).
pub struct TcpTable {
    /// Fixed-size array of connection slots.
    connections: [TcpConnection; TCP_TABLE_SIZE],
    /// Validity flags for each slot.
    active: [bool; TCP_TABLE_SIZE],
}

impl Default for TcpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTable {
    /// Create an empty connection table.
    pub const fn new() -> Self {
        const EMPTY: TcpConnection = TcpConnection::new();
        Self {
            connections: [EMPTY; TCP_TABLE_SIZE],
            active: [false; TCP_TABLE_SIZE],
        }
    }

    /// Look up a connection by 4-tuple.
    ///
    /// Returns a mutable reference to the matching connection, or
    /// `None` if no match is found.
    pub fn lookup(
        &mut self,
        local_ip: &[u8; 4],
        local_port: u16,
        remote_ip: &[u8; 4],
        remote_port: u16,
    ) -> Option<&mut TcpConnection> {
        for i in 0..TCP_TABLE_SIZE {
            if !self.active[i] {
                continue;
            }
            let conn = &self.connections[i];
            if conn.local_ip == *local_ip
                && conn.local_port == local_port
                && conn.remote_ip == *remote_ip
                && conn.remote_port == remote_port
            {
                return Some(&mut self.connections[i]);
            }
        }
        None
    }

    /// Look up a listening socket by local port.
    ///
    /// Returns a mutable reference to a connection in the `Listen`
    /// state bound to `local_port`, or `None`.
    pub fn lookup_listener(&mut self, local_port: u16) -> Option<&mut TcpConnection> {
        for i in 0..TCP_TABLE_SIZE {
            if !self.active[i] {
                continue;
            }
            let conn = &self.connections[i];
            if conn.state == TcpState::Listen && conn.local_port == local_port {
                return Some(&mut self.connections[i]);
            }
        }
        None
    }

    /// Allocate a new connection slot and return a mutable reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are occupied.
    pub fn allocate(&mut self) -> Result<&mut TcpConnection> {
        for i in 0..TCP_TABLE_SIZE {
            if !self.active[i] {
                self.connections[i] = TcpConnection::new();
                self.active[i] = true;
                return Ok(&mut self.connections[i]);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Release the connection slot matching the given 4-tuple.
    ///
    /// Returns `true` if a connection was released, `false` if no
    /// match was found.
    pub fn release(
        &mut self,
        local_ip: &[u8; 4],
        local_port: u16,
        remote_ip: &[u8; 4],
        remote_port: u16,
    ) -> bool {
        for i in 0..TCP_TABLE_SIZE {
            if !self.active[i] {
                continue;
            }
            let conn = &self.connections[i];
            if conn.local_ip == *local_ip
                && conn.local_port == local_port
                && conn.remote_ip == *remote_ip
                && conn.remote_port == remote_port
            {
                self.active[i] = false;
                return true;
            }
        }
        false
    }

    /// Return the number of active connections.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for slot in &self.active {
            if *slot {
                count += 1;
            }
        }
        count
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- TcpHeader flag helpers --

    #[test]
    fn test_tcp_header_flags() {
        let hdr = TcpHeader {
            source_port: 1234,
            dest_port: 80,
            seq_num: 0,
            ack_num: 0,
            // data offset = 5, flags = SYN|ACK
            data_offset_flags: (5 << 12) | TCP_SYN | TCP_ACK,
            window_size: 8192,
            checksum: 0,
            urgent_ptr: 0,
        };

        assert!(hdr.syn());
        assert!(hdr.ack());
        assert!(!hdr.fin());
        assert!(!hdr.rst());
        assert!(!hdr.psh());
        assert_eq!(hdr.data_offset(), 5);
        assert_eq!(hdr.header_len(), 20);
    }

    // -- parse_tcp --

    #[test]
    fn test_parse_tcp_valid() {
        #[rustfmt::skip]
        let data: [u8; 24] = [
            0x04, 0xD2, // src port 1234
            0x00, 0x50, // dst port 80
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x02, // ack 2
            0x50, 0x12, // data offset=5, SYN+ACK
            0x20, 0x00, // window 8192
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];

        let (hdr, payload) = parse_tcp(&data).ok().unwrap();
        assert_eq!(hdr.source_port, 1234);
        assert_eq!(hdr.dest_port, 80);
        assert_eq!(hdr.seq_num, 1);
        assert_eq!(hdr.ack_num, 2);
        assert!(hdr.syn());
        assert!(hdr.ack());
        assert_eq!(hdr.window_size, 8192);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_tcp_too_short() {
        let data = [0u8; 10];
        assert!(parse_tcp(&data).is_err());
    }

    #[test]
    fn test_parse_tcp_bad_offset() {
        let mut data = [0u8; 20];
        // data offset = 3 (invalid, minimum is 5)
        data[12] = 0x30;
        assert!(parse_tcp(&data).is_err());
    }

    // -- Three-way handshake (client side) --

    #[test]
    fn test_client_handshake() {
        let mut conn = TcpConnection::new();
        conn.local_ip = [10, 0, 0, 1];
        conn.local_port = 5000;

        // connect() -> SynSent
        let action = conn.connect([10, 0, 0, 2], 80).ok().unwrap();
        assert_eq!(conn.state, TcpState::SynSent);
        match action {
            TcpAction::SendSegment { flags, .. } => {
                assert_eq!(flags, TCP_SYN);
            }
            _ => panic!("expected SendSegment"),
        }

        // Receive SYN+ACK -> Established
        let syn_ack = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 100,
            ack_num: 1,
            data_offset_flags: (5 << 12) | TCP_SYN | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&syn_ack, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::Established);
        match action {
            TcpAction::SendSegment { flags, .. } => {
                assert_eq!(flags, TCP_ACK);
            }
            _ => panic!("expected SendSegment"),
        }
        assert_eq!(conn.recv_next, 101);
    }

    // -- Three-way handshake (server side) --

    #[test]
    fn test_server_handshake() {
        let mut conn = TcpConnection::new();
        conn.local_ip = [10, 0, 0, 2];
        conn.listen(80).ok().unwrap();
        assert_eq!(conn.state, TcpState::Listen);

        // Receive SYN
        let syn = TcpHeader {
            source_port: 5000,
            dest_port: 80,
            seq_num: 0,
            ack_num: 0,
            data_offset_flags: (5 << 12) | TCP_SYN,
            window_size: 8192,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.accept_syn(&syn).ok().unwrap();
        assert_eq!(conn.state, TcpState::SynReceived);
        match action {
            TcpAction::SendSegment { flags, ack, .. } => {
                assert_eq!(flags, TCP_SYN | TCP_ACK);
                assert_eq!(ack, 1); // seq_num + 1
            }
            _ => panic!("expected SendSegment"),
        }

        // Receive ACK -> Established
        let ack_hdr = TcpHeader {
            source_port: 5000,
            dest_port: 80,
            seq_num: 1,
            ack_num: 101,
            data_offset_flags: (5 << 12) | TCP_ACK,
            window_size: 8192,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&ack_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::Established);
        assert_eq!(action, TcpAction::ConnectionEstablished);
    }

    // -- Data transfer --

    #[test]
    fn test_data_send_recv() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;
        conn.local_ip = [10, 0, 0, 1];
        conn.local_port = 5000;
        conn.remote_ip = [10, 0, 0, 2];
        conn.remote_port = 80;
        conn.send_next = 1;
        conn.recv_next = 1;

        // Buffer data for sending.
        let n = conn.send(b"hello").ok().unwrap();
        assert_eq!(n, 5);

        // Simulate receiving data.
        let data_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 1,
            ack_num: 1,
            data_offset_flags: (5 << 12) | TCP_ACK | TCP_PSH,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let payload = b"world";
        let action = conn.process_segment(&data_hdr, payload).ok().unwrap();

        // Should ACK the received data.
        match action {
            TcpAction::SendSegment { flags, ack, .. } => {
                assert_eq!(flags, TCP_ACK);
                assert_eq!(ack, 6); // 1 + 5
            }
            _ => panic!("expected SendSegment"),
        }

        // Read from receive buffer.
        let mut buf = [0u8; 32];
        let n = conn.recv(&mut buf).ok().unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"world");
    }

    // -- Active close (client) --

    #[test]
    fn test_active_close() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;
        conn.send_next = 10;
        conn.recv_next = 20;

        // close() -> FinWait1
        let action = conn.close().ok().unwrap();
        assert_eq!(conn.state, TcpState::FinWait1);
        match action {
            TcpAction::SendSegment { flags, seq, .. } => {
                assert_eq!(flags, TCP_FIN | TCP_ACK);
                assert_eq!(seq, 10);
            }
            _ => panic!("expected SendSegment"),
        }

        // Receive ACK of FIN -> FinWait2
        let ack_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 20,
            ack_num: 11,
            data_offset_flags: (5 << 12) | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&ack_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::FinWait2);
        assert_eq!(action, TcpAction::Nothing);

        // Receive FIN -> TimeWait
        let fin_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 20,
            ack_num: 11,
            data_offset_flags: (5 << 12) | TCP_FIN | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&fin_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::TimeWait);
        match action {
            TcpAction::SendSegment { flags, .. } => {
                assert_eq!(flags, TCP_ACK);
            }
            _ => panic!("expected SendSegment"),
        }
    }

    // -- Passive close (server) --

    #[test]
    fn test_passive_close() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;
        conn.send_next = 10;
        conn.recv_next = 20;

        // Receive FIN -> CloseWait
        let fin_hdr = TcpHeader {
            source_port: 5000,
            dest_port: 80,
            seq_num: 20,
            ack_num: 10,
            data_offset_flags: (5 << 12) | TCP_FIN | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&fin_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::CloseWait);
        match action {
            TcpAction::SendSegment { flags, .. } => {
                assert_eq!(flags, TCP_ACK);
            }
            _ => panic!("expected SendSegment"),
        }

        // Application calls close() -> LastAck
        let action = conn.close().ok().unwrap();
        assert_eq!(conn.state, TcpState::LastAck);
        match action {
            TcpAction::SendSegment { flags, .. } => {
                assert_eq!(flags, TCP_FIN | TCP_ACK);
            }
            _ => panic!("expected SendSegment"),
        }

        // Receive ACK of FIN -> Closed
        let ack_hdr = TcpHeader {
            source_port: 5000,
            dest_port: 80,
            seq_num: 21,
            ack_num: 11,
            data_offset_flags: (5 << 12) | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&ack_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::Closed);
        assert_eq!(action, TcpAction::ConnectionClosed);
    }

    // -- RST handling --

    #[test]
    fn test_rst_aborts_connection() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;

        let rst_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 0,
            ack_num: 0,
            data_offset_flags: (5 << 12) | TCP_RST,
            window_size: 0,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&rst_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::Closed);
        assert_eq!(action, TcpAction::ConnectionClosed);
    }

    // -- Simultaneous close (FinWait1 + FIN -> Closing) --

    #[test]
    fn test_simultaneous_close() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::FinWait1;
        conn.send_next = 11;
        conn.recv_next = 20;

        // Receive FIN without ACK for our FIN.
        let fin_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 20,
            ack_num: 10,
            data_offset_flags: (5 << 12) | TCP_FIN,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let _action = conn.process_segment(&fin_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::Closing);

        // Receive ACK -> TimeWait
        let ack_hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 21,
            ack_num: 11,
            data_offset_flags: (5 << 12) | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let action = conn.process_segment(&ack_hdr, &[]).ok().unwrap();
        assert_eq!(conn.state, TcpState::TimeWait);
        assert_eq!(action, TcpAction::Nothing);
    }

    // -- TcpTable --

    #[test]
    fn test_tcp_table_allocate_and_lookup() {
        let mut table = TcpTable::new();
        assert_eq!(table.active_count(), 0);

        {
            let conn = table.allocate().ok().unwrap();
            conn.local_ip = [10, 0, 0, 1];
            conn.local_port = 5000;
            conn.remote_ip = [10, 0, 0, 2];
            conn.remote_port = 80;
            conn.state = TcpState::Established;
        }
        assert_eq!(table.active_count(), 1);

        let found = table.lookup(&[10, 0, 0, 1], 5000, &[10, 0, 0, 2], 80);
        assert!(found.is_some());

        let not_found = table.lookup(&[10, 0, 0, 1], 5000, &[10, 0, 0, 3], 80);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_tcp_table_release() {
        let mut table = TcpTable::new();
        {
            let conn = table.allocate().ok().unwrap();
            conn.local_ip = [10, 0, 0, 1];
            conn.local_port = 5000;
            conn.remote_ip = [10, 0, 0, 2];
            conn.remote_port = 80;
        }
        assert_eq!(table.active_count(), 1);

        let released = table.release(&[10, 0, 0, 1], 5000, &[10, 0, 0, 2], 80);
        assert!(released);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn test_tcp_table_full() {
        let mut table = TcpTable::new();
        for i in 0..TCP_TABLE_SIZE {
            let conn = table.allocate().ok().unwrap();
            conn.local_port = i as u16;
        }
        assert_eq!(table.active_count(), TCP_TABLE_SIZE);
        assert!(table.allocate().is_err());
    }

    #[test]
    fn test_tcp_table_lookup_listener() {
        let mut table = TcpTable::new();
        {
            let conn = table.allocate().ok().unwrap();
            conn.local_ip = [0, 0, 0, 0];
            conn.local_port = 80;
            conn.state = TcpState::Listen;
        }

        let listener = table.lookup_listener(80);
        assert!(listener.is_some());

        let no_listener = table.lookup_listener(443);
        assert!(no_listener.is_none());
    }

    // -- Edge cases --

    #[test]
    fn test_send_when_not_established() {
        let mut conn = TcpConnection::new();
        assert!(conn.send(b"data").is_err());
    }

    #[test]
    fn test_recv_when_not_established() {
        let mut conn = TcpConnection::new();
        let mut buf = [0u8; 32];
        assert!(conn.recv(&mut buf).is_err());
    }

    #[test]
    fn test_connect_when_not_closed() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Listen;
        assert!(conn.connect([10, 0, 0, 1], 80).is_err());
    }

    #[test]
    fn test_listen_when_not_closed() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;
        assert!(conn.listen(80).is_err());
    }

    #[test]
    fn test_close_invalid_state() {
        let mut conn = TcpConnection::new();
        assert!(conn.close().is_err());
    }

    #[test]
    fn test_send_buffer_full() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;

        let big = [0xAA; SEND_BUF_SIZE];
        let n = conn.send(&big).ok().unwrap();
        assert_eq!(n, SEND_BUF_SIZE);

        // Buffer is full — should return 0.
        let n = conn.send(b"more").ok().unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_recv_partial() {
        let mut conn = TcpConnection::new();
        conn.state = TcpState::Established;
        conn.recv_next = 1;

        // Simulate receiving 10 bytes.
        let hdr = TcpHeader {
            source_port: 80,
            dest_port: 5000,
            seq_num: 1,
            ack_num: 1,
            data_offset_flags: (5 << 12) | TCP_ACK,
            window_size: 4096,
            checksum: 0,
            urgent_ptr: 0,
        };
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        conn.process_segment(&hdr, &payload).ok().unwrap();

        // Read only 4 bytes.
        let mut buf = [0u8; 4];
        let n = conn.recv(&mut buf).ok().unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [1, 2, 3, 4]);

        // Remaining 6 bytes should still be available.
        let mut buf2 = [0u8; 16];
        let n = conn.recv(&mut buf2).ok().unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf2[..6], &[5, 6, 7, 8, 9, 10]);
    }
}

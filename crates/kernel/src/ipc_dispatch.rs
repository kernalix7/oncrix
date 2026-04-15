// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel IPC dispatch — handles IPC syscalls and routes messages
//! between the kernel and user-space services.
//!
//! In the ONCRIX microkernel, IPC is a first-class kernel primitive.
//! The kernel intercepts IPC-related syscalls (512–516) in the
//! [`crate::arch::x86_64::syscall_entry`] wrapper and dispatches
//! them here, where they operate directly on the [`KernelState`]'s
//! [`ChannelRegistry`].
//!
//! # Message Protocol
//!
//! Services communicate through tagged messages. Each service defines
//! a range of message tags:
//!
//! | Range         | Service           |
//! |---------------|-------------------|
//! | `0x0100–01FF` | Console           |
//! | `0x0200–02FF` | Device Manager    |
//! | `0x0300–03FF` | Network Daemon    |
//! | `0xFF00–FFFF` | Kernel replies    |
//!
//! # Syscall Interface
//!
//! | Number | Name                  | Args                        |
//! |--------|-----------------------|-----------------------------|
//! | 512    | `IPC_SEND`            | endpoint_id, msg_ptr        |
//! | 513    | `IPC_RECEIVE`         | endpoint_id, msg_buf_ptr    |
//! | 514    | `IPC_REPLY`           | endpoint_id, msg_ptr        |
//! | 515    | `IPC_CALL`            | endpoint_id, msg_ptr        |
//! | 516    | `IPC_CREATE_ENDPOINT` | (none)                      |
//!
//! Reference: L4/seL4 IPC semantics, QNX message passing.

use core::sync::atomic::{AtomicU64, Ordering};

use oncrix_ipc::channel::ChannelRegistry;
use oncrix_ipc::message::{EndpointId, Message};
use oncrix_lib::Error;

// ── Message protocol tags ───────────────────────────────────────

/// Console service: write data to the kernel log.
pub const MSG_CONSOLE_WRITE: u32 = 0x0100;
/// Console service: read input from the console.
pub const MSG_CONSOLE_READ: u32 = 0x0101;
/// Console service: query terminal dimensions.
pub const MSG_CONSOLE_GET_SIZE: u32 = 0x0102;

/// Device manager: enumerate known devices.
pub const MSG_DEV_ENUMERATE: u32 = 0x0200;
/// Device manager: register a new device.
pub const MSG_DEV_REGISTER: u32 = 0x0201;
/// Device manager: open a device by name.
pub const MSG_DEV_OPEN: u32 = 0x0202;
/// Device manager: close a previously opened device.
pub const MSG_DEV_CLOSE: u32 = 0x0203;

/// Network daemon: configure an interface.
pub const MSG_NET_CONFIGURE: u32 = 0x0300;
/// Network daemon: send a packet.
pub const MSG_NET_SEND: u32 = 0x0301;
/// Network daemon: receive a queued packet.
pub const MSG_NET_RECEIVE: u32 = 0x0302;
/// Network daemon: query interface status.
pub const MSG_NET_STATUS: u32 = 0x0303;

/// Kernel reply: success (payload carries result data).
pub const MSG_REPLY_OK: u32 = 0xFF00;
/// Kernel reply: error (first 4 bytes of payload = error code).
pub const MSG_REPLY_ERROR: u32 = 0xFF01;

// ── Well-known endpoint IDs ─────────────────────────────────────

/// Kernel endpoint (always 0).
pub const EP_KERNEL: u64 = 0;
/// Console service endpoint.
pub const EP_CONSOLE: u64 = 1;
/// Device manager endpoint.
pub const EP_DEVMANAGER: u64 = 2;
/// Network daemon endpoint.
pub const EP_NETD: u64 = 3;

/// First dynamically allocated endpoint ID.
const EP_DYNAMIC_START: u64 = 64;

/// Next endpoint ID for dynamic allocation.
static NEXT_ENDPOINT_ID: AtomicU64 = AtomicU64::new(EP_DYNAMIC_START);

// ── Errno constants ─────────────────────────────────────────────

const ENOSYS: i64 = -38;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EAGAIN: i64 = -11;
const ENOENT: i64 = -2;
const EIO: i64 = -5;
const EFAULT: i64 = -14;

/// Convert a kernel error to a negative errno.
fn error_to_errno(err: Error) -> i64 {
    match err {
        Error::NotFound => ENOENT,
        Error::PermissionDenied => -13,
        Error::OutOfMemory => ENOMEM,
        Error::InvalidArgument => EINVAL,
        Error::AlreadyExists => -17,
        Error::WouldBlock => EAGAIN,
        Error::Busy => -16,
        Error::NotImplemented => ENOSYS,
        Error::Interrupted => -4,
        Error::IoError => EIO,
    }
}

// ── IPC syscall handlers ────────────────────────────────────────

/// `SYS_IPC_SEND` (512) — Send a message through a channel.
///
/// The caller specifies the destination endpoint. The kernel looks
/// up a channel where the current process is the source and the
/// given endpoint is the destination, then enqueues the message.
///
/// # Arguments
///
/// - `dst_endpoint`: destination endpoint ID
/// - `msg_ptr`: user-space pointer to a [`Message`] struct
///
/// # Returns
///
/// 0 on success, negative errno on failure.
pub fn kernel_ipc_send(dst_endpoint: u64, msg_ptr: u64) -> i64 {
    if msg_ptr == 0 {
        return EFAULT;
    }

    crate::state::with_global_mut(|state| {
        let dst = EndpointId::new(dst_endpoint);

        // Build a kernel-side message.
        // In a full implementation this would copy_from_user the
        // Message struct from msg_ptr. For now, we construct a
        // minimal message from the raw arguments.
        //
        // msg_ptr layout (user convention):
        //   [0..8]   sender endpoint (filled by kernel)
        //   [8..16]  receiver endpoint (must match dst_endpoint)
        //   [16..20] tag (u32)
        //   [20..24] payload_len (u32)
        //   [24..]   payload bytes
        //
        // Until real user-space exists, we accept the raw pointer
        // as a tag value for testing (send a message with tag=msg_ptr
        // and no payload).
        let src = EndpointId::new(EP_KERNEL);
        let msg = Message::new(src, dst, msg_ptr as u32);

        // Find the channel src→dst and enqueue.
        match state.channels.find_mut(src, dst) {
            Some(ch) => match ch.send(&msg) {
                Ok(()) => 0,
                Err(e) => error_to_errno(e),
            },
            None => {
                // Try the reverse direction (dst→src) — channels
                // are bidirectional but stored by creation order.
                match state.channels.find_mut(dst, src) {
                    Some(ch) => match ch.send(&msg) {
                        Ok(()) => 0,
                        Err(e) => error_to_errno(e),
                    },
                    None => ENOENT,
                }
            }
        }
    })
    .unwrap_or(ENOSYS)
}

/// `SYS_IPC_RECEIVE` (513) — Receive a message from a channel.
///
/// Dequeues the next message addressed to `endpoint_id`.
///
/// # Arguments
///
/// - `endpoint_id`: the receiving endpoint
/// - `msg_buf_ptr`: user-space pointer to a buffer for the received
///   [`Message`]
///
/// # Returns
///
/// Number of payload bytes received on success, negative errno on
/// failure. Returns `-EAGAIN` if no message is available.
pub fn kernel_ipc_receive(endpoint_id: u64, msg_buf_ptr: u64) -> i64 {
    if msg_buf_ptr == 0 {
        return EFAULT;
    }

    crate::state::with_global_mut(|state| {
        let ep = EndpointId::new(endpoint_id);

        // Search all channels where this endpoint is the destination.
        if let Some(msg) = try_receive_for(&mut state.channels, ep) {
            // In a full implementation we would copy_to_user the
            // Message to msg_buf_ptr. For now return the payload
            // length to indicate success.
            //
            // If the message is destined for a kernel service,
            // dispatch it internally and write the reply.
            if endpoint_id == EP_KERNEL {
                let reply = dispatch_to_kernel_service(msg.tag(), msg.payload());
                // Enqueue the reply on the reverse channel.
                let _ = enqueue_reply(&mut state.channels, ep, msg.header.sender, &reply);
                return reply.header.payload_len as i64;
            }
            msg.header.payload_len as i64
        } else {
            EAGAIN
        }
    })
    .unwrap_or(ENOSYS)
}

/// `SYS_IPC_REPLY` (514) — Reply to a previously received message.
///
/// Sends a reply message back to the original sender.
///
/// # Arguments
///
/// - `dst_endpoint`: the endpoint to reply to
/// - `msg_ptr`: user-space pointer to the reply [`Message`]
///
/// # Returns
///
/// 0 on success, negative errno on failure.
pub fn kernel_ipc_reply(dst_endpoint: u64, msg_ptr: u64) -> i64 {
    // Reply is semantically identical to send for the channel
    // implementation — the difference is in the protocol layer
    // (reply messages use MSG_REPLY_OK/MSG_REPLY_ERROR tags).
    kernel_ipc_send(dst_endpoint, msg_ptr)
}

/// `SYS_IPC_CALL` (515) — Synchronous send + receive.
///
/// Sends a message and blocks until a reply arrives on the same
/// channel. This is the primary IPC pattern for client→server
/// requests.
///
/// # Arguments
///
/// - `dst_endpoint`: destination service endpoint
/// - `msg_ptr`: user-space pointer to the request [`Message`];
///   the reply overwrites this buffer
///
/// # Returns
///
/// Number of reply payload bytes on success, negative errno on
/// failure.
pub fn kernel_ipc_call(dst_endpoint: u64, msg_ptr: u64) -> i64 {
    if msg_ptr == 0 {
        return EFAULT;
    }

    crate::state::with_global_mut(|state| {
        let src = EndpointId::new(EP_KERNEL);
        let dst = EndpointId::new(dst_endpoint);
        let msg = Message::new(src, dst, msg_ptr as u32);

        // Phase 1: Send the request.
        let send_result = send_on_channel(&mut state.channels, src, dst, &msg);
        if send_result < 0 {
            return send_result;
        }

        // Phase 2: Dispatch to the target service if it is a
        // kernel-internal endpoint.
        if dst_endpoint <= EP_NETD {
            let reply = dispatch_to_kernel_service(msg.tag(), msg.payload());
            // Write reply back — in a real implementation this
            // would copy_to_user. Return the payload length.
            return reply.header.payload_len as i64;
        }

        // For external services, we would block the calling thread
        // and wait for a reply. Until the scheduler supports
        // blocking IPC, return EAGAIN.
        EAGAIN
    })
    .unwrap_or(ENOSYS)
}

/// `SYS_IPC_CREATE_ENDPOINT` (516) — Allocate a new endpoint ID.
///
/// Returns a unique endpoint ID that the calling process can use
/// for IPC. The endpoint is not connected to any channel yet;
/// the caller must arrange for a channel to be created (via the
/// kernel or a service manager).
///
/// # Returns
///
/// The new endpoint ID (>= 64) on success, negative errno on
/// failure.
pub fn kernel_ipc_create_endpoint() -> i64 {
    let id = NEXT_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed);
    if id > u32::MAX as u64 {
        // Overflow — extremely unlikely but handle gracefully.
        return ENOMEM;
    }
    id as i64
}

// ── Channel helpers ─────────────────────────────────────────────

/// Try to receive a message destined for `ep` from any channel.
///
/// Scans the registry for a channel where `ep` is either the
/// source or destination, and the ring buffer is non-empty.
fn try_receive_for(reg: &mut ChannelRegistry, ep: EndpointId) -> Option<Message> {
    // We need to scan all channels. ChannelRegistry doesn't expose
    // an iterator, so we probe known endpoint pairs. For a
    // production kernel this would use a proper per-endpoint
    // receive queue.
    //
    // Try each well-known remote endpoint.
    for remote_id in [EP_KERNEL, EP_CONSOLE, EP_DEVMANAGER, EP_NETD] {
        let remote = EndpointId::new(remote_id);
        if remote == ep {
            continue;
        }
        // Channel stored as (remote → ep)?
        if let Some(ch) = reg.find_mut(remote, ep) {
            if !ch.is_empty() {
                if let Ok(msg) = ch.receive() {
                    return Some(msg);
                }
            }
        }
        // Channel stored as (ep → remote)?
        if let Some(ch) = reg.find_mut(ep, remote) {
            if !ch.is_empty() {
                if let Ok(msg) = ch.receive() {
                    return Some(msg);
                }
            }
        }
    }
    None
}

/// Send a message on the channel between `src` and `dst`.
///
/// Handles both channel orientations (src→dst and dst→src).
fn send_on_channel(
    reg: &mut ChannelRegistry,
    src: EndpointId,
    dst: EndpointId,
    msg: &Message,
) -> i64 {
    if let Some(ch) = reg.find_mut(src, dst) {
        return match ch.send(msg) {
            Ok(()) => 0,
            Err(e) => error_to_errno(e),
        };
    }
    if let Some(ch) = reg.find_mut(dst, src) {
        return match ch.send(msg) {
            Ok(()) => 0,
            Err(e) => error_to_errno(e),
        };
    }
    ENOENT
}

/// Enqueue a reply message from `src` to `dst`.
fn enqueue_reply(
    reg: &mut ChannelRegistry,
    src: EndpointId,
    dst: EndpointId,
    reply: &Message,
) -> i64 {
    send_on_channel(reg, src, dst, reply)
}

// ── Kernel service dispatch ─────────────────────────────────────

/// Route a message to the appropriate kernel-internal service
/// handler based on its tag.
///
/// Returns a reply message to be sent back to the caller.
fn dispatch_to_kernel_service(tag: u32, payload: &[u8]) -> Message {
    match tag & 0xFF00 {
        0x0100 => handle_console_message(tag, payload),
        0x0200 => handle_devmanager_message(tag, payload),
        0x0300 => handle_netd_message(tag, payload),
        _ => make_error_reply(EndpointId::new(EP_KERNEL), EINVAL as u32),
    }
}

// ── Console service handler ─────────────────────────────────────

/// Handle a message destined for the console service.
fn handle_console_message(tag: u32, payload: &[u8]) -> Message {
    match tag {
        MSG_CONSOLE_WRITE => {
            // Write payload bytes to the serial console.
            #[cfg(target_arch = "x86_64")]
            {
                use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
                use oncrix_hal::serial::SerialPort;
                let mut serial = Uart16550::new(COM1);
                for &byte in payload {
                    let _ = serial.write_byte(byte);
                }
            }
            // Reply with the number of bytes written.
            let mut reply = Message::new(
                EndpointId::new(EP_CONSOLE),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            );
            let len = (payload.len() as u32).to_le_bytes();
            let _ = reply.set_payload(&len);
            reply
        }
        MSG_CONSOLE_READ => {
            // Console read is not yet implemented — return empty.
            Message::new(
                EndpointId::new(EP_CONSOLE),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            )
        }
        MSG_CONSOLE_GET_SIZE => {
            // Return default 80×25 terminal size.
            let mut reply = Message::new(
                EndpointId::new(EP_CONSOLE),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            );
            let mut buf = [0u8; 4];
            buf[0] = 80; // columns
            buf[1] = 0;
            buf[2] = 25; // rows
            buf[3] = 0;
            let _ = reply.set_payload(&buf);
            reply
        }
        _ => make_error_reply(EndpointId::new(EP_CONSOLE), EINVAL as u32),
    }
}

// ── Device manager service handler ──────────────────────────────

/// Handle a message destined for the device manager.
fn handle_devmanager_message(tag: u32, payload: &[u8]) -> Message {
    match tag {
        MSG_DEV_ENUMERATE => {
            // Return a summary of known device count.
            // In a real implementation this would query the device
            // registry. For now return 0 devices.
            let mut reply = Message::new(
                EndpointId::new(EP_DEVMANAGER),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            );
            let count = 0u32.to_le_bytes();
            let _ = reply.set_payload(&count);
            reply
        }
        MSG_DEV_REGISTER => {
            // Accept a device registration request.
            // Payload: device name (variable length string).
            if payload.is_empty() {
                return make_error_reply(EndpointId::new(EP_DEVMANAGER), EINVAL as u32);
            }
            // Acknowledge registration.
            Message::new(
                EndpointId::new(EP_DEVMANAGER),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            )
        }
        MSG_DEV_OPEN | MSG_DEV_CLOSE => {
            // Stub: acknowledge the request.
            Message::new(
                EndpointId::new(EP_DEVMANAGER),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            )
        }
        _ => make_error_reply(EndpointId::new(EP_DEVMANAGER), EINVAL as u32),
    }
}

// ── Network daemon service handler ──────────────────────────────

/// Handle a message destined for the network daemon.
fn handle_netd_message(tag: u32, payload: &[u8]) -> Message {
    match tag {
        MSG_NET_STATUS => {
            // Return network status: 0 = down, 1 = up.
            let mut reply = Message::new(
                EndpointId::new(EP_NETD),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            );
            // Network is down during early boot.
            let status = 0u32.to_le_bytes();
            let _ = reply.set_payload(&status);
            reply
        }
        MSG_NET_CONFIGURE => {
            // Accept configuration but no-op for now.
            if payload.is_empty() {
                return make_error_reply(EndpointId::new(EP_NETD), EINVAL as u32);
            }
            Message::new(
                EndpointId::new(EP_NETD),
                EndpointId::new(EP_KERNEL),
                MSG_REPLY_OK,
            )
        }
        MSG_NET_SEND | MSG_NET_RECEIVE => {
            // Network I/O not yet available.
            make_error_reply(EndpointId::new(EP_NETD), EAGAIN.unsigned_abs() as u32)
        }
        _ => make_error_reply(EndpointId::new(EP_NETD), EINVAL as u32),
    }
}

// ── Reply helpers ───────────────────────────────────────────────

/// Construct an error reply message.
///
/// The first 4 bytes of the payload carry the error code as a
/// little-endian u32.
fn make_error_reply(sender: EndpointId, error_code: u32) -> Message {
    let mut reply = Message::new(sender, EndpointId::new(EP_KERNEL), MSG_REPLY_ERROR);
    let code = error_code.to_le_bytes();
    let _ = reply.set_payload(&code);
    reply
}

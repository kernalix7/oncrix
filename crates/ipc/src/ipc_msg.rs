// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System V message queues — `msgget` / `msgsnd` / `msgrcv` / `msgctl`.
//!
//! Implements the System V message-queue API as defined by POSIX.1-2024.
//! Each queue holds up to [`MSG_QUEUE_DEPTH`] messages and is identified
//! by a numeric key.  Messages are typed (`mtype > 0`) and retrieved
//! selectively:
//!
//! - `msgtyp == 0`: return the first message.
//! - `msgtyp > 0`:  return the first message with `mtype == msgtyp`.
//! - `msgtyp < 0`:  return the first message with `mtype <= |msgtyp|`.
//!
//! # Supported `msgctl` commands
//!
//! `IPC_RMID`, `IPC_STAT`, `IPC_SET`, `IPC_INFO`, `MSG_INFO`,
//! `MSG_STAT`.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/msgget.html` and
//! `msgsnd.html` for the authoritative specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum text payload per message (bytes).
pub const MSG_MAX_TEXT: usize = 4096;

/// Maximum number of messages in one queue.
const MSG_QUEUE_DEPTH: usize = 32;

/// Maximum number of simultaneous message queues.
const MSG_REGISTRY_MAX: usize = 32;

/// Default maximum bytes a queue may hold.
pub const MSG_DEFAULT_MAX_BYTES: u64 = (MSG_MAX_TEXT * MSG_QUEUE_DEPTH) as u64;

// ---------------------------------------------------------------------------
// IPC flags and msgctl commands
// ---------------------------------------------------------------------------

/// Create a new IPC object.
pub const IPC_CREAT: i32 = 0o001000;
/// Fail if the object already exists (with `IPC_CREAT`).
pub const IPC_EXCL: i32 = 0o002000;
/// Private IPC key.
pub const IPC_PRIVATE: u32 = 0;
/// Don't block; return `WouldBlock` instead.
pub const IPC_NOWAIT: i32 = 0o004000;

/// Remove the message queue.
pub const IPC_RMID: i32 = 0;
/// Update ownership/permissions.
pub const IPC_SET: i32 = 1;
/// Retrieve the `MsqDs` status structure.
pub const IPC_STAT: i32 = 2;
/// Get kernel-wide message-queue limits.
pub const IPC_INFO: i32 = 3;
/// Retrieve per-queue live statistics.
pub const MSG_STAT: i32 = 11;
/// Get system-wide message-queue statistics.
pub const MSG_INFO: i32 = 12;

// ---------------------------------------------------------------------------
// IpcMessage
// ---------------------------------------------------------------------------

/// A single message stored in a queue.
///
/// Mirrors the POSIX `msgbuf` layout: a long `mtype` followed by
/// up to `MSG_MAX_TEXT` bytes of payload.
pub struct IpcMessage {
    /// Message type (must be > 0 when sending).
    pub mtype: i64,
    /// Payload data.
    pub mtext: [u8; MSG_MAX_TEXT],
    /// Number of valid bytes in `mtext`.
    pub msize: usize,
    /// PID of the sender.
    pub sender_pid: u32,
}

impl IpcMessage {
    /// Create an empty message.
    pub const fn new() -> Self {
        Self {
            mtype: 0,
            mtext: [0u8; MSG_MAX_TEXT],
            msize: 0,
            sender_pid: 0,
        }
    }

    /// Return the payload as a byte slice.
    pub fn text(&self) -> &[u8] {
        &self.mtext[..self.msize]
    }
}

impl Default for IpcMessage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MsgPerm
// ---------------------------------------------------------------------------

/// IPC permission structure for message queues.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsgPerm {
    /// User ID of the creator.
    pub cuid: u32,
    /// Group ID of the creator.
    pub cgid: u32,
    /// Effective user ID of the owner.
    pub uid: u32,
    /// Effective group ID of the owner.
    pub gid: u32,
    /// Permission mode bits (low 9 bits).
    pub mode: u16,
}

// ---------------------------------------------------------------------------
// MsqDs — status structure for IPC_STAT / MSG_STAT
// ---------------------------------------------------------------------------

/// Status structure for a message queue (`struct msqid_ds`).
#[derive(Debug, Clone, Copy, Default)]
pub struct MsqDs {
    /// Permission information.
    pub msg_perm: MsgPerm,
    /// Maximum bytes allowed on the queue.
    pub msg_qbytes: u64,
    /// Current bytes on the queue.
    pub msg_cbytes: u64,
    /// Current number of messages.
    pub msg_qnum: u64,
    /// PID of last `msgsnd` caller.
    pub msg_lspid: u32,
    /// PID of last `msgrcv` caller.
    pub msg_lrpid: u32,
    /// Time of last `msgsnd`.
    pub msg_stime: u64,
    /// Time of last `msgrcv`.
    pub msg_rtime: u64,
    /// Time of last change.
    pub msg_ctime: u64,
}

// ---------------------------------------------------------------------------
// MsgQueue
// ---------------------------------------------------------------------------

/// A System V message queue.
pub struct MsgQueue {
    /// IPC key.
    pub key: u32,
    /// Whether this queue has been marked for removal.
    removed: bool,
    /// Stored messages (ring buffer by insertion order).
    messages: [IpcMessage; MSG_QUEUE_DEPTH],
    /// Number of messages currently stored.
    count: usize,
    /// Write index (next insertion point in the ring).
    write_idx: usize,
    /// Read index (oldest message position in the ring).
    read_idx: usize,
    /// Permission information.
    perm: MsgPerm,
    /// Maximum bytes allowed on this queue.
    max_bytes: u64,
    /// Current bytes on this queue.
    current_bytes: u64,
    /// PID of last `msgsnd`.
    lspid: u32,
    /// PID of last `msgrcv`.
    lrpid: u32,
    /// Monotonic tick of last `msgsnd`.
    stime: u64,
    /// Monotonic tick of last `msgrcv`.
    rtime: u64,
    /// Monotonic tick of last change.
    ctime: u64,
}

impl MsgQueue {
    /// Create a new, empty message queue.
    fn new(key: u32, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            key,
            removed: false,
            messages: [const { IpcMessage::new() }; MSG_QUEUE_DEPTH],
            count: 0,
            write_idx: 0,
            read_idx: 0,
            perm: MsgPerm {
                cuid: uid,
                cgid: gid,
                uid,
                gid,
                mode,
            },
            max_bytes: MSG_DEFAULT_MAX_BYTES,
            current_bytes: 0,
            lspid: 0,
            lrpid: 0,
            stime: 0,
            rtime: 0,
            ctime: 0,
        }
    }

    /// Return the status structure.
    pub fn stat(&self) -> MsqDs {
        MsqDs {
            msg_perm: self.perm,
            msg_qbytes: self.max_bytes,
            msg_cbytes: self.current_bytes,
            msg_qnum: self.count as u64,
            msg_lspid: self.lspid,
            msg_lrpid: self.lrpid,
            msg_stime: self.stime,
            msg_rtime: self.rtime,
            msg_ctime: self.ctime,
        }
    }

    /// Return `true` if the queue is full.
    fn is_full(&self) -> bool {
        self.count >= MSG_QUEUE_DEPTH
    }

    /// Enqueue a message.
    fn enqueue(&mut self, mtype: i64, data: &[u8], msgsz: usize, sender_pid: u32) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        let actual = msgsz.min(data.len()).min(MSG_MAX_TEXT);
        if self.current_bytes + actual as u64 > self.max_bytes {
            return Err(Error::WouldBlock);
        }

        let slot = &mut self.messages[self.write_idx];
        slot.mtype = mtype;
        slot.msize = actual;
        slot.mtext[..actual].copy_from_slice(&data[..actual]);
        slot.sender_pid = sender_pid;

        self.write_idx = (self.write_idx + 1) % MSG_QUEUE_DEPTH;
        self.count += 1;
        self.current_bytes += actual as u64;
        self.lspid = sender_pid;
        self.stime = self.stime.wrapping_add(1);
        Ok(())
    }

    /// Find the index of the first matching message for `msgtyp`.
    ///
    /// Returns `None` if no match is found.
    fn find_message(&self, msgtyp: i64) -> Option<usize> {
        if self.count == 0 {
            return None;
        }

        if msgtyp == 0 {
            // First message in queue order.
            return Some(self.read_idx);
        }

        if msgtyp > 0 {
            // First message with exact type.
            for i in 0..self.count {
                let idx = (self.read_idx + i) % MSG_QUEUE_DEPTH;
                if self.messages[idx].mtype == msgtyp {
                    return Some(idx);
                }
            }
            return None;
        }

        // msgtyp < 0: find the message with the smallest type <= |msgtyp|.
        let limit = -msgtyp;
        let mut best_idx: Option<usize> = None;
        let mut best_type: i64 = i64::MAX;

        for i in 0..self.count {
            let idx = (self.read_idx + i) % MSG_QUEUE_DEPTH;
            let t = self.messages[idx].mtype;
            if t <= limit && t < best_type {
                best_type = t;
                best_idx = Some(idx);
            }
        }

        best_idx
    }

    /// Dequeue the message at physical index `phys_idx`.
    ///
    /// Shifts remaining messages to maintain logical order.
    fn dequeue_at(
        &mut self,
        phys_idx: usize,
        buf: &mut [u8],
        msgsz: usize,
        receiver_pid: u32,
    ) -> Result<(usize, i64)> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }

        let msg_size = self.messages[phys_idx].msize;
        let mtype = self.messages[phys_idx].mtype;

        if msg_size > msgsz {
            // Message too large for the buffer — Linux returns E2BIG.
            return Err(Error::InvalidArgument);
        }

        let copy_len = msg_size.min(buf.len());
        buf[..copy_len].copy_from_slice(&self.messages[phys_idx].mtext[..copy_len]);

        // Compact: shift slots between `phys_idx` and `write_idx`.
        // We walk forward from phys_idx, overwriting each slot with the next.
        let mut cur = phys_idx;
        let remaining = self.count - 1;
        let mut steps = 0usize;

        // Determine how many slots are logically after phys_idx.
        // This is the number of positions from phys_idx to write_idx - 1.
        let write_before = self.write_idx;
        // Number of logical slots after phys_idx in the ring.
        let after = if write_before > phys_idx {
            write_before - phys_idx - 1
        } else if write_before < phys_idx {
            (MSG_QUEUE_DEPTH - phys_idx - 1) + write_before
        } else {
            // write_idx == phys_idx → this was the only slot
            0
        };

        while steps < after {
            let next = (cur + 1) % MSG_QUEUE_DEPTH;
            // Copy next into cur.
            let (mtype_n, msize_n, mpid_n) = {
                let n = &self.messages[next];
                (n.mtype, n.msize, n.sender_pid)
            };
            let mtext_copy = {
                let n = &self.messages[next];
                let mut tmp = [0u8; MSG_MAX_TEXT];
                tmp[..msize_n].copy_from_slice(&n.mtext[..msize_n]);
                tmp
            };
            let slot = &mut self.messages[cur];
            slot.mtype = mtype_n;
            slot.msize = msize_n;
            slot.sender_pid = mpid_n;
            slot.mtext[..msize_n].copy_from_slice(&mtext_copy[..msize_n]);

            cur = next;
            steps += 1;
        }

        // Adjust write index back by one.
        self.write_idx = (self.write_idx + MSG_QUEUE_DEPTH - 1) % MSG_QUEUE_DEPTH;
        // Clear the vacated slot.
        self.messages[self.write_idx] = IpcMessage::new();

        self.count = remaining;
        self.current_bytes = self.current_bytes.saturating_sub(msg_size as u64);
        self.lrpid = receiver_pid;
        self.rtime = self.rtime.wrapping_add(1);

        Ok((copy_len, mtype))
    }
}

// ---------------------------------------------------------------------------
// MsgStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the message queue subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsgStats {
    /// Total messages sent across all queues.
    pub total_sent: u64,
    /// Total messages received across all queues.
    pub total_received: u64,
    /// Total queues ever created.
    pub total_queues: u64,
    /// Current bytes across all active queues.
    pub bytes_in_queues: u64,
}

// ---------------------------------------------------------------------------
// MsgRegistry
// ---------------------------------------------------------------------------

/// Global registry of System V message queues.
pub struct MsgRegistry {
    /// Queue slots.
    queues: [Option<MsgQueue>; MSG_REGISTRY_MAX],
    /// Cumulative statistics.
    pub stats: MsgStats,
}

impl MsgRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            queues: [const { None }; MSG_REGISTRY_MAX],
            stats: MsgStats {
                total_sent: 0,
                total_received: 0,
                total_queues: 0,
                bytes_in_queues: 0,
            },
        }
    }

    // -- internal helpers --------------------------------------------------

    /// Find a queue slot by key (ignoring removed queues).
    fn find_by_key(&self, key: u32) -> Option<usize> {
        if key == IPC_PRIVATE {
            return None;
        }
        self.queues
            .iter()
            .position(|q| q.as_ref().map_or(false, |mq| mq.key == key && !mq.removed))
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.queues.iter().position(|q| q.is_none())
    }

    /// Validate that `msqid` is valid and the queue is active.
    fn check_msqid(&self, msqid: usize) -> Result<()> {
        if msqid >= MSG_REGISTRY_MAX {
            return Err(Error::InvalidArgument);
        }
        match self.queues[msqid] {
            Some(ref q) if !q.removed => Ok(()),
            _ => Err(Error::NotFound),
        }
    }
}

impl Default for MsgRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// msgget
// ---------------------------------------------------------------------------

/// Create or open a message queue.
///
/// Returns the message queue identifier (index) on success.
pub fn msgget(
    registry: &mut MsgRegistry,
    key: u32,
    flags: i32,
    uid: u32,
    gid: u32,
) -> Result<usize> {
    let mode = (flags & 0o777) as u16;
    let creat = flags & IPC_CREAT != 0;
    let excl = flags & IPC_EXCL != 0;

    if key != IPC_PRIVATE {
        if let Some(idx) = registry.find_by_key(key) {
            if creat && excl {
                return Err(Error::AlreadyExists);
            }
            return Ok(idx);
        }
    }

    if key != IPC_PRIVATE && !creat {
        return Err(Error::NotFound);
    }

    let idx = registry.find_free().ok_or(Error::OutOfMemory)?;
    registry.queues[idx] = Some(MsgQueue::new(key, mode, uid, gid));
    registry.stats.total_queues = registry.stats.total_queues.saturating_add(1);
    Ok(idx)
}

// ---------------------------------------------------------------------------
// msgsnd
// ---------------------------------------------------------------------------

/// Send a message to a queue.
///
/// `msgtyp` must be > 0 (encoded in `msgp.mtype`).
/// If the queue is full and `IPC_NOWAIT` is set, returns `WouldBlock`.
pub fn msgsnd(
    registry: &mut MsgRegistry,
    msqid: usize,
    mtype: i64,
    msgp: &[u8],
    msgsz: usize,
    flags: i32,
    sender_pid: u32,
) -> Result<()> {
    registry.check_msqid(msqid)?;

    if mtype <= 0 {
        return Err(Error::InvalidArgument);
    }
    if msgsz > MSG_MAX_TEXT {
        return Err(Error::InvalidArgument);
    }

    // Check capacity before mutating.
    let would_block = {
        let queue = registry.queues[msqid].as_ref().ok_or(Error::NotFound)?;
        queue.is_full() || queue.current_bytes + msgsz as u64 > queue.max_bytes
    };
    if would_block {
        // IPC_NOWAIT controls whether we block (currently always non-blocking).
        let _ = flags;
        return Err(Error::WouldBlock);
    }

    let actual = msgsz.min(msgp.len());
    {
        let queue = registry.queues[msqid].as_mut().ok_or(Error::NotFound)?;
        queue.enqueue(mtype, msgp, actual, sender_pid)?;
    }

    registry.stats.total_sent = registry.stats.total_sent.saturating_add(1);
    registry.stats.bytes_in_queues = registry.stats.bytes_in_queues.saturating_add(actual as u64);
    Ok(())
}

// ---------------------------------------------------------------------------
// msgrcv
// ---------------------------------------------------------------------------

/// Receive a message from a queue.
///
/// Returns `(bytes_copied, mtype)` on success.
/// The `msgtyp` argument controls message selection (see module docs).
pub fn msgrcv(
    registry: &mut MsgRegistry,
    msqid: usize,
    buf: &mut [u8],
    msgsz: usize,
    msgtyp: i64,
    flags: i32,
    receiver_pid: u32,
) -> Result<(usize, i64)> {
    registry.check_msqid(msqid)?;

    let queue = registry.queues[msqid].as_mut().ok_or(Error::NotFound)?;

    let phys_idx = match queue.find_message(msgtyp) {
        Some(i) => i,
        None => {
            if flags & IPC_NOWAIT != 0 {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
    };

    let (n, mtype) = queue.dequeue_at(phys_idx, buf, msgsz, receiver_pid)?;

    registry.stats.total_received = registry.stats.total_received.saturating_add(1);
    registry.stats.bytes_in_queues = registry.stats.bytes_in_queues.saturating_sub(n as u64);
    Ok((n, mtype))
}

// ---------------------------------------------------------------------------
// msgctl
// ---------------------------------------------------------------------------

/// Perform a control operation on a message queue.
///
/// Returns 0 on success for most commands; for `IPC_INFO` / `MSG_INFO`
/// returns the number of active queues.
pub fn msgctl(
    registry: &mut MsgRegistry,
    msqid: usize,
    cmd: i32,
    new_ds: Option<&MsqDs>,
) -> Result<i32> {
    match cmd {
        IPC_RMID => {
            if msqid >= MSG_REGISTRY_MAX {
                return Err(Error::InvalidArgument);
            }
            if registry.queues[msqid].is_none() {
                return Err(Error::NotFound);
            }
            if let Some(ref q) = registry.queues[msqid] {
                registry.stats.bytes_in_queues = registry
                    .stats
                    .bytes_in_queues
                    .saturating_sub(q.current_bytes);
            }
            registry.queues[msqid] = None;
            Ok(0)
        }

        IPC_STAT | MSG_STAT => {
            registry.check_msqid(msqid)?;
            let _ds = registry.queues[msqid]
                .as_ref()
                .ok_or(Error::NotFound)?
                .stat();
            // In a real kernel this would copy `_ds` to user-space.
            Ok(0)
        }

        IPC_SET => {
            registry.check_msqid(msqid)?;
            if let Some(ds) = new_ds {
                let queue = registry.queues[msqid].as_mut().ok_or(Error::NotFound)?;
                queue.perm.uid = ds.msg_perm.uid;
                queue.perm.gid = ds.msg_perm.gid;
                queue.perm.mode = ds.msg_perm.mode & 0o777;
                if ds.msg_qbytes > 0 {
                    queue.max_bytes = ds.msg_qbytes;
                }
                queue.ctime = queue.ctime.wrapping_add(1);
            }
            Ok(0)
        }

        IPC_INFO | MSG_INFO => {
            let active = registry.queues.iter().filter(|q| q.is_some()).count();
            Ok(active as i32)
        }

        _ => Err(Error::InvalidArgument),
    }
}

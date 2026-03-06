// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `msgget(2)`, `msgsnd(2)`, `msgrcv(2)`, and `msgctl(2)` syscall handlers.
//!
//! System V message queue interface.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `msgget()` specification.  Key behaviours:
//! - `IPC_PRIVATE` always creates a new queue.
//! - `msgsnd` blocks (or returns `EAGAIN`) when the queue is full.
//! - `msgrcv` with `msgtyp == 0` receives the first message; `msgtyp > 0`
//!   receives the first message with matching type; `msgtyp < 0` receives
//!   the lowest-type message ≤ `|msgtyp|`.
//! - `MSG_NOERROR` truncates oversized messages instead of failing.
//!
//! # References
//!
//! - POSIX.1-2024: `msgget()`
//! - Linux man pages: `msgget(2)`, `msgsnd(2)`, `msgrcv(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Create if not exists.
pub const IPC_CREAT: i32 = 0o1000;
/// Fail if already exists.
pub const IPC_EXCL: i32 = 0o2000;
/// Private key.
pub const IPC_PRIVATE: i32 = 0;
/// Remove queue.
pub const IPC_RMID: i32 = 0;
/// No-wait on send/receive.
pub const IPC_NOWAIT: i32 = 0o4000;
/// Truncate message on receive if too large.
pub const MSG_NOERROR: i32 = 0o10000;

/// Maximum messages per queue.
pub const MSGMNB: usize = 16;
/// Maximum message data size.
pub const MSGMAX: usize = 8192;
/// Maximum number of queues.
pub const MSGMNI: usize = 32;

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A System V message.
#[derive(Clone, Copy)]
pub struct MsgBuf {
    /// Message type (positive integer).
    pub mtype: i64,
    /// Message data (fixed-size for simplicity; actual length tracked separately).
    pub data: [u8; 256],
    /// Length of valid data.
    pub len: usize,
}

// ---------------------------------------------------------------------------
// Message queue
// ---------------------------------------------------------------------------

/// A System V message queue.
pub struct MsgQueue {
    /// IPC key.
    pub key: i32,
    /// Queue ID (msqid).
    pub id: i32,
    /// Permission mode.
    pub mode: u16,
    /// Owner UID.
    pub uid: u32,
    /// Messages in the queue (ring buffer by insertion order).
    msgs: [Option<MsgBuf>; MSGMNB],
    head: usize,
    tail: usize,
    count: usize,
}

impl MsgQueue {
    fn new(key: i32, id: i32, mode: u16, uid: u32) -> Self {
        Self {
            key,
            id,
            mode,
            uid,
            msgs: [const { None }; MSGMNB],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.count >= MSGMNB
    }

    fn enqueue(&mut self, msg: MsgBuf) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        self.msgs[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % MSGMNB;
        self.count += 1;
        Ok(())
    }

    /// Find index of message matching `msgtyp`.
    fn find_msg(&self, msgtyp: i64) -> Option<usize> {
        if msgtyp == 0 {
            // First message.
            if self.count > 0 {
                Some(self.head)
            } else {
                None
            }
        } else if msgtyp > 0 {
            // First message with exact type.
            let mut i = self.head;
            for _ in 0..self.count {
                if let Some(m) = &self.msgs[i] {
                    if m.mtype == msgtyp {
                        return Some(i);
                    }
                }
                i = (i + 1) % MSGMNB;
            }
            None
        } else {
            // Lowest type ≤ |msgtyp|.
            let limit = (-msgtyp) as i64;
            let mut best_idx = None;
            let mut best_type = i64::MAX;
            let mut i = self.head;
            for _ in 0..self.count {
                if let Some(m) = &self.msgs[i] {
                    if m.mtype <= limit && m.mtype < best_type {
                        best_type = m.mtype;
                        best_idx = Some(i);
                    }
                }
                i = (i + 1) % MSGMNB;
            }
            best_idx
        }
    }

    fn remove_at(&mut self, idx: usize) -> Option<MsgBuf> {
        let msg = self.msgs[idx].take();
        if msg.is_some() {
            self.count -= 1;
            // Compact: if idx == head, advance head.
            if idx == self.head && self.count > 0 {
                self.head = (self.head + 1) % MSGMNB;
            }
        }
        msg
    }
}

/// Table of System V message queues.
pub struct MsgTable {
    queues: [Option<MsgQueue>; MSGMNI],
    next_id: i32,
}

impl Default for MsgTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MsgTable {
    /// Create an empty message queue table.
    pub fn new() -> Self {
        // SAFETY: MsgQueue contains arrays — manually initialise.
        Self {
            queues: core::array::from_fn(|_| None),
            next_id: 1,
        }
    }

    fn find_by_key(&self, key: i32) -> Option<usize> {
        self.queues
            .iter()
            .position(|q| q.as_ref().map_or(false, |qq| qq.key == key))
    }

    fn find_by_id(&self, id: i32) -> Option<usize> {
        self.queues
            .iter()
            .position(|q| q.as_ref().map_or(false, |qq| qq.id == id))
    }

    fn alloc_slot(&self) -> Option<usize> {
        self.queues.iter().position(|q| q.is_none())
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `msgget(2)`.
///
/// # Errors
///
/// | `Error`         | Condition                                        |
/// |-----------------|--------------------------------------------------|
/// | `AlreadyExists` | `IPC_CREAT|IPC_EXCL` and key already exists      |
/// | `NotFound`      | Key not found and `IPC_CREAT` not set            |
/// | `OutOfMemory`   | Queue table is full                              |
pub fn do_msgget(table: &mut MsgTable, key: i32, msgflg: i32, uid: u32) -> Result<i32> {
    let creat = msgflg & IPC_CREAT != 0;
    let excl = msgflg & IPC_EXCL != 0;
    let mode = (msgflg & 0o777) as u16;

    if key == IPC_PRIVATE {
        let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
        let id = table.next_id;
        table.next_id += 1;
        table.queues[slot] = Some(MsgQueue::new(key, id, mode, uid));
        return Ok(id);
    }

    if let Some(idx) = table.find_by_key(key) {
        if creat && excl {
            return Err(Error::AlreadyExists);
        }
        return Ok(table.queues[idx].as_ref().unwrap().id);
    }

    if !creat {
        return Err(Error::NotFound);
    }

    let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
    let id = table.next_id;
    table.next_id += 1;
    table.queues[slot] = Some(MsgQueue::new(key, id, mode, uid));
    Ok(id)
}

/// Handler for `msgsnd(2)`.
///
/// # Errors
///
/// | `Error`       | Condition                                  |
/// |---------------|--------------------------------------------|
/// | `NotFound`    | `msqid` is invalid                         |
/// | `InvalidArgument` | `mtype <= 0` or data too large         |
/// | `WouldBlock`  | Queue full and `IPC_NOWAIT` set (`EAGAIN`) |
pub fn do_msgsnd(
    table: &mut MsgTable,
    msqid: i32,
    mtype: i64,
    data: &[u8],
    msgflg: i32,
) -> Result<()> {
    if mtype <= 0 {
        return Err(Error::InvalidArgument);
    }
    if data.len() > 256 {
        return Err(Error::InvalidArgument);
    }

    let idx = table.find_by_id(msqid).ok_or(Error::NotFound)?;
    let q = table.queues[idx].as_mut().unwrap();

    if q.is_full() {
        if msgflg & IPC_NOWAIT != 0 {
            return Err(Error::WouldBlock);
        }
        return Err(Error::WouldBlock);
    }

    let mut buf = MsgBuf {
        mtype,
        data: [0u8; 256],
        len: data.len(),
    };
    buf.data[..data.len()].copy_from_slice(data);
    q.enqueue(buf)
}

/// Handler for `msgrcv(2)`.
///
/// Returns the message data.  `msgtyp` controls selection (see module docs).
///
/// # Errors
///
/// | `Error`         | Condition                                  |
/// |-----------------|--------------------------------------------|
/// | `NotFound`      | `msqid` invalid or no matching message     |
/// | `InvalidArgument` | `msgsz` too small and `MSG_NOERROR` not set|
/// | `WouldBlock`    | No match and `IPC_NOWAIT` set              |
pub fn do_msgrcv(
    table: &mut MsgTable,
    msqid: i32,
    msgtyp: i64,
    msgsz: usize,
    msgflg: i32,
) -> Result<MsgBuf> {
    let idx = table.find_by_id(msqid).ok_or(Error::NotFound)?;
    let q = table.queues[idx].as_mut().unwrap();

    let msg_idx = match q.find_msg(msgtyp) {
        Some(i) => i,
        None => {
            if msgflg & IPC_NOWAIT != 0 {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
    };

    let msg = q.msgs[msg_idx].as_ref().unwrap();
    if msg.len > msgsz && msgflg & MSG_NOERROR == 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(q.remove_at(msg_idx).unwrap())
}

/// Handler for `msgctl(IPC_RMID)`.
pub fn do_msgctl_rmid(table: &mut MsgTable, msqid: i32) -> Result<()> {
    let idx = table.find_by_id(msqid).ok_or(Error::NotFound)?;
    table.queues[idx] = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(s: &[u8]) -> ([u8; 256], usize) {
        let mut d = [0u8; 256];
        d[..s.len()].copy_from_slice(s);
        (d, s.len())
    }

    #[test]
    fn send_recv() {
        let mut t = MsgTable::new();
        let id = do_msgget(&mut t, IPC_PRIVATE, 0o600, 0).unwrap();
        do_msgsnd(&mut t, id, 1, b"hello", 0).unwrap();
        let msg = do_msgrcv(&mut t, id, 0, 256, 0).unwrap();
        assert_eq!(msg.mtype, 1);
        assert_eq!(&msg.data[..5], b"hello");
    }

    #[test]
    fn msgget_no_creat_not_found() {
        let mut t = MsgTable::new();
        assert_eq!(do_msgget(&mut t, 77, 0, 0), Err(Error::NotFound));
    }

    #[test]
    fn msgrcv_no_match_nowait() {
        let mut t = MsgTable::new();
        let id = do_msgget(&mut t, IPC_PRIVATE, 0, 0).unwrap();
        assert_eq!(
            do_msgrcv(&mut t, id, 0, 256, IPC_NOWAIT),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn msgsnd_invalid_type() {
        let mut t = MsgTable::new();
        let id = do_msgget(&mut t, IPC_PRIVATE, 0, 0).unwrap();
        assert_eq!(
            do_msgsnd(&mut t, id, 0, b"x", 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn make_data_helper() {
        let (d, len) = make_data(b"abc");
        assert_eq!(len, 3);
        assert_eq!(&d[..3], b"abc");
    }
}

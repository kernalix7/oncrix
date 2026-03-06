// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous IPC with wait queues.
//!
//! Extends the synchronous channel-based IPC with non-blocking
//! send/receive and wait queues for blocking operations. When a
//! thread blocks on an empty channel or full channel, it is added
//! to a wait queue and suspended by the scheduler.
//!
//! When a message is sent to a channel with waiters, one waiter
//! is woken. This enables efficient producer-consumer patterns
//! without busy-waiting.
//!
//! Reference: Linux `kernel/sched/wait.c`, L4 IPC semantics.

use oncrix_lib::{Error, Result};

/// Process identifier (mirrors `oncrix_process::pid::Pid`).
///
/// Kept as a plain `u64` here to avoid a circular dependency
/// between the IPC and process crates.
pub type Pid = u64;

/// Maximum number of waiters per queue.
const MAX_WAITERS_PER_QUEUE: usize = 16;

/// Maximum number of async channels.
const MAX_ASYNC_CHANNELS: usize = 64;

/// A thread waiting on an IPC operation.
#[derive(Debug, Clone, Copy)]
pub struct IpcWaiter {
    /// Process owning the waiting thread.
    pub pid: Pid,
    /// Thread ID.
    pub tid: u64,
    /// What the thread is waiting for.
    pub wait_type: WaitType,
}

/// What kind of IPC operation the thread is waiting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitType {
    /// Waiting to send (channel is full).
    Send,
    /// Waiting to receive (channel is empty).
    Receive,
}

/// A wait queue for IPC operations.
///
/// Threads are woken in FIFO order.
#[derive(Debug)]
pub struct WaitQueue {
    /// Waiting threads.
    waiters: [Option<IpcWaiter>; MAX_WAITERS_PER_QUEUE],
    /// Number of active waiters.
    count: usize,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        const NONE: Option<IpcWaiter> = None;
        Self {
            waiters: [NONE; MAX_WAITERS_PER_QUEUE],
            count: 0,
        }
    }

    /// Add a waiter to the queue.
    pub fn enqueue(&mut self, waiter: IpcWaiter) -> Result<()> {
        if self.count >= MAX_WAITERS_PER_QUEUE {
            return Err(Error::OutOfMemory);
        }
        for slot in self.waiters.iter_mut() {
            if slot.is_none() {
                *slot = Some(waiter);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Wake the first waiter (FIFO order).
    ///
    /// Returns the woken waiter, or `None` if the queue is empty.
    pub fn wake_one(&mut self) -> Option<IpcWaiter> {
        for slot in self.waiters.iter_mut() {
            if let Some(waiter) = slot.take() {
                self.count = self.count.saturating_sub(1);
                return Some(waiter);
            }
        }
        None
    }

    /// Wake all waiters.
    ///
    /// Returns the number of waiters woken.
    pub fn wake_all(&mut self) -> usize {
        let woken = self.count;
        for slot in self.waiters.iter_mut() {
            *slot = None;
        }
        self.count = 0;
        woken
    }

    /// Remove all waiters for a given process.
    pub fn remove_process(&mut self, pid: Pid) {
        for slot in self.waiters.iter_mut() {
            if let Some(waiter) = slot {
                if waiter.pid == pid {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Return the number of waiters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// An async IPC port — a named endpoint with send/receive wait queues.
///
/// Ports are the async counterpart to synchronous channels.
/// They support non-blocking try_send/try_receive and blocking
/// send/receive with wait queues.
#[derive(Debug)]
pub struct AsyncPort {
    /// Port identifier.
    pub port_id: u64,
    /// Owner process.
    pub owner: Pid,
    /// Wait queue for senders (channel full).
    pub send_waiters: WaitQueue,
    /// Wait queue for receivers (channel empty).
    pub recv_waiters: WaitQueue,
    /// Whether this port is open.
    pub open: bool,
}

impl AsyncPort {
    /// Create a new async port.
    pub fn new(port_id: u64, owner: Pid) -> Self {
        Self {
            port_id,
            owner,
            send_waiters: WaitQueue::new(),
            recv_waiters: WaitQueue::new(),
            open: true,
        }
    }

    /// Close the port, waking all waiters with an error.
    ///
    /// Returns the number of waiters woken.
    pub fn close(&mut self) -> usize {
        self.open = false;
        let s = self.send_waiters.wake_all();
        let r = self.recv_waiters.wake_all();
        s + r
    }

    /// Block a sender (channel full).
    pub fn block_sender(&mut self, pid: Pid, tid: u64) -> Result<()> {
        if !self.open {
            return Err(Error::IoError);
        }
        self.send_waiters.enqueue(IpcWaiter {
            pid,
            tid,
            wait_type: WaitType::Send,
        })
    }

    /// Block a receiver (channel empty).
    pub fn block_receiver(&mut self, pid: Pid, tid: u64) -> Result<()> {
        if !self.open {
            return Err(Error::IoError);
        }
        self.recv_waiters.enqueue(IpcWaiter {
            pid,
            tid,
            wait_type: WaitType::Receive,
        })
    }

    /// Notify that a message was sent — wake one receiver.
    pub fn notify_send(&mut self) -> Option<IpcWaiter> {
        self.recv_waiters.wake_one()
    }

    /// Notify that a message was consumed — wake one sender.
    pub fn notify_receive(&mut self) -> Option<IpcWaiter> {
        self.send_waiters.wake_one()
    }
}

/// Registry of async IPC ports.
pub struct AsyncPortRegistry {
    /// Ports.
    ports: [Option<AsyncPort>; MAX_ASYNC_CHANNELS],
    /// Next port ID.
    next_id: u64,
    /// Number of active ports.
    count: usize,
}

impl Default for AsyncPortRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncPortRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<AsyncPort> = None;
        Self {
            ports: [NONE; MAX_ASYNC_CHANNELS],
            next_id: 1,
            count: 0,
        }
    }

    /// Create a new async port.
    pub fn create(&mut self, owner: Pid) -> Result<u64> {
        if self.count >= MAX_ASYNC_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let port_id = self.next_id;
        self.next_id += 1;

        for slot in self.ports.iter_mut() {
            if slot.is_none() {
                *slot = Some(AsyncPort::new(port_id, owner));
                self.count += 1;
                return Ok(port_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a port by ID.
    pub fn get(&self, port_id: u64) -> Option<&AsyncPort> {
        self.ports
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| p.port_id == port_id)
    }

    /// Look up a port by ID (mutable).
    pub fn get_mut(&mut self, port_id: u64) -> Option<&mut AsyncPort> {
        self.ports
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|p| p.port_id == port_id)
    }

    /// Close and remove a port.
    pub fn remove(&mut self, port_id: u64) -> Option<usize> {
        for slot in self.ports.iter_mut() {
            if let Some(port) = slot {
                if port.port_id == port_id {
                    let woken = port.close();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Some(woken);
                }
            }
        }
        None
    }

    /// Remove all ports owned by a process.
    pub fn remove_process(&mut self, owner: Pid) {
        for slot in self.ports.iter_mut() {
            if let Some(port) = slot {
                if port.owner == owner {
                    port.close();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Return the number of active ports.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for AsyncPortRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncPortRegistry")
            .field("active_ports", &self.count)
            .field("capacity", &MAX_ASYNC_CHANNELS)
            .finish()
    }
}

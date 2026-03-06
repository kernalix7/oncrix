// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler wait/wake primitives.
//!
//! Provides the fundamental wait and wake mechanisms used by the
//! scheduler for task blocking and unblocking. Implements
//! exclusive and non-exclusive wait entries, wake-one and
//! wake-all semantics, and interruptible/uninterruptible sleep
//! states with timeout support.

use oncrix_lib::{Error, Result};

/// Maximum number of wait entries.
const MAX_WAIT_ENTRIES: usize = 1024;

/// Maximum number of wait channels.
const MAX_WAIT_CHANNELS: usize = 256;

/// Wait entry flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WaitMode {
    /// Non-exclusive: all waiters are woken.
    NonExclusive,
    /// Exclusive: only one waiter is woken.
    Exclusive,
}

/// Sleep state of a waiting task.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SleepState {
    /// Task is runnable (not sleeping).
    Running,
    /// Interruptible sleep (can be woken by signals).
    Interruptible,
    /// Uninterruptible sleep (cannot be woken by signals).
    Uninterruptible,
    /// Killable sleep (can be woken by fatal signals).
    Killable,
    /// Idle sleep (for idle tasks).
    Idle,
}

impl SleepState {
    /// Returns whether this state can be interrupted by signals.
    pub const fn is_signal_interruptible(&self) -> bool {
        matches!(self, Self::Interruptible | Self::Killable)
    }
}

/// A wait entry representing a task waiting on a channel.
#[derive(Clone, Copy)]
pub struct WaitEntry {
    /// Task identifier.
    task_id: u64,
    /// Wait channel this entry belongs to.
    channel_id: u32,
    /// Wait mode (exclusive or non-exclusive).
    mode: WaitMode,
    /// Sleep state.
    sleep_state: SleepState,
    /// Timeout in nanoseconds (0 = no timeout).
    timeout_ns: u64,
    /// Timestamp when the wait started.
    start_ns: u64,
    /// Whether this entry is active.
    active: bool,
    /// Whether the wait was interrupted by a signal.
    interrupted: bool,
    /// Whether the wait timed out.
    timed_out: bool,
}

impl WaitEntry {
    /// Creates a new wait entry.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            channel_id: 0,
            mode: WaitMode::NonExclusive,
            sleep_state: SleepState::Running,
            timeout_ns: 0,
            start_ns: 0,
            active: false,
            interrupted: false,
            timed_out: false,
        }
    }

    /// Returns the task identifier.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the channel identifier.
    pub const fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Returns the wait mode.
    pub const fn mode(&self) -> WaitMode {
        self.mode
    }

    /// Returns the sleep state.
    pub const fn sleep_state(&self) -> SleepState {
        self.sleep_state
    }

    /// Returns whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns whether the wait was interrupted.
    pub const fn was_interrupted(&self) -> bool {
        self.interrupted
    }

    /// Returns whether the wait timed out.
    pub const fn was_timed_out(&self) -> bool {
        self.timed_out
    }
}

impl Default for WaitEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// A wait channel that tasks can sleep on.
#[derive(Clone, Copy)]
pub struct WaitChannel {
    /// Channel identifier.
    id: u32,
    /// Number of waiters on this channel.
    waiter_count: u32,
    /// Number of exclusive waiters.
    exclusive_count: u32,
    /// Whether this channel is active.
    active: bool,
    /// Total number of wakeups performed on this channel.
    total_wakeups: u64,
}

impl WaitChannel {
    /// Creates a new wait channel.
    pub const fn new() -> Self {
        Self {
            id: 0,
            waiter_count: 0,
            exclusive_count: 0,
            active: false,
            total_wakeups: 0,
        }
    }

    /// Returns the channel identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the number of waiters.
    pub const fn waiter_count(&self) -> u32 {
        self.waiter_count
    }

    /// Returns the number of exclusive waiters.
    pub const fn exclusive_count(&self) -> u32 {
        self.exclusive_count
    }

    /// Returns whether this channel is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for WaitChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler wait/wake manager.
pub struct SchedWaitManager {
    /// Wait entries pool.
    entries: [WaitEntry; MAX_WAIT_ENTRIES],
    /// Number of active wait entries.
    entry_count: usize,
    /// Wait channels.
    channels: [WaitChannel; MAX_WAIT_CHANNELS],
    /// Number of active channels.
    channel_count: usize,
    /// Next channel ID.
    next_channel_id: u32,
    /// Total wait operations.
    total_waits: u64,
    /// Total wake operations.
    total_wakes: u64,
}

impl SchedWaitManager {
    /// Creates a new scheduler wait manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { WaitEntry::new() }; MAX_WAIT_ENTRIES],
            entry_count: 0,
            channels: [const { WaitChannel::new() }; MAX_WAIT_CHANNELS],
            channel_count: 0,
            next_channel_id: 1,
            total_waits: 0,
            total_wakes: 0,
        }
    }

    /// Creates a new wait channel.
    pub fn create_channel(&mut self) -> Result<u32> {
        if self.channel_count >= MAX_WAIT_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_channel_id;
        self.next_channel_id += 1;
        self.channels[self.channel_count] = WaitChannel {
            id,
            waiter_count: 0,
            exclusive_count: 0,
            active: true,
            total_wakeups: 0,
        };
        self.channel_count += 1;
        Ok(id)
    }

    /// Puts a task to sleep on a wait channel.
    pub fn wait(
        &mut self,
        task_id: u64,
        channel_id: u32,
        mode: WaitMode,
        sleep_state: SleepState,
        timeout_ns: u64,
        now_ns: u64,
    ) -> Result<()> {
        if self.entry_count >= MAX_WAIT_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Find the channel
        let chan = self.channels[..self.channel_count]
            .iter_mut()
            .find(|c| c.id == channel_id && c.active);
        let chan = chan.ok_or(Error::NotFound)?;
        chan.waiter_count += 1;
        if mode == WaitMode::Exclusive {
            chan.exclusive_count += 1;
        }

        self.entries[self.entry_count] = WaitEntry {
            task_id,
            channel_id,
            mode,
            sleep_state,
            timeout_ns,
            start_ns: now_ns,
            active: true,
            interrupted: false,
            timed_out: false,
        };
        self.entry_count += 1;
        self.total_waits += 1;
        Ok(())
    }

    /// Wakes one exclusive waiter or all non-exclusive waiters.
    pub fn wake_up(&mut self, channel_id: u32) -> Result<usize> {
        let mut woken = 0usize;
        let mut exclusive_woken = false;

        for i in 0..self.entry_count {
            if self.entries[i].channel_id == channel_id && self.entries[i].active {
                match self.entries[i].mode {
                    WaitMode::NonExclusive => {
                        self.entries[i].active = false;
                        woken += 1;
                    }
                    WaitMode::Exclusive => {
                        if !exclusive_woken {
                            self.entries[i].active = false;
                            exclusive_woken = true;
                            woken += 1;
                        }
                    }
                }
            }
        }

        // Update channel counts
        for i in 0..self.channel_count {
            if self.channels[i].id == channel_id {
                self.channels[i].waiter_count =
                    self.channels[i].waiter_count.saturating_sub(woken as u32);
                self.channels[i].total_wakeups += woken as u64;
                break;
            }
        }

        self.total_wakes += woken as u64;
        if woken == 0 {
            Err(Error::NotFound)
        } else {
            Ok(woken)
        }
    }

    /// Wakes all waiters on a channel.
    pub fn wake_up_all(&mut self, channel_id: u32) -> Result<usize> {
        let mut woken = 0usize;

        for i in 0..self.entry_count {
            if self.entries[i].channel_id == channel_id && self.entries[i].active {
                self.entries[i].active = false;
                woken += 1;
            }
        }

        for i in 0..self.channel_count {
            if self.channels[i].id == channel_id {
                self.channels[i].waiter_count = 0;
                self.channels[i].exclusive_count = 0;
                self.channels[i].total_wakeups += woken as u64;
                break;
            }
        }

        self.total_wakes += woken as u64;
        if woken == 0 {
            Err(Error::NotFound)
        } else {
            Ok(woken)
        }
    }

    /// Checks for timed-out wait entries.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut timed_out = 0usize;

        for i in 0..self.entry_count {
            if self.entries[i].active && self.entries[i].timeout_ns > 0 {
                let elapsed = now_ns.saturating_sub(self.entries[i].start_ns);
                if elapsed >= self.entries[i].timeout_ns {
                    self.entries[i].active = false;
                    self.entries[i].timed_out = true;
                    timed_out += 1;
                }
            }
        }
        timed_out
    }

    /// Returns the total number of wait operations.
    pub const fn total_waits(&self) -> u64 {
        self.total_waits
    }

    /// Returns the total number of wake operations.
    pub const fn total_wakes(&self) -> u64 {
        self.total_wakes
    }

    /// Returns the number of active wait entries.
    pub fn active_waiters(&self) -> usize {
        self.entries[..self.entry_count]
            .iter()
            .filter(|e| e.active)
            .count()
    }

    /// Returns the number of wait channels.
    pub const fn channel_count(&self) -> usize {
        self.channel_count
    }
}

impl Default for SchedWaitManager {
    fn default() -> Self {
        Self::new()
    }
}

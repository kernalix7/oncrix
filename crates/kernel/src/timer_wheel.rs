// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hierarchical timer wheel for kernel timer management.
//!
//! Implements a multi-level cascading timer wheel (modelled after
//! Linux `kernel/time/timer.c`).  Each level covers progressively
//! larger time ranges with coarser granularity, enabling O(1) timer
//! insertion and amortised O(1) expiration.
//!
//! # Wheel Structure
//!
//! ```text
//! Level 0: slots 0..63   granularity = 1 tick        range = 64 ticks
//! Level 1: slots 0..63   granularity = 64 ticks      range = 4096 ticks
//! Level 2: slots 0..63   granularity = 4096 ticks    range = 262144 ticks
//! Level 3: slots 0..63   granularity = 262144 ticks  range = 16M ticks
//! ```
//!
//! When level 0 wraps its current slot past a level-1 boundary the
//! next level-1 slot is cascaded down: its timers are re-inserted
//! into the finer level.  This cascading propagates upward.
//!
//! Reference: Linux `kernel/time/timer.c`,
//! `Documentation/timers/timers-howto.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Slots per wheel level.
const WHEEL_SIZE: usize = 64;

/// Number of cascading levels.
const NR_LEVELS: usize = 4;

/// Bits per level (log2 of WHEEL_SIZE).
const LEVEL_BITS: u32 = 6;

/// Maximum timers in the entire wheel.
const MAX_TIMERS: usize = 4096;

// ── TimerState ─────────────────────────────────────────────────────

/// State of a timer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    /// Slot is free.
    Inactive,
    /// Timer is enqueued in a wheel slot.
    Enqueued,
    /// Timer callback is executing.
    Running,
    /// Timer has been cancelled.
    Cancelled,
}

// ── WheelTimer ─────────────────────────────────────────────────────

/// A single timer entry.
#[derive(Clone, Copy)]
pub struct WheelTimer {
    /// Unique timer identifier.
    id: u64,
    /// Absolute expiration (ticks).
    expires: u64,
    /// Current state.
    state: TimerState,
    /// Level this timer resides in.
    level: u8,
    /// Slot index within the level.
    slot: u8,
    /// Opaque user data.
    data: u64,
    /// Whether this is periodic.
    periodic: bool,
    /// Period in ticks (meaningful only if periodic).
    period: u64,
    /// Number of times this timer has fired.
    fire_count: u64,
}

impl WheelTimer {
    /// Creates an inactive timer.
    pub const fn new() -> Self {
        Self {
            id: 0,
            expires: 0,
            state: TimerState::Inactive,
            level: 0,
            slot: 0,
            data: 0,
            periodic: false,
            period: 0,
            fire_count: 0,
        }
    }

    /// Creates a one-shot timer.
    pub const fn oneshot(id: u64, expires: u64, data: u64) -> Self {
        Self {
            id,
            expires,
            state: TimerState::Inactive,
            level: 0,
            slot: 0,
            data,
            periodic: false,
            period: 0,
            fire_count: 0,
        }
    }

    /// Creates a periodic timer.
    pub const fn periodic(id: u64, expires: u64, period: u64, data: u64) -> Self {
        Self {
            id,
            expires,
            state: TimerState::Inactive,
            level: 0,
            slot: 0,
            data,
            periodic: true,
            period,
            fire_count: 0,
        }
    }

    /// Returns the timer identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the expiration tick.
    pub const fn expires(&self) -> u64 {
        self.expires
    }

    /// Returns the state.
    pub const fn state(&self) -> TimerState {
        self.state
    }

    /// Returns the associated data.
    pub const fn data(&self) -> u64 {
        self.data
    }

    /// Returns whether periodic.
    pub const fn is_periodic(&self) -> bool {
        self.periodic
    }

    /// Returns the fire count.
    pub const fn fire_count(&self) -> u64 {
        self.fire_count
    }
}

// ── WheelLevel ─────────────────────────────────────────────────────

/// A single level of the timer wheel.
#[derive(Clone, Copy)]
pub struct WheelLevel {
    /// Timer count per slot.
    slot_counts: [u16; WHEEL_SIZE],
    /// Bitmap: bit `i` set when slot `i` is non-empty.
    bitmap: u64,
    /// Granularity of this level in ticks.
    granularity: u64,
    /// Level index (0..NR_LEVELS-1).
    level_idx: u8,
}

impl WheelLevel {
    /// Creates a wheel level with the given index.
    pub const fn new(level_idx: u8) -> Self {
        let granularity = 1u64 << (level_idx as u32 * LEVEL_BITS);
        Self {
            slot_counts: [0u16; WHEEL_SIZE],
            bitmap: 0,
            granularity,
            level_idx,
        }
    }

    /// Returns the slot index for an absolute expiration time.
    pub const fn slot_for(&self, expires: u64) -> u8 {
        let shifted = expires / self.granularity;
        (shifted % WHEEL_SIZE as u64) as u8
    }

    /// Increments the timer count in a slot.
    pub fn add_to_slot(&mut self, slot: u8) {
        let s = slot as usize;
        self.slot_counts[s] = self.slot_counts[s].saturating_add(1);
        self.bitmap |= 1u64 << s;
    }

    /// Decrements the timer count in a slot.
    pub fn remove_from_slot(&mut self, slot: u8) {
        let s = slot as usize;
        self.slot_counts[s] = self.slot_counts[s].saturating_sub(1);
        if self.slot_counts[s] == 0 {
            self.bitmap &= !(1u64 << s);
        }
    }

    /// Returns the number of timers in a slot.
    pub const fn slot_count(&self, slot: u8) -> u16 {
        self.slot_counts[slot as usize]
    }

    /// Returns whether a slot has any timers.
    pub const fn slot_occupied(&self, slot: u8) -> bool {
        (self.bitmap >> slot as u32) & 1 == 1
    }

    /// Returns the granularity.
    pub const fn granularity(&self) -> u64 {
        self.granularity
    }

    /// Returns the level index.
    pub const fn level_idx(&self) -> u8 {
        self.level_idx
    }

    /// Finds the next non-empty slot at or after `start`.
    pub fn next_pending(&self, start: u8) -> Option<u8> {
        if self.bitmap == 0 {
            return None;
        }
        let mask = self.bitmap >> start as u32;
        if mask != 0 {
            return Some(start + mask.trailing_zeros() as u8);
        }
        // Wrap around.
        if self.bitmap != 0 {
            return Some(self.bitmap.trailing_zeros() as u8);
        }
        None
    }
}

// ── WheelStats ─────────────────────────────────────────────────────

/// Timer wheel statistics.
#[derive(Clone, Copy)]
pub struct WheelStats {
    /// Total timers added.
    pub added: u64,
    /// Total timers cancelled.
    pub cancelled: u64,
    /// Total timers expired (fired).
    pub expired: u64,
    /// Total cascade operations.
    pub cascades: u64,
    /// Total periodic re-arms.
    pub rearms: u64,
}

impl WheelStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            added: 0,
            cancelled: 0,
            expired: 0,
            cascades: 0,
            rearms: 0,
        }
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ── TimerWheel ─────────────────────────────────────────────────────

/// Hierarchical timer wheel manager.
pub struct TimerWheel {
    /// Wheel levels.
    levels: [WheelLevel; NR_LEVELS],
    /// Timer pool.
    timers: [WheelTimer; MAX_TIMERS],
    /// Number of active timers.
    nr_active: usize,
    /// Current tick (jiffies).
    current_tick: u64,
    /// Next timer identifier.
    next_id: u64,
    /// Statistics.
    stats: WheelStats,
}

impl TimerWheel {
    /// Creates a new timer wheel starting at the given tick.
    pub fn new(start_tick: u64) -> Self {
        Self {
            levels: [
                WheelLevel::new(0),
                WheelLevel::new(1),
                WheelLevel::new(2),
                WheelLevel::new(3),
            ],
            timers: [const { WheelTimer::new() }; MAX_TIMERS],
            nr_active: 0,
            current_tick: start_tick,
            next_id: 1,
            stats: WheelStats::new(),
        }
    }

    /// Adds a one-shot timer expiring at `expires`.
    pub fn add_oneshot(&mut self, expires: u64, data: u64) -> Result<u64> {
        if expires <= self.current_tick {
            return Err(Error::InvalidArgument);
        }
        let id = self.alloc_id();
        let mut timer = WheelTimer::oneshot(id, expires, data);
        self.place_timer(&mut timer)?;
        self.store_timer(timer)?;
        self.stats.added += 1;
        Ok(id)
    }

    /// Adds a periodic timer.
    pub fn add_periodic(&mut self, expires: u64, period: u64, data: u64) -> Result<u64> {
        if expires <= self.current_tick || period == 0 {
            return Err(Error::InvalidArgument);
        }
        let id = self.alloc_id();
        let mut timer = WheelTimer::periodic(id, expires, period, data);
        self.place_timer(&mut timer)?;
        self.store_timer(timer)?;
        self.stats.added += 1;
        Ok(id)
    }

    /// Cancels a timer by its identifier.
    pub fn cancel(&mut self, id: u64) -> Result<()> {
        let idx = self.find_timer(id)?;
        let timer = &self.timers[idx];
        let level = timer.level;
        let slot = timer.slot;
        self.levels[level as usize].remove_from_slot(slot);
        self.timers[idx].state = TimerState::Cancelled;
        self.nr_active = self.nr_active.saturating_sub(1);
        self.stats.cancelled += 1;
        Ok(())
    }

    /// Modifies the expiration time of an existing timer.
    pub fn modify(&mut self, id: u64, new_expires: u64) -> Result<()> {
        if new_expires <= self.current_tick {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_timer(id)?;
        let timer = &self.timers[idx];
        let old_level = timer.level;
        let old_slot = timer.slot;
        self.levels[old_level as usize].remove_from_slot(old_slot);

        self.timers[idx].expires = new_expires;
        let (lvl, s) = self.compute_placement(new_expires);
        self.timers[idx].level = lvl;
        self.timers[idx].slot = s;
        self.levels[lvl as usize].add_to_slot(s);
        Ok(())
    }

    /// Advances the wheel to `now` and returns the number of
    /// timers that expired.
    pub fn advance(&mut self, now: u64) -> u64 {
        let mut fired = 0u64;
        while self.current_tick < now {
            self.current_tick += 1;
            fired += self.process_tick();
        }
        fired
    }

    /// Returns the number of active timers.
    pub const fn nr_active(&self) -> usize {
        self.nr_active
    }

    /// Returns the current tick.
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Returns a read-only reference to the statistics.
    pub const fn stats(&self) -> &WheelStats {
        &self.stats
    }

    /// Returns the nearest expiration tick, or `None`.
    pub fn next_expiry(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for timer in &self.timers {
            if timer.state == TimerState::Enqueued {
                match earliest {
                    Some(e) if timer.expires < e => {
                        earliest = Some(timer.expires);
                    }
                    None => {
                        earliest = Some(timer.expires);
                    }
                    _ => {}
                }
            }
        }
        earliest
    }

    // ── internal helpers ───────────────────────────────────────────

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn place_timer(&self, timer: &mut WheelTimer) -> Result<()> {
        let (lvl, slot) = self.compute_placement(timer.expires);
        timer.level = lvl;
        timer.slot = slot;
        timer.state = TimerState::Enqueued;
        Ok(())
    }

    fn compute_placement(&self, expires: u64) -> (u8, u8) {
        let delta = expires.saturating_sub(self.current_tick);
        for lvl in 0..NR_LEVELS {
            let range = (WHEEL_SIZE as u64) << (lvl as u32 * LEVEL_BITS);
            if delta < range {
                let slot = self.levels[lvl].slot_for(expires);
                return (lvl as u8, slot);
            }
        }
        // Overflow: place in the highest level.
        let slot = self.levels[NR_LEVELS - 1].slot_for(expires);
        ((NR_LEVELS - 1) as u8, slot)
    }

    fn store_timer(&mut self, timer: WheelTimer) -> Result<()> {
        let idx = self
            .timers
            .iter()
            .position(|t| t.state == TimerState::Inactive || t.state == TimerState::Cancelled)
            .ok_or(Error::OutOfMemory)?;
        self.levels[timer.level as usize].add_to_slot(timer.slot);
        self.timers[idx] = timer;
        self.nr_active += 1;
        Ok(())
    }

    fn find_timer(&self, id: u64) -> Result<usize> {
        self.timers
            .iter()
            .position(|t| t.id == id && t.state == TimerState::Enqueued)
            .ok_or(Error::NotFound)
    }

    fn process_tick(&mut self) -> u64 {
        let mut fired = 0u64;

        // Cascade higher levels when level-0 wraps.
        self.cascade_levels();

        // Fire all timers in level-0's current slot.
        let slot = self.levels[0].slot_for(self.current_tick);

        for timer in &mut self.timers {
            if timer.state != TimerState::Enqueued {
                continue;
            }
            if timer.level != 0 || timer.slot != slot {
                continue;
            }
            if timer.expires > self.current_tick {
                continue;
            }
            timer.state = TimerState::Running;
            timer.fire_count += 1;
            fired += 1;
        }

        // Post-fire: handle periodic re-arm or mark inactive.
        let current = self.current_tick;
        let mut rearm_list = [(0u64, 0u64, 0u64); 64];
        let mut rearm_count = 0usize;

        for timer in &mut self.timers {
            if timer.state != TimerState::Running {
                continue;
            }
            if timer.periodic && timer.period > 0 {
                let new_exp = current.saturating_add(timer.period);
                rearm_list[rearm_count] = (timer.id, new_exp, timer.period);
                rearm_count = rearm_count.min(rearm_list.len() - 1) + 1
                    - if rearm_count >= rearm_list.len() - 1 {
                        1
                    } else {
                        0
                    };
            }
            timer.state = TimerState::Inactive;
            self.nr_active = self.nr_active.saturating_sub(1);
        }

        // Re-arm periodic timers.
        for i in 0..rearm_count {
            let (id, new_exp, period) = rearm_list[i];
            let (lvl, s) = self.compute_placement(new_exp);
            if let Some(pos) = self
                .timers
                .iter()
                .position(|t| t.state == TimerState::Inactive || t.state == TimerState::Cancelled)
            {
                self.timers[pos] = WheelTimer {
                    id,
                    expires: new_exp,
                    state: TimerState::Enqueued,
                    level: lvl,
                    slot: s,
                    data: 0,
                    periodic: true,
                    period,
                    fire_count: 0,
                };
                self.levels[lvl as usize].add_to_slot(s);
                self.nr_active += 1;
                self.stats.rearms += 1;
            }
        }

        self.stats.expired += fired;
        fired
    }

    fn cascade_levels(&mut self) {
        // Collect cascade actions to avoid borrowing self
        // mutably via timers and immutably via levels at once.
        let mut actions = [(0u16, 0u8, 0u8, 0u8, 0u8); 256];
        let mut nr_actions = 0usize;

        for lvl in 1..NR_LEVELS {
            let gran = self.levels[lvl].granularity;
            if self.current_tick % gran != 0 {
                break;
            }
            let slot = self.levels[lvl].slot_for(self.current_tick);
            if !self.levels[lvl].slot_occupied(slot) {
                continue;
            }
            let current_tick = self.current_tick;
            for (i, timer) in self.timers.iter().enumerate() {
                if timer.state != TimerState::Enqueued {
                    continue;
                }
                if timer.level != lvl as u8 || timer.slot != slot {
                    continue;
                }
                let (new_lvl, new_slot) =
                    Self::compute_placement_static(timer.expires, current_tick, lvl, &self.levels);
                if nr_actions < actions.len() {
                    actions[nr_actions] = (i as u16, lvl as u8, slot, new_lvl, new_slot);
                    nr_actions += 1;
                }
            }
        }

        // Apply collected actions.
        for a in &actions[..nr_actions] {
            let (idx, old_lvl, old_slot, new_lvl, new_slot) = *a;
            self.levels[old_lvl as usize].remove_from_slot(old_slot);
            self.timers[idx as usize].level = new_lvl;
            self.timers[idx as usize].slot = new_slot;
            self.levels[new_lvl as usize].add_to_slot(new_slot);
            self.stats.cascades += 1;
        }
    }

    fn compute_placement_static(
        expires: u64,
        current_tick: u64,
        max_level: usize,
        levels: &[WheelLevel; NR_LEVELS],
    ) -> (u8, u8) {
        let delta = expires.saturating_sub(current_tick);
        for lvl in 0..max_level {
            let range = (WHEEL_SIZE as u64) << (lvl as u32 * LEVEL_BITS);
            if delta < range {
                let slot = levels[lvl].slot_for(expires);
                return (lvl as u8, slot);
            }
        }
        let clamped = if max_level > 0 { max_level - 1 } else { 0 };
        let slot = levels[clamped].slot_for(expires);
        (clamped as u8, slot)
    }
}

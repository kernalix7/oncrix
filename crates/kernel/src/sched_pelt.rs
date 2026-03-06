// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-Entity Load Tracking (PELT) for the CFS scheduler.
//!
//! PELT computes decaying averages of task and run-queue utilisation.
//! Each scheduling entity (task or task group) maintains a geometric
//! series of its recent CPU demand, giving the scheduler accurate
//! load information for placement and frequency-scaling decisions.
//!
//! # Decay Formula
//!
//! ```text
//! load_avg = sum_{i=0}^{n} (load_i * y^i)
//! ```
//!
//! where `y` is a decay factor (~0.978 for a 32ms half-life) and
//! `load_i` is the load contribution in period `i`.
//!
//! # Architecture
//!
//! ```text
//! PeltManager
//!  ├── entities: [PeltEntity; MAX_ENTITIES]
//!  ├── rq_pelt:  [RunqueuePelt; MAX_CPUS]
//!  └── period_us: u64  (PELT period length)
//! ```
//!
//! Each 1024-us PELT period, running time is accumulated and then
//! decayed into the geometric average.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum tracked entities (tasks + groups).
const MAX_ENTITIES: usize = 4096;

/// Maximum CPUs for per-runqueue PELT.
const MAX_CPUS: usize = 64;

/// PELT period in microseconds (1024 us ≈ 1 ms).
const PELT_PERIOD_US: u64 = 1024;

/// Decay factor numerator (y ≈ 0.978).
/// Represented as fixed-point: 1002 / 1024.
const DECAY_NUM: u64 = 1002;

/// Decay factor denominator.
const DECAY_DEN: u64 = 1024;

/// Maximum load_avg value (prevents overflow).
const MAX_LOAD_AVG: u64 = 47_742;

/// Maximum util_avg value.
const MAX_UTIL_AVG: u64 = 1024;

// ======================================================================
// Types
// ======================================================================

/// PELT signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeltSignal {
    /// Load average (weighted by task priority).
    LoadAvg,
    /// Utilisation average (fraction of CPU capacity used).
    UtilAvg,
    /// Runnable average (fraction of time the entity was runnable).
    RunnableAvg,
}

impl Default for PeltSignal {
    fn default() -> Self {
        Self::LoadAvg
    }
}

/// A PELT-tracked scheduling entity.
#[derive(Debug, Clone, Copy)]
pub struct PeltEntity {
    /// Entity identifier (PID or group ID).
    pub id: u64,
    /// Accumulated running time in current period (us).
    pub running_sum: u64,
    /// Accumulated runnable time in current period (us).
    pub runnable_sum: u64,
    /// Decaying load average.
    pub load_avg: u64,
    /// Decaying utilisation average (0..1024).
    pub util_avg: u64,
    /// Decaying runnable average.
    pub runnable_avg: u64,
    /// Task weight (from nice value).
    pub weight: u64,
    /// Last update timestamp (us).
    pub last_update_us: u64,
    /// Whether this entity is active.
    pub active: bool,
}

impl PeltEntity {
    /// Creates an empty PELT entity.
    pub const fn new() -> Self {
        Self {
            id: 0,
            running_sum: 0,
            runnable_sum: 0,
            load_avg: 0,
            util_avg: 0,
            runnable_avg: 0,
            weight: 1024,
            last_update_us: 0,
            active: false,
        }
    }
}

impl Default for PeltEntity {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-runqueue (per-CPU) PELT aggregation.
#[derive(Debug, Clone, Copy)]
pub struct RunqueuePelt {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Aggregate load average of all entities on this RQ.
    pub rq_load_avg: u64,
    /// Aggregate utilisation average.
    pub rq_util_avg: u64,
    /// Number of runnable entities.
    pub nr_running: u32,
    /// Last update timestamp (us).
    pub last_update_us: u64,
}

impl RunqueuePelt {
    /// Creates an empty runqueue PELT entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            rq_load_avg: 0,
            rq_util_avg: 0,
            nr_running: 0,
            last_update_us: 0,
        }
    }
}

impl Default for RunqueuePelt {
    fn default() -> Self {
        Self::new()
    }
}

/// PELT manager for the system.
pub struct PeltManager {
    /// Per-entity PELT data.
    entities: [PeltEntity; MAX_ENTITIES],
    /// Number of active entities.
    nr_entities: usize,
    /// Per-runqueue PELT data.
    rq_pelt: [RunqueuePelt; MAX_CPUS],
    /// Number of CPUs.
    nr_cpus: u32,
}

impl PeltManager {
    /// Creates a new PELT manager.
    pub const fn new() -> Self {
        Self {
            entities: [PeltEntity::new(); MAX_ENTITIES],
            nr_entities: 0,
            rq_pelt: [RunqueuePelt::new(); MAX_CPUS],
            nr_cpus: 1,
        }
    }

    /// Sets the number of CPUs.
    pub fn set_nr_cpus(&mut self, nr: u32) -> Result<()> {
        if nr == 0 || (nr as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr;
        for i in 0..(nr as usize) {
            self.rq_pelt[i].cpu_id = i as u32;
        }
        Ok(())
    }

    /// Registers a new entity for PELT tracking.
    pub fn register(&mut self, id: u64, weight: u64) -> Result<usize> {
        if self.nr_entities >= MAX_ENTITIES {
            return Err(Error::OutOfMemory);
        }
        for (i, entity) in self.entities.iter_mut().enumerate() {
            if !entity.active {
                *entity = PeltEntity {
                    id,
                    running_sum: 0,
                    runnable_sum: 0,
                    load_avg: 0,
                    util_avg: 0,
                    runnable_avg: 0,
                    weight,
                    last_update_us: 0,
                    active: true,
                };
                self.nr_entities += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters an entity.
    pub fn unregister(&mut self, id: u64) -> Result<()> {
        let idx = self.find_entity(id).ok_or(Error::NotFound)?;
        self.entities[idx].active = false;
        self.nr_entities = self.nr_entities.saturating_sub(1);
        Ok(())
    }

    /// Updates an entity's PELT signals after it ran for `delta_us`.
    ///
    /// `was_runnable_us` is the time the entity was runnable (may
    /// include time waiting in the run queue).
    pub fn update_entity(
        &mut self,
        id: u64,
        now_us: u64,
        running_us: u64,
        runnable_us: u64,
    ) -> Result<()> {
        let idx = self.find_entity(id).ok_or(Error::NotFound)?;
        let entity = &mut self.entities[idx];

        let elapsed = now_us.saturating_sub(entity.last_update_us);
        if elapsed == 0 {
            return Ok(());
        }

        entity.running_sum += running_us;
        entity.runnable_sum += runnable_us;
        entity.last_update_us = now_us;

        // Decay and fold if a full period has elapsed.
        let periods = elapsed / PELT_PERIOD_US;
        if periods > 0 {
            // Decay existing averages.
            for _ in 0..periods.min(64) {
                entity.load_avg = (entity.load_avg * DECAY_NUM) / DECAY_DEN;
                entity.util_avg = (entity.util_avg * DECAY_NUM) / DECAY_DEN;
                entity.runnable_avg = (entity.runnable_avg * DECAY_NUM) / DECAY_DEN;
            }

            // Add new contribution.
            let load_contrib = if PELT_PERIOD_US > 0 {
                (entity.running_sum * entity.weight) / PELT_PERIOD_US
            } else {
                0
            };
            entity.load_avg = entity
                .load_avg
                .saturating_add(load_contrib)
                .min(MAX_LOAD_AVG);

            let util_contrib = if PELT_PERIOD_US > 0 {
                (entity.running_sum * MAX_UTIL_AVG) / PELT_PERIOD_US
            } else {
                0
            };
            entity.util_avg = entity
                .util_avg
                .saturating_add(util_contrib)
                .min(MAX_UTIL_AVG);

            let runnable_contrib = if PELT_PERIOD_US > 0 {
                (entity.runnable_sum * MAX_UTIL_AVG) / PELT_PERIOD_US
            } else {
                0
            };
            entity.runnable_avg = entity
                .runnable_avg
                .saturating_add(runnable_contrib)
                .min(MAX_UTIL_AVG);

            // Reset accumulators.
            entity.running_sum = 0;
            entity.runnable_sum = 0;
        }
        Ok(())
    }

    /// Returns the load average of an entity.
    pub fn load_avg(&self, id: u64) -> Result<u64> {
        let idx = self.find_entity(id).ok_or(Error::NotFound)?;
        Ok(self.entities[idx].load_avg)
    }

    /// Returns the utilisation average of an entity.
    pub fn util_avg(&self, id: u64) -> Result<u64> {
        let idx = self.find_entity(id).ok_or(Error::NotFound)?;
        Ok(self.entities[idx].util_avg)
    }

    /// Updates per-runqueue PELT from all entities on that CPU.
    pub fn update_rq(&mut self, cpu_id: u32, entity_ids: &[u64], now_us: u64) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rq_pelt[cpu_id as usize].rq_load_avg = 0;
        self.rq_pelt[cpu_id as usize].rq_util_avg = 0;
        self.rq_pelt[cpu_id as usize].nr_running = 0;
        self.rq_pelt[cpu_id as usize].last_update_us = now_us;

        for &eid in entity_ids {
            let idx = self.entities.iter().position(|e| e.active && e.id == eid);
            if let Some(i) = idx {
                let load = self.entities[i].load_avg;
                let util = self.entities[i].util_avg;
                self.rq_pelt[cpu_id as usize].rq_load_avg = self.rq_pelt[cpu_id as usize]
                    .rq_load_avg
                    .saturating_add(load);
                self.rq_pelt[cpu_id as usize].rq_util_avg = self.rq_pelt[cpu_id as usize]
                    .rq_util_avg
                    .saturating_add(util);
                self.rq_pelt[cpu_id as usize].nr_running += 1;
            }
        }
        Ok(())
    }

    /// Returns the aggregate load for a runqueue.
    pub fn rq_load_avg(&self, cpu_id: u32) -> Result<u64> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.rq_pelt[cpu_id as usize].rq_load_avg)
    }

    /// Returns the aggregate utilisation for a runqueue.
    pub fn rq_util_avg(&self, cpu_id: u32) -> Result<u64> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.rq_pelt[cpu_id as usize].rq_util_avg)
    }

    /// Returns the number of tracked entities.
    pub fn nr_entities(&self) -> usize {
        self.nr_entities
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_entity(&self, id: u64) -> Option<usize> {
        self.entities.iter().position(|e| e.active && e.id == id)
    }
}

impl Default for PeltManager {
    fn default() -> Self {
        Self::new()
    }
}

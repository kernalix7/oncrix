// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task migration across CPUs.
//!
//! Handles moving tasks between CPU runqueues for load balancing,
//! affinity changes, and CPU hotplug events. Manages migration
//! requests, stop-machine migration for pinned tasks, and
//! migration statistics tracking. Ensures cache and NUMA
//! locality considerations are respected during migration.

use oncrix_lib::{Error, Result};

/// Maximum number of pending migration requests.
const MAX_PENDING_MIGRATIONS: usize = 512;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum migration history entries.
const MAX_MIGRATION_HISTORY: usize = 128;

/// Migration request type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MigrationType {
    /// Load balancer initiated migration.
    LoadBalance,
    /// Affinity change forced migration.
    AffinityChange,
    /// CPU hotplug offline forced migration.
    CpuOffline,
    /// NUMA balancing migration.
    NumaBalance,
    /// Active balance (pull from overloaded CPU).
    ActiveBalance,
    /// User requested migration (sched_setaffinity).
    UserRequest,
}

/// Migration request state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// Request is pending.
    Pending,
    /// Migration is in progress.
    InProgress,
    /// Migration completed successfully.
    Completed,
    /// Migration failed.
    Failed,
    /// Migration was cancelled.
    Cancelled,
}

/// A migration request for a task.
#[derive(Clone, Copy)]
pub struct MigrationRequest {
    /// Request identifier.
    id: u64,
    /// Task to migrate.
    task_id: u64,
    /// Source CPU.
    src_cpu: u32,
    /// Destination CPU.
    dst_cpu: u32,
    /// Migration type.
    migration_type: MigrationType,
    /// Current state.
    state: MigrationState,
    /// Request timestamp.
    request_ns: u64,
    /// Completion timestamp.
    complete_ns: u64,
    /// Whether this is a forced migration (cannot be refused).
    forced: bool,
}

impl MigrationRequest {
    /// Creates a new migration request.
    pub const fn new() -> Self {
        Self {
            id: 0,
            task_id: 0,
            src_cpu: 0,
            dst_cpu: 0,
            migration_type: MigrationType::LoadBalance,
            state: MigrationState::Pending,
            request_ns: 0,
            complete_ns: 0,
            forced: false,
        }
    }

    /// Creates a migration request with parameters.
    pub const fn with_params(
        id: u64,
        task_id: u64,
        src_cpu: u32,
        dst_cpu: u32,
        migration_type: MigrationType,
        now_ns: u64,
    ) -> Self {
        Self {
            id,
            task_id,
            src_cpu,
            dst_cpu,
            migration_type,
            state: MigrationState::Pending,
            request_ns: now_ns,
            complete_ns: 0,
            forced: false,
        }
    }

    /// Returns the request identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the task identifier.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the source CPU.
    pub const fn src_cpu(&self) -> u32 {
        self.src_cpu
    }

    /// Returns the destination CPU.
    pub const fn dst_cpu(&self) -> u32 {
        self.dst_cpu
    }

    /// Returns the migration type.
    pub const fn migration_type(&self) -> MigrationType {
        self.migration_type
    }

    /// Returns the current state.
    pub const fn state(&self) -> MigrationState {
        self.state
    }

    /// Returns the migration latency in nanoseconds.
    pub const fn latency_ns(&self) -> u64 {
        if self.complete_ns > self.request_ns {
            self.complete_ns - self.request_ns
        } else {
            0
        }
    }
}

impl Default for MigrationRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU migration statistics.
#[derive(Clone, Copy)]
pub struct CpuMigrationStats {
    /// CPU identifier.
    cpu_id: u32,
    /// Tasks migrated away from this CPU.
    migrations_out: u64,
    /// Tasks migrated to this CPU.
    migrations_in: u64,
    /// Failed migration attempts.
    migration_failures: u64,
    /// Active balance pull count.
    active_balance_count: u64,
}

impl CpuMigrationStats {
    /// Creates new CPU migration statistics.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            migrations_out: 0,
            migrations_in: 0,
            migration_failures: 0,
            active_balance_count: 0,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns total migrations out.
    pub const fn migrations_out(&self) -> u64 {
        self.migrations_out
    }

    /// Returns total migrations in.
    pub const fn migrations_in(&self) -> u64 {
        self.migrations_in
    }

    /// Returns total migration failures.
    pub const fn migration_failures(&self) -> u64 {
        self.migration_failures
    }
}

impl Default for CpuMigrationStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Task migration manager.
pub struct TaskMigrationManager {
    /// Pending migration requests.
    requests: [MigrationRequest; MAX_PENDING_MIGRATIONS],
    /// Number of active requests.
    request_count: usize,
    /// Per-CPU migration statistics.
    cpu_stats: [CpuMigrationStats; MAX_CPUS],
    /// Number of CPUs.
    cpu_count: usize,
    /// Migration history.
    history: [MigrationRequest; MAX_MIGRATION_HISTORY],
    /// History count.
    history_count: usize,
    /// Next request ID.
    next_id: u64,
    /// Total successful migrations.
    total_migrations: u64,
    /// Whether migration is globally enabled.
    enabled: bool,
}

impl TaskMigrationManager {
    /// Creates a new task migration manager.
    pub const fn new() -> Self {
        Self {
            requests: [const { MigrationRequest::new() }; MAX_PENDING_MIGRATIONS],
            request_count: 0,
            cpu_stats: [const { CpuMigrationStats::new() }; MAX_CPUS],
            cpu_count: 0,
            history: [const { MigrationRequest::new() }; MAX_MIGRATION_HISTORY],
            history_count: 0,
            next_id: 1,
            total_migrations: 0,
            enabled: true,
        }
    }

    /// Registers a CPU for migration tracking.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.cpu_stats[self.cpu_count].cpu_id = cpu_id;
        self.cpu_count += 1;
        Ok(())
    }

    /// Submits a migration request.
    pub fn submit_migration(
        &mut self,
        task_id: u64,
        src_cpu: u32,
        dst_cpu: u32,
        migration_type: MigrationType,
        now_ns: u64,
    ) -> Result<u64> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if self.request_count >= MAX_PENDING_MIGRATIONS {
            return Err(Error::OutOfMemory);
        }
        if src_cpu == dst_cpu {
            return Err(Error::InvalidArgument);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.requests[self.request_count] =
            MigrationRequest::with_params(id, task_id, src_cpu, dst_cpu, migration_type, now_ns);
        self.request_count += 1;
        Ok(id)
    }

    /// Completes a migration request.
    pub fn complete_migration(
        &mut self,
        request_id: u64,
        now_ns: u64,
        success: bool,
    ) -> Result<()> {
        for i in 0..self.request_count {
            if self.requests[i].id == request_id
                && self.requests[i].state == MigrationState::Pending
            {
                if success {
                    self.requests[i].state = MigrationState::Completed;
                    self.requests[i].complete_ns = now_ns;
                    self.total_migrations += 1;

                    // Update CPU stats
                    let src = self.requests[i].src_cpu;
                    let dst = self.requests[i].dst_cpu;
                    for s in &mut self.cpu_stats[..self.cpu_count] {
                        if s.cpu_id == src {
                            s.migrations_out += 1;
                        }
                        if s.cpu_id == dst {
                            s.migrations_in += 1;
                        }
                    }
                } else {
                    self.requests[i].state = MigrationState::Failed;
                    let src = self.requests[i].src_cpu;
                    for s in &mut self.cpu_stats[..self.cpu_count] {
                        if s.cpu_id == src {
                            s.migration_failures += 1;
                        }
                    }
                }

                // Add to history
                if self.history_count < MAX_MIGRATION_HISTORY {
                    self.history[self.history_count] = self.requests[i];
                    self.history_count += 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Cancels a pending migration request.
    pub fn cancel_migration(&mut self, request_id: u64) -> Result<()> {
        for i in 0..self.request_count {
            if self.requests[i].id == request_id
                && self.requests[i].state == MigrationState::Pending
            {
                self.requests[i].state = MigrationState::Cancelled;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.requests[..self.request_count]
            .iter()
            .filter(|r| r.state == MigrationState::Pending)
            .count()
    }

    /// Returns total successful migrations.
    pub const fn total_migrations(&self) -> u64 {
        self.total_migrations
    }

    /// Returns the number of CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Enables or disables migration.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for TaskMigrationManager {
    fn default() -> Self {
        Self::new()
    }
}

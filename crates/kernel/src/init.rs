// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Init process (PID 1) service manager.
//!
//! The init system is the first user-space process and acts as the
//! ancestor of all other processes. It is responsible for:
//!
//! - Spawning and monitoring system services
//! - Restarting failed services according to their restart policy
//! - Orchestrating the boot sequence through defined stages
//!
//! This module provides the `InitSystem` service manager and the
//! `do_init_boot` function that drives the boot sequence.
//!
//! Reference: Linux `init/main.c`, POSIX.1-2024 §Process Creation.

use oncrix_lib::{Error, Result};

/// Maximum number of services the init system can manage.
const MAX_SERVICES: usize = 32;

/// Maximum length of a service name.
const MAX_NAME_LEN: usize = 32;

/// Maximum length of a service executable path.
const MAX_PATH_LEN: usize = 256;

/// Maximum length of a single argument.
const MAX_ARG_LEN: usize = 64;

/// Maximum number of arguments per service.
const MAX_ARGS: usize = 4;

/// Base PID for simulated service processes.
///
/// Real PID allocation would come from the process subsystem;
/// this constant is used for deterministic testing.
const BASE_SERVICE_PID: u64 = 100;

/// Lifecycle state of a managed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is not running and not scheduled to start.
    Stopped,
    /// Service is in the process of being started.
    Starting,
    /// Service is running normally.
    Running,
    /// Service has been asked to stop (SIGTERM sent).
    Stopping,
    /// Service exited with an error and will not be restarted.
    Failed,
    /// Service is waiting for its restart delay to elapse.
    Restarting,
}

/// Policy controlling whether and when a service is restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Never restart the service after it exits.
    Never,
    /// Always restart the service regardless of exit status.
    Always,
    /// Restart only when the service exits with a non-zero status.
    OnFailure,
}

/// Configuration for a managed service.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Service name (UTF-8 encoded, padded with zeros).
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Path to the service executable (UTF-8 encoded).
    pub path: [u8; MAX_PATH_LEN],
    /// Number of valid bytes in `path`.
    pub path_len: usize,
    /// Command-line arguments (up to 4).
    pub args: [[u8; MAX_ARG_LEN]; MAX_ARGS],
    /// Length of each argument in `args`.
    pub arg_lens: [usize; MAX_ARGS],
    /// Number of arguments actually used.
    pub arg_count: usize,
    /// Policy for restarting the service after exit.
    pub restart_policy: RestartPolicy,
    /// Number of ticks to wait before restarting.
    pub restart_delay_ticks: u64,
    /// Maximum number of restarts (0 means unlimited).
    pub max_restarts: u32,
    /// Scheduling priority for the service process.
    pub priority: u8,
    /// Capability bitmask required by the service.
    pub required_caps: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceConfig {
    /// Creates a new `ServiceConfig` with all fields zeroed.
    pub fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            args: [[0u8; MAX_ARG_LEN]; MAX_ARGS],
            arg_lens: [0usize; MAX_ARGS],
            arg_count: 0,
            restart_policy: RestartPolicy::Never,
            restart_delay_ticks: 0,
            max_restarts: 0,
            priority: 0,
            required_caps: 0,
        }
    }

    /// Sets the service name from a byte slice.
    ///
    /// Returns `InvalidArgument` if the name is empty or too long.
    pub fn set_name(&mut self, n: &[u8]) -> Result<()> {
        if n.is_empty() || n.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..n.len()].copy_from_slice(n);
        self.name_len = n.len();
        Ok(())
    }

    /// Sets the executable path from a byte slice.
    ///
    /// Returns `InvalidArgument` if the path is empty or too long.
    pub fn set_path(&mut self, p: &[u8]) -> Result<()> {
        if p.is_empty() || p.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        self.path[..p.len()].copy_from_slice(p);
        self.path_len = p.len();
        Ok(())
    }

    /// Adds a command-line argument.
    ///
    /// Returns `InvalidArgument` if the argument is too long or the
    /// maximum argument count has been reached.
    pub fn add_arg(&mut self, arg: &[u8]) -> Result<()> {
        if self.arg_count >= MAX_ARGS || arg.len() > MAX_ARG_LEN {
            return Err(Error::InvalidArgument);
        }
        self.args[self.arg_count][..arg.len()].copy_from_slice(arg);
        self.arg_lens[self.arg_count] = arg.len();
        self.arg_count = self.arg_count.saturating_add(1);
        Ok(())
    }

    /// Returns the service name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the executable path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

/// A managed service tracked by the init system.
#[derive(Debug, Clone)]
pub struct Service {
    /// Configuration for this service.
    pub config: ServiceConfig,
    /// Current lifecycle state.
    pub state: ServiceState,
    /// PID of the running process (0 when not running).
    pub pid: u64,
    /// Number of times this service has been restarted.
    pub restart_count: u32,
    /// Exit status from the most recent termination.
    pub last_exit_status: i32,
    /// Tick at which the service was last started.
    pub start_tick: u64,
    /// Tick at which the service was last stopped.
    pub stop_tick: u64,
}

impl Service {
    /// Creates a new `Service` from the given configuration.
    pub fn new(config: ServiceConfig) -> Self {
        Self {
            config,
            state: ServiceState::Stopped,
            pid: 0,
            restart_count: 0,
            last_exit_status: 0,
            start_tick: 0,
            stop_tick: 0,
        }
    }
}

/// Boot stages traversed by the init system during startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStage {
    /// Hardware and early kernel subsystem initialisation.
    EarlyInit,
    /// Mounting root and essential file systems.
    MountFilesystems,
    /// Starting core system services.
    StartServices,
    /// Transitioning to user-space operation.
    UserSpace,
    /// Boot sequence finished; system is fully operational.
    Complete,
}

/// The PID 1 service manager.
///
/// `InitSystem` maintains an array of up to 32 managed services,
/// tracks the system tick for restart delay accounting, and
/// exposes methods for service lifecycle management.
pub struct InitSystem {
    /// Registered services (slot is `None` when unused).
    services: [Option<Service>; MAX_SERVICES],
    /// Whether the boot sequence has completed.
    boot_complete: bool,
    /// Monotonic tick counter, updated via [`Self::tick`].
    system_tick: u64,
    /// Counter for generating simulated PIDs.
    next_pid: u64,
}

impl Default for InitSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl InitSystem {
    /// Creates a new `InitSystem` with no registered services.
    pub const fn new() -> Self {
        // const-compatible initialisation using array repetition.
        const NONE: Option<Service> = None;
        Self {
            services: [NONE; MAX_SERVICES],
            boot_complete: false,
            system_tick: 0,
            next_pid: BASE_SERVICE_PID,
        }
    }

    /// Registers a service and returns its slot index.
    ///
    /// Returns `OutOfMemory` if all 32 slots are occupied, or
    /// `InvalidArgument` if the config has an empty name or path.
    pub fn register_service(&mut self, config: ServiceConfig) -> Result<usize> {
        if config.name_len == 0 || config.path_len == 0 {
            return Err(Error::InvalidArgument);
        }
        for (i, slot) in self.services.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Service::new(config));
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a service from the given slot.
    ///
    /// Returns `NotFound` if the slot is empty, or `Busy` if the
    /// service is currently running or stopping.
    pub fn unregister_service(&mut self, index: usize) -> Result<()> {
        let svc = self.get_service_mut(index)?;
        match svc.state {
            ServiceState::Running | ServiceState::Stopping => {
                return Err(Error::Busy);
            }
            _ => {}
        }
        self.services[index] = None;
        Ok(())
    }

    /// Starts the service at `index` and returns its allocated PID.
    ///
    /// The PID is simulated via an internal counter; actual process
    /// creation would be delegated to the process subsystem.
    ///
    /// Returns `NotFound` if the slot is empty, or `Busy` if the
    /// service is already running.
    pub fn start_service(&mut self, index: usize) -> Result<u64> {
        let tick = self.system_tick;
        let pid = self.allocate_pid();
        let svc = self.get_service_mut(index)?;
        if svc.state == ServiceState::Running || svc.state == ServiceState::Starting {
            return Err(Error::Busy);
        }
        svc.state = ServiceState::Starting;
        svc.pid = pid;
        svc.start_tick = tick;
        // Transition immediately to Running (simulated).
        svc.state = ServiceState::Running;
        Ok(pid)
    }

    /// Requests a running service to stop by sending SIGTERM.
    ///
    /// Sets the service state to `Stopping`. The service will
    /// eventually call back through [`Self::notify_exit`].
    ///
    /// Returns `NotFound` if the slot is empty, or
    /// `InvalidArgument` if the service is not running.
    pub fn stop_service(&mut self, index: usize) -> Result<()> {
        let tick = self.system_tick;
        let svc = self.get_service_mut(index)?;
        if svc.state != ServiceState::Running {
            return Err(Error::InvalidArgument);
        }
        svc.state = ServiceState::Stopping;
        svc.stop_tick = tick;
        // In a real kernel, SIGTERM would be sent to svc.pid here.
        Ok(())
    }

    /// Notifies the init system that a service process has exited.
    ///
    /// Looks up the service by PID, records the exit status, and
    /// applies the restart policy. If the service should be
    /// restarted, it transitions to `Restarting`; otherwise it
    /// moves to `Stopped` or `Failed`.
    pub fn notify_exit(&mut self, pid: u64, status: i32) {
        let index = match self.find_service_by_pid(pid) {
            Some(i) => i,
            None => return,
        };
        // Take a local copy of fields we need before mutating.
        let tick = self.system_tick;
        if let Some(ref mut svc) = self.services[index] {
            svc.last_exit_status = status;
            svc.stop_tick = tick;
            svc.pid = 0;

            let should_restart = match svc.config.restart_policy {
                RestartPolicy::Never => false,
                RestartPolicy::Always => true,
                RestartPolicy::OnFailure => status != 0,
            };

            let restarts_exhausted =
                svc.config.max_restarts != 0 && svc.restart_count >= svc.config.max_restarts;

            if should_restart && !restarts_exhausted {
                svc.state = ServiceState::Restarting;
                svc.restart_count = svc.restart_count.saturating_add(1);
            } else if status != 0 {
                svc.state = ServiceState::Failed;
            } else {
                svc.state = ServiceState::Stopped;
            }
        }
    }

    /// Advances the system tick and processes restart timers.
    ///
    /// Services in the `Restarting` state whose delay has elapsed
    /// are started automatically.
    pub fn tick(&mut self, current_tick: u64) {
        self.system_tick = current_tick;

        // Collect indices of services ready to restart so we can
        // call start_service without holding a mutable borrow on
        // the iterator.
        let mut restart_indices = [0usize; MAX_SERVICES];
        let mut restart_count = 0usize;

        for (i, slot) in self.services.iter().enumerate() {
            if let Some(svc) = slot {
                if svc.state == ServiceState::Restarting {
                    let elapsed = current_tick.saturating_sub(svc.stop_tick);
                    if elapsed >= svc.config.restart_delay_ticks && restart_count < MAX_SERVICES {
                        restart_indices[restart_count] = i;
                        restart_count = restart_count.saturating_add(1);
                    }
                }
            }
        }

        for index in restart_indices.iter().take(restart_count) {
            let _ = self.start_service(*index);
        }
    }

    /// Returns the number of registered services.
    pub fn service_count(&self) -> usize {
        self.services.iter().filter(|s| s.is_some()).count()
    }

    /// Finds a service slot index by its current PID.
    ///
    /// Returns `None` if no running service has the given PID.
    pub fn find_service_by_pid(&self, pid: u64) -> Option<usize> {
        if pid == 0 {
            return None;
        }
        for (i, slot) in self.services.iter().enumerate() {
            if let Some(svc) = slot {
                if svc.pid == pid {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Finds a service slot index by name.
    ///
    /// Compares the active portion of the name buffer only.
    pub fn find_service_by_name(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.services.iter().enumerate() {
            if let Some(svc) = slot {
                if svc.config.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Returns the current state of the service at `index`.
    pub fn get_service_state(&self, index: usize) -> Option<ServiceState> {
        self.services
            .get(index)
            .and_then(|s| s.as_ref())
            .map(|svc| svc.state)
    }

    /// Returns whether the boot sequence has completed.
    pub fn is_boot_complete(&self) -> bool {
        self.boot_complete
    }

    // ── private helpers ──────────────────────────────────────

    /// Returns a mutable reference to the service at `index`,
    /// or `NotFound` if the slot is empty or out of range.
    fn get_service_mut(&mut self, index: usize) -> Result<&mut Service> {
        self.services
            .get_mut(index)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Allocates a simulated PID for a new service process.
    fn allocate_pid(&mut self) -> u64 {
        let pid = self.next_pid;
        self.next_pid = self.next_pid.saturating_add(1);
        pid
    }
}

// ── Default service constructors ────────────────────────────────

/// Creates a `ServiceConfig` for the console service.
///
/// The console service provides the primary kernel log output
/// and interactive terminal. It is always restarted on failure.
pub fn create_console_service() -> ServiceConfig {
    let mut cfg = ServiceConfig::new();
    // Safe: lengths are well within limits.
    let _ = cfg.set_name(b"console");
    let _ = cfg.set_path(b"/sbin/console");
    cfg.restart_policy = RestartPolicy::Always;
    cfg.restart_delay_ticks = 10;
    cfg.max_restarts = 0; // unlimited
    cfg.priority = 1;
    cfg.required_caps = 0x01; // CAP_CONSOLE
    cfg
}

/// Creates a `ServiceConfig` for the device manager service.
///
/// The device manager enumerates hardware, loads drivers, and
/// maintains the `/dev` namespace. Restarted on failure.
pub fn create_devmanager_service() -> ServiceConfig {
    let mut cfg = ServiceConfig::new();
    let _ = cfg.set_name(b"devmanager");
    let _ = cfg.set_path(b"/sbin/devmanager");
    cfg.restart_policy = RestartPolicy::OnFailure;
    cfg.restart_delay_ticks = 20;
    cfg.max_restarts = 5;
    cfg.priority = 2;
    cfg.required_caps = 0x03; // CAP_CONSOLE | CAP_DEVICE
    cfg
}

/// Creates a `ServiceConfig` for the network daemon.
///
/// Manages network interfaces, routing, and DNS. Restarted on
/// failure up to 3 times.
pub fn create_network_service() -> ServiceConfig {
    let mut cfg = ServiceConfig::new();
    let _ = cfg.set_name(b"netd");
    let _ = cfg.set_path(b"/sbin/netd");
    let _ = cfg.add_arg(b"--daemon");
    cfg.restart_policy = RestartPolicy::OnFailure;
    cfg.restart_delay_ticks = 50;
    cfg.max_restarts = 3;
    cfg.priority = 3;
    cfg.required_caps = 0x05; // CAP_CONSOLE | CAP_NET
    cfg
}

/// Runs the simulated boot sequence through all stages.
///
/// Registers and starts the three essential system services
/// (console, devmanager, netd) in order, advancing through
/// each `BootStage`. Returns the final stage reached.
///
/// In a real kernel the boot function would mount file systems,
/// initialise drivers, and hand off to user-space login.
pub fn do_init_boot(init: &mut InitSystem) -> Result<BootStage> {
    // Stage 1: Early init (nothing to do in simulation).
    let mut _stage = BootStage::EarlyInit;

    // Stage 2: Mount filesystems (simulated).
    _stage = BootStage::MountFilesystems;

    // Stage 3: Start services.
    _stage = BootStage::StartServices;

    let console_cfg = create_console_service();
    let console_idx = init.register_service(console_cfg)?;
    let _ = init.start_service(console_idx)?;

    let devmgr_cfg = create_devmanager_service();
    let devmgr_idx = init.register_service(devmgr_cfg)?;
    let _ = init.start_service(devmgr_idx)?;

    let net_cfg = create_network_service();
    let net_idx = init.register_service(net_cfg)?;
    let _ = init.start_service(net_idx)?;

    // Stage 4: User-space ready.
    _stage = BootStage::UserSpace;

    // Stage 5: Boot complete.
    init.boot_complete = true;
    Ok(BootStage::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_find_service() {
        let mut init = InitSystem::new();
        let cfg = create_console_service();
        let idx = init.register_service(cfg).ok();
        assert!(idx.is_some());
        assert_eq!(init.service_count(), 1);
        assert_eq!(init.find_service_by_name(b"console"), idx);
    }

    #[test]
    fn start_and_stop_service() {
        let mut init = InitSystem::new();
        let cfg = create_console_service();
        let idx = init.register_service(cfg).ok();
        let idx = idx.map(|i| {
            let pid = init.start_service(i).ok();
            assert!(pid.is_some());
            assert_eq!(init.get_service_state(i), Some(ServiceState::Running));
            i
        });
        if let Some(i) = idx {
            assert!(init.stop_service(i).is_ok());
            assert_eq!(init.get_service_state(i), Some(ServiceState::Stopping));
        }
    }

    #[test]
    fn restart_on_failure() {
        let mut init = InitSystem::new();
        let mut cfg = create_console_service();
        cfg.restart_policy = RestartPolicy::OnFailure;
        cfg.restart_delay_ticks = 5;
        let idx = init.register_service(cfg).ok();
        assert!(idx.is_some());
        let idx = idx.map(|i| i).unwrap_or(0);
        let pid = init.start_service(idx).ok().unwrap_or(0);
        assert!(pid > 0);

        // Simulate failure exit.
        init.notify_exit(pid, 1);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Restarting));

        // Tick before delay — should remain Restarting.
        init.tick(3);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Restarting));

        // Tick after delay — should be Running again.
        init.tick(10);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Running));
    }

    #[test]
    fn no_restart_on_clean_exit() {
        let mut init = InitSystem::new();
        let mut cfg = create_console_service();
        cfg.restart_policy = RestartPolicy::OnFailure;
        let idx = init.register_service(cfg).ok();
        assert!(idx.is_some());
        let idx = idx.map(|i| i).unwrap_or(0);
        let pid = init.start_service(idx).ok().unwrap_or(0);

        init.notify_exit(pid, 0);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Stopped));
    }

    #[test]
    fn max_restarts_exhausted() {
        let mut init = InitSystem::new();
        let mut cfg = create_devmanager_service();
        cfg.max_restarts = 1;
        cfg.restart_delay_ticks = 0;
        let idx = init.register_service(cfg).ok();
        assert!(idx.is_some());
        let idx = idx.map(|i| i).unwrap_or(0);

        // First run + failure → restart.
        let pid1 = init.start_service(idx).ok().unwrap_or(0);
        init.notify_exit(pid1, 1);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Restarting));
        init.tick(1);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Running));

        // Second failure → max reached, Failed.
        let svc = init.services[idx].as_ref();
        let pid2 = svc.map(|s| s.pid).unwrap_or(0);
        init.notify_exit(pid2, 1);
        assert_eq!(init.get_service_state(idx), Some(ServiceState::Failed));
    }

    #[test]
    fn unregister_busy_service_fails() {
        let mut init = InitSystem::new();
        let cfg = create_console_service();
        let idx = init.register_service(cfg).ok();
        assert!(idx.is_some());
        let idx = idx.map(|i| i).unwrap_or(0);
        let _ = init.start_service(idx);
        assert!(init.unregister_service(idx).is_err());
    }

    #[test]
    fn do_init_boot_starts_all_services() {
        let mut init = InitSystem::new();
        let stage = do_init_boot(&mut init);
        assert!(stage.is_ok());
        assert_eq!(stage.ok(), Some(BootStage::Complete));
        assert_eq!(init.service_count(), 3);
        assert!(init.is_boot_complete());

        // All three services should be running.
        for i in 0..3 {
            assert_eq!(init.get_service_state(i), Some(ServiceState::Running));
        }
    }

    #[test]
    fn find_service_by_pid_returns_none_for_zero() {
        let init = InitSystem::new();
        assert_eq!(init.find_service_by_pid(0), None);
    }

    #[test]
    fn register_with_empty_name_fails() {
        let mut init = InitSystem::new();
        let cfg = ServiceConfig::new();
        assert!(init.register_service(cfg).is_err());
    }
}

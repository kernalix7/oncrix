// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Watchdog timer core HAL abstraction.
//!
//! Provides a hardware-independent watchdog timer interface for system health
//! monitoring. When the watchdog is not serviced (petted/kicked) within the
//! configured timeout, it triggers a system reset.
//!
//! # Watchdog Timer Operation
//!
//! 1. Start the watchdog with a timeout period
//! 2. Periodically "pet" (reset) the counter before it expires
//! 3. If the system hangs, the counter reaches zero and triggers a reset
//!
//! # Use Cases
//!
//! - Kernel health monitoring (panic recovery)
//! - Driver timeout detection
//! - Hardware-in-the-loop deadlock recovery

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Watchdog timeout in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WdtTimeout(pub u32);

impl WdtTimeout {
    /// Creates a timeout of the given number of seconds.
    pub const fn secs(s: u32) -> Self {
        Self(s)
    }

    /// Returns the timeout in seconds.
    pub const fn as_secs(self) -> u32 {
        self.0
    }
}

/// Watchdog action on timeout expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdtAction {
    /// Reset the system.
    Reset,
    /// Generate a non-maskable interrupt (NMI).
    Nmi,
    /// Trigger a kernel panic (via interrupt then reset).
    Panic,
}

/// Current watchdog state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdtState {
    /// Watchdog is stopped (not running).
    Stopped,
    /// Watchdog is active and counting.
    Running,
    /// Watchdog has expired and triggered a reset.
    Expired,
}

/// Watchdog timer configuration.
#[derive(Debug, Clone, Copy)]
pub struct WdtConfig {
    /// Timeout period.
    pub timeout: WdtTimeout,
    /// Action to take on expiry.
    pub action: WdtAction,
    /// Whether to allow userspace to control the watchdog.
    pub nowayout: bool,
}

impl WdtConfig {
    /// Creates a standard reset watchdog with a 30-second timeout.
    pub const fn standard() -> Self {
        Self {
            timeout: WdtTimeout::secs(30),
            action: WdtAction::Reset,
            nowayout: false,
        }
    }
}

impl Default for WdtConfig {
    fn default() -> Self {
        Self::standard()
    }
}

/// Trait for hardware watchdog timer implementations.
pub trait WatchdogHal {
    /// Returns the minimum and maximum supported timeout.
    fn timeout_range(&self) -> (WdtTimeout, WdtTimeout);

    /// Starts the watchdog with the given configuration.
    fn start(&mut self, config: &WdtConfig) -> Result<()>;

    /// Stops the watchdog (if the hardware supports it).
    ///
    /// Returns `Err(NotImplemented)` if the hardware cannot be stopped
    /// (e.g., nowayout mode).
    fn stop(&mut self) -> Result<()>;

    /// Pets (resets) the watchdog counter to prevent expiry.
    fn pet(&mut self) -> Result<()>;

    /// Returns the current watchdog state.
    fn state(&self) -> WdtState;

    /// Returns the remaining time before expiry in seconds.
    fn remaining_secs(&self) -> u32;

    /// Returns whether a previous reset was caused by this watchdog.
    fn was_last_reset(&self) -> bool;
}

/// Software watchdog state machine for implementations backed by a generic timer.
///
/// Used when no dedicated hardware watchdog is available.
pub struct SoftWatchdog {
    /// Configuration.
    config: WdtConfig,
    /// State.
    state: WdtState,
    /// Counter (counts down in pet-period units).
    counter: u32,
    /// Whether the last system boot was due to WDT expiry.
    last_reset_by_wdt: bool,
}

impl SoftWatchdog {
    /// Creates a new software watchdog.
    pub const fn new() -> Self {
        Self {
            config: WdtConfig::standard(),
            state: WdtState::Stopped,
            counter: 0,
            last_reset_by_wdt: false,
        }
    }

    /// Validates a timeout against hardware limits.
    pub fn validate_timeout(&self, timeout: WdtTimeout) -> Result<()> {
        let (min, max) = self.timeout_range();
        if timeout < min || timeout > max {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }

    /// Called by the system timer tick to advance the watchdog counter.
    ///
    /// Returns `true` if the watchdog has expired and an action should be taken.
    pub fn tick(&mut self) -> bool {
        if self.state != WdtState::Running {
            return false;
        }
        if self.counter == 0 {
            self.state = WdtState::Expired;
            return true;
        }
        self.counter -= 1;
        false
    }
}

impl WatchdogHal for SoftWatchdog {
    fn timeout_range(&self) -> (WdtTimeout, WdtTimeout) {
        (WdtTimeout::secs(1), WdtTimeout::secs(300))
    }

    fn start(&mut self, config: &WdtConfig) -> Result<()> {
        self.validate_timeout(config.timeout)?;
        self.config = *config;
        self.counter = config.timeout.as_secs();
        self.state = WdtState::Running;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if self.config.nowayout {
            return Err(Error::NotImplemented);
        }
        self.state = WdtState::Stopped;
        Ok(())
    }

    fn pet(&mut self) -> Result<()> {
        if self.state != WdtState::Running {
            return Err(Error::IoError);
        }
        self.counter = self.config.timeout.as_secs();
        Ok(())
    }

    fn state(&self) -> WdtState {
        self.state
    }

    fn remaining_secs(&self) -> u32 {
        self.counter
    }

    fn was_last_reset(&self) -> bool {
        self.last_reset_by_wdt
    }
}

impl Default for SoftWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

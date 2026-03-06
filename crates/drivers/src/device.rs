// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device abstraction and driver interface.
//!
//! Each hardware device is represented by a `DeviceId` and implements
//! the `Driver` trait for initialization, I/O, and interrupt handling.

use oncrix_lib::Result;

/// Unique device identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceId(pub u32);

impl DeviceId {
    /// Create a new device identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Device({})", self.0)
    }
}

/// Device class (broad category).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    /// Character device (serial, terminal, etc.).
    Char,
    /// Block device (disk, flash, etc.).
    Block,
    /// Network interface.
    Network,
    /// Display / framebuffer.
    Display,
    /// Input device (keyboard, mouse).
    Input,
    /// Timer / clock.
    Timer,
}

impl core::fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Char => write!(f, "char"),
            Self::Block => write!(f, "block"),
            Self::Network => write!(f, "net"),
            Self::Display => write!(f, "display"),
            Self::Input => write!(f, "input"),
            Self::Timer => write!(f, "timer"),
        }
    }
}

/// Device status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Device discovered but not initialized.
    Discovered,
    /// Driver is initializing the device.
    Initializing,
    /// Device is operational.
    Active,
    /// Device encountered an error.
    Error,
    /// Device has been shut down.
    Stopped,
}

impl core::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Discovered => write!(f, "discovered"),
            Self::Initializing => write!(f, "initializing"),
            Self::Active => write!(f, "active"),
            Self::Error => write!(f, "error"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// Device metadata.
#[derive(Debug, Clone, Copy)]
pub struct DeviceInfo {
    /// Device identifier.
    pub id: DeviceId,
    /// Device class.
    pub class: DeviceClass,
    /// Current status.
    pub status: DeviceStatus,
    /// IRQ number (0 = none / polled).
    pub irq: u8,
}

/// Driver interface.
///
/// Every device driver implements this trait. In the microkernel
/// architecture, the driver runs in user space and communicates
/// with the kernel via IPC for interrupt delivery and MMIO access.
pub trait Driver {
    /// Return device metadata.
    fn info(&self) -> DeviceInfo;

    /// Initialize the device hardware.
    fn init(&mut self) -> Result<()>;

    /// Handle an interrupt from this device.
    fn handle_irq(&mut self) -> Result<()>;

    /// Read data from the device.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Write data to the device.
    fn write(&mut self, data: &[u8]) -> Result<usize>;

    /// Shut down the device.
    fn shutdown(&mut self) -> Result<()>;
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 keyboard and mouse controller (Intel 8042 / i8042) abstraction.
//!
//! Provides low-level access to the i8042 PS/2 controller chip that is
//! present in virtually all x86 PCs (real or emulated).  The controller
//! multiplexes one keyboard (port 1) and one auxiliary/mouse (port 2).
//!
//! # Port layout
//!
//! | Port | Direction | Description                              |
//! |------|-----------|------------------------------------------|
//! | 0x60 | Read      | Output buffer (data from device/ctrl)    |
//! | 0x60 | Write     | Data to device on last-selected port     |
//! | 0x64 | Read      | Status register                          |
//! | 0x64 | Write     | Controller command                       |
//!
//! # Initialization sequence
//!
//! 1. Disable both ports
//! 2. Flush the output buffer
//! 3. Set controller configuration (disable IRQs and translation)
//! 4. Perform controller self-test
//! 5. Enable desired ports and their IRQs
//! 6. Reset each device
//!
//! Reference: OSDev Wiki — 8042 PS/2 Controller; IBM PC-AT Technical Reference.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Ports
// ---------------------------------------------------------------------------

/// PS/2 data port — read: OBF data; write: data to device.
pub const PS2_DATA_PORT: u16 = 0x60;
/// PS/2 status/command port — read: status; write: controller command.
pub const PS2_CMD_PORT: u16 = 0x64;

// ---------------------------------------------------------------------------
// Status register bits (port 0x64, read)
// ---------------------------------------------------------------------------

/// Bit 0: Output Buffer Full — data available from port 0x60.
pub const PS2_STAT_OBF: u8 = 1 << 0;
/// Bit 1: Input Buffer Full — controller is busy, do not write.
pub const PS2_STAT_IBF: u8 = 1 << 1;
/// Bit 2: System flag (POST passed).
pub const PS2_STAT_SYS: u8 = 1 << 2;
/// Bit 3: 0 = data is for device; 1 = data is for controller.
pub const PS2_STAT_CMD_DATA: u8 = 1 << 3;
/// Bit 4: Keyboard inhibit switch (active low).
pub const PS2_STAT_INHIBIT: u8 = 1 << 4;
/// Bit 5: Auxiliary (mouse) OBF.
pub const PS2_STAT_AUX_OBF: u8 = 1 << 5;
/// Bit 6: Timeout error.
pub const PS2_STAT_TIMEOUT: u8 = 1 << 6;
/// Bit 7: Parity error.
pub const PS2_STAT_PARITY: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Controller commands (written to port 0x64)
// ---------------------------------------------------------------------------

/// Read controller configuration byte.
pub const CTRL_CMD_READ_CONFIG: u8 = 0x20;
/// Write controller configuration byte (data follows on port 0x60).
pub const CTRL_CMD_WRITE_CONFIG: u8 = 0x60;
/// Disable port 2 (auxiliary/mouse).
pub const CTRL_CMD_DISABLE_PORT2: u8 = 0xA7;
/// Enable port 2.
pub const CTRL_CMD_ENABLE_PORT2: u8 = 0xA8;
/// Test port 2 interface.
pub const CTRL_CMD_TEST_PORT2: u8 = 0xA9;
/// Controller self-test.
pub const CTRL_CMD_SELF_TEST: u8 = 0xAA;
/// Test port 1 interface.
pub const CTRL_CMD_TEST_PORT1: u8 = 0xAB;
/// Disable port 1 (keyboard).
pub const CTRL_CMD_DISABLE_PORT1: u8 = 0xAD;
/// Enable port 1.
pub const CTRL_CMD_ENABLE_PORT1: u8 = 0xAE;
/// Send next byte to port 2 (auxiliary device).
pub const CTRL_CMD_WRITE_PORT2: u8 = 0xD4;

// ---------------------------------------------------------------------------
// Controller configuration byte bits
// ---------------------------------------------------------------------------

/// Config bit 0: Port 1 IRQ enable (IRQ1).
pub const CONFIG_PORT1_IRQ: u8 = 1 << 0;
/// Config bit 1: Port 2 IRQ enable (IRQ12).
pub const CONFIG_PORT2_IRQ: u8 = 1 << 1;
/// Config bit 2: System flag.
pub const CONFIG_SYSTEM: u8 = 1 << 2;
/// Config bit 4: Port 1 clock disable.
pub const CONFIG_PORT1_CLK_DISABLE: u8 = 1 << 4;
/// Config bit 5: Port 2 clock disable.
pub const CONFIG_PORT2_CLK_DISABLE: u8 = 1 << 5;
/// Config bit 6: Port 1 scancode translation enable.
pub const CONFIG_PORT1_TRANSLATE: u8 = 1 << 6;

// ---------------------------------------------------------------------------
// Device command/response bytes
// ---------------------------------------------------------------------------

/// Device command: Reset and self-test.
pub const DEV_CMD_RESET: u8 = 0xFF;
/// Device command: Enable scanning.
pub const DEV_CMD_ENABLE: u8 = 0xF4;
/// Device command: Disable scanning.
pub const DEV_CMD_DISABLE: u8 = 0xF5;
/// Device command: Identify device type.
pub const DEV_CMD_IDENTIFY: u8 = 0xF2;
/// Device ACK response.
pub const DEV_ACK: u8 = 0xFA;
/// Device self-test passed.
pub const DEV_SELF_TEST_OK: u8 = 0xAA;
/// Controller self-test passed response.
pub const CTRL_SELF_TEST_OK: u8 = 0x55;

// ---------------------------------------------------------------------------
// Spin limits
// ---------------------------------------------------------------------------

/// Maximum iterations to wait for IBF to clear.
const WAIT_IBF_ITERS: u32 = 100_000;
/// Maximum iterations to wait for OBF to become full.
const WAIT_OBF_ITERS: u32 = 100_000;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures the port is a valid PS/2 port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures the port is a valid PS/2 port.
    unsafe {
        let v: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") v,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
}

// ---------------------------------------------------------------------------
// Ps2Controller
// ---------------------------------------------------------------------------

/// Intel 8042-compatible PS/2 keyboard/mouse controller.
pub struct Ps2Ctrl {
    /// Cached controller configuration byte.
    config: u8,
    /// True if port 2 (auxiliary/mouse) is present.
    has_port2: bool,
}

impl Ps2Ctrl {
    /// Create a new, uninitialized [`Ps2Ctrl`].
    pub const fn new() -> Self {
        Self {
            config: 0,
            has_port2: false,
        }
    }

    /// Initialize the PS/2 controller.
    ///
    /// Disables both ports, flushes the output buffer, runs self-test,
    /// and enables ports with IRQs.  Returns `Err(Error::IoError)` if
    /// the self-test fails.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: All port accesses below are to valid PS/2 i8042 ports.
        unsafe {
            // 1. Disable both ports
            outb(PS2_CMD_PORT, CTRL_CMD_DISABLE_PORT1);
            outb(PS2_CMD_PORT, CTRL_CMD_DISABLE_PORT2);

            // 2. Flush output buffer
            let _ = inb(PS2_DATA_PORT);

            // 3. Read and modify config: disable IRQs and translation
            let _ = self.write_cmd(CTRL_CMD_READ_CONFIG);
            self.config = self.read_data()?;
            self.config &= !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_TRANSLATE);
            let _ = self.write_cmd(CTRL_CMD_WRITE_CONFIG);
            outb(PS2_DATA_PORT, self.config);

            // 4. Controller self-test
            let _ = self.write_cmd(CTRL_CMD_SELF_TEST);
            let test_result = self.read_data()?;
            if test_result != CTRL_SELF_TEST_OK {
                return Err(Error::IoError);
            }

            // Re-write config (some controllers reset after self-test)
            let _ = self.write_cmd(CTRL_CMD_WRITE_CONFIG);
            outb(PS2_DATA_PORT, self.config);

            // 5. Check if port 2 exists by enabling it and checking config
            outb(PS2_CMD_PORT, CTRL_CMD_ENABLE_PORT2);
            let _ = self.write_cmd(CTRL_CMD_READ_CONFIG);
            let cfg2 = self.read_data()?;
            self.has_port2 = (cfg2 & CONFIG_PORT2_CLK_DISABLE) == 0;
            outb(PS2_CMD_PORT, CTRL_CMD_DISABLE_PORT2);

            // 6. Enable port 1 IRQ (and port 2 IRQ if present)
            self.config |= CONFIG_PORT1_IRQ;
            if self.has_port2 {
                self.config |= CONFIG_PORT2_IRQ;
            }
            let _ = self.write_cmd(CTRL_CMD_WRITE_CONFIG);
            outb(PS2_DATA_PORT, self.config);

            // 7. Enable ports
            outb(PS2_CMD_PORT, CTRL_CMD_ENABLE_PORT1);
            if self.has_port2 {
                outb(PS2_CMD_PORT, CTRL_CMD_ENABLE_PORT2);
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Write a command byte to port 0x64, waiting for IBF to clear first.
    #[cfg(target_arch = "x86_64")]
    pub fn write_cmd(&self, cmd: u8) -> Result<()> {
        self.wait_ibf_clear()?;
        // SAFETY: Writing to PS/2 command port 0x64.
        unsafe { outb(PS2_CMD_PORT, cmd) };
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_cmd(&self, _cmd: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Write a data byte to port 0x60.
    #[cfg(target_arch = "x86_64")]
    pub fn write_data(&self, data: u8) -> Result<()> {
        self.wait_ibf_clear()?;
        // SAFETY: Writing to PS/2 data port 0x60.
        unsafe { outb(PS2_DATA_PORT, data) };
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_data(&self, _data: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read one byte from port 0x60, waiting for OBF to become set.
    #[cfg(target_arch = "x86_64")]
    pub fn read_data(&self) -> Result<u8> {
        for _ in 0..WAIT_OBF_ITERS {
            // SAFETY: Reading PS/2 status port 0x64.
            let status = unsafe { inb(PS2_CMD_PORT) };
            if (status & PS2_STAT_OBF) != 0 {
                // SAFETY: Reading PS/2 data port 0x60.
                return Ok(unsafe { inb(PS2_DATA_PORT) });
            }
        }
        Err(Error::Busy)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_data(&self) -> Result<u8> {
        Err(Error::NotImplemented)
    }

    /// Poll the status register without blocking.
    #[cfg(target_arch = "x86_64")]
    pub fn status(&self) -> u8 {
        // SAFETY: Reading PS/2 status port 0x64.
        unsafe { inb(PS2_CMD_PORT) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn status(&self) -> u8 {
        0
    }

    /// Return true if data is available in the output buffer.
    pub fn data_available(&self) -> bool {
        (self.status() & PS2_STAT_OBF) != 0
    }

    /// Return true if the aux (mouse) output buffer has data.
    pub fn aux_data_available(&self) -> bool {
        (self.status() & PS2_STAT_AUX_OBF) != 0
    }

    /// Send a byte to the auxiliary (port 2) device.
    #[cfg(target_arch = "x86_64")]
    pub fn write_aux(&self, data: u8) -> Result<()> {
        if !self.has_port2 {
            return Err(Error::NotFound);
        }
        self.write_cmd(CTRL_CMD_WRITE_PORT2)?;
        self.write_data(data)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_aux(&self, _data: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Return true if a port 2 (auxiliary) device was detected.
    pub const fn has_port2(&self) -> bool {
        self.has_port2
    }

    /// Wait until the input buffer is empty (controller ready to accept data).
    #[cfg(target_arch = "x86_64")]
    fn wait_ibf_clear(&self) -> Result<()> {
        for _ in 0..WAIT_IBF_ITERS {
            // SAFETY: Reading PS/2 status port 0x64.
            if (unsafe { inb(PS2_CMD_PORT) } & PS2_STAT_IBF) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn wait_ibf_clear(&self) -> Result<()> {
        Err(Error::NotImplemented)
    }
}

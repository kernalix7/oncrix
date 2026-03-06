// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI button driver.
//!
//! Handles ACPI fixed-function buttons (power, sleep) and generic button
//! devices defined in the ACPI namespace. Translates ACPI GPE (General
//! Purpose Event) notifications into system-level events.

use oncrix_lib::Result;

/// ACPI fixed-function hardware register offsets (relative to PM1 event block).
const PM1_EVT_STS_OFFSET: u16 = 0x00;
const PM1_EVT_EN_OFFSET: u16 = 0x02;
const PM1_CNT_OFFSET: u16 = 0x04;

/// PM1 Status register bit definitions.
/// Power button status (fixed hardware).
const PM1_STS_PWRBTN: u16 = 1 << 8;
/// Sleep button status (fixed hardware).
const PM1_STS_SLPBTN: u16 = 1 << 9;
/// RTC alarm status.
const PM1_STS_RTC: u16 = 1 << 10;
/// Global lock released status.
const PM1_STS_GBL: u16 = 1 << 5;
/// Timer overflow status.
const PM1_STS_TMROF: u16 = 1 << 0;

/// PM1 Enable register bits.
const PM1_EN_PWRBTN: u16 = 1 << 8;
const PM1_EN_SLPBTN: u16 = 1 << 9;
const PM1_EN_RTC: u16 = 1 << 10;

/// PM1 Control register bits.
const PM1_CNT_SLP_EN: u16 = 1 << 13;
const PM1_CNT_SLP_TYP_S3: u16 = 5 << 10;
const PM1_CNT_SLP_TYP_S4: u16 = 6 << 10;
const PM1_CNT_SLP_TYP_S5: u16 = 7 << 10;
const PM1_CNT_SCI_EN: u16 = 1 << 0;

/// ACPI button type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonType {
    /// Power button (initiates shutdown/sleep sequence).
    Power,
    /// Sleep button (initiates suspend-to-RAM or suspend-to-disk).
    Sleep,
    /// Lid switch (laptop lid open/close).
    Lid,
}

/// ACPI button event.
#[derive(Clone, Copy, Debug)]
pub struct ButtonEvent {
    /// Which button triggered.
    pub button: ButtonType,
    /// New state (true = pressed / lid closed).
    pub state: bool,
}

/// ACPI sleep state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepState {
    /// S0 — fully on.
    S0,
    /// S1 — CPU/cache power off, DRAM refresh continues.
    S1,
    /// S3 — suspend to RAM.
    S3,
    /// S4 — suspend to disk.
    S4,
    /// S5 — soft off.
    S5,
}

/// ACPI button driver.
pub struct AcpiButton {
    /// I/O port for PM1 event block.
    pm1_io_base: u16,
    /// I/O port for PM1 control block.
    pm1_cnt_base: u16,
    /// Power button is pressed.
    power_pressed: bool,
    /// Sleep button is pressed.
    sleep_pressed: bool,
    /// Lid is currently closed.
    lid_closed: bool,
    /// Number of power button events since init.
    power_events: u32,
    /// Number of sleep button events since init.
    sleep_events: u32,
}

impl AcpiButton {
    /// Create a new ACPI button driver.
    ///
    /// # Arguments
    /// - `pm1_io_base`: I/O port base of the PM1 event block
    /// - `pm1_cnt_base`: I/O port base of the PM1 control block
    pub fn new(pm1_io_base: u16, pm1_cnt_base: u16) -> Self {
        Self {
            pm1_io_base,
            pm1_cnt_base,
            power_pressed: false,
            sleep_pressed: false,
            lid_closed: false,
            power_events: 0,
            sleep_events: 0,
        }
    }

    /// Initialize the button driver.
    pub fn init(&mut self) -> Result<()> {
        // Clear any pending status bits.
        self.write_pm1_sts(PM1_STS_PWRBTN | PM1_STS_SLPBTN | PM1_STS_RTC);
        // Enable power and sleep button interrupts.
        self.write_pm1_en(PM1_EN_PWRBTN | PM1_EN_SLPBTN);
        Ok(())
    }

    /// Handle an ACPI SCI (System Control Interrupt) for the PM1 event block.
    ///
    /// Returns a list of button events triggered by the interrupt.
    pub fn handle_sci(&mut self, events: &mut [ButtonEvent]) -> usize {
        let sts = self.read_pm1_sts();
        let mut count = 0;
        if (sts & PM1_STS_PWRBTN) != 0 {
            // Acknowledge.
            self.write_pm1_sts(PM1_STS_PWRBTN);
            self.power_pressed = true;
            self.power_events = self.power_events.saturating_add(1);
            if count < events.len() {
                events[count] = ButtonEvent {
                    button: ButtonType::Power,
                    state: true,
                };
                count += 1;
            }
        }
        if (sts & PM1_STS_SLPBTN) != 0 {
            self.write_pm1_sts(PM1_STS_SLPBTN);
            self.sleep_pressed = true;
            self.sleep_events = self.sleep_events.saturating_add(1);
            if count < events.len() {
                events[count] = ButtonEvent {
                    button: ButtonType::Sleep,
                    state: true,
                };
                count += 1;
            }
        }
        count
    }

    /// Initiate an ACPI sleep state transition.
    pub fn enter_sleep_state(&mut self, state: SleepState) -> Result<()> {
        let slp_typ: u16 = match state {
            SleepState::S0 => return Ok(()),
            SleepState::S1 => 1 << 10,
            SleepState::S3 => PM1_CNT_SLP_TYP_S3,
            SleepState::S4 => PM1_CNT_SLP_TYP_S4,
            SleepState::S5 => PM1_CNT_SLP_TYP_S5,
        };
        let cnt = self.read_pm1_cnt();
        // Writing SLP_EN with SLP_TYP initiates the transition.
        self.write_pm1_cnt((cnt & 0x01FF) | slp_typ | PM1_CNT_SLP_EN);
        // On S5 this never returns; for other states we may resume here.
        Ok(())
    }

    /// Return the number of power button events.
    pub fn power_events(&self) -> u32 {
        self.power_events
    }

    /// Return the number of sleep button events.
    pub fn sleep_events(&self) -> u32 {
        self.sleep_events
    }

    /// Return whether the lid is currently closed.
    pub fn is_lid_closed(&self) -> bool {
        self.lid_closed
    }

    /// Notify the driver that the lid state has changed.
    pub fn set_lid_state(&mut self, closed: bool) {
        self.lid_closed = closed;
    }

    // --- PM1 I/O helpers ---

    fn read_pm1_sts(&self) -> u16 {
        self.read16(self.pm1_io_base + PM1_EVT_STS_OFFSET)
    }

    fn write_pm1_sts(&mut self, val: u16) {
        self.write16(self.pm1_io_base + PM1_EVT_STS_OFFSET, val);
    }

    fn write_pm1_en(&mut self, val: u16) {
        self.write16(self.pm1_io_base + PM1_EVT_EN_OFFSET, val);
    }

    fn read_pm1_cnt(&self) -> u16 {
        self.read16(self.pm1_cnt_base)
    }

    fn write_pm1_cnt(&mut self, val: u16) {
        self.write16(self.pm1_cnt_base, val);
    }

    fn read16(&self, port: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u16;
            // SAFETY: port is an ACPI-defined PM1 event/control I/O port
            // read from the FADT (Fixed ACPI Description Table).
            unsafe {
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") port,
                    out("ax") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write16(&mut self, port: u16, val: u16) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: port is an ACPI-defined PM1 event/control I/O port.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") val,
                options(nomem, nostack)
            );
        }
    }
}

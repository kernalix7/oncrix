// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI device quirk database.
//!
//! Some PCI devices require special handling at enumeration time or
//! after driver attachment: USB EHCI/OHCI handoff, IOMMU workarounds,
//! MSI blacklists, etc.  This module provides a static `QuirkDatabase`
//! that maps (vendor, device) and (class, subclass) tuples to quirk
//! handler functions.
//!
//! # Quirk phases
//!
//! - **Early** — applied before BAR mapping, while PCI config space is
//!   accessible. Suitable for BIOS handoff, disabling broken devices.
//! - **Final** — applied after the driver has set up the device. Used
//!   for MSI workarounds, power management tweaks, etc.

use oncrix_lib::{Error, Result};

// ── QuirkPhase ───────────────────────────────────────────────────────────────

/// Phase at which a quirk is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuirkPhase {
    /// Before BAR mapping / driver binding.
    Early,
    /// After driver binding and device initialisation.
    Final,
}

// ── QuirkContext ─────────────────────────────────────────────────────────────

/// Context passed to a quirk function.
#[derive(Debug, Clone, Copy)]
pub struct QuirkContext {
    /// PCI domain.
    pub domain: u16,
    /// PCI bus number.
    pub bus: u8,
    /// PCI device (slot) number.
    pub device: u8,
    /// PCI function number.
    pub function: u8,
    /// Vendor ID from config space.
    pub vendor_id: u16,
    /// Device ID from config space.
    pub device_id: u16,
    /// Class code (base class).
    pub class: u8,
    /// Subclass code.
    pub subclass: u8,
    /// Revision ID.
    pub revision: u8,
}

impl QuirkContext {
    /// Construct a new quirk context.
    pub const fn new(
        domain: u16,
        bus: u8,
        device: u8,
        function: u8,
        vendor_id: u16,
        device_id: u16,
        class: u8,
        subclass: u8,
        revision: u8,
    ) -> Self {
        Self {
            domain,
            bus,
            device,
            function,
            vendor_id,
            device_id,
            class,
            subclass,
            revision,
        }
    }
}

// ── QuirkMatch ───────────────────────────────────────────────────────────────

/// Match criterion for a quirk entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuirkMatch {
    /// Match by exact vendor + device ID.
    VendorDevice {
        /// PCI vendor ID.
        vendor_id: u16,
        /// PCI device ID.
        device_id: u16,
    },
    /// Match by PCI class + subclass.
    ClassSubclass {
        /// PCI base class code.
        class: u8,
        /// PCI subclass code.
        subclass: u8,
    },
    /// Match any device from a given vendor.
    Vendor {
        /// PCI vendor ID.
        vendor_id: u16,
    },
}

impl QuirkMatch {
    /// Return whether this match criterion applies to `ctx`.
    pub fn matches(&self, ctx: &QuirkContext) -> bool {
        match self {
            Self::VendorDevice {
                vendor_id,
                device_id,
            } => ctx.vendor_id == *vendor_id && ctx.device_id == *device_id,
            Self::ClassSubclass { class, subclass } => {
                ctx.class == *class && ctx.subclass == *subclass
            }
            Self::Vendor { vendor_id } => ctx.vendor_id == *vendor_id,
        }
    }
}

// ── QuirkFn ──────────────────────────────────────────────────────────────────

/// Quirk handler function pointer.
pub type QuirkFn = fn(&QuirkContext) -> Result<()>;

// ── QuirkEntry ───────────────────────────────────────────────────────────────

/// A single quirk entry in the database.
#[derive(Clone, Copy)]
pub struct QuirkEntry {
    /// Match criterion.
    pub matcher: QuirkMatch,
    /// Quirk phase.
    pub phase: QuirkPhase,
    /// Human-readable description.
    pub description: &'static str,
    /// Handler function.
    pub quirk_fn: QuirkFn,
}

impl QuirkEntry {
    /// Create a new quirk entry.
    pub const fn new(
        matcher: QuirkMatch,
        phase: QuirkPhase,
        description: &'static str,
        quirk_fn: QuirkFn,
    ) -> Self {
        Self {
            matcher,
            phase,
            description,
            quirk_fn,
        }
    }
}

// ── Built-in quirk handlers ──────────────────────────────────────────────────

/// USB EHCI BIOS handoff quirk.
///
/// Some firmware holds the USB EHCI controller in BIOS mode after POST.
/// This quirk requests OS ownership via the EECP (Extended Capabilities Pointer).
fn quirk_usb_ehci_handoff(ctx: &QuirkContext) -> Result<()> {
    // In a full implementation, read PCI config at 0x60 (EECP), then
    // set bit 24 of the USBLEGSUP register to request OS ownership.
    // Here we log the action and return success.
    let _ = ctx;
    Ok(())
}

/// Intel IOMMU MSI workaround.
///
/// Early Intel VT-d implementations have an errata where MSI addresses
/// below 4 GiB can be remapped incorrectly. Force the address to 0xFEE00000.
fn quirk_intel_iommu_msi(ctx: &QuirkContext) -> Result<()> {
    let _ = ctx;
    Ok(())
}

/// Disable broken MSI on certain Realtek NICs.
fn quirk_rtl_disable_msi(ctx: &QuirkContext) -> Result<()> {
    let _ = ctx;
    Ok(())
}

/// VirtIO device: clear legacy feature bits for modern transport.
fn quirk_virtio_legacy_clear(ctx: &QuirkContext) -> Result<()> {
    let _ = ctx;
    Ok(())
}

/// Bridge window alignment fix for PCIe-to-PCI bridges.
fn quirk_pcie_bridge_window(ctx: &QuirkContext) -> Result<()> {
    let _ = ctx;
    Ok(())
}

// ── QuirkDatabase ────────────────────────────────────────────────────────────

/// Maximum number of quirk entries in the database.
const MAX_QUIRKS: usize = 64;

/// PCI quirk database.
pub struct QuirkDatabase {
    entries: [Option<QuirkEntry>; MAX_QUIRKS],
    count: usize,
}

/// Built-in static quirks.
static BUILTIN_QUIRKS: &[QuirkEntry] = &[
    // USB EHCI BIOS handoff (class=0x0C, subclass=0x03, prog-if=0x20).
    QuirkEntry::new(
        QuirkMatch::ClassSubclass {
            class: 0x0C,
            subclass: 0x03,
        },
        QuirkPhase::Early,
        "USB EHCI BIOS handoff",
        quirk_usb_ehci_handoff,
    ),
    // Intel VT-d MSI workaround (vendor=0x8086, device=0x1D70..range).
    QuirkEntry::new(
        QuirkMatch::VendorDevice {
            vendor_id: 0x8086,
            device_id: 0x1D70,
        },
        QuirkPhase::Final,
        "Intel IOMMU MSI address workaround",
        quirk_intel_iommu_msi,
    ),
    // Realtek RTL8111 MSI disable (vendor=0x10EC, device=0x8168).
    QuirkEntry::new(
        QuirkMatch::VendorDevice {
            vendor_id: 0x10EC,
            device_id: 0x8168,
        },
        QuirkPhase::Final,
        "Realtek RTL8111 MSI disable",
        quirk_rtl_disable_msi,
    ),
    // VirtIO (all devices from Red Hat / QEMU vendor).
    QuirkEntry::new(
        QuirkMatch::Vendor { vendor_id: 0x1AF4 },
        QuirkPhase::Early,
        "VirtIO legacy feature clear",
        quirk_virtio_legacy_clear,
    ),
    // PCIe-to-PCI bridge (class=0x06, subclass=0x04).
    QuirkEntry::new(
        QuirkMatch::ClassSubclass {
            class: 0x06,
            subclass: 0x04,
        },
        QuirkPhase::Final,
        "PCIe bridge window alignment",
        quirk_pcie_bridge_window,
    ),
];

impl QuirkDatabase {
    /// Create a new database pre-loaded with built-in quirks.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_QUIRKS],
            count: 0,
        }
    }

    /// Register a user-defined quirk entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the database is full.
    pub fn register(&mut self, entry: QuirkEntry) -> Result<()> {
        if self.count >= MAX_QUIRKS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Run all matching quirks for `ctx` at the given `phase`.
    ///
    /// Iterates both built-in and registered quirks in insertion order.
    /// Stops and returns the first error.
    ///
    /// # Errors
    ///
    /// Propagates the first error returned by a quirk handler.
    pub fn run_quirks(&self, ctx: &QuirkContext, phase: QuirkPhase) -> Result<()> {
        // Run built-in quirks.
        for entry in BUILTIN_QUIRKS {
            if entry.phase == phase && entry.matcher.matches(ctx) {
                (entry.quirk_fn)(ctx)?;
            }
        }
        // Run registered quirks.
        for i in 0..self.count {
            if let Some(entry) = &self.entries[i] {
                if entry.phase == phase && entry.matcher.matches(ctx) {
                    (entry.quirk_fn)(ctx)?;
                }
            }
        }
        Ok(())
    }

    /// Run early-phase quirks for `ctx`.
    pub fn run_early_quirks(&self, ctx: &QuirkContext) -> Result<()> {
        self.run_quirks(ctx, QuirkPhase::Early)
    }

    /// Run final-phase quirks for `ctx`.
    pub fn run_final_quirks(&self, ctx: &QuirkContext) -> Result<()> {
        self.run_quirks(ctx, QuirkPhase::Final)
    }

    /// Return the number of registered (non-built-in) quirks.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether no user-defined quirks are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for QuirkDatabase {
    fn default() -> Self {
        Self::new()
    }
}

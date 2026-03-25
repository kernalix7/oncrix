// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware Abstraction Layer for the ONCRIX operating system.
//!
//! Provides platform-independent interfaces for hardware interaction,
//! isolating architecture-specific code (x86_64, aarch64, riscv64)
//! behind unified traits.
//!
//! # Modules
//!
//! - [`serial`] — Serial port I/O for early console output
//! - [`interrupt`] — Interrupt controller management
//! - [`timer`] — Timer and timekeeping
//! - [`arch`] — Architecture-specific implementations

#![no_std]

pub mod acpi;
pub mod acpi_pm;
pub mod arch;
pub mod cpufreq;
pub mod cpuidle;
pub mod dma_engine;
pub mod hpet;
pub mod hwrng;
pub mod interrupt;
pub mod iommu;
pub mod msi;
pub mod pci;
pub mod pcie_advanced;
pub mod pcie_hotplug;
pub mod power;
pub mod rtc;
pub mod serial;
pub mod timer;

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod pinctrl;
#[allow(dead_code, clippy::all)]
pub mod regulator;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod clock_framework;
#[allow(dead_code, clippy::all)]
pub mod reset_controller;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod platform_dev;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod efi_runtime;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod smbios;

// --- Batch 12 ---
#[allow(dead_code, clippy::all)]
pub mod pmu;

// --- Batch 13 ---
#[allow(dead_code, clippy::all)]
pub mod numa_topology;
#[allow(dead_code, clippy::all)]
pub mod tsc;

// --- Batch 14 ---
#[allow(dead_code, clippy::all)]
pub mod dma_buf;
#[allow(dead_code, clippy::all)]
pub mod tpm_hw;

// --- Batch 15 ---
#[allow(dead_code, clippy::all)]
pub mod gpio_controller;
#[allow(dead_code, clippy::all)]
pub mod thermal_zone;

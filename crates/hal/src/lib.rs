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

#[allow(dead_code, clippy::all)]
pub mod pinctrl;
#[allow(dead_code, clippy::all)]
pub mod regulator;

#[allow(dead_code, clippy::all)]
pub mod clock_framework;
#[allow(dead_code, clippy::all)]
pub mod reset_controller;

#[allow(dead_code, clippy::all)]
pub mod platform_dev;

#[allow(dead_code, clippy::all)]
pub mod efi_runtime;

#[allow(dead_code, clippy::all)]
pub mod smbios;

#[allow(dead_code, clippy::all)]
pub mod pmu;

#[allow(dead_code, clippy::all)]
pub mod numa_topology;
#[allow(dead_code, clippy::all)]
pub mod tsc;

#[allow(dead_code, clippy::all)]
pub mod dma_buf;
#[allow(dead_code, clippy::all)]
pub mod tpm_hw;

#[allow(dead_code, clippy::all)]
pub mod gpio_controller;
#[allow(dead_code, clippy::all)]
pub mod thermal_zone;

#[allow(dead_code, clippy::all)]
pub mod devfreq;
#[allow(dead_code, clippy::all)]
pub mod iommu_dma;

#[allow(dead_code, clippy::all)]
pub mod clk_framework;
#[allow(dead_code, clippy::all)]
pub mod watchdog_hw;

#[allow(dead_code, clippy::all)]
pub mod dma_fence;
#[allow(dead_code, clippy::all)]
pub mod mmc_host;
#[allow(dead_code, clippy::all)]
pub mod usb_gadget;

#[allow(dead_code, clippy::all)]
pub mod acpi_ec;
#[allow(dead_code, clippy::all)]
pub mod iommu_sva;
#[allow(dead_code, clippy::all)]
pub mod pci_pm;

#[allow(dead_code, clippy::all)]
pub mod cpufreq_gov;
#[allow(dead_code, clippy::all)]
pub mod interrupt_chip;
#[allow(dead_code, clippy::all)]
pub mod nvdimm;
#[allow(dead_code, clippy::all)]
pub mod pci_bridge;
#[allow(dead_code, clippy::all)]
pub mod topology;
#[allow(dead_code, clippy::all)]
pub mod virtio_rng;

#[allow(dead_code, clippy::all)]
pub mod backlight;
#[allow(dead_code, clippy::all)]
pub mod i2c_bus;
#[allow(dead_code, clippy::all)]
pub mod power_supply;
#[allow(dead_code, clippy::all)]
pub mod rtc_hw;
#[allow(dead_code, clippy::all)]
pub mod spi_bus;

#[allow(dead_code, clippy::all)]
pub mod apic;
#[allow(dead_code, clippy::all)]
pub mod dma_coherent;
#[allow(dead_code, clippy::all)]
pub mod pci_config;

#[allow(dead_code, clippy::all)]
pub mod ioapic;

#[allow(dead_code, clippy::all)]
pub mod clocksource_hw;
#[allow(dead_code, clippy::all)]
pub mod dma_mapping;
#[allow(dead_code, clippy::all)]
pub mod firmware_acpi;
#[allow(dead_code, clippy::all)]
pub mod gpio_chip;
#[allow(dead_code, clippy::all)]
pub mod irq_domain;
#[allow(dead_code, clippy::all)]
pub mod pci_capability;
#[allow(dead_code, clippy::all)]
pub mod platform_device;

#[allow(dead_code, clippy::all)]
pub mod acpi_battery;
#[allow(dead_code, clippy::all)]
pub mod iommu_domain;
#[allow(dead_code, clippy::all)]
pub mod pcie_aer;

#[allow(dead_code, clippy::all)]
pub mod apic_timer;
#[allow(dead_code, clippy::all)]
pub mod cpu_feature;
#[allow(dead_code, clippy::all)]
pub mod early_console;
#[allow(dead_code, clippy::all)]
pub mod interrupt_remap;
#[allow(dead_code, clippy::all)]
pub mod io_port;
#[allow(dead_code, clippy::all)]
pub mod mmio;
#[allow(dead_code, clippy::all)]
pub mod mtrr;
#[allow(dead_code, clippy::all)]
pub mod pat;
#[allow(dead_code, clippy::all)]
pub mod smp_boot;
#[allow(dead_code, clippy::all)]
pub mod suspend_hw;

#[allow(dead_code, clippy::all)]
pub mod cmos;
#[allow(dead_code, clippy::all)]
pub mod cr_regs;
#[allow(dead_code, clippy::all)]
pub mod fpu_state;
#[allow(dead_code, clippy::all)]
pub mod gdt;
#[allow(dead_code, clippy::all)]
pub mod idt;
#[allow(dead_code, clippy::all)]
pub mod lapic;
#[allow(dead_code, clippy::all)]
pub mod msr;
#[allow(dead_code, clippy::all)]
pub mod pic_8259;
#[allow(dead_code, clippy::all)]
pub mod pit_8254;
#[allow(dead_code, clippy::all)]
pub mod tss;

#[allow(dead_code, clippy::all)]
pub mod acpi_power;
#[allow(dead_code, clippy::all)]
pub mod dma_remap;
#[allow(dead_code, clippy::all)]
pub mod e820;
#[allow(dead_code, clippy::all)]
pub mod numa_hw;
#[allow(dead_code, clippy::all)]
pub mod ps2_controller;
#[allow(dead_code, clippy::all)]
pub mod vga_text;

#[allow(dead_code, clippy::all)]
pub mod firmware_dt;
#[allow(dead_code, clippy::all)]
pub mod irq_chip;
#[allow(dead_code, clippy::all)]
pub mod pci_express;
#[allow(dead_code, clippy::all)]
pub mod suspend_resume;
#[allow(dead_code, clippy::all)]
pub mod thermal_hw;
#[allow(dead_code, clippy::all)]
pub mod wdt_hw;
#[allow(dead_code, clippy::all)]
pub mod x2apic;

#[allow(dead_code, clippy::all)]
pub mod cmos_rtc;
#[allow(dead_code, clippy::all)]
pub mod cpufreq_hw;
#[allow(dead_code, clippy::all)]
pub mod hpet_hw;
#[allow(dead_code, clippy::all)]
pub mod iommu_hw;
#[allow(dead_code, clippy::all)]
pub mod pic8259;
#[allow(dead_code, clippy::all)]
pub mod power_mgmt;
#[allow(dead_code, clippy::all)]
pub mod ps2_ctrl;
#[allow(dead_code, clippy::all)]
pub mod serial_hw;

#[allow(dead_code, clippy::all)]
pub mod acpi_tables;
#[allow(dead_code, clippy::all)]
pub mod lapic_timer;
#[allow(dead_code, clippy::all)]
pub mod msi_hw;
#[allow(dead_code, clippy::all)]
pub mod pci_msi;
#[allow(dead_code, clippy::all)]
pub mod pit_hw;
#[allow(dead_code, clippy::all)]
pub mod reset_hw;
#[allow(dead_code, clippy::all)]
pub mod tsc_hw;

#[allow(dead_code, clippy::all)]
pub mod apic_ipi;
#[allow(dead_code, clippy::all)]
pub mod cpuid_hw;
#[allow(dead_code, clippy::all)]
pub mod fpu_hw;
#[allow(dead_code, clippy::all)]
pub mod gdt_hw;
#[allow(dead_code, clippy::all)]
pub mod idt_hw;
#[allow(dead_code, clippy::all)]
pub mod msr_access;
#[allow(dead_code, clippy::all)]
pub mod page_table_hw;
#[allow(dead_code, clippy::all)]
pub mod pci_ecam;
#[allow(dead_code, clippy::all)]
pub mod tss_hw;

#[allow(dead_code, clippy::all)]
pub mod arm_timer;
#[allow(dead_code, clippy::all)]
pub mod gic_hw;
#[allow(dead_code, clippy::all)]
pub mod mmio_reg;
#[allow(dead_code, clippy::all)]
pub mod pio_reg;
#[allow(dead_code, clippy::all)]
pub mod riscv_clint;
#[allow(dead_code, clippy::all)]
pub mod riscv_csr;
#[allow(dead_code, clippy::all)]
pub mod riscv_plic;
#[allow(dead_code, clippy::all)]
pub mod smmu_hw;

#[allow(dead_code, clippy::all)]
pub mod adc_hw;
#[allow(dead_code, clippy::all)]
pub mod can_hw;
#[allow(dead_code, clippy::all)]
pub mod clock_gate;
#[allow(dead_code, clippy::all)]
pub mod dac_hw;
#[allow(dead_code, clippy::all)]
pub mod dma_scatter;
#[allow(dead_code, clippy::all)]
pub mod edp_hw;
#[allow(dead_code, clippy::all)]
pub mod emmc_hw;
#[allow(dead_code, clippy::all)]
pub mod fan_ctrl;
#[allow(dead_code, clippy::all)]
pub mod hdmi_hw;
#[allow(dead_code, clippy::all)]
pub mod i2s_hw;
#[allow(dead_code, clippy::all)]
pub mod mipi_dsi;
#[allow(dead_code, clippy::all)]
pub mod nand_ctrl;
#[allow(dead_code, clippy::all)]
pub mod nor_flash;
#[allow(dead_code, clippy::all)]
pub mod pcie_phy;
#[allow(dead_code, clippy::all)]
pub mod pmu_hw;
#[allow(dead_code, clippy::all)]
pub mod power_domain;
#[allow(dead_code, clippy::all)]
pub mod sdio_hw;
#[allow(dead_code, clippy::all)]
pub mod spi_master;
#[allow(dead_code, clippy::all)]
pub mod thermal_sensor;
#[allow(dead_code, clippy::all)]
pub mod usb_phy;
#[allow(dead_code, clippy::all)]
pub mod voltage_regulator;

#[allow(dead_code, clippy::all)]
pub mod acpi_cpufreq;
#[allow(dead_code, clippy::all)]
pub mod clk_provider;
#[allow(dead_code, clippy::all)]
pub mod crypto_engine;
#[allow(dead_code, clippy::all)]
pub mod efifb_hw;
#[allow(dead_code, clippy::all)]
pub mod mailbox_hw;
#[allow(dead_code, clippy::all)]
pub mod pcie_rc;
#[allow(dead_code, clippy::all)]
pub mod pmu_events;
#[allow(dead_code, clippy::all)]
pub mod regmap;
#[allow(dead_code, clippy::all)]
pub mod scmi_hw;
#[allow(dead_code, clippy::all)]
pub mod vgic_hw;

#[allow(dead_code, clippy::all)]
pub mod arm_gicv3;
#[allow(dead_code, clippy::all)]
pub mod arm_psci;
#[allow(dead_code, clippy::all)]
pub mod cpu_hotplug;
#[allow(dead_code, clippy::all)]
pub mod efuse_hw;
#[allow(dead_code, clippy::all)]
pub mod iommu_fault;
#[allow(dead_code, clippy::all)]
pub mod mem_controller;
#[allow(dead_code, clippy::all)]
pub mod pcie_dma;
#[allow(dead_code, clippy::all)]
pub mod riscv_aia;
#[allow(dead_code, clippy::all)]
pub mod secure_boot;
#[allow(dead_code, clippy::all)]
pub mod x86_lapic;

#[allow(dead_code, clippy::all)]
pub mod acpi_gpio;
#[allow(dead_code, clippy::all)]
pub mod arm_gicv2;
#[allow(dead_code, clippy::all)]
pub mod arm_mmu;
#[allow(dead_code, clippy::all)]
pub mod arm_smc;
#[allow(dead_code, clippy::all)]
pub mod cache_maint;
#[allow(dead_code, clippy::all)]
pub mod clk_divider;
#[allow(dead_code, clippy::all)]
pub mod cpu_topology;
#[allow(dead_code, clippy::all)]
pub mod dma_pool;
#[allow(dead_code, clippy::all)]
pub mod i2c_slave;
#[allow(dead_code, clippy::all)]
pub mod iommu_group;
#[allow(dead_code, clippy::all)]
pub mod irq_affinity_hw;
#[allow(dead_code, clippy::all)]
pub mod mem_bandwidth;
#[allow(dead_code, clippy::all)]
pub mod nvmem_hw;
#[allow(dead_code, clippy::all)]
pub mod otp_hw;
#[allow(dead_code, clippy::all)]
pub mod pci_arbiter;
#[allow(dead_code, clippy::all)]
pub mod pcie_endpoint;
#[allow(dead_code, clippy::all)]
pub mod pcie_msi;
#[allow(dead_code, clippy::all)]
pub mod power_sequencer;
#[allow(dead_code, clippy::all)]
pub mod pwm_core;
#[allow(dead_code, clippy::all)]
pub mod riscv_intc;
#[allow(dead_code, clippy::all)]
pub mod riscv_mmu;
#[allow(dead_code, clippy::all)]
pub mod spi_slave;
#[allow(dead_code, clippy::all)]
pub mod tlb_ops;
#[allow(dead_code, clippy::all)]
pub mod trustzone_hw;
#[allow(dead_code, clippy::all)]
pub mod uart_core;
#[allow(dead_code, clippy::all)]
pub mod usb_ehci;
#[allow(dead_code, clippy::all)]
pub mod usb_ohci;
#[allow(dead_code, clippy::all)]
pub mod wdt_core;
#[allow(dead_code, clippy::all)]
pub mod x86_ioapic;
#[allow(dead_code, clippy::all)]
pub mod x86_mmu;

#[allow(dead_code, clippy::all)]
pub mod dma_fence_chain;
#[allow(dead_code, clippy::all)]
pub mod scatterlist_ops;
#[allow(dead_code, clippy::all)]
pub mod swiotlb_pool;

#[allow(dead_code, clippy::all)]
pub mod gpio_chip_ops;
#[allow(dead_code, clippy::all)]
pub mod iommu_dma_ops;
#[allow(dead_code, clippy::all)]
pub mod pcie_aer_handler;

#[allow(dead_code, clippy::all)]
pub mod dma_buf_export;
#[allow(dead_code, clippy::all)]
pub mod i2c_core_base;
#[allow(dead_code, clippy::all)]
pub mod pcie_link_train;

#[allow(dead_code, clippy::all)]
pub mod edac_mc_core;
#[allow(dead_code, clippy::all)]
pub mod platform_device_ops;
#[allow(dead_code, clippy::all)]
pub mod regmap_mmio;

#[allow(dead_code, clippy::all)]
pub mod dma_mapping_core;
#[allow(dead_code, clippy::all)]
pub mod ioapic_driver;
#[allow(dead_code, clippy::all)]
pub mod pci_config_space;

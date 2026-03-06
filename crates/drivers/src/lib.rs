// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space device driver framework for the ONCRIX operating system.
//!
//! In the microkernel architecture, device drivers run in user space
//! for fault isolation. This crate provides the driver framework,
//! device registration, and common driver interfaces.
//!
//! # Modules
//!
//! - [`device`] — Device trait and device types
//! - [`registry`] — Driver registration and lookup

#![no_std]

pub mod ahci;
pub mod ata;
pub mod bio;
pub mod bluetooth;
pub mod device;
#[allow(dead_code, clippy::all)]
pub mod drm;
pub mod e1000;
pub mod edac;
pub mod framebuffer;
pub mod gpio;
pub mod hda;
pub mod i2c;
pub mod keyboard;
pub mod mouse;
pub mod nvdimm;
pub mod nvme;
pub mod pwm;
pub mod registry;
pub mod rtl8139;
pub mod spi;
pub mod thermal;
pub mod usb_audio;
pub mod usb_hid;
pub mod usb_storage;
pub mod vesa;
pub mod virtio;
pub mod virtio_balloon;
pub mod virtio_blk;
pub mod virtio_console;
pub mod virtio_fs;
pub mod virtio_gpu;
pub mod virtio_input;
pub mod virtio_net;
pub mod watchdog;
pub mod xhci;

#[allow(dead_code, clippy::all)]
pub mod power_supply;

#[allow(dead_code, clippy::all)]
pub mod input_core;

#[allow(dead_code, clippy::all)]
pub mod firmware_loader;
#[allow(dead_code, clippy::all)]
pub mod led_class;

#[allow(dead_code, clippy::all)]
pub mod scsi;
#[allow(dead_code, clippy::all)]
pub mod virtio_crypto;

#[allow(dead_code, clippy::all)]
pub mod i2s_audio;
#[allow(dead_code, clippy::all)]
pub mod mdio_phy;

#[allow(dead_code, clippy::all)]
pub mod ahci_pm;
#[allow(dead_code, clippy::all)]
pub mod can_bus;
#[allow(dead_code, clippy::all)]
pub mod usb_mass_storage;

#[allow(dead_code, clippy::all)]
pub mod drm_kms;
#[allow(dead_code, clippy::all)]
pub mod mmc_sd;
#[allow(dead_code, clippy::all)]
pub mod usb_typec;

#[allow(dead_code, clippy::all)]
pub mod usb_cdc_acm;
#[allow(dead_code, clippy::all)]
pub mod virtio_scsi;

#[allow(dead_code, clippy::all)]
pub mod usb_net;
#[allow(dead_code, clippy::all)]
pub mod virtio_mem;

#[allow(dead_code, clippy::all)]
pub mod fpga_manager;
#[allow(dead_code, clippy::all)]
pub mod mei;
#[allow(dead_code, clippy::all)]
pub mod nvme_tcp;
#[allow(dead_code, clippy::all)]
pub mod thunderbolt;

#[allow(dead_code, clippy::all)]
pub mod drm_gem;
#[allow(dead_code, clippy::all)]
pub mod nvme_pci;
#[allow(dead_code, clippy::all)]
pub mod tty_core;
#[allow(dead_code, clippy::all)]
pub mod v4l2;

#[allow(dead_code, clippy::all)]
pub mod drm_fb_helper;
#[allow(dead_code, clippy::all)]
pub mod nvme_multipath;
#[allow(dead_code, clippy::all)]
pub mod usb_dwc3;
#[allow(dead_code, clippy::all)]
pub mod virtio_pmem;

#[allow(dead_code, clippy::all)]
pub mod i2c_controller;
#[allow(dead_code, clippy::all)]
pub mod pwm_controller;
#[allow(dead_code, clippy::all)]
pub mod regulator_core;
#[allow(dead_code, clippy::all)]
pub mod spi_controller;

#[allow(dead_code, clippy::all)]
pub mod drm_atomic;
#[allow(dead_code, clippy::all)]
pub mod input_evdev;
#[allow(dead_code, clippy::all)]
pub mod nvme_fabrics;

#[allow(dead_code, clippy::all)]
pub mod drm_dp;
#[allow(dead_code, clippy::all)]
pub mod hwmon;
#[allow(dead_code, clippy::all)]
pub mod usb_class;

#[allow(dead_code, clippy::all)]
pub mod block_loop;
#[allow(dead_code, clippy::all)]
pub mod drm_prime;
#[allow(dead_code, clippy::all)]
pub mod input_tablet;
#[allow(dead_code, clippy::all)]
pub mod nvme_passthrough;
#[allow(dead_code, clippy::all)]
pub mod scsi_sd;
#[allow(dead_code, clippy::all)]
pub mod usb_serial;

#[allow(dead_code, clippy::all)]
pub mod ps2_kbd;
#[allow(dead_code, clippy::all)]
pub mod serial_16550;

#[allow(dead_code, clippy::all)]
pub mod ac97_codec;
#[allow(dead_code, clippy::all)]
pub mod ata_piix;
#[allow(dead_code, clippy::all)]
pub mod cdrom_sr;
#[allow(dead_code, clippy::all)]
pub mod drm_crtc;
#[allow(dead_code, clippy::all)]
pub mod hid_input;
#[allow(dead_code, clippy::all)]
pub mod i2c_smbus;
#[allow(dead_code, clippy::all)]
pub mod i8042_ps2;
#[allow(dead_code, clippy::all)]
pub mod pci_msi;
#[allow(dead_code, clippy::all)]
pub mod pstore_ram;
#[allow(dead_code, clippy::all)]
pub mod rtc_cmos;
#[allow(dead_code, clippy::all)]
pub mod usb_hub;
#[allow(dead_code, clippy::all)]
pub mod usb_xhci;
#[allow(dead_code, clippy::all)]
pub mod virtio_serial;
#[allow(dead_code, clippy::all)]
pub mod virtio_vsock;

#[allow(dead_code, clippy::all)]
pub mod alsa_pcm;
#[allow(dead_code, clippy::all)]
pub mod drm_connector;
#[allow(dead_code, clippy::all)]
pub mod nvme_admin;

#[allow(dead_code, clippy::all)]
pub mod block_request;
#[allow(dead_code, clippy::all)]
pub mod drm_plane;
#[allow(dead_code, clippy::all)]
pub mod i2c_algo_bit;
#[allow(dead_code, clippy::all)]
pub mod input_ff;
#[allow(dead_code, clippy::all)]
pub mod net_phy;
#[allow(dead_code, clippy::all)]
pub mod pci_quirk;
#[allow(dead_code, clippy::all)]
pub mod scsi_host;
#[allow(dead_code, clippy::all)]
pub mod spi_flash;
#[allow(dead_code, clippy::all)]
pub mod tty_ldisc;
#[allow(dead_code, clippy::all)]
pub mod virtio_socket;

#[allow(dead_code, clippy::all)]
pub mod ahci_port;
#[allow(dead_code, clippy::all)]
pub mod block_partition;
#[allow(dead_code, clippy::all)]
pub mod drm_framebuffer;
#[allow(dead_code, clippy::all)]
pub mod e1000e;
#[allow(dead_code, clippy::all)]
pub mod input_touchscreen;
#[allow(dead_code, clippy::all)]
pub mod net_loopback;
#[allow(dead_code, clippy::all)]
pub mod nvme_io;
#[allow(dead_code, clippy::all)]
pub mod tty_uart;
#[allow(dead_code, clippy::all)]
pub mod usb_ehci;
#[allow(dead_code, clippy::all)]
pub mod virtio_pci;

#[allow(dead_code, clippy::all)]
pub mod framebuffer_fb;
#[allow(dead_code, clippy::all)]
pub mod i2c_bitbang;
#[allow(dead_code, clippy::all)]
pub mod pci_msi_driver;
#[allow(dead_code, clippy::all)]
pub mod sata_ahci;
#[allow(dead_code, clippy::all)]
pub mod spi_master;
#[allow(dead_code, clippy::all)]
pub mod virtio_mmio;

#[allow(dead_code, clippy::all)]
pub mod nvme_queue;
#[allow(dead_code, clippy::all)]
pub mod rtl8169;
#[allow(dead_code, clippy::all)]
pub mod usb_xhci_ring;

#[allow(dead_code, clippy::all)]
pub mod fb_generic;
#[allow(dead_code, clippy::all)]
pub mod i2c_master;
#[allow(dead_code, clippy::all)]
pub mod null_blk;

#[allow(dead_code, clippy::all)]
pub mod dm_linear;
#[allow(dead_code, clippy::all)]
pub mod loop_dev;
#[allow(dead_code, clippy::all)]
pub mod ramdisk;
#[allow(dead_code, clippy::all)]
pub mod serial_console;

#[allow(dead_code, clippy::all)]
pub mod ahci_fis;
#[allow(dead_code, clippy::all)]
pub mod ehci_async;
#[allow(dead_code, clippy::all)]
pub mod input_event;
#[allow(dead_code, clippy::all)]
pub mod pci_driver;
#[allow(dead_code, clippy::all)]
pub mod platform_bus;
#[allow(dead_code, clippy::all)]
pub mod xhci_ring;

#[allow(dead_code, clippy::all)]
pub mod dm_crypt;
#[allow(dead_code, clippy::all)]
pub mod e1000_hw;
#[allow(dead_code, clippy::all)]
pub mod hda_codec;
#[allow(dead_code, clippy::all)]
pub mod md_raid;
#[allow(dead_code, clippy::all)]
pub mod ne2k;
#[allow(dead_code, clippy::all)]
pub mod scsi_disk;
#[allow(dead_code, clippy::all)]
pub mod scsi_generic;
#[allow(dead_code, clippy::all)]
pub mod usb_hub_driver;

#[allow(dead_code, clippy::all)]
pub mod ahci_em;
#[allow(dead_code, clippy::all)]
pub mod ata_ahci;
#[allow(dead_code, clippy::all)]
pub mod drm_vblank;
#[allow(dead_code, clippy::all)]
pub mod mmc_block;
#[allow(dead_code, clippy::all)]
pub mod ns16550a;
#[allow(dead_code, clippy::all)]
pub mod nvme_zns;
#[allow(dead_code, clippy::all)]
pub mod pcie_endpoint;
#[allow(dead_code, clippy::all)]
pub mod pl011_uart;
#[allow(dead_code, clippy::all)]
pub mod usb_net_cdc;
#[allow(dead_code, clippy::all)]
pub mod virtio_iommu;

#[allow(dead_code, clippy::all)]
pub mod ahci_atapi;
#[allow(dead_code, clippy::all)]
pub mod pci_hotplug_drv;
#[allow(dead_code, clippy::all)]
pub mod pcie_bridge_drv;
#[allow(dead_code, clippy::all)]
pub mod qemu_fw_cfg;
#[allow(dead_code, clippy::all)]
pub mod sata_fis;
#[allow(dead_code, clippy::all)]
pub mod sb16_audio;
#[allow(dead_code, clippy::all)]
pub mod scsi_tape;
#[allow(dead_code, clippy::all)]
pub mod tpm_drv;
#[allow(dead_code, clippy::all)]
pub mod usb_midi;
#[allow(dead_code, clippy::all)]
pub mod virtio_rng_drv;

#[allow(dead_code, clippy::all)]
pub mod ac97_audio;
#[allow(dead_code, clippy::all)]
pub mod acpi_battery;
#[allow(dead_code, clippy::all)]
pub mod acpi_button;
#[allow(dead_code, clippy::all)]
pub mod amdgpu_core;
#[allow(dead_code, clippy::all)]
pub mod bochs_vbe;
#[allow(dead_code, clippy::all)]
pub mod btusb;
#[allow(dead_code, clippy::all)]
pub mod can_socket;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq;
#[allow(dead_code, clippy::all)]
pub mod cpuidle_core;
#[allow(dead_code, clippy::all)]
pub mod dax_driver;
#[allow(dead_code, clippy::all)]
pub mod dma_engine;
#[allow(dead_code, clippy::all)]
pub mod e100;
#[allow(dead_code, clippy::all)]
pub mod ehci_hcd;
#[allow(dead_code, clippy::all)]
pub mod gpio_expander;
#[allow(dead_code, clippy::all)]
pub mod i915_gfx;
#[allow(dead_code, clippy::all)]
pub mod igb;
#[allow(dead_code, clippy::all)]
pub mod iommu_intel;
#[allow(dead_code, clippy::all)]
pub mod ixgbe;
#[allow(dead_code, clippy::all)]
pub mod nvmem_core;
#[allow(dead_code, clippy::all)]
pub mod nvram_driver;
#[allow(dead_code, clippy::all)]
pub mod pci_bridge;
#[allow(dead_code, clippy::all)]
pub mod pcspkr;
#[allow(dead_code, clippy::all)]
pub mod phy_generic;
#[allow(dead_code, clippy::all)]
pub mod ps2_mouse;
#[allow(dead_code, clippy::all)]
pub mod sdhci;
#[allow(dead_code, clippy::all)]
pub mod serial_8250;
#[allow(dead_code, clippy::all)]
pub mod uhci_hcd;
#[allow(dead_code, clippy::all)]
pub mod vga_text;
#[allow(dead_code, clippy::all)]
pub mod vhost_blk;
#[allow(dead_code, clippy::all)]
pub mod vhost_net;
#[allow(dead_code, clippy::all)]
pub mod virtio_rng;
#[allow(dead_code, clippy::all)]
pub mod wlan_core;

#[allow(dead_code, clippy::all)]
pub mod pci_msi_irq;
#[allow(dead_code, clippy::all)]
pub mod usb_hub_event;
#[allow(dead_code, clippy::all)]
pub mod watchdog_dev;

#[allow(dead_code, clippy::all)]
pub mod nvme_ns_head;
#[allow(dead_code, clippy::all)]
pub mod sata_pmp;
#[allow(dead_code, clippy::all)]
pub mod spi_bitbang;

#[allow(dead_code, clippy::all)]
pub mod afs_fscache;
#[allow(dead_code, clippy::all)]
pub mod nvme_admin_cmd;
#[allow(dead_code, clippy::all)]
pub mod virtio_gpu_cmd;

#[allow(dead_code, clippy::all)]
pub mod cgroup_attach;
#[allow(dead_code, clippy::all)]
pub mod hwmon_chip_ops;
#[allow(dead_code, clippy::all)]
pub mod tpm_chip;

#[allow(dead_code, clippy::all)]
pub mod nvme_cq;
#[allow(dead_code, clippy::all)]
pub mod usb_descriptor;
#[allow(dead_code, clippy::all)]
pub mod virtio_blk_req;

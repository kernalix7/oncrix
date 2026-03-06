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

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod power_supply;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod input_core;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod firmware_loader;
#[allow(dead_code, clippy::all)]
pub mod led_class;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod scsi;
#[allow(dead_code, clippy::all)]
pub mod virtio_crypto;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod i2s_audio;
#[allow(dead_code, clippy::all)]
pub mod mdio_phy;

// --- Batch 10 ---
#[allow(dead_code, clippy::all)]
pub mod ahci_pm;
#[allow(dead_code, clippy::all)]
pub mod can_bus;
#[allow(dead_code, clippy::all)]
pub mod usb_mass_storage;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod drm_kms;
#[allow(dead_code, clippy::all)]
pub mod mmc_sd;
#[allow(dead_code, clippy::all)]
pub mod usb_typec;

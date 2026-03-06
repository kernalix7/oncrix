// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCIe advanced features: SR-IOV (Single Root I/O Virtualisation) and
//! AER (Advanced Error Reporting).
//!
//! SR-IOV allows a single physical function (PF) to present multiple
//! virtual functions (VFs) to the hypervisor, each assignable to a
//! separate VM. AER provides a standardised mechanism for detecting,
//! logging, and reporting PCIe errors.
//!
//! This module also tracks additional PCIe extended capabilities
//! (ACS, ATS, PASID, LTR, DPC) via the [`PcieCapability`] enum.
//!
//! Reference: PCI Express Base Specification 5.0, Chapter 9 (SR-IOV)
//! and Chapter 6.2 (AER).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum virtual functions tracked per physical function.
const MAX_VFS: usize = 32;

/// Maximum AER error log entries.
const MAX_AER_ERRORS: usize = 32;

/// Maximum PCIe devices in the advanced registry.
const MAX_PCIE_DEVICES: usize = 16;

// ── PCIe Capability Enum ─────────────────────────────────────────

/// PCIe extended capability identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PcieCapability {
    /// Single Root I/O Virtualisation.
    #[default]
    Sriov,
    /// Advanced Error Reporting.
    Aer,
    /// Access Control Services.
    Acs,
    /// Address Translation Services.
    Ats,
    /// Process Address Space ID.
    Pasid,
    /// Latency Tolerance Reporting.
    Ltr,
    /// Downstream Port Containment.
    Dpc,
}

// ── SR-IOV ───────────────────────────────────────────────────────

/// A single SR-IOV virtual function descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct SriovVf {
    /// Virtual function ID within this physical function.
    pub vf_id: u16,
    /// PCI bus number assigned to this VF.
    pub bus: u8,
    /// PCI device number assigned to this VF.
    pub device: u8,
    /// PCI function number assigned to this VF.
    pub function: u8,
    /// Whether this VF is currently enabled.
    pub enabled: bool,
    /// Owner identifier (e.g. VM or process handle); 0 = unassigned.
    pub assigned_to: u64,
}

/// SR-IOV capability state for a physical function.
#[derive(Debug, Clone, Copy)]
pub struct SriovCapability {
    /// Maximum number of VFs the hardware supports.
    pub total_vfs: u16,
    /// Number of VFs currently enabled.
    pub num_vfs: u16,
    /// First VF offset (relative to the PF's routing ID).
    pub vf_offset: u16,
    /// Routing ID stride between consecutive VFs.
    pub vf_stride: u16,
    /// VF descriptors.
    pub vfs: [SriovVf; MAX_VFS],
    /// Whether SR-IOV is globally enabled on this PF.
    pub enabled: bool,
}

impl Default for SriovCapability {
    fn default() -> Self {
        Self {
            total_vfs: 0,
            num_vfs: 0,
            vf_offset: 0,
            vf_stride: 0,
            vfs: [SriovVf::default(); MAX_VFS],
            enabled: false,
        }
    }
}

impl SriovCapability {
    /// Enable `count` virtual functions on this physical function.
    ///
    /// Each VF is initialised with a bus/device/function address
    /// derived from [`Self::vf_offset`] and [`Self::vf_stride`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `count` is zero or exceeds
    ///   [`Self::total_vfs`] or `MAX_VFS`.
    /// - [`Error::Busy`] if SR-IOV is already enabled.
    pub fn enable_vfs(&mut self, count: u16) -> Result<()> {
        if self.enabled {
            return Err(Error::Busy);
        }
        if count == 0 || count > self.total_vfs || count as usize > MAX_VFS {
            return Err(Error::InvalidArgument);
        }

        let offset = self.vf_offset;
        let stride = self.vf_stride;

        for i in 0..count {
            let routing_id = offset.wrapping_add(i.wrapping_mul(stride));
            let idx = i as usize;
            self.vfs[idx] = SriovVf {
                vf_id: i,
                bus: (routing_id >> 8) as u8,
                device: ((routing_id >> 3) & 0x1F) as u8,
                function: (routing_id & 0x07) as u8,
                enabled: true,
                assigned_to: 0,
            };
        }

        self.num_vfs = count;
        self.enabled = true;
        Ok(())
    }

    /// Disable all virtual functions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if SR-IOV is not enabled.
    pub fn disable_vfs(&mut self) -> Result<()> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }

        for vf in &mut self.vfs {
            vf.enabled = false;
            vf.assigned_to = 0;
        }

        self.num_vfs = 0;
        self.enabled = false;
        Ok(())
    }

    /// Get a reference to a virtual function by its VF ID.
    pub fn get_vf(&self, id: u16) -> Option<&SriovVf> {
        self.vfs
            .iter()
            .take(self.num_vfs as usize)
            .find(|vf| vf.vf_id == id && vf.enabled)
    }

    /// Assign a virtual function to an owner.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `id` does not match an enabled VF.
    /// - [`Error::Busy`] if the VF is already assigned.
    pub fn assign_vf(&mut self, id: u16, owner: u64) -> Result<()> {
        let vf = self
            .vfs
            .iter_mut()
            .take(self.num_vfs as usize)
            .find(|vf| vf.vf_id == id && vf.enabled)
            .ok_or(Error::NotFound)?;

        if vf.assigned_to != 0 {
            return Err(Error::Busy);
        }

        vf.assigned_to = owner;
        Ok(())
    }
}

// ── AER ──────────────────────────────────────────────────────────

/// AER error severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AerSeverity {
    /// Correctable error — hardware recovered automatically.
    #[default]
    Correctable,
    /// Non-fatal uncorrectable error — link still usable.
    NonFatalUncorrectable,
    /// Fatal uncorrectable error — link is unreliable.
    FatalUncorrectable,
}

/// A single AER error record.
#[derive(Debug, Clone, Copy, Default)]
pub struct AerError {
    /// Error severity.
    pub severity: AerSeverity,
    /// Error status register value.
    pub status: u32,
    /// Error mask register value at the time of capture.
    pub mask: u32,
    /// Source ID (requester BDF) of the error.
    pub source_id: u16,
    /// Timestamp (platform ticks) when the error was captured.
    pub timestamp: u64,
}

/// AER capability state for a PCIe device.
#[derive(Debug, Clone, Copy)]
pub struct AerCapability {
    /// Correctable error mask register.
    pub correctable_mask: u32,
    /// Uncorrectable error mask register.
    pub uncorrectable_mask: u32,
    /// Uncorrectable error severity register (1 = fatal, 0 = non-fatal).
    pub uncorrectable_severity: u32,
    /// Circular error log.
    pub errors: [AerError; MAX_AER_ERRORS],
    /// Number of errors currently stored.
    pub error_count: usize,
    /// Whether AER is enabled.
    pub enabled: bool,
}

impl Default for AerCapability {
    fn default() -> Self {
        Self {
            correctable_mask: 0,
            uncorrectable_mask: 0,
            uncorrectable_severity: 0,
            errors: [AerError::default(); MAX_AER_ERRORS],
            error_count: 0,
            enabled: false,
        }
    }
}

impl AerCapability {
    /// Report an error to the AER log.
    ///
    /// Errors are stored in a circular buffer; when full the oldest
    /// entry is overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if AER is not enabled.
    pub fn report_error(&mut self, error: AerError) -> Result<()> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }

        let idx = self.error_count % MAX_AER_ERRORS;
        self.errors[idx] = error;
        self.error_count = self.error_count.saturating_add(1);
        Ok(())
    }

    /// Mask a specific error bit for the given severity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bit >= 32`.
    pub fn mask_error(&mut self, bit: u8, severity: AerSeverity) -> Result<()> {
        if bit >= 32 {
            return Err(Error::InvalidArgument);
        }
        let mask_bit = 1u32 << bit;
        match severity {
            AerSeverity::Correctable => self.correctable_mask |= mask_bit,
            AerSeverity::NonFatalUncorrectable | AerSeverity::FatalUncorrectable => {
                self.uncorrectable_mask |= mask_bit;
            }
        }
        Ok(())
    }

    /// Unmask a specific error bit for the given severity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `bit >= 32`.
    pub fn unmask_error(&mut self, bit: u8, severity: AerSeverity) -> Result<()> {
        if bit >= 32 {
            return Err(Error::InvalidArgument);
        }
        let mask_bit = 1u32 << bit;
        match severity {
            AerSeverity::Correctable => self.correctable_mask &= !mask_bit,
            AerSeverity::NonFatalUncorrectable | AerSeverity::FatalUncorrectable => {
                self.uncorrectable_mask &= !mask_bit;
            }
        }
        Ok(())
    }

    /// Return a slice of all recorded errors.
    ///
    /// If the log has wrapped, only the last `MAX_AER_ERRORS` entries
    /// are accessible via this slice.
    pub fn get_errors(&self) -> &[AerError] {
        let len = self.error_count.min(MAX_AER_ERRORS);
        &self.errors[..len]
    }

    /// Clear all error records and return the number cleared.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if AER is not enabled.
    pub fn clear_errors(&mut self) -> Result<u32> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }
        let cleared = self.error_count.min(MAX_AER_ERRORS) as u32;
        self.errors = [AerError::default(); MAX_AER_ERRORS];
        self.error_count = 0;
        Ok(cleared)
    }
}

// ── PCIe Device ──────────────────────────────────────────────────

/// A PCIe device with advanced capability tracking.
#[derive(Debug, Clone, Copy)]
pub struct PcieDevice {
    /// Bus/device/function encoded as a single u32.
    pub bdf: u32,
    /// Whether SR-IOV capability is present.
    pub has_sriov: bool,
    /// SR-IOV capability state.
    pub sriov: SriovCapability,
    /// Whether AER capability is present.
    pub has_aer: bool,
    /// AER capability state.
    pub aer: AerCapability,
    /// Negotiated link speed (PCIe gen, e.g. 1–5).
    pub link_speed: u8,
    /// Negotiated link width (x1, x2, x4, x8, x16).
    pub link_width: u8,
    /// Max payload size in bytes.
    pub max_payload: u16,
    /// Whether the device is currently in use by a driver.
    pub in_use: bool,
}

impl Default for PcieDevice {
    fn default() -> Self {
        Self {
            bdf: 0,
            has_sriov: false,
            sriov: SriovCapability::default(),
            has_aer: false,
            aer: AerCapability::default(),
            link_speed: 0,
            link_width: 0,
            max_payload: 128,
            in_use: false,
        }
    }
}

impl PcieDevice {
    /// Initialise the SR-IOV capability on this device.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if SR-IOV was already initialised.
    /// - [`Error::InvalidArgument`] if `total_vfs` is zero or exceeds
    ///   `MAX_VFS`.
    pub fn init_sriov(&mut self, total_vfs: u16) -> Result<()> {
        if self.has_sriov {
            return Err(Error::AlreadyExists);
        }
        if total_vfs == 0 || total_vfs as usize > MAX_VFS {
            return Err(Error::InvalidArgument);
        }

        self.sriov = SriovCapability {
            total_vfs,
            vf_offset: 1,
            vf_stride: 1,
            ..SriovCapability::default()
        };
        self.has_sriov = true;
        Ok(())
    }

    /// Initialise the AER capability on this device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if AER was already initialised.
    pub fn init_aer(&mut self) -> Result<()> {
        if self.has_aer {
            return Err(Error::AlreadyExists);
        }

        self.aer = AerCapability {
            enabled: true,
            ..AerCapability::default()
        };
        self.has_aer = true;
        Ok(())
    }

    /// Return the negotiated link speed and width.
    pub fn get_link_info(&self) -> (u8, u8) {
        (self.link_speed, self.link_width)
    }

    /// Set the maximum payload size.
    ///
    /// Valid sizes are powers of two from 128 to 4096 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is not a valid
    /// max payload value.
    pub fn set_max_payload(&mut self, size: u16) -> Result<()> {
        if !size.is_power_of_two() || !(128..=4096).contains(&size) {
            return Err(Error::InvalidArgument);
        }
        self.max_payload = size;
        Ok(())
    }
}

// ── PCIe Advanced Registry ───────────────────────────────────────

/// Fixed-capacity registry of PCIe devices with advanced capabilities.
pub struct PcieAdvancedRegistry {
    /// Backing storage.
    devices: [PcieDevice; MAX_PCIE_DEVICES],
    /// Number of devices currently registered.
    count: usize,
}

impl Default for PcieAdvancedRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PcieAdvancedRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        // const-compatible: PcieDevice contains only Copy types.
        const EMPTY: PcieDevice = PcieDevice {
            bdf: 0,
            has_sriov: false,
            sriov: SriovCapability {
                total_vfs: 0,
                num_vfs: 0,
                vf_offset: 0,
                vf_stride: 0,
                vfs: [SriovVf {
                    vf_id: 0,
                    bus: 0,
                    device: 0,
                    function: 0,
                    enabled: false,
                    assigned_to: 0,
                }; MAX_VFS],
                enabled: false,
            },
            has_aer: false,
            aer: AerCapability {
                correctable_mask: 0,
                uncorrectable_mask: 0,
                uncorrectable_severity: 0,
                errors: [AerError {
                    severity: AerSeverity::Correctable,
                    status: 0,
                    mask: 0,
                    source_id: 0,
                    timestamp: 0,
                }; MAX_AER_ERRORS],
                error_count: 0,
                enabled: false,
            },
            link_speed: 0,
            link_width: 0,
            max_payload: 128,
            in_use: false,
        };

        Self {
            devices: [EMPTY; MAX_PCIE_DEVICES],
            count: 0,
        }
    }

    /// Register a new PCIe device by its BDF.
    ///
    /// Returns the index at which the device was stored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, bdf: u32) -> Result<u16> {
        if self.count >= MAX_PCIE_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = PcieDevice {
            bdf,
            ..PcieDevice::default()
        };
        self.count += 1;
        Ok(idx as u16)
    }

    /// Remove a device from the registry by index.
    ///
    /// The slot is cleared; it is **not** reused by future
    /// [`Self::register`] calls (append-only).
    pub fn unregister(&mut self, idx: usize) {
        if idx < self.count {
            self.devices[idx] = PcieDevice::default();
        }
    }

    /// Get a reference to a registered device.
    pub fn get(&self, idx: usize) -> Option<&PcieDevice> {
        if idx < self.count {
            Some(&self.devices[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to a registered device.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut PcieDevice> {
        if idx < self.count {
            Some(&mut self.devices[idx])
        } else {
            None
        }
    }

    /// Walk all registered devices and collect AER errors.
    ///
    /// Returns the total number of new errors found across all
    /// devices.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no devices have AER enabled.
    pub fn handle_aer_interrupt(&self) -> Result<u32> {
        let total: u32 = self
            .devices
            .iter()
            .take(self.count)
            .filter(|d| d.has_aer && d.aer.enabled)
            .map(|d| d.aer.error_count.min(MAX_AER_ERRORS) as u32)
            .sum();

        if total == 0 {
            // No AER-capable devices or no errors recorded.
            let has_aer = self
                .devices
                .iter()
                .take(self.count)
                .any(|d| d.has_aer && d.aer.enabled);
            if !has_aer {
                return Err(Error::NotFound);
            }
        }

        Ok(total)
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

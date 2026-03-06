// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO IOMMU driver.
//!
//! Implements the virtio-iommu device (virtio specification, device ID 23).
//! The virtio-iommu virtualizes an IOMMU to allow a guest VM to program DMA
//! mappings through a paravirtualized interface rather than emulating a real
//! IOMMU device (like Intel VT-d or AMD-Vi).
//!
//! Reference: virtio specification 1.2, section 5.12 (IOMMU Device).

use oncrix_lib::{Error, Result};

/// Maximum number of domains managed by this driver.
pub const VIOMMU_MAX_DOMAINS: usize = 64;
/// Maximum number of endpoint attachments.
pub const VIOMMU_MAX_ENDPOINTS: usize = 256;

/// VirtIO IOMMU feature bits (VIRTIO_IOMMU_F_*).
pub mod features {
    /// Supports page-table input address size configuration.
    pub const INPUT_RANGE: u64 = 1 << 0;
    /// Supports domain range configuration.
    pub const DOMAIN_RANGE: u64 = 1 << 1;
    /// Supports probe request.
    pub const MAP_UNMAP: u64 = 1 << 2;
    /// Supports bypass domains.
    pub const BYPASS: u64 = 1 << 3;
    /// Supports probe requests.
    pub const PROBE: u64 = 1 << 4;
    /// MSI remap support.
    pub const MMIO: u64 = 1 << 5;
    /// DIRTY page tracking.
    pub const DIRTY_TRACKING: u64 = 1 << 6;
}

/// VirtIO IOMMU request types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VirtioIommuReqType {
    /// Attach endpoint to domain.
    AttachEndpoint = 0x01,
    /// Detach endpoint from domain.
    DetachEndpoint = 0x02,
    /// Map a virtual-to-physical address range.
    Map = 0x03,
    /// Unmap a virtual address range.
    Unmap = 0x04,
    /// Probe a topology path.
    Probe = 0x05,
    /// Attach endpoint with flags.
    AttachEndpointV2 = 0x06,
}

/// VirtIO IOMMU response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VirtioIommuStatus {
    /// Request completed successfully.
    Ok = 0,
    /// I/O error.
    IoError = 1,
    /// Unsupported operation.
    Unsupported = 2,
    /// Invalid parameters.
    Invalid = 3,
    /// Domain already exists.
    DomainAlreadyExists = 4,
    /// Domain ID not found.
    NoDomain = 5,
    /// No memory.
    NoMemory = 6,
    /// Endpoint already exists.
    EndpointAlreadyExists = 7,
}

/// Map request flags.
pub mod map_flags {
    /// Map as readable.
    pub const READ: u32 = 1 << 0;
    /// Map as writable.
    pub const WRITE: u32 = 1 << 1;
    /// Map with execute permission.
    pub const EXEC: u32 = 1 << 2;
    /// Map as MMIO (no cacheable speculative access).
    pub const MMIO: u32 = 1 << 3;
}

/// VirtIO IOMMU attach-endpoint request.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AttachRequest {
    /// Request type (must be AttachEndpoint).
    pub req_type: u8,
    pub _reserved: [u8; 3],
    /// Domain ID to attach to.
    pub domain: u32,
    /// Endpoint ID (e.g., PCI BDF encoded as bus<<16|dev<<11|func<<8).
    pub endpoint: u32,
    pub _reserved2: [u8; 4],
}

/// VirtIO IOMMU map request.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MapRequest {
    /// Request type (must be Map).
    pub req_type: u8,
    pub _reserved: [u8; 3],
    /// Flags (map_flags).
    pub flags: u32,
    /// Domain ID.
    pub domain: u32,
    pub _reserved2: [u8; 4],
    /// IOVA (input address) start.
    pub virt_start: u64,
    /// IOVA end (inclusive).
    pub virt_end: u64,
    /// Physical address start.
    pub phys_start: u64,
}

/// VirtIO IOMMU unmap request.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UnmapRequest {
    /// Request type (must be Unmap).
    pub req_type: u8,
    pub _reserved: [u8; 3],
    /// Domain ID.
    pub domain: u32,
    pub _reserved2: [u8; 4],
    /// IOVA start.
    pub virt_start: u64,
    /// IOVA end (inclusive).
    pub virt_end: u64,
}

/// A tracked IOMMU mapping.
#[derive(Debug, Clone, Copy, Default)]
pub struct IommuMapping {
    /// IOVA start.
    pub iova: u64,
    /// Physical address.
    pub paddr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Flags.
    pub flags: u32,
    /// Whether this slot is occupied.
    pub valid: bool,
}

/// Per-domain state.
#[derive(Debug, Clone, Copy, Default)]
pub struct IommuDomain {
    /// Domain ID.
    pub id: u32,
    /// Whether this domain is allocated.
    pub allocated: bool,
    /// Whether this is a bypass domain (no translations).
    pub bypass: bool,
    /// Endpoint attached to this domain (u32::MAX = none).
    pub endpoint: u32,
}

/// VirtIO IOMMU driver.
pub struct VirtioIommu {
    /// Negotiated feature bits.
    pub features: u64,
    /// Number of allocated domains.
    pub num_domains: usize,
    /// Domain table.
    pub domains: [IommuDomain; VIOMMU_MAX_DOMAINS],
    /// Next request ID.
    next_req_id: u32,
}

impl VirtioIommu {
    /// Creates a new virtio-iommu driver with negotiated `features`.
    pub const fn new(features: u64) -> Self {
        Self {
            features,
            num_domains: 0,
            domains: [const {
                IommuDomain {
                    id: 0,
                    allocated: false,
                    bypass: false,
                    endpoint: u32::MAX,
                }
            }; VIOMMU_MAX_DOMAINS],
            next_req_id: 0,
        }
    }

    /// Allocates a new domain, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain table is full.
    pub fn alloc_domain(&mut self, bypass: bool) -> Result<u32> {
        if self.num_domains >= VIOMMU_MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .domains
            .iter()
            .position(|d| !d.allocated)
            .ok_or(Error::OutOfMemory)?;
        let id = idx as u32;
        self.domains[idx] = IommuDomain {
            id,
            allocated: true,
            bypass,
            endpoint: u32::MAX,
        };
        self.num_domains += 1;
        Ok(id)
    }

    /// Frees a domain by ID.
    pub fn free_domain(&mut self, domain_id: u32) -> Result<()> {
        let dom = self.find_domain_mut(domain_id)?;
        *dom = IommuDomain::default();
        if self.num_domains > 0 {
            self.num_domains -= 1;
        }
        Ok(())
    }

    /// Attaches `endpoint` to `domain_id`.
    pub fn attach_endpoint(&mut self, domain_id: u32, endpoint: u32) -> Result<AttachRequest> {
        self.find_domain_mut(domain_id)?.endpoint = endpoint;
        Ok(AttachRequest {
            req_type: VirtioIommuReqType::AttachEndpoint as u8,
            _reserved: [0u8; 3],
            domain: domain_id,
            endpoint,
            _reserved2: [0u8; 4],
        })
    }

    /// Builds a Map request.
    pub fn build_map(
        &mut self,
        domain_id: u32,
        iova: u64,
        paddr: u64,
        size: u64,
        flags: u32,
    ) -> Result<MapRequest> {
        self.find_domain(domain_id)?;
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(MapRequest {
            req_type: VirtioIommuReqType::Map as u8,
            _reserved: [0u8; 3],
            flags,
            domain: domain_id,
            _reserved2: [0u8; 4],
            virt_start: iova,
            virt_end: iova + size - 1,
            phys_start: paddr,
        })
    }

    /// Builds an Unmap request.
    pub fn build_unmap(&mut self, domain_id: u32, iova: u64, size: u64) -> Result<UnmapRequest> {
        self.find_domain(domain_id)?;
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(UnmapRequest {
            req_type: VirtioIommuReqType::Unmap as u8,
            _reserved: [0u8; 3],
            domain: domain_id,
            _reserved2: [0u8; 4],
            virt_start: iova,
            virt_end: iova + size - 1,
        })
    }

    /// Returns true if the given feature is negotiated.
    pub fn has_feature(&self, feature: u64) -> bool {
        (self.features & feature) != 0
    }

    /// Returns a fresh request sequence number.
    pub fn next_seq(&mut self) -> u32 {
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        id
    }

    // ---- private helpers ----

    fn find_domain(&self, id: u32) -> Result<&IommuDomain> {
        self.domains
            .iter()
            .find(|d| d.allocated && d.id == id)
            .ok_or(Error::NotFound)
    }

    fn find_domain_mut(&mut self, id: u32) -> Result<&mut IommuDomain> {
        self.domains
            .iter_mut()
            .find(|d| d.allocated && d.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for VirtioIommu {
    fn default() -> Self {
        Self::new(features::MAP_UNMAP)
    }
}

/// Converts a VirtIO IOMMU status code to an ONCRIX error.
pub fn status_to_result(status: VirtioIommuStatus) -> Result<()> {
    match status {
        VirtioIommuStatus::Ok => Ok(()),
        VirtioIommuStatus::NoMemory => Err(Error::OutOfMemory),
        VirtioIommuStatus::Invalid => Err(Error::InvalidArgument),
        VirtioIommuStatus::Unsupported => Err(Error::NotImplemented),
        VirtioIommuStatus::NoDomain => Err(Error::NotFound),
        _ => Err(Error::IoError),
    }
}

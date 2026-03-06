// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware memory encryption support.
//!
//! Implements management for hardware-based memory encryption
//! technologies:
//!
//! - **AMD SME** (Secure Memory Encryption) — transparent AES-128
//!   encryption with a single key, controlled by the C-bit in page
//!   table entries.
//! - **AMD SEV** (Secure Encrypted Virtualisation) — per-VM
//!   encryption keys managed by the AMD Secure Processor (PSP).
//! - **AMD SEV-ES** — extends SEV with encrypted register state.
//! - **AMD SEV-SNP** — adds memory integrity and attestation.
//! - **Intel TME** (Total Memory Encryption) — transparent AES-XTS
//!   encryption of all DRAM.
//! - **Intel MKTME** (Multi-Key TME) — per-page encryption with
//!   multiple KeyIDs in page table entries.
//!
//! # Architecture
//!
//! The encryption subsystem manages three orthogonal concerns:
//!
//! 1. **Key management** — allocating, assigning, and revoking
//!    encryption keys (KeyIDs for MKTME, ASIDs for SEV).
//! 2. **Page table integration** — setting the C-bit (AMD) or
//!    KeyID bits (Intel) in PTE entries for encrypted ranges.
//! 3. **Attestation** — SEV-SNP remote attestation stubs for
//!    verifying VM integrity.
//!
//! # Key types
//!
//! - [`EncryptionMode`] — hardware encryption technology in use
//! - [`EncryptionKeyId`] — key slot identifier
//! - [`EncryptedRange`] — a tracked encrypted memory region
//! - [`SevPolicy`] — AMD SEV guest policy
//! - [`AttestationReport`] — SEV-SNP attestation stub
//! - [`EncryptionStats`] — aggregate statistics
//! - [`EncryptionManager`] — the encryption state machine
//!
//! # Reference
//!
//! - AMD APM Vol. 2, Ch. 15 (SME/SEV)
//! - AMD SEV-SNP ABI Specification
//! - Intel SDM Vol. 3, Ch. 6 (TME/MKTME)
//! - Linux `arch/x86/mm/mem_encrypt*.c`, `virt/kvm/sev.c`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Maximum number of encryption keys (MKTME KeyIDs).
const MAX_KEY_SLOTS: usize = 64;

/// Maximum number of tracked encrypted ranges.
const MAX_RANGES: usize = 256;

/// Maximum SEV ASIDs (per AMD PPR, typically 509 for SEV-SNP).
const MAX_SEV_ASIDS: usize = 64;

/// AMD C-bit position in PTE (varies by CPU; common default = 51).
const DEFAULT_CBIT_POSITION: u32 = 51;

/// Intel MKTME KeyID bit width (typically 4-6 bits).
const DEFAULT_KEYID_BITS: u32 = 4;

/// AES-128 key size in bytes.
const AES128_KEY_SIZE: usize = 16;

/// AES-256 key size in bytes.
const AES256_KEY_SIZE: usize = 32;

/// Attestation report size in bytes (SEV-SNP).
const ATTESTATION_REPORT_SIZE: usize = 64;

// ── EncryptionMode ────────────────────────────────────────────────

/// Hardware memory encryption technology in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// No hardware encryption available.
    None,
    /// AMD SME — single-key transparent encryption.
    AmdSme,
    /// AMD SEV — per-VM encryption.
    AmdSev,
    /// AMD SEV-ES — encrypted register state.
    AmdSevEs,
    /// AMD SEV-SNP — integrity + attestation.
    AmdSevSnp,
    /// Intel TME — single-key total memory encryption.
    IntelTme,
    /// Intel MKTME — multi-key per-page encryption.
    IntelMktme,
}

impl EncryptionMode {
    /// Whether this mode supports per-page key selection.
    pub const fn supports_per_page_keys(self) -> bool {
        matches!(self, Self::IntelMktme)
    }

    /// Whether this mode requires the C-bit in page tables.
    pub const fn uses_cbit(self) -> bool {
        matches!(
            self,
            Self::AmdSme | Self::AmdSev | Self::AmdSevEs | Self::AmdSevSnp
        )
    }

    /// Whether this mode uses KeyID bits in page tables.
    pub const fn uses_keyid(self) -> bool {
        matches!(self, Self::IntelMktme)
    }

    /// Whether this mode supports remote attestation.
    pub const fn supports_attestation(self) -> bool {
        matches!(self, Self::AmdSevSnp)
    }

    /// Whether this mode encrypts register state.
    pub const fn encrypts_registers(self) -> bool {
        matches!(self, Self::AmdSevEs | Self::AmdSevSnp)
    }

    /// Whether this mode provides memory integrity.
    pub const fn provides_integrity(self) -> bool {
        matches!(self, Self::AmdSevSnp)
    }

    /// Whether any encryption is active.
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl Default for EncryptionMode {
    fn default() -> Self {
        Self::None
    }
}

// ── EncryptionAlgorithm ───────────────────────────────────────────

/// Encryption algorithm used by the hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-128 (AMD SME/SEV default).
    Aes128,
    /// AES-256-XTS (Intel TME/MKTME).
    Aes256Xts,
}

impl EncryptionAlgorithm {
    /// Key size in bytes.
    pub const fn key_size(self) -> usize {
        match self {
            Self::Aes128 => AES128_KEY_SIZE,
            Self::Aes256Xts => AES256_KEY_SIZE,
        }
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::Aes128
    }
}

// ── EncryptionKeyId ───────────────────────────────────────────────

/// An encryption key slot identifier.
///
/// For Intel MKTME, this is the KeyID embedded in the upper bits
/// of a physical address. For AMD SEV, this maps to an ASID.
/// Key 0 is typically the platform default key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKeyId(u32);

impl EncryptionKeyId {
    /// The platform default key (key 0).
    pub const DEFAULT: Self = Self(0);

    /// Create a new key ID.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// The raw integer value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Default for EncryptionKeyId {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ── KeySlot ───────────────────────────────────────────────────────

/// Internal key slot tracking.
#[derive(Debug, Clone, Copy)]
struct KeySlot {
    /// Key ID.
    key_id: EncryptionKeyId,
    /// Algorithm.
    algorithm: EncryptionAlgorithm,
    /// Whether this key is user-supplied or platform-generated.
    user_supplied: bool,
    /// Reference count (number of ranges using this key).
    ref_count: u32,
    /// Whether this slot is active.
    active: bool,
}

impl KeySlot {
    const fn empty() -> Self {
        Self {
            key_id: EncryptionKeyId::DEFAULT,
            algorithm: EncryptionAlgorithm::Aes128,
            user_supplied: false,
            ref_count: 0,
            active: false,
        }
    }
}

// ── EncryptedRange ────────────────────────────────────────────────

/// A tracked encrypted memory region.
///
/// Each range is associated with an encryption key and tracks
/// the physical address range that is encrypted.
#[derive(Debug, Clone, Copy)]
pub struct EncryptedRange {
    /// Start physical address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Encryption key used for this range.
    pub key_id: EncryptionKeyId,
    /// Encryption mode applied to this range.
    pub mode: EncryptionMode,
    /// Whether the C-bit is set (AMD) or KeyID embedded (Intel).
    pub pte_encrypted: bool,
    /// ASID for SEV guests (0 if not applicable).
    pub sev_asid: u32,
    /// Whether this range is active.
    pub active: bool,
}

impl EncryptedRange {
    /// Creates an empty, inactive range.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            key_id: EncryptionKeyId::DEFAULT,
            mode: EncryptionMode::None,
            pte_encrypted: false,
            sev_asid: 0,
            active: false,
        }
    }

    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Total pages in this range.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Whether an address falls within this range.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Whether this range overlaps `[start, start+size)`.
    pub const fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.active || size == 0 {
            return false;
        }
        let end = start.saturating_add(size);
        self.start < end && self.end() > start
    }
}

// ── SevPolicy ─────────────────────────────────────────────────────

/// AMD SEV guest policy flags.
///
/// Controls which features are allowed for a SEV/SEV-ES/SEV-SNP
/// guest. Encoded as a 64-bit policy word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SevPolicy(u64);

/// Bit: guest must not be sent to another platform.
const SEV_POLICY_NODBG: u64 = 1 << 0;
/// Bit: guest must not run with KS (key sharing).
const SEV_POLICY_NOKS: u64 = 1 << 1;
/// Bit: SEV-ES required.
const SEV_POLICY_ES: u64 = 1 << 2;
/// Bit: no key sharing outside SEV-SNP.
const SEV_POLICY_NOSEND: u64 = 1 << 3;
/// Bit: single-socket only.
const SEV_POLICY_SINGLE_SOCKET: u64 = 1 << 4;
/// Bit: debugging is allowed.
const SEV_POLICY_DEBUG: u64 = 1 << 5;
/// Bit: migration is allowed.
const SEV_POLICY_MIGRATE: u64 = 1 << 6;

impl SevPolicy {
    /// Create an empty (permissive) policy.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a policy from a raw 64-bit word.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw policy word.
    pub const fn as_raw(self) -> u64 {
        self.0
    }

    /// Whether debugging is disallowed.
    pub const fn no_debug(self) -> bool {
        self.0 & SEV_POLICY_NODBG != 0
    }

    /// Whether key sharing is disallowed.
    pub const fn no_key_sharing(self) -> bool {
        self.0 & SEV_POLICY_NOKS != 0
    }

    /// Whether SEV-ES is required.
    pub const fn requires_es(self) -> bool {
        self.0 & SEV_POLICY_ES != 0
    }

    /// Whether migration sending is disallowed.
    pub const fn no_send(self) -> bool {
        self.0 & SEV_POLICY_NOSEND != 0
    }

    /// Whether single-socket mode is required.
    pub const fn single_socket(self) -> bool {
        self.0 & SEV_POLICY_SINGLE_SOCKET != 0
    }

    /// Whether debugging is allowed.
    pub const fn debug_allowed(self) -> bool {
        self.0 & SEV_POLICY_DEBUG != 0
    }

    /// Whether migration is allowed.
    pub const fn migration_allowed(self) -> bool {
        self.0 & SEV_POLICY_MIGRATE != 0
    }

    /// Builder: set no-debug.
    pub const fn with_no_debug(self) -> Self {
        Self(self.0 | SEV_POLICY_NODBG)
    }

    /// Builder: set no-key-sharing.
    pub const fn with_no_key_sharing(self) -> Self {
        Self(self.0 | SEV_POLICY_NOKS)
    }

    /// Builder: require SEV-ES.
    pub const fn with_es_required(self) -> Self {
        Self(self.0 | SEV_POLICY_ES)
    }

    /// Builder: set no-send.
    pub const fn with_no_send(self) -> Self {
        Self(self.0 | SEV_POLICY_NOSEND)
    }
}

// ── AttestationReport ─────────────────────────────────────────────

/// SEV-SNP attestation report (stub).
///
/// In a full implementation this would contain a signed report
/// from the AMD Secure Processor. Here we model the essential
/// fields for the interface.
#[derive(Debug, Clone, Copy)]
pub struct AttestationReport {
    /// Guest policy.
    pub policy: SevPolicy,
    /// Platform firmware version (major).
    pub fw_major: u8,
    /// Platform firmware version (minor).
    pub fw_minor: u8,
    /// Guest-supplied 64-byte data (e.g. nonce or hash).
    pub report_data: [u8; ATTESTATION_REPORT_SIZE],
    /// Measurement of the guest launch digest.
    pub measurement: [u8; 48],
    /// Whether this report has been populated.
    pub valid: bool,
}

impl AttestationReport {
    /// Creates an empty, invalid report.
    pub const fn empty() -> Self {
        Self {
            policy: SevPolicy::empty(),
            fw_major: 0,
            fw_minor: 0,
            report_data: [0u8; ATTESTATION_REPORT_SIZE],
            measurement: [0u8; 48],
            valid: false,
        }
    }
}

impl Default for AttestationReport {
    fn default() -> Self {
        Self::empty()
    }
}

// ── CbitConfig ────────────────────────────────────────────────────

/// AMD C-bit configuration.
///
/// The C-bit is a single bit in the page table entry that
/// indicates whether the physical page is encrypted.
#[derive(Debug, Clone, Copy)]
pub struct CbitConfig {
    /// Bit position of the C-bit in PTEs (from CPUID).
    pub position: u32,
    /// Mask derived from the position.
    pub mask: u64,
}

impl CbitConfig {
    /// Create a C-bit config for a given bit position.
    pub const fn new(position: u32) -> Self {
        Self {
            position,
            mask: 1u64 << position,
        }
    }

    /// Apply the C-bit to a PTE value (set encrypted).
    pub const fn encrypt_pte(self, pte: u64) -> u64 {
        pte | self.mask
    }

    /// Clear the C-bit from a PTE value (set decrypted).
    pub const fn decrypt_pte(self, pte: u64) -> u64 {
        pte & !self.mask
    }

    /// Whether the C-bit is set in a PTE value.
    pub const fn is_encrypted(self, pte: u64) -> bool {
        pte & self.mask != 0
    }
}

impl Default for CbitConfig {
    fn default() -> Self {
        Self::new(DEFAULT_CBIT_POSITION)
    }
}

// ── KeyIdConfig ───────────────────────────────────────────────────

/// Intel MKTME KeyID configuration.
///
/// KeyIDs occupy the upper bits of physical addresses in page
/// table entries. The number of bits and their position are
/// determined by CPUID.
#[derive(Debug, Clone, Copy)]
pub struct KeyIdConfig {
    /// Number of KeyID bits.
    pub bits: u32,
    /// Bit position where KeyID starts in the physical address.
    pub shift: u32,
    /// Mask for extracting the KeyID from a PTE.
    pub mask: u64,
    /// Maximum KeyID value.
    pub max_key_id: u32,
}

impl KeyIdConfig {
    /// Create a KeyID config.
    ///
    /// `bits` is the number of KeyID bits; `shift` is the starting
    /// bit position (typically phys_addr_width - bits).
    pub const fn new(bits: u32, shift: u32) -> Self {
        let max = if bits >= 32 {
            u32::MAX
        } else {
            (1u32 << bits).saturating_sub(1)
        };
        Self {
            bits,
            shift,
            mask: (max as u64) << shift,
            max_key_id: max,
        }
    }

    /// Embed a KeyID into a PTE value.
    pub const fn set_key_in_pte(self, pte: u64, key_id: u32) -> u64 {
        (pte & !self.mask) | ((key_id as u64) << self.shift)
    }

    /// Extract the KeyID from a PTE value.
    pub const fn get_key_from_pte(self, pte: u64) -> u32 {
        ((pte & self.mask) >> self.shift) as u32
    }
}

impl Default for KeyIdConfig {
    fn default() -> Self {
        Self::new(DEFAULT_KEYID_BITS, 48)
    }
}

// ── EncryptionStats ───────────────────────────────────────────────

/// Aggregate statistics for the encryption subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncryptionStats {
    /// Total encrypted ranges created.
    pub ranges_created: u64,
    /// Total encrypted ranges removed.
    pub ranges_removed: u64,
    /// Total pages currently encrypted.
    pub pages_encrypted: u64,
    /// Total keys allocated.
    pub keys_allocated: u64,
    /// Total keys released.
    pub keys_released: u64,
    /// Attestation reports requested.
    pub attestation_requests: u64,
    /// Key allocation failures.
    pub key_alloc_failures: u64,
    /// Range creation failures.
    pub range_failures: u64,
}

// ── EncryptionManager ─────────────────────────────────────────────

/// The memory encryption state machine.
///
/// Manages encryption keys, tracks encrypted memory ranges, and
/// provides C-bit / KeyID manipulation for page table integration.
pub struct EncryptionManager {
    /// Active encryption mode.
    mode: EncryptionMode,
    /// AMD C-bit configuration.
    cbit: CbitConfig,
    /// Intel MKTME KeyID configuration.
    keyid_config: KeyIdConfig,
    /// Key slot table.
    keys: [KeySlot; MAX_KEY_SLOTS],
    /// Next key ID to allocate.
    next_key_id: u32,
    /// Encrypted memory ranges.
    ranges: [EncryptedRange; MAX_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// SEV guest policy (AMD only).
    sev_policy: SevPolicy,
    /// Latest attestation report (SEV-SNP only).
    attestation: AttestationReport,
    /// Statistics.
    stats: EncryptionStats,
}

impl Default for EncryptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionManager {
    /// Creates a new manager with no encryption active.
    pub const fn new() -> Self {
        Self {
            mode: EncryptionMode::None,
            cbit: CbitConfig {
                position: DEFAULT_CBIT_POSITION,
                mask: 1u64 << DEFAULT_CBIT_POSITION,
            },
            keyid_config: KeyIdConfig {
                bits: DEFAULT_KEYID_BITS,
                shift: 48,
                mask: ((1u64 << DEFAULT_KEYID_BITS) - 1) << 48,
                max_key_id: (1u32 << DEFAULT_KEYID_BITS) - 1,
            },
            keys: [KeySlot::empty(); MAX_KEY_SLOTS],
            next_key_id: 1,
            ranges: [EncryptedRange::empty(); MAX_RANGES],
            range_count: 0,
            sev_policy: SevPolicy::empty(),
            attestation: AttestationReport::empty(),
            stats: EncryptionStats {
                ranges_created: 0,
                ranges_removed: 0,
                pages_encrypted: 0,
                keys_allocated: 0,
                keys_released: 0,
                attestation_requests: 0,
                key_alloc_failures: 0,
                range_failures: 0,
            },
        }
    }

    // ── Initialisation ────────────────────────────────────────────

    /// Initialise the manager for a specific encryption mode.
    ///
    /// Must be called before any other operations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if mode is `None`.
    pub fn init(&mut self, mode: EncryptionMode) -> Result<()> {
        if !mode.is_active() {
            return Err(Error::InvalidArgument);
        }
        self.mode = mode;
        Ok(())
    }

    /// Configure AMD C-bit position (from CPUID Fn8000_001F).
    pub fn configure_cbit(&mut self, position: u32) {
        self.cbit = CbitConfig::new(position);
    }

    /// Configure Intel MKTME KeyID parameters.
    pub fn configure_keyid(&mut self, bits: u32, shift: u32) {
        self.keyid_config = KeyIdConfig::new(bits, shift);
    }

    /// Set the SEV guest policy.
    pub fn set_sev_policy(&mut self, policy: SevPolicy) {
        self.sev_policy = policy;
    }

    // ── Key management ────────────────────────────────────────────

    /// Allocate a new encryption key.
    ///
    /// Returns the allocated [`EncryptionKeyId`].
    ///
    /// # Arguments
    ///
    /// - `algorithm` — encryption algorithm to use.
    /// - `user_supplied` — whether the key material is provided
    ///   by the caller (true) or generated by hardware (false).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no key slots are available.
    /// Returns [`Error::NotReady`] if encryption is not initialised.
    pub fn allocate_key(
        &mut self,
        algorithm: EncryptionAlgorithm,
        user_supplied: bool,
    ) -> Result<EncryptionKeyId> {
        if !self.mode.is_active() {
            return Err(Error::Busy);
        }

        let slot = self.keys.iter_mut().find(|k| !k.active).ok_or_else(|| {
            self.stats.key_alloc_failures += 1;
            Error::OutOfMemory
        })?;

        let key_id = EncryptionKeyId::new(self.next_key_id);
        self.next_key_id += 1;

        *slot = KeySlot {
            key_id,
            algorithm,
            user_supplied,
            ref_count: 0,
            active: true,
        };
        self.stats.keys_allocated += 1;

        Ok(key_id)
    }

    /// Release an encryption key.
    ///
    /// The key must have zero references (no ranges using it).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the key is not allocated.
    /// Returns [`Error::Busy`] if the key still has references.
    pub fn release_key(&mut self, key_id: EncryptionKeyId) -> Result<()> {
        let slot = self
            .keys
            .iter_mut()
            .find(|k| k.active && k.key_id == key_id)
            .ok_or(Error::NotFound)?;

        if slot.ref_count > 0 {
            return Err(Error::Busy);
        }

        slot.active = false;
        self.stats.keys_released += 1;
        Ok(())
    }

    /// Look up key metadata.
    pub fn key_info(&self, key_id: EncryptionKeyId) -> Option<(EncryptionAlgorithm, bool, u32)> {
        self.keys
            .iter()
            .find(|k| k.active && k.key_id == key_id)
            .map(|k| (k.algorithm, k.user_supplied, k.ref_count))
    }

    /// Number of allocated keys.
    pub fn key_count(&self) -> usize {
        self.keys.iter().filter(|k| k.active).count()
    }

    // ── Range management ──────────────────────────────────────────

    /// Create an encrypted memory range.
    ///
    /// # Arguments
    ///
    /// - `start` — physical start address (page-aligned).
    /// - `size` — size in bytes (page-aligned, non-zero).
    /// - `key_id` — encryption key to use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if addresses are not
    /// page-aligned or size is zero.
    /// Returns [`Error::NotFound`] if the key is not allocated.
    /// Returns [`Error::OutOfMemory`] if the range table is full.
    /// Returns [`Error::NotReady`] if encryption is not active.
    pub fn create_range(&mut self, start: u64, size: u64, key_id: EncryptionKeyId) -> Result<()> {
        if !self.mode.is_active() {
            return Err(Error::Busy);
        }

        if start & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 {
            self.stats.range_failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Verify key exists and increment refcount.
        let key_slot = self
            .keys
            .iter_mut()
            .find(|k| k.active && k.key_id == key_id)
            .ok_or(Error::NotFound)?;
        key_slot.ref_count += 1;

        let slot = match self.ranges.iter_mut().find(|r| !r.active) {
            Some(s) => s,
            None => {
                // Roll back key refcount.
                if let Some(k) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.active && k.key_id == key_id)
                {
                    k.ref_count = k.ref_count.saturating_sub(1);
                }
                self.stats.range_failures += 1;
                return Err(Error::OutOfMemory);
            }
        };

        let pages = size / PAGE_SIZE;
        *slot = EncryptedRange {
            start,
            size,
            key_id,
            mode: self.mode,
            pte_encrypted: true,
            sev_asid: 0,
            active: true,
        };
        self.range_count += 1;
        self.stats.ranges_created += 1;
        self.stats.pages_encrypted += pages;

        Ok(())
    }

    /// Remove an encrypted range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn remove_range(&mut self, start: u64) -> Result<()> {
        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.start == start)
            .ok_or(Error::NotFound)?;

        let pages = range.page_count();
        let key_id = range.key_id;
        range.active = false;
        self.range_count = self.range_count.saturating_sub(1);
        self.stats.ranges_removed += 1;
        self.stats.pages_encrypted = self.stats.pages_encrypted.saturating_sub(pages);

        // Decrement key refcount.
        if let Some(k) = self
            .keys
            .iter_mut()
            .find(|k| k.active && k.key_id == key_id)
        {
            k.ref_count = k.ref_count.saturating_sub(1);
        }

        Ok(())
    }

    /// Set the SEV ASID for a range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    /// Returns [`Error::InvalidArgument`] if ASID exceeds limit.
    pub fn set_range_asid(&mut self, start: u64, asid: u32) -> Result<()> {
        if asid as usize >= MAX_SEV_ASIDS {
            return Err(Error::InvalidArgument);
        }
        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.start == start)
            .ok_or(Error::NotFound)?;
        range.sev_asid = asid;
        Ok(())
    }

    // ── PTE helpers ───────────────────────────────────────────────

    /// Apply encryption bits to a PTE for the current mode.
    ///
    /// - AMD modes: sets the C-bit.
    /// - Intel MKTME: embeds the KeyID.
    /// - Intel TME / None: returns the PTE unchanged.
    pub fn encrypt_pte(&self, pte: u64, key_id: EncryptionKeyId) -> u64 {
        match self.mode {
            EncryptionMode::AmdSme
            | EncryptionMode::AmdSev
            | EncryptionMode::AmdSevEs
            | EncryptionMode::AmdSevSnp => self.cbit.encrypt_pte(pte),
            EncryptionMode::IntelMktme => self.keyid_config.set_key_in_pte(pte, key_id.as_u32()),
            EncryptionMode::IntelTme | EncryptionMode::None => pte,
        }
    }

    /// Remove encryption bits from a PTE.
    pub fn decrypt_pte(&self, pte: u64) -> u64 {
        match self.mode {
            EncryptionMode::AmdSme
            | EncryptionMode::AmdSev
            | EncryptionMode::AmdSevEs
            | EncryptionMode::AmdSevSnp => self.cbit.decrypt_pte(pte),
            EncryptionMode::IntelMktme => self.keyid_config.set_key_in_pte(pte, 0),
            EncryptionMode::IntelTme | EncryptionMode::None => pte,
        }
    }

    /// Check whether a PTE has encryption bits set.
    pub fn is_pte_encrypted(&self, pte: u64) -> bool {
        match self.mode {
            EncryptionMode::AmdSme
            | EncryptionMode::AmdSev
            | EncryptionMode::AmdSevEs
            | EncryptionMode::AmdSevSnp => self.cbit.is_encrypted(pte),
            EncryptionMode::IntelMktme => self.keyid_config.get_key_from_pte(pte) != 0,
            EncryptionMode::IntelTme | EncryptionMode::None => false,
        }
    }

    // ── Attestation (SEV-SNP stub) ────────────────────────────────

    /// Request an attestation report (SEV-SNP).
    ///
    /// In a real implementation, this would invoke the AMD Secure
    /// Processor via the SEV firmware ABI (`SNP_GUEST_REQUEST`).
    /// Here we populate a stub report.
    ///
    /// # Arguments
    ///
    /// - `report_data` — 64 bytes of caller-supplied data (nonce,
    ///   hash, etc.) included in the signed report.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSupported`] if the mode is not SEV-SNP.
    pub fn request_attestation(
        &mut self,
        report_data: &[u8; ATTESTATION_REPORT_SIZE],
    ) -> Result<&AttestationReport> {
        if !self.mode.supports_attestation() {
            return Err(Error::NotImplemented);
        }

        self.stats.attestation_requests += 1;

        // Stub: populate with policy and report_data.
        self.attestation = AttestationReport {
            policy: self.sev_policy,
            fw_major: 1,
            fw_minor: 0,
            report_data: *report_data,
            measurement: [0u8; 48],
            valid: true,
        };

        Ok(&self.attestation)
    }

    /// Get the latest attestation report.
    pub fn attestation_report(&self) -> &AttestationReport {
        &self.attestation
    }

    // ── Accessors ─────────────────────────────────────────────────

    /// Current encryption mode.
    pub fn mode(&self) -> EncryptionMode {
        self.mode
    }

    /// Current C-bit configuration.
    pub fn cbit_config(&self) -> &CbitConfig {
        &self.cbit
    }

    /// Current KeyID configuration.
    pub fn keyid_config(&self) -> &KeyIdConfig {
        &self.keyid_config
    }

    /// Current SEV policy.
    pub fn sev_policy(&self) -> &SevPolicy {
        &self.sev_policy
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> &EncryptionStats {
        &self.stats
    }

    /// Number of active encrypted ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Look up an encrypted range by start address.
    pub fn find_range(&self, start: u64) -> Option<&EncryptedRange> {
        self.ranges.iter().find(|r| r.active && r.start == start)
    }

    /// Find all encrypted ranges containing a given address.
    pub fn ranges_containing(&self, addr: u64) -> impl Iterator<Item = &EncryptedRange> {
        self.ranges.iter().filter(move |r| r.contains(addr))
    }

    /// Iterate over all active encrypted ranges.
    pub fn all_ranges(&self) -> impl Iterator<Item = &EncryptedRange> {
        self.ranges.iter().filter(|r| r.active)
    }

    /// Total encrypted pages across all ranges.
    pub fn total_encrypted_pages(&self) -> u64 {
        self.ranges
            .iter()
            .filter(|r| r.active)
            .map(|r| r.page_count())
            .sum()
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Align a value up to the next page boundary.
const fn _page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}

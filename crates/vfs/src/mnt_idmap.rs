// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount ID mapping — user/group ID translation for idmapped mounts.
//!
//! Idmapped mounts allow a filesystem to be mounted with a user/group ID
//! translation table, so that files owned by host uid X appear to a container
//! as owned by ns uid Y.  This is the kernel mechanism behind bind mounts used
//! by container runtimes (e.g., `mount --bind --map-users=...`).
//!
//! # Design
//!
//! ```text
//! create_idmap() → idmap_id
//!   │
//!   ├── add_uid_mapping(idmap_id, host_id=1000, ns_id=0, count=1000)
//!   └── add_gid_mapping(idmap_id, host_id=1000, ns_id=0, count=1000)
//!
//! apply_to_mount(mount_id, idmap_id) — attach the map to a mount
//!
//! map_id_to_ns(idmap_id, Uid, host_id=1042) → ns_id=42
//! map_id_from_ns(idmap_id, Uid, ns_id=42)   → host_id=1042
//! ```
//!
//! Each [`IdMapEntry`] describes a *range* mapping:
//! `[host_id, host_id+count)` ↔ `[ns_id, ns_id+count)`.
//!
//! # References
//!
//! - Linux `fs/idmapping.c`, `include/linux/user_namespace.h`
//! - Linux `Documentation/filesystems/idmappings.rst`
//! - `man 7 user_namespaces`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of UID map entries per [`MntIdMap`].
pub const MAX_UID_MAP_ENTRIES: usize = 32;

/// Maximum number of GID map entries per [`MntIdMap`].
pub const MAX_GID_MAP_ENTRIES: usize = 32;

/// Maximum number of idmaps held in the [`MntIdMapRegistry`].
pub const MAX_IDMAPS: usize = 64;

/// Sentinel value meaning "no mapping" (i.e. the ID is unmapped).
pub const ID_NONE: u32 = u32::MAX;

// ── IdMapType ─────────────────────────────────────────────────────────────────

/// Selects whether a mapping operation applies to user IDs or group IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdMapType {
    /// User ID mapping.
    Uid,
    /// Group ID mapping.
    Gid,
}

// ── IdMapEntry ────────────────────────────────────────────────────────────────

/// A single contiguous range mapping between host and namespace IDs.
///
/// The range `[host_id, host_id + count)` maps to `[ns_id, ns_id + count)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMapEntry {
    /// First host-namespace ID in the range.
    pub host_id: u32,
    /// First mount-namespace ID in the range.
    pub ns_id: u32,
    /// Number of IDs in the range.
    pub count: u32,
}

impl Default for IdMapEntry {
    fn default() -> Self {
        Self {
            host_id: 0,
            ns_id: 0,
            count: 0,
        }
    }
}

impl IdMapEntry {
    /// Construct a new map entry.
    pub const fn new(host_id: u32, ns_id: u32, count: u32) -> Self {
        Self {
            host_id,
            ns_id,
            count,
        }
    }

    /// Return `true` when this entry is valid (non-zero count and no overflow).
    pub fn is_valid(&self) -> bool {
        self.count > 0
            && self.host_id.checked_add(self.count).is_some()
            && self.ns_id.checked_add(self.count).is_some()
    }

    /// Map `host_id` → ns_id if within this range, otherwise return `None`.
    pub fn map_to_ns(&self, host_id: u32) -> Option<u32> {
        if host_id >= self.host_id && host_id < self.host_id.saturating_add(self.count) {
            Some(self.ns_id + (host_id - self.host_id))
        } else {
            None
        }
    }

    /// Map `ns_id` → host_id if within this range, otherwise return `None`.
    pub fn map_from_ns(&self, ns_id: u32) -> Option<u32> {
        if ns_id >= self.ns_id && ns_id < self.ns_id.saturating_add(self.count) {
            Some(self.host_id + (ns_id - self.ns_id))
        } else {
            None
        }
    }

    /// Check whether this entry overlaps `other` in the host ID space.
    pub fn overlaps_host(&self, other: &Self) -> bool {
        let s_end = self.host_id.saturating_add(self.count);
        let o_end = other.host_id.saturating_add(other.count);
        self.host_id < o_end && other.host_id < s_end
    }

    /// Check whether this entry overlaps `other` in the namespace ID space.
    pub fn overlaps_ns(&self, other: &Self) -> bool {
        let s_end = self.ns_id.saturating_add(self.count);
        let o_end = other.ns_id.saturating_add(other.count);
        self.ns_id < o_end && other.ns_id < s_end
    }
}

// ── MntIdMap ─────────────────────────────────────────────────────────────────

/// A complete ID mapping for one mount point.
///
/// Holds up to [`MAX_UID_MAP_ENTRIES`] UID mappings and [`MAX_GID_MAP_ENTRIES`]
/// GID mappings.  Once `active` is set, the map is considered immutable (Linux
/// behaviour: maps cannot be modified after the first write).
#[derive(Clone, Copy)]
pub struct MntIdMap {
    /// UID map entries.
    uid_map: [IdMapEntry; MAX_UID_MAP_ENTRIES],
    /// Number of valid entries in `uid_map`.
    uid_count: usize,
    /// GID map entries.
    gid_map: [IdMapEntry; MAX_GID_MAP_ENTRIES],
    /// Number of valid entries in `gid_map`.
    gid_count: usize,
    /// When `true` the mapping is in use and no further entries may be added.
    pub active: bool,
    /// Whether this idmap slot is occupied.
    in_use: bool,
}

impl Default for MntIdMap {
    fn default() -> Self {
        Self::new()
    }
}

impl MntIdMap {
    /// Construct an empty, inactive [`MntIdMap`].
    pub const fn new() -> Self {
        Self {
            uid_map: [const { IdMapEntry::new(0, 0, 0) }; MAX_UID_MAP_ENTRIES],
            uid_count: 0,
            gid_map: [const { IdMapEntry::new(0, 0, 0) }; MAX_GID_MAP_ENTRIES],
            gid_count: 0,
            active: false,
            in_use: false,
        }
    }

    /// Add a UID mapping entry.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`]            — the map is already active (immutable).
    /// - [`Error::OutOfMemory`]     — the UID map is full.
    /// - [`Error::InvalidArgument`] — the entry is invalid or overlaps an existing entry.
    pub fn add_uid_mapping(&mut self, entry: IdMapEntry) -> Result<()> {
        if self.active {
            return Err(Error::Busy);
        }
        if !entry.is_valid() {
            return Err(Error::InvalidArgument);
        }
        for existing in &self.uid_map[..self.uid_count] {
            if existing.overlaps_host(&entry) || existing.overlaps_ns(&entry) {
                return Err(Error::InvalidArgument);
            }
        }
        if self.uid_count >= MAX_UID_MAP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.uid_map[self.uid_count] = entry;
        self.uid_count += 1;
        Ok(())
    }

    /// Add a GID mapping entry.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`]            — the map is already active (immutable).
    /// - [`Error::OutOfMemory`]     — the GID map is full.
    /// - [`Error::InvalidArgument`] — the entry is invalid or overlaps an existing entry.
    pub fn add_gid_mapping(&mut self, entry: IdMapEntry) -> Result<()> {
        if self.active {
            return Err(Error::Busy);
        }
        if !entry.is_valid() {
            return Err(Error::InvalidArgument);
        }
        for existing in &self.gid_map[..self.gid_count] {
            if existing.overlaps_host(&entry) || existing.overlaps_ns(&entry) {
                return Err(Error::InvalidArgument);
            }
        }
        if self.gid_count >= MAX_GID_MAP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.gid_map[self.gid_count] = entry;
        self.gid_count += 1;
        Ok(())
    }

    /// Map a host ID to its namespace ID.
    ///
    /// Returns [`ID_NONE`] when the host ID falls outside all defined ranges.
    pub fn map_to_ns(&self, map_type: IdMapType, host_id: u32) -> u32 {
        let entries = match map_type {
            IdMapType::Uid => &self.uid_map[..self.uid_count],
            IdMapType::Gid => &self.gid_map[..self.gid_count],
        };
        for entry in entries {
            if let Some(ns_id) = entry.map_to_ns(host_id) {
                return ns_id;
            }
        }
        ID_NONE
    }

    /// Map a namespace ID back to the host ID.
    ///
    /// Returns [`ID_NONE`] when the namespace ID falls outside all defined ranges.
    pub fn map_from_ns(&self, map_type: IdMapType, ns_id: u32) -> u32 {
        let entries = match map_type {
            IdMapType::Uid => &self.uid_map[..self.uid_count],
            IdMapType::Gid => &self.gid_map[..self.gid_count],
        };
        for entry in entries {
            if let Some(host_id) = entry.map_from_ns(ns_id) {
                return host_id;
            }
        }
        ID_NONE
    }

    /// Return the UID map entries as a slice.
    pub fn uid_entries(&self) -> &[IdMapEntry] {
        &self.uid_map[..self.uid_count]
    }

    /// Return the GID map entries as a slice.
    pub fn gid_entries(&self) -> &[IdMapEntry] {
        &self.gid_map[..self.gid_count]
    }
}

// ── MntIdMapRegistry ──────────────────────────────────────────────────────────

/// Global registry holding up to [`MAX_IDMAPS`] mount ID maps.
pub struct MntIdMapRegistry {
    /// Idmap slot table.
    maps: [MntIdMap; MAX_IDMAPS],
    /// Mount-to-idmap association: mount_association[i] = Some(idmap_id) means
    /// mount `i` uses the idmap with that id.  This is a stub array sized 64.
    mount_association: [Option<u32>; MAX_IDMAPS],
    /// Accumulated statistics.
    stats: MntIdMapStats,
}

impl Default for MntIdMapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MntIdMapRegistry {
    /// Construct an empty registry.
    pub const fn new() -> Self {
        Self {
            maps: [const {
                MntIdMap {
                    uid_map: [const { IdMapEntry::new(0, 0, 0) }; MAX_UID_MAP_ENTRIES],
                    uid_count: 0,
                    gid_map: [const { IdMapEntry::new(0, 0, 0) }; MAX_GID_MAP_ENTRIES],
                    gid_count: 0,
                    active: false,
                    in_use: false,
                }
            }; MAX_IDMAPS],
            mount_association: [None; MAX_IDMAPS],
            stats: MntIdMapStats::new(),
        }
    }

    /// Allocate a new idmap and return its id (1-based slot index).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the registry is full.
    pub fn create_idmap(&mut self) -> Result<u32> {
        let slot = self
            .maps
            .iter()
            .position(|m| !m.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.maps[slot] = MntIdMap::new();
        self.maps[slot].in_use = true;
        self.stats.mappings_created += 1;
        Ok((slot as u32) + 1)
    }

    /// Destroy an idmap, releasing its slot.
    ///
    /// Any mounts that referenced this idmap are disassociated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when `idmap_id` is not in use.
    pub fn destroy_idmap(&mut self, idmap_id: u32) -> Result<()> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        // Disassociate any mounts referencing this idmap.
        for assoc in self.mount_association.iter_mut() {
            if *assoc == Some(idmap_id) {
                *assoc = None;
            }
        }
        self.maps[slot] = MntIdMap::new();
        Ok(())
    }

    /// Add a UID mapping entry to `idmap_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]        — no idmap with `idmap_id`.
    /// - Errors from [`MntIdMap::add_uid_mapping`].
    pub fn add_uid_mapping(&mut self, idmap_id: u32, entry: IdMapEntry) -> Result<()> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        self.maps[slot].add_uid_mapping(entry)
    }

    /// Add a GID mapping entry to `idmap_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]        — no idmap with `idmap_id`.
    /// - Errors from [`MntIdMap::add_gid_mapping`].
    pub fn add_gid_mapping(&mut self, idmap_id: u32, entry: IdMapEntry) -> Result<()> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        self.maps[slot].add_gid_mapping(entry)
    }

    /// Translate `host_id` to its namespace ID using idmap `idmap_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when `idmap_id` does not exist.
    pub fn map_id_to_ns(
        &mut self,
        idmap_id: u32,
        map_type: IdMapType,
        host_id: u32,
    ) -> Result<u32> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        self.stats.lookups += 1;
        let ns_id = self.maps[slot].map_to_ns(map_type, host_id);
        if ns_id == ID_NONE {
            self.stats.misses += 1;
        }
        Ok(ns_id)
    }

    /// Translate `ns_id` back to the host ID using idmap `idmap_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when `idmap_id` does not exist.
    pub fn map_id_from_ns(
        &mut self,
        idmap_id: u32,
        map_type: IdMapType,
        ns_id: u32,
    ) -> Result<u32> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        self.stats.reverse_lookups += 1;
        let host_id = self.maps[slot].map_from_ns(map_type, ns_id);
        if host_id == ID_NONE {
            self.stats.misses += 1;
        }
        Ok(host_id)
    }

    /// Attach idmap `idmap_id` to mount `mount_id`, marking the map active.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]   — `idmap_id` or `mount_id` out of range.
    /// - [`Error::Busy`]       — `mount_id` already has an idmap attached.
    pub fn apply_to_mount(&mut self, mount_id: usize, idmap_id: u32) -> Result<()> {
        if mount_id >= MAX_IDMAPS {
            return Err(Error::NotFound);
        }
        if self.mount_association[mount_id].is_some() {
            return Err(Error::Busy);
        }
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        self.maps[slot].active = true;
        self.mount_association[mount_id] = Some(idmap_id);
        Ok(())
    }

    /// Return the idmap id associated with `mount_id`, if any.
    pub fn idmap_for_mount(&self, mount_id: usize) -> Option<u32> {
        self.mount_association.get(mount_id).copied().flatten()
    }

    /// Return a reference to the idmap for `idmap_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when `idmap_id` does not exist.
    pub fn get(&self, idmap_id: u32) -> Result<&MntIdMap> {
        let slot = self.slot_of(idmap_id).ok_or(Error::NotFound)?;
        Ok(&self.maps[slot])
    }

    /// Return a snapshot of accumulated statistics.
    pub fn stats(&self) -> &MntIdMapStats {
        &self.stats
    }

    // -- private helpers ------------------------------------------------------

    fn slot_of(&self, idmap_id: u32) -> Option<usize> {
        if idmap_id == 0 {
            return None;
        }
        let slot = (idmap_id as usize).checked_sub(1)?;
        if slot >= MAX_IDMAPS {
            return None;
        }
        if self.maps[slot].in_use {
            Some(slot)
        } else {
            None
        }
    }
}

// ── Convenience free functions ────────────────────────────────────────────────

/// Translate `host_id` to a namespace ID using the idmap attached to `mount_id`.
///
/// Returns [`ID_NONE`] when the mount has no idmap or the ID is unmapped.
///
/// # Errors
///
/// Returns [`Error::NotFound`] when `mount_id` is out of range.
pub fn map_id_to_ns(
    registry: &mut MntIdMapRegistry,
    mount_id: usize,
    map_type: IdMapType,
    host_id: u32,
) -> Result<u32> {
    match registry.idmap_for_mount(mount_id) {
        None => Ok(host_id), // identity mapping — no idmap attached
        Some(idmap_id) => registry.map_id_to_ns(idmap_id, map_type, host_id),
    }
}

/// Translate `ns_id` back to a host ID using the idmap attached to `mount_id`.
///
/// Returns `ns_id` unchanged when the mount has no idmap (identity mapping).
///
/// # Errors
///
/// Returns [`Error::NotFound`] when `mount_id` is out of range.
pub fn map_id_from_ns(
    registry: &mut MntIdMapRegistry,
    mount_id: usize,
    map_type: IdMapType,
    ns_id: u32,
) -> Result<u32> {
    match registry.idmap_for_mount(mount_id) {
        None => Ok(ns_id),
        Some(idmap_id) => registry.map_id_from_ns(idmap_id, map_type, ns_id),
    }
}

// ── MntIdMapStats ─────────────────────────────────────────────────────────────

/// Cumulative statistics for the mount ID mapping subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MntIdMapStats {
    /// Total idmaps created.
    pub mappings_created: u64,
    /// Forward ID mapping lookups (host → ns).
    pub lookups: u64,
    /// Reverse ID mapping lookups (ns → host).
    pub reverse_lookups: u64,
    /// Lookups that resulted in [`ID_NONE`] (unmapped IDs).
    pub misses: u64,
}

impl MntIdMapStats {
    /// Construct zeroed stats.
    pub const fn new() -> Self {
        Self {
            mappings_created: 0,
            lookups: 0,
            reverse_lookups: 0,
            misses: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_map() -> (MntIdMapRegistry, u32) {
        let mut reg = MntIdMapRegistry::new();
        let id = reg.create_idmap().unwrap();
        reg.add_uid_mapping(id, IdMapEntry::new(1000, 0, 1000))
            .unwrap();
        reg.add_gid_mapping(id, IdMapEntry::new(1000, 0, 1000))
            .unwrap();
        (reg, id)
    }

    #[test]
    fn uid_forward_mapping() {
        let (mut reg, id) = registry_with_map();
        let ns = reg.map_id_to_ns(id, IdMapType::Uid, 1042).unwrap();
        assert_eq!(ns, 42);
    }

    #[test]
    fn uid_reverse_mapping() {
        let (mut reg, id) = registry_with_map();
        let host = reg.map_id_from_ns(id, IdMapType::Uid, 42).unwrap();
        assert_eq!(host, 1042);
    }

    #[test]
    fn unmapped_id_returns_none() {
        let (mut reg, id) = registry_with_map();
        let ns = reg.map_id_to_ns(id, IdMapType::Uid, 500).unwrap();
        assert_eq!(ns, ID_NONE);
        assert_eq!(reg.stats().misses, 1);
    }

    #[test]
    fn apply_to_mount_prevents_double() {
        let (mut reg, id) = registry_with_map();
        reg.apply_to_mount(0, id).unwrap();
        assert!(reg.apply_to_mount(0, id).is_err());
    }

    #[test]
    fn identity_when_no_idmap() {
        let mut reg = MntIdMapRegistry::new();
        let result = map_id_to_ns(&mut reg, 3, IdMapType::Uid, 500).unwrap();
        assert_eq!(result, 500); // identity
    }

    #[test]
    fn overlap_rejected() {
        let mut reg = MntIdMapRegistry::new();
        let id = reg.create_idmap().unwrap();
        reg.add_uid_mapping(id, IdMapEntry::new(0, 0, 100)).unwrap();
        // Overlapping range in host space.
        assert!(
            reg.add_uid_mapping(id, IdMapEntry::new(50, 200, 100))
                .is_err()
        );
    }

    #[test]
    fn active_map_immutable() {
        let (mut reg, id) = registry_with_map();
        reg.apply_to_mount(1, id).unwrap();
        // After activation, adding entries must fail with Busy.
        let result = reg.add_uid_mapping(id, IdMapEntry::new(2000, 1000, 10));
        assert!(result.is_err());
    }
}

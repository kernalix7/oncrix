// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS ID mapping — name ↔ UID/GID translation.
//!
//! NFSv4 represents file owners and groups as domain-qualified strings of the
//! form `user@domain` or `group@domain`. This module translates between those
//! strings and the kernel's numeric `uid_t`/`gid_t` values, mirroring the
//! logic in `fs/nfs/nfs4idmap.c`.
//!
//! # Cache design
//!
//! Translations are cached with a configurable TTL to amortise the cost of
//! upcalls to the userspace `rpc.idmapd` daemon. Both positive and negative
//! cache entries are stored in separate fixed-size tables.
//!
//! # Upcall mechanism
//!
//! When a name is not in the cache the module enqueues an [`UpcallRequest`]
//! representing the pending lookup. In a full system this would be delivered
//! to `rpc.idmapd` via a `request-key` channel; here the queue is exposed for
//! the caller to drain.
//!
//! # References
//!
//! - Linux `fs/nfs/nfs4idmap.c`
//! - RFC 7530 §5.9 — NFSv4 String Representation of Users and Groups

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum length of a domain-qualified name (e.g. `user@domain`).
pub const IDMAP_NAME_MAX: usize = 128;

/// Maximum number of positive cache entries.
pub const IDMAP_CACHE_SIZE: usize = 256;

/// Maximum number of negative cache entries.
pub const IDMAP_NEG_CACHE_SIZE: usize = 64;

/// Default TTL for positive cache entries (seconds).
pub const IDMAP_CACHE_TTL: u64 = 600;

/// Default TTL for negative cache entries (seconds).
pub const IDMAP_NEG_TTL: u64 = 30;

/// Maximum number of pending upcall requests.
pub const IDMAP_UPCALL_QUEUE: usize = 32;

/// Sentinel UID/GID meaning "nobody".
pub const IDMAP_NOBODY_UID: u32 = 65534;

/// Sentinel UID/GID meaning "nogroup".
pub const IDMAP_NOBODY_GID: u32 = 65534;

// ── IdmapType ────────────────────────────────────────────────────────────────

/// Distinguishes between user and group lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdmapType {
    /// User (UID) mapping.
    #[default]
    User,
    /// Group (GID) mapping.
    Group,
}

// ── NameBuf ───────────────────────────────────────────────────────────────────

/// Fixed-size buffer holding a domain-qualified name.
#[derive(Clone, Copy)]
pub struct NameBuf {
    /// Raw bytes of the name (not NUL-terminated; use `len` to delimit).
    pub bytes: [u8; IDMAP_NAME_MAX],
    /// Number of valid bytes.
    pub len: usize,
}

impl Default for NameBuf {
    fn default() -> Self {
        Self {
            bytes: [0u8; IDMAP_NAME_MAX],
            len: 0,
        }
    }
}

impl core::fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NameBuf").field(&self.as_bytes()).finish()
    }
}

impl NameBuf {
    /// Creates a `NameBuf` from a byte slice.
    ///
    /// Returns [`Error::InvalidArgument`] if `src` is longer than
    /// [`IDMAP_NAME_MAX`].
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.len() > IDMAP_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = Self::default();
        buf.bytes[..src.len()].copy_from_slice(src);
        buf.len = src.len();
        Ok(buf)
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl PartialEq for NameBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for NameBuf {}

// ── IdmapCacheEntry ───────────────────────────────────────────────────────────

/// A positive cache entry mapping a name to a numeric ID.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdmapCacheEntry {
    /// Mapping type (user or group).
    pub idmap_type: IdmapType,
    /// Domain-qualified name.
    pub name: NameBuf,
    /// Resolved numeric ID (UID or GID).
    pub id: u32,
    /// Monotonic timestamp when this entry was inserted (seconds since boot).
    pub inserted_at: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl IdmapCacheEntry {
    /// Returns `true` if the entry has expired given `now` (seconds since boot).
    pub const fn is_expired(&self, now: u64, ttl: u64) -> bool {
        now.saturating_sub(self.inserted_at) >= ttl
    }
}

// ── IdmapNegEntry ────────────────────────────────────────────────────────────

/// A negative cache entry recording that a name could not be resolved.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdmapNegEntry {
    /// Mapping type (user or group).
    pub idmap_type: IdmapType,
    /// The name that failed to resolve.
    pub name: NameBuf,
    /// Monotonic timestamp of the failed lookup.
    pub inserted_at: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

// ── UpcallRequest ─────────────────────────────────────────────────────────────

/// A pending upcall request to be delivered to the userspace idmapd daemon.
#[derive(Debug, Clone, Copy, Default)]
pub struct UpcallRequest {
    /// What kind of mapping is requested.
    pub idmap_type: IdmapType,
    /// Direction: `true` = name→id, `false` = id→name.
    pub name_to_id: bool,
    /// Name to resolve (valid when `name_to_id == true`).
    pub name: NameBuf,
    /// Numeric ID to resolve (valid when `name_to_id == false`).
    pub id: u32,
    /// Sequence number used to match responses.
    pub seq: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

// ── IdmapDomain ──────────────────────────────────────────────────────────────

/// NFS ID mapping domain — manages the cache and upcall queue for one NFS
/// mount's identity namespace.
pub struct IdmapDomain {
    /// Domain string (e.g. `localdomain`).
    domain: NameBuf,
    /// Positive cache entries.
    cache: [IdmapCacheEntry; IDMAP_CACHE_SIZE],
    /// Number of active positive entries.
    cache_count: usize,
    /// Negative cache entries.
    neg_cache: [IdmapNegEntry; IDMAP_NEG_CACHE_SIZE],
    /// Number of active negative entries.
    neg_count: usize,
    /// Pending upcall queue.
    upcalls: [UpcallRequest; IDMAP_UPCALL_QUEUE],
    /// Number of pending upcalls.
    upcall_count: usize,
    /// Next upcall sequence number.
    next_seq: u32,
    /// Positive entry TTL (seconds).
    pub ttl: u64,
    /// Negative entry TTL (seconds).
    pub neg_ttl: u64,
}

impl Default for IdmapDomain {
    fn default() -> Self {
        Self {
            domain: NameBuf::default(),
            cache: [IdmapCacheEntry::default(); IDMAP_CACHE_SIZE],
            cache_count: 0,
            neg_cache: [IdmapNegEntry::default(); IDMAP_NEG_CACHE_SIZE],
            neg_count: 0,
            upcalls: [UpcallRequest::default(); IDMAP_UPCALL_QUEUE],
            upcall_count: 0,
            next_seq: 1,
            ttl: IDMAP_CACHE_TTL,
            neg_ttl: IDMAP_NEG_TTL,
        }
    }
}

impl IdmapDomain {
    /// Creates a new domain with the given domain string.
    pub fn new(domain: &[u8]) -> Result<Self> {
        Ok(Self {
            domain: NameBuf::from_bytes(domain)?,
            ..Self::default()
        })
    }

    /// Returns the domain string.
    pub fn domain(&self) -> &[u8] {
        self.domain.as_bytes()
    }

    // ── Positive cache ────────────────────────────────────────────────────────

    /// Looks up a name in the positive cache.
    ///
    /// Returns the numeric ID if found and not expired, [`Error::NotFound`]
    /// otherwise.
    pub fn lookup_name(&self, idmap_type: IdmapType, name: &[u8], now: u64) -> Result<u32> {
        let name_buf = NameBuf::from_bytes(name)?;
        for e in &self.cache[..self.cache_count] {
            if e.active
                && e.idmap_type == idmap_type
                && e.name == name_buf
                && !e.is_expired(now, self.ttl)
            {
                return Ok(e.id);
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a numeric ID in the positive cache, returning the name.
    pub fn lookup_id<'a>(&'a self, idmap_type: IdmapType, id: u32, now: u64) -> Result<&'a [u8]> {
        for e in &self.cache[..self.cache_count] {
            if e.active && e.idmap_type == idmap_type && e.id == id && !e.is_expired(now, self.ttl)
            {
                return Ok(e.name.as_bytes());
            }
        }
        Err(Error::NotFound)
    }

    /// Inserts a positive mapping into the cache.
    ///
    /// If a matching entry already exists it is refreshed. Returns
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, idmap_type: IdmapType, name: &[u8], id: u32, now: u64) -> Result<()> {
        let name_buf = NameBuf::from_bytes(name)?;
        // Update existing entry.
        for e in &mut self.cache[..self.cache_count] {
            if e.active && e.idmap_type == idmap_type && e.name == name_buf {
                e.id = id;
                e.inserted_at = now;
                return Ok(());
            }
        }
        // Evict one expired entry if the table is full.
        if self.cache_count >= IDMAP_CACHE_SIZE {
            self.evict_expired(now);
        }
        if self.cache_count >= IDMAP_CACHE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.cache[self.cache_count] = IdmapCacheEntry {
            idmap_type,
            name: name_buf,
            id,
            inserted_at: now,
            active: true,
        };
        self.cache_count += 1;
        Ok(())
    }

    // ── Negative cache ────────────────────────────────────────────────────────

    /// Checks whether a name has a live negative cache entry.
    ///
    /// Returns `true` if the name was recently looked up and found to not exist.
    pub fn is_negative(&self, idmap_type: IdmapType, name: &[u8], now: u64) -> bool {
        let Ok(name_buf) = NameBuf::from_bytes(name) else {
            return false;
        };
        self.neg_cache[..self.neg_count].iter().any(|e| {
            e.active
                && e.idmap_type == idmap_type
                && e.name == name_buf
                && now.saturating_sub(e.inserted_at) < self.neg_ttl
        })
    }

    /// Inserts a negative cache entry for a name that could not be resolved.
    pub fn insert_negative(&mut self, idmap_type: IdmapType, name: &[u8], now: u64) -> Result<()> {
        let name_buf = NameBuf::from_bytes(name)?;
        // Refresh if already present.
        for e in &mut self.neg_cache[..self.neg_count] {
            if e.active && e.idmap_type == idmap_type && e.name == name_buf {
                e.inserted_at = now;
                return Ok(());
            }
        }
        if self.neg_count >= IDMAP_NEG_CACHE_SIZE {
            // Evict the oldest negative entry.
            let pos = self.neg_cache[..self.neg_count]
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.neg_cache[pos] = IdmapNegEntry {
                idmap_type,
                name: name_buf,
                inserted_at: now,
                active: true,
            };
            return Ok(());
        }
        self.neg_cache[self.neg_count] = IdmapNegEntry {
            idmap_type,
            name: name_buf,
            inserted_at: now,
            active: true,
        };
        self.neg_count += 1;
        Ok(())
    }

    // ── Upcall mechanism ──────────────────────────────────────────────────────

    /// Enqueues an upcall request for a name→id lookup.
    ///
    /// Returns the sequence number that the daemon must echo in its reply.
    pub fn enqueue_name_upcall(&mut self, idmap_type: IdmapType, name: &[u8]) -> Result<u32> {
        if self.upcall_count >= IDMAP_UPCALL_QUEUE {
            return Err(Error::Busy);
        }
        let name_buf = NameBuf::from_bytes(name)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.upcalls[self.upcall_count] = UpcallRequest {
            idmap_type,
            name_to_id: true,
            name: name_buf,
            id: 0,
            seq,
            active: true,
        };
        self.upcall_count += 1;
        Ok(seq)
    }

    /// Enqueues an upcall request for an id→name lookup.
    pub fn enqueue_id_upcall(&mut self, idmap_type: IdmapType, id: u32) -> Result<u32> {
        if self.upcall_count >= IDMAP_UPCALL_QUEUE {
            return Err(Error::Busy);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.upcalls[self.upcall_count] = UpcallRequest {
            idmap_type,
            name_to_id: false,
            name: NameBuf::default(),
            id,
            seq,
            active: true,
        };
        self.upcall_count += 1;
        Ok(seq)
    }

    /// Dequeues the next pending upcall request.
    pub fn dequeue_upcall(&mut self) -> Option<UpcallRequest> {
        if self.upcall_count == 0 {
            return None;
        }
        let req = self.upcalls[0];
        // Shift remaining entries.
        for i in 0..self.upcall_count - 1 {
            self.upcalls[i] = self.upcalls[i + 1];
        }
        self.upcall_count -= 1;
        Some(req)
    }

    /// Handles a successful reply from the idmapd daemon.
    ///
    /// Inserts the mapping into the positive cache and removes any matching
    /// negative entry.
    pub fn handle_reply(
        &mut self,
        idmap_type: IdmapType,
        name: &[u8],
        id: u32,
        now: u64,
    ) -> Result<()> {
        // Remove stale negative entry.
        if let Ok(name_buf) = NameBuf::from_bytes(name) {
            for e in &mut self.neg_cache[..self.neg_count] {
                if e.active && e.idmap_type == idmap_type && e.name == name_buf {
                    e.active = false;
                }
            }
        }
        self.insert(idmap_type, name, id, now)
    }

    /// Translates a name to a numeric ID, falling back to the "nobody" sentinel
    /// on lookup failure without enqueuing a new upcall.
    pub fn name_to_id_nowait(&self, idmap_type: IdmapType, name: &[u8], now: u64) -> u32 {
        self.lookup_name(idmap_type, name, now)
            .unwrap_or(match idmap_type {
                IdmapType::User => IDMAP_NOBODY_UID,
                IdmapType::Group => IDMAP_NOBODY_GID,
            })
    }

    /// Returns the number of active positive cache entries.
    pub const fn cache_len(&self) -> usize {
        self.cache_count
    }

    /// Returns the number of pending upcalls.
    pub const fn pending_upcalls(&self) -> usize {
        self.upcall_count
    }

    // ── Private ───────────────────────────────────────────────────────────────

    /// Evicts all expired positive cache entries.
    fn evict_expired(&mut self, now: u64) {
        let ttl = self.ttl;
        let mut i = 0;
        while i < self.cache_count {
            if self.cache[i].is_expired(now, ttl) {
                self.cache[i] = self.cache[self.cache_count - 1];
                self.cache[self.cache_count - 1] = IdmapCacheEntry::default();
                self.cache_count -= 1;
            } else {
                i += 1;
            }
        }
    }
}

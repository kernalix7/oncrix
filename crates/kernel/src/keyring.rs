// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel keyring for cryptographic key management.
//!
//! Provides an in-kernel key management facility inspired by
//! Linux's `add_key(2)`, `request_key(2)`, and `keyctl(2)`
//! system calls. Keys are stored in a fixed-size registry and
//! can be organized into keyrings for per-thread, per-process,
//! or per-session grouping.
//!
//! # Architecture
//!
//! ```text
//!  syscall layer
//!       │
//!       ▼
//!  KeyringRegistry
//!   ├── keys: [Key; 128]
//!   └── keyrings: [Keyring; 32]
//!         └── keys: [u32; 32]  (linked key IDs)
//! ```
//!
//! Reference: Linux `security/keys/`, `include/linux/key.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of keys the registry can hold.
const MAX_KEYS: usize = 128;

/// Maximum number of keyrings the registry can hold.
const MAX_KEYRINGS: usize = 32;

/// Maximum size in bytes for key payload data.
const MAX_KEY_DATA: usize = 256;

/// Maximum length in bytes for a key description.
const MAX_KEY_DESC: usize = 64;

/// Maximum number of keys linked into a single keyring.
const _MAX_KEYRING_KEYS: usize = 32;

/// Maximum length in bytes for a keyring name.
const _MAX_KEYRING_NAME: usize = 32;

/// Maximum keyring-link traversal depth when checking for cycles.
///
/// SECURITY: A crafted keyring graph that contains a cycle (keyring A links
/// keyring B which links A) would otherwise let a reachability walk loop
/// forever in ring 0 (a hard hang, since the kernel cannot be preempted out of
/// it). Every keyring traversal is bounded by this depth so a pre-existing or
/// attacker-induced cycle terminates the walk instead of hanging the machine.
const MAX_KEYRING_DEPTH: usize = MAX_KEYRINGS;

/// Special key ID: thread-specific keyring.
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;

/// Special key ID: process-specific keyring.
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;

/// Special key ID: session keyring.
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;

// -----------------------------------------------------------------------
// Permission bit constants
// -----------------------------------------------------------------------

/// Permission bit: view key attributes.
pub const KEY_POS_VIEW: u8 = 0x01;

/// Permission bit: read key payload.
pub const KEY_POS_READ: u8 = 0x02;

/// Permission bit: write (update) key payload.
pub const KEY_POS_WRITE: u8 = 0x04;

/// Permission bit: search for the key.
pub const KEY_POS_SEARCH: u8 = 0x08;

/// Permission bit: link the key into a keyring.
pub const KEY_POS_LINK: u8 = 0x10;

/// Permission bit: set key attributes (permission mask, expiry, revoke).
///
/// SECURITY: Mirrors Linux `KEY_OTH_SETATTR`. Attribute-changing operations
/// (SETPERM, SET_TIMEOUT, REVOKE) require this right (or key ownership) so a
/// caller cannot re-permission, retime, or revoke another principal's key.
pub const KEY_POS_SETATTR: u8 = 0x20;

// -----------------------------------------------------------------------
// KeyType
// -----------------------------------------------------------------------

/// The type of a key stored in the keyring.
///
/// Each type determines how the key payload is interpreted and
/// what operations are permitted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    /// A user-defined key with arbitrary payload.
    #[default]
    User,
    /// A logon key that cannot be read from user space.
    Logon,
    /// A keyring (a key that contains references to other keys).
    Keyring,
    /// A key whose payload exceeds the inline limit and is
    /// stored in a separate large buffer.
    BigKey,
    /// An encrypted key whose payload is sealed with a master
    /// key.
    Encrypted,
}

// -----------------------------------------------------------------------
// KeyPermission
// -----------------------------------------------------------------------

/// Permission mask for a key, split into four 8-bit roles.
///
/// The 32-bit permission value is laid out as:
/// `[possessor:8][user:8][group:8][other:8]`
///
/// Each role byte is a bitmask of `KEY_POS_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPermission {
    /// Permission bits for the key possessor.
    pub possessor: u8,
    /// Permission bits for the owning user.
    pub user: u8,
    /// Permission bits for the owning group.
    pub group: u8,
    /// Permission bits for all others.
    pub other: u8,
}

impl Default for KeyPermission {
    fn default() -> Self {
        Self::new(0)
    }
}

impl KeyPermission {
    /// Create a new permission mask from a packed 32-bit value.
    ///
    /// Bits 31..24 = possessor, 23..16 = user,
    /// 15..8 = group, 7..0 = other.
    pub const fn new(perm: u32) -> Self {
        Self {
            possessor: ((perm >> 24) & 0xFF) as u8,
            user: ((perm >> 16) & 0xFF) as u8,
            group: ((perm >> 8) & 0xFF) as u8,
            other: (perm & 0xFF) as u8,
        }
    }

    /// Pack the permission fields back into a 32-bit value.
    pub const fn to_u32(&self) -> u32 {
        ((self.possessor as u32) << 24)
            | ((self.user as u32) << 16)
            | ((self.group as u32) << 8)
            | (self.other as u32)
    }

    /// Check whether the given role byte grants read access.
    pub const fn can_read(&self, role: u8) -> bool {
        role & KEY_POS_READ != 0
    }

    /// Check whether the given role byte grants write access.
    pub const fn can_write(&self, role: u8) -> bool {
        role & KEY_POS_WRITE != 0
    }

    /// Check whether the given role byte grants search access.
    pub const fn can_search(&self, role: u8) -> bool {
        role & KEY_POS_SEARCH != 0
    }

    /// Check whether the given role byte grants link access.
    pub const fn can_link(&self, role: u8) -> bool {
        role & KEY_POS_LINK != 0
    }

    /// Check whether the given role byte grants set-attribute access.
    ///
    /// SECURITY: Used to gate the attribute-mutating keyctl ops (SETPERM,
    /// SET_TIMEOUT, REVOKE) for non-owners. Same role-byte shape as the other
    /// `can_*` checks so it composes with [`perm_allows`].
    pub const fn can_setattr(&self, role: u8) -> bool {
        role & KEY_POS_SETATTR != 0
    }
}

// -----------------------------------------------------------------------
// Key
// -----------------------------------------------------------------------

/// A single key in the kernel keyring.
///
/// Each key has a type, a human-readable description, a binary
/// payload, ownership metadata, permissions, and an optional
/// expiry time.
#[derive(Clone, Copy)]
pub struct Key {
    /// Unique key identifier (non-zero when active).
    pub id: u32,
    /// The type of this key.
    pub key_type: KeyType,
    /// Human-readable description (UTF-8 bytes, not
    /// null-terminated).
    pub description: [u8; MAX_KEY_DESC],
    /// Number of valid bytes in `description`.
    pub desc_len: usize,
    /// Binary key payload.
    pub data: [u8; MAX_KEY_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Permission mask.
    pub perm: KeyPermission,
    /// Expiry time in nanoseconds since boot (0 = no expiry).
    pub expiry_ns: u64,
    /// Whether this key slot is in use.
    pub active: bool,
    /// Whether this key has been revoked.
    pub revoked: bool,
}

impl Key {
    /// Create a new empty (inactive) key.
    const fn empty() -> Self {
        Self {
            id: 0,
            key_type: KeyType::User,
            description: [0u8; MAX_KEY_DESC],
            desc_len: 0,
            data: [0u8; MAX_KEY_DATA],
            data_len: 0,
            uid: 0,
            gid: 0,
            perm: KeyPermission::new(0),
            expiry_ns: 0,
            active: false,
            revoked: false,
        }
    }
}

// -----------------------------------------------------------------------
// Keyring
// -----------------------------------------------------------------------

/// A keyring that groups keys by ownership or scope.
///
/// Keyrings hold up to 32 key IDs and are associated with a
/// specific process (by PID). Thread and session keyrings are
/// identified by the `KEY_SPEC_*` constants.
#[derive(Clone, Copy)]
pub struct Keyring {
    /// Unique keyring identifier.
    pub id: u32,
    /// Human-readable name.
    pub name: [u8; 32],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Key IDs linked into this keyring.
    pub keys: [u32; 32],
    /// Number of keys currently linked.
    pub key_count: usize,
    /// PID of the owning process.
    pub owner_pid: u64,
    /// Whether this keyring slot is in use.
    pub active: bool,
}

impl Keyring {
    /// Create an empty (inactive) keyring.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; 32],
            name_len: 0,
            keys: [0u32; 32],
            key_count: 0,
            owner_pid: 0,
            active: false,
        }
    }
}

// -----------------------------------------------------------------------
// KeyringRegistry
// -----------------------------------------------------------------------

/// Central registry for all keys and keyrings in the kernel.
///
/// Provides the backing store for `add_key`, `request_key`, and
/// `keyctl` operations. All slots are statically allocated to
/// avoid heap usage in the kernel.
pub struct KeyringRegistry {
    /// Key storage slots.
    keys: [Key; MAX_KEYS],
    /// Keyring storage slots.
    keyrings: [Keyring; MAX_KEYRINGS],
    /// Next key ID to allocate.
    next_key_id: u32,
    /// Next keyring ID to allocate.
    next_ring_id: u32,
    /// Number of active keys.
    key_count: usize,
    /// Number of active keyrings.
    ring_count: usize,
}

impl Default for KeyringRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringRegistry {
    /// Create a new, empty keyring registry.
    pub const fn new() -> Self {
        Self {
            keys: [Key::empty(); MAX_KEYS],
            keyrings: [Keyring::empty(); MAX_KEYRINGS],
            next_key_id: 1,
            next_ring_id: 1,
            key_count: 0,
            ring_count: 0,
        }
    }

    /// Add a new key to the registry.
    ///
    /// Returns the allocated key ID on success, or
    /// `Err(Error::OutOfMemory)` if the registry is full, or
    /// `Err(Error::InvalidArgument)` if the description or data
    /// exceeds the maximum size.
    pub fn add_key(
        &mut self,
        key_type: KeyType,
        desc: &[u8],
        data: &[u8],
        uid: u32,
    ) -> Result<u32> {
        if desc.is_empty() || desc.len() > MAX_KEY_DESC {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_KEY_DATA {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_key_slot().ok_or(Error::OutOfMemory)?;

        let id = self.next_key_id;
        self.next_key_id = self.next_key_id.wrapping_add(1);

        let key = &mut self.keys[slot];
        key.id = id;
        key.key_type = key_type;
        key.description[..desc.len()].copy_from_slice(desc);
        key.desc_len = desc.len();
        key.data[..data.len()].copy_from_slice(data);
        key.data_len = data.len();
        key.uid = uid;
        key.gid = 0;
        key.perm = KeyPermission::new(0x1F1F_0000);
        key.expiry_ns = 0;
        key.active = true;
        key.revoked = false;

        self.key_count = self.key_count.saturating_add(1);
        Ok(id)
    }

    /// Returns `true` if a key is currently inaccessible because it is
    /// revoked or its expiry time has passed.
    ///
    /// Expiry is enforced here (in addition to the lazy [`expire_keys`] sweep)
    /// so that an expired-but-not-yet-swept key is never read or returned by a
    /// search.
    fn is_inaccessible(key: &Key, now_ns: u64) -> bool {
        key.revoked || (key.expiry_ns > 0 && key.expiry_ns <= now_ns)
    }

    /// Select the effective permission role byte for `caller_uid` against a
    /// key, then test it with `check`.
    ///
    /// The possessor and group roles require a per-process possessed-keyring
    /// set and group list that this registry does not currently track, so only
    /// the `user` (owner-uid match) and `other` roles are evaluated. Because
    /// the possessor/group bits can only *add* rights in the real model,
    /// omitting them is fail-closed: access is never granted where the full
    /// check would deny it.
    fn perm_allows(key: &Key, caller_uid: u32, check: fn(&KeyPermission, u8) -> bool) -> bool {
        let role = if key.uid == caller_uid {
            key.perm.user
        } else {
            key.perm.other
        };
        check(&key.perm, role)
    }

    /// Search for a key by type and description.
    ///
    /// Only keys that are accessible (not revoked, not expired) and that grant
    /// `KEY_POS_SEARCH` to `caller_uid` are matched. Returns the key ID of the
    /// first such key, or `Err(Error::NotFound)`.
    pub fn request_key(
        &self,
        key_type: KeyType,
        desc: &[u8],
        caller_uid: u32,
        now_ns: u64,
    ) -> Result<u32> {
        let mut i = 0;
        while i < MAX_KEYS {
            let key = &self.keys[i];
            if key.active
                && !Self::is_inaccessible(key, now_ns)
                && key.key_type == key_type
                && key.desc_len == desc.len()
                && key.description[..key.desc_len] == *desc
                && Self::perm_allows(key, caller_uid, KeyPermission::can_search)
            {
                return Ok(key.id);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Read the payload of a key into `buf`.
    ///
    /// Enforces, in order: the key exists; it is not revoked or expired
    /// (`now_ns`); its type is readable from user space (`Logon` and
    /// `Encrypted` payloads are never returned); and `caller_uid` is granted
    /// `KEY_POS_READ`.
    ///
    /// Returns the number of bytes copied, `Err(Error::NotFound)` if the key
    /// does not exist, or `Err(Error::PermissionDenied)` if any check fails.
    pub fn read_key(&self, id: u32, buf: &mut [u8], caller_uid: u32, now_ns: u64) -> Result<usize> {
        let key = self.find_key(id)?;
        if Self::is_inaccessible(key, now_ns) {
            return Err(Error::PermissionDenied);
        }
        // Logon and Encrypted key payloads must never be read from user space.
        if matches!(key.key_type, KeyType::Logon | KeyType::Encrypted) {
            return Err(Error::PermissionDenied);
        }
        if !Self::perm_allows(key, caller_uid, KeyPermission::can_read) {
            return Err(Error::PermissionDenied);
        }
        let copy_len = buf.len().min(key.data_len);
        buf[..copy_len].copy_from_slice(&key.data[..copy_len]);
        Ok(copy_len)
    }

    /// Update the payload of an existing key.
    ///
    /// Enforces the data-size limit, that the key is not revoked or expired,
    /// and that `caller_uid` is granted `KEY_POS_WRITE`.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the data exceeds the maximum
    /// size, or `Err(Error::PermissionDenied)` if the key is inaccessible or
    /// the caller lacks write permission.
    pub fn update_key(&mut self, id: u32, data: &[u8], caller_uid: u32, now_ns: u64) -> Result<()> {
        if data.len() > MAX_KEY_DATA {
            return Err(Error::InvalidArgument);
        }
        let key = self.find_key_mut(id)?;
        if Self::is_inaccessible(key, now_ns) {
            return Err(Error::PermissionDenied);
        }
        if !Self::perm_allows(key, caller_uid, KeyPermission::can_write) {
            return Err(Error::PermissionDenied);
        }
        key.data[..data.len()].copy_from_slice(data);
        key.data_len = data.len();
        Ok(())
    }

    /// Revoke a key, making it inaccessible for read/write.
    ///
    /// Revoked keys remain in the registry until explicitly
    /// unlinked.
    ///
    /// SECURITY INVARIANT: `caller_uid` MUST be the authenticated UID of the
    /// calling principal (the keyctl dispatcher in `crates/syscall` is
    /// responsible for resolving it from current credentials). Revocation is a
    /// destructive mutation, so it is gated on the same authority as any other
    /// attribute change: the caller must own the key (`key.uid == caller_uid`)
    /// or hold `KEY_POS_SETATTR` on it, otherwise `Error::PermissionDenied` is
    /// returned. Without this gate any caller could revoke another principal's
    /// key (denial of service against that key).
    pub fn revoke_key(&mut self, id: u32, caller_uid: u32) -> Result<()> {
        let key = self.find_key_mut(id)?;
        // SECURITY: ownership OR set-attribute right required to revoke.
        if key.uid != caller_uid && !Self::perm_allows(key, caller_uid, KeyPermission::can_setattr)
        {
            return Err(Error::PermissionDenied);
        }
        key.revoked = true;
        Ok(())
    }

    /// Remove a key from the registry entirely.
    ///
    /// The slot is freed and the key count decremented.
    ///
    /// SECURITY INVARIANT: `caller_uid` MUST be the authenticated UID of the
    /// calling principal (resolved by the keyctl dispatcher). Destroying a key
    /// is gated on the same authority as any other mutation: the caller must
    /// own the key (`key.uid == caller_uid`) or hold `KEY_POS_WRITE` on it,
    /// otherwise `Error::PermissionDenied` is returned. Without this gate any
    /// caller could delete another principal's key.
    pub fn unlink_key(&mut self, id: u32, caller_uid: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_KEYS {
            if self.keys[i].active && self.keys[i].id == id {
                // SECURITY: authorize against the matched key BEFORE freeing it.
                // Ownership OR write right is required to remove a key.
                let key = &self.keys[i];
                if key.uid != caller_uid
                    && !Self::perm_allows(key, caller_uid, KeyPermission::can_write)
                {
                    return Err(Error::PermissionDenied);
                }
                self.keys[i] = Key::empty();
                self.key_count = self.key_count.saturating_sub(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Set the permission mask on a key.
    ///
    /// SECURITY INVARIANT: `caller_uid` MUST be the authenticated UID of the
    /// calling principal (resolved by the keyctl dispatcher). Mirroring Linux,
    /// where only the key owner (or `CAP_SYS_ADMIN`) may `keyctl setperm`, the
    /// caller must own the key (`key.uid == caller_uid`) or hold
    /// `KEY_POS_SETATTR` on it. Otherwise `Error::PermissionDenied` is
    /// returned. Without this gate any caller could rewrite another principal's
    /// permission mask and grant itself read/write/link rights it was never
    /// given (privilege escalation).
    pub fn set_key_perm(&mut self, id: u32, perm: u32, caller_uid: u32) -> Result<()> {
        let key = self.find_key_mut(id)?;
        // SECURITY: ownership OR set-attribute right required to re-permission.
        // Checked BEFORE writing the new mask so the operation cannot be used
        // to bootstrap rights the caller does not already hold.
        if key.uid != caller_uid && !Self::perm_allows(key, caller_uid, KeyPermission::can_setattr)
        {
            return Err(Error::PermissionDenied);
        }
        key.perm = KeyPermission::new(perm);
        Ok(())
    }

    /// Set (or clear) the expiry time on a key.
    ///
    /// Pass `0` for `expiry_ns` to remove the expiry.
    ///
    /// SECURITY INVARIANT: `caller_uid` MUST be the authenticated UID of the
    /// calling principal (resolved by the keyctl `SET_TIMEOUT` dispatcher).
    /// Changing the expiry is an attribute mutation, so the caller must own the
    /// key (`key.uid == caller_uid`) or hold `KEY_POS_SETATTR` on it; otherwise
    /// `Error::PermissionDenied` is returned. Without this gate any caller
    /// could clear another principal's expiry (keeping a key alive past its
    /// intended lifetime) or force-expire it (denial of service).
    pub fn set_key_expiry(&mut self, id: u32, expiry_ns: u64, caller_uid: u32) -> Result<()> {
        let key = self.find_key_mut(id)?;
        // SECURITY: ownership OR set-attribute right required to retime a key.
        if key.uid != caller_uid && !Self::perm_allows(key, caller_uid, KeyPermission::can_setattr)
        {
            return Err(Error::PermissionDenied);
        }
        key.expiry_ns = expiry_ns;
        Ok(())
    }

    /// Create a new keyring associated with a process.
    ///
    /// Returns the keyring ID on success, or
    /// `Err(Error::OutOfMemory)` if the keyring table is full.
    pub fn create_keyring(&mut self, name: &[u8], pid: u64) -> Result<u32> {
        if name.is_empty() || name.len() > 32 {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_ring_slot().ok_or(Error::OutOfMemory)?;

        let id = self.next_ring_id;
        self.next_ring_id = self.next_ring_id.wrapping_add(1);

        let ring = &mut self.keyrings[slot];
        ring.id = id;
        ring.name[..name.len()].copy_from_slice(name);
        ring.name_len = name.len();
        ring.keys = [0u32; 32];
        ring.key_count = 0;
        ring.owner_pid = pid;
        ring.active = true;

        self.ring_count = self.ring_count.saturating_add(1);
        Ok(id)
    }

    /// Link a key into a keyring.
    ///
    /// Requires the key to grant `KEY_POS_LINK` to `caller_uid`.
    ///
    /// SECURITY: A keyring may not be linked into itself, and linking one
    /// keyring into another may not create a cycle in the keyring graph; both
    /// are rejected with `Error::InvalidArgument` because a cycle would let a
    /// later keyring walk loop forever in ring 0.
    ///
    /// Returns `Err(Error::InvalidArgument)` for a self-link or a cycle-forming
    /// link, `Err(Error::NotFound)` if either the key or keyring does not
    /// exist, `Err(Error::PermissionDenied)` if the caller lacks link
    /// permission, `Err(Error::AlreadyExists)` if the key is already linked, or
    /// `Err(Error::OutOfMemory)` if the keyring is full.
    pub fn link_to_keyring(&mut self, key_id: u32, ring_id: u32, caller_uid: u32) -> Result<()> {
        // SECURITY: Reject a keyring self-link outright. Linking a keyring into
        // itself is the smallest possible cycle and would make any later
        // traversal of `ring_id` loop forever in ring 0.
        if key_id == ring_id {
            return Err(Error::InvalidArgument);
        }

        // Verify the key exists and grants link permission to the caller.
        let key = self.find_key(key_id)?;
        if !Self::perm_allows(key, caller_uid, KeyPermission::can_link) {
            return Err(Error::PermissionDenied);
        }

        // SECURITY: If the object being linked is itself a keyring, linking it
        // into `ring_id` must not create a cycle. A cycle (ring_id reachable
        // from key_id, which would then point back at ring_id) lets a later
        // walk of the keyring graph loop forever -> ring-0 hang. The walk below
        // is depth-bounded, so even a pre-existing cycle cannot hang here.
        if self.find_ring(key_id).is_ok()
            && self.keyring_reaches(key_id, ring_id, MAX_KEYRING_DEPTH)
        {
            return Err(Error::InvalidArgument);
        }

        let ring = self.find_ring_mut(ring_id)?;

        // Check for duplicate.
        let mut i = 0;
        while i < ring.key_count {
            if ring.keys[i] == key_id {
                return Err(Error::AlreadyExists);
            }
            i = i.saturating_add(1);
        }

        if ring.key_count >= 32 {
            return Err(Error::OutOfMemory);
        }

        ring.keys[ring.key_count] = key_id;
        ring.key_count = ring.key_count.saturating_add(1);
        Ok(())
    }

    /// Unlink a key from a keyring.
    ///
    /// SECURITY INVARIANT: `caller_uid` MUST be the authenticated UID of the
    /// calling principal (resolved by the keyctl dispatcher). This is the
    /// asymmetric counterpart to [`Self::link_to_keyring`] and is gated on the
    /// same authority: the caller must own the key (`key.uid == caller_uid`) or
    /// hold link permission on it. Without this gate any caller could unlink
    /// another principal's key from a keyring (membership denial-of-service). A
    /// stale link whose key no longer exists in the registry is treated as a
    /// harmless dangling entry and may be removed (cleanup only — no live key is
    /// affected), so the gate is enforced only when the key still exists.
    ///
    /// Returns `Err(Error::PermissionDenied)` if the caller lacks authority over
    /// a live key, or `Err(Error::NotFound)` if the keyring does not exist or the
    /// key is not linked in it.
    pub fn unlink_from_keyring(
        &mut self,
        key_id: u32,
        ring_id: u32,
        caller_uid: u32,
    ) -> Result<()> {
        // SECURITY: authorize against the key being unlinked BEFORE mutating the
        // keyring membership. The immutable borrow ends with this block, so the
        // subsequent `find_ring_mut` borrow does not conflict.
        if let Ok(key) = self.find_key(key_id) {
            if key.uid != caller_uid && !Self::perm_allows(key, caller_uid, KeyPermission::can_link)
            {
                return Err(Error::PermissionDenied);
            }
        }

        let ring = self.find_ring_mut(ring_id)?;

        let mut i = 0;
        while i < ring.key_count {
            if ring.keys[i] == key_id {
                // Shift remaining entries down.
                let mut j = i;
                while j + 1 < ring.key_count {
                    ring.keys[j] = ring.keys[j + 1];
                    j = j.saturating_add(1);
                }
                ring.key_count = ring.key_count.saturating_sub(1);
                ring.keys[ring.key_count] = 0;
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Revoke all keys whose expiry time has passed.
    ///
    /// Returns the number of keys that were revoked.
    pub fn expire_keys(&mut self, now_ns: u64) -> usize {
        let mut count: usize = 0;
        let mut i = 0;
        while i < MAX_KEYS {
            let key = &mut self.keys[i];
            if key.active && !key.revoked && key.expiry_ns > 0 && key.expiry_ns <= now_ns {
                key.revoked = true;
                count = count.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
        count
    }

    /// Return the number of active keys in the registry.
    pub fn len(&self) -> usize {
        self.key_count
    }

    /// Check whether the registry contains no active keys.
    pub fn is_empty(&self) -> bool {
        self.key_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find the first free key slot.
    fn find_free_key_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < MAX_KEYS {
            if !self.keys[i].active {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Find the first free keyring slot.
    fn find_free_ring_slot(&self) -> Option<usize> {
        let mut i = 0;
        while i < MAX_KEYRINGS {
            if !self.keyrings[i].active {
                return Some(i);
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Look up an active key by ID (immutable).
    fn find_key(&self, id: u32) -> Result<&Key> {
        let mut i = 0;
        while i < MAX_KEYS {
            if self.keys[i].active && self.keys[i].id == id {
                return Ok(&self.keys[i]);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Look up an active key by ID (mutable).
    fn find_key_mut(&mut self, id: u32) -> Result<&mut Key> {
        let mut i = 0;
        while i < MAX_KEYS {
            if self.keys[i].active && self.keys[i].id == id {
                return Ok(&mut self.keys[i]);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Look up an active keyring by ID (immutable).
    fn find_ring(&self, id: u32) -> Result<&Keyring> {
        let mut i = 0;
        while i < MAX_KEYRINGS {
            if self.keyrings[i].active && self.keyrings[i].id == id {
                return Ok(&self.keyrings[i]);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Look up an active keyring by ID (mutable).
    fn find_ring_mut(&mut self, id: u32) -> Result<&mut Keyring> {
        let mut i = 0;
        while i < MAX_KEYRINGS {
            if self.keyrings[i].active && self.keyrings[i].id == id {
                return Ok(&mut self.keyrings[i]);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Return `true` if `target` is reachable from keyring `start` by following
    /// keyring-to-keyring links, searching no deeper than `depth` levels.
    ///
    /// SECURITY: This is the cycle guard for [`link_to_keyring`]. The traversal
    /// is strictly bounded by `depth` (and by the fact that only the at most
    /// `MAX_KEYRINGS` distinct keyrings can ever be visited), so a keyring
    /// graph that already contains a cycle terminates the walk instead of
    /// spinning forever in ring 0. Non-keyring linked entries are leaves and
    /// are skipped. The walk is iterative (no recursion) to keep ring-0 stack
    /// use constant.
    fn keyring_reaches(&self, start: u32, target: u32, depth: usize) -> bool {
        // Breadth-first walk over a fixed-size frontier. `MAX_KEYRINGS` bounds
        // the number of distinct keyrings, so a queue of that size with a
        // per-id "seen" guard can never overflow or revisit a node.
        let mut queue = [0u32; MAX_KEYRINGS];
        let mut seen = [false; MAX_KEYRINGS];
        let mut head = 0usize;
        let mut tail = 0usize;

        queue[tail] = start;
        tail = tail.saturating_add(1);
        let mut steps = 0usize;

        while head < tail {
            // Hard cap on iterations: defence-in-depth against any indexing
            // mistake that could otherwise keep the loop alive.
            if steps >= depth.saturating_mul(MAX_KEYRINGS).saturating_add(1) {
                break;
            }
            steps = steps.saturating_add(1);

            let ring_id = queue[head];
            head = head.saturating_add(1);

            if ring_id == target {
                return true;
            }

            // Resolve the keyring slot; non-keyring or missing ids are leaves.
            let ring = match self.find_ring(ring_id) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Mark visited by slot index to avoid re-enqueueing a node in a
            // cycle. `find_ring` only returns active slots within bounds.
            let mut slot = 0usize;
            let mut already = false;
            while slot < MAX_KEYRINGS {
                if self.keyrings[slot].active && self.keyrings[slot].id == ring_id {
                    if seen[slot] {
                        already = true;
                    } else {
                        seen[slot] = true;
                    }
                    break;
                }
                slot = slot.saturating_add(1);
            }
            if already {
                continue;
            }

            // Enqueue child entries that are themselves keyrings.
            let mut k = 0usize;
            while k < ring.key_count && k < ring.keys.len() {
                let child = ring.keys[k];
                if child != 0 && self.find_ring(child).is_ok() && tail < MAX_KEYRINGS {
                    queue[tail] = child;
                    tail = tail.saturating_add(1);
                }
                k = k.saturating_add(1);
            }
        }
        false
    }
}

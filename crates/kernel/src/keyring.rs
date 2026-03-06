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

    /// Search for a key by type and description.
    ///
    /// Returns the key ID of the first matching active,
    /// non-revoked key, or `Err(Error::NotFound)`.
    pub fn request_key(&self, key_type: KeyType, desc: &[u8]) -> Result<u32> {
        let mut i = 0;
        while i < MAX_KEYS {
            let key = &self.keys[i];
            if key.active
                && !key.revoked
                && key.key_type == key_type
                && key.desc_len == desc.len()
                && key.description[..key.desc_len] == *desc
            {
                return Ok(key.id);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Read the payload of a key into `buf`.
    ///
    /// Returns the number of bytes copied, or
    /// `Err(Error::NotFound)` if the key does not exist, or
    /// `Err(Error::PermissionDenied)` if the key is revoked.
    pub fn read_key(&self, id: u32, buf: &mut [u8]) -> Result<usize> {
        let key = self.find_key(id)?;
        if key.revoked {
            return Err(Error::PermissionDenied);
        }
        let copy_len = buf.len().min(key.data_len);
        buf[..copy_len].copy_from_slice(&key.data[..copy_len]);
        Ok(copy_len)
    }

    /// Update the payload of an existing key.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the data exceeds
    /// the maximum size, or `Err(Error::PermissionDenied)` if the
    /// key is revoked.
    pub fn update_key(&mut self, id: u32, data: &[u8]) -> Result<()> {
        if data.len() > MAX_KEY_DATA {
            return Err(Error::InvalidArgument);
        }
        let key = self.find_key_mut(id)?;
        if key.revoked {
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
    pub fn revoke_key(&mut self, id: u32) -> Result<()> {
        let key = self.find_key_mut(id)?;
        key.revoked = true;
        Ok(())
    }

    /// Remove a key from the registry entirely.
    ///
    /// The slot is freed and the key count decremented.
    pub fn unlink_key(&mut self, id: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_KEYS {
            if self.keys[i].active && self.keys[i].id == id {
                self.keys[i] = Key::empty();
                self.key_count = self.key_count.saturating_sub(1);
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Set the permission mask on a key.
    pub fn set_key_perm(&mut self, id: u32, perm: u32) -> Result<()> {
        let key = self.find_key_mut(id)?;
        key.perm = KeyPermission::new(perm);
        Ok(())
    }

    /// Set (or clear) the expiry time on a key.
    ///
    /// Pass `0` for `expiry_ns` to remove the expiry.
    pub fn set_key_expiry(&mut self, id: u32, expiry_ns: u64) -> Result<()> {
        let key = self.find_key_mut(id)?;
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
    /// Returns `Err(Error::NotFound)` if either the key or
    /// keyring does not exist, `Err(Error::AlreadyExists)` if
    /// the key is already linked, or `Err(Error::OutOfMemory)`
    /// if the keyring is full.
    pub fn link_to_keyring(&mut self, key_id: u32, ring_id: u32) -> Result<()> {
        // Verify the key exists.
        let _ = self.find_key(key_id)?;

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
    /// Returns `Err(Error::NotFound)` if the keyring does not
    /// exist or the key is not linked in it.
    pub fn unlink_from_keyring(&mut self, key_id: u32, ring_id: u32) -> Result<()> {
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
}

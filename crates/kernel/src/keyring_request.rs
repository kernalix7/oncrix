// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Keyring request handling — key request and instantiation protocol.
//!
//! When a kernel subsystem needs a key that doesn't exist yet, it
//! submits a request.  The request can be satisfied by user-space
//! key managers (e.g., request-key) or by kernel-space key types.
//!
//! # Reference
//!
//! Linux `security/keys/request_key.c`, `include/linux/key.h`.

use oncrix_lib::{Error, Result};

const MAX_REQUESTS: usize = 128;
const MAX_CALLOUT_LEN: usize = 128;
const MAX_TYPE_LEN: usize = 32;
const MAX_DESC_LEN: usize = 64;

/// State of a key request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestState {
    /// Slot is free.
    Free = 0,
    /// Request is pending.
    Pending = 1,
    /// Request is being processed by user-space.
    InProgress = 2,
    /// Key was successfully instantiated.
    Fulfilled = 3,
    /// Request failed / timed out.
    Failed = 4,
}

/// Type of key being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    /// User-defined key.
    User = 0,
    /// Logon key (not readable by user-space).
    Logon = 1,
    /// Keyring (container of other keys).
    Keyring = 2,
    /// Asymmetric key (public/private).
    Asymmetric = 3,
    /// Encrypted key.
    Encrypted = 4,
    /// Trusted key (sealed by TPM).
    Trusted = 5,
}

impl KeyType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Logon => "logon",
            Self::Keyring => "keyring",
            Self::Asymmetric => "asymmetric",
            Self::Encrypted => "encrypted",
            Self::Trusted => "trusted",
        }
    }
}

/// A key request.
#[derive(Debug, Clone, Copy)]
pub struct KeyRequest {
    /// Request identifier.
    pub request_id: u64,
    /// Key type being requested.
    pub key_type: KeyType,
    /// Key type name.
    pub type_name: [u8; MAX_TYPE_LEN],
    /// Type name length.
    pub type_name_len: usize,
    /// Key description.
    pub description: [u8; MAX_DESC_LEN],
    /// Description length.
    pub desc_len: usize,
    /// Callout info (for user-space key manager).
    pub callout: [u8; MAX_CALLOUT_LEN],
    /// Callout length.
    pub callout_len: usize,
    /// Requesting PID.
    pub requester_pid: u64,
    /// Target keyring ID.
    pub dest_keyring_id: u64,
    /// Current state.
    pub state: RequestState,
    /// Resulting key ID (valid when Fulfilled).
    pub result_key_id: u64,
    /// Timestamp of request.
    pub timestamp: u64,
}

impl KeyRequest {
    const fn empty() -> Self {
        Self {
            request_id: 0,
            key_type: KeyType::User,
            type_name: [0u8; MAX_TYPE_LEN],
            type_name_len: 0,
            description: [0u8; MAX_DESC_LEN],
            desc_len: 0,
            callout: [0u8; MAX_CALLOUT_LEN],
            callout_len: 0,
            requester_pid: 0,
            dest_keyring_id: 0,
            state: RequestState::Free,
            result_key_id: 0,
            timestamp: 0,
        }
    }

    /// Returns `true` if the slot is in use.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, RequestState::Free)
    }
}

/// Statistics for key requests.
#[derive(Debug, Clone, Copy)]
pub struct KeyringRequestStats {
    /// Total requests submitted.
    pub total_requests: u64,
    /// Total requests fulfilled.
    pub total_fulfilled: u64,
    /// Total requests failed.
    pub total_failed: u64,
    /// Total requests timed out.
    pub total_timeouts: u64,
    /// Total requests currently pending.
    pub current_pending: u64,
}

impl KeyringRequestStats {
    const fn new() -> Self {
        Self {
            total_requests: 0,
            total_fulfilled: 0,
            total_failed: 0,
            total_timeouts: 0,
            current_pending: 0,
        }
    }
}

/// Top-level keyring request subsystem.
pub struct KeyringRequestManager {
    /// Active requests.
    requests: [KeyRequest; MAX_REQUESTS],
    /// Statistics.
    stats: KeyringRequestStats,
    /// Next request ID.
    next_request_id: u64,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for KeyringRequestManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringRequestManager {
    /// Create a new keyring request manager.
    pub const fn new() -> Self {
        Self {
            requests: [const { KeyRequest::empty() }; MAX_REQUESTS],
            stats: KeyringRequestStats::new(),
            next_request_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Submit a key request.
    pub fn request_key(
        &mut self,
        key_type: KeyType,
        description: &[u8],
        callout: &[u8],
        requester_pid: u64,
        dest_keyring_id: u64,
        timestamp: u64,
    ) -> Result<u64> {
        if description.is_empty() || description.len() > MAX_DESC_LEN {
            return Err(Error::InvalidArgument);
        }
        if callout.len() > MAX_CALLOUT_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .requests
            .iter()
            .position(|r| matches!(r.state, RequestState::Free))
            .ok_or(Error::OutOfMemory)?;

        let request_id = self.next_request_id;
        self.next_request_id += 1;

        let type_name = key_type.name().as_bytes();
        self.requests[slot] = KeyRequest::empty();
        self.requests[slot].request_id = request_id;
        self.requests[slot].key_type = key_type;
        let tn_len = type_name.len().min(MAX_TYPE_LEN);
        self.requests[slot].type_name[..tn_len].copy_from_slice(&type_name[..tn_len]);
        self.requests[slot].type_name_len = tn_len;
        self.requests[slot].description[..description.len()].copy_from_slice(description);
        self.requests[slot].desc_len = description.len();
        if !callout.is_empty() {
            self.requests[slot].callout[..callout.len()].copy_from_slice(callout);
            self.requests[slot].callout_len = callout.len();
        }
        self.requests[slot].requester_pid = requester_pid;
        self.requests[slot].dest_keyring_id = dest_keyring_id;
        self.requests[slot].state = RequestState::Pending;
        self.requests[slot].timestamp = timestamp;

        self.stats.total_requests += 1;
        self.stats.current_pending += 1;
        Ok(request_id)
    }

    /// Mark a request as in-progress.
    pub fn start_processing(&mut self, request_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        if !matches!(self.requests[slot].state, RequestState::Pending) {
            return Err(Error::InvalidArgument);
        }
        self.requests[slot].state = RequestState::InProgress;
        Ok(())
    }

    /// Fulfil a request with a key ID.
    pub fn fulfil(&mut self, request_id: u64, key_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        self.requests[slot].state = RequestState::Fulfilled;
        self.requests[slot].result_key_id = key_id;
        self.stats.total_fulfilled += 1;
        self.stats.current_pending = self.stats.current_pending.saturating_sub(1);
        Ok(())
    }

    /// Fail a request.
    pub fn fail(&mut self, request_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        self.requests[slot].state = RequestState::Failed;
        self.stats.total_failed += 1;
        self.stats.current_pending = self.stats.current_pending.saturating_sub(1);
        Ok(())
    }

    /// Release a completed/failed request.
    pub fn release(&mut self, request_id: u64) -> Result<()> {
        let slot = self.find_request(request_id)?;
        if matches!(
            self.requests[slot].state,
            RequestState::Pending | RequestState::InProgress
        ) {
            return Err(Error::Busy);
        }
        self.requests[slot] = KeyRequest::empty();
        Ok(())
    }

    /// Return a request.
    pub fn request(&self, request_id: u64) -> Result<&KeyRequest> {
        let slot = self.find_request_const(request_id)?;
        Ok(&self.requests[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> KeyringRequestStats {
        self.stats
    }

    /// Return the number of active requests.
    pub fn active_count(&self) -> usize {
        self.requests.iter().filter(|r| r.is_active()).count()
    }

    fn find_request(&self, request_id: u64) -> Result<usize> {
        self.requests
            .iter()
            .position(|r| r.is_active() && r.request_id == request_id)
            .ok_or(Error::NotFound)
    }

    fn find_request_const(&self, request_id: u64) -> Result<usize> {
        self.find_request(request_id)
    }
}

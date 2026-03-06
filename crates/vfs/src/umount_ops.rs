// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! umount and lazy umount operations.
//!
//! Implements `umount(2)` and `umount2(2)` which detach filesystems from the
//! directory hierarchy. Supports normal umount, lazy umount (MNT_DETACH),
//! forced umount (MNT_FORCE), and expire-based umount (MNT_EXPIRE).

use oncrix_lib::{Error, Result};

/// Flags for `umount2`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UmountFlags(pub u32);

impl UmountFlags {
    /// Force umount even if the filesystem is busy.
    pub const MNT_FORCE: u32 = 1;
    /// Lazy umount: detach immediately, clean up when no longer busy.
    pub const MNT_DETACH: u32 = 2;
    /// Mark mount as expired; umount only succeeds on second call.
    pub const MNT_EXPIRE: u32 = 4;
    /// Attempt to perform an UMOUNT_NOFOLLOW style operation.
    pub const UMOUNT_NOFOLLOW: u32 = 8;

    /// Create flags from a raw value.
    pub const fn from_raw(v: u32) -> Self {
        UmountFlags(v)
    }

    /// Check if force flag is set.
    pub fn is_force(self) -> bool {
        self.0 & Self::MNT_FORCE != 0
    }

    /// Check if lazy flag is set.
    pub fn is_lazy(self) -> bool {
        self.0 & Self::MNT_DETACH != 0
    }

    /// Check if expire flag is set.
    pub fn is_expire(self) -> bool {
        self.0 & Self::MNT_EXPIRE != 0
    }

    /// Validate that the flag combination is legal.
    pub fn is_valid(self) -> bool {
        // MNT_EXPIRE is incompatible with MNT_FORCE and MNT_DETACH.
        if self.is_expire() && (self.is_force() || self.is_lazy()) {
            return false;
        }
        // Unknown flags.
        if self.0 & !0xF != 0 {
            return false;
        }
        true
    }
}

/// Status of a mount with respect to busy-ness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountBusyStatus {
    /// No active references; can be unmounted normally.
    NotBusy,
    /// Has active file/directory references.
    Busy {
        /// Approximate number of active references.
        ref_count: u32,
    },
    /// Has mounted filesystems under it.
    HasChildren,
}

/// Result of an umount validation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UmountCheck {
    /// Can proceed with normal umount.
    CanUmount,
    /// Mount is busy but lazy umount is requested.
    LazyDetach,
    /// Mount is busy and no force/lazy flag was given.
    Blocked,
    /// Mount has children that must be unmounted first.
    HasChildren,
}

/// Check whether a mount can be unmounted.
pub fn check_umount(
    busy: MountBusyStatus,
    flags: UmountFlags,
    caller_privileged: bool,
) -> Result<UmountCheck> {
    if !caller_privileged {
        return Err(Error::PermissionDenied);
    }
    if !flags.is_valid() {
        return Err(Error::InvalidArgument);
    }
    match busy {
        MountBusyStatus::HasChildren => {
            if flags.is_lazy() {
                Ok(UmountCheck::LazyDetach)
            } else {
                Ok(UmountCheck::HasChildren)
            }
        }
        MountBusyStatus::Busy { .. } => {
            if flags.is_lazy() {
                Ok(UmountCheck::LazyDetach)
            } else if flags.is_force() {
                Ok(UmountCheck::CanUmount)
            } else {
                Ok(UmountCheck::Blocked)
            }
        }
        MountBusyStatus::NotBusy => Ok(UmountCheck::CanUmount),
    }
}

/// State machine for a lazy-detached mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LazyMountState {
    /// Still has active references; kept alive.
    Alive,
    /// All references dropped; ready for final cleanup.
    Ready,
    /// Cleanup complete.
    Done,
}

/// A lazily-unmounted mount record.
#[derive(Debug, Clone, Copy)]
pub struct LazyMount {
    /// Mount ID that was lazily detached.
    pub mount_id: u32,
    /// Current ref count.
    pub refs: u32,
    /// Current state.
    pub state: LazyMountState,
}

impl LazyMount {
    /// Create a new lazy mount record.
    pub const fn new(mount_id: u32, refs: u32) -> Self {
        LazyMount {
            mount_id,
            refs,
            state: LazyMountState::Alive,
        }
    }

    /// Decrement ref count; transition to Ready when it reaches zero.
    pub fn put_ref(&mut self) {
        self.refs = self.refs.saturating_sub(1);
        if self.refs == 0 {
            self.state = LazyMountState::Ready;
        }
    }

    /// Mark as fully cleaned up.
    pub fn mark_done(&mut self) {
        self.state = LazyMountState::Done;
    }
}

/// Queue of lazily-unmounted mounts awaiting final cleanup.
pub struct LazyUmountQueue {
    mounts: [Option<LazyMount>; 32],
    count: usize,
}

impl LazyUmountQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        LazyUmountQueue {
            mounts: [None; 32],
            count: 0,
        }
    }

    /// Add a lazily-unmounted mount to the queue.
    pub fn enqueue(&mut self, mount_id: u32, refs: u32) -> Result<()> {
        for slot in &mut self.mounts {
            if slot.is_none() {
                *slot = Some(LazyMount::new(mount_id, refs));
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Drop a reference on a queued mount.
    pub fn put_ref(&mut self, mount_id: u32) {
        for slot in &mut self.mounts {
            if let Some(m) = slot {
                if m.mount_id == mount_id {
                    m.put_ref();
                }
            }
        }
    }

    /// Process all mounts that are ready for final cleanup.
    ///
    /// Calls `cleanup` for each ready mount and removes it from the queue.
    pub fn process_ready(&mut self, cleanup: impl Fn(u32)) {
        for slot in &mut self.mounts {
            if let Some(m) = slot {
                if m.state == LazyMountState::Ready {
                    cleanup(m.mount_id);
                    m.mark_done();
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Return number of pending lazy unmounts.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for LazyUmountQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform an umount operation.
///
/// Returns the mount ID that was unmounted on success.
pub fn do_umount(
    mount_id: u32,
    busy: MountBusyStatus,
    flags: UmountFlags,
    privileged: bool,
    lazy_queue: &mut LazyUmountQueue,
) -> Result<u32> {
    let check = check_umount(busy, flags, privileged)?;
    match check {
        UmountCheck::CanUmount => Ok(mount_id),
        UmountCheck::LazyDetach => {
            let refs = match busy {
                MountBusyStatus::Busy { ref_count } => ref_count,
                _ => 1,
            };
            lazy_queue.enqueue(mount_id, refs)?;
            Ok(mount_id)
        }
        UmountCheck::Blocked => Err(Error::Busy),
        UmountCheck::HasChildren => Err(Error::Busy),
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Access-time update policies — noatime, relatime, strictatime.
//!
//! Implements the Linux atime update semantics as described in `mount(2)`:
//! - `strictatime`: always update atime on read (POSIX default)
//! - `noatime`: never update atime (maximum performance)
//! - `relatime`: update atime only if atime <= mtime or atime is older than
//!   a configurable threshold (typically 24 hours)
//! - `nodiratime`: like `noatime` for directories only

use oncrix_lib::{Error, Result};

/// Access-time update policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtimePolicy {
    /// Always update atime on read access (POSIX-compliant but slow).
    StrictAtime,
    /// Never update atime (best performance, not POSIX-compliant).
    NoAtime,
    /// Update atime only when it is stale relative to mtime or a time window.
    RelAtime,
    /// Skip atime updates for directories only.
    NoDirAtime,
}

impl Default for AtimePolicy {
    fn default() -> Self {
        AtimePolicy::RelAtime
    }
}

/// Relatime configuration parameters.
#[derive(Debug, Clone, Copy)]
pub struct RelAtimeConfig {
    /// Maximum age of an atime before it is always updated (seconds).
    ///
    /// Linux default: 86400 (24 hours).
    pub max_age_secs: u64,
}

impl Default for RelAtimeConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 86400,
        }
    }
}

/// Inode timestamps used for atime decision.
#[derive(Debug, Clone, Copy, Default)]
pub struct InodeTimes {
    /// Last access time (seconds since epoch).
    pub atime: i64,
    /// Last data modification time.
    pub mtime: i64,
    /// Last metadata-change time.
    pub ctime: i64,
    /// True if the inode represents a directory.
    pub is_dir: bool,
}

/// Decision result from the atime checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtimeDecision {
    /// The atime should be updated to `now`.
    Update,
    /// The atime should NOT be updated.
    Skip,
}

/// Evaluate whether the inode's atime should be updated given the policy.
///
/// `now` is the current wall-clock time in seconds since the Unix epoch.
pub fn should_update_atime(
    policy: AtimePolicy,
    cfg: &RelAtimeConfig,
    times: &InodeTimes,
    now: i64,
) -> AtimeDecision {
    match policy {
        AtimePolicy::StrictAtime => AtimeDecision::Update,

        AtimePolicy::NoAtime => AtimeDecision::Skip,

        AtimePolicy::NoDirAtime => {
            if times.is_dir {
                AtimeDecision::Skip
            } else {
                AtimeDecision::Update
            }
        }

        AtimePolicy::RelAtime => {
            // Rule 1: if atime > mtime and atime > ctime, the inode has been
            //         accessed more recently than it was modified — skip.
            if times.atime > times.mtime && times.atime > times.ctime {
                // Rule 2: but if atime is very old, update anyway.
                let age = now.saturating_sub(times.atime);
                if (age as u64) < cfg.max_age_secs {
                    return AtimeDecision::Skip;
                }
            }
            AtimeDecision::Update
        }
    }
}

/// Compute the updated atime value, clamping to avoid wrap-around.
///
/// Returns `now` if the update should proceed, otherwise the existing atime.
pub fn compute_new_atime(decision: AtimeDecision, current_atime: i64, now: i64) -> i64 {
    match decision {
        AtimeDecision::Update => now,
        AtimeDecision::Skip => current_atime,
    }
}

/// Per-filesystem atime policy manager.
#[derive(Debug, Clone, Copy)]
pub struct AtimeManager {
    /// Active policy for this filesystem/mount.
    pub policy: AtimePolicy,
    /// Relatime configuration (used only when policy == RelAtime).
    pub rel_cfg: RelAtimeConfig,
    /// Statistics: number of atime updates performed.
    pub updates: u64,
    /// Statistics: number of atime updates skipped.
    pub skips: u64,
}

impl AtimeManager {
    /// Create a new manager with the given policy.
    pub const fn new(policy: AtimePolicy) -> Self {
        Self {
            policy,
            rel_cfg: RelAtimeConfig {
                max_age_secs: 86400,
            },
            updates: 0,
            skips: 0,
        }
    }

    /// Determine and record whether the atime should be updated.
    ///
    /// Returns the new atime value to write.
    pub fn process(&mut self, times: &InodeTimes, now: i64) -> i64 {
        let decision = should_update_atime(self.policy, &self.rel_cfg, times, now);
        match decision {
            AtimeDecision::Update => self.updates += 1,
            AtimeDecision::Skip => self.skips += 1,
        }
        compute_new_atime(decision, times.atime, now)
    }

    /// Change the active policy (e.g., on remount).
    pub fn set_policy(&mut self, policy: AtimePolicy) {
        self.policy = policy;
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.updates = 0;
        self.skips = 0;
    }
}

impl Default for AtimeManager {
    fn default() -> Self {
        Self::new(AtimePolicy::RelAtime)
    }
}

/// Parse an atime policy from a mount option string.
///
/// Recognises: "strictatime", "noatime", "relatime", "nodiratime".
pub fn parse_atime_policy(opt: &str) -> Result<AtimePolicy> {
    match opt {
        "strictatime" => Ok(AtimePolicy::StrictAtime),
        "noatime" => Ok(AtimePolicy::NoAtime),
        "relatime" => Ok(AtimePolicy::RelAtime),
        "nodiratime" => Ok(AtimePolicy::NoDirAtime),
        _ => Err(Error::InvalidArgument),
    }
}

/// Return the string representation of an atime policy (for /proc/mounts).
pub fn atime_policy_str(policy: AtimePolicy) -> &'static str {
    match policy {
        AtimePolicy::StrictAtime => "strictatime",
        AtimePolicy::NoAtime => "noatime",
        AtimePolicy::RelAtime => "relatime",
        AtimePolicy::NoDirAtime => "nodiratime",
    }
}

/// Apply atime update to an inode's timestamp record.
///
/// Returns `true` if the inode was modified and must be marked dirty.
pub fn apply_atime_update(manager: &mut AtimeManager, times: &mut InodeTimes, now: i64) -> bool {
    let new_atime = manager.process(times, now);
    if new_atime != times.atime {
        times.atime = new_atime;
        true
    } else {
        false
    }
}

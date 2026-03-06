// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack guard implementation.
//!
//! Implements stack canary and stack clash protection. A canary value
//! is written at the bottom of each kernel/user stack on setup and
//! verified periodically or on function return. Stack clash protection
//! probes each page when growing the stack to ensure guard pages are
//! not skipped.
//!
//! - [`StackGuardConfig`] — canary and protection settings
//! - [`StackCanary`] — per-stack canary state
//! - [`ClashProbeResult`] — outcome of a stack probe
//! - [`StackGuardManager`] — the stack guard manager
//!
//! Reference: `.kernelORG/` — `arch/x86/include/asm/stackprotector.h`,
//!   stack clash mitigation (GCC -fstack-clash-protection).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default canary value.
const DEFAULT_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Corrupted canary value (for detection).
const CORRUPTED_CANARY: u64 = 0;

/// Maximum tracked stacks.
const MAX_STACKS: usize = 256;

/// Default stack size (8 KiB for kernel).
const DEFAULT_KERNEL_STACK_SIZE: u64 = 8192;

/// Default user stack size (8 MiB).
const DEFAULT_USER_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// Stack probe interval (must touch each page).
const PROBE_INTERVAL: u64 = PAGE_SIZE;

// -------------------------------------------------------------------
// StackGuardConfig
// -------------------------------------------------------------------

/// Stack guard configuration.
#[derive(Debug, Clone, Copy)]
pub struct StackGuardConfig {
    /// The canary value to write at stack base.
    pub canary_value: u64,
    /// Whether canary checking is enabled.
    pub canary_enabled: bool,
    /// Whether stack clash protection is enabled.
    pub clash_protection: bool,
    /// Probe interval for clash protection (bytes).
    pub probe_interval: u64,
    /// Whether to randomize canary per-stack.
    pub randomize_canary: bool,
}

impl StackGuardConfig {
    /// Creates default configuration.
    pub fn new() -> Self {
        Self {
            canary_value: DEFAULT_CANARY,
            canary_enabled: true,
            clash_protection: true,
            probe_interval: PROBE_INTERVAL,
            randomize_canary: false,
        }
    }

    /// Creates configuration with a custom canary.
    pub fn with_canary(canary: u64) -> Self {
        Self {
            canary_value: canary,
            ..Self::new()
        }
    }
}

impl Default for StackGuardConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// StackCanary
// -------------------------------------------------------------------

/// Per-stack canary state.
#[derive(Debug, Clone, Copy)]
pub struct StackCanary {
    /// Stack identifier (thread/task ID).
    pub stack_id: u32,
    /// Stack base address (lowest address).
    pub stack_base: u64,
    /// Stack top address (highest address).
    pub stack_top: u64,
    /// Address where the canary is written.
    pub canary_addr: u64,
    /// Expected canary value.
    pub canary_value: u64,
    /// Current canary value (for checking).
    pub current_value: u64,
    /// Whether this stack is kernel or user.
    pub is_kernel: bool,
    /// Whether this entry is active.
    pub active: bool,
}

impl StackCanary {
    /// Creates a new canary for a stack.
    pub fn new(
        stack_id: u32,
        stack_base: u64,
        stack_size: u64,
        canary_value: u64,
        is_kernel: bool,
    ) -> Self {
        let stack_top = stack_base + stack_size;
        // Canary is placed at the very bottom of the stack.
        let canary_addr = stack_base;
        Self {
            stack_id,
            stack_base,
            stack_top,
            canary_addr,
            canary_value,
            current_value: canary_value,
            is_kernel,
            active: true,
        }
    }

    /// Returns the stack size.
    pub fn stack_size(&self) -> u64 {
        self.stack_top - self.stack_base
    }

    /// Checks if the canary is intact.
    pub fn is_intact(&self) -> bool {
        self.current_value == self.canary_value
    }

    /// Simulates canary corruption (for testing).
    pub fn corrupt(&mut self) {
        self.current_value = CORRUPTED_CANARY;
    }

    /// Restores the canary value.
    pub fn restore(&mut self) {
        self.current_value = self.canary_value;
    }
}

impl Default for StackCanary {
    fn default() -> Self {
        Self {
            stack_id: 0,
            stack_base: 0,
            stack_top: 0,
            canary_addr: 0,
            canary_value: 0,
            current_value: 0,
            is_kernel: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// CanaryCheckResult
// -------------------------------------------------------------------

/// Result of a canary check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryCheckResult {
    /// Canary is intact.
    Intact,
    /// Canary has been corrupted (stack overflow detected).
    Corrupted,
    /// Stack not found.
    NotFound,
}

// -------------------------------------------------------------------
// ClashProbeResult
// -------------------------------------------------------------------

/// Result of a stack clash probe.
#[derive(Debug, Clone, Copy)]
pub struct ClashProbeResult {
    /// Number of pages probed.
    pub pages_probed: u64,
    /// Whether a guard page was hit.
    pub guard_hit: bool,
    /// Address where the probe started.
    pub start_addr: u64,
    /// Address where the probe ended.
    pub end_addr: u64,
    /// Whether the probe completed successfully.
    pub success: bool,
}

impl ClashProbeResult {
    /// Creates a successful probe result.
    pub fn success(pages_probed: u64, start: u64, end: u64) -> Self {
        Self {
            pages_probed,
            guard_hit: false,
            start_addr: start,
            end_addr: end,
            success: true,
        }
    }

    /// Creates a result indicating guard page hit.
    pub fn guard_hit(pages_probed: u64, guard_addr: u64) -> Self {
        Self {
            pages_probed,
            guard_hit: true,
            start_addr: guard_addr,
            end_addr: guard_addr,
            success: false,
        }
    }
}

// -------------------------------------------------------------------
// StackGuardStats
// -------------------------------------------------------------------

/// Stack guard statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackGuardStats {
    /// Total stacks registered.
    pub stacks_registered: u64,
    /// Total canary checks performed.
    pub canary_checks: u64,
    /// Canary corruptions detected.
    pub corruptions_detected: u64,
    /// Stack clash probes performed.
    pub clash_probes: u64,
    /// Guard page hits during probing.
    pub guard_hits: u64,
}

// -------------------------------------------------------------------
// StackGuardManager
// -------------------------------------------------------------------

/// Manages stack guards for all tasks.
pub struct StackGuardManager {
    /// Per-stack canary states.
    stacks: [StackCanary; MAX_STACKS],
    /// Number of active stacks.
    nr_active: usize,
    /// Configuration.
    config: StackGuardConfig,
    /// Statistics.
    stats: StackGuardStats,
    /// Next canary seed (for randomization).
    canary_seed: u64,
}

impl StackGuardManager {
    /// Creates a new stack guard manager.
    pub fn new(config: StackGuardConfig) -> Self {
        Self {
            stacks: [StackCanary::default(); MAX_STACKS],
            nr_active: 0,
            config,
            stats: StackGuardStats::default(),
            canary_seed: DEFAULT_CANARY,
        }
    }

    /// Sets up a stack guard (writes canary at stack base).
    pub fn stack_guard_setup(
        &mut self,
        stack_id: u32,
        stack_base: u64,
        stack_size: u64,
        is_kernel: bool,
    ) -> Result<()> {
        // Find a free slot (index-based to avoid borrow conflict with next_canary).
        let slot = self.stacks.iter().position(|c| !c.active);
        if let Some(idx) = slot {
            let value = if self.config.randomize_canary {
                self.next_canary()
            } else {
                self.config.canary_value
            };
            self.stacks[idx] = StackCanary::new(stack_id, stack_base, stack_size, value, is_kernel);
            self.nr_active += 1;
            self.stats.stacks_registered += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Checks the canary for a specific stack.
    pub fn stack_guard_check(&mut self, stack_id: u32) -> CanaryCheckResult {
        self.stats.canary_checks += 1;
        for canary in &self.stacks {
            if canary.active && canary.stack_id == stack_id {
                if canary.is_intact() {
                    return CanaryCheckResult::Intact;
                } else {
                    self.stats.corruptions_detected += 1;
                    return CanaryCheckResult::Corrupted;
                }
            }
        }
        CanaryCheckResult::NotFound
    }

    /// Checks all active canaries.
    pub fn check_all(&mut self) -> usize {
        let mut corrupted = 0;
        for canary in &self.stacks {
            if canary.active {
                self.stats.canary_checks += 1;
                if !canary.is_intact() {
                    self.stats.corruptions_detected += 1;
                    corrupted += 1;
                }
            }
        }
        corrupted
    }

    /// Performs stack clash protection probing.
    ///
    /// When growing the stack by `grow_size` bytes, probes each page
    /// from `current_sp` downward to ensure no guard pages are skipped.
    pub fn stack_clash_protection(
        &mut self,
        current_sp: u64,
        grow_size: u64,
        guard_start: u64,
        guard_end: u64,
    ) -> ClashProbeResult {
        if !self.config.clash_protection {
            return ClashProbeResult::success(0, current_sp, current_sp);
        }

        self.stats.clash_probes += 1;
        let interval = self.config.probe_interval;
        let target = current_sp.saturating_sub(grow_size);
        let mut probe_addr = current_sp;
        let mut pages_probed = 0u64;

        while probe_addr > target {
            probe_addr = probe_addr.saturating_sub(interval);
            pages_probed += 1;

            // Check if we hit the guard region.
            if probe_addr >= guard_start && probe_addr < guard_end {
                self.stats.guard_hits += 1;
                return ClashProbeResult::guard_hit(pages_probed, probe_addr);
            }
        }

        ClashProbeResult::success(pages_probed, current_sp, target)
    }

    /// Removes a stack guard (task exit).
    pub fn remove_guard(&mut self, stack_id: u32) -> Result<()> {
        for canary in &mut self.stacks {
            if canary.active && canary.stack_id == stack_id {
                canary.active = false;
                self.nr_active = self.nr_active.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Generates the next canary value (simple PRNG).
    fn next_canary(&mut self) -> u64 {
        self.canary_seed = self
            .canary_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.canary_seed
    }

    /// Returns the configuration.
    pub fn config(&self) -> &StackGuardConfig {
        &self.config
    }

    /// Returns statistics.
    pub fn stats(&self) -> &StackGuardStats {
        &self.stats
    }

    /// Returns the number of active stacks.
    pub fn nr_active(&self) -> usize {
        self.nr_active
    }
}

impl Default for StackGuardManager {
    fn default() -> Self {
        Self::new(StackGuardConfig::new())
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `futex(2)` operation dispatcher and extended operations.
//!
//! Provides validation and dispatch for `FUTEX_WAIT`, `FUTEX_WAKE`,
//! `FUTEX_CMP_REQUEUE`, `FUTEX_WAKE_OP`, `FUTEX_LOCK_PI`, `FUTEX_UNLOCK_PI`,
//! `FUTEX_WAIT_BITSET`, and `FUTEX_WAKE_BITSET` operations.
//!
//! The basic `futex_call.rs` handles the entry point; this module handles
//! the argument validation, bitset logic, and wake-op encoding.
//!
//! # POSIX reference
//!
//! `futex` is a Linux-specific primitive; not in POSIX.1-2024.
//!
//! # References
//!
//! - Linux: `kernel/futex/core.c`, `kernel/futex/pi.c`
//! - `futex(2)` man page
//! - `include/uapi/linux/futex.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Futex operation constants
// ---------------------------------------------------------------------------

/// Wait if value matches.
pub const FUTEX_WAIT: u32 = 0;
/// Wake up to N waiters.
pub const FUTEX_WAKE: u32 = 1;
/// Requeue waiters to another futex.
pub const FUTEX_REQUEUE: u32 = 3;
/// Conditional requeue.
pub const FUTEX_CMP_REQUEUE: u32 = 4;
/// Wake and modify another futex.
pub const FUTEX_WAKE_OP: u32 = 5;
/// Lock a priority-inheritance futex.
pub const FUTEX_LOCK_PI: u32 = 6;
/// Unlock a priority-inheritance futex.
pub const FUTEX_UNLOCK_PI: u32 = 7;
/// Trylock PI.
pub const FUTEX_TRYLOCK_PI: u32 = 8;
/// Wait with bitset.
pub const FUTEX_WAIT_BITSET: u32 = 9;
/// Wake with bitset.
pub const FUTEX_WAKE_BITSET: u32 = 10;
/// Lock PI with requeue.
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
/// Conditional requeue PI.
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
/// Lock PI (2.0).
pub const FUTEX_LOCK_PI2: u32 = 13;

/// Private futex flag (no shared-memory sharing needed).
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
/// Clock-realtime flag.
pub const FUTEX_CLOCK_REALTIME: u32 = 256;

/// Mask to extract the base operation.
const FUTEX_OP_MASK: u32 = 0x7F;

/// Bitset meaning "all waiters".
pub const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// FutexOp — decoded operation
// ---------------------------------------------------------------------------

/// Decoded futex operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexOp {
    Wait,
    Wake,
    Requeue,
    CmpRequeue,
    WakeOp,
    LockPi,
    UnlockPi,
    TrylockPi,
    WaitBitset,
    WakeBitset,
    WaitRequeuePi,
    CmpRequeuePi,
    LockPi2,
}

impl FutexOp {
    /// Decode the operation from raw `futex_op` argument.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised operation codes.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw & FUTEX_OP_MASK {
            FUTEX_WAIT => Ok(Self::Wait),
            FUTEX_WAKE => Ok(Self::Wake),
            FUTEX_REQUEUE => Ok(Self::Requeue),
            FUTEX_CMP_REQUEUE => Ok(Self::CmpRequeue),
            FUTEX_WAKE_OP => Ok(Self::WakeOp),
            FUTEX_LOCK_PI => Ok(Self::LockPi),
            FUTEX_UNLOCK_PI => Ok(Self::UnlockPi),
            FUTEX_TRYLOCK_PI => Ok(Self::TrylockPi),
            FUTEX_WAIT_BITSET => Ok(Self::WaitBitset),
            FUTEX_WAKE_BITSET => Ok(Self::WakeBitset),
            FUTEX_WAIT_REQUEUE_PI => Ok(Self::WaitRequeuePi),
            FUTEX_CMP_REQUEUE_PI => Ok(Self::CmpRequeuePi),
            FUTEX_LOCK_PI2 => Ok(Self::LockPi2),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// FutexFlags — private + realtime flags
// ---------------------------------------------------------------------------

/// Decoded futex flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FutexFlags {
    /// Private (process-local) futex.
    pub private: bool,
    /// Use `CLOCK_REALTIME` for the timeout.
    pub realtime: bool,
}

impl FutexFlags {
    /// Parse from raw operation bits.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            private: raw & FUTEX_PRIVATE_FLAG != 0,
            realtime: raw & FUTEX_CLOCK_REALTIME != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// WakeOpEncoding — FUTEX_WAKE_OP argument
// ---------------------------------------------------------------------------

/// FUTEX_WAKE_OP operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOpCode {
    Set,
    Add,
    Or,
    AndNot,
    Xor,
}

impl WakeOpCode {
    fn from_raw(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::Set),
            1 => Ok(Self::Add),
            2 => Ok(Self::Or),
            3 => Ok(Self::AndNot),
            4 => Ok(Self::Xor),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// FUTEX_WAKE_OP comparison codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOpCmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl WakeOpCmp {
    fn from_raw(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::Eq),
            1 => Ok(Self::Ne),
            2 => Ok(Self::Lt),
            3 => Ok(Self::Le),
            4 => Ok(Self::Gt),
            5 => Ok(Self::Ge),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Evaluate the comparison.
    pub fn evaluate(self, old: u32, cmparg: u32) -> bool {
        match self {
            Self::Eq => old == cmparg,
            Self::Ne => old != cmparg,
            Self::Lt => old < cmparg,
            Self::Le => old <= cmparg,
            Self::Gt => old > cmparg,
            Self::Ge => old >= cmparg,
        }
    }
}

/// Decoded `FUTEX_WAKE_OP` val3 argument.
#[derive(Debug, Clone, Copy)]
pub struct WakeOp {
    /// Operation to apply to the second futex.
    pub op: WakeOpCode,
    /// Operand for the operation.
    pub oparg: u32,
    /// Comparison to apply to the old value.
    pub cmp: WakeOpCmp,
    /// Comparison argument.
    pub cmparg: u32,
    /// Whether oparg is a shift.
    pub shift: bool,
}

impl WakeOp {
    /// Decode from a packed `val3`.
    ///
    /// Bit layout (from Linux `include/uapi/linux/futex.h`):
    /// bits 31..28 = op | SHIFT
    /// bits 27..24 = cmp
    /// bits 23..12 = oparg
    /// bits 11..0  = cmparg
    pub fn from_val3(val3: u32) -> Result<Self> {
        let shift = (val3 >> 31) & 1 != 0;
        let op_raw = (val3 >> 28) & 0x7;
        let cmp_raw = (val3 >> 24) & 0xF;
        let oparg = (val3 >> 12) & 0xFFF;
        let cmparg = val3 & 0xFFF;
        Ok(Self {
            op: WakeOpCode::from_raw(op_raw)?,
            cmp: WakeOpCmp::from_raw(cmp_raw)?,
            oparg,
            cmparg,
            shift,
        })
    }

    /// Apply the operation to `old_val` and return the new value.
    pub fn apply(&self, old_val: u32) -> u32 {
        let arg = if self.shift {
            1u32 << self.oparg
        } else {
            self.oparg
        };
        match self.op {
            WakeOpCode::Set => arg,
            WakeOpCode::Add => old_val.wrapping_add(arg),
            WakeOpCode::Or => old_val | arg,
            WakeOpCode::AndNot => old_val & !arg,
            WakeOpCode::Xor => old_val ^ arg,
        }
    }
}

// ---------------------------------------------------------------------------
// sys_futex_wake_op — FUTEX_WAKE_OP handler
// ---------------------------------------------------------------------------

/// Process `FUTEX_WAKE_OP`.
///
/// 1. Apply `wake_op` to the second futex word (`uaddr2_val`).
/// 2. Wake up to `val` waiters on `uaddr1`.
/// 3. If the comparison passes, also wake up to `val2` waiters on `uaddr2`.
///
/// Returns `(new_uaddr2_val, wake_uaddr2)` where `wake_uaddr2` indicates
/// whether the condition comparison passed.
///
/// # Arguments
///
/// * `uaddr1_waiters` — Number of waiters on the primary futex.
/// * `uaddr2_old_val` — Current value at `uaddr2`.
/// * `val3`           — Encoded `WakeOp`.
///
/// # Errors
///
/// [`Error::InvalidArgument`] if `val3` is malformed.
pub fn sys_futex_wake_op(uaddr2_old_val: u32, val3: u32) -> Result<(u32, bool)> {
    let wake_op = WakeOp::from_val3(val3)?;
    let new_val = wake_op.apply(uaddr2_old_val);
    let wake_uaddr2 = wake_op.cmp.evaluate(uaddr2_old_val, wake_op.cmparg);
    Ok((new_val, wake_uaddr2))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn futex_op_decode() {
        assert_eq!(FutexOp::from_raw(FUTEX_WAIT).unwrap(), FutexOp::Wait);
        assert_eq!(FutexOp::from_raw(FUTEX_WAKE).unwrap(), FutexOp::Wake);
        assert_eq!(
            FutexOp::from_raw(FUTEX_WAIT | FUTEX_PRIVATE_FLAG).unwrap(),
            FutexOp::Wait
        );
    }

    #[test]
    fn futex_flags_private() {
        let flags = FutexFlags::from_raw(FUTEX_WAIT | FUTEX_PRIVATE_FLAG);
        assert!(flags.private);
        assert!(!flags.realtime);
    }

    #[test]
    fn unknown_op_rejected() {
        assert_eq!(FutexOp::from_raw(99), Err(Error::InvalidArgument));
    }

    #[test]
    fn wake_op_set() {
        // val3: op=0(Set), cmp=0(Eq), oparg=5, cmparg=3
        // bits: 0 000 0000 0000 0000 0101 0000 0000 0011
        let val3: u32 = (0 << 28) | (0 << 24) | (5 << 12) | 3;
        let (new_val, cond) = sys_futex_wake_op(3, val3).unwrap();
        assert_eq!(new_val, 5); // SET to 5
        assert!(cond); // old_val (3) == cmparg (3)
    }

    #[test]
    fn wake_op_add() {
        let val3: u32 = (1 << 28) | (4 << 24) | (10 << 12) | 0; // ADD 10, cmp GT 0
        let (new_val, cond) = sys_futex_wake_op(5, val3).unwrap();
        assert_eq!(new_val, 15); // 5 + 10
        assert!(cond); // 5 > 0
    }

    #[test]
    fn wake_op_condition_fails() {
        // op=Set, cmp=Eq, old=7, cmparg=3 → condition false
        let val3: u32 = (0 << 28) | (0 << 24) | (99 << 12) | 3;
        let (_, cond) = sys_futex_wake_op(7, val3).unwrap();
        assert!(!cond);
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Linux AArch64 syscall ABI normalization.

use crate::dispatch::SyscallArgs;
use crate::handler::SyscallResult;

/// Linux AArch64 syscall number for `getpid(2)`.
pub const LINUX_SYS_GETPID: u64 = 172;

fn normalize_trap_registers(native_number: u64, args: [u64; 6]) -> Option<SyscallArgs> {
    match native_number {
        LINUX_SYS_GETPID => Some(SyscallArgs {
            number: crate::number::SYS_GETPID,
            arg0: args[0],
            arg1: args[1],
            arg2: args[2],
            arg3: args[3],
            arg4: args[4],
            arg5: args[5],
        }),
        _ => None,
    }
}

/// Dispatch a syscall captured from Linux AArch64 trap registers.
pub fn dispatch_from_trap_registers(native_number: u64, args: [u64; 6]) -> SyscallResult {
    match normalize_trap_registers(native_number, args) {
        Some(normalized) => crate::dispatch::dispatch(&normalized),
        None => -i64::from(crate::libc::ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trap_registers_map_linux_getpid_to_shared_args() {
        // Given
        let native_args = [11, 22, 33, 44, 55, 66];

        // When
        let normalized = normalize_trap_registers(LINUX_SYS_GETPID, native_args);

        // Then
        assert!(normalized.is_some(), "AArch64 getpid must be normalized");
        let normalized = normalized.unwrap();
        assert_eq!(normalized.number, crate::number::SYS_GETPID);
        assert_eq!(
            [
                normalized.arg0,
                normalized.arg1,
                normalized.arg2,
                normalized.arg3,
                normalized.arg4,
                normalized.arg5,
            ],
            native_args
        );
    }

    #[test]
    fn x86_getpid_number_is_not_accepted_as_aarch64() {
        // Given
        let x86_getpid_number = crate::number::SYS_GETPID;

        // When
        let normalized = normalize_trap_registers(x86_getpid_number, [0; 6]);

        // Then
        assert!(normalized.is_none());
    }

    #[test]
    fn getpid_dispatch_returns_existing_stub_pid() {
        // Given
        let native_args = [1, 2, 3, 4, 5, 6];

        // When
        let result = dispatch_from_trap_registers(LINUX_SYS_GETPID, native_args);

        // Then
        assert_eq!(result, 0);
    }

    #[test]
    fn unknown_aarch64_syscall_returns_enosys() {
        // Given
        let unknown_number = u64::MAX;

        // When
        let result = dispatch_from_trap_registers(unknown_number, [0; 6]);

        // Then
        assert_eq!(result, -i64::from(crate::libc::ENOSYS));
    }
}

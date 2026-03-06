// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pause(2)` syscall dispatch layer.
//!
//! Suspends the calling process until any signal is received.  If the
//! signal has a handler, `pause` returns -1 with errno `EINTR` after the
//! handler returns.  If the signal terminates the process, `pause` does
//! not return.
//!
//! # Syscall signature
//!
//! ```text
//! int pause(void);
//! ```
//!
//! Takes no arguments.  Always returns -1 with `EINTR`.
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `pause()` in `<unistd.h>`
//! - `.TheOpenGroup/susv5-html/functions/pause.html`
//!
//! # References
//!
//! - Linux: `kernel/signal.c` (`sys_pause`)
//! - `pause(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `pause(2)`.
///
/// Suspends until a signal is delivered.  Returns `Interrupted` when a
/// signal handler returns, which corresponds to errno `EINTR`.
///
/// # Errors
///
/// - [`Error::Interrupted`] — a signal was received (normal return path).
/// - [`Error::NotImplemented`] — stub; scheduler sleep not yet wired.
pub fn sys_pause() -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pause_call() -> Result<i64> {
    sys_pause()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_reaches_stub() {
        assert_eq!(sys_pause().unwrap_err(), Error::NotImplemented);
    }
}

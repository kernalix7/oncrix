// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared libraries and common utilities for the ONCRIX operating system.
//!
//! This crate provides foundational types, error definitions, and utility
//! functions used across all other ONCRIX crates.

#![no_std]

pub mod errno;
pub mod sync;

/// ONCRIX kernel result type alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Top-level error type for the ONCRIX kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Operation not permitted.
    PermissionDenied,
    /// Resource not found.
    NotFound,
    /// Out of memory.
    OutOfMemory,
    /// Invalid argument provided.
    InvalidArgument,
    /// Resource is busy or locked.
    Busy,
    /// Operation would block.
    WouldBlock,
    /// Operation interrupted.
    Interrupted,
    /// I/O error.
    IoError,
    /// Not implemented / not supported.
    NotImplemented,
    /// Resource already exists.
    AlreadyExists,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::PermissionDenied => write!(f, "permission denied"),
            Error::NotFound => write!(f, "not found"),
            Error::OutOfMemory => write!(f, "out of memory"),
            Error::InvalidArgument => write!(f, "invalid argument"),
            Error::Busy => write!(f, "resource busy"),
            Error::WouldBlock => write!(f, "operation would block"),
            Error::Interrupted => write!(f, "operation interrupted"),
            Error::IoError => write!(f, "I/O error"),
            Error::NotImplemented => write!(f, "not implemented"),
            Error::AlreadyExists => write!(f, "already exists"),
        }
    }
}

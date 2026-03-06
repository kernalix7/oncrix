// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX microkernel core.
//!
//! The microkernel provides only the essential services: scheduling,
//! inter-process communication, and basic memory management.
//! All other OS services (drivers, file systems, networking) run
//! as isolated user-space processes communicating via IPC.

#![no_std]

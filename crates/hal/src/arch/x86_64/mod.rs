// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 architecture-specific HAL implementations.

pub mod apic;
pub mod gdt;
pub mod idt;
pub mod io;
pub mod ioapic;
pub mod pic;
pub mod pit;
pub mod uart;

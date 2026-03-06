# ONCRIX Kernel Documentation

[한국어](index.ko.md)

Welcome to the ONCRIX kernel documentation. This documentation is organized
similarly to the Linux kernel documentation, covering all subsystems,
APIs, and development guidelines.

**ONCRIX Is Not a Copy, Real Independent uniX**

---

## Documentation Structure

### For Developers

- [Development Process](process/index.md) — How to contribute, coding style, patch workflow
- [Core API](core-api/index.md) — Kernel-internal API reference
- [Driver API](driver-api/index.md) — Writing device drivers for ONCRIX

### Subsystem Documentation

- [Memory Management](mm/index.md) — Physical/virtual memory, page tables, allocators, CoW
- [Process Management](process/process-model.md) — Processes, threads, scheduling, signals
- [Scheduler](scheduler/index.md) — Scheduling algorithms and preemption
- [Inter-Process Communication](ipc/index.md) — Message passing, channels, endpoints
- [File Systems](filesystems/index.md) — VFS layer, ramfs, devfs, procfs
- [System Call Interface](core-api/syscalls.md) — POSIX-compatible syscall ABI

### Architecture-Specific

- [x86_64](arch/x86_64/index.md) — GDT, IDT, APIC, SYSCALL/SYSRET, paging

### Administration

- [Admin Guide](admin-guide/index.md) — Building, booting, configuring ONCRIX
- [Security](security/index.md) — Capability model, privilege separation, threat model

### Reference

- [Architecture Overview](ARCHITECTURE.md) — Full technical architecture document
- [Developer Wiki](DEVELOPER_WIKI.md) — Crate-by-crate guide and patterns
- [Verification Checklist](VERIFICATION_CHECKLIST.md) — Pre-commit quality checks
- [Glossary](core-api/glossary.md) — ONCRIX-specific terminology

---

## Quick Links

| What you want to do | Where to look |
|---------------------|---------------|
| Build ONCRIX | [Admin Guide → Building](admin-guide/building.md) |
| Write a driver | [Driver API](driver-api/index.md) |
| Understand IPC | [IPC → Design](ipc/design.md) |
| Add a syscall | [Core API → Syscalls](core-api/syscalls.md) |
| Understand memory layout | [MM → Address Space](mm/address-space.md) |
| Contribute code | [Process → Contributing](process/contributing.md) |

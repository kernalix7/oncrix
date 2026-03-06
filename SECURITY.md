# Security Policy

**English** | [한국어](docs/SECURITY.ko.md)

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

As ONCRIX is in active development, security updates are applied to the latest version on the `main` branch.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them through [GitHub Security Advisories](https://github.com/kernalix7/oncrix/security/advisories/new).

### What to Include

When reporting a vulnerability, please include:

1. **Description** — A clear description of the vulnerability
2. **Steps to Reproduce** — Detailed steps to reproduce the issue
3. **Impact** — The potential impact of the vulnerability
4. **Affected Components** — Which parts of ONCRIX are affected
5. **Environment** — OS version, Rust toolchain version, QEMU version, target architecture

### Response Timeline

- **Acknowledgment** — Within 48 hours of the report
- **Initial Assessment** — Within 7 days
- **Fix & Disclosure** — Coordinated with the reporter; typically within 30 days for critical issues

### Scope

The following areas are considered in-scope for security reports:

- Memory safety issues in kernel code
- Privilege escalation vulnerabilities
- IPC capability bypass
- Syscall argument validation failures
- User-space pointer dereference without validation
- Integer overflow leading to security impact
- Race conditions in kernel synchronization primitives
- Driver isolation bypass

### Out of Scope

- Bugs that require physical access to the user's machine
- Social engineering attacks
- Issues in third-party dependencies (please report these upstream, but let us know)

## Security Best Practices

ONCRIX follows these security practices:

- All kernel code written in Rust with `#![no_std]` for memory safety
- Minimal `unsafe` usage with documented safety invariants (`// SAFETY:`)
- Capability-based access control for all IPC endpoints
- User-space pointer validation before kernel access
- Seccomp BPF syscall filtering
- `cargo audit` run regularly for dependency vulnerabilities

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged (with permission) in our release notes.

---

*This security policy is subject to change as the project matures.*

# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Please report security vulnerabilities through
[GitHub Security Advisories](https://github.com/kernalix7/oncrix/security/advisories).

## Scope

### In-scope

- Memory safety issues in kernel code
- Privilege escalation vulnerabilities
- IPC capability bypass
- Syscall argument validation failures
- User-space pointer dereference without validation
- Integer overflow leading to security impact
- Race conditions in kernel synchronization primitives
- Driver isolation bypass

### Out-of-scope

- Vulnerabilities requiring physical access to hardware
- Social engineering attacks
- Issues in upstream dependencies (report to upstream)
- Denial of service without security impact

## Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix for critical issues | Within 30 days |

## Security Practices

- All kernel code written in Rust with `#![no_std]`
- Minimal `unsafe` usage with documented safety invariants
- Capability-based access control for all IPC endpoints
- User-space pointer validation before kernel access
- `cargo audit` run regularly for dependency vulnerabilities

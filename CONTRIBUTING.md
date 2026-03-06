# Contributing to ONCRIX

**English** | [한국어](docs/CONTRIBUTING.ko.md)

Thank you for your interest in contributing to ONCRIX!

## Development Setup

### Prerequisites

- **Rust 1.85+** (nightly recommended for `#![no_std]` features)
- **QEMU 7.0+** (for system-level testing)
- **Git** (for version control)

### Getting Started

```bash
git clone https://github.com/kernalix7/oncrix.git
cd oncrix
cargo build --workspace
```

## Workflow

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-change`
3. **Implement** your changes following the coding conventions in [docs/VERIFICATION_CHECKLIST.md](docs/VERIFICATION_CHECKLIST.md)
4. **Verify** your changes: `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace`
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/)
6. **Push** and open a Pull Request

## Commit Conventions

Use the [Conventional Commits](https://www.conventionalcommits.org/) format:

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `refactor:` | Code refactoring (no behavior change) |
| `test:` | Adding or updating tests |
| `chore:` | Build, CI, tooling changes |

Example: `feat(ipc): implement synchronous send/receive`

## Pull Request Checklist

- [ ] Clear description of the change and its rationale
- [ ] Tests added or updated for new functionality
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo build --workspace` succeeds
- [ ] Public APIs are documented with `///` comments
- [ ] No `unwrap()`/`expect()` in production code paths
- [ ] All `unsafe` blocks have `// SAFETY:` comments
- [ ] License header present in new files
- [ ] README/docs updated if public API changes
- [ ] No hardcoded paths, secrets, or personal information

## Code Review

- All pull requests require at least one review before merge
- Squash merge is preferred for clean history
- CI must pass before merge

## Security

If you discover a security vulnerability, please report it through
[GitHub Security Advisories](https://github.com/kernalix7/oncrix/security/advisories)
rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.

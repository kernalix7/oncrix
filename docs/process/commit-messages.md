# Commit Message Convention

ONCRIX uses [Conventional Commits](https://www.conventionalcommits.org/).

## Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

## Types

| Type | When to use |
|------|-------------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or fixing tests |
| `chore` | Build scripts, CI, tooling |
| `perf` | Performance improvement |

## Scope

Use the crate name without the `oncrix-` prefix:

- `kernel`, `mm`, `hal`, `process`, `ipc`, `vfs`, `syscall`, `drivers`, `lib`, `bootloader`

## Examples

```
feat(mm): implement CoW page fault handler

Add copy-on-write page fault handling in mm::cow module.
Uses PTE bit 9 (OS-available) as the CoW marker. On a write
fault to a CoW page, allocates a new frame, copies contents,
and remaps with write permission.
```

```
fix(hal): remove preserves_flags from cli instruction

The `cli` instruction modifies the IF bit in RFLAGS, so
`preserves_flags` must not be used. This could cause the
compiler to incorrectly assume FLAGS are unchanged.
```

```
refactor(vfs): extract path resolution to separate module
```

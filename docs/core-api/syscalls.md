# System Call Interface

ONCRIX uses the Linux x86_64 SYSCALL convention for POSIX-compatible
calls, with ONCRIX extensions starting at number 512.

## ABI Convention (x86_64)

```
Register   Purpose
────────   ─────────────────
RAX        Syscall number
RDI        Argument 0
RSI        Argument 1
RDX        Argument 2
R10        Argument 3
R8         Argument 4
R9         Argument 5
RAX        Return value (≥ 0 success, < 0 = -errno)
```

Entry/exit uses `SYSCALL`/`SYSRET` instructions with `swapgs` for
kernel GS base swap.

## Syscall Table

### Process Management

| Number | Name | Arguments | Description |
|--------|------|-----------|-------------|
| 39 | `getpid` | — | Get process ID |
| 57 | `fork` | — | Create child process |
| 59 | `execve` | pathname, argv, envp | Execute program |
| 60 | `exit` | status | Terminate process |
| 61 | `wait4` | pid, wstatus, options, rusage | Wait for child |
| 62 | `kill` | pid, sig | Send signal |

### File I/O

| Number | Name | Arguments | Description |
|--------|------|-----------|-------------|
| 0 | `read` | fd, buf, count | Read from fd |
| 1 | `write` | fd, buf, count | Write to fd |
| 2 | `open` | pathname, flags, mode | Open file |
| 3 | `close` | fd | Close fd |
| 4 | `stat` | pathname, statbuf | File status by path |
| 5 | `fstat` | fd, statbuf | File status by fd |
| 8 | `lseek` | fd, offset, whence | Reposition offset |
| 22 | `pipe` | pipefd | Create pipe |
| 33 | `dup2` | oldfd, newfd | Duplicate fd |
| 79 | `getcwd` | buf, size | Get working directory |
| 80 | `chdir` | path | Change directory |
| 83 | `mkdir` | pathname, mode | Create directory |
| 84 | `rmdir` | pathname | Remove directory |
| 87 | `unlink` | pathname | Delete file |

### Memory Management

| Number | Name | Arguments | Description |
|--------|------|-----------|-------------|
| 9 | `mmap` | addr, len, prot, flags, fd, off | Map memory |
| 11 | `munmap` | addr, length | Unmap memory |
| 12 | `brk` | addr | Set program break |

### Signals

| Number | Name | Arguments | Description |
|--------|------|-----------|-------------|
| 13 | `rt_sigaction` | sig, act, oldact | Set signal handler |

### IPC (ONCRIX Extensions)

| Number | Name | Arguments | Description |
|--------|------|-----------|-------------|
| 512 | `ipc_send` | endpoint, msg | Send IPC message |
| 513 | `ipc_receive` | endpoint, msg | Receive IPC message |
| 514 | `ipc_reply` | endpoint, msg | Reply to IPC call |
| 515 | `ipc_call` | endpoint, msg | Synchronous IPC |
| 516 | `ipc_create_endpoint` | — | Create endpoint |

## Adding a New Syscall

1. Add the syscall number in `syscall/src/number.rs`
2. Implement the handler in `syscall/src/handler.rs`
3. Wire it into `syscall/src/dispatch.rs`
4. Validate all user pointers before dereferencing
5. Return negative errno on error, non-negative on success
6. Update this document

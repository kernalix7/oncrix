# Inter-Process Communication (IPC)

IPC is the backbone of the ONCRIX microkernel. All communication
between OS services (drivers, VFS, network stack) flows through
typed message channels.

## Contents

- [Design](design.md) — IPC architecture and message format
- [Channels](channels.md) — Ring buffer channels and registry
- [Endpoints](endpoints.md) — Named communication endpoints
- [Syscall Interface](syscalls.md) — User-space IPC syscalls

---

## Overview

### Why Message Passing?

In a monolithic kernel, subsystems call each other's functions
directly (shared address space). In ONCRIX's microkernel:

- Each service runs in its own process (isolation)
- Communication happens through IPC (no shared state)
- The kernel mediates all message transfers (security)

### Message Format

```rust
pub struct Message {
    pub header: MessageHeader,
    pub payload: [u8; MAX_INLINE_PAYLOAD],  // 256 bytes
}

pub struct MessageHeader {
    pub msg_type: u32,
    pub sender: u64,
    pub receiver: u64,
    pub payload_len: u32,
    pub flags: u32,
}
```

### Channel Architecture

```
Process A                    Process B
┌─────────┐                ┌─────────┐
│ send()  │──────────────▶│ recv()  │
│         │   Channel      │         │
│ recv()  │◀──────────────│ send()  │
└─────────┘   (ring buf)   └─────────┘
              16 messages
```

### IPC Syscalls

| Syscall | Number | Description |
|---------|--------|-------------|
| `ipc_send` | 512 | Send a message |
| `ipc_receive` | 513 | Receive a message (blocking) |
| `ipc_reply` | 514 | Reply to an IPC call |
| `ipc_call` | 515 | Synchronous send + receive |
| `ipc_create_endpoint` | 516 | Create a new endpoint |

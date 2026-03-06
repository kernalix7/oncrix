# IPC Design

## Principles

1. **Synchronous by default** — `call()` blocks until reply arrives
2. **Bounded buffers** — Fixed 16-message ring prevents unbounded memory use
3. **Capability-based** — Endpoint access requires a capability token
4. **Copy semantics** — Messages are copied, not shared (isolation)

## Message Types

```rust
pub mod msg_type {
    pub const REQUEST: u32 = 1;   // Client → Server
    pub const RESPONSE: u32 = 2;  // Server → Client
    pub const NOTIFY: u32 = 3;    // One-way notification
    pub const ERROR: u32 = 4;     // Error response
}
```

## Channel Ring Buffer

Each channel is a fixed-size ring buffer:

```
Capacity: 16 messages
Structure:
  ┌──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┬──┐
  │ 0│ 1│ 2│ 3│ 4│ 5│ 6│ 7│ 8│ 9│10│11│12│13│14│15│
  └──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┴──┘
       ▲                          ▲
       │                          │
     head (read)               tail (write)
```

### Back-pressure

When the ring is full, `send()` returns `WouldBlock`. The caller
can either retry or block (future: add blocking send support).

## Endpoint Registry

The `ChannelRegistry` manages up to 64 active channels. Each channel
is identified by a `ChannelId(u32)`. Endpoints map to channels
for routing.

## Performance Considerations

- Inline payload (256 bytes) avoids heap allocation for small messages
- Ring buffer is cache-friendly (contiguous memory)
- No locks needed for single-producer, single-consumer (future optimization)
- Payload length is clamped to `MAX_INLINE_PAYLOAD` to prevent OOB access

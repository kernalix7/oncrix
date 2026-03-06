# Driver API

In the ONCRIX microkernel, device drivers run as user-space processes.
They communicate with the kernel via IPC for interrupt delivery and
use memory-mapped I/O for hardware access.

## Contents

- [Driver Model](driver-model.md) — `Driver` trait, `DeviceInfo`, lifecycle
- [Device Registry](registry.md) — Registering and discovering devices
- [Interrupt Handling](interrupts.md) — IRQ delivery to user-space drivers

---

## Overview

### Driver Trait

Every driver implements:

```rust
pub trait Driver {
    fn info(&self) -> DeviceInfo;
    fn init(&mut self) -> Result<()>;
    fn handle_irq(&mut self) -> Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, data: &[u8]) -> Result<usize>;
    fn shutdown(&mut self) -> Result<()>;
}
```

### Device Classes

| Class | Examples |
|-------|---------|
| `Char` | Serial port, terminal |
| `Block` | Disk, flash |
| `Network` | Ethernet NIC |
| `Display` | Framebuffer |
| `Input` | Keyboard, mouse |
| `Timer` | PIT, APIC timer |

### Device Lifecycle

```
Discovered → Initializing → Active → Stopped
                              ↓
                            Error
```

### Registry

The `DeviceRegistry` tracks up to 64 devices. Lookup by:
- Device ID (`DeviceId`)
- Device class (`DeviceClass`)
- IRQ number

### Currently Implemented Drivers

| Driver | Crate | Type |
|--------|-------|------|
| UART 16550 | `hal` | Serial I/O |
| 8259 PIC | `hal` | Interrupt controller |
| PIT 8254 | `hal` | Timer |
| Local APIC Timer | `hal` | Timer |

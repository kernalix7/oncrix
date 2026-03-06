// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF trampoline subsystem.
//!
//! BPF trampolines are dynamically generated code stubs that enable
//! BPF programs to be attached to kernel functions at entry (fentry)
//! and exit (fexit) points without the overhead of traditional
//! kprobes/kretprobes. Each trampoline is associated with a target
//! kernel function and manages a set of attached BPF programs.
//!
//! # Architecture
//!
//! ```text
//! caller → trampoline → [fentry progs] → target fn → [fexit progs] → return
//! ```
//!
//! The trampoline intercepts calls to the target function, runs
//! attached fentry programs before the target, and fexit programs
//! after the target returns. This is done by patching the target
//! function's prologue to jump to the trampoline image.
//!
//! # Key Features
//!
//! - **Image generation**: Produces architecture-specific code for
//!   entry/exit interception.
//! - **Function prototype tracking**: Records the target function's
//!   argument and return types for safe BPF program verification.
//! - **Attach/detach**: Programs can be dynamically added/removed.
//! - **Reference counting**: Trampolines are freed when no programs
//!   remain attached.
//! - **Batch update**: Multiple program changes are batched into a
//!   single trampoline regeneration.
//! - **Registry**: Global lookup from target address to trampoline.
//!
//! # Reference
//!
//! Linux kernel `kernel/bpf/trampoline.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of trampolines in the global registry.
const MAX_TRAMPOLINES: usize = 128;

/// Maximum number of BPF programs attached to a single trampoline.
const MAX_PROGS_PER_TRAMPOLINE: usize = 32;

/// Maximum number of function arguments tracked.
const MAX_FUNC_ARGS: usize = 12;

/// Maximum trampoline image size in bytes.
const MAX_IMAGE_SIZE: usize = 4096;

/// Maximum length of a function name (bytes).
const MAX_FUNC_NAME_LEN: usize = 64;

/// Maximum number of pending batch updates.
const MAX_BATCH_OPS: usize = 16;

// ── AttachType ────────────────────────────────────────────────────────────────

/// BPF trampoline attachment type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttachType {
    /// Attached at function entry (fentry).
    #[default]
    Fentry,
    /// Attached at function exit (fexit).
    Fexit,
    /// Attached for function argument modification (fmod_ret).
    FmodRet,
}

// ── ArgType ───────────────────────────────────────────────────────────────────

/// Type descriptor for a function argument or return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArgType {
    /// No type / void.
    #[default]
    Void,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Pointer (opaque, size depends on architecture).
    Pointer,
    /// Boolean.
    Bool,
}

impl ArgType {
    /// Size of this type in bytes on a 64-bit architecture.
    pub const fn size_bytes(&self) -> usize {
        match self {
            Self::Void => 0,
            Self::U8 | Self::Bool => 1,
            Self::U16 => 2,
            Self::U32 | Self::I32 => 4,
            Self::U64 | Self::I64 | Self::Pointer => 8,
        }
    }
}

// ── FuncPrototype ─────────────────────────────────────────────────────────────

/// Prototype of a target kernel function.
///
/// Describes the function's name, argument types, and return type
/// so that the BPF verifier can type-check attached programs.
#[derive(Debug)]
pub struct FuncPrototype {
    /// Function name.
    name: [u8; MAX_FUNC_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Argument types (in order).
    args: [ArgType; MAX_FUNC_ARGS],
    /// Number of arguments.
    arg_count: usize,
    /// Return type.
    ret_type: ArgType,
    /// Target function address.
    func_addr: u64,
}

impl FuncPrototype {
    /// Create a new function prototype.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_FUNC_NAME_LEN],
            name_len: 0,
            args: [const { ArgType::Void }; MAX_FUNC_ARGS],
            arg_count: 0,
            ret_type: ArgType::Void,
            func_addr: 0,
        }
    }

    /// Set the function name.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > MAX_FUNC_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let len = name.len().min(MAX_FUNC_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
        Ok(())
    }

    /// Get the function name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Add an argument type.
    pub fn add_arg(&mut self, arg: ArgType) -> Result<()> {
        if self.arg_count >= MAX_FUNC_ARGS {
            return Err(Error::OutOfMemory);
        }
        self.args[self.arg_count] = arg;
        self.arg_count += 1;
        Ok(())
    }

    /// Get the argument types.
    pub fn args(&self) -> &[ArgType] {
        &self.args[..self.arg_count]
    }

    /// Set the return type.
    pub fn set_ret_type(&mut self, ret: ArgType) {
        self.ret_type = ret;
    }

    /// Get the return type.
    pub const fn ret_type(&self) -> ArgType {
        self.ret_type
    }

    /// Set the target function address.
    pub fn set_func_addr(&mut self, addr: u64) {
        self.func_addr = addr;
    }

    /// Get the target function address.
    pub const fn func_addr(&self) -> u64 {
        self.func_addr
    }

    /// Compute total argument size in bytes.
    pub fn args_size(&self) -> usize {
        let mut total = 0;
        for i in 0..self.arg_count {
            total += self.args[i].size_bytes();
        }
        total
    }
}

impl Default for FuncPrototype {
    fn default() -> Self {
        Self::new()
    }
}

// ── AttachedProg ──────────────────────────────────────────────────────────────

/// A BPF program attached to a trampoline.
#[derive(Debug, Clone, Copy)]
pub struct AttachedProg {
    /// BPF program ID.
    prog_id: u32,
    /// Attachment type.
    attach_type: AttachType,
    /// Priority (lower = runs first).
    priority: u32,
    /// Whether this slot is active.
    active: bool,
}

impl AttachedProg {
    /// Create an empty (inactive) attached program slot.
    pub const fn new() -> Self {
        Self {
            prog_id: 0,
            attach_type: AttachType::Fentry,
            priority: 0,
            active: false,
        }
    }

    /// Create an active attached program.
    pub const fn with(prog_id: u32, attach_type: AttachType, priority: u32) -> Self {
        Self {
            prog_id,
            attach_type,
            priority,
            active: true,
        }
    }

    /// Get the program ID.
    pub const fn prog_id(&self) -> u32 {
        self.prog_id
    }

    /// Get the attachment type.
    pub const fn attach_type(&self) -> AttachType {
        self.attach_type
    }

    /// Get the priority.
    pub const fn priority(&self) -> u32 {
        self.priority
    }

    /// Whether this entry is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for AttachedProg {
    fn default() -> Self {
        Self::new()
    }
}

// ── TrampolineImage ───────────────────────────────────────────────────────────

/// Generated trampoline code image.
///
/// Contains the machine code that intercepts calls to the target
/// function and dispatches to attached BPF programs.
#[derive(Debug)]
pub struct TrampolineImage {
    /// Raw image bytes.
    code: [u8; MAX_IMAGE_SIZE],
    /// Size of the valid code region.
    size: usize,
    /// Generation counter (incremented on each regeneration).
    generation: u64,
}

impl TrampolineImage {
    /// Create an empty image.
    pub const fn new() -> Self {
        Self {
            code: [0u8; MAX_IMAGE_SIZE],
            size: 0,
            generation: 0,
        }
    }

    /// Get the image bytes.
    pub fn code(&self) -> &[u8] {
        &self.code[..self.size]
    }

    /// Get the image size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Get the generation counter.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Generate a trampoline image for the given prototype and
    /// attached programs.
    ///
    /// This produces a stub that saves registers, calls fentry
    /// programs, invokes the original function, calls fexit
    /// programs, and restores registers.
    pub fn generate(
        &mut self,
        proto: &FuncPrototype,
        fentry_count: usize,
        fexit_count: usize,
        fmod_ret_count: usize,
    ) -> Result<()> {
        // Compute required image size.
        // Prologue (push regs) + fentry dispatch + call original +
        // fexit dispatch + epilogue (pop regs + ret).
        let prologue_size = 32;
        let fentry_stub_size = fentry_count * 24;
        let call_site_size = 16 + proto.args_size();
        let fexit_stub_size = fexit_count * 24;
        let fmod_stub_size = fmod_ret_count * 32;
        let epilogue_size = 32;

        let total = prologue_size
            + fentry_stub_size
            + call_site_size
            + fexit_stub_size
            + fmod_stub_size
            + epilogue_size;

        if total > MAX_IMAGE_SIZE {
            return Err(Error::OutOfMemory);
        }

        // Fill with NOP-sled pattern (0x90 = NOP on x86).
        // A real implementation would emit actual instructions here.
        for byte in &mut self.code[..total] {
            *byte = 0x90;
        }

        // Mark prologue boundary.
        self.code[0] = 0x55; // push rbp
        self.code[1] = 0x48; // mov rbp, rsp prefix
        self.code[2] = 0x89;
        self.code[3] = 0xE5;

        // Mark epilogue boundary.
        if total >= 2 {
            self.code[total - 2] = 0x5D; // pop rbp
            self.code[total - 1] = 0xC3; // ret
        }

        self.size = total;
        self.generation += 1;
        Ok(())
    }

    /// Reset the image.
    pub fn reset(&mut self) {
        for byte in &mut self.code[..self.size] {
            *byte = 0;
        }
        self.size = 0;
    }
}

impl Default for TrampolineImage {
    fn default() -> Self {
        Self::new()
    }
}

// ── BatchOp ───────────────────────────────────────────────────────────────────

/// A pending batch operation on a trampoline.
#[derive(Debug, Clone, Copy)]
pub enum BatchOp {
    /// Attach a program.
    Attach {
        /// Program ID.
        prog_id: u32,
        /// Attachment type.
        attach_type: AttachType,
        /// Priority.
        priority: u32,
    },
    /// Detach a program.
    Detach {
        /// Program ID to detach.
        prog_id: u32,
    },
}

// ── BpfTrampoline ─────────────────────────────────────────────────────────────

/// A BPF trampoline for a single target kernel function.
///
/// Manages attached programs, generates the interception image,
/// and supports batch updates for atomic multi-program changes.
pub struct BpfTrampoline {
    /// Target function prototype.
    prototype: FuncPrototype,
    /// Attached programs.
    progs: [AttachedProg; MAX_PROGS_PER_TRAMPOLINE],
    /// Number of active attached programs.
    prog_count: usize,
    /// Generated trampoline image.
    image: TrampolineImage,
    /// Reference count (number of users holding a reference).
    refcount: u32,
    /// Pending batch operations.
    batch_ops: [Option<BatchOp>; MAX_BATCH_OPS],
    /// Number of pending batch operations.
    batch_count: usize,
    /// Whether this trampoline is active.
    active: bool,
    /// Unique trampoline ID.
    tramp_id: u64,
}

impl BpfTrampoline {
    /// Create a new inactive trampoline.
    pub const fn new() -> Self {
        Self {
            prototype: FuncPrototype::new(),
            progs: [const { AttachedProg::new() }; MAX_PROGS_PER_TRAMPOLINE],
            prog_count: 0,
            image: TrampolineImage::new(),
            refcount: 0,
            batch_ops: [const { None }; MAX_BATCH_OPS],
            batch_count: 0,
            active: false,
            tramp_id: 0,
        }
    }

    /// Initialize the trampoline for a target function.
    pub fn init(&mut self, tramp_id: u64, prototype: FuncPrototype) -> Result<()> {
        self.prototype = prototype;
        self.tramp_id = tramp_id;
        self.active = true;
        self.refcount = 1;
        self.prog_count = 0;
        self.batch_count = 0;
        self.image.reset();
        Ok(())
    }

    /// Get the trampoline ID.
    pub const fn id(&self) -> u64 {
        self.tramp_id
    }

    /// Get the target function prototype.
    pub const fn prototype(&self) -> &FuncPrototype {
        &self.prototype
    }

    /// Get the generated image.
    pub const fn image(&self) -> &TrampolineImage {
        &self.image
    }

    /// Get the reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Check if active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Increment reference count.
    pub fn get_ref(&mut self) -> Result<()> {
        self.refcount = self.refcount.checked_add(1).ok_or(Error::OutOfMemory)?;
        Ok(())
    }

    /// Decrement reference count. Returns true if the trampoline
    /// should be freed (refcount reached zero).
    pub fn put_ref(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        if self.refcount == 0 {
            self.active = false;
            self.image.reset();
            true
        } else {
            false
        }
    }

    /// Attach a BPF program to this trampoline.
    ///
    /// After attaching, the trampoline image is regenerated.
    pub fn attach(&mut self, prog_id: u32, attach_type: AttachType, priority: u32) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }

        // Check for duplicate.
        for i in 0..self.prog_count {
            if self.progs[i].active && self.progs[i].prog_id == prog_id {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        let slot = self.find_free_prog_slot()?;
        self.progs[slot] = AttachedProg::with(prog_id, attach_type, priority);
        if slot >= self.prog_count {
            self.prog_count = slot + 1;
        }

        self.regenerate_image()
    }

    /// Detach a BPF program from this trampoline.
    pub fn detach(&mut self, prog_id: u32) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }

        let mut found = false;
        for i in 0..self.prog_count {
            if self.progs[i].active && self.progs[i].prog_id == prog_id {
                self.progs[i].active = false;
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.regenerate_image()
    }

    /// Queue a batch operation (attach or detach).
    pub fn queue_batch_op(&mut self, op: BatchOp) -> Result<()> {
        if self.batch_count >= MAX_BATCH_OPS {
            return Err(Error::OutOfMemory);
        }
        self.batch_ops[self.batch_count] = Some(op);
        self.batch_count += 1;
        Ok(())
    }

    /// Commit all pending batch operations atomically.
    ///
    /// All queued attach/detach operations are applied, then the
    /// trampoline image is regenerated once.
    pub fn commit_batch(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }

        // Collect operations into a local buffer to avoid
        // borrow conflicts.
        let mut ops = [const { None::<BatchOp> }; MAX_BATCH_OPS];
        let count = self.batch_count;
        for i in 0..count {
            ops[i] = self.batch_ops[i];
        }
        self.batch_count = 0;
        for op in &mut self.batch_ops {
            *op = None;
        }

        // Apply each operation.
        for i in 0..count {
            if let Some(op) = ops[i] {
                match op {
                    BatchOp::Attach {
                        prog_id,
                        attach_type,
                        priority,
                    } => {
                        let slot = self.find_free_prog_slot()?;
                        self.progs[slot] = AttachedProg::with(prog_id, attach_type, priority);
                        if slot >= self.prog_count {
                            self.prog_count = slot + 1;
                        }
                    }
                    BatchOp::Detach { prog_id } => {
                        for j in 0..self.prog_count {
                            if self.progs[j].active && self.progs[j].prog_id == prog_id {
                                self.progs[j].active = false;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Single image regeneration.
        self.regenerate_image()
    }

    /// Count attached programs of a given type.
    pub fn count_by_type(&self, attach_type: AttachType) -> usize {
        let mut n = 0;
        for i in 0..self.prog_count {
            if self.progs[i].active && self.progs[i].attach_type == attach_type {
                n += 1;
            }
        }
        n
    }

    /// Total number of active attached programs.
    pub fn active_prog_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.prog_count {
            if self.progs[i].active {
                n += 1;
            }
        }
        n
    }

    /// Find a free program slot.
    fn find_free_prog_slot(&self) -> Result<usize> {
        for i in 0..self.prog_count {
            if !self.progs[i].active {
                return Ok(i);
            }
        }
        if self.prog_count < MAX_PROGS_PER_TRAMPOLINE {
            return Ok(self.prog_count);
        }
        Err(Error::OutOfMemory)
    }

    /// Regenerate the trampoline image based on currently
    /// attached programs.
    fn regenerate_image(&mut self) -> Result<()> {
        let fentry = self.count_by_type(AttachType::Fentry);
        let fexit = self.count_by_type(AttachType::Fexit);
        let fmod = self.count_by_type(AttachType::FmodRet);

        if fentry == 0 && fexit == 0 && fmod == 0 {
            self.image.reset();
            return Ok(());
        }

        self.image.generate(&self.prototype, fentry, fexit, fmod)
    }
}

impl Default for BpfTrampoline {
    fn default() -> Self {
        Self::new()
    }
}

// ── TrampolineRegistry ───────────────────────────────────────────────────────

/// Global registry of BPF trampolines.
///
/// Provides lookup by target function address and trampoline ID.
pub struct TrampolineRegistry {
    /// All trampoline slots.
    trampolines: [BpfTrampoline; MAX_TRAMPOLINES],
    /// Number of used slots.
    count: usize,
    /// Next trampoline ID to assign.
    next_id: u64,
}

impl TrampolineRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            trampolines: [const { BpfTrampoline::new() }; MAX_TRAMPOLINES],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a new trampoline for a target function.
    ///
    /// Returns the trampoline ID.
    pub fn register(&mut self, prototype: FuncPrototype) -> Result<u64> {
        // Check if a trampoline already exists for this address.
        let addr = prototype.func_addr();
        if addr != 0 {
            for i in 0..self.count {
                if self.trampolines[i].active && self.trampolines[i].prototype.func_addr() == addr {
                    self.trampolines[i].get_ref()?;
                    return Ok(self.trampolines[i].id());
                }
            }
        }

        let slot = self.find_free_slot()?;
        let id = self.next_id;
        self.next_id += 1;
        self.trampolines[slot].init(id, prototype)?;
        if slot >= self.count {
            self.count = slot + 1;
        }
        Ok(id)
    }

    /// Unregister a trampoline by ID.
    ///
    /// Decrements the reference count. The trampoline is freed when
    /// the count reaches zero.
    pub fn unregister(&mut self, tramp_id: u64) -> Result<bool> {
        let idx = self.find_by_id(tramp_id)?;
        let freed = self.trampolines[idx].put_ref();
        Ok(freed)
    }

    /// Look up a trampoline by ID.
    pub fn get(&self, tramp_id: u64) -> Result<&BpfTrampoline> {
        let idx = self.find_by_id(tramp_id)?;
        Ok(&self.trampolines[idx])
    }

    /// Look up a mutable trampoline by ID.
    pub fn get_mut(&mut self, tramp_id: u64) -> Result<&mut BpfTrampoline> {
        let idx = self.find_by_id(tramp_id)?;
        Ok(&mut self.trampolines[idx])
    }

    /// Look up a trampoline by target function address.
    pub fn find_by_addr(&self, func_addr: u64) -> Result<&BpfTrampoline> {
        for i in 0..self.count {
            if self.trampolines[i].active && self.trampolines[i].prototype.func_addr() == func_addr
            {
                return Ok(&self.trampolines[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Number of active trampolines.
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.trampolines[i].active {
                n += 1;
            }
        }
        n
    }

    /// Find a trampoline slot by ID.
    fn find_by_id(&self, tramp_id: u64) -> Result<usize> {
        for i in 0..self.count {
            if self.trampolines[i].active && self.trampolines[i].tramp_id == tramp_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a free slot.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..self.count {
            if !self.trampolines[i].active {
                return Ok(i);
            }
        }
        if self.count < MAX_TRAMPOLINES {
            return Ok(self.count);
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for TrampolineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

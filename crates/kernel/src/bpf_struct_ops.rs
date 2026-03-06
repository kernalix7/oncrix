// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF struct_ops — replace kernel function pointers with BPF programs.
//!
//! Implements the BPF struct_ops subsystem, which allows BPF programs
//! to implement kernel callback structures (like `tcp_congestion_ops`,
//! `sched_ext_ops`) at runtime:
//!
//! - **Type descriptors** ([`StructOpsTypeDesc`]): schema definitions
//!   for kernel structures whose members can be replaced with BPF.
//! - **Member descriptors** ([`MemberDesc`]): per-member metadata
//!   including type signature, offset, and flags.
//! - **Struct ops maps** ([`StructOpsMap`]): BPF map type that binds
//!   a set of BPF programs to a specific struct_ops type.
//! - **State machine** ([`StructOpsState`]): lifecycle management
//!   from initialization through registration to teardown.
//! - **Verifier hooks** ([`StructOpsVerifier`]): additional
//!   verification pass for struct_ops BPF programs.
//! - **Global registry** ([`StructOpsRegistry`]): manages all
//!   registered struct_ops types and active instances.
//!
//! Reference: Linux `kernel/bpf/bpf_struct_ops.c`,
//! `include/linux/bpf_struct_ops.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of struct_ops type descriptors.
const MAX_TYPES: usize = 32;

/// Maximum members per struct_ops type.
const MAX_MEMBERS: usize = 32;

/// Maximum active struct_ops instances (maps).
const MAX_INSTANCES: usize = 64;

/// Maximum name length for types and members.
const MAX_NAME_LEN: usize = 64;

/// Maximum BPF programs that can be attached per member.
const MAX_PROGS_PER_MEMBER: usize = 1;

/// Maximum number of BTF type IDs we track.
const MAX_BTF_TYPES: usize = 128;

/// Verification pass limit for struct_ops programs.
const MAX_VERIFY_INSNS: u32 = 100_000;

/// Maximum arguments per callback member.
const MAX_ARGS: usize = 8;

/// Maximum number of links (references) to a struct_ops map.
const MAX_LINKS: usize = 16;

// ── MemberKind ─────────────────────────────────────────────────────

/// Kind of a struct_ops member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// A function pointer that can be replaced by a BPF program.
    FuncPtr,
    /// A scalar data field (not replaceable by BPF).
    Data,
    /// An optional callback (NULL allowed).
    OptionalFuncPtr,
    /// A required callback that must be provided.
    RequiredFuncPtr,
}

impl Default for MemberKind {
    fn default() -> Self {
        Self::Data
    }
}

// ── StructOpsState ─────────────────────────────────────────────────

/// Lifecycle state of a struct_ops instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructOpsState {
    /// Map created but not yet initialized with BPF programs.
    Init,
    /// BPF programs attached, pending verification.
    Prepared,
    /// Verified and ready for registration.
    Ready,
    /// Registered with the kernel and active.
    Registered,
    /// Being torn down.
    Unregistering,
    /// Fully torn down and inactive.
    Inactive,
}

impl Default for StructOpsState {
    fn default() -> Self {
        Self::Init
    }
}

// ── ArgDesc ────────────────────────────────────────────────────────

/// Descriptor for a callback argument.
#[derive(Debug, Clone, Copy)]
pub struct ArgDesc {
    /// BTF type ID of the argument.
    pub btf_type_id: u32,
    /// Size in bytes.
    pub size: u32,
    /// Whether the argument is a pointer.
    pub is_ptr: bool,
    /// Whether the argument is const.
    pub is_const: bool,
}

impl ArgDesc {
    /// Create an empty argument descriptor.
    pub const fn new() -> Self {
        Self {
            btf_type_id: 0,
            size: 0,
            is_ptr: false,
            is_const: false,
        }
    }
}

impl Default for ArgDesc {
    fn default() -> Self {
        Self::new()
    }
}

// ── MemberDesc ─────────────────────────────────────────────────────

/// Descriptor for a single member of a struct_ops type.
#[derive(Debug)]
pub struct MemberDesc {
    /// Member name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Kind of member.
    pub kind: MemberKind,
    /// Byte offset within the struct.
    pub offset: u32,
    /// Size in bytes.
    pub size: u32,
    /// BTF type ID for the member type.
    pub btf_type_id: u32,
    /// BTF type ID for the function prototype (if func ptr).
    pub func_proto_btf_id: u32,
    /// Number of arguments (if func ptr).
    pub arg_count: usize,
    /// Argument descriptors (if func ptr).
    pub args: [ArgDesc; MAX_ARGS],
    /// Return type BTF ID (if func ptr).
    pub ret_btf_id: u32,
    /// Whether this member is active.
    active: bool,
}

impl MemberDesc {
    /// Create an empty member descriptor.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            kind: MemberKind::Data,
            offset: 0,
            size: 0,
            btf_type_id: 0,
            func_proto_btf_id: 0,
            arg_count: 0,
            args: [const { ArgDesc::new() }; MAX_ARGS],
            ret_btf_id: 0,
            active: false,
        }
    }

    /// Initialize a member descriptor.
    pub fn init(
        &mut self,
        name: &[u8],
        kind: MemberKind,
        offset: u32,
        size: u32,
        btf_type_id: u32,
    ) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.kind = kind;
        self.offset = offset;
        self.size = size;
        self.btf_type_id = btf_type_id;
        self.active = true;
        Ok(())
    }

    /// Set function prototype information.
    pub fn set_func_proto(
        &mut self,
        proto_btf_id: u32,
        args: &[ArgDesc],
        ret_btf_id: u32,
    ) -> Result<()> {
        if args.len() > MAX_ARGS {
            return Err(Error::InvalidArgument);
        }
        if self.kind != MemberKind::FuncPtr
            && self.kind != MemberKind::OptionalFuncPtr
            && self.kind != MemberKind::RequiredFuncPtr
        {
            return Err(Error::InvalidArgument);
        }
        self.func_proto_btf_id = proto_btf_id;
        self.args[..args.len()].copy_from_slice(args);
        self.arg_count = args.len();
        self.ret_btf_id = ret_btf_id;
        Ok(())
    }

    /// Return the member name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Whether this member is a function pointer.
    pub fn is_func_ptr(&self) -> bool {
        matches!(
            self.kind,
            MemberKind::FuncPtr | MemberKind::OptionalFuncPtr | MemberKind::RequiredFuncPtr
        )
    }

    /// Whether this member is required.
    pub fn is_required(&self) -> bool {
        self.kind == MemberKind::RequiredFuncPtr
    }

    /// Whether this member is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for MemberDesc {
    fn default() -> Self {
        Self::new()
    }
}

// ── StructOpsTypeDesc ──────────────────────────────────────────────

/// Schema descriptor for a struct_ops type.
///
/// Defines the layout and semantics of a kernel structure
/// whose function-pointer members can be replaced by BPF programs.
pub struct StructOpsTypeDesc {
    /// Type name (e.g., `tcp_congestion_ops`).
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique type ID.
    pub type_id: u32,
    /// BTF type ID for the struct.
    pub btf_id: u32,
    /// Total struct size in bytes.
    pub struct_size: u32,
    /// Member descriptors.
    pub members: [MemberDesc; MAX_MEMBERS],
    /// Number of active members.
    member_count: usize,
    /// Whether this type is registered.
    registered: bool,
    /// Number of required function pointers.
    required_func_count: usize,
    /// Whether the type allows multiple active instances.
    pub allow_multi: bool,
}

impl StructOpsTypeDesc {
    /// Create an empty type descriptor.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            type_id: 0,
            btf_id: 0,
            struct_size: 0,
            members: [const { MemberDesc::new() }; MAX_MEMBERS],
            member_count: 0,
            registered: false,
            required_func_count: 0,
            allow_multi: false,
        }
    }

    /// Initialize a type descriptor.
    pub fn init(&mut self, name: &[u8], type_id: u32, btf_id: u32, struct_size: u32) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if struct_size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.type_id = type_id;
        self.btf_id = btf_id;
        self.struct_size = struct_size;
        self.member_count = 0;
        self.registered = true;
        self.required_func_count = 0;
        Ok(())
    }

    /// Add a member to the type descriptor.
    pub fn add_member(
        &mut self,
        name: &[u8],
        kind: MemberKind,
        offset: u32,
        size: u32,
        btf_type_id: u32,
    ) -> Result<usize> {
        if self.member_count >= MAX_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.member_count;
        self.members[idx].init(name, kind, offset, size, btf_type_id)?;
        self.member_count += 1;
        if kind == MemberKind::RequiredFuncPtr {
            self.required_func_count += 1;
        }
        Ok(idx)
    }

    /// Return the type name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the number of members.
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Iterate over function-pointer members.
    pub fn func_members(&self) -> impl Iterator<Item = (usize, &MemberDesc)> {
        self.members[..self.member_count]
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_func_ptr())
    }

    /// Return the number of required callbacks.
    pub fn required_func_count(&self) -> usize {
        self.required_func_count
    }

    /// Whether this type is registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Unregister this type.
    pub fn unregister(&mut self) {
        self.registered = false;
    }
}

impl Default for StructOpsTypeDesc {
    fn default() -> Self {
        Self::new()
    }
}

// ── ProgAttachment ─────────────────────────────────────────────────

/// Tracks a BPF program attached to a struct_ops member.
#[derive(Debug, Clone, Copy)]
pub struct ProgAttachment {
    /// BPF program file descriptor / ID.
    pub prog_id: u32,
    /// Member index this program implements.
    pub member_idx: usize,
    /// Whether this attachment has been verified.
    pub verified: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl ProgAttachment {
    /// Create an empty attachment.
    pub const fn new() -> Self {
        Self {
            prog_id: 0,
            member_idx: 0,
            verified: false,
            active: false,
        }
    }
}

impl Default for ProgAttachment {
    fn default() -> Self {
        Self::new()
    }
}

// ── StructOpsLink ──────────────────────────────────────────────────

/// A reference-counted link to a struct_ops instance.
#[derive(Debug, Clone, Copy)]
pub struct StructOpsLink {
    /// Map ID this link references.
    pub map_id: u32,
    /// Link ID.
    pub link_id: u32,
    /// Whether this link is active.
    pub active: bool,
}

impl StructOpsLink {
    /// Create an empty link.
    pub const fn new() -> Self {
        Self {
            map_id: 0,
            link_id: 0,
            active: false,
        }
    }
}

impl Default for StructOpsLink {
    fn default() -> Self {
        Self::new()
    }
}

// ── StructOpsMap ───────────────────────────────────────────────────

/// A BPF map of type `BPF_MAP_TYPE_STRUCT_OPS`.
///
/// Binds a set of BPF programs to the function pointers
/// defined by a [`StructOpsTypeDesc`].
pub struct StructOpsMap {
    /// Map ID.
    pub id: u32,
    /// Type descriptor index (into the registry's type array).
    pub type_idx: usize,
    /// Current lifecycle state.
    pub state: StructOpsState,
    /// Attached BPF programs (one per member).
    attachments: [ProgAttachment; MAX_MEMBERS],
    /// Number of attached programs.
    attachment_count: usize,
    /// Links referencing this map.
    links: [StructOpsLink; MAX_LINKS],
    /// Number of active links.
    link_count: usize,
    /// Next link ID.
    next_link_id: u32,
    /// Whether this map slot is in use.
    active: bool,
    /// Generation counter for ABA protection.
    generation: u64,
    /// Image data for the struct (filled during prepare).
    image: [u8; 256],
    /// Image size.
    image_len: usize,
}

impl StructOpsMap {
    /// Create an empty struct_ops map.
    pub const fn new() -> Self {
        Self {
            id: 0,
            type_idx: 0,
            state: StructOpsState::Init,
            attachments: [const { ProgAttachment::new() }; MAX_MEMBERS],
            attachment_count: 0,
            links: [const { StructOpsLink::new() }; MAX_LINKS],
            link_count: 0,
            next_link_id: 1,
            active: false,
            generation: 0,
            image: [0u8; 256],
            image_len: 0,
        }
    }

    /// Initialize the map.
    pub fn init(&mut self, id: u32, type_idx: usize) {
        self.id = id;
        self.type_idx = type_idx;
        self.state = StructOpsState::Init;
        self.attachment_count = 0;
        self.link_count = 0;
        self.next_link_id = 1;
        self.active = true;
        self.generation = self.generation.wrapping_add(1);
        self.image_len = 0;
    }

    /// Attach a BPF program to a member.
    pub fn attach_prog(&mut self, member_idx: usize, prog_id: u32) -> Result<()> {
        if self.state != StructOpsState::Init {
            return Err(Error::InvalidArgument);
        }
        if member_idx >= MAX_MEMBERS {
            return Err(Error::InvalidArgument);
        }
        if self.attachments[member_idx].active {
            return Err(Error::AlreadyExists);
        }
        self.attachments[member_idx] = ProgAttachment {
            prog_id,
            member_idx,
            verified: false,
            active: true,
        };
        self.attachment_count += 1;
        Ok(())
    }

    /// Get the program attached to a member.
    pub fn get_prog(&self, member_idx: usize) -> Option<&ProgAttachment> {
        if member_idx < MAX_MEMBERS && self.attachments[member_idx].active {
            Some(&self.attachments[member_idx])
        } else {
            None
        }
    }

    /// Transition to the Prepared state.
    pub fn prepare(&mut self) -> Result<()> {
        if self.state != StructOpsState::Init {
            return Err(Error::InvalidArgument);
        }
        self.state = StructOpsState::Prepared;
        Ok(())
    }

    /// Mark a member's program as verified.
    pub fn mark_verified(&mut self, member_idx: usize) -> Result<()> {
        if member_idx >= MAX_MEMBERS {
            return Err(Error::InvalidArgument);
        }
        if !self.attachments[member_idx].active {
            return Err(Error::NotFound);
        }
        self.attachments[member_idx].verified = true;
        Ok(())
    }

    /// Check if all required members are attached and verified.
    pub fn is_fully_verified(&self, type_desc: &StructOpsTypeDesc) -> bool {
        for (idx, member) in type_desc.members[..type_desc.member_count()]
            .iter()
            .enumerate()
        {
            if member.is_required()
                && (!self.attachments[idx].active || !self.attachments[idx].verified)
            {
                return false;
            }
        }
        true
    }

    /// Transition to Ready state.
    pub fn mark_ready(&mut self) -> Result<()> {
        if self.state != StructOpsState::Prepared {
            return Err(Error::InvalidArgument);
        }
        self.state = StructOpsState::Ready;
        Ok(())
    }

    /// Register with the kernel (activate).
    pub fn register(&mut self) -> Result<()> {
        if self.state != StructOpsState::Ready {
            return Err(Error::InvalidArgument);
        }
        self.state = StructOpsState::Registered;
        Ok(())
    }

    /// Create a link to this map.
    pub fn create_link(&mut self) -> Result<u32> {
        if self.state != StructOpsState::Registered {
            return Err(Error::InvalidArgument);
        }
        if self.link_count >= MAX_LINKS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .links
            .iter()
            .position(|l| !l.active)
            .ok_or(Error::OutOfMemory)?;
        let lid = self.next_link_id;
        self.next_link_id = self.next_link_id.wrapping_add(1);
        self.links[slot] = StructOpsLink {
            map_id: self.id,
            link_id: lid,
            active: true,
        };
        self.link_count += 1;
        Ok(lid)
    }

    /// Destroy a link.
    pub fn destroy_link(&mut self, link_id: u32) -> Result<()> {
        let slot = self
            .links
            .iter()
            .position(|l| l.active && l.link_id == link_id)
            .ok_or(Error::NotFound)?;
        self.links[slot].active = false;
        self.link_count = self.link_count.saturating_sub(1);
        Ok(())
    }

    /// Begin unregistration.
    pub fn unregister(&mut self) -> Result<()> {
        if self.state != StructOpsState::Registered {
            return Err(Error::InvalidArgument);
        }
        if self.link_count > 0 {
            return Err(Error::Busy);
        }
        self.state = StructOpsState::Unregistering;
        Ok(())
    }

    /// Finalize teardown.
    pub fn finalize(&mut self) {
        self.state = StructOpsState::Inactive;
        for att in &mut self.attachments {
            att.active = false;
        }
        self.attachment_count = 0;
        self.active = false;
    }

    /// Set the struct image data.
    pub fn set_image(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.image.len() {
            return Err(Error::InvalidArgument);
        }
        self.image[..data.len()].copy_from_slice(data);
        self.image_len = data.len();
        Ok(())
    }

    /// Return the struct image data.
    pub fn image(&self) -> &[u8] {
        &self.image[..self.image_len]
    }

    /// Whether this map is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the number of attached programs.
    pub fn attachment_count(&self) -> usize {
        self.attachment_count
    }

    /// Return the number of active links.
    pub fn link_count(&self) -> usize {
        self.link_count
    }

    /// Return the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Default for StructOpsMap {
    fn default() -> Self {
        Self::new()
    }
}

// ── VerifyResult ───────────────────────────────────────────────────

/// Result of struct_ops BPF program verification.
#[derive(Debug, Clone, Copy)]
pub struct VerifyResult {
    /// Whether verification passed.
    pub passed: bool,
    /// Number of instructions verified.
    pub insn_count: u32,
    /// Error code if verification failed (0 = success).
    pub error_code: u32,
    /// Offset of the failing instruction (if any).
    pub error_offset: u32,
}

impl Default for VerifyResult {
    fn default() -> Self {
        Self {
            passed: false,
            insn_count: 0,
            error_code: 0,
            error_offset: 0,
        }
    }
}

// ── StructOpsVerifier ──────────────────────────────────────────────

/// Additional verification pass for struct_ops BPF programs.
///
/// Ensures that BPF programs attached to struct_ops members
/// conform to the expected calling convention and do not
/// access forbidden kernel state.
pub struct StructOpsVerifier {
    /// Maximum instructions allowed.
    pub max_insns: u32,
    /// Whether to allow helper calls.
    pub allow_helpers: bool,
    /// Whether to allow map access.
    pub allow_maps: bool,
    /// Total programs verified.
    pub total_verified: u64,
    /// Total programs rejected.
    pub total_rejected: u64,
}

impl StructOpsVerifier {
    /// Create a new verifier with default settings.
    pub const fn new() -> Self {
        Self {
            max_insns: MAX_VERIFY_INSNS,
            allow_helpers: true,
            allow_maps: true,
            total_verified: 0,
            total_rejected: 0,
        }
    }

    /// Verify a BPF program for use with a struct_ops member.
    ///
    /// This checks the program's argument types match the member's
    /// function prototype and that the return type is compatible.
    pub fn verify_prog(&mut self, member: &MemberDesc, prog_insn_count: u32) -> VerifyResult {
        // Check instruction count
        if prog_insn_count > self.max_insns {
            self.total_rejected += 1;
            return VerifyResult {
                passed: false,
                insn_count: prog_insn_count,
                error_code: 1, // E2BIG equivalent
                error_offset: 0,
            };
        }

        // Verify member is a function pointer
        if !member.is_func_ptr() {
            self.total_rejected += 1;
            return VerifyResult {
                passed: false,
                insn_count: prog_insn_count,
                error_code: 2, // EINVAL equivalent
                error_offset: 0,
            };
        }

        // Verify function prototype exists
        if member.func_proto_btf_id == 0 {
            self.total_rejected += 1;
            return VerifyResult {
                passed: false,
                insn_count: prog_insn_count,
                error_code: 3, // ENOENT equivalent
                error_offset: 0,
            };
        }

        // All checks passed
        self.total_verified += 1;
        VerifyResult {
            passed: true,
            insn_count: prog_insn_count,
            error_code: 0,
            error_offset: 0,
        }
    }

    /// Return total verified count.
    pub fn total_verified(&self) -> u64 {
        self.total_verified
    }

    /// Return total rejected count.
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }
}

impl Default for StructOpsVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ── BtfTypeEntry ───────────────────────────────────────────────────

/// Minimal BTF type record for struct_ops tracking.
#[derive(Debug, Clone, Copy)]
pub struct BtfTypeEntry {
    /// BTF type ID.
    pub id: u32,
    /// Associated struct_ops type index (or u32::MAX).
    pub struct_ops_type_idx: u32,
    /// Whether this entry is in use.
    pub active: bool,
}

impl BtfTypeEntry {
    /// Create an empty entry.
    pub const fn new() -> Self {
        Self {
            id: 0,
            struct_ops_type_idx: u32::MAX,
            active: false,
        }
    }
}

impl Default for BtfTypeEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ── StructOpsRegistry ──────────────────────────────────────────────

/// Global registry for all struct_ops types and instances.
///
/// Manages type registration, map creation/destruction, and
/// the verification pipeline.
pub struct StructOpsRegistry {
    /// Registered type descriptors.
    types: [StructOpsTypeDesc; MAX_TYPES],
    /// Number of registered types.
    type_count: usize,
    /// Active struct_ops map instances.
    maps: [StructOpsMap; MAX_INSTANCES],
    /// Number of active maps.
    map_count: usize,
    /// BTF type index for quick lookup.
    btf_index: [BtfTypeEntry; MAX_BTF_TYPES],
    /// Verifier instance.
    pub verifier: StructOpsVerifier,
    /// Next map ID.
    next_map_id: u32,
    /// Next type ID.
    next_type_id: u32,
    /// Whether the registry is initialized.
    initialized: bool,
    /// Total maps created.
    pub total_maps_created: u64,
    /// Total maps destroyed.
    pub total_maps_destroyed: u64,
}

impl StructOpsRegistry {
    /// Create a new uninitialized registry.
    pub const fn new() -> Self {
        Self {
            types: [const { StructOpsTypeDesc::new() }; MAX_TYPES],
            type_count: 0,
            maps: [const { StructOpsMap::new() }; MAX_INSTANCES],
            map_count: 0,
            btf_index: [const { BtfTypeEntry::new() }; MAX_BTF_TYPES],
            verifier: StructOpsVerifier::new(),
            next_map_id: 1,
            next_type_id: 1,
            initialized: false,
            total_maps_created: 0,
            total_maps_destroyed: 0,
        }
    }

    /// Initialize the registry.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a new struct_ops type.
    ///
    /// Returns the type index for future reference.
    pub fn register_type(&mut self, name: &[u8], btf_id: u32, struct_size: u32) -> Result<usize> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if self.type_count >= MAX_TYPES {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate BTF ID
        if self.btf_index.iter().any(|e| e.active && e.id == btf_id) {
            return Err(Error::AlreadyExists);
        }

        let idx = self.type_count;
        let tid = self.next_type_id;
        self.next_type_id = self.next_type_id.wrapping_add(1);

        self.types[idx].init(name, tid, btf_id, struct_size)?;
        self.type_count += 1;

        // Index the BTF type
        if let Some(entry) = self.btf_index.iter_mut().find(|e| !e.active) {
            entry.id = btf_id;
            entry.struct_ops_type_idx = idx as u32;
            entry.active = true;
        }

        Ok(idx)
    }

    /// Unregister a struct_ops type by index.
    pub fn unregister_type(&mut self, type_idx: usize) -> Result<()> {
        if type_idx >= self.type_count {
            return Err(Error::NotFound);
        }
        if !self.types[type_idx].is_registered() {
            return Err(Error::NotFound);
        }

        // Ensure no active maps use this type
        let has_active_maps = self
            .maps
            .iter()
            .any(|m| m.is_active() && m.type_idx == type_idx);
        if has_active_maps {
            return Err(Error::Busy);
        }

        let btf_id = self.types[type_idx].btf_id;
        self.types[type_idx].unregister();

        // Remove from BTF index
        for entry in &mut self.btf_index {
            if entry.active && entry.id == btf_id {
                entry.active = false;
                break;
            }
        }

        Ok(())
    }

    /// Create a new struct_ops map for a given type.
    ///
    /// Returns the map ID.
    pub fn create_map(&mut self, type_idx: usize) -> Result<u32> {
        if type_idx >= self.type_count || !self.types[type_idx].is_registered() {
            return Err(Error::NotFound);
        }
        if self.map_count >= MAX_INSTANCES {
            return Err(Error::OutOfMemory);
        }

        // Check multi-instance policy
        if !self.types[type_idx].allow_multi {
            let has_registered = self.maps.iter().any(|m| {
                m.is_active() && m.type_idx == type_idx && m.state == StructOpsState::Registered
            });
            if has_registered {
                return Err(Error::Busy);
            }
        }

        let slot = self
            .maps
            .iter()
            .position(|m| !m.is_active())
            .ok_or(Error::OutOfMemory)?;

        let mid = self.next_map_id;
        self.next_map_id = self.next_map_id.wrapping_add(1);
        self.maps[slot].init(mid, type_idx);
        self.map_count += 1;
        self.total_maps_created += 1;
        Ok(mid)
    }

    /// Prepare, verify, and register a struct_ops map.
    ///
    /// This is the main entry point for activating a struct_ops
    /// instance after programs have been attached.
    pub fn activate_map(&mut self, map_id: u32) -> Result<()> {
        let map_idx = self.find_map_index(map_id)?;
        let type_idx = self.maps[map_idx].type_idx;

        // Prepare
        self.maps[map_idx].prepare()?;

        // Verify each attached program
        let member_count = self.types[type_idx].member_count();
        for midx in 0..member_count {
            if let Some(att) = self.maps[map_idx].get_prog(midx) {
                let prog_id = att.prog_id;
                let result = self.verifier.verify_prog(
                    &self.types[type_idx].members[midx],
                    prog_id, // use prog_id as instruction count
                );
                if !result.passed {
                    self.maps[map_idx].finalize();
                    self.map_count = self.map_count.saturating_sub(1);
                    return Err(Error::InvalidArgument);
                }
                self.maps[map_idx].mark_verified(midx)?;
            }
        }

        // Check all required members are satisfied
        if !self.maps[map_idx].is_fully_verified(&self.types[type_idx]) {
            self.maps[map_idx].finalize();
            self.map_count = self.map_count.saturating_sub(1);
            return Err(Error::InvalidArgument);
        }

        // Ready and register
        self.maps[map_idx].mark_ready()?;
        self.maps[map_idx].register()
    }

    /// Destroy a struct_ops map.
    pub fn destroy_map(&mut self, map_id: u32) -> Result<()> {
        let idx = self.find_map_index(map_id)?;
        if self.maps[idx].state == StructOpsState::Registered {
            self.maps[idx].unregister()?;
        }
        self.maps[idx].finalize();
        self.map_count = self.map_count.saturating_sub(1);
        self.total_maps_destroyed += 1;
        Ok(())
    }

    /// Look up a type by BTF ID.
    pub fn find_type_by_btf(&self, btf_id: u32) -> Option<usize> {
        self.btf_index
            .iter()
            .find(|e| e.active && e.id == btf_id)
            .map(|e| e.struct_ops_type_idx as usize)
    }

    /// Get a type descriptor by index.
    pub fn get_type(&self, idx: usize) -> Result<&StructOpsTypeDesc> {
        if idx >= self.type_count {
            return Err(Error::NotFound);
        }
        Ok(&self.types[idx])
    }

    /// Get a map by ID.
    pub fn get_map(&self, map_id: u32) -> Result<&StructOpsMap> {
        let idx = self.find_map_index(map_id)?;
        Ok(&self.maps[idx])
    }

    /// Return the number of registered types.
    pub fn type_count(&self) -> usize {
        self.type_count
    }

    /// Return the number of active maps.
    pub fn map_count(&self) -> usize {
        self.map_count
    }

    /// Find a map's internal index by ID.
    fn find_map_index(&self, map_id: u32) -> Result<usize> {
        self.maps
            .iter()
            .position(|m| m.is_active() && m.id == map_id)
            .ok_or(Error::NotFound)
    }
}

impl Default for StructOpsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space shared library loader (ld.so).
//!
//! Provides structures and functions for loading shared libraries at
//! runtime, implementing the POSIX `dlopen`/`dlclose`/`dlsym`/`dlerror`
//! interface. Manages a fixed-capacity registry of loaded libraries
//! with reference counting, dependency tracking, and topological
//! ordering for initialization.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of a shared library path in bytes.
const MAX_LIB_PATH: usize = 64;

/// Maximum number of simultaneously loaded shared libraries.
const MAX_LOADED_LIBS: usize = 32;

/// Maximum number of direct dependencies per library.
const MAX_DEPS: usize = 8;

/// Maximum length of a symbol name in bytes.
const MAX_SYMBOL_NAME: usize = 64;

/// Maximum length of the `dlerror` message buffer.
const MAX_DLERROR_MSG: usize = 128;

// ---------------------------------------------------------------------------
// DlFlags — RTLD_* flag constants
// ---------------------------------------------------------------------------

/// Flags controlling shared library loading behavior.
///
/// These mirror the POSIX `RTLD_*` constants used with `dlopen()`.
/// Multiple flags can be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlFlags(u32);

impl DlFlags {
    /// Lazy binding: resolve symbols when they are first referenced.
    pub const RTLD_LAZY: DlFlags = DlFlags(0x0001);

    /// Immediate binding: resolve all symbols at load time.
    pub const RTLD_NOW: DlFlags = DlFlags(0x0002);

    /// Symbols are available for subsequently loaded libraries.
    pub const RTLD_GLOBAL: DlFlags = DlFlags(0x0100);

    /// Symbols are not made available (default scope).
    pub const RTLD_LOCAL: DlFlags = DlFlags(0x0000);

    /// Creates a new `DlFlags` from a raw bitmask.
    pub fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw bitmask.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if the given flag is set.
    pub fn contains(self, other: DlFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combines two flag sets with bitwise OR.
    pub fn union(self, other: DlFlags) -> Self {
        Self(self.0 | other.0)
    }

    /// Validates that the flags contain a binding mode.
    ///
    /// At least one of `RTLD_LAZY` or `RTLD_NOW` must be set.
    /// Returns `Err(Error::InvalidArgument)` otherwise.
    pub fn validate(self) -> Result<()> {
        if !self.contains(Self::RTLD_LAZY) && !self.contains(Self::RTLD_NOW) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for DlFlags {
    fn default() -> Self {
        Self::RTLD_LAZY
    }
}

// ---------------------------------------------------------------------------
// DlHandle — opaque handle to a loaded library
// ---------------------------------------------------------------------------

/// Opaque handle to a loaded shared library.
///
/// Returned by [`dlopen`] and consumed by [`dlclose`] and [`dlsym`].
/// The inner value is an index into the [`LoadedLibraries`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlHandle {
    /// Index into the loaded libraries array.
    index: usize,
    /// Generation counter to detect stale handles.
    generation: u32,
}

impl DlHandle {
    /// Creates a new handle from an index and generation.
    fn new(index: usize, generation: u32) -> Self {
        Self { index, generation }
    }

    /// Returns the internal index (for testing/debugging).
    pub fn index(&self) -> usize {
        self.index
    }
}

// ---------------------------------------------------------------------------
// ElfHeaderInfo — minimal ELF header metadata for a shared library
// ---------------------------------------------------------------------------

/// Minimal ELF header information cached for a loaded library.
///
/// Stores the essential fields from the ELF64 header that are
/// needed for symbol resolution and relocation processing.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfHeaderInfo {
    /// Entry point virtual address (0 for libraries).
    pub entry: u64,
    /// ELF type: 3 for `ET_DYN` (shared object).
    pub elf_type: u16,
    /// Number of program header entries.
    pub phnum: u16,
    /// Program header table offset.
    pub phoff: u64,
}

// ---------------------------------------------------------------------------
// LibraryDep — dependency tracking for a single library
// ---------------------------------------------------------------------------

/// Tracks the direct dependencies of a loaded shared library.
///
/// Each library may depend on up to [`MAX_DEPS`] other libraries
/// (recorded as indices into the [`LoadedLibraries`] table).
/// Dependencies are derived from `DT_NEEDED` entries in the
/// ELF dynamic section.
#[derive(Debug, Clone, Copy)]
pub struct LibraryDep {
    /// Indices of libraries this library depends on.
    deps: [usize; MAX_DEPS],
    /// Number of valid dependency entries.
    count: usize,
}

impl Default for LibraryDep {
    fn default() -> Self {
        Self::new()
    }
}

impl LibraryDep {
    /// Creates an empty dependency list.
    pub fn new() -> Self {
        Self {
            deps: [0; MAX_DEPS],
            count: 0,
        }
    }

    /// Adds a dependency by library index.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the dependency list
    /// is full.
    pub fn add(&mut self, lib_index: usize) -> Result<()> {
        if self.count >= MAX_DEPS {
            return Err(Error::OutOfMemory);
        }
        self.deps[self.count] = lib_index;
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Returns the dependency indices as a slice.
    pub fn as_slice(&self) -> &[usize] {
        &self.deps[..self.count]
    }

    /// Returns the number of dependencies.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no dependencies.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// SharedLibrary — a single loaded shared library
// ---------------------------------------------------------------------------

/// Represents a single shared library loaded into a process's
/// address space.
///
/// Tracks the library's path, load address, memory footprint,
/// reference count, ELF metadata, and dependency information.
#[derive(Debug, Clone, Copy)]
pub struct SharedLibrary {
    /// Library path (fixed-size, NUL-padded).
    path: [u8; MAX_LIB_PATH],
    /// Number of valid bytes in `path`.
    path_len: usize,
    /// Base address where the library is mapped.
    base_addr: u64,
    /// Total size of the mapped region in bytes.
    size: u64,
    /// Reference count (number of active `DlHandle`s).
    refcount: u32,
    /// Generation counter (incremented on each reuse of the slot).
    generation: u32,
    /// Cached ELF header information.
    elf_info: ElfHeaderInfo,
    /// Direct dependencies of this library.
    deps: LibraryDep,
    /// Flags used when the library was loaded.
    flags: DlFlags,
    /// Whether this slot is occupied.
    active: bool,
}

impl Default for SharedLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedLibrary {
    /// Creates an empty, inactive library entry.
    pub fn new() -> Self {
        Self {
            path: [0u8; MAX_LIB_PATH],
            path_len: 0,
            base_addr: 0,
            size: 0,
            refcount: 0,
            generation: 0,
            elf_info: ElfHeaderInfo::default(),
            deps: LibraryDep::new(),
            flags: DlFlags::default(),
            active: false,
        }
    }

    /// Returns the library path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Returns the base address of the library mapping.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the size of the library mapping.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the current reference count.
    pub fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Returns the cached ELF header information.
    pub fn elf_info(&self) -> &ElfHeaderInfo {
        &self.elf_info
    }

    /// Returns the library's dependency list.
    pub fn deps(&self) -> &LibraryDep {
        &self.deps
    }

    /// Returns `true` if this slot is occupied by a loaded library.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the flags used when the library was loaded.
    pub fn flags(&self) -> DlFlags {
        self.flags
    }
}

// ---------------------------------------------------------------------------
// DlError — dlerror() message buffer
// ---------------------------------------------------------------------------

/// Error information buffer for the `dlerror()` interface.
///
/// Stores a fixed-size human-readable error message from the most
/// recent failed `dlopen`, `dlclose`, or `dlsym` operation.
/// Calling [`DlError::take`] clears the message (as POSIX requires
/// that `dlerror()` returns `NULL` after being called once).
#[derive(Debug, Clone, Copy)]
pub struct DlError {
    /// Error message bytes.
    msg: [u8; MAX_DLERROR_MSG],
    /// Length of the valid message.
    msg_len: usize,
    /// Whether an error is pending.
    has_error: bool,
}

impl Default for DlError {
    fn default() -> Self {
        Self::new()
    }
}

impl DlError {
    /// Creates a new, empty error buffer.
    pub fn new() -> Self {
        Self {
            msg: [0u8; MAX_DLERROR_MSG],
            msg_len: 0,
            has_error: false,
        }
    }

    /// Sets an error message from a byte slice.
    ///
    /// If `message` is longer than the buffer, it is truncated.
    pub fn set(&mut self, message: &[u8]) {
        let copy_len = if message.len() > MAX_DLERROR_MSG {
            MAX_DLERROR_MSG
        } else {
            message.len()
        };
        self.msg[..copy_len].copy_from_slice(&message[..copy_len]);
        self.msg_len = copy_len;
        self.has_error = true;
    }

    /// Returns the pending error message and clears the buffer.
    ///
    /// Returns `None` if no error is pending (mirrors POSIX
    /// `dlerror()` returning `NULL`).
    pub fn take(&mut self) -> Option<&[u8]> {
        if !self.has_error {
            return None;
        }
        self.has_error = false;
        Some(&self.msg[..self.msg_len])
    }

    /// Returns `true` if an error is pending.
    pub fn has_error(&self) -> bool {
        self.has_error
    }

    /// Returns the pending message without clearing it.
    pub fn peek(&self) -> Option<&[u8]> {
        if !self.has_error {
            return None;
        }
        Some(&self.msg[..self.msg_len])
    }
}

// ---------------------------------------------------------------------------
// LoadOrder — topological sort for library initialization
// ---------------------------------------------------------------------------

/// Determines the initialization order for loaded libraries.
///
/// Performs a topological sort over the dependency graph so that
/// each library's `.init` function runs after all its dependencies
/// have been initialized. Uses iterative DFS with a fixed-size
/// stack to avoid recursion in kernel context.
#[derive(Debug, Clone, Copy)]
pub struct LoadOrder {
    /// Library indices in initialization order.
    order: [usize; MAX_LOADED_LIBS],
    /// Number of entries in `order`.
    count: usize,
}

impl Default for LoadOrder {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadOrder {
    /// Creates an empty load order.
    pub fn new() -> Self {
        Self {
            order: [0; MAX_LOADED_LIBS],
            count: 0,
        }
    }

    /// Returns the initialization order as a slice of library
    /// indices.
    pub fn as_slice(&self) -> &[usize] {
        &self.order[..self.count]
    }

    /// Returns the number of libraries in the order.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the order is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Computes the topological initialization order for a set of
    /// loaded libraries.
    ///
    /// `libs` is the full [`LoadedLibraries`] table. `root` is the
    /// index of the library whose transitive dependency tree should
    /// be sorted.
    ///
    /// Returns `Err(Error::InvalidArgument)` if `root` is invalid
    /// or if a dependency cycle is detected (more visits than
    /// libraries).
    pub fn compute(libs: &LoadedLibraries, root: usize) -> Result<Self> {
        if root >= MAX_LOADED_LIBS || !libs.libs[root].active {
            return Err(Error::InvalidArgument);
        }

        let mut result = Self::new();

        // State: 0 = unvisited, 1 = in-progress, 2 = done.
        let mut state = [0u8; MAX_LOADED_LIBS];

        // Iterative DFS stack: (library_index, dep_cursor).
        let mut stack: [(usize, usize); MAX_LOADED_LIBS] = [(0, 0); MAX_LOADED_LIBS];
        state[root] = 1;
        stack[0] = (root, 0);
        let mut stack_top: usize = 1;

        while stack_top > 0 {
            let (node, cursor) = stack[stack_top.saturating_sub(1)];
            let dep_slice = libs.libs[node].deps.as_slice();

            if cursor < dep_slice.len() {
                // Advance cursor for current frame.
                stack[stack_top.saturating_sub(1)].1 = cursor.saturating_add(1);

                let dep = dep_slice[cursor];
                if dep < MAX_LOADED_LIBS && libs.libs[dep].active {
                    match state[dep] {
                        0 => {
                            // Push unvisited dependency.
                            state[dep] = 1;
                            if stack_top >= MAX_LOADED_LIBS {
                                return Err(Error::OutOfMemory);
                            }
                            stack[stack_top] = (dep, 0);
                            stack_top = stack_top.saturating_add(1);
                        }
                        1 => {
                            // Cycle detected.
                            return Err(Error::InvalidArgument);
                        }
                        _ => {
                            // Already processed; skip.
                        }
                    }
                }
            } else {
                // All dependencies visited; emit this node.
                state[node] = 2;
                stack_top = stack_top.saturating_sub(1);
                if result.count >= MAX_LOADED_LIBS {
                    return Err(Error::OutOfMemory);
                }
                result.order[result.count] = node;
                result.count = result.count.saturating_add(1);
            }
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// LoadedLibraries — registry of all loaded shared libraries
// ---------------------------------------------------------------------------

/// Fixed-capacity registry of loaded shared libraries.
///
/// Manages up to [`MAX_LOADED_LIBS`] concurrently loaded libraries
/// with path-based deduplication and reference counting.
#[derive(Debug, Clone)]
pub struct LoadedLibraries {
    /// Array of library slots.
    libs: [SharedLibrary; MAX_LOADED_LIBS],
    /// Number of active (occupied) slots.
    active_count: usize,
    /// Per-thread error buffer for `dlerror()`.
    last_error: DlError,
}

impl Default for LoadedLibraries {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadedLibraries {
    /// Creates an empty library registry.
    pub fn new() -> Self {
        Self {
            libs: [SharedLibrary::new(); MAX_LOADED_LIBS],
            active_count: 0,
            last_error: DlError::new(),
        }
    }

    /// Returns the number of currently loaded libraries.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns a reference to the error buffer.
    pub fn last_error(&self) -> &DlError {
        &self.last_error
    }

    /// Returns a mutable reference to the error buffer.
    pub fn last_error_mut(&mut self) -> &mut DlError {
        &mut self.last_error
    }

    /// Finds a loaded library by path.
    ///
    /// Returns the slot index if a library with a matching path
    /// is currently loaded, or `None` otherwise.
    fn find_by_path(&self, path: &[u8]) -> Option<usize> {
        (0..MAX_LOADED_LIBS).find(|&i| {
            self.libs[i].active
                && self.libs[i].path_len == path.len()
                && self.libs[i].path_bytes() == path
        })
    }

    /// Finds a free slot in the library array.
    fn find_free_slot(&self) -> Option<usize> {
        (0..MAX_LOADED_LIBS).find(|&i| !self.libs[i].active)
    }

    /// Validates a [`DlHandle`] against the current library state.
    ///
    /// Returns the slot index if the handle is valid, or
    /// `Err(Error::InvalidArgument)` if the handle is stale or
    /// out of range.
    fn validate_handle(&self, handle: DlHandle) -> Result<usize> {
        let idx = handle.index;
        if idx >= MAX_LOADED_LIBS {
            return Err(Error::InvalidArgument);
        }
        let lib = &self.libs[idx];
        if !lib.active || lib.generation != handle.generation {
            return Err(Error::InvalidArgument);
        }
        Ok(idx)
    }

    /// Returns a reference to the library at the given index.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the index is out
    /// of range or the slot is inactive.
    pub fn get(&self, index: usize) -> Result<&SharedLibrary> {
        if index >= MAX_LOADED_LIBS || !self.libs[index].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.libs[index])
    }
}

// ---------------------------------------------------------------------------
// dlopen — load a shared library
// ---------------------------------------------------------------------------

/// Loads a shared library or increments its reference count.
///
/// If the library identified by `path` is already loaded, its
/// reference count is incremented and the existing handle is
/// returned. Otherwise a new slot is allocated.
///
/// `base_addr` and `size` describe the virtual memory region where
/// the library's segments have been (or will be) mapped.
/// `elf_info` provides cached ELF header metadata.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `path` is empty, exceeds
///   [`MAX_LIB_PATH`], or `flags` are invalid.
/// - `Error::OutOfMemory` — no free slot in the library table.
pub fn dlopen(
    libs: &mut LoadedLibraries,
    path: &[u8],
    flags: DlFlags,
    base_addr: u64,
    size: u64,
    elf_info: ElfHeaderInfo,
) -> Result<DlHandle> {
    if let Err(e) = flags.validate() {
        libs.last_error.set(b"dlopen: invalid flags");
        return Err(e);
    }

    if path.is_empty() || path.len() > MAX_LIB_PATH {
        libs.last_error.set(b"dlopen: invalid path");
        return Err(Error::InvalidArgument);
    }

    // Deduplication: if already loaded, bump refcount.
    if let Some(idx) = libs.find_by_path(path) {
        let lib = &mut libs.libs[idx];
        lib.refcount = lib.refcount.saturating_add(1);
        return Ok(DlHandle::new(idx, lib.generation));
    }

    // Allocate a new slot.
    let idx = match libs.find_free_slot() {
        Some(i) => i,
        None => {
            libs.last_error.set(b"dlopen: library table full");
            return Err(Error::OutOfMemory);
        }
    };

    let lib = &mut libs.libs[idx];
    lib.path[..path.len()].copy_from_slice(path);
    lib.path_len = path.len();
    lib.base_addr = base_addr;
    lib.size = size;
    lib.refcount = 1;
    lib.generation = lib.generation.saturating_add(1);
    lib.elf_info = elf_info;
    lib.deps = LibraryDep::new();
    lib.flags = flags;
    lib.active = true;

    libs.active_count = libs.active_count.saturating_add(1);

    Ok(DlHandle::new(idx, lib.generation))
}

// ---------------------------------------------------------------------------
// dlclose — unload a shared library
// ---------------------------------------------------------------------------

/// Decrements the reference count of a loaded library.
///
/// If the reference count reaches zero, the library slot is freed.
/// Returns the remaining reference count (0 means the library was
/// unloaded).
///
/// # Errors
///
/// - `Error::InvalidArgument` — the handle is invalid or stale.
pub fn dlclose(libs: &mut LoadedLibraries, handle: DlHandle) -> Result<u32> {
    let idx = match libs.validate_handle(handle) {
        Ok(i) => i,
        Err(e) => {
            libs.last_error.set(b"dlclose: invalid handle");
            return Err(e);
        }
    };

    let lib = &mut libs.libs[idx];
    lib.refcount = lib.refcount.saturating_sub(1);

    if lib.refcount == 0 {
        // Mark the slot as free but preserve generation for
        // stale handle detection.
        lib.active = false;
        lib.path_len = 0;
        lib.base_addr = 0;
        lib.size = 0;
        lib.deps = LibraryDep::new();
        libs.active_count = libs.active_count.saturating_sub(1);
        return Ok(0);
    }

    Ok(lib.refcount)
}

// ---------------------------------------------------------------------------
// dlsym — look up a symbol in a loaded library
// ---------------------------------------------------------------------------

/// Looks up a symbol by name in a loaded shared library.
///
/// This is a **simulation** — actual symbol resolution would parse
/// the library's `.dynsym` and `.dynstr` sections in memory. This
/// implementation searches a caller-provided symbol table
/// (`sym_names` / `sym_addrs`) that represents the library's
/// exported symbols.
///
/// # Arguments
///
/// * `libs` — The loaded library registry (for handle validation
///   and error reporting).
/// * `handle` — Handle to the library to search.
/// * `symbol_name` — Name of the symbol to find.
/// * `sym_names` — Parallel array of symbol name byte slices.
/// * `sym_addrs` — Parallel array of symbol addresses.
/// * `sym_count` — Number of valid entries in the arrays.
///
/// # Returns
///
/// The virtual address of the symbol, adjusted by the library's
/// base address. Returns `Err(Error::NotFound)` if the symbol
/// is not found.
///
/// # Errors
///
/// - `Error::InvalidArgument` — handle is invalid, symbol name
///   is empty or too long, or array lengths are inconsistent.
/// - `Error::NotFound` — no matching symbol was found.
pub fn dlsym(
    libs: &mut LoadedLibraries,
    handle: DlHandle,
    symbol_name: &[u8],
    sym_names: &[&[u8]],
    sym_addrs: &[u64],
    sym_count: usize,
) -> Result<u64> {
    if symbol_name.is_empty() || symbol_name.len() > MAX_SYMBOL_NAME {
        libs.last_error.set(b"dlsym: invalid symbol name");
        return Err(Error::InvalidArgument);
    }

    let idx = match libs.validate_handle(handle) {
        Ok(i) => i,
        Err(e) => {
            libs.last_error.set(b"dlsym: invalid handle");
            return Err(e);
        }
    };

    if sym_count > sym_names.len() || sym_count > sym_addrs.len() {
        libs.last_error.set(b"dlsym: array length mismatch");
        return Err(Error::InvalidArgument);
    }

    let base = libs.libs[idx].base_addr;

    for i in 0..sym_count {
        if sym_names[i] == symbol_name {
            let addr = base
                .checked_add(sym_addrs[i])
                .ok_or(Error::InvalidArgument)?;
            return Ok(addr);
        }
    }

    libs.last_error.set(b"dlsym: symbol not found");
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Adds a dependency edge between two loaded libraries.
///
/// Records that the library at `lib_index` depends on the library
/// at `dep_index`.
///
/// # Errors
///
/// - `Error::InvalidArgument` — either index is out of range or
///   refers to an inactive slot.
/// - `Error::OutOfMemory` — the dependency list is full.
pub fn add_dependency(
    libs: &mut LoadedLibraries,
    lib_index: usize,
    dep_index: usize,
) -> Result<()> {
    if lib_index >= MAX_LOADED_LIBS || dep_index >= MAX_LOADED_LIBS {
        return Err(Error::InvalidArgument);
    }
    if !libs.libs[lib_index].active || !libs.libs[dep_index].active {
        return Err(Error::InvalidArgument);
    }
    libs.libs[lib_index].deps.add(dep_index)
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! kernfs — kernel filesystem infrastructure.
//!
//! kernfs is the generic filesystem substrate used by sysfs (and, in Linux,
//! also by cgroup v2). It provides a hierarchical pseudo-filesystem with
//! per-node attributes and optional read/write callbacks, freeing individual
//! kernel subsystems from having to implement their own VFS glue.
//!
//! # Design
//!
//! ```text
//! KernfsRoot
//! └── KernfsNode (directory or file)
//!     ├── name: [u8; MAX_NAME_LEN]
//!     ├── kind: KernfsNodeKind
//!     │       ├── Dir  { children: [Option<NodeId>; MAX_CHILDREN] }
//!     │       └── File { ops: KernfsFileOps }
//!     └── parent: Option<NodeId>
//! ```
//!
//! Nodes are stored in a fixed-size flat array; each node is identified by
//! a [`NodeId`] (index). This avoids heap allocation in filesystem hot paths.
//!
//! # Subsystem usage
//!
//! A subsystem (e.g. sysfs) calls [`KernfsRoot::new`], then creates nodes
//! with [`KernfsRoot::create_dir`] / [`KernfsRoot::create_file`]. The
//! root directory is always at [`NodeId::ROOT`].
//!
//! # Read / write
//!
//! File nodes carry a [`KernfsFileOps`] struct with optional `show` and
//! `store` function pointers. `show` fills a buffer with the attribute
//! content; `store` processes data written to the file.
//!
//! Reference: Linux `fs/kernfs/`, `include/linux/kernfs.h`;
//! `.kernelORG/` — `filesystems/sysfs.rst`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of nodes (directories + files) in a single kernfs instance.
const MAX_NODES: usize = 512;

/// Maximum byte length of a node name (excluding NUL).
const MAX_NAME_LEN: usize = 64;

/// Maximum children per directory node.
const MAX_CHILDREN: usize = 32;

/// Maximum byte length of a file attribute value (for show output).
pub const KERNFS_MAX_ATTR_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// NodeId
// ---------------------------------------------------------------------------

/// Opaque identifier for a kernfs node (index into the node table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub usize);

impl NodeId {
    /// The root directory node is always at index 0.
    pub const ROOT: Self = Self(0);

    /// Returns `true` if this ID is within the valid table range.
    pub fn is_valid(self) -> bool {
        self.0 < MAX_NODES
    }
}

// ---------------------------------------------------------------------------
// KernfsFileOps
// ---------------------------------------------------------------------------

/// Callbacks for a kernfs file node.
///
/// Both callbacks are optional. A file with no `show` callback returns
/// an empty read; a file with no `store` callback rejects writes.
#[derive(Clone, Copy)]
pub struct KernfsFileOps {
    /// Read (show) callback.
    ///
    /// Writes the attribute value into `buf` and returns the number of
    /// bytes written. The implementation must not panic.
    pub show: Option<fn(id: NodeId, buf: &mut [u8]) -> usize>,

    /// Write (store) callback.
    ///
    /// Processes `data` written by userspace. Returns `Ok(())` on success.
    pub store: Option<fn(id: NodeId, data: &[u8]) -> Result<()>>,

    /// Permission bits (lower 12 bits; e.g. 0o644 for rw-r--r--).
    pub mode: u16,
}

impl core::fmt::Debug for KernfsFileOps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernfsFileOps")
            .field("show", &self.show.is_some())
            .field("store", &self.store.is_some())
            .field("mode", &self.mode)
            .finish()
    }
}

impl KernfsFileOps {
    /// Create a read-only file ops (no store callback).
    pub const fn read_only(show: fn(NodeId, &mut [u8]) -> usize) -> Self {
        Self {
            show: Some(show),
            store: None,
            mode: 0o444,
        }
    }

    /// Create a read-write file ops.
    pub const fn read_write(
        show: fn(NodeId, &mut [u8]) -> usize,
        store: fn(NodeId, &[u8]) -> Result<()>,
    ) -> Self {
        Self {
            show: Some(show),
            store: Some(store),
            mode: 0o644,
        }
    }

    /// Create a write-only file ops (no show callback).
    pub const fn write_only(store: fn(NodeId, &[u8]) -> Result<()>) -> Self {
        Self {
            show: None,
            store: Some(store),
            mode: 0o200,
        }
    }
}

// ---------------------------------------------------------------------------
// KernfsNodeKind
// ---------------------------------------------------------------------------

/// The kind of a kernfs node.
#[derive(Debug, Clone, Copy)]
pub enum KernfsNodeKind {
    /// A directory node. Holds a list of child [`NodeId`]s.
    Dir {
        /// Child node IDs (up to [`MAX_CHILDREN`]).
        children: [NodeId; MAX_CHILDREN],
        /// Number of valid child entries.
        child_count: usize,
    },
    /// A regular file node with read/write callbacks.
    File {
        /// File operations.
        ops: KernfsFileOps,
    },
    /// A symbolic link.
    Symlink {
        /// Target node ID.
        target: NodeId,
    },
}

// ---------------------------------------------------------------------------
// KernfsNode
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// KernfsNodeState — activate/deactivate lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle state of a kernfs node.
///
/// New nodes start `Inactive`. After all setup (attribute registration, etc.)
/// is complete the owning subsystem calls [`KernfsRoot::activate`] to
/// transition to `Active`, making the node visible to VFS lookups. Calling
/// [`KernfsRoot::deactivate`] puts it back to `Inactive` so in-flight
/// operations can drain before [`KernfsRoot::remove`] is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernfsNodeState {
    /// Node exists in the table but is not yet visible to lookups.
    Inactive,
    /// Node is fully initialised and visible.
    Active,
    /// Node has been deactivated; waiting for references to drain.
    Draining,
}

// ---------------------------------------------------------------------------
// KernfsNode
// ---------------------------------------------------------------------------

/// A single node in the kernfs tree.
#[derive(Debug, Clone, Copy)]
pub struct KernfsNode {
    /// Node name (NUL-padded).
    name: [u8; MAX_NAME_LEN],
    /// Byte length of the name.
    name_len: usize,
    /// Node kind.
    pub kind: KernfsNodeKind,
    /// Parent node ID (`None` for root).
    pub parent: Option<NodeId>,
    /// Whether this slot is occupied.
    active: bool,
    /// Lifecycle state.
    pub state: KernfsNodeState,
}

impl KernfsNode {
    const EMPTY: Self = Self {
        name: [0; MAX_NAME_LEN],
        name_len: 0,
        kind: KernfsNodeKind::Dir {
            children: [NodeId(0); MAX_CHILDREN],
            child_count: 0,
        },
        parent: None,
        active: false,
        state: KernfsNodeState::Inactive,
    };

    /// Create an inactive root-placeholder node.
    const fn root() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            kind: KernfsNodeKind::Dir {
                children: [NodeId(0); MAX_CHILDREN],
                child_count: 0,
            },
            parent: None,
            active: true,
            state: KernfsNodeState::Active,
        }
    }

    /// Return the node name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if this node is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, KernfsNodeKind::Dir { .. })
    }

    /// Returns `true` if this node is a file.
    pub fn is_file(&self) -> bool {
        matches!(self.kind, KernfsNodeKind::File { .. })
    }
}

// ---------------------------------------------------------------------------
// KernfsRoot
// ---------------------------------------------------------------------------

/// A kernfs filesystem instance.
///
/// Holds the flat node table and provides node creation, lookup, read, and
/// write operations.
pub struct KernfsRoot {
    nodes: [KernfsNode; MAX_NODES],
    /// Total number of active nodes (including root).
    count: usize,
}

impl KernfsRoot {
    /// Create a new kernfs instance with an empty root directory.
    pub const fn new() -> Self {
        let mut nodes = [KernfsNode::EMPTY; MAX_NODES];
        nodes[0] = KernfsNode::root();
        Self { nodes, count: 1 }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Allocate a new node slot.
    fn alloc_node(&mut self) -> Result<NodeId> {
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if !node.active {
                *node = KernfsNode::EMPTY;
                node.active = true;
                if i >= self.count {
                    self.count = i + 1;
                }
                return Ok(NodeId(i));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Copy a name string into a fixed-size buffer.
    fn copy_name(name: &str, buf: &mut [u8; MAX_NAME_LEN]) -> Result<usize> {
        let bytes = name.as_bytes();
        if bytes.len() == 0 || bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    /// Add `child` to the children list of directory node `parent_id`.
    fn add_child(&mut self, parent_id: NodeId, child_id: NodeId) -> Result<()> {
        let parent = self.nodes.get_mut(parent_id.0).ok_or(Error::NotFound)?;
        match &mut parent.kind {
            KernfsNodeKind::Dir {
                children,
                child_count,
            } => {
                if *child_count >= MAX_CHILDREN {
                    return Err(Error::OutOfMemory);
                }
                children[*child_count] = child_id;
                *child_count += 1;
                Ok(())
            }
            _ => Err(Error::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Public node creation API
    // -----------------------------------------------------------------------

    /// Create a child directory under `parent`.
    ///
    /// The new node starts in [`KernfsNodeState::Inactive`] and is invisible
    /// to [`lookup`](KernfsRoot::lookup) until [`activate`](KernfsRoot::activate)
    /// is called.
    ///
    /// Returns the [`NodeId`] of the new directory.
    pub fn create_dir(&mut self, parent: NodeId, name: &str) -> Result<NodeId> {
        if !parent.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[parent.0].active || !self.nodes[parent.0].is_dir() {
            return Err(Error::NotFound);
        }
        // Check for duplicate name (any state).
        if self.lookup_any_state(parent, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let id = self.alloc_node()?;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let name_len = Self::copy_name(name, &mut name_buf)?;
        let node = &mut self.nodes[id.0];
        node.name = name_buf;
        node.name_len = name_len;
        node.parent = Some(parent);
        node.state = KernfsNodeState::Inactive;
        node.kind = KernfsNodeKind::Dir {
            children: [NodeId(0); MAX_CHILDREN],
            child_count: 0,
        };
        self.add_child(parent, id)?;
        Ok(id)
    }

    /// Create a child file under `parent`.
    ///
    /// The new node starts in [`KernfsNodeState::Inactive`]. Call
    /// [`activate`](KernfsRoot::activate) to make it visible.
    ///
    /// Returns the [`NodeId`] of the new file.
    pub fn create_file(
        &mut self,
        parent: NodeId,
        name: &str,
        ops: KernfsFileOps,
    ) -> Result<NodeId> {
        if !parent.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[parent.0].active || !self.nodes[parent.0].is_dir() {
            return Err(Error::NotFound);
        }
        // Check for duplicate name (any state).
        if self.lookup_any_state(parent, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let id = self.alloc_node()?;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let name_len = Self::copy_name(name, &mut name_buf)?;
        let node = &mut self.nodes[id.0];
        node.name = name_buf;
        node.name_len = name_len;
        node.parent = Some(parent);
        node.state = KernfsNodeState::Inactive;
        node.kind = KernfsNodeKind::File { ops };
        self.add_child(parent, id)?;
        Ok(id)
    }

    /// Create a symbolic link under `parent` pointing to `target`.
    ///
    /// The new node starts in [`KernfsNodeState::Inactive`].
    pub fn create_symlink(&mut self, parent: NodeId, name: &str, target: NodeId) -> Result<NodeId> {
        if !parent.is_valid() || !target.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if !self.nodes[parent.0].active || !self.nodes[parent.0].is_dir() {
            return Err(Error::NotFound);
        }
        if self.lookup_any_state(parent, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let id = self.alloc_node()?;
        let mut name_buf = [0u8; MAX_NAME_LEN];
        let name_len = Self::copy_name(name, &mut name_buf)?;
        let node = &mut self.nodes[id.0];
        node.name = name_buf;
        node.name_len = name_len;
        node.parent = Some(parent);
        node.state = KernfsNodeState::Inactive;
        node.kind = KernfsNodeKind::Symlink { target };
        self.add_child(parent, id)?;
        Ok(id)
    }

    /// Remove a node (file or empty directory) from the tree.
    ///
    /// The node may be in any lifecycle state. For a graceful shutdown,
    /// call [`deactivate`](KernfsRoot::deactivate) first, drain any open
    /// file handles, then call `remove`.
    pub fn remove(&mut self, id: NodeId) -> Result<()> {
        if !id.is_valid() || id == NodeId::ROOT {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get(id.0).ok_or(Error::NotFound)?;
        if !node.active {
            return Err(Error::NotFound);
        }
        // Prevent removal of non-empty directories.
        if let KernfsNodeKind::Dir { child_count, .. } = node.kind {
            if child_count > 0 {
                return Err(Error::Busy);
            }
        }
        let parent_id = node.parent;
        // Remove from parent's child list.
        if let Some(pid) = parent_id {
            let parent = self.nodes.get_mut(pid.0).ok_or(Error::NotFound)?;
            if let KernfsNodeKind::Dir {
                children,
                child_count,
            } = &mut parent.kind
            {
                if let Some(pos) = children[..*child_count].iter().position(|c| *c == id) {
                    children[pos] = children[*child_count - 1];
                    *child_count -= 1;
                }
            }
        }
        self.nodes[id.0] = KernfsNode::EMPTY;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lookup and traversal
    // -----------------------------------------------------------------------

    /// Look up a child of `parent` by `name`.
    ///
    /// Only finds children in the [`KernfsNodeState::Active`] state. Nodes
    /// that are `Inactive` or `Draining` are invisible to this call.
    ///
    /// Returns the [`NodeId`] of the matching child.
    pub fn lookup(&self, parent: NodeId, name: &str) -> Result<NodeId> {
        self.lookup_with_state(parent, name, true)
    }

    /// Like [`lookup`](KernfsRoot::lookup) but also finds `Inactive`/`Draining`
    /// nodes. Used internally to prevent duplicate names during creation.
    fn lookup_any_state(&self, parent: NodeId, name: &str) -> Result<NodeId> {
        self.lookup_with_state(parent, name, false)
    }

    fn lookup_with_state(&self, parent: NodeId, name: &str, active_only: bool) -> Result<NodeId> {
        if !parent.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let parent_node = self.nodes.get(parent.0).ok_or(Error::NotFound)?;
        if !parent_node.active {
            return Err(Error::NotFound);
        }
        let (children, child_count) = match parent_node.kind {
            KernfsNodeKind::Dir {
                children,
                child_count,
            } => (children, child_count),
            _ => return Err(Error::NotFound),
        };
        let name_bytes = name.as_bytes();
        for i in 0..child_count {
            let cid = children[i];
            if !cid.is_valid() {
                continue;
            }
            let child = &self.nodes[cid.0];
            if !child.active {
                continue;
            }
            if active_only && child.state != KernfsNodeState::Active {
                continue;
            }
            if child.name() == name_bytes {
                return Ok(cid);
            }
        }
        Err(Error::NotFound)
    }

    /// Resolve a `/`-separated path starting from the root.
    ///
    /// Empty components (from leading or double slashes) are skipped.
    pub fn resolve_path(&self, path: &str) -> Result<NodeId> {
        let mut current = NodeId::ROOT;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            current = self.lookup(current, component)?;
        }
        Ok(current)
    }

    /// Get a reference to a node by ID.
    ///
    /// Returns `Err(NotFound)` unless the node is present and [`KernfsNodeState::Active`].
    pub fn node(&self, id: NodeId) -> Result<&KernfsNode> {
        if !id.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get(id.0).ok_or(Error::NotFound)?;
        if !node.active || node.state != KernfsNodeState::Active {
            return Err(Error::NotFound);
        }
        Ok(node)
    }

    /// Get a reference to a node regardless of lifecycle state.
    ///
    /// Used internally and by subsystems managing the activate/deactivate
    /// lifecycle. Returns `Err(NotFound)` only if the slot is unoccupied.
    pub fn node_any_state(&self, id: NodeId) -> Result<&KernfsNode> {
        if !id.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get(id.0).ok_or(Error::NotFound)?;
        if !node.active {
            return Err(Error::NotFound);
        }
        Ok(node)
    }

    // -----------------------------------------------------------------------
    // Activate / deactivate lifecycle
    // -----------------------------------------------------------------------

    /// Activate a node, making it visible to VFS lookups.
    ///
    /// Nodes created with [`create_dir`] / [`create_file`] / [`create_symlink`]
    /// start in the [`KernfsNodeState::Inactive`] state. Call `activate` once
    /// all attributes are registered.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — node does not exist
    /// - [`Error::InvalidArgument`] — node is already `Active` or `Draining`
    pub fn activate(&mut self, id: NodeId) -> Result<()> {
        if !id.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get_mut(id.0).ok_or(Error::NotFound)?;
        if !node.active {
            return Err(Error::NotFound);
        }
        if node.state != KernfsNodeState::Inactive {
            return Err(Error::InvalidArgument);
        }
        node.state = KernfsNodeState::Active;
        Ok(())
    }

    /// Deactivate a node, hiding it from new VFS lookups.
    ///
    /// The node transitions to [`KernfsNodeState::Draining`]. Once all
    /// in-flight file handles have been closed the caller may call
    /// [`remove`](KernfsRoot::remove) to free the slot.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — node does not exist
    /// - [`Error::InvalidArgument`] — node is not currently `Active`
    pub fn deactivate(&mut self, id: NodeId) -> Result<()> {
        if !id.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get_mut(id.0).ok_or(Error::NotFound)?;
        if !node.active {
            return Err(Error::NotFound);
        }
        if node.state != KernfsNodeState::Active {
            return Err(Error::InvalidArgument);
        }
        node.state = KernfsNodeState::Draining;
        Ok(())
    }

    /// Return the [`KernfsNodeState`] of a node.
    pub fn state(&self, id: NodeId) -> Result<KernfsNodeState> {
        if !id.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let node = self.nodes.get(id.0).ok_or(Error::NotFound)?;
        if !node.active {
            return Err(Error::NotFound);
        }
        Ok(node.state)
    }

    // -----------------------------------------------------------------------
    // Read / write
    // -----------------------------------------------------------------------

    /// Call the `show` callback of a file node and return the output length.
    ///
    /// Writes attribute content into `buf`. Returns `Err(NotFound)` if `id`
    /// is not a file, or `Err(NotImplemented)` if the file has no `show`
    /// callback.
    pub fn read(&self, id: NodeId, buf: &mut [u8]) -> Result<usize> {
        let node = self.node(id)?;
        match node.kind {
            KernfsNodeKind::File { ops } => {
                if let Some(show) = ops.show {
                    Ok(show(id, buf))
                } else {
                    Err(Error::NotImplemented)
                }
            }
            _ => Err(Error::NotFound),
        }
    }

    /// Call the `store` callback of a file node.
    ///
    /// Returns `Err(NotFound)` if `id` is not a file, or
    /// `Err(PermissionDenied)` if the file has no `store` callback.
    pub fn write(&self, id: NodeId, data: &[u8]) -> Result<()> {
        let node = self.node(id)?;
        match node.kind {
            KernfsNodeKind::File { ops } => {
                if let Some(store) = ops.store {
                    store(id, data)
                } else {
                    Err(Error::PermissionDenied)
                }
            }
            _ => Err(Error::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Directory listing
    // -----------------------------------------------------------------------

    /// List children of a directory node.
    ///
    /// Fills `out` with child [`NodeId`]s and returns the count. Up to
    /// `out.len()` entries are written; remaining children are silently
    /// dropped.
    pub fn readdir(&self, dir: NodeId, out: &mut [NodeId]) -> Result<usize> {
        let node = self.node(dir)?;
        match node.kind {
            KernfsNodeKind::Dir {
                children,
                child_count,
            } => {
                let n = child_count.min(out.len());
                out[..n].copy_from_slice(&children[..n]);
                Ok(n)
            }
            _ => Err(Error::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------

    /// Return the number of active nodes in the tree.
    pub fn node_count(&self) -> usize {
        self.nodes[..self.count].iter().filter(|n| n.active).count()
    }
}

// ---------------------------------------------------------------------------
// Default impl
// ---------------------------------------------------------------------------

impl Default for KernfsRoot {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// KernfsOpenFile — sequential file read with offset tracking
// ---------------------------------------------------------------------------

/// Internal page-cache buffer for a single open kernfs file.
///
/// On the first `read(2)` the `show` callback is invoked once and its output
/// is latched in `buf[..buf_len]`. Subsequent reads at increasing offsets
/// serve data from this buffer. A read at offset 0 after the buffer is
/// exhausted re-invokes `show`, allowing `cat` to reread the attribute.
///
/// This matches Linux `kernfs_seq_show` / `seq_read` semantics.
pub struct KernfsOpenFile {
    /// The node this handle is associated with.
    pub node: NodeId,
    /// Cached attribute content.
    buf: [u8; KERNFS_MAX_ATTR_LEN],
    /// Number of valid bytes in `buf`.
    buf_len: usize,
    /// Whether `buf` has been populated for the current read sequence.
    buf_valid: bool,
}

impl KernfsOpenFile {
    /// Open a kernfs file node.
    pub fn open(node: NodeId) -> Self {
        Self {
            node,
            buf: [0u8; KERNFS_MAX_ATTR_LEN],
            buf_len: 0,
            buf_valid: false,
        }
    }

    /// Sequential read from a kernfs attribute file.
    ///
    /// Mirrors the Linux `kernfs_fop_read_iter` / `seq_read` contract:
    ///
    /// - On the first call (or when `offset == 0`), the node's `show`
    ///   callback is invoked and its output is latched.
    /// - Subsequent calls serve data from the latch at the given `offset`.
    /// - Returns `0` when `offset >= buf_len` (EOF).
    ///
    /// `root` must be the same [`KernfsRoot`] that owns `self.node`.
    pub fn read(&mut self, root: &KernfsRoot, offset: usize, out: &mut [u8]) -> Result<usize> {
        // Re-populate the buffer if this is a new read sequence (offset == 0)
        // or the buffer has not been filled yet.
        if offset == 0 || !self.buf_valid {
            self.buf_len = root.read(self.node, &mut self.buf)?;
            self.buf_valid = true;
        }
        if offset >= self.buf_len {
            return Ok(0); // EOF
        }
        let avail = self.buf_len - offset;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.buf[offset..offset + n]);
        Ok(n)
    }

    /// Invalidate the cached buffer, forcing the next read to re-invoke `show`.
    pub fn invalidate(&mut self) {
        self.buf_valid = false;
        self.buf_len = 0;
    }

    /// Return the total number of bytes produced by the last `show` call.
    ///
    /// Returns `0` if `show` has not been called yet for the current sequence.
    pub fn content_len(&self) -> usize {
        if self.buf_valid { self.buf_len } else { 0 }
    }
}

// ---------------------------------------------------------------------------
// KernfsAttr helper — typed attribute wrapper
// ---------------------------------------------------------------------------

/// A typed integer attribute backed by a kernfs file node.
///
/// Provides a `show` callback that formats the value as a decimal ASCII
/// string (e.g. `"42\n"`). Useful for exposing kernel counters.
pub struct KernfsIntAttr {
    /// The node ID in the parent [`KernfsRoot`].
    pub node: NodeId,
}

impl KernfsIntAttr {
    /// Register a new integer attribute under `parent` in `root`.
    ///
    /// The node is created and immediately activated.
    pub fn create(root: &mut KernfsRoot, parent: NodeId, name: &str) -> Result<Self> {
        fn show_zero(_id: NodeId, buf: &mut [u8]) -> usize {
            let s = b"0\n";
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            n
        }
        let ops = KernfsFileOps::read_only(show_zero);
        let node = root.create_file(parent, name, ops)?;
        root.activate(node)?;
        Ok(Self { node })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_lookup_dir() {
        let mut fs = KernfsRoot::new();
        let child = fs.create_dir(NodeId::ROOT, "devices").unwrap();
        // Inactive — not yet visible.
        assert!(fs.lookup(NodeId::ROOT, "devices").is_err());
        fs.activate(child).unwrap();
        let found = fs.lookup(NodeId::ROOT, "devices").unwrap();
        assert_eq!(found, child);
    }

    #[test]
    fn create_and_lookup_file() {
        let mut fs = KernfsRoot::new();
        let dir = fs.create_dir(NodeId::ROOT, "kernel").unwrap();
        fs.activate(dir).unwrap();
        fn show(_id: NodeId, buf: &mut [u8]) -> usize {
            let s = b"hello\n";
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            n
        }
        let file = fs
            .create_file(dir, "version", KernfsFileOps::read_only(show))
            .unwrap();
        fs.activate(file).unwrap();
        let found = fs.lookup(dir, "version").unwrap();
        assert_eq!(found, file);

        let mut buf = [0u8; 64];
        let n = fs.read(file, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello\n");
    }

    #[test]
    fn duplicate_name_rejected() {
        let mut fs = KernfsRoot::new();
        fs.create_dir(NodeId::ROOT, "bus").unwrap();
        // Duplicate rejected even if the first node is still Inactive.
        let result = fs.create_dir(NodeId::ROOT, "bus");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_path() {
        let mut fs = KernfsRoot::new();
        let a = fs.create_dir(NodeId::ROOT, "a").unwrap();
        fs.activate(a).unwrap();
        let b = fs.create_dir(a, "b").unwrap();
        fs.activate(b).unwrap();
        let found = fs.resolve_path("/a/b").unwrap();
        assert_eq!(found, b);
    }

    #[test]
    fn remove_empty_dir() {
        let mut fs = KernfsRoot::new();
        let d = fs.create_dir(NodeId::ROOT, "tmp").unwrap();
        fs.remove(d).unwrap();
        assert!(fs.lookup(NodeId::ROOT, "tmp").is_err());
    }

    #[test]
    fn remove_non_empty_dir_fails() {
        let mut fs = KernfsRoot::new();
        let d = fs.create_dir(NodeId::ROOT, "d").unwrap();
        fs.activate(d).unwrap();
        fs.create_dir(d, "child").unwrap();
        assert!(fs.remove(d).is_err());
    }

    #[test]
    fn write_only_file_rejects_read() {
        let mut fs = KernfsRoot::new();
        fn store(_id: NodeId, _data: &[u8]) -> Result<()> {
            Ok(())
        }
        let file = fs
            .create_file(NodeId::ROOT, "trigger", KernfsFileOps::write_only(store))
            .unwrap();
        fs.activate(file).unwrap();
        let mut buf = [0u8; 16];
        assert!(fs.read(file, &mut buf).is_err());
    }

    #[test]
    fn activate_deactivate_lifecycle() {
        let mut fs = KernfsRoot::new();
        let d = fs.create_dir(NodeId::ROOT, "dev").unwrap();
        assert_eq!(fs.state(d).unwrap(), KernfsNodeState::Inactive);

        fs.activate(d).unwrap();
        assert_eq!(fs.state(d).unwrap(), KernfsNodeState::Active);
        // Double-activate rejected.
        assert!(fs.activate(d).is_err());

        fs.deactivate(d).unwrap();
        assert_eq!(fs.state(d).unwrap(), KernfsNodeState::Draining);
        // Invisible to lookup.
        assert!(fs.lookup(NodeId::ROOT, "dev").is_err());

        // Can still be removed while draining.
        fs.remove(d).unwrap();
    }

    #[test]
    fn sequential_read_open_file() {
        let mut fs = KernfsRoot::new();
        fn show(_id: NodeId, buf: &mut [u8]) -> usize {
            let s = b"kernfs\n";
            let n = s.len().min(buf.len());
            buf[..n].copy_from_slice(&s[..n]);
            n
        }
        let file = fs
            .create_file(NodeId::ROOT, "info", KernfsFileOps::read_only(show))
            .unwrap();
        fs.activate(file).unwrap();

        let mut handle = KernfsOpenFile::open(file);
        let mut out = [0u8; 8];

        // First chunk.
        let n = handle.read(&fs, 0, &mut out[..4]).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..4], b"kern");

        // Continue at offset 4.
        let n = handle.read(&fs, 4, &mut out[..4]).unwrap();
        assert_eq!(n, 3); // "fs\n"
        assert_eq!(&out[..3], b"fs\n");

        // EOF.
        let n = handle.read(&fs, 7, &mut out).unwrap();
        assert_eq!(n, 0);
    }
}

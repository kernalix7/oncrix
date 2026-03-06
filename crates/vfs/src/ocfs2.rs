// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OCFS2 — Oracle Cluster File System version 2.
//!
//! OCFS2 is a shared-disk cluster filesystem that allows multiple nodes to
//! mount the same block device simultaneously with POSIX semantics. It uses:
//!
//! - **Disk locking** via the DLM (Distributed Lock Manager) for cache
//!   coherency across nodes.
//! - **Local allocation bitmaps** per node for reduced lock contention on
//!   block allocation.
//! - **Journal per node** (separate JBD2 journals).
//! - **Reflinks and inline data** (since OCFS2 1.6).
//!
//! # On-disk Layout
//!
//! ```text
//! [boot sector][superblock][node-local alloc bitmaps][journal N][global bitmap][root dir]...
//! ```
//!
//! # References
//!
//! - Linux `fs/ocfs2/`
//! - OCFS2 Technical Overview: oracle.com/technetwork/
//! - `Documentation/filesystems/ocfs2.rst`

use oncrix_lib::{Error, Result};

/// OCFS2 superblock magic.
pub const OCFS2_SUPER_MAGIC: u32 = 0x7461636f;
/// Maximum cluster nodes.
pub const OCFS2_MAX_NODES: usize = 255;
/// Maximum filename length.
pub const OCFS2_NAME_MAX: usize = 255;
/// Maximum in-memory inodes.
pub const MAX_OCFS2_INODES: usize = 512;
/// Maximum in-memory directory entries per dir.
pub const MAX_DIR_ENTRIES: usize = 256;

/// DLM lock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DlmLockLevel {
    /// Null lock (no access).
    Null,
    /// Concurrent read.
    ConcurrentRead,
    /// Concurrent write.
    ConcurrentWrite,
    /// Protected read.
    ProtectedRead,
    /// Protected write.
    ProtectedWrite,
    /// Exclusive.
    Exclusive,
}

/// DLM lock mode request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlmLockMode {
    /// Shared (protected read).
    Shared,
    /// Exclusive.
    Exclusive,
}

/// A DLM resource lock held by a node.
#[derive(Debug, Clone, Copy)]
pub struct DlmLock {
    /// Inode block number this lock protects.
    pub blkno: u64,
    /// Node that holds this lock.
    pub node_num: u8,
    /// Current level.
    pub level: DlmLockLevel,
}

/// Per-node allocation state (local allocation bitmap).
#[derive(Debug, Clone, Copy)]
pub struct NodeLocalAlloc {
    /// Node number.
    pub node_num: u8,
    /// Starting cluster in the local window.
    pub la_bm_off: u32,
    /// Number of clusters in the window.
    pub la_size: u32,
    /// Bitmap of free clusters within the window.
    pub bitmap: u64,
}

impl NodeLocalAlloc {
    /// Create a new local alloc for a node with a window of `size` clusters.
    pub fn new(node_num: u8, start: u32, size: u32) -> Result<Self> {
        if size > 64 {
            return Err(Error::InvalidArgument);
        }
        let bitmap = if size == 64 {
            u64::MAX
        } else {
            (1u64 << size) - 1
        };
        Ok(Self {
            node_num,
            la_bm_off: start,
            la_size: size,
            bitmap,
        })
    }

    /// Allocate one cluster. Returns local offset or `OutOfMemory`.
    pub fn alloc_cluster(&mut self) -> Result<u32> {
        if self.bitmap == 0 {
            return Err(Error::OutOfMemory);
        }
        let bit = self.bitmap.trailing_zeros();
        self.bitmap &= !(1u64 << bit);
        Ok(self.la_bm_off + bit)
    }

    /// Free a cluster at `cluster_off`.
    pub fn free_cluster(&mut self, cluster_off: u32) -> Result<()> {
        if cluster_off < self.la_bm_off || cluster_off >= self.la_bm_off + self.la_size {
            return Err(Error::InvalidArgument);
        }
        let bit = (cluster_off - self.la_bm_off) as u64;
        if self.bitmap & (1 << bit) != 0 {
            return Err(Error::InvalidArgument); // already free
        }
        self.bitmap |= 1 << bit;
        Ok(())
    }

    /// Number of free clusters.
    pub fn free_count(&self) -> u32 {
        self.bitmap.count_ones()
    }
}

/// OCFS2 inode (dinode on disk).
#[derive(Debug, Clone)]
pub struct Ocfs2Inode {
    /// Block number of this inode.
    pub blkno: u64,
    /// File mode.
    pub mode: u16,
    /// UID.
    pub uid: u32,
    /// GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Number of hard links.
    pub nlink: u16,
    /// Creation time (nanoseconds since epoch).
    pub ctime: u64,
    /// Modification time.
    pub mtime: u64,
    /// Access time.
    pub atime: u64,
    /// Number of allocated clusters.
    pub clusters: u32,
    /// Generation number.
    pub generation: u32,
}

impl Ocfs2Inode {
    /// Create a new inode at `blkno`.
    pub fn new(blkno: u64, mode: u16) -> Self {
        Self {
            blkno,
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 1,
            ctime: 0,
            mtime: 0,
            atime: 0,
            clusters: 0,
            generation: 0,
        }
    }

    /// True if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }

    /// True if this is a regular file.
    pub fn is_reg(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
}

/// A directory entry in OCFS2.
#[derive(Debug, Clone, Copy)]
pub struct Ocfs2DirEntry {
    /// Inode block number.
    pub blkno: u64,
    /// File type (0 = unknown, 1 = reg, 2 = dir, 7 = symlink).
    pub file_type: u8,
    /// Entry name.
    name: [u8; OCFS2_NAME_MAX],
    name_len: u8,
}

impl Ocfs2DirEntry {
    /// Create a directory entry.
    pub fn new(blkno: u64, file_type: u8, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > OCFS2_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; OCFS2_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            blkno,
            file_type,
            name: buf,
            name_len: name.len() as u8,
        })
    }

    /// Return name bytes.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// True if name matches.
    pub fn name_matches(&self, other: &[u8]) -> bool {
        self.name() == other
    }
}

/// In-memory directory for OCFS2.
pub struct Ocfs2Dir {
    pub blkno: u64,
    entries: [Option<Ocfs2DirEntry>; MAX_DIR_ENTRIES],
    count: usize,
}

impl Ocfs2Dir {
    /// Create a new directory.
    pub fn new(blkno: u64, parent_blkno: u64) -> Result<Self> {
        let mut dir = Self {
            blkno,
            entries: [const { None }; MAX_DIR_ENTRIES],
            count: 0,
        };
        dir.add(blkno, 2, b".")?;
        dir.add(parent_blkno, 2, b"..")?;
        Ok(dir)
    }

    /// Add a directory entry.
    pub fn add(&mut self, blkno: u64, file_type: u8, name: &[u8]) -> Result<()> {
        if self.lookup(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = Ocfs2DirEntry::new(blkno, file_type, name)?;
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Remove a directory entry.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        if name == b"." || name == b".." {
            return Err(Error::InvalidArgument);
        }
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.as_ref().map(|e| e.name_matches(name)).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                Ok(())
            }
        }
    }

    /// Lookup by name. Returns block number or `None`.
    pub fn lookup(&self, name: &[u8]) -> Option<u64> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.name_matches(name))
            .map(|e| e.blkno)
    }

    /// Iterate non-dot entries.
    pub fn iter_user_entries(&self) -> impl Iterator<Item = &Ocfs2DirEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.name() != b"." && e.name() != b"..")
    }
}

/// In-memory inode table.
pub struct Ocfs2InodeTable {
    inodes: [Option<Ocfs2Inode>; MAX_OCFS2_INODES],
    count: usize,
    next_blkno: u64,
}

impl Ocfs2InodeTable {
    /// Create a new inode table starting block allocation at `first`.
    pub fn new(first: u64) -> Self {
        Self {
            inodes: [const { None }; MAX_OCFS2_INODES],
            count: 0,
            next_blkno: first,
        }
    }

    fn alloc_blkno(&mut self) -> u64 {
        let b = self.next_blkno;
        self.next_blkno += 1;
        b
    }

    /// Allocate a new inode.
    pub fn alloc(&mut self, mode: u16) -> Result<u64> {
        if self.count >= MAX_OCFS2_INODES {
            return Err(Error::OutOfMemory);
        }
        let blkno = self.alloc_blkno();
        self.inodes[self.count] = Some(Ocfs2Inode::new(blkno, mode));
        self.count += 1;
        Ok(blkno)
    }

    /// Get inode by block number.
    pub fn get(&self, blkno: u64) -> Option<&Ocfs2Inode> {
        self.inodes[..self.count]
            .iter()
            .filter_map(|i| i.as_ref())
            .find(|i| i.blkno == blkno)
    }

    /// Get inode mutably.
    pub fn get_mut(&mut self, blkno: u64) -> Option<&mut Ocfs2Inode> {
        self.inodes[..self.count]
            .iter_mut()
            .filter_map(|i| i.as_mut())
            .find(|i| i.blkno == blkno)
    }

    /// Free an inode.
    pub fn free(&mut self, blkno: u64) -> Result<()> {
        let pos = self.inodes[..self.count]
            .iter()
            .position(|i| i.as_ref().map(|i| i.blkno == blkno).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.inodes[idx] = self.inodes[self.count].take();
                Ok(())
            }
        }
    }

    /// Total allocated inodes.
    pub fn count(&self) -> usize {
        self.count
    }
}

/// OCFS2 superblock (in-memory representation).
#[derive(Debug, Clone)]
pub struct Ocfs2Superblock {
    /// Filesystem magic.
    pub magic: u16,
    /// Cluster size in bytes (must be power of 2, 4K–1M).
    pub cluster_size: u32,
    /// Total clusters.
    pub total_clusters: u32,
    /// Free clusters.
    pub free_clusters: u32,
    /// Block size in bytes.
    pub block_size: u32,
    /// Total block count.
    pub total_blocks: u64,
    /// Root directory block number.
    pub root_blkno: u64,
    /// System directory block number.
    pub system_dir_blkno: u64,
    /// Number of cluster nodes.
    pub max_nodes: u32,
    /// UUID of the filesystem (16 bytes).
    pub uuid: [u8; 16],
    /// Volume label (64 bytes).
    pub label: [u8; 64],
    /// Journal block for each node.
    pub journal_blknos: [u64; OCFS2_MAX_NODES],
}

impl Ocfs2Superblock {
    /// Create a default OCFS2 superblock.
    pub fn new(total_clusters: u32, cluster_size: u32, block_size: u32) -> Self {
        let total_blocks = (total_clusters as u64) * (cluster_size as u64 / block_size as u64);
        Self {
            magic: OCFS2_SUPER_MAGIC as u16,
            cluster_size,
            total_clusters,
            free_clusters: total_clusters.saturating_sub(32),
            block_size,
            total_blocks,
            root_blkno: 32,
            system_dir_blkno: 33,
            max_nodes: 8,
            uuid: [0u8; 16],
            label: [0u8; 64],
            journal_blknos: [0u64; OCFS2_MAX_NODES],
        }
    }

    /// True if magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == OCFS2_SUPER_MAGIC as u16
    }

    /// Set volume label (truncated to 64 bytes).
    pub fn set_label(&mut self, label: &[u8]) {
        let len = label.len().min(64);
        self.label[..len].copy_from_slice(&label[..len]);
    }

    /// Set UUID.
    pub fn set_uuid(&mut self, uuid: &[u8; 16]) {
        self.uuid = *uuid;
    }
}

/// Cluster-wide lock table (simplified — no network DLM).
pub struct Ocfs2LockTable {
    locks: [Option<DlmLock>; 256],
    count: usize,
}

impl Ocfs2LockTable {
    /// Create empty lock table.
    pub const fn new() -> Self {
        Self {
            locks: [const { None }; 256],
            count: 0,
        }
    }

    /// Acquire lock on `blkno` for `node_num` at `level`.
    ///
    /// Fails with `Busy` if another node holds a conflicting lock.
    pub fn acquire(&mut self, blkno: u64, node_num: u8, mode: DlmLockMode) -> Result<()> {
        let requested = match mode {
            DlmLockMode::Shared => DlmLockLevel::ProtectedRead,
            DlmLockMode::Exclusive => DlmLockLevel::Exclusive,
        };
        // Check for conflicts.
        for i in 0..self.count {
            if let Some(ref l) = self.locks[i] {
                if l.blkno == blkno && l.node_num != node_num {
                    let conflict = match (requested, l.level) {
                        (DlmLockLevel::Exclusive, _) => true,
                        (_, DlmLockLevel::Exclusive) => true,
                        _ => false,
                    };
                    if conflict {
                        return Err(Error::Busy);
                    }
                }
            }
        }
        // Update existing or add new.
        for i in 0..self.count {
            if let Some(ref mut l) = self.locks[i] {
                if l.blkno == blkno && l.node_num == node_num {
                    l.level = requested;
                    return Ok(());
                }
            }
        }
        if self.count >= 256 {
            return Err(Error::OutOfMemory);
        }
        self.locks[self.count] = Some(DlmLock {
            blkno,
            node_num,
            level: requested,
        });
        self.count += 1;
        Ok(())
    }

    /// Release lock on `blkno` for `node_num`.
    pub fn release(&mut self, blkno: u64, node_num: u8) -> Result<()> {
        let pos = self.locks[..self.count].iter().position(|l| {
            l.as_ref()
                .map(|l| l.blkno == blkno && l.node_num == node_num)
                .unwrap_or(false)
        });
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.locks[idx] = self.locks[self.count].take();
                Ok(())
            }
        }
    }
}

impl Default for Ocfs2LockTable {
    fn default() -> Self {
        Self::new()
    }
}

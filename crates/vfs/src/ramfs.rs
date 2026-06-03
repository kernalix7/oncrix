// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RAM filesystem — a simple in-memory filesystem for early boot.
//!
//! Ramfs stores all data in fixed-size memory buffers. It provides
//! a minimal but functional filesystem for the kernel's initial
//! root before a real filesystem is mounted.

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Maximum number of inodes in ramfs.
const MAX_INODES: usize = 128;

/// Maximum file data size (4 KiB per file).
const MAX_FILE_SIZE: usize = 4096;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 32;

/// Maximum symbolic-link target length (bytes).
const SYMLINK_MAX: usize = 256;

/// A directory entry in ramfs.
#[derive(Debug, Clone)]
struct RamDirEntry {
    /// Entry name.
    name: [u8; 256],
    /// Name length.
    name_len: usize,
    /// Child inode number.
    inode: InodeNumber,
}

/// Ramfs inode data — either file content or directory entries.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RamInodeData {
    /// Regular file data.
    File {
        /// File content buffer.
        data: [u8; MAX_FILE_SIZE],
        /// Actual data length.
        len: usize,
    },
    /// Directory entries.
    Dir {
        /// Child entries.
        entries: [Option<RamDirEntry>; MAX_DIR_ENTRIES],
        /// Number of entries.
        count: usize,
    },
    /// Symbolic-link target path.
    Symlink {
        /// Target path bytes.
        target: [u8; SYMLINK_MAX],
        /// Actual target length.
        len: usize,
    },
    /// Named pipe (FIFO).
    ///
    /// `ring_id` is the index of the kernel pipe ring backing this FIFO,
    /// allocated lazily on first `open` and persisting for the inode's
    /// lifetime so that a writer and a reader opening the same path share
    /// one buffer. `None` until the first open wires the ring.
    Fifo {
        /// Backing pipe-ring index, or `None` if not yet opened.
        ring_id: Option<u32>,
    },
}

/// Ramfs filesystem.
pub struct Ramfs {
    /// Inode metadata.
    inodes: [Option<Inode>; MAX_INODES],
    /// Inode data (parallel array).
    data: [Option<RamInodeData>; MAX_INODES],
    /// Next inode number to allocate.
    next_ino: u64,
}

impl Default for Ramfs {
    fn default() -> Self {
        Self::new()
    }
}

/// A directory listing entry returned by [`Ramfs::list_children`].
pub struct RamfsDirEntry {
    /// Entry name.
    pub name: alloc::string::String,
    /// Child inode number.
    pub ino: InodeNumber,
    /// File type of the child.
    pub kind: FileType,
}

impl Ramfs {
    /// Create a new ramfs with a root directory (inode 1).
    pub fn new() -> Self {
        const NONE_INODE: Option<Inode> = None;
        const NONE_DATA: Option<RamInodeData> = None;
        const NONE_ENTRY: Option<RamDirEntry> = None;

        let mut fs = Self {
            inodes: [NONE_INODE; MAX_INODES],
            data: [NONE_DATA; MAX_INODES],
            next_ino: 2,
        };

        // Create root directory at inode 1.
        let root_ino = InodeNumber(1);
        fs.inodes[0] = Some(Inode::new(
            root_ino,
            FileType::Directory,
            FileMode::DIR_DEFAULT,
        ));
        fs.data[0] = Some(RamInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });

        fs
    }

    /// Return the root inode number.
    pub fn root_inode(&self) -> InodeNumber {
        InodeNumber(1)
    }

    /// Return the current size of the inode identified by `ino`, or `None`
    /// if the inode does not exist.
    ///
    /// Used by the VFS kernel API to service `SEEK_END` without exposing
    /// internal inode-table slot indexing.
    pub fn inode_size(&self, ino: InodeNumber) -> Option<u64> {
        let slot = self.slot_of(ino)?;
        self.inodes[slot].as_ref().map(|i| i.size)
    }

    /// Set the owner and/or group of the inode identified by `ino`.
    ///
    /// POSIX.1-2024 `chown(2)` (ramfs subset): a field of `u32::MAX`
    /// leaves that id unchanged (matching the `(uid_t)-1` convention).
    /// Only the inode metadata is updated; ONCRIX does not enforce
    /// ownership yet.
    ///
    /// Returns `NotFound` if no inode with that number exists.
    pub fn set_owner(&mut self, ino: InodeNumber, uid: u32, gid: u32) -> Result<()> {
        let slot = self.slot_of(ino).ok_or(Error::NotFound)?;
        let inode = self.inodes[slot].as_mut().ok_or(Error::NotFound)?;
        if uid != u32::MAX {
            inode.uid = uid;
        }
        if gid != u32::MAX {
            inode.gid = gid;
        }
        Ok(())
    }

    /// Set the permission bits of the inode identified by `ino`.
    ///
    /// POSIX.1-2024 `chmod(2)` (ramfs subset): updates only the mode
    /// bits stored in the inode metadata. ONCRIX does not yet enforce
    /// permissions, so the change is observable via `stat` but has no
    /// access-control effect.
    ///
    /// Returns `NotFound` if no inode with that number exists.
    pub fn set_mode(&mut self, ino: InodeNumber, mode: FileMode) -> Result<()> {
        let slot = self.slot_of(ino).ok_or(Error::NotFound)?;
        let inode = self.inodes[slot].as_mut().ok_or(Error::NotFound)?;
        inode.mode = mode;
        Ok(())
    }

    /// Return a copy of the [`Inode`] with the given number, or `None` if
    /// no such inode exists in this filesystem.
    ///
    /// Used by the kernel fd-dispatch layer to materialise a full `Inode`
    /// struct from the number stored in a `FileBackend::RamfsFile` handle.
    pub fn inode_by_number(&self, ino: InodeNumber) -> Option<Inode> {
        let slot = self.slot_of(ino)?;
        self.inodes[slot]
    }

    /// Return the number of inode slots currently in use.
    ///
    /// Scans the fixed-size `self.inodes` table and counts `Some` entries.
    /// Used by `statfs(2)`/`fstatfs(2)` to fill `f_ffree`
    /// (free inodes = `MAX_INODES - used_inodes()`). O(MAX_INODES).
    pub fn used_inodes(&self) -> usize {
        self.inodes.iter().filter(|slot| slot.is_some()).count()
    }

    /// Find the slot index for an inode number.
    fn slot_of(&self, ino: InodeNumber) -> Option<usize> {
        self.inodes
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|i| i.ino == ino))
    }

    /// Allocate a new inode number and slot.
    fn alloc_inode(&mut self, file_type: FileType, mode: FileMode) -> Result<(usize, InodeNumber)> {
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        for (idx, slot) in self.inodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Inode::new(ino, file_type, mode));
                return Ok((idx, ino));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Return all child entries of `parent` as a `Vec`.
    ///
    /// Returns an empty `Vec` if `parent` is not a directory or has no
    /// children.  The caller may use this to implement `getdents` /
    /// `readdir`.
    pub fn list_children(&self, parent: &Inode) -> alloc::vec::Vec<RamfsDirEntry> {
        let slot = match self.slot_of(parent.ino) {
            Some(s) => s,
            None => return alloc::vec::Vec::new(),
        };
        let data = match self.data[slot].as_ref() {
            Some(d) => d,
            None => return alloc::vec::Vec::new(),
        };
        let RamInodeData::Dir { entries, .. } = data else {
            return alloc::vec::Vec::new();
        };
        let mut out = alloc::vec::Vec::new();
        for entry in entries.iter().flatten() {
            let name_bytes = &entry.name[..entry.name_len];
            let name = match alloc::string::String::from_utf8(name_bytes.to_vec()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let kind = self
                .slot_of(entry.inode)
                .and_then(|s| self.inodes[s].as_ref().map(|i| i.file_type))
                .unwrap_or(FileType::Regular);
            out.push(RamfsDirEntry {
                name,
                ino: entry.inode,
                kind,
            });
        }
        out
    }

    /// Remove the entry named `name` from `parent`.
    ///
    /// - Returns `NotFound` if the entry does not exist.
    /// - Returns `InvalidArgument` if the entry is a directory (use rmdir).
    /// - The directory entry is always removed. The child inode and its
    ///   data are freed only when the inode's link count drops to zero
    ///   (POSIX hard-link semantics); other names for the same inode
    ///   keep it alive. See [`link`](Self::link).
    pub fn unlink_entry(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
                let name_bytes = name.as_bytes();
                entries
                    .iter()
                    .flatten()
                    .find(|e| &e.name[..e.name_len] == name_bytes)
                    .map(|e| e.inode)
                    .ok_or(Error::NotFound)?
            } else {
                return Err(Error::InvalidArgument);
            }
        };

        // Phase-19 simplification: rm only handles files.
        if let Some(slot) = self.slot_of(child_ino) {
            if let Some(inode) = &self.inodes[slot] {
                if inode.file_type == FileType::Directory {
                    return Err(Error::InvalidArgument);
                }
            }
        }

        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        let ino = entry.inode;
                        *slot = None;
                        *count -= 1;
                        // Decrement the link count; free the inode + data
                        // only when no names remain (POSIX hard links).
                        if let Some(child_slot) = self.slot_of(ino) {
                            let nlink = self.inodes[child_slot]
                                .as_ref()
                                .map(|i| i.nlink)
                                .unwrap_or(0);
                            if nlink > 1 {
                                if let Some(inode) = self.inodes[child_slot].as_mut() {
                                    inode.nlink -= 1;
                                }
                            } else {
                                self.inodes[child_slot] = None;
                                self.data[child_slot] = None;
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Add a directory entry to a directory.
    ///
    /// Returns `AlreadyExists` if a child with the same name already exists.
    fn add_dir_entry(
        &mut self,
        parent_slot: usize,
        name: &str,
        child_ino: InodeNumber,
    ) -> Result<()> {
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            if *count >= MAX_DIR_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            let name_bytes = name.as_bytes();
            if name_bytes.len() > 255 {
                return Err(Error::InvalidArgument);
            }

            // Check for duplicate names.
            for existing in entries.iter().flatten() {
                if &existing.name[..existing.name_len] == name_bytes {
                    return Err(Error::AlreadyExists);
                }
            }

            let mut entry_name = [0u8; 256];
            entry_name[..name_bytes.len()].copy_from_slice(name_bytes);

            for slot in entries.iter_mut() {
                if slot.is_none() {
                    *slot = Some(RamDirEntry {
                        name: entry_name,
                        name_len: name_bytes.len(),
                        inode: child_ino,
                    });
                    *count += 1;
                    return Ok(());
                }
            }
            Err(Error::OutOfMemory)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Detach the entry named `name` from `parent` WITHOUT freeing the
    /// child inode, returning the child inode number.
    ///
    /// Counterpart to [`unlink_entry`](Self::unlink_entry), which frees
    /// the inode. Used by [`rename`](Self::rename) to move a name from
    /// one directory to another while keeping the underlying inode.
    fn detach_dir_entry(&mut self, parent_slot: usize, name: &str) -> Result<InodeNumber> {
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        let ino = entry.inode;
                        *slot = None;
                        *count -= 1;
                        return Ok(ino);
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Rename `old_name` in `old_parent` to `new_name` in `new_parent`.
    ///
    /// POSIX.1-2024 `rename(2)` (ramfs subset): the source name is
    /// detached and re-attached under the destination directory without
    /// reallocating the inode, so open file handles and inode numbers
    /// stay valid. If the destination name already exists it is removed
    /// first (overwrite semantics). Source and destination may be the
    /// same directory (pure rename) or different directories (move).
    ///
    /// Returns `NotFound` if `old_name` does not exist, `AlreadyExists`
    /// only on internal re-attach failure (should not occur after the
    /// destination is cleared).
    pub fn rename(
        &mut self,
        old_parent: &Inode,
        old_name: &str,
        new_parent: &Inode,
        new_name: &str,
    ) -> Result<()> {
        let old_parent_slot = self.slot_of(old_parent.ino).ok_or(Error::NotFound)?;
        let new_parent_slot = self.slot_of(new_parent.ino).ok_or(Error::NotFound)?;

        // No-op when source and destination name the same path.
        if old_parent.ino == new_parent.ino && old_name == new_name {
            // Still verify the source exists.
            let data = self.data[old_parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
                let nb = old_name.as_bytes();
                if entries
                    .iter()
                    .flatten()
                    .any(|e| &e.name[..e.name_len] == nb)
                {
                    return Ok(());
                }
            }
            return Err(Error::NotFound);
        }

        // Remove an existing destination entry first (overwrite), freeing
        // its inode. Ignore NotFound — destination need not pre-exist.
        let dst_parent_inode = *self.inodes[new_parent_slot]
            .as_ref()
            .ok_or(Error::NotFound)?;
        match self.unlink_entry(&dst_parent_inode, new_name) {
            Ok(()) | Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }

        // Detach the source name (keeps the inode alive).
        let child_ino = self.detach_dir_entry(old_parent_slot, old_name)?;

        // Re-attach under the destination directory.
        self.add_dir_entry(new_parent_slot, new_name, child_ino)
    }

    /// Create a hard link `new_name` in `new_parent` pointing at the
    /// same inode as `target`.
    ///
    /// POSIX.1-2024 `link(2)` (ramfs subset): adds a second directory
    /// entry for an existing regular file and bumps its link count, so
    /// removing either name keeps the inode alive until the last link
    /// is unlinked. Hard-linking directories is rejected
    /// (`InvalidArgument`), matching POSIX.
    ///
    /// Returns `NotFound` if `target` does not exist, `AlreadyExists` if
    /// `new_name` is already present in `new_parent`.
    pub fn link(&mut self, target: &Inode, new_parent: &Inode, new_name: &str) -> Result<()> {
        let target_slot = self.slot_of(target.ino).ok_or(Error::NotFound)?;
        let new_parent_slot = self.slot_of(new_parent.ino).ok_or(Error::NotFound)?;

        // POSIX: hard links to directories are not permitted.
        if let Some(inode) = self.inodes[target_slot].as_ref() {
            if inode.file_type == FileType::Directory {
                return Err(Error::InvalidArgument);
            }
        }

        let target_ino = target.ino;
        self.add_dir_entry(new_parent_slot, new_name, target_ino)?;

        // Bump the link count only after the entry is committed.
        if let Some(inode) = self.inodes[target_slot].as_mut() {
            inode.nlink += 1;
        }
        Ok(())
    }

    /// Create a symbolic link `name` in `parent` whose target is `target`.
    ///
    /// POSIX.1-2024 `symlink(2)` (ramfs subset): allocates a new inode of
    /// type [`FileType::Symlink`] storing the literal `target` bytes. The
    /// link is not yet followed by path resolution — use
    /// [`read_link`](Self::read_link) to retrieve the target.
    ///
    /// Returns `AlreadyExists` if `name` exists, `InvalidArgument` if the
    /// target exceeds [`SYMLINK_MAX`] bytes, `OutOfMemory` if the inode
    /// or directory table is full.
    pub fn symlink(&mut self, parent: &Inode, name: &str, target: &[u8]) -> Result<Inode> {
        if target.len() > SYMLINK_MAX {
            return Err(Error::InvalidArgument);
        }
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) =
            self.alloc_inode(FileType::Symlink, FileMode::FILE_DEFAULT)?;
        let mut buf = [0u8; SYMLINK_MAX];
        buf[..target.len()].copy_from_slice(target);
        self.data[child_slot] = Some(RamInodeData::Symlink {
            target: buf,
            len: target.len(),
        });
        if let Some(inode) = self.inodes[child_slot].as_mut() {
            inode.size = target.len() as u64;
        }
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    /// Create a named pipe (FIFO) `name` in `parent`.
    ///
    /// POSIX.1-2024 `mkfifo(2)` (ramfs subset): allocates a new inode of
    /// type [`FileType::Fifo`]. The FIFO is not yet connected to a pipe
    /// ring — this only makes the node exist so `mkfifo` succeeds and
    /// `ls -l` reports it as `p`.
    ///
    /// Returns `AlreadyExists` if `name` exists, `OutOfMemory` if the
    /// inode/directory table is full.
    pub fn mknod_fifo(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Fifo, mode)?;
        self.data[child_slot] = Some(RamInodeData::Fifo { ring_id: None });
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    /// Read the target of the symbolic link identified by `ino` into `buf`.
    ///
    /// Returns the number of bytes copied (≤ `buf.len()`). Returns
    /// `InvalidArgument` if the inode is not a symlink, `NotFound` if no
    /// such inode exists.
    pub fn read_link(&self, ino: InodeNumber, buf: &mut [u8]) -> Result<usize> {
        let slot = self.slot_of(ino).ok_or(Error::NotFound)?;
        let data = self.data[slot].as_ref().ok_or(Error::NotFound)?;
        if let RamInodeData::Symlink { target, len } = data {
            let n = (*len).min(buf.len());
            buf[..n].copy_from_slice(&target[..n]);
            Ok(n)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Return the pipe-ring index backing the FIFO `ino`, if one has been
    /// allocated.
    ///
    /// Returns `Err(InvalidArgument)` if `ino` is not a FIFO, `NotFound`
    /// if no such inode exists.
    pub fn fifo_ring_id(&self, ino: InodeNumber) -> Result<Option<u32>> {
        let slot = self.slot_of(ino).ok_or(Error::NotFound)?;
        match self.data[slot].as_ref() {
            Some(RamInodeData::Fifo { ring_id }) => Ok(*ring_id),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Record the pipe-ring index backing the FIFO `ino`.
    ///
    /// Returns `Err(InvalidArgument)` if `ino` is not a FIFO, `NotFound`
    /// if no such inode exists.
    pub fn set_fifo_ring_id(&mut self, ino: InodeNumber, id: u32) -> Result<()> {
        let slot = self.slot_of(ino).ok_or(Error::NotFound)?;
        match self.data[slot].as_mut() {
            Some(RamInodeData::Fifo { ring_id }) => {
                *ring_id = Some(id);
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

impl InodeOps for Ramfs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;

        if let RamInodeData::Dir { entries, .. } = data {
            let name_bytes = name.as_bytes();
            for entry in entries.iter().flatten() {
                if &entry.name[..entry.name_len] == name_bytes {
                    let child_slot = self.slot_of(entry.inode).ok_or(Error::NotFound)?;
                    return self.inodes[child_slot]
                        .as_ref()
                        .copied()
                        .ok_or(Error::NotFound);
                }
            }
            Err(Error::NotFound)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Regular, mode)?;
        self.data[child_slot] = Some(RamInodeData::File {
            data: [0u8; MAX_FILE_SIZE],
            len: 0,
        });
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        const NONE_ENTRY: Option<RamDirEntry> = None;
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Directory, mode)?;
        self.data[child_slot] = Some(RamInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // First, find the child inode to check its type.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
                let name_bytes = name.as_bytes();
                let entry = entries
                    .iter()
                    .flatten()
                    .find(|e| &e.name[..e.name_len] == name_bytes)
                    .ok_or(Error::NotFound)?;
                entry.inode
            } else {
                return Err(Error::InvalidArgument);
            }
        };

        // POSIX: unlink must not remove directories (use rmdir).
        if let Some(slot) = self.slot_of(child_ino) {
            if let Some(inode) = &self.inodes[slot] {
                if inode.file_type == FileType::Directory {
                    return Err(Error::PermissionDenied);
                }
            }
        }

        // Remove the directory entry and free the inode.
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        let ino = entry.inode;
                        *slot = None;
                        *count -= 1;
                        // Decrement the link count; free the inode + data
                        // only when no names remain (POSIX hard links).
                        if let Some(child_slot) = self.slot_of(ino) {
                            let nlink = self.inodes[child_slot]
                                .as_ref()
                                .map(|i| i.nlink)
                                .unwrap_or(0);
                            if nlink > 1 {
                                if let Some(inode) = self.inodes[child_slot].as_mut() {
                                    inode.nlink -= 1;
                                }
                            } else {
                                self.inodes[child_slot] = None;
                                self.data[child_slot] = None;
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // Find the child inode.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
                let name_bytes = name.as_bytes();
                let entry = entries
                    .iter()
                    .flatten()
                    .find(|e| &e.name[..e.name_len] == name_bytes)
                    .ok_or(Error::NotFound)?;
                entry.inode
            } else {
                return Err(Error::InvalidArgument);
            }
        };

        // Verify the child is a directory.
        let child_slot = self.slot_of(child_ino).ok_or(Error::NotFound)?;
        if let Some(inode) = &self.inodes[child_slot] {
            if inode.file_type != FileType::Directory {
                return Err(Error::InvalidArgument);
            }
        }

        // POSIX: rmdir must fail if the directory is not empty.
        if let Some(RamInodeData::Dir { count, .. }) = &self.data[child_slot] {
            if *count > 0 {
                return Err(Error::InvalidArgument);
            }
        }

        // Remove the directory entry from parent and free child.
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        *slot = None;
                        *count -= 1;
                        self.inodes[child_slot] = None;
                        self.data[child_slot] = None;
                        return Ok(());
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let data = self.data[slot].as_ref().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = data
        {
            let offset = offset as usize;
            if offset >= *len {
                return Ok(0);
            }
            let available = *len - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&file_data[offset..offset + to_read]);
            Ok(to_read)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let inode_data = self.data[slot].as_mut().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            let offset = offset as usize;
            let end = offset
                .checked_add(data.len())
                .ok_or(Error::InvalidArgument)?;
            if end > MAX_FILE_SIZE {
                return Err(Error::OutOfMemory);
            }
            file_data[offset..end].copy_from_slice(data);
            if end > *len {
                *len = end;
            }

            // Update inode size.
            if let Some(inode_meta) = self.inodes[slot].as_mut() {
                inode_meta.size = *len as u64;
            }

            Ok(data.len())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let inode_data = self.data[slot].as_mut().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            let new_len = (size as usize).min(MAX_FILE_SIZE);
            if new_len < *len {
                // Zero out truncated region.
                file_data[new_len..*len].fill(0);
            }
            *len = new_len;

            if let Some(inode_meta) = self.inodes[slot].as_mut() {
                inode_meta.size = new_len as u64;
            }
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn readlink(&self, inode: &Inode, buf: &mut [u8]) -> Result<usize> {
        self.read_link(inode.ino, buf)
    }
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Overlay filesystem — union mount merging upper (writable) and
//! lower (read-only) layers into a single merged view.
//!
//! Implements the standard overlay semantics: reads fall through to
//! the lower layer when absent from the upper, writes trigger a
//! copy-up from lower to upper, and deletions are recorded as
//! whiteout entries in the upper layer.
//!
//! Reference: Linux `fs/overlayfs/`, POSIX union mount semantics.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Maximum number of inodes per layer.
const MAX_INODES: usize = 128;

/// Maximum file data size (4 KiB per file).
const MAX_FILE_SIZE: usize = 4096;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 32;

/// Maximum number of layers (upper + lower layers).
const MAX_LAYERS: usize = 4;

/// Maximum number of whiteout entries.
const MAX_WHITEOUTS: usize = 64;

/// Maximum path length in bytes.
const MAX_PATH_LEN: usize = 256;

/// Maximum merged directory listing entries.
const MAX_MERGED_ENTRIES: usize = 64;

/// A directory entry in an overlay layer.
#[derive(Debug, Clone)]
struct OverlayDirEntryInner {
    /// Entry name.
    name: [u8; MAX_PATH_LEN],
    /// Name length.
    name_len: usize,
    /// Child inode number.
    inode: InodeNumber,
}

/// Per-inode data — either file content or directory entries.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum LayerInodeData {
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
        entries: [Option<OverlayDirEntryInner>; MAX_DIR_ENTRIES],
        /// Number of entries.
        count: usize,
    },
}

/// Layer descriptor identifying a single filesystem layer.
#[derive(Debug, Clone, Copy)]
pub struct OverlayLayer {
    /// Unique identifier for this layer.
    pub layer_id: u32,
    /// Mount point path prefix length (bytes stored in mount_point).
    mount_point_len: usize,
    /// Mount point path bytes.
    mount_point: [u8; MAX_PATH_LEN],
    /// Whether this layer is read-only.
    pub read_only: bool,
}

impl OverlayLayer {
    /// Create a new layer descriptor.
    ///
    /// `mount_point` is the path prefix for this layer's root.
    /// `read_only` marks the layer as immutable (lower layer).
    pub fn new(layer_id: u32, mount_point: &str, read_only: bool) -> Result<Self> {
        let bytes = mount_point.as_bytes();
        if bytes.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            layer_id,
            mount_point_len: bytes.len(),
            mount_point: buf,
            read_only,
        })
    }

    /// Return the mount point as a byte slice.
    pub fn mount_point_bytes(&self) -> &[u8] {
        &self.mount_point[..self.mount_point_len]
    }
}

/// Merged inode tracking which layer an inode originates from.
#[derive(Debug, Clone, Copy)]
pub struct OverlayInode {
    /// The resolved inode metadata.
    pub inode: Inode,
    /// Layer ID that this inode belongs to.
    pub source_layer: u32,
    /// Whether this entry is a whiteout (deleted in upper).
    pub whiteout: bool,
    /// Whether a copy-up has been performed for this inode.
    pub copied_up: bool,
}

/// Directory entry with layer resolution information.
///
/// Upper layer entries take priority over lower layer entries
/// with the same name. Whiteout entries hide lower entries.
#[derive(Debug, Clone, Copy)]
pub struct OverlayDentry {
    /// Inode number of this entry.
    pub ino: InodeNumber,
    /// Layer ID where this entry was resolved from.
    pub source_layer: u32,
    /// Name length.
    name_len: usize,
    /// Name bytes.
    name: [u8; MAX_PATH_LEN],
    /// Whether this entry is hidden by a whiteout.
    pub hidden: bool,
}

impl OverlayDentry {
    /// Return the entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Merged directory listing from upper + lower layers.
///
/// Combines entries from all layers, with upper taking priority.
/// Whiteout entries from the upper layer suppress corresponding
/// lower layer entries.
#[derive(Debug)]
pub struct OverlayDir {
    /// Merged directory entries (visible only, whiteouts filtered).
    entries: [Option<OverlayDentry>; MAX_MERGED_ENTRIES],
    /// Number of visible entries.
    count: usize,
}

impl Default for OverlayDir {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayDir {
    /// Create an empty merged directory listing.
    pub fn new() -> Self {
        const NONE: Option<OverlayDentry> = None;
        Self {
            entries: [NONE; MAX_MERGED_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of visible entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the directory listing is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return visible entries as a slice (only populated portion).
    pub fn entries(&self) -> &[Option<OverlayDentry>] {
        &self.entries[..self.count.min(MAX_MERGED_ENTRIES)]
    }

    /// Add an entry to the merged listing.
    fn add(&mut self, entry: OverlayDentry) -> Result<()> {
        if self.count >= MAX_MERGED_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }
}

/// Whiteout marker — records a deleted file in the upper layer.
///
/// Following the Linux overlayfs convention, a whiteout is a
/// character device with major/minor 0/0. This struct records
/// the path that is being hidden.
#[derive(Debug, Clone, Copy)]
pub struct Whiteout {
    /// Path name that is hidden.
    name: [u8; MAX_PATH_LEN],
    /// Name length.
    name_len: usize,
    /// Parent inode in the upper layer.
    pub parent_ino: InodeNumber,
}

impl Whiteout {
    /// Create a new whiteout for the given name under a parent.
    pub fn new(name: &str, parent_ino: InodeNumber) -> Result<Self> {
        let bytes = name.as_bytes();
        if bytes.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_PATH_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name: buf,
            name_len: bytes.len(),
            parent_ino,
        })
    }

    /// Return the whiteout name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Copy-up operation descriptor.
///
/// When a file from a lower (read-only) layer is modified, it must
/// first be copied to the upper (writable) layer. This struct tracks
/// the copy-up state for a single inode.
#[derive(Debug, Clone, Copy)]
pub struct CopyUp {
    /// Source inode number (in lower layer).
    pub source_ino: InodeNumber,
    /// Source layer ID.
    pub source_layer: u32,
    /// Destination inode number (in upper layer, after copy).
    pub dest_ino: InodeNumber,
    /// Whether the copy-up is complete.
    pub completed: bool,
}

impl CopyUp {
    /// Create a new pending copy-up descriptor.
    pub fn new(source_ino: InodeNumber, source_layer: u32) -> Self {
        Self {
            source_ino,
            source_layer,
            dest_ino: InodeNumber(0),
            completed: false,
        }
    }
}

/// Mount configuration for the overlay filesystem.
///
/// Specifies the upper (writable) directory, one or more lower
/// (read-only) directories, and a work directory for atomic
/// operations (copy-up staging).
#[derive(Debug, Clone, Copy)]
pub struct OverlayMount {
    /// Upper directory path length.
    upper_len: usize,
    /// Upper directory path bytes (writable layer).
    upper_dir: [u8; MAX_PATH_LEN],
    /// Lower directory path length.
    lower_len: usize,
    /// Lower directory path bytes (read-only layer).
    lower_dir: [u8; MAX_PATH_LEN],
    /// Work directory path length.
    work_len: usize,
    /// Work directory path bytes (copy-up staging area).
    work_dir: [u8; MAX_PATH_LEN],
}

impl OverlayMount {
    /// Create a new overlay mount configuration.
    ///
    /// - `upper_dir`: writable layer directory path
    /// - `lower_dir`: read-only layer directory path
    /// - `work_dir`: staging area for copy-up operations
    pub fn new(upper_dir: &str, lower_dir: &str, work_dir: &str) -> Result<Self> {
        let ub = upper_dir.as_bytes();
        let lb = lower_dir.as_bytes();
        let wb = work_dir.as_bytes();
        if ub.len() > MAX_PATH_LEN || lb.len() > MAX_PATH_LEN || wb.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut upper = [0u8; MAX_PATH_LEN];
        upper[..ub.len()].copy_from_slice(ub);
        let mut lower = [0u8; MAX_PATH_LEN];
        lower[..lb.len()].copy_from_slice(lb);
        let mut work = [0u8; MAX_PATH_LEN];
        work[..wb.len()].copy_from_slice(wb);
        Ok(Self {
            upper_len: ub.len(),
            upper_dir: upper,
            lower_len: lb.len(),
            lower_dir: lower,
            work_len: wb.len(),
            work_dir: work,
        })
    }

    /// Return the upper directory path as a byte slice.
    pub fn upper_dir(&self) -> &[u8] {
        &self.upper_dir[..self.upper_len]
    }

    /// Return the lower directory path as a byte slice.
    pub fn lower_dir(&self) -> &[u8] {
        &self.lower_dir[..self.lower_len]
    }

    /// Return the work directory path as a byte slice.
    pub fn work_dir(&self) -> &[u8] {
        &self.work_dir[..self.work_len]
    }
}

/// Internal storage for a single layer's data.
struct LayerStorage {
    /// Layer descriptor.
    layer: OverlayLayer,
    /// Inode metadata.
    inodes: [Option<Inode>; MAX_INODES],
    /// Inode data (parallel array).
    data: [Option<LayerInodeData>; MAX_INODES],
    /// Next inode number to allocate.
    next_ino: u64,
}

/// Overlay filesystem — merges upper and lower layers.
///
/// The upper layer is writable; lower layers are read-only.
/// Lookups check the upper layer first, falling through to
/// lower layers. Writes trigger copy-up from lower to upper.
/// Deletions create whiteout entries in the upper layer.
pub struct OverlayFs {
    /// Layer storage (index 0 = upper, rest = lower).
    layers: [Option<LayerStorage>; MAX_LAYERS],
    /// Number of active layers.
    layer_count: usize,
    /// Whiteout table.
    whiteouts: [Option<Whiteout>; MAX_WHITEOUTS],
    /// Number of active whiteouts.
    whiteout_count: usize,
    /// Mount configuration.
    mount: OverlayMount,
}

impl OverlayFs {
    /// Create a new overlay filesystem with the given mount config.
    ///
    /// Initialises the upper layer (writable) and one lower layer
    /// (read-only), each with a root directory at inode 1.
    pub fn new(mount: OverlayMount) -> Result<Self> {
        const NONE_LAYER: Option<LayerStorage> = None;
        const NONE_WH: Option<Whiteout> = None;

        let upper = OverlayLayer::new(0, "/upper", false)?;
        let lower = OverlayLayer::new(1, "/lower", true)?;

        let mut fs = Self {
            layers: [NONE_LAYER; MAX_LAYERS],
            layer_count: 0,
            whiteouts: [NONE_WH; MAX_WHITEOUTS],
            whiteout_count: 0,
            mount,
        };
        fs.add_layer(upper)?;
        fs.add_layer(lower)?;
        Ok(fs)
    }

    /// Add a layer with a root directory at inode 1.
    fn add_layer(&mut self, layer: OverlayLayer) -> Result<()> {
        if self.layer_count >= MAX_LAYERS {
            return Err(Error::OutOfMemory);
        }
        const NONE_INODE: Option<Inode> = None;
        const NONE_DATA: Option<LayerInodeData> = None;
        const NONE_ENTRY: Option<OverlayDirEntryInner> = None;

        let idx = self.layer_count;
        let mut inodes = [NONE_INODE; MAX_INODES];
        let mut data = [NONE_DATA; MAX_INODES];

        let root_ino = InodeNumber(1);
        inodes[0] = Some(Inode::new(
            root_ino,
            FileType::Directory,
            FileMode::DIR_DEFAULT,
        ));
        data[0] = Some(LayerInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });

        self.layers[idx] = Some(LayerStorage {
            layer,
            inodes,
            data,
            next_ino: 2,
        });
        self.layer_count += 1;
        Ok(())
    }

    /// Return the mount configuration.
    pub fn mount_config(&self) -> &OverlayMount {
        &self.mount
    }

    /// Return the number of active layers.
    pub fn layer_count(&self) -> usize {
        self.layer_count
    }

    /// Find the slot index for an inode in a specific layer.
    fn slot_in_layer(storage: &LayerStorage, ino: InodeNumber) -> Option<usize> {
        storage
            .inodes
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|i| i.ino == ino))
    }

    /// Check whether a name is whited-out under a given parent.
    fn is_whiteout(&self, parent_ino: InodeNumber, name: &[u8]) -> bool {
        self.whiteouts.iter().any(|wh| {
            wh.as_ref()
                .is_some_and(|w| w.parent_ino == parent_ino && w.name_bytes() == name)
        })
    }

    /// Add a whiteout entry for a name under a parent.
    fn add_whiteout(&mut self, parent_ino: InodeNumber, name: &str) -> Result<()> {
        if self.whiteout_count >= MAX_WHITEOUTS {
            return Err(Error::OutOfMemory);
        }
        let wh = Whiteout::new(name, parent_ino)?;
        for slot in &mut self.whiteouts {
            if slot.is_none() {
                *slot = Some(wh);
                self.whiteout_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a whiteout entry if it exists.
    fn remove_whiteout(&mut self, parent_ino: InodeNumber, name: &[u8]) {
        for slot in &mut self.whiteouts {
            let matches = slot
                .as_ref()
                .is_some_and(|w| w.parent_ino == parent_ino && w.name_bytes() == name);
            if matches {
                *slot = None;
                self.whiteout_count = self.whiteout_count.saturating_sub(1);
                return;
            }
        }
    }

    /// Allocate a new inode in the upper layer.
    fn alloc_upper_inode(
        &mut self,
        file_type: FileType,
        mode: FileMode,
    ) -> Result<(usize, InodeNumber)> {
        let storage = self.layers[0].as_mut().ok_or(Error::NotFound)?;
        let ino = InodeNumber(storage.next_ino);
        storage.next_ino += 1;

        for (idx, slot) in storage.inodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Inode::new(ino, file_type, mode));
                return Ok((idx, ino));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Add a directory entry to the upper layer.
    fn add_upper_dir_entry(
        &mut self,
        parent_slot: usize,
        name: &str,
        child_ino: InodeNumber,
    ) -> Result<()> {
        let storage = self.layers[0].as_mut().ok_or(Error::NotFound)?;
        let data = storage.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let LayerInodeData::Dir { entries, count } = data {
            if *count >= MAX_DIR_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            let name_bytes = name.as_bytes();
            if name_bytes.len() > 255 {
                return Err(Error::InvalidArgument);
            }
            for existing in entries.iter().flatten() {
                if &existing.name[..existing.name_len] == name_bytes {
                    return Err(Error::AlreadyExists);
                }
            }
            let mut entry_name = [0u8; MAX_PATH_LEN];
            entry_name[..name_bytes.len()].copy_from_slice(name_bytes);
            for slot in entries.iter_mut() {
                if slot.is_none() {
                    *slot = Some(OverlayDirEntryInner {
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

    /// Perform a copy-up: copy file data from lower to upper layer.
    ///
    /// Returns a [`CopyUp`] descriptor with the new upper inode.
    fn copy_up_file(
        &mut self,
        lower_layer_idx: usize,
        lower_slot: usize,
        parent_slot_upper: usize,
        name: &str,
    ) -> Result<CopyUp> {
        // Read source data from the lower layer.
        let (src_data, src_len, src_inode) = {
            let lower = self.layers[lower_layer_idx]
                .as_ref()
                .ok_or(Error::NotFound)?;
            let inode = lower.inodes[lower_slot].ok_or(Error::NotFound)?;
            match &lower.data[lower_slot] {
                Some(LayerInodeData::File { data, len }) => {
                    let mut buf = [0u8; MAX_FILE_SIZE];
                    buf[..*len].copy_from_slice(&data[..*len]);
                    (buf, *len, inode)
                }
                _ => return Err(Error::InvalidArgument),
            }
        };

        // Allocate in upper layer.
        let (upper_slot, upper_ino) =
            self.alloc_upper_inode(src_inode.file_type, src_inode.mode)?;

        // Store file data in upper layer.
        if let Some(storage) = &mut self.layers[0] {
            storage.data[upper_slot] = Some(LayerInodeData::File {
                data: src_data,
                len: src_len,
            });
            if let Some(meta) = &mut storage.inodes[upper_slot] {
                meta.size = src_len as u64;
                meta.uid = src_inode.uid;
                meta.gid = src_inode.gid;
            }
        }

        // Add directory entry in upper.
        self.add_upper_dir_entry(parent_slot_upper, name, upper_ino)?;

        Ok(CopyUp {
            source_ino: src_inode.ino,
            source_layer: self.layers[lower_layer_idx]
                .as_ref()
                .map_or(0, |s| s.layer.layer_id),
            dest_ino: upper_ino,
            completed: true,
        })
    }

    /// Ensure the upper layer has a directory entry for the parent
    /// path. Returns the upper-layer slot of the parent directory.
    fn ensure_upper_parent(&mut self, parent_ino: InodeNumber) -> Result<usize> {
        // Check if parent already exists in upper layer.
        if let Some(storage) = &self.layers[0] {
            if let Some(slot) = Self::slot_in_layer(storage, parent_ino) {
                return Ok(slot);
            }
        }
        // Parent not in upper — create a directory in upper
        // with the same inode number semantics.
        const NONE_ENTRY: Option<OverlayDirEntryInner> = None;
        let (slot, _) = self.alloc_upper_inode(FileType::Directory, FileMode::DIR_DEFAULT)?;
        if let Some(storage) = &mut self.layers[0] {
            storage.data[slot] = Some(LayerInodeData::Dir {
                entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
                count: 0,
            });
        }
        Ok(slot)
    }
}

/// Resolve a path through overlay layers (upper first, then lower).
///
/// Returns an [`OverlayInode`] describing which layer the resolved
/// inode belongs to and its whiteout/copy-up status.
pub fn overlay_lookup(fs: &OverlayFs, name: &str) -> Result<OverlayInode> {
    let name_bytes = name.as_bytes();
    let root_ino = InodeNumber(1);

    // Check whiteouts first.
    if fs.is_whiteout(root_ino, name_bytes) {
        return Err(Error::NotFound);
    }

    // Search upper layer first (index 0).
    for layer_idx in 0..fs.layer_count {
        let storage = match &fs.layers[layer_idx] {
            Some(s) => s,
            None => continue,
        };
        // Look up in root directory of this layer.
        let root_slot = match OverlayFs::slot_in_layer(storage, root_ino) {
            Some(s) => s,
            None => continue,
        };
        let data = match &storage.data[root_slot] {
            Some(d) => d,
            None => continue,
        };
        if let LayerInodeData::Dir { entries, .. } = data {
            for entry in entries.iter().flatten() {
                if &entry.name[..entry.name_len] == name_bytes {
                    let child_slot = match OverlayFs::slot_in_layer(storage, entry.inode) {
                        Some(s) => s,
                        None => continue,
                    };
                    let inode = match &storage.inodes[child_slot] {
                        Some(i) => *i,
                        None => continue,
                    };
                    return Ok(OverlayInode {
                        inode,
                        source_layer: storage.layer.layer_id,
                        whiteout: false,
                        copied_up: layer_idx == 0,
                    });
                }
            }
        }
    }

    Err(Error::NotFound)
}

/// Read data from the appropriate layer for an overlay inode.
///
/// Reads from whichever layer currently holds the inode data.
/// If the inode was copied up, reads come from the upper layer.
pub fn overlay_read(
    fs: &OverlayFs,
    ov_inode: &OverlayInode,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize> {
    // Find the layer that owns this inode.
    for layer_idx in 0..fs.layer_count {
        let storage = match &fs.layers[layer_idx] {
            Some(s) => s,
            None => continue,
        };
        if storage.layer.layer_id != ov_inode.source_layer {
            continue;
        }
        let slot = match OverlayFs::slot_in_layer(storage, ov_inode.inode.ino) {
            Some(s) => s,
            None => return Err(Error::NotFound),
        };
        let data = storage.data[slot].as_ref().ok_or(Error::NotFound)?;
        if let LayerInodeData::File {
            data: file_data,
            len,
        } = data
        {
            let off = offset as usize;
            if off >= *len {
                return Ok(0);
            }
            let available = *len - off;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&file_data[off..off + to_read]);
            return Ok(to_read);
        }
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotFound)
}

/// Write data to the upper layer, performing copy-up if needed.
///
/// If the inode resides in a lower layer, it is first copied to
/// the upper layer. All writes go to the upper layer.
pub fn overlay_write(
    fs: &mut OverlayFs,
    ov_inode: &mut OverlayInode,
    offset: u64,
    data: &[u8],
) -> Result<usize> {
    let off = offset as usize;
    let end = off + data.len();
    if end > MAX_FILE_SIZE {
        return Err(Error::OutOfMemory);
    }

    // If the inode is not in the upper layer, copy-up first.
    if ov_inode.source_layer != 0 {
        let lower_idx = {
            let mut found = None;
            for i in 0..fs.layer_count {
                if let Some(s) = &fs.layers[i] {
                    if s.layer.layer_id == ov_inode.source_layer {
                        found = Some(i);
                        break;
                    }
                }
            }
            found.ok_or(Error::NotFound)?
        };
        let lower_slot = {
            let storage = fs.layers[lower_idx].as_ref().ok_or(Error::NotFound)?;
            OverlayFs::slot_in_layer(storage, ov_inode.inode.ino).ok_or(Error::NotFound)?
        };
        let parent_slot = fs.ensure_upper_parent(InodeNumber(1))?;
        let copy = fs.copy_up_file(lower_idx, lower_slot, parent_slot, "")?;
        ov_inode.inode.ino = copy.dest_ino;
        ov_inode.source_layer = 0;
        ov_inode.copied_up = true;
    }

    // Write to the upper layer.
    let storage = fs.layers[0].as_mut().ok_or(Error::NotFound)?;
    let slot = OverlayFs::slot_in_layer(storage, ov_inode.inode.ino).ok_or(Error::NotFound)?;
    let inode_data = storage.data[slot].as_mut().ok_or(Error::NotFound)?;

    if let LayerInodeData::File {
        data: file_data,
        len,
    } = inode_data
    {
        file_data[off..end].copy_from_slice(data);
        if end > *len {
            *len = end;
        }
        if let Some(meta) = storage.inodes[slot].as_mut() {
            meta.size = *len as u64;
        }
        Ok(data.len())
    } else {
        Err(Error::InvalidArgument)
    }
}

/// Produce a merged directory listing with whiteout filtering.
///
/// Iterates over all layers starting from the upper layer.
/// Entries present in higher layers shadow entries with the same
/// name in lower layers. Whiteout entries suppress the
/// corresponding lower-layer entries entirely.
pub fn overlay_readdir(fs: &OverlayFs, parent_ino: InodeNumber) -> Result<OverlayDir> {
    let mut merged = OverlayDir::new();

    for layer_idx in 0..fs.layer_count {
        let storage = match &fs.layers[layer_idx] {
            Some(s) => s,
            None => continue,
        };
        let root_slot = match OverlayFs::slot_in_layer(storage, parent_ino) {
            Some(s) => s,
            None => continue,
        };
        let data = match &storage.data[root_slot] {
            Some(d) => d,
            None => continue,
        };
        if let LayerInodeData::Dir { entries, .. } = data {
            for entry in entries.iter().flatten() {
                let name = &entry.name[..entry.name_len];

                // Skip if whited out.
                if fs.is_whiteout(parent_ino, name) {
                    continue;
                }

                // Skip if already present from a higher layer.
                let already_present = merged
                    .entries()
                    .iter()
                    .any(|e| e.as_ref().is_some_and(|d| d.name_bytes() == name));
                if already_present {
                    continue;
                }

                let mut dentry_name = [0u8; MAX_PATH_LEN];
                dentry_name[..entry.name_len].copy_from_slice(name);

                merged.add(OverlayDentry {
                    ino: entry.inode,
                    source_layer: storage.layer.layer_id,
                    name_len: entry.name_len,
                    name: dentry_name,
                    hidden: false,
                })?;
            }
        }
    }

    Ok(merged)
}

impl InodeOps for OverlayFs {
    fn lookup(&self, _parent: &Inode, name: &str) -> Result<Inode> {
        let ov = overlay_lookup(self, name)?;
        Ok(ov.inode)
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        // Remove any existing whiteout for this name.
        self.remove_whiteout(parent.ino, name.as_bytes());

        let parent_slot = self.ensure_upper_parent(parent.ino)?;
        let (child_slot, child_ino) = self.alloc_upper_inode(FileType::Regular, mode)?;

        if let Some(storage) = &mut self.layers[0] {
            storage.data[child_slot] = Some(LayerInodeData::File {
                data: [0u8; MAX_FILE_SIZE],
                len: 0,
            });
        }

        self.add_upper_dir_entry(parent_slot, name, child_ino)?;

        let storage = self.layers[0].as_ref().ok_or(Error::NotFound)?;
        storage.inodes[child_slot].ok_or(Error::NotFound)
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        self.remove_whiteout(parent.ino, name.as_bytes());

        let parent_slot = self.ensure_upper_parent(parent.ino)?;
        let (child_slot, child_ino) = self.alloc_upper_inode(FileType::Directory, mode)?;

        const NONE_ENTRY: Option<OverlayDirEntryInner> = None;
        if let Some(storage) = &mut self.layers[0] {
            storage.data[child_slot] = Some(LayerInodeData::Dir {
                entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
                count: 0,
            });
        }

        self.add_upper_dir_entry(parent_slot, name, child_ino)?;

        let storage = self.layers[0].as_ref().ok_or(Error::NotFound)?;
        storage.inodes[child_slot].ok_or(Error::NotFound)
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();

        // Try to remove from upper layer first.
        let removed_from_upper = if let Some(storage) = &mut self.layers[0] {
            let parent_slot = Self::slot_in_layer(storage, parent.ino);
            if let Some(ps) = parent_slot {
                let data = storage.data[ps].as_mut();
                if let Some(LayerInodeData::Dir { entries, count, .. }) = data {
                    let mut found = false;
                    for slot in entries.iter_mut() {
                        if let Some(entry) = slot {
                            if &entry.name[..entry.name_len] == name_bytes {
                                let ino = entry.inode;
                                *slot = None;
                                *count -= 1;
                                // Free inode data.
                                if let Some(cs) = Self::slot_in_layer(storage, ino) {
                                    storage.inodes[cs] = None;
                                    storage.data[cs] = None;
                                }
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // Check if the file exists in a lower layer.
        let exists_in_lower = (1..self.layer_count).any(|i| {
            if let Some(storage) = &self.layers[i] {
                let ps = Self::slot_in_layer(storage, parent.ino);
                if let Some(ps) = ps {
                    if let Some(LayerInodeData::Dir { entries, .. }) = &storage.data[ps] {
                        return entries
                            .iter()
                            .flatten()
                            .any(|e| &e.name[..e.name_len] == name_bytes);
                    }
                }
            }
            false
        });

        if !removed_from_upper && !exists_in_lower {
            return Err(Error::NotFound);
        }

        // If it exists in a lower layer, add a whiteout.
        if exists_in_lower {
            self.add_whiteout(parent.ino, name)?;
        }

        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        // Reuse unlink semantics — overlayfs rmdir also creates
        // whiteouts for lower-layer directories.
        self.unlink(parent, name)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        // Search all layers for the inode.
        for layer_idx in 0..self.layer_count {
            let storage = match &self.layers[layer_idx] {
                Some(s) => s,
                None => continue,
            };
            let slot = match Self::slot_in_layer(storage, inode.ino) {
                Some(s) => s,
                None => continue,
            };
            let data = storage.data[slot].as_ref().ok_or(Error::NotFound)?;
            if let LayerInodeData::File {
                data: file_data,
                len,
            } = data
            {
                let off = offset as usize;
                if off >= *len {
                    return Ok(0);
                }
                let available = *len - off;
                let to_read = buf.len().min(available);
                buf[..to_read].copy_from_slice(&file_data[off..off + to_read]);
                return Ok(to_read);
            }
            return Err(Error::InvalidArgument);
        }
        Err(Error::NotFound)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let off = offset as usize;
        let end = off + data.len();
        if end > MAX_FILE_SIZE {
            return Err(Error::OutOfMemory);
        }

        // Check if inode is in upper layer.
        let upper_slot = self.layers[0]
            .as_ref()
            .and_then(|s| Self::slot_in_layer(s, inode.ino));

        if let Some(slot) = upper_slot {
            // Direct write to upper.
            let storage = self.layers[0].as_mut().ok_or(Error::NotFound)?;
            let inode_data = storage.data[slot].as_mut().ok_or(Error::NotFound)?;
            if let LayerInodeData::File {
                data: file_data,
                len,
            } = inode_data
            {
                file_data[off..end].copy_from_slice(data);
                if end > *len {
                    *len = end;
                }
                if let Some(meta) = storage.inodes[slot].as_mut() {
                    meta.size = *len as u64;
                }
                return Ok(data.len());
            }
            return Err(Error::InvalidArgument);
        }

        // Inode is in a lower layer — need copy-up.
        // Find which lower layer has it.
        let (lower_idx, lower_slot) = {
            let mut found = None;
            for i in 1..self.layer_count {
                if let Some(s) = &self.layers[i] {
                    if let Some(slot) = Self::slot_in_layer(s, inode.ino) {
                        found = Some((i, slot));
                        break;
                    }
                }
            }
            found.ok_or(Error::NotFound)?
        };

        let parent_slot = self.ensure_upper_parent(InodeNumber(1))?;
        let copy = self.copy_up_file(lower_idx, lower_slot, parent_slot, "")?;

        // Now write to the copied-up inode in upper.
        let storage = self.layers[0].as_mut().ok_or(Error::NotFound)?;
        let slot = Self::slot_in_layer(storage, copy.dest_ino).ok_or(Error::NotFound)?;
        let inode_data = storage.data[slot].as_mut().ok_or(Error::NotFound)?;
        if let LayerInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            file_data[off..end].copy_from_slice(data);
            if end > *len {
                *len = end;
            }
            if let Some(meta) = storage.inodes[slot].as_mut() {
                meta.size = *len as u64;
            }
            Ok(data.len())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        // Check upper layer first.
        let upper_slot = self.layers[0]
            .as_ref()
            .and_then(|s| Self::slot_in_layer(s, inode.ino));

        let slot = if let Some(s) = upper_slot {
            s
        } else {
            // Copy-up needed.
            let (lower_idx, lower_slot) = {
                let mut found = None;
                for i in 1..self.layer_count {
                    if let Some(s) = &self.layers[i] {
                        if let Some(slot) = Self::slot_in_layer(s, inode.ino) {
                            found = Some((i, slot));
                            break;
                        }
                    }
                }
                found.ok_or(Error::NotFound)?
            };
            let parent_slot = self.ensure_upper_parent(InodeNumber(1))?;
            let copy = self.copy_up_file(lower_idx, lower_slot, parent_slot, "")?;
            let storage = self.layers[0].as_ref().ok_or(Error::NotFound)?;
            Self::slot_in_layer(storage, copy.dest_ino).ok_or(Error::NotFound)?
        };

        let storage = self.layers[0].as_mut().ok_or(Error::NotFound)?;
        let inode_data = storage.data[slot].as_mut().ok_or(Error::NotFound)?;

        if let LayerInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            let new_len = (size as usize).min(MAX_FILE_SIZE);
            if new_len < *len {
                file_data[new_len..*len].fill(0);
            }
            *len = new_len;
            if let Some(meta) = storage.inodes[slot].as_mut() {
                meta.size = new_len as u64;
            }
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

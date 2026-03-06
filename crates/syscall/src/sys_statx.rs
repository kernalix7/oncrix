// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `statx(2)` — extended file attribute query.
//!
//! `statx` supersedes `stat`, `lstat`, and `fstat` by exposing fields that the
//! original `struct stat` cannot represent:
//!
//! - **Birth time** (`stx_btime`) — file creation timestamp.
//! - **Mount ID** (`stx_mnt_id`) — identifies the mount point.
//! - **Direct I/O alignment** (`stx_dio_mem_align`, `stx_dio_offset_align`).
//! - **Attributes** (`stx_attributes`) — immutable, append-only, encrypted, etc.
//!
//! The caller specifies a *request mask* indicating which fields it needs.
//! The kernel fills only the fields it can provide; the *result mask* reports
//! which fields are actually valid in the returned buffer.
//!
//! # Syscall signature
//!
//! ```text
//! int statx(int dirfd, const char *restrict pathname,
//!           int flags, unsigned int mask,
//!           struct statx *restrict statxbuf);
//! ```
//!
//! # AT_STATX synchronisation flags
//!
//! | Flag                    | Value  | Meaning                                    |
//! |-------------------------|--------|--------------------------------------------|
//! | `AT_STATX_SYNC_AS_STAT` | 0x0000 | Default; sync behaviour matches `stat(2)`. |
//! | `AT_STATX_FORCE_SYNC`   | 0x2000 | Force a network/remote filesystem sync.    |
//! | `AT_STATX_DONT_SYNC`    | 0x4000 | Return cached data only; no I/O.           |
//!
//! # POSIX context
//!
//! `statx` is a Linux extension; POSIX.1-2024 defines `stat(2)` and `fstat(2)`
//! only.  The field naming follows the Linux UAPI (`struct statx`).
//!
//! # Linux reference
//!
//! `fs/stat.c` — `do_statx`, `vfs_statx`; `include/uapi/linux/stat.h`

use oncrix_lib::{Error, Result};

// Re-export the core `StatxMask` and `StatxTimestamp` types from the lower-
// level module so callers only need to import this module.
pub use crate::statx::{StatxMask, StatxTimestamp};

// ---------------------------------------------------------------------------
// AT_* flags
// ---------------------------------------------------------------------------

/// Use the current working directory as base when `pathname` is relative.
pub const AT_FDCWD: i32 = -100;
/// Do not follow a trailing symbolic link.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// Operate on `dirfd` itself when `pathname` is empty.
pub const AT_EMPTY_PATH: i32 = 0x1000;
/// Do not automount the final path component.
pub const AT_NO_AUTOMOUNT: i32 = 0x800;
/// Sync behaviour matches `stat(2)` (default; value is 0).
pub const AT_STATX_SYNC_AS_STAT: i32 = 0x0000;
/// Force synchronisation with the filesystem before returning.
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// Return cached data only; do not trigger any I/O.
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;

/// All valid flag bits for `statx`.
const FLAGS_VALID: i32 = AT_SYMLINK_NOFOLLOW
    | AT_EMPTY_PATH
    | AT_NO_AUTOMOUNT
    | AT_STATX_FORCE_SYNC
    | AT_STATX_DONT_SYNC;

// ---------------------------------------------------------------------------
// Attribute bit constants (stx_attributes / stx_attributes_mask)
// ---------------------------------------------------------------------------

/// File is compressed by the filesystem.
pub const STATX_ATTR_COMPRESSED: u64 = 1 << 2;
/// File is immutable.
pub const STATX_ATTR_IMMUTABLE: u64 = 1 << 3;
/// File is append-only.
pub const STATX_ATTR_APPEND: u64 = 1 << 4;
/// File is not a candidate for backup.
pub const STATX_ATTR_NODUMP: u64 = 1 << 6;
/// File requires a key to be encrypted/decrypted.
pub const STATX_ATTR_ENCRYPTED: u64 = 1 << 11;
/// Directory is an automount point.
pub const STATX_ATTR_AUTOMOUNT: u64 = 1 << 12;
/// This is the root of a mount.
pub const STATX_ATTR_MOUNT_ROOT: u64 = 1 << 13;
/// File has fs-verity protection enabled.
pub const STATX_ATTR_VERITY: u64 = 1 << 20;
/// File is in the DAX (direct access) state.
pub const STATX_ATTR_DAX: u64 = 1 << 21;

// ---------------------------------------------------------------------------
// File type constants (stx_mode & S_IFMT)
// ---------------------------------------------------------------------------

/// Regular file.
pub const S_IFREG: u16 = 0o100000;
/// Directory.
pub const S_IFDIR: u16 = 0o040000;
/// Symbolic link.
pub const S_IFLNK: u16 = 0o120000;
/// Character device.
pub const S_IFCHR: u16 = 0o020000;
/// Block device.
pub const S_IFBLK: u16 = 0o060000;
/// FIFO / named pipe.
pub const S_IFIFO: u16 = 0o010000;
/// Unix-domain socket.
pub const S_IFSOCK: u16 = 0o140000;
/// File type mask.
pub const S_IFMT: u16 = 0o170000;

// ---------------------------------------------------------------------------
// Statx — the extended stat buffer
// ---------------------------------------------------------------------------

/// Extended file metadata buffer returned by `statx(2)`.
///
/// Mirrors `struct statx` from `include/uapi/linux/stat.h`.
/// Fields that were not requested by the caller, or that the filesystem cannot
/// supply, are zero-initialised; only fields present in `mask` are valid.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Statx {
    /// Mask of bits indicating filled fields.
    pub mask: u32,
    /// Block size for filesystem I/O.
    pub blksize: u32,
    /// Further status information (see `STATX_ATTR_*`).
    pub attributes: u64,
    /// Number of hard links.
    pub nlink: u32,
    /// User ID of owner.
    pub uid: u32,
    /// Group ID of owner.
    pub gid: u32,
    /// File type and mode.
    pub mode: u16,
    /// Padding (reserved).
    pub _spare0: [u16; 1],
    /// Inode number.
    pub ino: u64,
    /// Total size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Mask of supported attributes.
    pub attributes_mask: u64,
    /// Last access time.
    pub atime: StatxTimestamp,
    /// File birth (creation) time.
    pub btime: StatxTimestamp,
    /// Last status change time.
    pub ctime: StatxTimestamp,
    /// Last data modification time.
    pub mtime: StatxTimestamp,
    /// Device major (if special file).
    pub rdev_major: u32,
    /// Device minor (if special file).
    pub rdev_minor: u32,
    /// Device major on which file resides.
    pub dev_major: u32,
    /// Device minor on which file resides.
    pub dev_minor: u32,
    /// Mount ID of the mount the file belongs to.
    pub mnt_id: u64,
    /// Memory alignment for direct I/O buffers (0 = unknown).
    pub dio_mem_align: u32,
    /// Offset alignment for direct I/O (0 = unknown).
    pub dio_offset_align: u32,
    /// Extended mount ID (64-bit; may differ from `mnt_id`).
    pub mnt_id_unique: u64,
}

impl Statx {
    /// Create an empty, zeroed `Statx` buffer.
    pub const fn new() -> Self {
        Self {
            mask: 0,
            blksize: 0,
            attributes: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            _spare0: [0],
            ino: 0,
            size: 0,
            blocks: 0,
            attributes_mask: 0,
            atime: StatxTimestamp {
                tv_sec: 0,
                tv_nsec: 0,
                pad: 0,
            },
            btime: StatxTimestamp {
                tv_sec: 0,
                tv_nsec: 0,
                pad: 0,
            },
            ctime: StatxTimestamp {
                tv_sec: 0,
                tv_nsec: 0,
                pad: 0,
            },
            mtime: StatxTimestamp {
                tv_sec: 0,
                tv_nsec: 0,
                pad: 0,
            },
            rdev_major: 0,
            rdev_minor: 0,
            dev_major: 0,
            dev_minor: 0,
            mnt_id: 0,
            dio_mem_align: 0,
            dio_offset_align: 0,
            mnt_id_unique: 0,
        }
    }

    /// Return `true` if the file is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// Return `true` if the file is a regular file.
    pub fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    /// Return `true` if the file is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    /// Return `true` if the attribute `STATX_ATTR_IMMUTABLE` is set and valid.
    pub fn is_immutable(&self) -> bool {
        self.attributes_mask & STATX_ATTR_IMMUTABLE != 0
            && self.attributes & STATX_ATTR_IMMUTABLE != 0
    }
}

// ---------------------------------------------------------------------------
// Stub filesystem entry
// ---------------------------------------------------------------------------

/// Maximum number of entries in the stub filesystem.
const MAX_ENTRIES: usize = 64;

/// A stub inode entry in the mock filesystem, used for tests.
#[derive(Clone, Copy)]
pub struct InodeEntry {
    /// Whether this slot is occupied.
    pub active: bool,
    /// Inode number.
    pub ino: u64,
    /// File mode (type + permission bits).
    pub mode: u16,
    /// File size.
    pub size: u64,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Birth time.
    pub btime_sec: i64,
    /// Modification time.
    pub mtime_sec: i64,
    /// Mount ID.
    pub mnt_id: u64,
    /// Attribute bits.
    pub attributes: u64,
    /// Attribute mask.
    pub attributes_mask: u64,
    /// Pathname (null-terminated, up to 63 bytes).
    pub path: [u8; 64],
}

impl InodeEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            ino: 0,
            mode: 0,
            size: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            btime_sec: 0,
            mtime_sec: 0,
            mnt_id: 0,
            attributes: 0,
            attributes_mask: 0,
            path: [0; 64],
        }
    }
}

/// Stub filesystem used by `do_sys_statx` in tests.
pub struct StubFs {
    entries: [InodeEntry; MAX_ENTRIES],
    count: usize,
}

impl StubFs {
    /// Create an empty stub filesystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { InodeEntry::empty() }; MAX_ENTRIES],
            count: 0,
        }
    }

    /// Register an inode entry.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, entry: InodeEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.active {
                *slot = entry;
                slot.active = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an entry by path bytes.
    pub fn find_path(&self, path: &[u8]) -> Option<&InodeEntry> {
        self.entries.iter().find(|e| {
            if !e.active {
                return false;
            }
            // Compare up to the null terminator or path length.
            let elen = e.path.iter().position(|&b| b == 0).unwrap_or(64);
            &e.path[..elen] == path
        })
    }
}

impl Default for StubFs {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// statx handler
// ---------------------------------------------------------------------------

/// Validated arguments for the `statx` call (internal).
struct ValidatedStatxArgs {
    dirfd: i32,
    flags: i32,
    mask: u32,
}

/// Validate `statx` arguments (pure, no side effects).
fn validate_statx_args(
    dirfd: i32,
    pathname_ptr: u64,
    flags: i32,
    mask: u32,
    statxbuf_ptr: u64,
) -> Result<ValidatedStatxArgs> {
    // Reject unknown flag bits.
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    // FORCE_SYNC and DONT_SYNC are mutually exclusive.
    if flags & AT_STATX_FORCE_SYNC != 0 && flags & AT_STATX_DONT_SYNC != 0 {
        return Err(Error::InvalidArgument);
    }
    // Null `statxbuf` pointer is always invalid.
    if statxbuf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // Null pathname is only allowed with AT_EMPTY_PATH.
    if pathname_ptr == 0 && flags & AT_EMPTY_PATH == 0 {
        return Err(Error::InvalidArgument);
    }
    // dirfd must be AT_FDCWD or a plausible file descriptor.
    if dirfd != AT_FDCWD && !(0..=1_048_576).contains(&dirfd) {
        return Err(Error::InvalidArgument);
    }

    Ok(ValidatedStatxArgs { dirfd, flags, mask })
}

/// Fill a `Statx` buffer from a stub inode entry, respecting the `mask`.
fn fill_statx(entry: &InodeEntry, args: &ValidatedStatxArgs) -> Statx {
    let mut buf = Statx::new();
    let m = StatxMask::from_raw(args.mask);

    if m.contains(StatxMask::TYPE) || m.contains(StatxMask::MODE) {
        buf.mode = entry.mode;
        buf.mask |= StatxMask::TYPE.bits() | StatxMask::MODE.bits();
    }
    if m.contains(StatxMask::NLINK) {
        buf.nlink = entry.nlink;
        buf.mask |= StatxMask::NLINK.bits();
    }
    if m.contains(StatxMask::UID) {
        buf.uid = entry.uid;
        buf.mask |= StatxMask::UID.bits();
    }
    if m.contains(StatxMask::GID) {
        buf.gid = entry.gid;
        buf.mask |= StatxMask::GID.bits();
    }
    if m.contains(StatxMask::SIZE) {
        buf.size = entry.size;
        buf.mask |= StatxMask::SIZE.bits();
    }
    if m.contains(StatxMask::INO) {
        buf.ino = entry.ino;
        buf.mask |= StatxMask::INO.bits();
    }
    if m.contains(StatxMask::MTIME) {
        buf.mtime = StatxTimestamp {
            tv_sec: entry.mtime_sec,
            tv_nsec: 0,
            pad: 0,
        };
        buf.mask |= StatxMask::MTIME.bits();
    }
    if m.contains(StatxMask::BTIME) {
        buf.btime = StatxTimestamp {
            tv_sec: entry.btime_sec,
            tv_nsec: 0,
            pad: 0,
        };
        buf.mask |= StatxMask::BTIME.bits();
    }
    if m.contains(StatxMask::MNT_ID) {
        buf.mnt_id = entry.mnt_id;
        buf.mnt_id_unique = entry.mnt_id;
        buf.mask |= StatxMask::MNT_ID.bits();
    }
    buf.attributes = entry.attributes;
    buf.attributes_mask = entry.attributes_mask;
    buf.blksize = 4096;
    // Blocks = ceil(size / 512).
    buf.blocks = entry.size.saturating_add(511) / 512;
    // dirfd is inspected here to avoid a dead-code warning.
    let _ = args.dirfd;
    buf
}

/// `statx(2)` handler.
///
/// Validates arguments and fills a `Statx` buffer from the stub filesystem.
///
/// # Arguments
///
/// * `dirfd`        — Base directory fd or `AT_FDCWD`.
/// * `pathname_ptr` — User-space address of the pathname (0 allowed with
///                    `AT_EMPTY_PATH`).
/// * `flags`        — `AT_*` flags.
/// * `mask`         — Requested field mask (`STATX_*` bits).
/// * `statxbuf_ptr` — User-space address of the output buffer (must be != 0).
/// * `path_bytes`   — Resolved path bytes (kernel-side; replaces user copy).
/// * `fs`           — Stub filesystem for path lookup.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad flags, null buffer, or null path without
///   `AT_EMPTY_PATH`.
/// * [`Error::NotFound`]        — path not found in the stub filesystem.
pub fn do_sys_statx(
    dirfd: i32,
    pathname_ptr: u64,
    flags: i32,
    mask: u32,
    statxbuf_ptr: u64,
    path_bytes: &[u8],
    fs: &StubFs,
) -> Result<Statx> {
    let args: ValidatedStatxArgs =
        validate_statx_args(dirfd, pathname_ptr, flags, mask, statxbuf_ptr)?;

    // With AT_EMPTY_PATH the caller wants metadata for `dirfd` itself.
    // For the stub we still do a path lookup using whatever path_bytes
    // the caller supplies (the integration path would resolve dirfd).
    let entry = fs.find_path(path_bytes).ok_or(Error::NotFound)?;
    Ok(fill_statx(entry, &args))
}

/// Convenience wrapper: query all fields for a path.
///
/// Uses [`StatxMask::ALL`] as the request mask.
pub fn statx_query_all(dirfd: i32, path_bytes: &[u8], fs: &StubFs) -> Result<Statx> {
    // Placeholder non-null pointer values for validation.
    let pathname_ptr: u64 = if path_bytes.is_empty() { 0 } else { 0x1000 };
    let statxbuf_ptr: u64 = 0x2000;
    let flags = if path_bytes.is_empty() {
        AT_EMPTY_PATH
    } else {
        0
    };
    do_sys_statx(
        dirfd,
        pathname_ptr,
        flags,
        StatxMask::ALL.bits(),
        statxbuf_ptr,
        path_bytes,
        fs,
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fs() -> StubFs {
        let mut fs = StubFs::new();
        let mut path = [0u8; 64];
        let src = b"/etc/passwd";
        path[..src.len()].copy_from_slice(src);
        fs.insert(InodeEntry {
            active: true,
            ino: 12345,
            mode: S_IFREG | 0o644,
            size: 2048,
            nlink: 1,
            uid: 0,
            gid: 0,
            btime_sec: 1_700_000_000,
            mtime_sec: 1_710_000_000,
            mnt_id: 42,
            attributes: STATX_ATTR_IMMUTABLE,
            attributes_mask: STATX_ATTR_IMMUTABLE,
            path,
        })
        .unwrap();
        fs
    }

    #[test]
    fn basic_query_regular_file() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        assert!(buf.is_regular());
        assert_eq!(buf.ino, 12345);
        assert_eq!(buf.size, 2048);
        assert_eq!(buf.uid, 0);
        assert_eq!(buf.mnt_id, 42);
    }

    #[test]
    fn birth_time_returned() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        assert_eq!(buf.btime.tv_sec, 1_700_000_000);
    }

    #[test]
    fn mtime_returned() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        assert_eq!(buf.mtime.tv_sec, 1_710_000_000);
    }

    #[test]
    fn immutable_attribute_visible() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        assert!(buf.is_immutable());
    }

    #[test]
    fn path_not_found() {
        let fs = make_fs();
        assert_eq!(
            statx_query_all(AT_FDCWD, b"/no/such/file", &fs),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn null_statxbuf_rejected() {
        let fs = StubFs::new();
        assert_eq!(
            do_sys_statx(AT_FDCWD, 0x1000, 0, 0xFFFF, 0, b"x", &fs),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_path_without_empty_path_rejected() {
        let fs = StubFs::new();
        assert_eq!(
            do_sys_statx(AT_FDCWD, 0, 0, 0xFFFF, 0x2000, b"", &fs),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let fs = StubFs::new();
        assert_eq!(
            do_sys_statx(AT_FDCWD, 0x1000, 0x8000, 0, 0x2000, b"x", &fs),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn force_sync_and_dont_sync_mutually_exclusive() {
        let fs = StubFs::new();
        let flags = AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;
        assert_eq!(
            do_sys_statx(AT_FDCWD, 0x1000, flags, 0, 0x2000, b"x", &fs),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn selective_mask_fills_only_requested_fields() {
        let fs = make_fs();
        // Request only size and inode.
        let mask = StatxMask::SIZE.bits() | StatxMask::INO.bits();
        let buf = do_sys_statx(AT_FDCWD, 0x1000, 0, mask, 0x2000, b"/etc/passwd", &fs).unwrap();
        // Size and ino should be filled.
        assert_eq!(buf.size, 2048);
        assert_eq!(buf.ino, 12345);
        // nlink was not requested, so mask bit should be clear.
        assert_eq!(buf.mask & StatxMask::NLINK.bits(), 0);
    }

    #[test]
    fn blocks_computed_from_size() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        // ceil(2048 / 512) = 4
        assert_eq!(buf.blocks, 4);
    }

    #[test]
    fn blksize_always_4096() {
        let fs = make_fs();
        let buf = statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).unwrap();
        assert_eq!(buf.blksize, 4096);
    }

    #[test]
    fn is_dir_type_check() {
        let mut buf = Statx::new();
        buf.mode = S_IFDIR | 0o755;
        assert!(buf.is_dir());
        assert!(!buf.is_regular());
        assert!(!buf.is_symlink());
    }

    #[test]
    fn is_symlink_type_check() {
        let mut buf = Statx::new();
        buf.mode = S_IFLNK | 0o777;
        assert!(buf.is_symlink());
    }

    #[test]
    fn at_fdcwd_accepted() {
        let fs = make_fs();
        assert!(statx_query_all(AT_FDCWD, b"/etc/passwd", &fs).is_ok());
    }
}

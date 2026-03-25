// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtual File System for the ONCRIX operating system.
//!
//! Provides a unified interface for file system operations across
//! different file system implementations. Supports mounting,
//! path resolution, file descriptors, and POSIX file semantics.
//!
//! # Modules
//!
//! - [`inode`] — Inode type and operations trait
//! - [`dentry`] — Directory entry cache
//! - [`superblock`] — Filesystem superblock and registration
//! - [`file`] — Open file descriptions and file descriptor table
//! - [`file_ops`] — Unified I/O dispatch layer for fd-backed types
//! - [`flock`] — POSIX file locking (flock + fcntl advisory locks)
//! - [`page_cache`] — Page cache for file data with LRU eviction
//! - [`pipe`] — POSIX pipe (unidirectional byte stream)
//! - [`pty`] — Pseudo-terminal pairs (master/slave)
//! - [`ramfs`] — In-memory filesystem for early boot
//! - [`overlayfs`] — Overlay filesystem (union mount)
//! - [`xattr_vfs`] — VFS-level extended attribute integration

#![no_std]

pub mod acl;
pub mod btrfs;
pub mod ceph;
pub mod configfs;
#[allow(dead_code, clippy::all)]
pub mod debugfs;
pub mod dentry;
pub mod devfs;
pub mod devpts;
pub mod erofs;
pub mod ext2;
pub mod ext4;
pub mod f2fs;
pub mod fat32;
pub mod file;
pub mod file_ops;
pub mod flock;
pub mod fscrypt;
pub mod fuse;
pub mod hugetlbfs;
pub mod inode;
pub mod inotify;
pub mod journal;
pub mod nfs;
pub mod notify;

pub mod ops;
pub mod overlay_ops;
pub mod overlayfs;
pub mod page_cache;
pub mod path;
pub mod pipe;
pub mod procfs;
pub mod pty;
pub mod quota;
pub mod quota_v2;
pub mod ramfs;
pub mod squashfs;
pub mod statfs;
pub mod superblock;
pub mod sysfs;
pub mod tmpfs;
pub mod tmpfs_enhanced;
pub mod xattr_vfs;
pub mod xfs;

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod autofs;
#[allow(dead_code, clippy::all)]
pub mod pstore;
#[allow(dead_code, clippy::all)]
pub mod tracefs;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod direct_io;
#[allow(dead_code, clippy::all)]
pub mod plan9fs;
#[allow(dead_code, clippy::all)]
pub mod romfs;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod file_lease;
#[allow(dead_code, clippy::all)]
pub mod iso9660;
#[allow(dead_code, clippy::all)]
pub mod udf;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod aio;
#[allow(dead_code, clippy::all)]
pub mod file_seal;
#[allow(dead_code, clippy::all)]
pub mod splice;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod fallocate;
#[allow(dead_code, clippy::all)]
pub mod io_uring_vfs;
#[allow(dead_code, clippy::all)]
pub mod sendpage;

// --- Batch 10 ---
#[allow(dead_code, clippy::all)]
pub mod btrfs_cow;
#[allow(dead_code, clippy::all)]
pub mod fuse_dev;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod cifs;
#[allow(dead_code, clippy::all)]
pub mod fs_freeze;
#[allow(dead_code, clippy::all)]
pub mod fsnotify;

// --- Batch 12 ---
#[allow(dead_code, clippy::all)]
pub mod binderfs;
#[allow(dead_code, clippy::all)]
pub mod kernfs;
#[allow(dead_code, clippy::all)]
pub mod ntfs;

// --- Batch 13 ---
#[allow(dead_code, clippy::all)]
pub mod overlayfs_copy_up;
#[allow(dead_code, clippy::all)]
pub mod zonefs;

// --- Batch 14 ---
#[allow(dead_code, clippy::all)]
pub mod cramfs;
#[allow(dead_code, clippy::all)]
pub mod ecryptfs;
#[allow(dead_code, clippy::all)]
pub mod efivarfs;
#[allow(dead_code, clippy::all)]
pub mod exfat;
#[allow(dead_code, clippy::all)]
pub mod nilfs2;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_huge;

// --- Batch 15 ---
#[allow(dead_code, clippy::all)]
pub mod buffer_head;
#[allow(dead_code, clippy::all)]
pub mod dcache_ops;
#[allow(dead_code, clippy::all)]
pub mod fscache;
#[allow(dead_code, clippy::all)]
pub mod mount_ns;
#[allow(dead_code, clippy::all)]
pub mod readahead;
#[allow(dead_code, clippy::all)]
pub mod writeback;

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

#[allow(dead_code, clippy::all)]
pub mod autofs;
#[allow(dead_code, clippy::all)]
pub mod pstore;
#[allow(dead_code, clippy::all)]
pub mod tracefs;

#[allow(dead_code, clippy::all)]
pub mod direct_io;
#[allow(dead_code, clippy::all)]
pub mod plan9fs;
#[allow(dead_code, clippy::all)]
pub mod romfs;

#[allow(dead_code, clippy::all)]
pub mod file_lease;
#[allow(dead_code, clippy::all)]
pub mod iso9660;
#[allow(dead_code, clippy::all)]
pub mod udf;

#[allow(dead_code, clippy::all)]
pub mod aio;
#[allow(dead_code, clippy::all)]
pub mod file_seal;
#[allow(dead_code, clippy::all)]
pub mod splice;

#[allow(dead_code, clippy::all)]
pub mod fallocate;
#[allow(dead_code, clippy::all)]
pub mod io_uring_vfs;
#[allow(dead_code, clippy::all)]
pub mod sendpage;

#[allow(dead_code, clippy::all)]
pub mod btrfs_cow;
#[allow(dead_code, clippy::all)]
pub mod fuse_dev;

#[allow(dead_code, clippy::all)]
pub mod cifs;
#[allow(dead_code, clippy::all)]
pub mod fs_freeze;
#[allow(dead_code, clippy::all)]
pub mod fsnotify;

#[allow(dead_code, clippy::all)]
pub mod binderfs;
#[allow(dead_code, clippy::all)]
pub mod kernfs;
#[allow(dead_code, clippy::all)]
pub mod ntfs;

#[allow(dead_code, clippy::all)]
pub mod overlayfs_copy_up;
#[allow(dead_code, clippy::all)]
pub mod zonefs;

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

#[allow(dead_code, clippy::all)]
pub mod cachefiles;
#[allow(dead_code, clippy::all)]
pub mod erofs_compress;
#[allow(dead_code, clippy::all)]
pub mod fsverity;
#[allow(dead_code, clippy::all)]
pub mod fuse_passthrough;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_redirect;
#[allow(dead_code, clippy::all)]
pub mod quota_netlink;

#[allow(dead_code, clippy::all)]
pub mod file_lock;
#[allow(dead_code, clippy::all)]
pub mod fuse_request;
#[allow(dead_code, clippy::all)]
pub mod inotify_fs;
#[allow(dead_code, clippy::all)]
pub mod splice_ops;
#[allow(dead_code, clippy::all)]
pub mod xattr_ops;

#[allow(dead_code, clippy::all)]
pub mod anon_inode;
#[allow(dead_code, clippy::all)]
pub mod fiemap;
#[allow(dead_code, clippy::all)]
pub mod file_table;
#[allow(dead_code, clippy::all)]
pub mod fs_context;
#[allow(dead_code, clippy::all)]
pub mod iomap;
#[allow(dead_code, clippy::all)]
pub mod pipe_fs;

#[allow(dead_code, clippy::all)]
pub mod dio_direct;
#[allow(dead_code, clippy::all)]
pub mod eventpoll_fs;
#[allow(dead_code, clippy::all)]
pub mod fhandle;
#[allow(dead_code, clippy::all)]
pub mod lookup_intent;
#[allow(dead_code, clippy::all)]
pub mod mnt_idmap;
#[allow(dead_code, clippy::all)]
pub mod posix_acl;

#[allow(dead_code, clippy::all)]
pub mod aio_ring;
#[allow(dead_code, clippy::all)]
pub mod jbd2;
#[allow(dead_code, clippy::all)]
pub mod locks_proc;
#[allow(dead_code, clippy::all)]
pub mod nfs_client;
#[allow(dead_code, clippy::all)]
pub mod shmem_fs;
#[allow(dead_code, clippy::all)]
pub mod vfs_rename;

#[allow(dead_code, clippy::all)]
pub mod dcache_negative;
#[allow(dead_code, clippy::all)]
pub mod ext4_extents;
#[allow(dead_code, clippy::all)]
pub mod file_rw_iter;
#[allow(dead_code, clippy::all)]
pub mod fuse_writeback;
#[allow(dead_code, clippy::all)]
pub mod mount_propagation;
#[allow(dead_code, clippy::all)]
pub mod notify_group;

#[allow(dead_code, clippy::all)]
pub mod btrfs_core;
#[allow(dead_code, clippy::all)]
pub mod ceph_fs;
#[allow(dead_code, clippy::all)]
pub mod nfsd;
#[allow(dead_code, clippy::all)]
pub mod xfs_inode;

#[allow(dead_code, clippy::all)]
pub mod binfmt_elf;
#[allow(dead_code, clippy::all)]
pub mod coredump;
#[allow(dead_code, clippy::all)]
pub mod dentry_cache;
#[allow(dead_code, clippy::all)]
pub mod ext4_journal;
#[allow(dead_code, clippy::all)]
pub mod fat16;
#[allow(dead_code, clippy::all)]
pub mod file_writeback;
#[allow(dead_code, clippy::all)]
pub mod fs_quota_ops;
#[allow(dead_code, clippy::all)]
pub mod mapping_dirty;
#[allow(dead_code, clippy::all)]
pub mod mount_table;
#[allow(dead_code, clippy::all)]
pub mod nfs_flock;
#[allow(dead_code, clippy::all)]
pub mod nsfs;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_copy;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_whiteout;
#[allow(dead_code, clippy::all)]
pub mod readahead_control;
#[allow(dead_code, clippy::all)]
pub mod socket_fs;
#[allow(dead_code, clippy::all)]
pub mod squashfs_xattr;
#[allow(dead_code, clippy::all)]
pub mod sysfs_attr;
#[allow(dead_code, clippy::all)]
pub mod thermal_cooling;

#[allow(dead_code, clippy::all)]
pub mod btrfs_extent;
#[allow(dead_code, clippy::all)]
pub mod ext4_mballoc;
#[allow(dead_code, clippy::all)]
pub mod fuse_inode;
#[allow(dead_code, clippy::all)]
pub mod nfs_rpc;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_metacopy;
#[allow(dead_code, clippy::all)]
pub mod procfs_stat;

#[allow(dead_code, clippy::all)]
pub mod btrfs_compress;
#[allow(dead_code, clippy::all)]
pub mod btrfs_subvol;
#[allow(dead_code, clippy::all)]
pub mod cifs_ops;
#[allow(dead_code, clippy::all)]
pub mod configfs_item;
#[allow(dead_code, clippy::all)]
pub mod debugfs_file;
#[allow(dead_code, clippy::all)]
pub mod ext2_balloc;
#[allow(dead_code, clippy::all)]
pub mod ext4_inline;
#[allow(dead_code, clippy::all)]
pub mod fat32_long_name;
#[allow(dead_code, clippy::all)]
pub mod fuse_dir;
#[allow(dead_code, clippy::all)]
pub mod hugetlbfs_inode;
#[allow(dead_code, clippy::all)]
pub mod kernfs_node;
#[allow(dead_code, clippy::all)]
pub mod nfs_delegation;
#[allow(dead_code, clippy::all)]
pub mod nfs_write;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_index;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_readdir;
#[allow(dead_code, clippy::all)]
pub mod procfs_meminfo;
#[allow(dead_code, clippy::all)]
pub mod procfs_pid;
#[allow(dead_code, clippy::all)]
pub mod sysfs_group;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_swap;
#[allow(dead_code, clippy::all)]
pub mod xfs_alloc;

#[allow(dead_code, clippy::all)]
pub mod btrfs_raid;
#[allow(dead_code, clippy::all)]
pub mod configfs_subsys;
#[allow(dead_code, clippy::all)]
pub mod debugfs_blob;
#[allow(dead_code, clippy::all)]
pub mod devpts_alloc;
#[allow(dead_code, clippy::all)]
pub mod ext2_dir;
#[allow(dead_code, clippy::all)]
pub mod ext4_resize;
#[allow(dead_code, clippy::all)]
pub mod fat32_boot;
#[allow(dead_code, clippy::all)]
pub mod fuse_mount;
#[allow(dead_code, clippy::all)]
pub mod nfs_mount;
#[allow(dead_code, clippy::all)]
pub mod nilfs2_segment;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_merge;
#[allow(dead_code, clippy::all)]
pub mod proc_filesystems;
#[allow(dead_code, clippy::all)]
pub mod proc_sys;
#[allow(dead_code, clippy::all)]
pub mod ramfs_inode;
#[allow(dead_code, clippy::all)]
pub mod securityfs_node;
#[allow(dead_code, clippy::all)]
pub mod squashfs_block;
#[allow(dead_code, clippy::all)]
pub mod sysfs_symlink;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_xattr;
#[allow(dead_code, clippy::all)]
pub mod tracefs_event;
#[allow(dead_code, clippy::all)]
pub mod xfs_log;

#[allow(dead_code, clippy::all)]
pub mod btrfs_inode;
#[allow(dead_code, clippy::all)]
pub mod btrfs_tree;
#[allow(dead_code, clippy::all)]
pub mod devtmpfs;
#[allow(dead_code, clippy::all)]
pub mod dnotify;
#[allow(dead_code, clippy::all)]
pub mod epoll_fs;
#[allow(dead_code, clippy::all)]
pub mod eventfd_fs;
#[allow(dead_code, clippy::all)]
pub mod ext2_inode;
#[allow(dead_code, clippy::all)]
pub mod ext4_dir;
#[allow(dead_code, clippy::all)]
pub mod ext4_xattr;
#[allow(dead_code, clippy::all)]
pub mod fat32_dir;
#[allow(dead_code, clippy::all)]
pub mod fuse_file;
#[allow(dead_code, clippy::all)]
pub mod nfs_dir;
#[allow(dead_code, clippy::all)]
pub mod nfs_read;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_xattr;
#[allow(dead_code, clippy::all)]
pub mod procfs_net;
#[allow(dead_code, clippy::all)]
pub mod signalfd_fs;
#[allow(dead_code, clippy::all)]
pub mod sysfs_bin;
#[allow(dead_code, clippy::all)]
pub mod timerfd_fs;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_acl;
#[allow(dead_code, clippy::all)]
pub mod xfs_inode_ops;

#[allow(dead_code, clippy::all)]
pub mod btrfs_chunk;
#[allow(dead_code, clippy::all)]
pub mod configfs_attr;
#[allow(dead_code, clippy::all)]
pub mod devfs_dynamic;
#[allow(dead_code, clippy::all)]
pub mod ext2_super;
#[allow(dead_code, clippy::all)]
pub mod ext4_extent_tree;
#[allow(dead_code, clippy::all)]
pub mod fat32_fat_table;
#[allow(dead_code, clippy::all)]
pub mod fuse_reply;
#[allow(dead_code, clippy::all)]
pub mod jffs2;
#[allow(dead_code, clippy::all)]
pub mod nfs_cache;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_nlink;
#[allow(dead_code, clippy::all)]
pub mod proc_loadavg;
#[allow(dead_code, clippy::all)]
pub mod proc_uptime;
#[allow(dead_code, clippy::all)]
pub mod ramfs_super;
#[allow(dead_code, clippy::all)]
pub mod squashfs_super;
#[allow(dead_code, clippy::all)]
pub mod sysfs_device;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_quota;
#[allow(dead_code, clippy::all)]
pub mod xfs_btree;

#[allow(dead_code, clippy::all)]
pub mod btrfs_snapshot;
#[allow(dead_code, clippy::all)]
pub mod cgroup_fs;
#[allow(dead_code, clippy::all)]
pub mod epoll;
#[allow(dead_code, clippy::all)]
pub mod eventfd;
#[allow(dead_code, clippy::all)]
pub mod ext4_dir_index;
#[allow(dead_code, clippy::all)]
pub mod f2fs_checkpoint;
#[allow(dead_code, clippy::all)]
pub mod f2fs_segment;
#[allow(dead_code, clippy::all)]
pub mod io_uring_sqe;
#[allow(dead_code, clippy::all)]
pub mod pipe_buf;
#[allow(dead_code, clippy::all)]
pub mod signalfd;
#[allow(dead_code, clippy::all)]
pub mod timerfd;
#[allow(dead_code, clippy::all)]
pub mod xfs_ag;

#[allow(dead_code, clippy::all)]
pub mod btrfs_disk_io;
#[allow(dead_code, clippy::all)]
pub mod cifs_smb2;
#[allow(dead_code, clippy::all)]
pub mod ext4_balloc;
#[allow(dead_code, clippy::all)]
pub mod ext4_ialloc;
#[allow(dead_code, clippy::all)]
pub mod fat_dir;
#[allow(dead_code, clippy::all)]
pub mod fat_file;
#[allow(dead_code, clippy::all)]
pub mod ntfs_attr;
#[allow(dead_code, clippy::all)]
pub mod ntfs_mft;
#[allow(dead_code, clippy::all)]
pub mod udf_fs;
#[allow(dead_code, clippy::all)]
pub mod unionfs;

#[allow(dead_code, clippy::all)]
pub mod affs;
#[allow(dead_code, clippy::all)]
pub mod btrfs_qgroup;
#[allow(dead_code, clippy::all)]
pub mod btrfs_scrub;
#[allow(dead_code, clippy::all)]
pub mod ext4_orphan;
#[allow(dead_code, clippy::all)]
pub mod f2fs_gc;
#[allow(dead_code, clippy::all)]
pub mod f2fs_nat;
#[allow(dead_code, clippy::all)]
pub mod hfsplus;
#[allow(dead_code, clippy::all)]
pub mod minixfs;
#[allow(dead_code, clippy::all)]
pub mod ocfs2;
#[allow(dead_code, clippy::all)]
pub mod reiserfs;
#[allow(dead_code, clippy::all)]
pub mod xfs_attr;
#[allow(dead_code, clippy::all)]
pub mod xfs_dir;
#[allow(dead_code, clippy::all)]
pub mod xfs_quota;

#[allow(dead_code, clippy::all)]
pub mod aio_ctx;
#[allow(dead_code, clippy::all)]
pub mod bio_layer;
#[allow(dead_code, clippy::all)]
pub mod blk_mq;
#[allow(dead_code, clippy::all)]
pub mod block_dev;
#[allow(dead_code, clippy::all)]
pub mod char_dev;
#[allow(dead_code, clippy::all)]
pub mod elevator;
#[allow(dead_code, clippy::all)]
pub mod fanotify;
#[allow(dead_code, clippy::all)]
pub mod lease;
#[allow(dead_code, clippy::all)]
pub mod misc_dev;
#[allow(dead_code, clippy::all)]
pub mod pty_master;
#[allow(dead_code, clippy::all)]
pub mod quota_core;
#[allow(dead_code, clippy::all)]
pub mod splice_pipe;

#[allow(dead_code, clippy::all)]
pub mod bdev_cache;
#[allow(dead_code, clippy::all)]
pub mod cifs_client;
#[allow(dead_code, clippy::all)]
pub mod cramfs_lz4;
#[allow(dead_code, clippy::all)]
pub mod dax_mapping;
#[allow(dead_code, clippy::all)]
pub mod dir_emit;
#[allow(dead_code, clippy::all)]
pub mod file_clone;
#[allow(dead_code, clippy::all)]
pub mod fs_writeback_ctrl;
#[allow(dead_code, clippy::all)]
pub mod fuse_lowlevel;
#[allow(dead_code, clippy::all)]
pub mod hole_punch;
#[allow(dead_code, clippy::all)]
pub mod io_uring_fs;
#[allow(dead_code, clippy::all)]
pub mod journal_commit;
#[allow(dead_code, clippy::all)]
pub mod journal_core;
#[allow(dead_code, clippy::all)]
pub mod journal_recover;
#[allow(dead_code, clippy::all)]
pub mod mpage;
#[allow(dead_code, clippy::all)]
pub mod ninep_fs;
#[allow(dead_code, clippy::all)]
pub mod posix_acl_core;
#[allow(dead_code, clippy::all)]
pub mod romfs_mmap;
#[allow(dead_code, clippy::all)]
pub mod sendfile_op;
#[allow(dead_code, clippy::all)]
pub mod xattr_security;
#[allow(dead_code, clippy::all)]
pub mod xattr_trusted;

#[allow(dead_code, clippy::all)]
pub mod atime_update;
#[allow(dead_code, clippy::all)]
pub mod dentry_negative;
#[allow(dead_code, clippy::all)]
pub mod dirent_iter;
#[allow(dead_code, clippy::all)]
pub mod fd_table;
#[allow(dead_code, clippy::all)]
pub mod file_pos;
#[allow(dead_code, clippy::all)]
pub mod fs_notify;
#[allow(dead_code, clippy::all)]
pub mod inode_cache;
#[allow(dead_code, clippy::all)]
pub mod iov_iter;
#[allow(dead_code, clippy::all)]
pub mod kiocb;
#[allow(dead_code, clippy::all)]
pub mod mount_bind;
#[allow(dead_code, clippy::all)]
pub mod namei;
#[allow(dead_code, clippy::all)]
pub mod open_flags;
#[allow(dead_code, clippy::all)]
pub mod page_cache_ops;
#[allow(dead_code, clippy::all)]
pub mod path_walk;
#[allow(dead_code, clippy::all)]
pub mod quota_ops;
#[allow(dead_code, clippy::all)]
pub mod rename_ops;
#[allow(dead_code, clippy::all)]
pub mod seq_file;
#[allow(dead_code, clippy::all)]
pub mod stat_ops;
#[allow(dead_code, clippy::all)]
pub mod super_ops;
#[allow(dead_code, clippy::all)]
pub mod symlink_ops;
#[allow(dead_code, clippy::all)]
pub mod truncate;
#[allow(dead_code, clippy::all)]
pub mod vfs_cache;
#[allow(dead_code, clippy::all)]
pub mod writeback_worker;

#[allow(dead_code, clippy::all)]
pub mod binfmt_script;
#[allow(dead_code, clippy::all)]
pub mod block_cache;
#[allow(dead_code, clippy::all)]
pub mod chroot_ops;
#[allow(dead_code, clippy::all)]
pub mod cred_check;
#[allow(dead_code, clippy::all)]
pub mod epoll_vfs;
#[allow(dead_code, clippy::all)]
pub mod eventfd_vfs;
#[allow(dead_code, clippy::all)]
pub mod file_lock_flock;
#[allow(dead_code, clippy::all)]
pub mod file_lock_posix;
#[allow(dead_code, clippy::all)]
pub mod file_seal_ops;
#[allow(dead_code, clippy::all)]
pub mod fs_error;
#[allow(dead_code, clippy::all)]
pub mod fs_parser;
#[allow(dead_code, clippy::all)]
pub mod inode_permission;
#[allow(dead_code, clippy::all)]
pub mod mmap_vfs;
#[allow(dead_code, clippy::all)]
pub mod path_resolver;
#[allow(dead_code, clippy::all)]
pub mod pivot_root;
#[allow(dead_code, clippy::all)]
pub mod remount_ops;
#[allow(dead_code, clippy::all)]
pub mod timerfd_vfs;
#[allow(dead_code, clippy::all)]
pub mod umount_ops;
#[allow(dead_code, clippy::all)]
pub mod vfs_ioctl;
#[allow(dead_code, clippy::all)]
pub mod xattr_user;

#[allow(dead_code, clippy::all)]
pub mod adfs_fs;
#[allow(dead_code, clippy::all)]
pub mod afs_callback;
#[allow(dead_code, clippy::all)]
pub mod afs_inode;
#[allow(dead_code, clippy::all)]
pub mod bcachefs_btree;
#[allow(dead_code, clippy::all)]
pub mod bcachefs_inode;
#[allow(dead_code, clippy::all)]
pub mod bpf_fs;
#[allow(dead_code, clippy::all)]
pub mod btrfs_balance;
#[allow(dead_code, clippy::all)]
pub mod btrfs_defrag;
#[allow(dead_code, clippy::all)]
pub mod btrfs_free_space;
#[allow(dead_code, clippy::all)]
pub mod ceph_mds;
#[allow(dead_code, clippy::all)]
pub mod erofs_super;
#[allow(dead_code, clippy::all)]
pub mod exfat_clus;
#[allow(dead_code, clippy::all)]
pub mod exfat_dir;
#[allow(dead_code, clippy::all)]
pub mod ext2_acl;
#[allow(dead_code, clippy::all)]
pub mod ext3_htree;
#[allow(dead_code, clippy::all)]
pub mod ext4_crypto;
#[allow(dead_code, clippy::all)]
pub mod ext4_extent;
#[allow(dead_code, clippy::all)]
pub mod f2fs_extent;
#[allow(dead_code, clippy::all)]
pub mod f2fs_node;
#[allow(dead_code, clippy::all)]
pub mod fat32_cluster;
#[allow(dead_code, clippy::all)]
pub mod fat_lfn;
#[allow(dead_code, clippy::all)]
pub mod fuse_connection;
#[allow(dead_code, clippy::all)]
pub mod gfs2_inode;
#[allow(dead_code, clippy::all)]
pub mod gfs2_log;
#[allow(dead_code, clippy::all)]
pub mod iso9660_dir;
#[allow(dead_code, clippy::all)]
pub mod jfs_super;
#[allow(dead_code, clippy::all)]
pub mod jfs_xtree;
#[allow(dead_code, clippy::all)]
pub mod minix_fs;
#[allow(dead_code, clippy::all)]
pub mod nfs_acl;
#[allow(dead_code, clippy::all)]
pub mod nfs_xdr;
#[allow(dead_code, clippy::all)]
pub mod nsfs_ops;
#[allow(dead_code, clippy::all)]
pub mod ntfs_index;
#[allow(dead_code, clippy::all)]
pub mod ocfs2_cluster;
#[allow(dead_code, clippy::all)]
pub mod ocfs2_inode;
#[allow(dead_code, clippy::all)]
pub mod ocfs2_slot;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_lower;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_upper;
#[allow(dead_code, clippy::all)]
pub mod pidfs;
#[allow(dead_code, clippy::all)]
pub mod proc_cmdline;
#[allow(dead_code, clippy::all)]
pub mod proc_environ;
#[allow(dead_code, clippy::all)]
pub mod proc_maps;
#[allow(dead_code, clippy::all)]
pub mod pstore_zone;
#[allow(dead_code, clippy::all)]
pub mod ramfs_aops;
#[allow(dead_code, clippy::all)]
pub mod ramfs_dir;
#[allow(dead_code, clippy::all)]
pub mod reiserfs_item;
#[allow(dead_code, clippy::all)]
pub mod reiserfs_journal;
#[allow(dead_code, clippy::all)]
pub mod securityfs_ops;
#[allow(dead_code, clippy::all)]
pub mod smbfs_session;
#[allow(dead_code, clippy::all)]
pub mod squashfs_inode;
#[allow(dead_code, clippy::all)]
pub mod sysfs_kobject;
#[allow(dead_code, clippy::all)]
pub mod tmpfs_inode;
#[allow(dead_code, clippy::all)]
pub mod udf_dirent;
#[allow(dead_code, clippy::all)]
pub mod udf_part;
#[allow(dead_code, clippy::all)]
pub mod ufs_fs;
#[allow(dead_code, clippy::all)]
pub mod vfat_dir;
#[allow(dead_code, clippy::all)]
pub mod vfs_mount;
#[allow(dead_code, clippy::all)]
pub mod vfs_namespace;
#[allow(dead_code, clippy::all)]
pub mod xfs_dquot;
#[allow(dead_code, clippy::all)]
pub mod xfs_extent;
#[allow(dead_code, clippy::all)]
pub mod xfs_symlink;
#[allow(dead_code, clippy::all)]
pub mod zonefs_ops;
#[allow(dead_code, clippy::all)]
pub mod zonefs_zone;

#[allow(dead_code, clippy::all)]
pub mod btrfs_chunk_alloc;
#[allow(dead_code, clippy::all)]
pub mod btrfs_extent_tree;
#[allow(dead_code, clippy::all)]
pub mod ext4_dir_hash;
#[allow(dead_code, clippy::all)]
pub mod fuse_inode_ops;
#[allow(dead_code, clippy::all)]
pub mod nfs_read_write;
#[allow(dead_code, clippy::all)]
pub mod nfs_rpc_clnt;

#[allow(dead_code, clippy::all)]
pub mod btrfs_free_space_cache;
#[allow(dead_code, clippy::all)]
pub mod ceph_snap;
#[allow(dead_code, clippy::all)]
pub mod ext4_xattr_inode;
#[allow(dead_code, clippy::all)]
pub mod nfs_idmap;
#[allow(dead_code, clippy::all)]
pub mod nfs_pnfs_layout;
#[allow(dead_code, clippy::all)]
pub mod xfs_log_recover;

#[allow(dead_code, clippy::all)]
pub mod btrfs_compression;
#[allow(dead_code, clippy::all)]
pub mod btrfs_delayed_inode;
#[allow(dead_code, clippy::all)]
pub mod ext4_fsync;
#[allow(dead_code, clippy::all)]
pub mod ext4_quota;
#[allow(dead_code, clippy::all)]
pub mod fat_shortname;
#[allow(dead_code, clippy::all)]
pub mod gfs2_glock;

#[allow(dead_code, clippy::all)]
pub mod btrfs_send_recv;
#[allow(dead_code, clippy::all)]
pub mod erofs_zmap;
#[allow(dead_code, clippy::all)]
pub mod ext4_orphan_cleanup;
#[allow(dead_code, clippy::all)]
pub mod ocfs2_dlm;
#[allow(dead_code, clippy::all)]
pub mod overlayfs_lowerdata;
#[allow(dead_code, clippy::all)]
pub mod squashfs_cache;

#[allow(dead_code, clippy::all)]
pub mod ext4_fast_commit;
#[allow(dead_code, clippy::all)]
pub mod ext4_verity;
#[allow(dead_code, clippy::all)]
pub mod f2fs_flush;
#[allow(dead_code, clippy::all)]
pub mod nfs_layoutreturn;
#[allow(dead_code, clippy::all)]
pub mod xfs_btree_ops;
#[allow(dead_code, clippy::all)]
pub mod xfs_refcount;

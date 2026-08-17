// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::Ramfs;
use crate::cred_check::VfsCred;
use crate::inode::{FileMode, FileType, Inode, InodeOps};
use crate::kernel_api::KernelVfs;
use oncrix_lib::Error;

static LARGE_PAYLOAD: [u8; 4097] = [0xA5; 4097];
static EXEC_PAYLOAD: [u8; 5000] = [0x5A; 5000];

#[test]
fn static_file_reads_large_payload_and_offset() {
    // Given
    let mut ramfs = Ramfs::new();
    let root = Inode::new(
        ramfs.root_inode(),
        FileType::Directory,
        FileMode::DIR_DEFAULT,
    );
    let inode = ramfs
        .create_static_file(&root, "tool", FileMode(0o555), &LARGE_PAYLOAD)
        .unwrap();
    let mut all = [0u8; LARGE_PAYLOAD.len()];
    let mut tail = [0u8; 8];

    // When
    let all_count = ramfs.read(&inode, 0, &mut all);
    let tail_count = ramfs.read(&inode, 4090, &mut tail);

    // Then
    assert_eq!((inode.mode, inode.size), (FileMode(0o555), 4097));
    assert_eq!(all_count, Ok(LARGE_PAYLOAD.len()));
    assert_eq!(all, LARGE_PAYLOAD);
    assert_eq!(tail_count, Ok(7));
    assert_eq!(&tail[..7], &LARGE_PAYLOAD[4090..]);
}

#[test]
fn static_file_rejects_write_and_truncate() {
    // Given
    let mut ramfs = Ramfs::new();
    let root = Inode::new(
        ramfs.root_inode(),
        FileType::Directory,
        FileMode::DIR_DEFAULT,
    );
    let inode = ramfs
        .create_static_file(&root, "tool", FileMode(0o555), &LARGE_PAYLOAD)
        .unwrap();

    // When
    let write_result = ramfs.write(&inode, 0, b"x");
    let truncate_result = ramfs.truncate(&inode, 0);

    // Then
    assert_eq!(write_result, Err(Error::PermissionDenied));
    assert_eq!(truncate_result, Err(Error::PermissionDenied));
}

#[test]
fn static_file_creation_rolls_back_inode_when_directory_entry_fails() {
    // Given
    let mut ramfs = Ramfs::new();
    let root = Inode::new(
        ramfs.root_inode(),
        FileType::Directory,
        FileMode::DIR_DEFAULT,
    );
    ramfs
        .create_static_file(&root, "tool", FileMode(0o555), &LARGE_PAYLOAD)
        .unwrap();
    let used_before_duplicate = ramfs.used_inodes();

    // When
    let result = ramfs.create_static_file(&root, "tool", FileMode(0o555), &LARGE_PAYLOAD);

    // Then
    assert!(matches!(result, Err(Error::AlreadyExists)));
    assert_eq!(ramfs.used_inodes(), used_before_duplicate);
}

#[test]
fn executable_reader_enforces_type_mode_and_bound() {
    // Given
    let mut vfs = KernelVfs::new();
    vfs.create_dir(b"/bin").unwrap();
    let bin = vfs.lookup_path(b"/bin").unwrap();
    vfs.ramfs
        .create_static_file(&bin, "tool", FileMode(0o555), &EXEC_PAYLOAD)
        .unwrap();
    vfs.ramfs
        .create_static_file(&bin, "data", FileMode(0o444), &EXEC_PAYLOAD)
        .unwrap();
    let cred = VfsCred::root();

    // When
    let directory_result = vfs.read_executable_bytes(b"/bin", &cred, EXEC_PAYLOAD.len());
    let mode_result = vfs.read_executable_bytes(b"/bin/data", &cred, EXEC_PAYLOAD.len());
    let bound_result = vfs.read_executable_bytes(b"/bin/tool", &cred, EXEC_PAYLOAD.len() - 1);
    let executable_result = vfs.read_executable_bytes(b"/bin/tool", &cred, EXEC_PAYLOAD.len());

    // Then
    assert_eq!(directory_result, Err(Error::PermissionDenied));
    assert_eq!(mode_result, Err(Error::PermissionDenied));
    assert_eq!(bound_result, Err(Error::OutOfMemory));
    assert_eq!(executable_result, Ok(EXEC_PAYLOAD.to_vec()));
}

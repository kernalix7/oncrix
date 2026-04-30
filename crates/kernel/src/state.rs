// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel state — central container for all boot-initialized subsystems.
//!
//! [`KernelState`] aggregates the major subsystem instances that are
//! created during kernel boot and persist for the lifetime of the
//! system. It is heap-allocated in `kernel_main()` and passed by
//! mutable reference to subsystem initialization routines.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::init::InitSystem;
use oncrix_ipc::channel::ChannelRegistry;
use oncrix_ipc::message::EndpointId;
use oncrix_process::pid::Pid;
use oncrix_process::process::Process;
use oncrix_process::table::ProcessTable;
use oncrix_vfs::inode::{FileMode, FileType, Inode, InodeOps};
use oncrix_vfs::kernel_api::KernelVfs;
use oncrix_vfs::superblock::{FsType, Superblock};

// ── Global kernel state ─────────────────────────────────────────

/// Global pointer to the heap-allocated [`KernelState`].
///
/// Set once during boot by [`set_global`] after `kernel_main()`
/// leaks the `Box<KernelState>`. Subsystems (interrupt handlers,
/// IPC dispatch, etc.) access the state through [`with_global`]
/// and [`with_global_mut`].
static GLOBAL_STATE: AtomicPtr<KernelState> = AtomicPtr::new(core::ptr::null_mut());

/// Publish the kernel state globally.
///
/// Must be called exactly once during boot after the `KernelState`
/// has been leaked into a `&'static mut` reference.
///
/// # Safety
///
/// The caller must ensure:
/// - `state` points to a valid, heap-allocated `KernelState` that
///   will live for the remaining lifetime of the kernel.
/// - This function is called exactly once (before any concurrent
///   access to the global state).
pub unsafe fn set_global(state: *mut KernelState) {
    GLOBAL_STATE.store(state, Ordering::Release);
}

/// Access the global kernel state immutably.
///
/// Returns `None` if [`set_global`] has not been called yet.
///
/// # Safety
///
/// The returned reference borrows the global state. The caller
/// must not hold it across operations that also call
/// [`with_global_mut`], as that would create aliased mutable
/// references. In practice, all accesses occur on a single CPU
/// during early boot and in interrupt-disabled syscall paths.
pub fn with_global<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&KernelState) -> T,
{
    let ptr = GLOBAL_STATE.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `set_global` guarantees the pointer is valid for
        // the kernel's lifetime. Single-CPU + interrupt-disabled
        // syscall context prevents data races.
        Some(f(unsafe { &*ptr }))
    }
}

/// Access the global kernel state mutably.
///
/// Returns `None` if [`set_global`] has not been called yet.
///
/// # Safety
///
/// Same constraints as [`with_global`]. Additionally the caller
/// must ensure no other code holds a reference to the state
/// (guaranteed by the single-CPU, interrupt-disabled syscall
/// entry path).
pub fn with_global_mut<F, T>(f: F) -> Option<T>
where
    F: FnOnce(&mut KernelState) -> T,
{
    let ptr = GLOBAL_STATE.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: see `with_global`. Mutable exclusivity is ensured
        // by the caller (single-CPU interrupt-disabled context).
        Some(f(unsafe { &mut *ptr }))
    }
}

/// Central kernel state container.
///
/// Holds all major subsystem instances that survive beyond boot.
/// Created once in `kernel_main()` via [`Box::new`] to avoid
/// stack overflow from the large `Ramfs` buffers.
pub struct KernelState {
    /// VFS subsystem: ramfs, mount table, and dentry cache.
    ///
    /// Replaces the previously separate `ramfs` and `mount_table`
    /// fields. Use `state.vfs.ramfs` / `state.vfs.mount_table` for
    /// direct access or the higher-level `KernelVfs` methods.
    pub vfs: KernelVfs,
    /// IPC channel registry.
    pub channels: ChannelRegistry,
    /// Global process table.
    pub process_table: ProcessTable,
    /// Service manager (PID 1).
    pub init_system: InitSystem,
}

impl KernelState {
    /// Create a new kernel state with all subsystems in their
    /// initial (empty) configuration.
    pub fn new() -> Self {
        Self {
            vfs: KernelVfs::new(),
            channels: ChannelRegistry::new(),
            process_table: ProcessTable::new(),
            init_system: InitSystem::new(),
        }
    }

    /// Phase 8: Mount the root filesystem and create standard
    /// directories.
    ///
    /// Creates a ramfs root and populates it with `/dev`, `/proc`,
    /// `/tmp`, `/sbin`, and `/etc` (which contains `/etc/motd`).
    pub fn init_rootfs(&mut self) -> oncrix_lib::Result<()> {
        let root_ino = self.vfs.ramfs.root_inode();
        let root_sb = Superblock::new(FsType::Ramfs, root_ino);
        self.vfs.mount_table.mount("/", root_sb)?;

        // Create standard directory hierarchy under root.
        let root = Inode::new(root_ino, FileType::Directory, FileMode::DIR_DEFAULT);
        let dev = self.vfs.ramfs.mkdir(&root, "dev", FileMode::DIR_DEFAULT)?;

        // Populate /dev with synthetic device stubs so `ls /dev` shows them.
        // The actual I/O is handled by the FileBackend::DevFile fast path in
        // sys_open — these inodes are never read or written via ramfs.
        let _ = self.vfs.ramfs.create(&dev, "null", FileMode::FILE_DEFAULT);
        let _ = self.vfs.ramfs.create(&dev, "zero", FileMode::FILE_DEFAULT);

        let _ = self.vfs.ramfs.mkdir(&root, "proc", FileMode::DIR_DEFAULT);
        let _ = self.vfs.ramfs.mkdir(&root, "tmp", FileMode::DIR_DEFAULT);
        let _ = self.vfs.ramfs.mkdir(&root, "sbin", FileMode::DIR_DEFAULT);

        // /etc and /etc/motd
        let etc = self.vfs.ramfs.mkdir(&root, "etc", FileMode::DIR_DEFAULT)?;
        let motd_content = b"Welcome to ONCRIX (Phase 15)\n";
        let motd = self
            .vfs
            .ramfs
            .create(&etc, "motd", FileMode::FILE_DEFAULT)?;
        self.vfs.ramfs.write(&motd, 0, motd_content)?;

        // /proc/version and /proc/uptime — static content, real procfs deferred.
        let proc = self.vfs.lookup_path(b"/proc")?;
        let version_file = self
            .vfs
            .ramfs
            .create(&proc, "version", FileMode::FILE_DEFAULT)?;
        self.vfs
            .ramfs
            .write(&version_file, 0, b"ONCRIX 0.1.0 x86_64\n")?;
        let uptime_file = self
            .vfs
            .ramfs
            .create(&proc, "uptime", FileMode::FILE_DEFAULT)?;
        // Placeholder: uptime is not yet dynamic (real procfs deferred).
        self.vfs.ramfs.write(&uptime_file, 0, b"0.00 0.00\n")?;

        Ok(())
    }

    /// Phase 9: Create IPC channels for core services.
    ///
    /// Sets up channels between the kernel endpoint (0) and each
    /// core service: console (1), devmanager (2), netd (3).
    pub fn init_ipc(&mut self) -> oncrix_lib::Result<()> {
        let kernel_ep = EndpointId::new(0);
        self.channels.create(kernel_ep, EndpointId::new(1))?;
        self.channels.create(kernel_ep, EndpointId::new(2))?;
        self.channels.create(kernel_ep, EndpointId::new(3))?;
        Ok(())
    }

    /// Phase 10: Register kernel (PID 0) and init (PID 1) in the
    /// process table, then run the service manager boot sequence.
    pub fn init_services(&mut self) -> oncrix_lib::Result<()> {
        use oncrix_process::table::ProcessEntry;

        // PID 0: kernel idle process.
        let kernel_proc = Process::new(Pid::KERNEL);
        self.process_table
            .insert(ProcessEntry::new(kernel_proc, Pid::KERNEL))?;

        // PID 1: init (service manager).
        let init_proc = Process::new(Pid::new(1));
        self.process_table
            .insert(ProcessEntry::new(init_proc, Pid::KERNEL))?;

        // Run the service manager boot sequence.
        crate::init::do_init_boot(&mut self.init_system)?;

        Ok(())
    }
}

impl Default for KernelState {
    fn default() -> Self {
        Self::new()
    }
}

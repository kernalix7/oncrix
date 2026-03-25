// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory management subsystem for the ONCRIX operating system.
//!
//! Implements physical page allocation, virtual memory management,
//! page table manipulation, and address space management.
//!
//! # Modules
//!
//! - [`addr`] — `PhysAddr` and `VirtAddr` newtypes
//! - [`frame`] — `Frame`, `Page`, and `FrameAllocator` trait
//! - [`bitmap`] — Bitmap-based physical frame allocator
//! - [`page_table`] — 4-level page table structures and TLB management
//! - [`heap`] — Kernel heap allocator (linked-list free-list)
//! - [`mprotect`] — Memory protection (`mprotect`) and advisory
//!   (`madvise`)
//! - [`stats`] — Memory statistics and `/proc/meminfo` formatting
//! - [`swap`] — Swap subsystem (swap areas, cache, LRU policy)

#![no_std]

pub mod addr;
pub mod address_space;
pub mod balloon;
pub mod bitmap;
pub mod cma;
pub mod compaction;
pub mod cow;
#[allow(dead_code, clippy::all)]
pub mod damon;
pub mod dma;
pub mod dma_sg;
pub mod frame;
pub mod heap;
pub mod hotplug;
pub mod huge_pages;
pub mod kasan;
pub mod kfence;
pub mod kmemleak;
pub mod ksm;
#[allow(dead_code, clippy::all)]
pub mod kswapd;
pub mod memcg;
pub mod memory_failure;
pub mod mempool;
pub mod migrate;
pub mod mprotect;
pub mod numa;
pub mod numa_balance;
pub mod oom;
pub mod page_owner;
pub mod page_pool;
pub mod page_table;
#[allow(dead_code, clippy::all)]
pub mod secretmem;
pub mod shm;
pub mod slab;
pub mod slub;
pub mod stats;
pub mod swap;
pub mod thp;
pub mod usercopy;
pub mod vmalloc;
pub mod vmstat;
pub mod z3fold;
pub mod zswap;

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod memory_tier;
#[allow(dead_code, clippy::all)]
pub mod per_cgroup_reclaim;
#[allow(dead_code, clippy::all)]
pub mod vmemmap_sparse;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod memblock;
#[allow(dead_code, clippy::all)]
pub mod page_writeback;
#[allow(dead_code, clippy::all)]
pub mod percpu;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod mlock;
#[allow(dead_code, clippy::all)]
pub mod mremap;
#[allow(dead_code, clippy::all)]
pub mod vmstat_proc;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod madvise;
#[allow(dead_code, clippy::all)]
pub mod page_reporting;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod memory_encrypt;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_ext;

// --- Batch 10 ---
#[allow(dead_code, clippy::all)]
pub mod cma_alloc;
#[allow(dead_code, clippy::all)]
pub mod damon_ops;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod maple_tree;
#[allow(dead_code, clippy::all)]
pub mod memfd_secret;

// --- Batch 12 ---
#[allow(dead_code, clippy::all)]
pub mod hmm;
#[allow(dead_code, clippy::all)]
pub mod page_alloc;

// --- Batch 13 ---
#[allow(dead_code, clippy::all)]
pub mod page_ext;
#[allow(dead_code, clippy::all)]
pub mod zsmalloc;

// --- Batch 14 ---
#[allow(dead_code, clippy::all)]
pub mod cleancache;
#[allow(dead_code, clippy::all)]
pub mod dax;
#[allow(dead_code, clippy::all)]
pub mod mincore;
#[allow(dead_code, clippy::all)]
pub mod page_idle;

// --- Batch 15 ---
#[allow(dead_code, clippy::all)]
pub mod frontswap;
#[allow(dead_code, clippy::all)]
pub mod khugepaged;
#[allow(dead_code, clippy::all)]
pub mod rmap;
#[allow(dead_code, clippy::all)]
pub mod zram;

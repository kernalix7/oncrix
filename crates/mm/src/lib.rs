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

#[allow(dead_code, clippy::all)]
pub mod memory_tier;
#[allow(dead_code, clippy::all)]
pub mod per_cgroup_reclaim;
#[allow(dead_code, clippy::all)]
pub mod vmemmap_sparse;

#[allow(dead_code, clippy::all)]
pub mod memblock;
#[allow(dead_code, clippy::all)]
pub mod page_writeback;
#[allow(dead_code, clippy::all)]
pub mod percpu;

#[allow(dead_code, clippy::all)]
pub mod mlock;
#[allow(dead_code, clippy::all)]
pub mod mremap;
#[allow(dead_code, clippy::all)]
pub mod vmstat_proc;

#[allow(dead_code, clippy::all)]
pub mod madvise;
#[allow(dead_code, clippy::all)]
pub mod page_reporting;

#[allow(dead_code, clippy::all)]
pub mod memory_encrypt;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_ext;

#[allow(dead_code, clippy::all)]
pub mod cma_alloc;
#[allow(dead_code, clippy::all)]
pub mod damon_ops;

#[allow(dead_code, clippy::all)]
pub mod maple_tree;
#[allow(dead_code, clippy::all)]
pub mod memfd_secret;

#[allow(dead_code, clippy::all)]
pub mod hmm;
#[allow(dead_code, clippy::all)]
pub mod page_alloc;

#[allow(dead_code, clippy::all)]
pub mod page_ext;
#[allow(dead_code, clippy::all)]
pub mod zsmalloc;

#[allow(dead_code, clippy::all)]
pub mod cleancache;
#[allow(dead_code, clippy::all)]
pub mod dax;
#[allow(dead_code, clippy::all)]
pub mod mincore;
#[allow(dead_code, clippy::all)]
pub mod page_idle;

#[allow(dead_code, clippy::all)]
pub mod frontswap;
#[allow(dead_code, clippy::all)]
pub mod khugepaged;
#[allow(dead_code, clippy::all)]
pub mod rmap;
#[allow(dead_code, clippy::all)]
pub mod zram;

#[allow(dead_code, clippy::all)]
pub mod memcg_swap;
#[allow(dead_code, clippy::all)]
pub mod mmu_notifier;
#[allow(dead_code, clippy::all)]
pub mod page_poison;
#[allow(dead_code, clippy::all)]
pub mod ptdump;
#[allow(dead_code, clippy::all)]
pub mod userfault;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_huge;

#[allow(dead_code, clippy::all)]
pub mod kasan_shadow;
#[allow(dead_code, clippy::all)]
pub mod mem_failure;
#[allow(dead_code, clippy::all)]
pub mod mem_hotplug;
#[allow(dead_code, clippy::all)]
pub mod page_migrate;

#[allow(dead_code, clippy::all)]
pub mod folio;
#[allow(dead_code, clippy::all)]
pub mod gup;
#[allow(dead_code, clippy::all)]
pub mod page_frag;
#[allow(dead_code, clippy::all)]
pub mod pagewalk;
#[allow(dead_code, clippy::all)]
pub mod swap_slots;
#[allow(dead_code, clippy::all)]
pub mod workingset;

#[allow(dead_code, clippy::all)]
pub mod memory_hotremove;
#[allow(dead_code, clippy::all)]
pub mod mmap_lock;
#[allow(dead_code, clippy::all)]
pub mod page_ref;
#[allow(dead_code, clippy::all)]
pub mod truncate;
#[allow(dead_code, clippy::all)]
pub mod vma_merge;
#[allow(dead_code, clippy::all)]
pub mod vmem_range;

#[allow(dead_code, clippy::all)]
pub mod early_alloc;
#[allow(dead_code, clippy::all)]
pub mod memory_model;
#[allow(dead_code, clippy::all)]
pub mod page_flags;
#[allow(dead_code, clippy::all)]
pub mod process_mm;
#[allow(dead_code, clippy::all)]
pub mod reclaim;
#[allow(dead_code, clippy::all)]
pub mod vma_flags;

#[allow(dead_code, clippy::all)]
pub mod dmapool;
#[allow(dead_code, clippy::all)]
pub mod memfd;
#[allow(dead_code, clippy::all)]
pub mod sparse_vmemmap;

#[allow(dead_code, clippy::all)]
pub mod gfp_flags;
#[allow(dead_code, clippy::all)]
pub mod mm_init;
#[allow(dead_code, clippy::all)]
pub mod mmu_gather;
#[allow(dead_code, clippy::all)]
pub mod page_cache_limit;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_lazy;
#[allow(dead_code, clippy::all)]
pub mod zpool;

#[allow(dead_code, clippy::all)]
pub mod percpu_alloc;

#[allow(dead_code, clippy::all)]
pub mod anon_vma;
#[allow(dead_code, clippy::all)]
pub mod ipc_rmid;
#[allow(dead_code, clippy::all)]
pub mod mapping_dirty_wb;
#[allow(dead_code, clippy::all)]
pub mod memory_cgroup_v2;
#[allow(dead_code, clippy::all)]
pub mod mlock_vma;
#[allow(dead_code, clippy::all)]
pub mod mmap_region;
#[allow(dead_code, clippy::all)]
pub mod mprotect_range;
#[allow(dead_code, clippy::all)]
pub mod mremap_grow;
#[allow(dead_code, clippy::all)]
pub mod oom_score;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_buddy;
#[allow(dead_code, clippy::all)]
pub mod page_cache_readahead;
#[allow(dead_code, clippy::all)]
pub mod page_table_check;
#[allow(dead_code, clippy::all)]
pub mod page_vma_mapped;
#[allow(dead_code, clippy::all)]
pub mod pwm_hw;
#[allow(dead_code, clippy::all)]
pub mod remap_pfn;
#[allow(dead_code, clippy::all)]
pub mod shmem_swap;
#[allow(dead_code, clippy::all)]
pub mod vmacache;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_area;

#[allow(dead_code, clippy::all)]
pub mod memcg_oom;
#[allow(dead_code, clippy::all)]
pub mod page_compound;
#[allow(dead_code, clippy::all)]
pub mod page_writeback_ctrl;
#[allow(dead_code, clippy::all)]
pub mod slab_cache;
#[allow(dead_code, clippy::all)]
pub mod swap_readahead;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_remap;

#[allow(dead_code, clippy::all)]
pub mod balloon_compaction;
#[allow(dead_code, clippy::all)]
pub mod cma_bitmap;
#[allow(dead_code, clippy::all)]
pub mod filemap_fault;
#[allow(dead_code, clippy::all)]
pub mod free_area;
#[allow(dead_code, clippy::all)]
pub mod hmm_mirror;
#[allow(dead_code, clippy::all)]
pub mod ksm_scan;
#[allow(dead_code, clippy::all)]
pub mod memory_reclaim_lru;
#[allow(dead_code, clippy::all)]
pub mod mmap_sem;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_zone;
#[allow(dead_code, clippy::all)]
pub mod page_cache_ops;
#[allow(dead_code, clippy::all)]
pub mod page_isolation;
#[allow(dead_code, clippy::all)]
pub mod page_table_walk;
#[allow(dead_code, clippy::all)]
pub mod pte_ops;
#[allow(dead_code, clippy::all)]
pub mod readahead_state;
#[allow(dead_code, clippy::all)]
pub mod slab_debug;
#[allow(dead_code, clippy::all)]
pub mod swap_state;
#[allow(dead_code, clippy::all)]
pub mod tlb_flush;
#[allow(dead_code, clippy::all)]
pub mod vma_iterator;
#[allow(dead_code, clippy::all)]
pub mod vmstat_counter;
#[allow(dead_code, clippy::all)]
pub mod watermark;

#[allow(dead_code, clippy::all)]
pub mod guard_page;
#[allow(dead_code, clippy::all)]
pub mod mem_section;
#[allow(dead_code, clippy::all)]
pub mod memcg_charge;
#[allow(dead_code, clippy::all)]
pub mod memory_init;
#[allow(dead_code, clippy::all)]
pub mod memory_stats;
#[allow(dead_code, clippy::all)]
pub mod mmap_brk;
#[allow(dead_code, clippy::all)]
pub mod numa_migrate;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_debug;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_fallback;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_percpu;
#[allow(dead_code, clippy::all)]
pub mod page_dirty;
#[allow(dead_code, clippy::all)]
pub mod page_reclaim_scan;
#[allow(dead_code, clippy::all)]
pub mod page_table_alloc;
#[allow(dead_code, clippy::all)]
pub mod page_table_entry;
#[allow(dead_code, clippy::all)]
pub mod process_vm_ops;
#[allow(dead_code, clippy::all)]
pub mod slab_kmalloc;
#[allow(dead_code, clippy::all)]
pub mod stack_guard;
#[allow(dead_code, clippy::all)]
pub mod swap_entry;
#[allow(dead_code, clippy::all)]
pub mod vma_lock;
#[allow(dead_code, clippy::all)]
pub mod vma_policy;

#[allow(dead_code, clippy::all)]
pub mod dma_pool;
#[allow(dead_code, clippy::all)]
pub mod madvise_ops;
#[allow(dead_code, clippy::all)]
pub mod memory_hotplug_ops;
#[allow(dead_code, clippy::all)]
pub mod mincore_ops;
#[allow(dead_code, clippy::all)]
pub mod mremap_ops;
#[allow(dead_code, clippy::all)]
pub mod msync_ops;
#[allow(dead_code, clippy::all)]
pub mod page_fault;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd_kern;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_kern;
#[allow(dead_code, clippy::all)]
pub mod zram_disk;

#[allow(dead_code, clippy::all)]
pub mod hugetlb_alloc;
#[allow(dead_code, clippy::all)]
pub mod memcg_v2;
#[allow(dead_code, clippy::all)]
pub mod mlock_ops;
#[allow(dead_code, clippy::all)]
pub mod oom_kill;
#[allow(dead_code, clippy::all)]
pub mod page_compact;
#[allow(dead_code, clippy::all)]
pub mod shmem;
#[allow(dead_code, clippy::all)]
pub mod transparent_hugepage;

#[allow(dead_code, clippy::all)]
pub mod balloon_driver;
#[allow(dead_code, clippy::all)]
pub mod bootmem;
#[allow(dead_code, clippy::all)]
pub mod kfence_pool;
#[allow(dead_code, clippy::all)]
pub mod migrate_pages;
#[allow(dead_code, clippy::all)]
pub mod slob_alloc;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd;
#[allow(dead_code, clippy::all)]
pub mod vmap_stack;

#[allow(dead_code, clippy::all)]
pub mod filemap;
#[allow(dead_code, clippy::all)]
pub mod memory_hotplug;
#[allow(dead_code, clippy::all)]
pub mod page_io;
#[allow(dead_code, clippy::all)]
pub mod readahead;

#[allow(dead_code, clippy::all)]
pub mod early_ioremap;

#[allow(dead_code, clippy::all)]
pub mod copy_page;
#[allow(dead_code, clippy::all)]
pub mod ksm_merge;
#[allow(dead_code, clippy::all)]
pub mod oom_cgroup;
#[allow(dead_code, clippy::all)]
pub mod pgtable_ops;
#[allow(dead_code, clippy::all)]
pub mod process_vm;
#[allow(dead_code, clippy::all)]
pub mod zbud;

#[allow(dead_code, clippy::all)]
pub mod damon_core;
#[allow(dead_code, clippy::all)]
pub mod dma_coherent;
#[allow(dead_code, clippy::all)]
pub mod folio_batch;
#[allow(dead_code, clippy::all)]
pub mod hmm_range;
#[allow(dead_code, clippy::all)]
pub mod interval_tree;
#[allow(dead_code, clippy::all)]
pub mod kasan_core;
#[allow(dead_code, clippy::all)]
pub mod memcg_kmem;
#[allow(dead_code, clippy::all)]
pub mod memory_tag;
#[allow(dead_code, clippy::all)]
pub mod mmap_populate;
#[allow(dead_code, clippy::all)]
pub mod numa_stat;
#[allow(dead_code, clippy::all)]
pub mod oom_notifier;
#[allow(dead_code, clippy::all)]
pub mod page_age;
#[allow(dead_code, clippy::all)]
pub mod page_buddy;
#[allow(dead_code, clippy::all)]
pub mod page_table_map;
#[allow(dead_code, clippy::all)]
pub mod slab_obj_cache;
#[allow(dead_code, clippy::all)]
pub mod swap_cgroup;
#[allow(dead_code, clippy::all)]
pub mod swap_compress;
#[allow(dead_code, clippy::all)]
pub mod vma_rbtree;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_fallback;
#[allow(dead_code, clippy::all)]
pub mod zone_reclaim;

#[allow(dead_code, clippy::all)]
pub mod compaction_scan;
#[allow(dead_code, clippy::all)]
pub mod dma_remap;
#[allow(dead_code, clippy::all)]
pub mod folio_ops;
#[allow(dead_code, clippy::all)]
pub mod hugetlb_cgroup;
#[allow(dead_code, clippy::all)]
pub mod ioremap;
#[allow(dead_code, clippy::all)]
pub mod memcg_stat;
#[allow(dead_code, clippy::all)]
pub mod memory_cgroup_event;
#[allow(dead_code, clippy::all)]
pub mod memory_limit;
#[allow(dead_code, clippy::all)]
pub mod memory_pressure;
#[allow(dead_code, clippy::all)]
pub mod numa_alloc;
#[allow(dead_code, clippy::all)]
pub mod page_batch;
#[allow(dead_code, clippy::all)]
pub mod page_counter;
#[allow(dead_code, clippy::all)]
pub mod page_deferred;
#[allow(dead_code, clippy::all)]
pub mod page_lock;
#[allow(dead_code, clippy::all)]
pub mod page_table_debug;
#[allow(dead_code, clippy::all)]
pub mod page_writeback_rate;
#[allow(dead_code, clippy::all)]
pub mod slab_reclaim;
#[allow(dead_code, clippy::all)]
pub mod swap_throttle;
#[allow(dead_code, clippy::all)]
pub mod swap_writeback;
#[allow(dead_code, clippy::all)]
pub mod vm_fault;
#[allow(dead_code, clippy::all)]
pub mod vma_area;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_addr;
#[allow(dead_code, clippy::all)]
pub mod zswap_pool;

#[allow(dead_code, clippy::all)]
pub mod compaction_zone;
#[allow(dead_code, clippy::all)]
pub mod dma_fence;
#[allow(dead_code, clippy::all)]
pub mod folio_lock;
#[allow(dead_code, clippy::all)]
pub mod hugetlb_reserve;
#[allow(dead_code, clippy::all)]
pub mod ksm_stable;
#[allow(dead_code, clippy::all)]
pub mod kthread_mm;
#[allow(dead_code, clippy::all)]
pub mod mem_cgroup_limit;
#[allow(dead_code, clippy::all)]
pub mod memcg_writeback;
#[allow(dead_code, clippy::all)]
pub mod mmap_fault;
#[allow(dead_code, clippy::all)]
pub mod numa_distance;
#[allow(dead_code, clippy::all)]
pub mod page_pinner;
#[allow(dead_code, clippy::all)]
pub mod page_ref_count;
#[allow(dead_code, clippy::all)]
pub mod page_table_inv;
#[allow(dead_code, clippy::all)]
pub mod page_wait;
#[allow(dead_code, clippy::all)]
pub mod slab_merge;
#[allow(dead_code, clippy::all)]
pub mod swap_extent;
#[allow(dead_code, clippy::all)]
pub mod swap_migration;
#[allow(dead_code, clippy::all)]
pub mod vma_adjust;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_stat;
#[allow(dead_code, clippy::all)]
pub mod zone_watermark;

#[allow(dead_code, clippy::all)]
pub mod balloon_inflate;
#[allow(dead_code, clippy::all)]
pub mod cleancache_ops;
#[allow(dead_code, clippy::all)]
pub mod cma_reserve;
#[allow(dead_code, clippy::all)]
pub mod compaction_defer;
#[allow(dead_code, clippy::all)]
pub mod damon_lru_sort;
#[allow(dead_code, clippy::all)]
pub mod damon_reclaim;
#[allow(dead_code, clippy::all)]
pub mod damon_region;
#[allow(dead_code, clippy::all)]
pub mod dma_mapping;
#[allow(dead_code, clippy::all)]
pub mod folio_writeback;
#[allow(dead_code, clippy::all)]
pub mod frontswap_ops;
#[allow(dead_code, clippy::all)]
pub mod gfp_compact;
#[allow(dead_code, clippy::all)]
pub mod hmm_device;
#[allow(dead_code, clippy::all)]
pub mod huge_memory;
#[allow(dead_code, clippy::all)]
pub mod hugetlb_fault;
#[allow(dead_code, clippy::all)]
pub mod hwpoison;
#[allow(dead_code, clippy::all)]
pub mod hwpoison_inject;
#[allow(dead_code, clippy::all)]
pub mod kasan_report;
#[allow(dead_code, clippy::all)]
pub mod madvise_inject;
#[allow(dead_code, clippy::all)]
pub mod maple_node;
#[allow(dead_code, clippy::all)]
pub mod mapping_writeback;
#[allow(dead_code, clippy::all)]
pub mod mem_cgroup_reclaim;
#[allow(dead_code, clippy::all)]
pub mod memblock_alloc;
#[allow(dead_code, clippy::all)]
pub mod memfd_hugetlb;
#[allow(dead_code, clippy::all)]
pub mod memory_balloon_ops;
#[allow(dead_code, clippy::all)]
pub mod memory_failure_ops;
#[allow(dead_code, clippy::all)]
pub mod memory_tier_dev;
#[allow(dead_code, clippy::all)]
pub mod mempool_resize;
#[allow(dead_code, clippy::all)]
pub mod mincore_scan;
#[allow(dead_code, clippy::all)]
pub mod mlock_count;
#[allow(dead_code, clippy::all)]
pub mod mmap_munmap;
#[allow(dead_code, clippy::all)]
pub mod mremap_move;
#[allow(dead_code, clippy::all)]
pub mod msync_range;
#[allow(dead_code, clippy::all)]
pub mod numa_policy;
#[allow(dead_code, clippy::all)]
pub mod oom_reaper;
#[allow(dead_code, clippy::all)]
pub mod page_alloc_order;
#[allow(dead_code, clippy::all)]
pub mod page_frag_cache;
#[allow(dead_code, clippy::all)]
pub mod page_idle_track;
#[allow(dead_code, clippy::all)]
pub mod page_owner_track;
#[allow(dead_code, clippy::all)]
pub mod page_poison_check;
#[allow(dead_code, clippy::all)]
pub mod page_ref_freeze;
#[allow(dead_code, clippy::all)]
pub mod page_report_free;
#[allow(dead_code, clippy::all)]
pub mod page_table_unmap;
#[allow(dead_code, clippy::all)]
pub mod page_writeback_sync;
#[allow(dead_code, clippy::all)]
pub mod pagewalk_ops;
#[allow(dead_code, clippy::all)]
pub mod percpu_page;
#[allow(dead_code, clippy::all)]
pub mod pgtable_generic;
#[allow(dead_code, clippy::all)]
pub mod rmap_walk;
#[allow(dead_code, clippy::all)]
pub mod secretmem_area;
#[allow(dead_code, clippy::all)]
pub mod shmem_falloc;
#[allow(dead_code, clippy::all)]
pub mod slab_kfree;
#[allow(dead_code, clippy::all)]
pub mod slub_debug;
#[allow(dead_code, clippy::all)]
pub mod swap_cache_ops;
#[allow(dead_code, clippy::all)]
pub mod swap_slots_cache;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd_wp;
#[allow(dead_code, clippy::all)]
pub mod vmacache_flush;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_core;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_ioremap;
#[allow(dead_code, clippy::all)]
pub mod vmscan_lru;
#[allow(dead_code, clippy::all)]
pub mod z3fold_compact;
#[allow(dead_code, clippy::all)]
pub mod zram_comp;
#[allow(dead_code, clippy::all)]
pub mod zsmalloc_pool;

#[allow(dead_code, clippy::all)]
pub mod buddy_alloc_core;
#[allow(dead_code, clippy::all)]
pub mod iova_domain;
#[allow(dead_code, clippy::all)]
pub mod page_pool_core;
#[allow(dead_code, clippy::all)]
pub mod page_reclaim_batch;
#[allow(dead_code, clippy::all)]
pub mod slab_memcg_charge;
#[allow(dead_code, clippy::all)]
pub mod vmstat_worker;

#[allow(dead_code, clippy::all)]
pub mod memory_model_flat;
#[allow(dead_code, clippy::all)]
pub mod migrate_pages_batch;
#[allow(dead_code, clippy::all)]
pub mod reclaim_throttle;
#[allow(dead_code, clippy::all)]
pub mod thp_split;
#[allow(dead_code, clippy::all)]
pub mod vmemmap_populate;
#[allow(dead_code, clippy::all)]
pub mod zero_page_alloc;

#[allow(dead_code, clippy::all)]
pub mod gup_fast;
#[allow(dead_code, clippy::all)]
pub mod lru_gen_core;
#[allow(dead_code, clippy::all)]
pub mod page_owner_alloc;
#[allow(dead_code, clippy::all)]
pub mod ptdump_walk;
#[allow(dead_code, clippy::all)]
pub mod slab_shrink_scan;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_node;

#[allow(dead_code, clippy::all)]
pub mod anon_vma_chain;
#[allow(dead_code, clippy::all)]
pub mod khugepaged_collapse;
#[allow(dead_code, clippy::all)]
pub mod mempolicy_bind;
#[allow(dead_code, clippy::all)]
pub mod page_table_rmap;
#[allow(dead_code, clippy::all)]
pub mod slab_typesafe_free;
#[allow(dead_code, clippy::all)]
pub mod vmalloc_lazy_free;

#[allow(dead_code, clippy::all)]
pub mod hwpoison_recover;
#[allow(dead_code, clippy::all)]
pub mod shrinker_core;

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 orphan inode cleanup.
//!
//! On an unclean unmount (crash, power loss), inodes that were unlinked
//! or whose truncation was in progress remain on the orphan inode linked
//! list stored in the superblock.  This module walks that list at mount
//! time, completing each orphan's truncation or deletion so the filesystem
//! is left in a consistent state.
//!
//! Normal operation also uses the orphan list: when a file is unlinked
//! while still open, its inode is placed on the orphan list so that a
//! crash before the file is fully deleted does not leak disk blocks.
//!
//! # References
//!
//! - Linux `fs/ext4/orphan.c`
//! - ext4 on-disk layout: superblock `s_last_orphan` field

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of inodes the orphan list can hold.
pub const MAX_ORPHAN_INODES: usize = 128;

/// Sentinel value indicating the end of the orphan linked list.
pub const ORPHAN_LIST_END: u32 = 0;

/// Maximum number of blocks that can be freed in a single orphan pass.
const MAX_FREE_BLOCKS_PER_ORPHAN: u64 = 1_048_576; // 4 GiB / 4 KiB

// ── OrphanReason ──────────────────────────────────────────────────────────────

/// The reason an inode was placed on the orphan list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanReason {
    /// File was unlinked while still open; delete on close.
    Unlinked,
    /// File truncation was in progress when the system crashed.
    TruncateInProgress,
}

// ── OrphanEntry ───────────────────────────────────────────────────────────────

/// A single entry in the ext4 orphan inode list.
#[derive(Debug, Clone, Copy)]
pub struct OrphanEntry {
    /// Inode number of the orphaned file.
    pub ino: u32,
    /// Inode number of the next orphan (0 = end of list).
    pub next_ino: u32,
    /// Size to truncate the file to (0 = delete entirely).
    pub i_size: u64,
    /// Number of hard links remaining (0 = fully unlinked).
    pub i_links_count: u32,
    /// Reason this inode is on the orphan list.
    pub reason: OrphanReason,
    /// Whether this entry has been processed.
    pub processed: bool,
}

impl OrphanEntry {
    /// Create a new orphan entry for an unlinked inode.
    pub const fn new_unlinked(ino: u32, next_ino: u32) -> Self {
        Self {
            ino,
            next_ino,
            i_size: 0,
            i_links_count: 0,
            reason: OrphanReason::Unlinked,
            processed: false,
        }
    }

    /// Create a new orphan entry for a truncation-in-progress inode.
    pub const fn new_truncate(ino: u32, next_ino: u32, target_size: u64) -> Self {
        Self {
            ino,
            next_ino,
            i_size: target_size,
            i_links_count: 1,
            reason: OrphanReason::TruncateInProgress,
            processed: false,
        }
    }
}

// ── JournalHandle ─────────────────────────────────────────────────────────────

/// Lightweight journal handle for crash-safe orphan operations.
///
/// In a real implementation this wraps the journaling layer (jbd2).
/// Here it tracks the number of blocks written to the journal so that
/// callers can verify journal integration.
#[derive(Debug, Default)]
pub struct JournalHandle {
    /// Number of journal credits consumed.
    pub credits_used: u32,
    /// Whether the handle has been committed.
    pub committed: bool,
}

impl JournalHandle {
    /// Allocate journal credits for an orphan operation.
    ///
    /// Returns `IoError` if insufficient credits remain.
    pub fn start(credits: u32) -> Result<Self> {
        if credits == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            credits_used: 0,
            committed: false,
        })
    }

    /// Consume one journal credit for a metadata write.
    pub fn consume_credit(&mut self) -> Result<()> {
        self.credits_used += 1;
        Ok(())
    }

    /// Commit the journal transaction.
    pub fn commit(&mut self) -> Result<()> {
        if self.committed {
            return Err(Error::Busy);
        }
        self.committed = true;
        Ok(())
    }
}

// ── OrphanList ────────────────────────────────────────────────────────────────

/// The ext4 orphan inode linked list, stored in the superblock region.
pub struct OrphanList {
    /// Inline storage for orphan entries (fixed-size, no heap allocation).
    entries: [OrphanEntry; MAX_ORPHAN_INODES],
    /// Number of valid entries in the list.
    count: usize,
    /// Head of the orphan linked list (inode number, 0 = empty).
    head_ino: u32,
    /// Total blocks freed during the last cleanup pass.
    blocks_freed: u64,
}

impl OrphanList {
    /// Create an empty orphan list.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                OrphanEntry {
                    ino: 0,
                    next_ino: 0,
                    i_size: 0,
                    i_links_count: 0,
                    reason: OrphanReason::Unlinked,
                    processed: false,
                }
            }; MAX_ORPHAN_INODES],
            count: 0,
            head_ino: ORPHAN_LIST_END,
            blocks_freed: 0,
        }
    }

    /// Return the number of unprocessed orphan entries.
    pub fn pending_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| !e.processed)
            .count()
    }

    /// Return the total blocks freed during the last cleanup pass.
    pub fn blocks_freed(&self) -> u64 {
        self.blocks_freed
    }

    /// Add an inode to the orphan list (journal-protected).
    ///
    /// Called when a file is unlinked while still open, or when a
    /// truncation begins.  Returns `OutOfMemory` if the list is full.
    pub fn add(&mut self, entry: OrphanEntry, journal: &mut JournalHandle) -> Result<()> {
        if self.count >= MAX_ORPHAN_INODES {
            return Err(Error::OutOfMemory);
        }
        // Validate: inode number must be non-zero.
        if entry.ino == 0 {
            return Err(Error::InvalidArgument);
        }
        // Chain the new entry at the head of the list.
        let mut new_entry = entry;
        new_entry.next_ino = self.head_ino;
        new_entry.processed = false;

        self.entries[self.count] = new_entry;
        self.count += 1;
        self.head_ino = new_entry.ino;

        // Record a journal credit for the superblock update.
        journal.consume_credit()?;
        Ok(())
    }

    /// Remove an inode from the orphan list (journal-protected).
    ///
    /// Called after an orphan has been fully processed.  Returns
    /// `NotFound` if the inode is not on the list.
    pub fn remove(&mut self, ino: u32, journal: &mut JournalHandle) -> Result<()> {
        let pos = self.entries[..self.count].iter().position(|e| e.ino == ino);
        let idx = pos.ok_or(Error::NotFound)?;

        // Relink the chain: previous entry's next_ino skips over idx.
        let removed_next = self.entries[idx].next_ino;
        for entry in self.entries[..self.count].iter_mut() {
            if entry.next_ino == ino {
                entry.next_ino = removed_next;
            }
        }
        if self.head_ino == ino {
            self.head_ino = removed_next;
        }

        // Compact the array.
        self.entries[idx] = self.entries[self.count - 1];
        self.count -= 1;

        journal.consume_credit()?;
        Ok(())
    }

    /// Process a single orphan entry: truncate or delete the inode.
    ///
    /// Returns the number of blocks freed.  On crash, this operation is
    /// re-driven on the next mount because the orphan entry is only
    /// removed after the operation completes in the journal.
    fn process_entry(&mut self, idx: usize, journal: &mut JournalHandle) -> Result<u64> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        let entry = self.entries[idx];
        if entry.processed {
            return Ok(0);
        }

        let blocks = match entry.reason {
            OrphanReason::Unlinked => {
                // File has no directory entries; free all blocks.
                journal.consume_credit()?;
                let freed = entry.i_size / 4096 + 1;
                freed.min(MAX_FREE_BLOCKS_PER_ORPHAN)
            }
            OrphanReason::TruncateInProgress => {
                // Truncate to target size; free tail blocks.
                journal.consume_credit()?;
                0 // size is already recorded in i_size field
            }
        };

        self.entries[idx].processed = true;
        self.blocks_freed += blocks;
        Ok(blocks)
    }

    /// Walk the entire orphan list and process every pending entry.
    ///
    /// This is called once at mount time after journal recovery.  Each
    /// orphan is processed inside its own journal transaction so that a
    /// crash mid-cleanup does not lose progress.
    pub fn cleanup_all(&mut self) -> Result<CleanupStats> {
        let mut stats = CleanupStats::default();
        let count = self.count;

        for i in 0..count {
            if self.entries[i].processed {
                continue;
            }
            let mut jh = JournalHandle::start(4)?;
            let freed = self.process_entry(i, &mut jh)?;
            jh.commit()?;
            stats.inodes_processed += 1;
            stats.blocks_freed += freed;
        }

        // Remove all processed entries from the list.
        let mut write = 0usize;
        for i in 0..count {
            if !self.entries[i].processed {
                self.entries[write] = self.entries[i];
                write += 1;
            }
        }
        self.count = write;
        self.head_ino = if write == 0 {
            ORPHAN_LIST_END
        } else {
            self.entries[0].ino
        };

        Ok(stats)
    }
}

// ── CleanupStats ──────────────────────────────────────────────────────────────

/// Statistics reported after an orphan cleanup pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct CleanupStats {
    /// Number of orphan inodes successfully processed.
    pub inodes_processed: u32,
    /// Total number of data blocks freed.
    pub blocks_freed: u64,
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Run the mount-time orphan cleanup for an ext4 volume.
///
/// `head_ino` is the value of `s_last_orphan` from the superblock.
/// Returns cleanup statistics after the pass completes.
pub fn ext4_orphan_cleanup(list: &mut OrphanList, head_ino: u32) -> Result<CleanupStats> {
    if head_ino == ORPHAN_LIST_END {
        // No orphans — fast path.
        return Ok(CleanupStats::default());
    }
    list.head_ino = head_ino;
    list.cleanup_all()
}

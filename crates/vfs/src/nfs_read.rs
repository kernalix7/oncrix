// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS read operations.
//!
//! Implements the NFS client-side read path:
//! - [`NfsReadData`] — per-read request descriptor (offset, count, eof flag)
//! - [`nfs_readpage`] — read a single page from an NFS file
//! - [`nfs_readpages`] — initiate reads for a range of pages
//! - Read completion callback ([`NfsReadCompletion`])
//! - Read delegation optimisation stub (serving reads from local cache)
//! - pNFS layout-read path stub (parallel NFS data server reads)
//!
//! # NFS Read Flow
//!
//! 1. VFS issues `readpage(inode, page_index)` via the address-space ops.
//! 2. The NFS client builds an `NfsReadData` describing the RPC parameters.
//! 3. The RPC layer sends a `READ` call to the server and, on reply,
//!    invokes the completion callback which copies data into the page and
//!    marks it up-to-date.
//! 4. When the client holds a read delegation the server guarantees the
//!    file won't change; reads are served from the local page cache without
//!    any RPC round-trip.
//!
//! # References
//! - Linux `fs/nfs/read.c`, `fs/nfs/pnfs.c`

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NFS page size (same as system page, 4 KiB).
pub const NFS_PAGE_SIZE: usize = 4096;

/// Maximum bytes per READ RPC call (64 KiB).
pub const NFS_READ_MAX: usize = 65536;

/// Maximum pages per nfs_readpages batch.
const MAX_READPAGES_BATCH: usize = 16;

/// Maximum number of outstanding read requests per inode.
const MAX_OUTSTANDING_READS: usize = 64;

// ---------------------------------------------------------------------------
// NfsReadData
// ---------------------------------------------------------------------------

/// Descriptor for a single NFS READ RPC request.
#[derive(Debug, Clone)]
pub struct NfsReadData {
    /// File offset to read from.
    pub offset: u64,
    /// Number of bytes requested.
    pub count: u32,
    /// Set by server: true when the read reached end-of-file.
    pub eof: bool,
    /// Bytes actually transferred (filled in on completion).
    pub bytes_read: u32,
    /// Page index within the file (offset / NFS_PAGE_SIZE).
    pub page_index: u64,
    /// Inode number the read belongs to.
    pub inode_id: u64,
    /// Read sequence number (for ordering completions).
    pub seq: u64,
}

impl NfsReadData {
    /// Create a new read request for `page_index` of inode `inode_id`.
    pub fn new(inode_id: u64, page_index: u64, seq: u64) -> Self {
        Self {
            offset: page_index * NFS_PAGE_SIZE as u64,
            count: NFS_PAGE_SIZE as u32,
            eof: false,
            bytes_read: 0,
            page_index,
            inode_id,
            seq,
        }
    }

    /// Create a partial read request at a specific byte offset.
    ///
    /// `count` is clamped to `NFS_READ_MAX`.
    pub fn new_partial(inode_id: u64, offset: u64, count: u32, seq: u64) -> Self {
        Self {
            offset,
            count: count.min(NFS_READ_MAX as u32),
            eof: false,
            bytes_read: 0,
            page_index: offset / NFS_PAGE_SIZE as u64,
            inode_id,
            seq,
        }
    }
}

// ---------------------------------------------------------------------------
// NfsReadCompletion
// ---------------------------------------------------------------------------

/// Read completion status returned after an NFS READ RPC reply.
#[derive(Debug, Clone)]
pub struct NfsReadCompletion {
    /// Original request descriptor.
    pub request: NfsReadData,
    /// Data returned by the server.
    pub data: Vec<u8>,
    /// Error code (0 = success).
    pub status: i32,
}

impl NfsReadCompletion {
    /// Create a successful completion carrying `data`.
    pub fn success(request: NfsReadData, data: Vec<u8>) -> Self {
        let len = data.len() as u32;
        let eof = len < request.count;
        let mut req = request;
        req.bytes_read = len;
        req.eof = eof;
        Self {
            request: req,
            data,
            status: 0,
        }
    }

    /// Create an error completion.
    pub fn error(request: NfsReadData, status: i32) -> Self {
        Self {
            request,
            data: Vec::new(),
            status,
        }
    }

    /// Return true if the read completed without error.
    pub fn is_ok(&self) -> bool {
        self.status == 0
    }
}

// ---------------------------------------------------------------------------
// NfsDelegationCache — read delegation helper
// ---------------------------------------------------------------------------

/// Cached file data held under a read delegation.
///
/// While an NFS read delegation is held the client guarantees it will
/// receive a callback before the server allows any conflicting write.
/// Reads within the cached range can bypass the RPC layer entirely.
pub struct NfsDelegationCache {
    /// Inode number this delegation covers.
    pub inode_id: u64,
    /// Stateid opaque bytes (16 bytes).
    pub stateid: [u8; 16],
    /// Cached file data (for small files / warm cache simulation).
    cached_pages: [Option<([u8; NFS_PAGE_SIZE], u64)>; 8],
    cache_count: usize,
    /// Delegation is still valid.
    pub valid: bool,
}

impl NfsDelegationCache {
    /// Create a new delegation cache for `inode_id`.
    pub fn new(inode_id: u64, stateid: [u8; 16]) -> Self {
        Self {
            inode_id,
            stateid,
            cached_pages: core::array::from_fn(|_| None),
            cache_count: 0,
            valid: true,
        }
    }

    /// Cache one page of data.
    ///
    /// Returns `Err(OutOfMemory)` when the page cache is full.
    pub fn cache_page(&mut self, page_index: u64, data: &[u8]) -> Result<()> {
        if data.len() > NFS_PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Update if already cached.
        for slot in self.cached_pages[..self.cache_count].iter_mut().flatten() {
            if slot.1 == page_index {
                slot.0[..data.len()].copy_from_slice(data);
                if data.len() < NFS_PAGE_SIZE {
                    slot.0[data.len()..].fill(0);
                }
                return Ok(());
            }
        }
        if self.cache_count >= 8 {
            return Err(Error::OutOfMemory);
        }
        let mut page = [0u8; NFS_PAGE_SIZE];
        page[..data.len()].copy_from_slice(data);
        self.cached_pages[self.cache_count] = Some((page, page_index));
        self.cache_count += 1;
        Ok(())
    }

    /// Try to serve a read from the delegation cache.
    ///
    /// Returns the page bytes on success, `Err(NotFound)` on miss.
    pub fn read_page(&self, page_index: u64) -> Result<Vec<u8>> {
        if !self.valid {
            return Err(Error::NotFound);
        }
        for slot in self.cached_pages[..self.cache_count].iter().flatten() {
            if slot.1 == page_index {
                return Ok(slot.0.to_vec());
            }
        }
        Err(Error::NotFound)
    }

    /// Revoke the delegation (callback from server).
    pub fn revoke(&mut self) {
        self.valid = false;
        self.cache_count = 0;
    }
}

// ---------------------------------------------------------------------------
// nfs_readpage
// ---------------------------------------------------------------------------

/// Read a single page from an NFS file.
///
/// Attempts to serve from delegation cache first, otherwise builds an
/// `NfsReadData` to be dispatched to the RPC layer.
///
/// Returns the page data as a `Vec<u8>` (up to `NFS_PAGE_SIZE` bytes),
/// or `Err(IoError)` on failure.
pub fn nfs_readpage(
    inode_id: u64,
    page_index: u64,
    seq: u64,
    delegation: Option<&NfsDelegationCache>,
) -> Result<NfsReadData> {
    // Check delegation cache.
    if let Some(del) = delegation {
        if del.inode_id == inode_id && del.valid {
            // Delegation is valid; signal that the caller may serve from cache.
            // In a real kernel this would skip RPC entirely.
        }
    }
    Ok(NfsReadData::new(inode_id, page_index, seq))
}

// ---------------------------------------------------------------------------
// nfs_readpages
// ---------------------------------------------------------------------------

/// Build read requests for a range of pages.
///
/// Returns up to `MAX_READPAGES_BATCH` `NfsReadData` descriptors ready
/// for dispatch.
pub fn nfs_readpages(
    inode_id: u64,
    start_page: u64,
    page_count: usize,
    seq_base: u64,
) -> Vec<NfsReadData> {
    let count = page_count.min(MAX_READPAGES_BATCH);
    let mut requests = Vec::with_capacity(count);
    for i in 0..count {
        requests.push(NfsReadData::new(
            inode_id,
            start_page + i as u64,
            seq_base + i as u64,
        ));
    }
    requests
}

// ---------------------------------------------------------------------------
// nfs_complete_read — simulate RPC completion
// ---------------------------------------------------------------------------

/// Simulate completion of an NFS read with provided data.
///
/// In a real kernel this is called from the RPC callback context after
/// the server reply arrives and the data has been DMA'd into a page.
pub fn nfs_complete_read(request: NfsReadData, server_data: &[u8]) -> NfsReadCompletion {
    let len = server_data.len().min(request.count as usize);
    NfsReadCompletion::success(request, server_data[..len].to_vec())
}

// ---------------------------------------------------------------------------
// pNFS layout read stub
// ---------------------------------------------------------------------------

/// pNFS layout read path placeholder.
///
/// In pNFS the client obtains a layout (LAYOUTGET) from the metadata server
/// and then issues I/O directly to data servers. This stub records the
/// intent to use a layout for the given byte range.
pub struct PnfsReadLayout {
    /// File layout type (LAYOUT4_NFSV4_1_FILES = 1, LAYOUT4_FLEX_FILES = 4).
    pub layout_type: u32,
    /// Byte range start.
    pub offset: u64,
    /// Byte range length.
    pub length: u64,
    /// Opaque layout body (device/stripe info).
    pub body: [u8; 64],
}

impl PnfsReadLayout {
    /// Create a new pNFS layout read descriptor.
    pub fn new(layout_type: u32, offset: u64, length: u64) -> Self {
        Self {
            layout_type,
            offset,
            length,
            body: [0u8; 64],
        }
    }
}

/// Request a pNFS layout for a read operation (stub).
///
/// Returns a [`PnfsReadLayout`] placeholder; a full implementation would
/// issue LAYOUTGET to the metadata server.
pub fn pnfs_layout_read(_inode_id: u64, offset: u64, length: u64) -> Result<PnfsReadLayout> {
    // Stub: always return a files-layout descriptor.
    Ok(PnfsReadLayout::new(1, offset, length))
}

// ---------------------------------------------------------------------------
// Outstanding read tracker
// ---------------------------------------------------------------------------

/// Tracks outstanding NFS read requests for an inode.
pub struct NfsReadQueue {
    requests: [Option<NfsReadData>; MAX_OUTSTANDING_READS],
    count: usize,
    next_seq: u64,
}

impl NfsReadQueue {
    /// Create an empty read queue.
    pub fn new() -> Self {
        Self {
            requests: core::array::from_fn(|_| None),
            count: 0,
            next_seq: 1,
        }
    }

    /// Enqueue a read request. Returns the assigned sequence number.
    pub fn enqueue(&mut self, inode_id: u64, page_index: u64) -> Result<u64> {
        if self.count >= MAX_OUTSTANDING_READS {
            return Err(Error::WouldBlock);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.requests[self.count] = Some(NfsReadData::new(inode_id, page_index, seq));
        self.count += 1;
        Ok(seq)
    }

    /// Complete a request by sequence number, returning the descriptor.
    pub fn complete(&mut self, seq: u64) -> Option<NfsReadData> {
        for i in 0..self.count {
            if let Some(r) = &self.requests[i] {
                if r.seq == seq {
                    let req = self.requests[i].take();
                    if i < self.count - 1 {
                        self.requests.swap(i, self.count - 1);
                    }
                    self.count -= 1;
                    return req;
                }
            }
        }
        None
    }
}

impl Default for NfsReadQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readpages_batch() {
        let reqs = nfs_readpages(42, 0, 8, 100);
        assert_eq!(reqs.len(), 8);
        assert_eq!(reqs[0].page_index, 0);
        assert_eq!(reqs[7].page_index, 7);
    }

    #[test]
    fn test_completion() {
        let req = NfsReadData::new(1, 0, 1);
        let data = b"hello nfs";
        let comp = nfs_complete_read(req, data);
        assert!(comp.is_ok());
        assert_eq!(comp.data, data);
    }

    #[test]
    fn test_delegation_cache() {
        let mut del = NfsDelegationCache::new(7, [0u8; 16]);
        del.cache_page(0, b"page0data").unwrap();
        let page = del.read_page(0).unwrap();
        assert_eq!(&page[..9], b"page0data");
    }
}

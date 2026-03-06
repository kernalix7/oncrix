// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC operation audit logging subsystem.
//!
//! Records all System V and POSIX IPC operations in a fixed-size ring-buffer
//! audit log.  Each event captures:
//! - Which IPC operation was performed.
//! - The process (PID) and user (UID) that initiated it.
//! - The IPC object identifier and key.
//! - A kernel-tick timestamp.
//! - Whether the operation succeeded or failed.
//!
//! The log is intended to be read via `/proc/ipc/audit` in a real kernel.
//! The [`format_audit_entry`] function formats a single entry for that output.
//!
//! # Design
//!
//! - 256-entry ring buffer (oldest entry overwritten when full).
//! - Optional filter by event type, PID, or UID.
//! - Enabled/disabled at runtime via [`IpcAuditSubsystem::set_enabled`].
//!
//! # Reference
//!
//! SysV IPC spec: `.TheOpenGroup/susv5-html/functions/shmget.html` and
//! related pages.  POSIX message queues:
//! `.TheOpenGroup/susv5-html/functions/mq_open.html`.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the ring-buffer (number of audit entries retained).
pub const AUDIT_LOG_SIZE: usize = 256;

/// Maximum length of a formatted audit entry string.
pub const AUDIT_FMT_MAX: usize = 256;

// ---------------------------------------------------------------------------
// IpcAuditEvent
// ---------------------------------------------------------------------------

/// IPC operation that triggered an audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcAuditEvent {
    /// `shmget(IPC_CREAT)` — shared memory segment created.
    ShmCreate,
    /// `shmat` — process attached to a shared memory segment.
    ShmAttach,
    /// `shmdt` — process detached from a shared memory segment.
    ShmDetach,
    /// `shmctl(IPC_RMID)` — shared memory segment removed.
    ShmRemove,
    /// `semget(IPC_CREAT)` — semaphore set created.
    SemCreate,
    /// `semop` / `semtimedop` — semaphore operation performed.
    SemOp,
    /// `semctl(IPC_RMID)` — semaphore set removed.
    SemRemove,
    /// `msgget(IPC_CREAT)` — message queue created.
    MsgCreate,
    /// `msgsnd` — message sent to queue.
    MsgSend,
    /// `msgrcv` — message received from queue.
    MsgRecv,
    /// `msgctl(IPC_RMID)` — message queue removed.
    MsgRemove,
    /// `mq_open` — POSIX message queue opened.
    MqOpen,
    /// `mq_send` / `mq_timedsend` — POSIX message sent.
    MqSend,
    /// `mq_receive` / `mq_timedreceive` — POSIX message received.
    MqRecv,
    /// `mq_close` — POSIX message queue closed.
    MqClose,
}

impl IpcAuditEvent {
    /// Return the event bitmask bit for this event (for `IpcAuditFilter`).
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32 % 32)
    }

    /// Return a short ASCII label for formatted output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ShmCreate => "shm_create",
            Self::ShmAttach => "shm_attach",
            Self::ShmDetach => "shm_detach",
            Self::ShmRemove => "shm_remove",
            Self::SemCreate => "sem_create",
            Self::SemOp => "sem_op",
            Self::SemRemove => "sem_remove",
            Self::MsgCreate => "msg_create",
            Self::MsgSend => "msg_send",
            Self::MsgRecv => "msg_recv",
            Self::MsgRemove => "msg_remove",
            Self::MqOpen => "mq_open",
            Self::MqSend => "mq_send",
            Self::MqRecv => "mq_recv",
            Self::MqClose => "mq_close",
        }
    }
}

// ---------------------------------------------------------------------------
// IpcAuditEntry
// ---------------------------------------------------------------------------

/// A single IPC audit log record.
#[derive(Debug, Clone, Copy)]
pub struct IpcAuditEntry {
    /// The IPC event type.
    pub event: IpcAuditEvent,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// UID of the user that triggered the event.
    pub uid: u32,
    /// IPC object identifier (shmid, semid, msqid, or MQ descriptor).
    pub ipc_id: u32,
    /// IPC key associated with the object (`0` if not applicable).
    pub key: u32,
    /// Kernel tick at the time of the event.
    pub timestamp_tick: u64,
    /// Whether the operation succeeded (`true`) or failed (`false`).
    pub success: bool,
}

impl IpcAuditEntry {
    /// Construct a successful audit entry.
    pub const fn success(
        event: IpcAuditEvent,
        pid: u32,
        uid: u32,
        ipc_id: u32,
        key: u32,
        tick: u64,
    ) -> Self {
        Self {
            event,
            pid,
            uid,
            ipc_id,
            key,
            timestamp_tick: tick,
            success: true,
        }
    }

    /// Construct a failed audit entry.
    pub const fn failure(
        event: IpcAuditEvent,
        pid: u32,
        uid: u32,
        ipc_id: u32,
        key: u32,
        tick: u64,
    ) -> Self {
        Self {
            event,
            pid,
            uid,
            ipc_id,
            key,
            timestamp_tick: tick,
            success: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcAuditFilter
// ---------------------------------------------------------------------------

/// Optional filter for querying the audit log.
///
/// An entry passes the filter when:
/// 1. Its event type bit is set in `event_mask` (or `event_mask == 0` for all).
/// 2. If `pid_filter` is `Some(p)`, the entry's `pid` equals `p`.
/// 3. If `uid_filter` is `Some(u)`, the entry's `uid` equals `u`.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcAuditFilter {
    /// Bitmask of allowed event types (0 = all events pass).
    pub event_mask: u32,
    /// Optional PID to match.
    pub pid_filter: Option<u32>,
    /// Optional UID to match.
    pub uid_filter: Option<u32>,
}

impl IpcAuditFilter {
    /// Create a filter that passes all entries.
    pub const fn new() -> Self {
        Self {
            event_mask: 0,
            pid_filter: None,
            uid_filter: None,
        }
    }

    /// Return `true` if `entry` passes this filter.
    pub fn matches(&self, entry: &IpcAuditEntry) -> bool {
        if self.event_mask != 0 && (self.event_mask & entry.event.bit() == 0) {
            return false;
        }
        if let Some(pid) = self.pid_filter {
            if entry.pid != pid {
                return false;
            }
        }
        if let Some(uid) = self.uid_filter {
            if entry.uid != uid {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// IpcAuditStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the IPC audit subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpcAuditStats {
    /// Total number of events recorded.
    pub total_events: u64,
    /// Number of events that were dropped due to active filters.
    pub filtered_events: u64,
    /// Number of times the ring buffer overflowed (oldest entry overwritten).
    pub buffer_overflows: u64,
}

impl IpcAuditStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_events: 0,
            filtered_events: 0,
            buffer_overflows: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IpcAuditLog — 256-entry ring buffer
// ---------------------------------------------------------------------------

/// Fixed-size ring-buffer audit log.
#[derive(Debug)]
pub struct IpcAuditLog {
    /// Ring-buffer entries (`None` for empty slots).
    entries: [Option<IpcAuditEntry>; AUDIT_LOG_SIZE],
    /// Index where the next entry will be written.
    head: usize,
    /// Number of entries currently stored (saturates at `AUDIT_LOG_SIZE`).
    count: usize,
    /// Whether audit logging is enabled.
    pub enabled: bool,
}

impl IpcAuditLog {
    /// Create an empty, enabled audit log.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; AUDIT_LOG_SIZE],
            head: 0,
            count: 0,
            enabled: true,
        }
    }

    /// Append an entry to the ring buffer.
    ///
    /// If the buffer is full the oldest entry is silently overwritten.
    /// Returns `true` if the buffer wrapped (overflow).
    pub fn push(&mut self, entry: IpcAuditEntry) -> bool {
        let overflow = self.count >= AUDIT_LOG_SIZE;
        self.entries[self.head] = Some(entry);
        self.head = (self.head + 1) % AUDIT_LOG_SIZE;
        if overflow {
            // count stays saturated at AUDIT_LOG_SIZE; oldest was overwritten.
            true
        } else {
            self.count += 1;
            false
        }
    }

    /// Return the number of stored entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries = [const { None }; AUDIT_LOG_SIZE];
        self.head = 0;
        self.count = 0;
    }

    /// Iterate over all stored entries in insertion order, yielding those
    /// that pass `filter` and collecting up to `max` into `out`.
    ///
    /// Returns the number of entries written to `out`.
    pub fn get_recent(
        &self,
        filter: &IpcAuditFilter,
        out: &mut [IpcAuditEntry],
        max: usize,
    ) -> usize {
        let cap = max.min(out.len());
        if cap == 0 || self.count == 0 {
            return 0;
        }

        // Walk the ring from the oldest entry towards the newest.
        // oldest_idx = (head - count + AUDIT_LOG_SIZE) % AUDIT_LOG_SIZE
        let start_idx = (self.head + AUDIT_LOG_SIZE - self.count) % AUDIT_LOG_SIZE;
        let mut written = 0usize;

        for i in 0..self.count {
            if written >= cap {
                break;
            }
            let idx = (start_idx + i) % AUDIT_LOG_SIZE;
            if let Some(entry) = &self.entries[idx] {
                if filter.matches(entry) {
                    out[written] = *entry;
                    written += 1;
                }
            }
        }
        written
    }
}

impl Default for IpcAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// format_audit_entry
// ---------------------------------------------------------------------------

/// Write a byte slice into `out` at `*offset`, advancing the offset.
///
/// Does not write beyond `AUDIT_FMT_MAX`.
fn fmt_write_bytes(out: &mut [u8; AUDIT_FMT_MAX], offset: &mut usize, src: &[u8]) {
    let avail = AUDIT_FMT_MAX.saturating_sub(*offset);
    let n = src.len().min(avail);
    out[*offset..*offset + n].copy_from_slice(&src[..n]);
    *offset += n;
}

/// Write a `u64` as decimal ASCII into `out` at `*offset`.
fn fmt_write_u64(out: &mut [u8; AUDIT_FMT_MAX], offset: &mut usize, val: u64) {
    let mut digits = [0u8; 20];
    let mut v = val;
    let mut len = 0usize;
    if v == 0 {
        digits[0] = b'0';
        len = 1;
    } else {
        while v > 0 {
            digits[len] = b'0' + (v % 10) as u8;
            v /= 10;
            len += 1;
        }
        digits[..len].reverse();
    }
    let avail = AUDIT_FMT_MAX.saturating_sub(*offset);
    let n = len.min(avail);
    out[*offset..*offset + n].copy_from_slice(&digits[..n]);
    *offset += n;
}

/// Format a single audit entry into `buf` for `/proc`-style output.
///
/// The format is:
/// ```text
/// tick=<tick> event=<label> pid=<pid> uid=<uid> id=<ipc_id> key=<key> result=<ok|fail>
/// ```
///
/// Returns the number of bytes written, or `0` if `buf` is too small.
pub fn format_audit_entry(entry: &IpcAuditEntry, buf: &mut [u8; AUDIT_FMT_MAX]) -> usize {
    let result_str = if entry.success {
        b"ok" as &[u8]
    } else {
        b"fail"
    };

    let mut tmp = [0u8; AUDIT_FMT_MAX];
    let mut pos = 0usize;

    fmt_write_bytes(&mut tmp, &mut pos, b"tick=");
    fmt_write_u64(&mut tmp, &mut pos, entry.timestamp_tick);
    fmt_write_bytes(&mut tmp, &mut pos, b" event=");
    fmt_write_bytes(&mut tmp, &mut pos, entry.event.label().as_bytes());
    fmt_write_bytes(&mut tmp, &mut pos, b" pid=");
    fmt_write_u64(&mut tmp, &mut pos, entry.pid as u64);
    fmt_write_bytes(&mut tmp, &mut pos, b" uid=");
    fmt_write_u64(&mut tmp, &mut pos, entry.uid as u64);
    fmt_write_bytes(&mut tmp, &mut pos, b" id=");
    fmt_write_u64(&mut tmp, &mut pos, entry.ipc_id as u64);
    fmt_write_bytes(&mut tmp, &mut pos, b" key=");
    fmt_write_u64(&mut tmp, &mut pos, entry.key as u64);
    fmt_write_bytes(&mut tmp, &mut pos, b" result=");
    fmt_write_bytes(&mut tmp, &mut pos, result_str);
    fmt_write_bytes(&mut tmp, &mut pos, b"\n");

    buf[..pos].copy_from_slice(&tmp[..pos]);
    pos
}

// ---------------------------------------------------------------------------
// IpcAuditSubsystem
// ---------------------------------------------------------------------------

/// Top-level IPC audit subsystem handle.
///
/// Wraps [`IpcAuditLog`] and [`IpcAuditStats`] together with filter support.
#[derive(Debug)]
pub struct IpcAuditSubsystem {
    /// The ring-buffer audit log.
    pub log: IpcAuditLog,
    /// Accumulated statistics.
    pub stats: IpcAuditStats,
    /// Active filter (applied at record time).
    pub filter: IpcAuditFilter,
}

impl IpcAuditSubsystem {
    /// Create a new subsystem with audit enabled and no filter.
    pub const fn new() -> Self {
        Self {
            log: IpcAuditLog::new(),
            stats: IpcAuditStats::new(),
            filter: IpcAuditFilter::new(),
        }
    }

    /// Enable or disable audit logging.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.log.enabled = enabled;
    }

    /// Return `true` if audit logging is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.log.enabled
    }

    /// Record an IPC event.
    ///
    /// If the subsystem is disabled the call is a no-op.
    /// If the active filter blocks the event, `stats.filtered_events` is
    /// incremented and the entry is not stored.
    pub fn record_event(&mut self, entry: IpcAuditEntry) {
        if !self.log.enabled {
            return;
        }
        if !self.filter.matches(&entry) {
            self.stats.filtered_events += 1;
            return;
        }
        let overflowed = self.log.push(entry);
        self.stats.total_events += 1;
        if overflowed {
            self.stats.buffer_overflows += 1;
        }
    }

    /// Retrieve the most-recent entries matching `filter` into `out`.
    ///
    /// The `filter` parameter is independent of the recording filter.
    /// Returns the number of entries written to `out`.
    pub fn get_recent(
        &self,
        filter: &IpcAuditFilter,
        out: &mut [IpcAuditEntry],
        max: usize,
    ) -> usize {
        self.log.get_recent(filter, out, max)
    }

    /// Clear all log entries and reset statistics.
    pub fn clear(&mut self) {
        self.log.clear();
        self.stats = IpcAuditStats::new();
    }

    /// Convenience: record a successful IPC event.
    pub fn record_success(
        &mut self,
        event: IpcAuditEvent,
        pid: u32,
        uid: u32,
        ipc_id: u32,
        key: u32,
        tick: u64,
    ) {
        self.record_event(IpcAuditEntry::success(event, pid, uid, ipc_id, key, tick));
    }

    /// Convenience: record a failed IPC event.
    pub fn record_failure(
        &mut self,
        event: IpcAuditEvent,
        pid: u32,
        uid: u32,
        ipc_id: u32,
        key: u32,
        tick: u64,
    ) {
        self.record_event(IpcAuditEntry::failure(event, pid, uid, ipc_id, key, tick));
    }
}

impl Default for IpcAuditSubsystem {
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

    fn make_subsystem() -> IpcAuditSubsystem {
        IpcAuditSubsystem::new()
    }

    fn shm_success(pid: u32, uid: u32, id: u32, tick: u64) -> IpcAuditEntry {
        IpcAuditEntry::success(IpcAuditEvent::ShmCreate, pid, uid, id, 0, tick)
    }

    #[test]
    fn test_record_and_count() {
        let mut s = make_subsystem();
        s.record_success(IpcAuditEvent::ShmCreate, 100, 1000, 1, 0, 1);
        s.record_success(IpcAuditEvent::ShmAttach, 100, 1000, 1, 0, 2);
        assert_eq!(s.log.count(), 2);
        assert_eq!(s.stats.total_events, 2);
    }

    #[test]
    fn test_disabled_no_record() {
        let mut s = make_subsystem();
        s.set_enabled(false);
        s.record_success(IpcAuditEvent::MsgSend, 200, 0, 5, 0, 10);
        assert_eq!(s.log.count(), 0);
        assert_eq!(s.stats.total_events, 0);
    }

    #[test]
    fn test_filter_by_pid() {
        let mut s = make_subsystem();
        s.record_event(shm_success(100, 0, 1, 1));
        s.record_event(shm_success(200, 0, 2, 2));
        s.record_event(shm_success(100, 0, 3, 3));

        let filter = IpcAuditFilter {
            pid_filter: Some(100),
            ..IpcAuditFilter::new()
        };
        let mut out = [shm_success(0, 0, 0, 0); 16];
        let n = s.get_recent(&filter, &mut out, 16);
        assert_eq!(n, 2);
        for i in 0..n {
            assert_eq!(out[i].pid, 100);
        }
    }

    #[test]
    fn test_filter_by_uid() {
        let mut s = make_subsystem();
        s.record_event(shm_success(1, 1000, 1, 1));
        s.record_event(shm_success(2, 2000, 2, 2));

        let filter = IpcAuditFilter {
            uid_filter: Some(2000),
            ..IpcAuditFilter::new()
        };
        let mut out = [shm_success(0, 0, 0, 0); 8];
        let n = s.get_recent(&filter, &mut out, 8);
        assert_eq!(n, 1);
        assert_eq!(out[0].uid, 2000);
    }

    #[test]
    fn test_filter_by_event_mask() {
        let mut s = make_subsystem();
        s.record_success(IpcAuditEvent::ShmCreate, 1, 0, 1, 0, 1);
        s.record_success(IpcAuditEvent::MsgSend, 1, 0, 2, 0, 2);
        s.record_success(IpcAuditEvent::MqOpen, 1, 0, 3, 0, 3);

        let filter = IpcAuditFilter {
            event_mask: IpcAuditEvent::MsgSend.bit(),
            ..IpcAuditFilter::new()
        };
        let mut out = [shm_success(0, 0, 0, 0); 8];
        let n = s.get_recent(&filter, &mut out, 8);
        assert_eq!(n, 1);
        assert_eq!(out[0].event, IpcAuditEvent::MsgSend);
    }

    #[test]
    fn test_ring_buffer_overflow() {
        let mut s = make_subsystem();
        for i in 0..AUDIT_LOG_SIZE + 10 {
            s.record_success(IpcAuditEvent::SemOp, i as u32, 0, 0, 0, i as u64);
        }
        // Count stays capped at AUDIT_LOG_SIZE.
        assert_eq!(s.log.count(), AUDIT_LOG_SIZE);
        assert_eq!(s.stats.buffer_overflows, 10);
        assert_eq!(s.stats.total_events, (AUDIT_LOG_SIZE + 10) as u64);
    }

    #[test]
    fn test_clear() {
        let mut s = make_subsystem();
        s.record_success(IpcAuditEvent::ShmCreate, 1, 0, 1, 0, 1);
        s.clear();
        assert_eq!(s.log.count(), 0);
        assert_eq!(s.stats.total_events, 0);
    }

    #[test]
    fn test_record_filter_blocks() {
        let mut s = make_subsystem();
        // Set a recording filter that only accepts ShmCreate.
        s.filter = IpcAuditFilter {
            event_mask: IpcAuditEvent::ShmCreate.bit(),
            ..IpcAuditFilter::new()
        };
        s.record_success(IpcAuditEvent::ShmCreate, 1, 0, 1, 0, 1);
        s.record_success(IpcAuditEvent::MsgSend, 1, 0, 2, 0, 2); // blocked
        assert_eq!(s.log.count(), 1);
        assert_eq!(s.stats.filtered_events, 1);
    }

    #[test]
    fn test_format_audit_entry_success() {
        let entry = IpcAuditEntry::success(IpcAuditEvent::ShmCreate, 42, 1000, 7, 12345, 9999);
        let mut buf = [0u8; AUDIT_FMT_MAX];
        let n = format_audit_entry(&entry, &mut buf);
        assert!(n > 0);
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains("shm_create"));
        assert!(s.contains("pid=42"));
        assert!(s.contains("uid=1000"));
        assert!(s.contains("result=ok"));
    }

    #[test]
    fn test_format_audit_entry_failure() {
        let entry = IpcAuditEntry::failure(IpcAuditEvent::MsgRecv, 99, 500, 3, 0, 1);
        let mut buf = [0u8; AUDIT_FMT_MAX];
        let n = format_audit_entry(&entry, &mut buf);
        let s = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains("result=fail"));
        assert!(s.contains("msg_recv"));
    }

    #[test]
    fn test_event_labels_unique() {
        let events = [
            IpcAuditEvent::ShmCreate,
            IpcAuditEvent::ShmAttach,
            IpcAuditEvent::ShmDetach,
            IpcAuditEvent::ShmRemove,
            IpcAuditEvent::SemCreate,
            IpcAuditEvent::SemOp,
            IpcAuditEvent::SemRemove,
            IpcAuditEvent::MsgCreate,
            IpcAuditEvent::MsgSend,
            IpcAuditEvent::MsgRecv,
            IpcAuditEvent::MsgRemove,
            IpcAuditEvent::MqOpen,
            IpcAuditEvent::MqSend,
            IpcAuditEvent::MqRecv,
            IpcAuditEvent::MqClose,
        ];
        // All labels should be distinct.
        for i in 0..events.len() {
            for j in (i + 1)..events.len() {
                assert_ne!(
                    events[i].label(),
                    events[j].label(),
                    "duplicate label for {:?} and {:?}",
                    events[i],
                    events[j]
                );
            }
        }
    }

    #[test]
    fn test_get_recent_max_limit() {
        let mut s = make_subsystem();
        for i in 0..20u32 {
            s.record_success(IpcAuditEvent::SemOp, i, 0, i, 0, i as u64);
        }
        let filter = IpcAuditFilter::new();
        let mut out = [shm_success(0, 0, 0, 0); 32];
        let n = s.get_recent(&filter, &mut out, 5);
        assert_eq!(n, 5);
    }

    #[test]
    fn test_success_failure_constructors() {
        let ok = IpcAuditEntry::success(IpcAuditEvent::MqOpen, 1, 2, 3, 4, 5);
        assert!(ok.success);
        let fail = IpcAuditEntry::failure(IpcAuditEvent::MqOpen, 1, 2, 3, 4, 5);
        assert!(!fail.success);
    }
}

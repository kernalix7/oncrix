// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! nftables packet filtering framework.
//!
//! Implements the nftables framework as the successor to iptables. Provides a
//! table/chain/rule hierarchy with expression-based rule matching, verdict
//! types, and set/map lookup. All structures are fixed-size for `#![no_std]`
//! operation.
//!
//! # Object Model
//!
//! ```text
//! Table (family: inet/ip/ip6/arp/netdev)
//!  └── Chain (base hook or regular)
//!       └── Rule (list of expressions + verdict)
//! ```
//!
//! A **base chain** is attached to a Netfilter hook point (prerouting,
//! input, forward, output, postrouting) and receives packets from the
//! network stack. A **regular chain** is only reachable via `jump`/`goto`
//! from another rule.
//!
//! # Expression Evaluation
//!
//! Rules contain up to [`MAX_EXPRS_PER_RULE`] expressions evaluated left-to-
//! right. Any expression that returns `Reject` immediately terminates with
//! a `Drop` verdict. If all expressions pass, the rule's terminal verdict
//! is applied.
//!
//! Reference: Linux `net/netfilter/nf_tables_core.c`, `nft_compat.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of tables.
const MAX_TABLES: usize = 8;

/// Maximum number of chains per table.
const MAX_CHAINS_PER_TABLE: usize = 16;

/// Maximum number of rules per chain.
const MAX_RULES_PER_CHAIN: usize = 64;

/// Maximum number of expressions per rule.
const MAX_EXPRS_PER_RULE: usize = 8;

/// Maximum number of sets globally.
const MAX_SETS: usize = 32;

/// Maximum elements per set.
const MAX_SET_ELEMENTS: usize = 256;

/// Maximum name length for tables/chains/sets.
const MAX_NAME_LEN: usize = 64;

/// Maximum log prefix length.
const MAX_LOG_PREFIX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Address family
// ---------------------------------------------------------------------------

/// nftables address family determines the layer at which a table operates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfFamily {
    /// Both IPv4 and IPv6.
    Inet = 0,
    /// IPv4 only.
    Ip = 1,
    /// IPv6 only.
    Ip6 = 2,
    /// ARP.
    Arp = 3,
    /// Bridge.
    Bridge = 4,
    /// Netdev (ingress/egress hook on specific interface).
    Netdev = 5,
}

// ---------------------------------------------------------------------------
// Hook and priority
// ---------------------------------------------------------------------------

/// Netfilter hook points where a base chain can be attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NfHook {
    /// Before routing decision (can alter destination).
    Prerouting = 0,
    /// Packets addressed to local system.
    Input = 1,
    /// Packets being forwarded.
    Forward = 2,
    /// Locally generated packets leaving the system.
    Output = 3,
    /// After routing (NAT, masquerade).
    Postrouting = 4,
    /// Ingress from a specific network device (Netdev family).
    Ingress = 5,
    /// Egress to a specific network device (Netdev family).
    Egress = 6,
}

// ---------------------------------------------------------------------------
// Verdict types
// ---------------------------------------------------------------------------

/// Verdict emitted by a rule or expression evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accept (pass to next layer).
    Accept,
    /// Drop the packet silently.
    Drop,
    /// Queue to user space via NFQUEUE.
    Queue(u16),
    /// Continue evaluation in the calling chain.
    Continue,
    /// Return to the calling chain (from a jump).
    Return,
    /// Jump to a named chain, then return.
    Jump(usize),
    /// Unconditionally transfer control to another chain (no return).
    Goto(usize),
}

impl Default for Verdict {
    fn default() -> Self {
        Self::Accept
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// Payload header offset for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PayloadSpec {
    /// Byte offset within the header (network layer starts at 0).
    pub offset: u8,
    /// Number of bytes to extract (1, 2, or 4).
    pub len: u8,
}

/// Comparison operator used in `cmp` expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CmpOp {
    /// Equal.
    Eq = 0,
    /// Not equal.
    Neq = 1,
    /// Less than.
    Lt = 2,
    /// Less than or equal.
    Lte = 3,
    /// Greater than.
    Gt = 4,
    /// Greater than or equal.
    Gte = 5,
}

/// NAT type for `nat` expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NatType {
    /// Source NAT (masquerade/SNAT).
    Snat = 0,
    /// Destination NAT (DNAT/port forwarding).
    Dnat = 1,
}

/// A single nftables expression within a rule.
///
/// Expressions form the building blocks of rules. They are evaluated
/// sequentially against the current packet.
#[derive(Debug, Clone, Copy)]
pub enum Expr {
    /// Load a field from the packet payload and push to register 0.
    Payload(PayloadSpec),
    /// Compare register 0 against a 32-bit immediate value.
    Cmp {
        /// Comparison operator.
        op: CmpOp,
        /// Immediate value to compare against.
        value: u32,
    },
    /// Increment the rule's packet and byte counters.
    Counter,
    /// Emit a log message with the given prefix (index into log prefix table).
    Log {
        /// Log prefix stored inline (null-terminated).
        prefix: [u8; MAX_LOG_PREFIX_LEN],
        /// Valid prefix byte length.
        prefix_len: usize,
    },
    /// Apply NAT to source or destination address/port.
    Nat {
        /// NAT direction.
        nat_type: NatType,
        /// Replacement IPv4 address.
        addr: u32,
        /// Replacement port (0 = unchanged).
        port: u16,
    },
    /// Perform a set lookup; accept if element is present.
    SetLookup {
        /// Set index in the global set table.
        set_idx: usize,
        /// Key to look up (extracted from register 0).
        key: u32,
    },
    /// Immediately apply a terminal verdict.
    Immediate(Verdict),
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// A single nftables rule: a sequence of expressions terminated by a verdict.
#[derive(Debug)]
pub struct Rule {
    /// Unique rule handle within its chain.
    pub handle: u32,
    /// Expressions to evaluate in order.
    pub exprs: [Option<Expr>; MAX_EXPRS_PER_RULE],
    /// Number of active expressions.
    pub expr_count: usize,
    /// Terminal verdict applied when all expressions pass.
    pub verdict: Verdict,
    /// Cumulative packet counter.
    pub packets: u64,
    /// Cumulative byte counter.
    pub bytes: u64,
    /// Whether this rule is currently active.
    pub enabled: bool,
    /// Optional comment.
    pub comment: [u8; MAX_NAME_LEN],
    /// Valid bytes in `comment`.
    pub comment_len: usize,
}

impl Rule {
    /// Create a new rule with the given handle and terminal verdict.
    pub fn new(handle: u32, verdict: Verdict) -> Self {
        Self {
            handle,
            exprs: [const { None }; MAX_EXPRS_PER_RULE],
            expr_count: 0,
            verdict,
            packets: 0,
            bytes: 0,
            enabled: true,
            comment: [0u8; MAX_NAME_LEN],
            comment_len: 0,
        }
    }

    /// Append an expression to this rule.
    pub fn add_expr(&mut self, expr: Expr) -> Result<()> {
        if self.expr_count >= MAX_EXPRS_PER_RULE {
            return Err(Error::OutOfMemory);
        }
        self.exprs[self.expr_count] = Some(expr);
        self.expr_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// Chain type: base (hooked into Netfilter) or regular (jump target only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    /// Regular chain; reachable only via jump/goto.
    Regular,
    /// Base chain; registered with a Netfilter hook.
    Base {
        /// Hook this chain is attached to.
        hook: NfHook,
        /// Priority: lower numbers evaluated first (range -400..+400).
        priority: i32,
    },
}

impl Default for ChainType {
    fn default() -> Self {
        Self::Regular
    }
}

/// Chain policy: default action when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainPolicy {
    /// Default: accept unmatched packets.
    #[default]
    Accept,
    /// Drop unmatched packets.
    Drop,
}

/// A named chain within a table.
#[derive(Debug)]
pub struct Chain {
    /// Name of the chain.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name bytes.
    pub name_len: usize,
    /// Chain classification.
    pub chain_type: ChainType,
    /// Default policy when all rules are exhausted without a terminal verdict.
    pub policy: ChainPolicy,
    /// Ordered list of rules.
    pub rules: [Option<Rule>; MAX_RULES_PER_CHAIN],
    /// Number of active rules.
    pub rule_count: usize,
    /// Next rule handle to assign.
    pub next_handle: u32,
}

impl Chain {
    /// Create a regular chain with the given name.
    pub fn new_regular(name: &[u8]) -> Self {
        let mut c = Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            chain_type: ChainType::Regular,
            policy: ChainPolicy::Accept,
            rules: [const { None }; MAX_RULES_PER_CHAIN],
            rule_count: 0,
            next_handle: 1,
        };
        let len = name.len().min(MAX_NAME_LEN);
        c.name[..len].copy_from_slice(&name[..len]);
        c.name_len = len;
        c
    }

    /// Create a base chain attached to a hook.
    pub fn new_base(name: &[u8], hook: NfHook, priority: i32, policy: ChainPolicy) -> Self {
        let mut c = Self::new_regular(name);
        c.chain_type = ChainType::Base { hook, priority };
        c.policy = policy;
        c
    }

    /// Add a rule at the end of the chain.
    pub fn add_rule(&mut self, mut rule: Rule) -> Result<u32> {
        if self.rule_count >= MAX_RULES_PER_CHAIN {
            return Err(Error::OutOfMemory);
        }
        let handle = self.next_handle;
        self.next_handle += 1;
        rule.handle = handle;
        self.rules[self.rule_count] = Some(rule);
        self.rule_count += 1;
        Ok(handle)
    }

    /// Delete a rule by handle.
    pub fn delete_rule(&mut self, handle: u32) -> Result<()> {
        let pos = self.rules[..self.rule_count]
            .iter()
            .position(|r| r.as_ref().map(|r| r.handle == handle).unwrap_or(false))
            .ok_or(Error::NotFound)?;
        for i in pos..self.rule_count - 1 {
            self.rules.swap(i, i + 1);
        }
        self.rules[self.rule_count - 1] = None;
        self.rule_count -= 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

/// A top-level nftables table.
///
/// Tables are organizational units scoped to an address family. A table
/// contains chains that hold rules.
#[derive(Debug)]
pub struct Table {
    /// Table name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name bytes.
    pub name_len: usize,
    /// Address family this table operates on.
    pub family: NfFamily,
    /// Chains within this table.
    pub chains: [Option<Chain>; MAX_CHAINS_PER_TABLE],
    /// Number of active chains.
    pub chain_count: usize,
    /// Whether the table is active (dormant tables skip processing).
    pub active: bool,
}

impl Table {
    /// Create a new empty table.
    pub fn new(name: &[u8], family: NfFamily) -> Self {
        let mut t = Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            family,
            chains: [const { None }; MAX_CHAINS_PER_TABLE],
            chain_count: 0,
            active: true,
        };
        let len = name.len().min(MAX_NAME_LEN);
        t.name[..len].copy_from_slice(&name[..len]);
        t.name_len = len;
        t
    }

    /// Add a chain to the table.
    ///
    /// Returns the index within the table's chain array.
    pub fn add_chain(&mut self, chain: Chain) -> Result<usize> {
        if self.chain_count >= MAX_CHAINS_PER_TABLE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.chain_count;
        self.chains[idx] = Some(chain);
        self.chain_count += 1;
        Ok(idx)
    }

    /// Find a chain by name and return its index.
    pub fn find_chain(&self, name: &[u8]) -> Option<usize> {
        self.chains[..self.chain_count].iter().position(|c| {
            c.as_ref()
                .map(|c| c.name[..c.name_len] == name[..name.len().min(c.name_len)])
                .unwrap_or(false)
        })
    }

    /// Delete a chain by name.
    pub fn delete_chain(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.find_chain(name).ok_or(Error::NotFound)?;
        for i in pos..self.chain_count - 1 {
            self.chains.swap(i, i + 1);
        }
        self.chains[self.chain_count - 1] = None;
        self.chain_count -= 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Set / Map
// ---------------------------------------------------------------------------

/// A set element key (32-bit value for simplicity).
type SetKey = u32;

/// A named set for O(1) membership lookups within nftables rules.
#[derive(Debug)]
pub struct NfSet {
    /// Set name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name bytes.
    pub name_len: usize,
    /// Set elements.
    pub elements: [SetKey; MAX_SET_ELEMENTS],
    /// Number of active elements.
    pub element_count: usize,
}

impl NfSet {
    /// Create a new empty set.
    pub fn new(name: &[u8]) -> Self {
        let mut s = Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            elements: [0u32; MAX_SET_ELEMENTS],
            element_count: 0,
        };
        let len = name.len().min(MAX_NAME_LEN);
        s.name[..len].copy_from_slice(&name[..len]);
        s.name_len = len;
        s
    }

    /// Add an element to the set.
    pub fn add(&mut self, key: SetKey) -> Result<()> {
        if self.element_count >= MAX_SET_ELEMENTS {
            return Err(Error::OutOfMemory);
        }
        if self.contains(key) {
            return Err(Error::AlreadyExists);
        }
        self.elements[self.element_count] = key;
        self.element_count += 1;
        Ok(())
    }

    /// Remove an element from the set.
    pub fn remove(&mut self, key: SetKey) -> Result<()> {
        let pos = self.elements[..self.element_count]
            .iter()
            .position(|&k| k == key)
            .ok_or(Error::NotFound)?;
        for i in pos..self.element_count - 1 {
            self.elements[i] = self.elements[i + 1];
        }
        self.element_count -= 1;
        Ok(())
    }

    /// Returns `true` if the key is a member of this set.
    pub fn contains(&self, key: SetKey) -> bool {
        self.elements[..self.element_count].contains(&key)
    }
}

// ---------------------------------------------------------------------------
// Packet context (passed during evaluation)
// ---------------------------------------------------------------------------

/// Minimal packet descriptor passed through the rule evaluation engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct PktCtx {
    /// Source IPv4 address.
    pub src_ip: u32,
    /// Destination IPv4 address.
    pub dst_ip: u32,
    /// IP protocol number.
    pub protocol: u8,
    /// Source port (TCP/UDP).
    pub src_port: u16,
    /// Destination port (TCP/UDP).
    pub dst_port: u16,
    /// Packet length in bytes.
    pub pkt_len: u32,
    /// Ingress interface index.
    pub iif: u32,
    /// Egress interface index.
    pub oif: u32,
}

impl PktCtx {
    /// Read a field from the packet payload at `offset` with `len` bytes.
    ///
    /// Supports 1, 2, and 4 byte reads from the IPv4 header model.
    fn payload_read(&self, offset: u8, len: u8) -> u32 {
        match (offset, len) {
            (9, 1) => self.protocol as u32,  // protocol
            (12, 4) => self.src_ip,          // src addr
            (16, 4) => self.dst_ip,          // dst addr
            (20, 2) => self.src_port as u32, // src port (L4)
            (22, 2) => self.dst_port as u32, // dst port (L4)
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Expression result
// ---------------------------------------------------------------------------

/// Result of evaluating a single expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprResult {
    /// Continue to next expression.
    Continue,
    /// Expression rejected the packet; rule should drop.
    Reject,
}

// ---------------------------------------------------------------------------
// Rule evaluator
// ---------------------------------------------------------------------------

/// Evaluate a single rule against a packet context.
///
/// Returns `Some(verdict)` if the rule matched (all expressions passed),
/// or `None` if the packet does not match (evaluation continues to next rule).
fn eval_rule(rule: &mut Rule, pkt: &PktCtx, sets: &[Option<NfSet>; MAX_SETS]) -> Option<Verdict> {
    if !rule.enabled {
        return None;
    }

    let mut reg0: u32 = 0;

    for i in 0..rule.expr_count {
        let expr = match rule.exprs[i] {
            Some(ref e) => *e,
            None => break,
        };

        let result = eval_expr(expr, pkt, sets, &mut reg0);
        if result == ExprResult::Reject {
            return None;
        }

        // Immediate verdict terminates the rule early
        if let Expr::Immediate(v) = expr {
            rule.packets += 1;
            rule.bytes += pkt.pkt_len as u64;
            return Some(v);
        }
    }

    // All expressions passed → apply terminal verdict
    rule.packets += 1;
    rule.bytes += pkt.pkt_len as u64;
    Some(rule.verdict)
}

/// Evaluate a single expression.
fn eval_expr(
    expr: Expr,
    pkt: &PktCtx,
    sets: &[Option<NfSet>; MAX_SETS],
    reg0: &mut u32,
) -> ExprResult {
    match expr {
        Expr::Payload(spec) => {
            *reg0 = pkt.payload_read(spec.offset, spec.len);
            ExprResult::Continue
        }
        Expr::Cmp { op, value } => {
            let matched = match op {
                CmpOp::Eq => *reg0 == value,
                CmpOp::Neq => *reg0 != value,
                CmpOp::Lt => *reg0 < value,
                CmpOp::Lte => *reg0 <= value,
                CmpOp::Gt => *reg0 > value,
                CmpOp::Gte => *reg0 >= value,
            };
            if matched {
                ExprResult::Continue
            } else {
                ExprResult::Reject
            }
        }
        Expr::Counter => ExprResult::Continue,
        Expr::Log { .. } => ExprResult::Continue, // logging is a side-effect; always continue
        Expr::Nat { .. } => ExprResult::Continue, // NAT side-effect; always continue
        Expr::SetLookup { set_idx, key } => {
            if set_idx >= MAX_SETS {
                return ExprResult::Reject;
            }
            let found = sets[set_idx]
                .as_ref()
                .map(|s| s.contains(key))
                .unwrap_or(false);
            if found {
                ExprResult::Continue
            } else {
                ExprResult::Reject
            }
        }
        Expr::Immediate(_) => ExprResult::Continue, // handled by caller
    }
}

// ---------------------------------------------------------------------------
// nftables engine
// ---------------------------------------------------------------------------

/// The central nftables engine holding all tables and sets.
pub struct NfTables {
    /// Registered tables.
    tables: [Option<Table>; MAX_TABLES],
    /// Number of active tables.
    table_count: usize,
    /// Global set storage.
    sets: [Option<NfSet>; MAX_SETS],
    /// Number of active sets.
    set_count: usize,
    /// Whether the engine is globally enabled.
    enabled: bool,
}

impl NfTables {
    /// Create an empty nftables engine.
    pub const fn new() -> Self {
        Self {
            tables: [const { None }; MAX_TABLES],
            table_count: 0,
            sets: [const { None }; MAX_SETS],
            set_count: 0,
            enabled: true,
        }
    }

    /// Enable or disable the nftables engine.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    // ── Table management ─────────────────────────────────────────────────

    /// Add a table to the engine. Returns the table index.
    pub fn add_table(&mut self, table: Table) -> Result<usize> {
        if self.table_count >= MAX_TABLES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.table_count;
        self.tables[idx] = Some(table);
        self.table_count += 1;
        Ok(idx)
    }

    /// Find a table index by name.
    pub fn find_table(&self, name: &[u8]) -> Option<usize> {
        self.tables[..self.table_count].iter().position(|t| {
            t.as_ref()
                .map(|t| t.name[..t.name_len] == name[..name.len().min(t.name_len)])
                .unwrap_or(false)
        })
    }

    /// Get a mutable reference to a table by index.
    pub fn get_table_mut(&mut self, idx: usize) -> Option<&mut Table> {
        self.tables.get_mut(idx)?.as_mut()
    }

    /// Delete a table by name.
    pub fn delete_table(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.find_table(name).ok_or(Error::NotFound)?;
        for i in pos..self.table_count - 1 {
            self.tables.swap(i, i + 1);
        }
        self.tables[self.table_count - 1] = None;
        self.table_count -= 1;
        Ok(())
    }

    // ── Set management ───────────────────────────────────────────────────

    /// Add a set. Returns its global index.
    pub fn add_set(&mut self, set: NfSet) -> Result<usize> {
        if self.set_count >= MAX_SETS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.set_count;
        self.sets[idx] = Some(set);
        self.set_count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a set by index.
    pub fn get_set_mut(&mut self, idx: usize) -> Option<&mut NfSet> {
        self.sets.get_mut(idx)?.as_mut()
    }

    // ── Packet processing ────────────────────────────────────────────────

    /// Process a packet at the given hook point.
    ///
    /// Iterates all active base chains attached to `hook` (sorted by
    /// priority if stable, otherwise in registration order) and evaluates
    /// rules. Returns the final verdict.
    pub fn process(&mut self, hook: NfHook, pkt: &PktCtx) -> Verdict {
        if !self.enabled {
            return Verdict::Accept;
        }

        // Collect (table_idx, chain_idx, priority) for base chains at hook
        let mut candidates: [(usize, usize, i32); MAX_TABLES * MAX_CHAINS_PER_TABLE] =
            [(0, 0, 0); MAX_TABLES * MAX_CHAINS_PER_TABLE];
        let mut candidate_count = 0;

        for (ti, table) in self.tables[..self.table_count].iter().enumerate() {
            let t = match table {
                Some(t) if t.active => t,
                _ => continue,
            };
            for (ci, chain) in t.chains[..t.chain_count].iter().enumerate() {
                if let Some(c) = chain {
                    if let ChainType::Base { hook: h, priority } = c.chain_type {
                        if h == hook && candidate_count < candidates.len() {
                            candidates[candidate_count] = (ti, ci, priority);
                            candidate_count += 1;
                        }
                    }
                }
            }
        }

        // Sort by priority (insertion sort — small N)
        for i in 1..candidate_count {
            let mut j = i;
            while j > 0 && candidates[j - 1].2 > candidates[j].2 {
                candidates.swap(j - 1, j);
                j -= 1;
            }
        }

        // Evaluate chains in priority order
        for k in 0..candidate_count {
            let (ti, ci, _) = candidates[k];
            let verdict = self.eval_chain(ti, ci, pkt);
            match verdict {
                Verdict::Accept | Verdict::Drop | Verdict::Queue(_) => return verdict,
                Verdict::Continue | Verdict::Return => continue,
                Verdict::Jump(_) | Verdict::Goto(_) => continue,
            }
        }

        Verdict::Accept
    }

    /// Evaluate all rules in a chain. Returns the first terminal verdict.
    fn eval_chain(&mut self, table_idx: usize, chain_idx: usize, pkt: &PktCtx) -> Verdict {
        let table = match self.tables.get_mut(table_idx).and_then(|t| t.as_mut()) {
            Some(t) => t,
            None => return Verdict::Accept,
        };
        let chain = match table.chains.get_mut(chain_idx).and_then(|c| c.as_mut()) {
            Some(c) => c,
            None => return Verdict::Accept,
        };

        let rule_count = chain.rule_count;
        let default_policy = chain.policy;

        for i in 0..rule_count {
            let rule = match chain.rules[i].as_mut() {
                Some(r) => r,
                None => continue,
            };
            if let Some(verdict) = eval_rule(rule, pkt, &self.sets) {
                match verdict {
                    Verdict::Continue => continue,
                    other => return other,
                }
            }
        }

        // No rule matched; apply chain policy
        match default_policy {
            ChainPolicy::Accept => Verdict::Accept,
            ChainPolicy::Drop => Verdict::Drop,
        }
    }

    // ── Statistics ───────────────────────────────────────────────────────

    /// Snapshot of aggregate counters across all rules.
    pub fn stats(&self) -> NfStats {
        let mut stats = NfStats::default();
        stats.tables = self.table_count;
        for table in self.tables[..self.table_count].iter().flatten() {
            stats.chains += table.chain_count;
            for chain in table.chains[..table.chain_count].iter().flatten() {
                stats.rules += chain.rule_count;
                for rule in chain.rules[..chain.rule_count].iter().flatten() {
                    stats.total_packets += rule.packets;
                    stats.total_bytes += rule.bytes;
                }
            }
        }
        stats.sets = self.set_count;
        stats
    }
}

impl Default for NfTables {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate statistics snapshot for the nftables engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct NfStats {
    /// Number of tables.
    pub tables: usize,
    /// Number of chains (across all tables).
    pub chains: usize,
    /// Number of rules (across all chains).
    pub rules: usize,
    /// Number of sets.
    pub sets: usize,
    /// Total matched packets.
    pub total_packets: u64,
    /// Total matched bytes.
    pub total_bytes: u64,
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/expr` — POSIX.1-2024 expression evaluator.
//!
//! Reads a single expression from `argv[1..]` (one operator/operand per
//! argv element — the shell is responsible for splitting), evaluates it,
//! prints the result followed by a newline, and exits with a status that
//! reflects the truthiness of the result.
//!
//! Supported operators, lowest precedence first (per POSIX):
//!
//! ```text
//! expr | expr     return the first if non-empty/non-zero, else the second
//! expr & expr     return the first if both non-empty/non-zero, else 0
//! expr REL expr   = != < <= > >= — numeric if both sides are integers,
//!                  else lexical; result is "1" (true) or "0" (false)
//! expr + expr     additive          (i64, checked)
//! expr - expr     additive          (i64, checked)
//! expr * expr     multiplicative    (i64, checked)
//! expr / expr     multiplicative    (i64, checked, /0 is fatal)
//! expr % expr     multiplicative    (i64, checked, %0 is fatal)
//! expr : expr     string match — emit the length of the longest prefix of
//!                  the LHS that contains the RHS as a literal substring.
//!                  ONCRIX has no regex engine yet, so RHS is treated as a
//!                  literal pattern (POSIX permits this with a doc note).
//! ( expr )        parenthesised sub-expression (each paren is its own arg)
//! ```
//!
//! Exit codes (POSIX):
//!
//! ```text
//! 0   expression evaluates to non-zero / non-empty
//! 1   expression evaluates to zero / empty
//! 2   invalid expression (parse error)
//! 3   internal error (i64 overflow, division by zero, ...)
//! ```
//!
//! Implementation notes:
//!
//! * No heap. Argv tokens are referenced as `&[u8]` slices; arithmetic
//!   uses `i64` with `checked_*` everywhere; output goes through a small
//!   stack-allocated formatter.
//! * The evaluator is a hand-written recursive-descent parser that walks
//!   an argv index. Each grammar level corresponds to one POSIX precedence
//!   tier so right-associative quirks are avoided naturally.
//! * Values are kept as a tagged enum (`Value`) carrying either an `i64`
//!   or a borrowed argv-slice. POSIX requires that an integer-shaped
//!   string compare numerically against another integer-shaped string,
//!   even after textual operations like `:`, so the tag is reasserted at
//!   every comparison via [`as_int`].
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/expr.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym expr_main,
    );
}

/// Maximum number of argv tokens the parser will accept.
///
/// Real POSIX `expr` invocations rarely exceed a handful of tokens; we
/// cap at 64 so the parser can store all token slices in a single
/// stack-allocated array without needing an allocator.
const MAX_TOKENS: usize = 64;

extern "C" fn expr_main(argc: usize, argv: *const *const u8) -> ! {
    let mut tokens: [&[u8]; MAX_TOKENS] = [b""; MAX_TOKENS];
    let mut ntok = 0usize;
    let mut i = 1usize;
    while i < argc {
        if ntok >= MAX_TOKENS {
            write_err(b"expr: too many arguments\n");
            libc::exit(2);
        }
        // SAFETY: 0 < i < argc so argv.add(i) is a valid pointer to a
        // C-string slot supplied by the kernel exec entry frame.
        tokens[ntok] = unsafe { cstr_at(argv, i) };
        ntok += 1;
        i += 1;
    }

    if ntok == 0 {
        write_err(b"expr: missing expression\n");
        libc::exit(2);
    }

    let mut p = Parser {
        tokens: &tokens[..ntok],
        pos: 0,
    };
    let v = match p.parse_or() {
        Ok(v) => v,
        Err(ExprError::Parse) => {
            write_err(b"expr: syntax error\n");
            libc::exit(2);
        }
        Err(ExprError::Internal) => {
            write_err(b"expr: internal error\n");
            libc::exit(3);
        }
    };
    if p.pos != p.tokens.len() {
        write_err(b"expr: syntax error\n");
        libc::exit(2);
    }

    print_value(&v);
    libc::exit(if value_is_truthy(&v) { 0 } else { 1 })
}

// ---------------------------------------------------------------------------
// Value representation
// ---------------------------------------------------------------------------

/// A POSIX `expr` value — either an integer or a string slice.
///
/// `Str` holds a borrow into argv (or a static literal such as `b"0"`),
/// so values never own heap memory.
#[derive(Clone, Copy)]
enum Value<'a> {
    Int(i64),
    Str(&'a [u8]),
}

/// Parse-time errors. `Parse` maps to exit 2, `Internal` to exit 3.
#[derive(Clone, Copy)]
enum ExprError {
    Parse,
    Internal,
}

/// Returns `true` if `v` is the POSIX "true" value: non-zero integer or
/// non-empty string.
fn value_is_truthy(v: &Value<'_>) -> bool {
    match *v {
        Value::Int(n) => n != 0,
        Value::Str(s) => !s.is_empty(),
    }
}

/// Try to interpret `v` as an `i64`. Strings are accepted only if they
/// match POSIX's optional-sign-followed-by-digits form.
fn as_int(v: &Value<'_>) -> Option<i64> {
    match *v {
        Value::Int(n) => Some(n),
        Value::Str(s) => parse_i64(s),
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    tokens: &'a [&'a [u8]],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a [u8]> {
        self.tokens.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<&'a [u8]> {
        let t = self.peek()?;
        self.pos += 1;
        Some(t)
    }

    /// `expr | expr` — lowest precedence.
    fn parse_or(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_and()?;
        while let Some(t) = self.peek()
            && t == b"|"
        {
            self.pos += 1;
            let right = self.parse_and()?;
            left = if value_is_truthy(&left) {
                left
            } else if value_is_truthy(&right) {
                right
            } else {
                Value::Int(0)
            };
        }
        Ok(left)
    }

    /// `expr & expr` — short-circuit AND, returns LHS if both truthy.
    fn parse_and(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_cmp()?;
        while let Some(t) = self.peek()
            && t == b"&"
        {
            self.pos += 1;
            let right = self.parse_cmp()?;
            left = if value_is_truthy(&left) && value_is_truthy(&right) {
                left
            } else {
                Value::Int(0)
            };
        }
        Ok(left)
    }

    /// `expr REL expr` — `=`, `!=`, `<`, `<=`, `>`, `>=`. Numeric if both
    /// sides parse as integers, else lexical (byte-wise).
    fn parse_cmp(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_add()?;
        while let Some(t) = self.peek() {
            let op = match t {
                b"=" => CmpOp::Eq,
                b"!=" => CmpOp::Ne,
                b"<" => CmpOp::Lt,
                b"<=" => CmpOp::Le,
                b">" => CmpOp::Gt,
                b">=" => CmpOp::Ge,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_add()?;
            let result = match (as_int(&left), as_int(&right)) {
                (Some(l), Some(r)) => op.apply_int(l, r),
                _ => {
                    let l = value_as_bytes(&left);
                    let r = value_as_bytes(&right);
                    op.apply_bytes(l, r)
                }
            };
            left = Value::Int(if result { 1 } else { 0 });
        }
        Ok(left)
    }

    /// `expr + expr` and `expr - expr`.
    fn parse_add(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_mul()?;
        while let Some(t) = self.peek() {
            let add = match t {
                b"+" => true,
                b"-" => false,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_mul()?;
            let l = as_int(&left).ok_or(ExprError::Parse)?;
            let r = as_int(&right).ok_or(ExprError::Parse)?;
            let res = if add {
                l.checked_add(r)
            } else {
                l.checked_sub(r)
            };
            left = Value::Int(res.ok_or(ExprError::Internal)?);
        }
        Ok(left)
    }

    /// `expr * expr`, `expr / expr`, `expr % expr`.
    fn parse_mul(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_match()?;
        while let Some(t) = self.peek() {
            let op = match t {
                b"*" => MulOp::Mul,
                b"/" => MulOp::Div,
                b"%" => MulOp::Mod,
                _ => break,
            };
            self.pos += 1;
            let right = self.parse_match()?;
            let l = as_int(&left).ok_or(ExprError::Parse)?;
            let r = as_int(&right).ok_or(ExprError::Parse)?;
            let res = match op {
                MulOp::Mul => l.checked_mul(r),
                MulOp::Div => {
                    if r == 0 {
                        return Err(ExprError::Internal);
                    }
                    l.checked_div(r)
                }
                MulOp::Mod => {
                    if r == 0 {
                        return Err(ExprError::Internal);
                    }
                    l.checked_rem(r)
                }
            };
            left = Value::Int(res.ok_or(ExprError::Internal)?);
        }
        Ok(left)
    }

    /// `expr : expr` — string match. RHS is treated as a literal substring
    /// since ONCRIX has no regex engine; the result is the byte length of
    /// the longest prefix of LHS that contains the literal RHS, or `0` if
    /// RHS is empty or not present.
    fn parse_match(&mut self) -> Result<Value<'a>, ExprError> {
        let mut left = self.parse_primary()?;
        while let Some(t) = self.peek()
            && t == b":"
        {
            self.pos += 1;
            let right = self.parse_primary()?;
            let l = value_as_bytes(&left);
            let r = value_as_bytes(&right);
            let len = match_prefix_len(l, r);
            left = Value::Int(len as i64);
        }
        Ok(left)
    }

    /// Primary: parenthesised expression or a single token.
    fn parse_primary(&mut self) -> Result<Value<'a>, ExprError> {
        let t = self.bump().ok_or(ExprError::Parse)?;
        if t == b"(" {
            let inner = self.parse_or()?;
            match self.bump() {
                Some(close) if close == b")" => Ok(inner),
                _ => Err(ExprError::Parse),
            }
        } else {
            // POSIX: a bare token is the operand "as-is". Numeric coercion
            // is deferred to the operator that consumes it.
            Ok(Value::Str(t))
        }
    }
}

#[derive(Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn apply_int(self, l: i64, r: i64) -> bool {
        match self {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            CmpOp::Lt => l < r,
            CmpOp::Le => l <= r,
            CmpOp::Gt => l > r,
            CmpOp::Ge => l >= r,
        }
    }

    fn apply_bytes(self, l: &[u8], r: &[u8]) -> bool {
        match self {
            CmpOp::Eq => l == r,
            CmpOp::Ne => l != r,
            CmpOp::Lt => l < r,
            CmpOp::Le => l <= r,
            CmpOp::Gt => l > r,
            CmpOp::Ge => l >= r,
        }
    }
}

#[derive(Clone, Copy)]
enum MulOp {
    Mul,
    Div,
    Mod,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Stack buffer big enough to hold the decimal form of any `i64`
/// (`-9223372036854775808` is 20 bytes).
const I64_STR_LEN: usize = 21;

/// Borrow `v`'s textual form. Integers go through a per-call stack
/// formatter so the caller can pass the result by reference; the string
/// variant aliases its argv slice directly.
fn value_as_bytes<'a>(v: &'a Value<'a>) -> &'a [u8] {
    match *v {
        Value::Int(_) => {
            // Integer-as-string is only needed for byte-wise comparisons
            // when the *other* side fails int parsing. In that case we
            // fall back to the integer's own decimal text via a per-call
            // static buffer; this is sound because comparisons consume
            // both sides immediately and never retain the borrow.
            //
            // Implementation: route through a thread-local-ish static
            // by stashing into one of two rotating buffers so left/right
            // sides don't clobber each other within a single comparison.
            static_int_buf(v)
        }
        Value::Str(s) => s,
    }
}

/// Two rotating static buffers used by [`value_as_bytes`] so a single
/// comparison can hold borrows for both LHS and RHS simultaneously.
fn static_int_buf<'a>(v: &Value<'_>) -> &'a [u8] {
    // SAFETY: the ONCRIX userspace runtime is single-threaded, so two
    // rotating static buffers suffice to satisfy two concurrent borrows
    // from one comparison. Each call advances the rotation index, and
    // the borrow lifetime is bounded by the comparison itself.
    static mut BUFS: [[u8; I64_STR_LEN]; 2] = [[0; I64_STR_LEN]; 2];
    static mut LENS: [usize; 2] = [0; 2];
    static mut TURN: usize = 0;
    let n = match *v {
        Value::Int(n) => n,
        Value::Str(_) => 0,
    };
    // SAFETY: single-threaded process; rotating index keeps the two most
    // recent borrows alive.
    unsafe {
        let i = TURN & 1;
        TURN = TURN.wrapping_add(1);
        let len = format_i64(n, &mut BUFS[i]);
        LENS[i] = len;
        let ptr = BUFS[i].as_ptr();
        core::slice::from_raw_parts(ptr, len)
    }
}

/// Write `n` as ASCII decimal into the front of `buf`, returning the
/// number of bytes written. `buf` must be at least [`I64_STR_LEN`] long.
fn format_i64(n: i64, buf: &mut [u8; I64_STR_LEN]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; I64_STR_LEN];
    let mut idx = 0;
    let (negative, mut abs) = if n < 0 {
        // Use unsigned arithmetic so i64::MIN's absolute value still fits.
        (true, (n as i128).unsigned_abs() as u64)
    } else {
        (false, n as u64)
    };
    while abs > 0 {
        tmp[idx] = b'0' + (abs % 10) as u8;
        abs /= 10;
        idx += 1;
    }
    let mut out = 0;
    if negative {
        buf[out] = b'-';
        out += 1;
    }
    while idx > 0 {
        idx -= 1;
        buf[out] = tmp[idx];
        out += 1;
    }
    out
}

/// Length of the longest prefix of `hay` that contains `needle` as a
/// literal substring; `0` if `needle` is empty or not found. The return
/// value is the index just past the end of the first match — POSIX `expr`
/// uses this convention for non-anchored regex matches with no capture.
fn match_prefix_len(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let h = hay.len();
    let n = needle.len();
    if n > h {
        return 0;
    }
    let mut i = 0;
    while i + n <= h {
        if &hay[i..i + n] == needle {
            return i + n;
        }
        i += 1;
    }
    0
}

/// Parse `bytes` as a decimal `i64`. Accepts an optional leading `+`/`-`.
/// Returns `None` for empty input, non-digit characters, or overflow.
fn parse_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }
    let (negative, digits) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return None;
    }
    let mut acc: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    if negative {
        acc.checked_neg()
    } else {
        Some(acc)
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Print the value to stdout followed by `\n`.
fn print_value(v: &Value<'_>) {
    match *v {
        Value::Int(n) => {
            let mut buf = [0u8; I64_STR_LEN];
            let len = format_i64(n, &mut buf);
            write_all(1, &buf[..len]);
        }
        Value::Str(s) => write_all(1, s),
    }
    write_all(1, b"\n");
}

fn write_all(fd: i32, msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: `msg` is a valid byte slice; pointer arithmetic stays
        // within its bounds because `pos < msg.len()`.
        let n = unsafe { libc::write(fd, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

fn write_err(msg: &[u8]) {
    write_all(2, msg);
}

// ---------------------------------------------------------------------------
// argv decoding
// ---------------------------------------------------------------------------

/// Read the C string at `argv[idx]` as a `&[u8]` slice (without the NUL).
///
/// # Safety
///
/// `idx` must be `< argc` and `argv` must be the kernel-supplied argv
/// pointer for the running process. The returned slice borrows from the
/// stack frame the kernel populated, which lives for the entire process
/// lifetime — `'static` is therefore accurate.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"expr: panic\n");
    libc::exit(3)
}

// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrandom(2)` — fill a user-space buffer with cryptographically
//! secure random bytes.
//!
//! # Design
//!
//! This is the live `getrandom(2)` backend reached from the x86-64
//! SYSCALL dispatcher (`SYS_GETRANDOM = 318`). Output comes from the
//! kernel CSPRNG ([`crate::random_kern::RandomSubsystem`], a ChaCha20
//! DRBG), accessed through a single kernel-global instance
//! ([`kernel_csprng`]) that is **lazily seeded on first use** from the
//! CPU hardware random generator (`RDSEED`/`RDRAND`, CPUID-gated, TSC
//! fallback) via [`crate::kaslr::hw_entropy_u64`].
//!
//! There is deliberately no fast non-cryptographic PRNG here: a weak
//! generator would make every userspace consumer of `getrandom(2)`
//! (TLS keys, ASLR cookies, stack-guard values, session tokens, salts,
//! nonces) predictable. If the CSPRNG cannot be seeded, the syscall
//! fails closed rather than emitting low-entropy bytes.
//!
//! # Flags
//!
//! `GRND_NONBLOCK` (1) and `GRND_RANDOM` (2) are accepted. Because the
//! pool is seeded synchronously from the hardware RNG on first use, the
//! CSPRNG is normally ready immediately; if seeding fails the call
//! returns `-EAGAIN` (matching Linux `getrandom` behaviour when the
//! pool is not yet initialised and `GRND_NONBLOCK` is set, and erring
//! on the safe side otherwise).
//!
//! # POSIX / Linux reference
//!
//! - Linux `getrandom(2)` — `GRND_NONBLOCK`, `GRND_RANDOM` semantics.
//! - SYS_GETRANDOM = 318 (x86-64 Linux ABI).

use crate::random::{GRND_NONBLOCK, GRND_RANDOM};
use crate::random_kern::RandomSubsystem;
use oncrix_lib::{Error, Result};

// ── errno constants ──────────────────────────────────────────────────────────

/// `EFAULT` — bad user-space address.
const EFAULT: i64 = -14;

/// `EAGAIN` — CSPRNG not yet seeded / would block.
const EAGAIN: i64 = -11;

/// Hardware-entropy words mixed in to reach the CSPRNG seed threshold.
///
/// The pool seeds at 256 entropy-credit bits. Each 64-bit hardware
/// draw is credited 32 bits (a conservative estimate for `RDSEED`),
/// so 12 draws (384 credited bits) comfortably crosses the threshold
/// even if a few draws are weak.
const SEED_DRAWS: usize = 12;

/// Conservative entropy credit (bits) per 64-bit *hardware* draw.
///
/// This credit is only applied when a real CPU hardware RNG
/// (`RDSEED`/`RDRAND`) is present (see [`hw_rng_present`]). When the
/// only entropy source is the TSC fallback, draws are credited **zero**
/// bits — timing jitter alone must never push the pool past the seed
/// threshold, since that would let an attacker who can model boot
/// timing predict the CSPRNG seed.
const CREDIT_BITS_PER_DRAW: u32 = 32;

/// Largest chunk passed to a single `get_random_bytes` call.
///
/// `RandomSubsystem::get_random_bytes` rejects requests larger than its
/// internal maximum; we chunk user requests below that bound. 256 is
/// the CSPRNG output-buffer size and a safe, aligned chunk.
const MAX_CHUNK: usize = 256;

// ── Kernel-global CSPRNG singleton ───────────────────────────────────────────

/// Kernel-global CSPRNG instance, lazily seeded on first use.
///
/// # Safety
///
/// Mutated only on the single-CPU SYSCALL dispatch path. SYSCALL entry
/// clears IF via FMASK so no timer IRQ can interleave, and ONCRIX does
/// not yet run `getrandom` concurrently on multiple CPUs; there are no
/// concurrent accessors. Access is funnelled exclusively through
/// [`kernel_csprng`].
static mut KERNEL_CSPRNG: RandomSubsystem = RandomSubsystem::new();

/// Tracks whether [`KERNEL_CSPRNG`] has completed lazy seeding.
///
/// # Safety
///
/// Same single-CPU SYSCALL-path guarantee as [`KERNEL_CSPRNG`].
static mut KERNEL_CSPRNG_SEEDED: bool = false;

/// Whether a real CPU hardware RNG (`RDSEED` or `RDRAND`) is present.
///
/// This mirrors the CPUID feature gates inside
/// [`crate::kaslr::hw_entropy_u64`]. When this returns `false`, that
/// function can only return TSC-derived values, which are **not**
/// cryptographic-grade; the seeding loop therefore credits zero
/// entropy bits and `getrandom(2)` fails closed until a real entropy
/// source exists.
///
/// # SECURITY
///
/// `hw_entropy_u64` (in `kaslr.rs`, out of this lane) returns a bare
/// `u64` with no signal of whether the value came from `RDSEED`/
/// `RDRAND` or the TSC fallback. The robust long-term fix is for
/// `kaslr.rs` to expose a quality flag, e.g.
/// `hw_entropy_u64_quality() -> (u64, bool)` returning `true` only on
/// a confirmed `RDSEED`/`RDRAND` draw. Until that exists, this helper
/// re-derives availability from CPUID so the credit decision is made
/// fail-closed in this lane.
#[cfg(target_arch = "x86_64")]
fn hw_rng_present() -> bool {
    // CPUID leaf 1 ECX bit 30 = RDRAND; leaf 7 sub-leaf 0 EBX bit 18
    // = RDSEED. Leaves 1 and 7 exist on every x86_64 CPU.
    let max_leaf = oncrix_hal::cpu_feature::cpuid(0, 0).eax;
    if max_leaf >= 7 {
        let ebx7 = oncrix_hal::cpu_feature::cpuid(7, 0).ebx;
        if ebx7 & (1 << 18) != 0 {
            return true;
        }
    }
    let ecx1 = oncrix_hal::cpu_feature::cpuid(1, 0).ecx;
    ecx1 & (1 << 30) != 0
}

/// Non-x86 fallback: no hardware RNG modelled, so credit nothing.
#[cfg(not(target_arch = "x86_64"))]
fn hw_rng_present() -> bool {
    false
}

/// Borrow the kernel-global CSPRNG, seeding it on first use.
///
/// Returns a mutable reference to the singleton. On the first call it
/// drives the entropy pool past its seed threshold using hardware
/// entropy ([`crate::kaslr::hw_entropy_u64`]); subsequent calls return
/// the already-seeded instance.
///
/// Seeding only credits entropy bits when a real hardware RNG is
/// present ([`hw_rng_present`]). On a platform with no hardware RNG the
/// pool never reaches the seed threshold from the TSC fallback alone,
/// so [`RandomSubsystem::is_seeded`] stays `false` and `getrandom(2)`
/// fails closed until real entropy (interrupt/jitter) is accumulated
/// elsewhere.
///
/// # Safety
///
/// Caller must be on the single-CPU SYSCALL dispatch path (IF cleared),
/// guaranteeing no concurrent access to the global state. The returned
/// reference must not outlive the syscall and must not alias another
/// live borrow of the singleton.
unsafe fn kernel_csprng() -> &'static mut RandomSubsystem {
    // SAFETY: single-CPU SYSCALL path; see KERNEL_CSPRNG note. We hand
    // out exactly one live reference per call.
    let rng = unsafe {
        let p = &raw mut KERNEL_CSPRNG;
        &mut *p
    };

    // SAFETY: same single-CPU guarantee for the seeded flag.
    let already = unsafe {
        let p = &raw const KERNEL_CSPRNG_SEEDED;
        *p
    };

    if !already {
        // `init` only fails if already initialised; ignore that case.
        let _ = rng.init();
        // Credit real entropy bits only when a hardware RNG backs the
        // draws. With TSC-only fallback, mix the words for pool state
        // but credit zero, so timing alone cannot reach the threshold.
        let credit = if hw_rng_present() {
            CREDIT_BITS_PER_DRAW
        } else {
            0
        };
        let mut i = 0usize;
        while i < SEED_DRAWS {
            rng.add_entropy(crate::kaslr::hw_entropy_u64(), credit);
            i += 1;
        }
        // Mark the lazy-seed attempt complete regardless: if the pool
        // did not cross the threshold (no hardware RNG), the CSPRNG
        // stays unseeded and callers fail closed via `is_seeded`. We do
        // not retry the same zero-credit draws on every call.
        // SAFETY: single-CPU SYSCALL path; see KERNEL_CSPRNG_SEEDED note.
        unsafe {
            let p = &raw mut KERNEL_CSPRNG_SEEDED;
            *p = true;
        }
    }

    rng
}

/// Fill `out` with CSPRNG bytes, chunking to satisfy the subsystem's
/// per-request size bound.
///
/// # Safety
///
/// Same single-CPU SYSCALL-path requirement as [`kernel_csprng`].
unsafe fn csprng_fill(out: &mut [u8]) -> Result<()> {
    // SAFETY: forwarded single-CPU SYSCALL-path guarantee.
    let rng = unsafe { kernel_csprng() };
    if !rng.is_seeded() {
        return Err(Error::WouldBlock);
    }
    let mut off = 0usize;
    while off < out.len() {
        let end = (off + MAX_CHUNK).min(out.len());
        rng.get_random_bytes(&mut out[off..end])?;
        off = end;
    }
    Ok(())
}

/// Fill `out` with bytes from the kernel-global CSPRNG.
///
/// Public entry point for in-kernel consumers that need cryptographic
/// randomness (e.g. the stack-protector canary path) before any other
/// entropy plumbing exists. Lazily seeds the CSPRNG on first use, the
/// same as the `getrandom(2)` path.
///
/// # Safety
///
/// Must be called only from the single-CPU SYSCALL / early-init path on
/// which the kernel-global CSPRNG is mutated (IF cleared), so there is
/// no concurrent access to the singleton.
///
/// # Errors
///
/// Returns [`Error::WouldBlock`] if the CSPRNG could not be seeded.
pub unsafe fn fill_random(out: &mut [u8]) -> Result<()> {
    // SAFETY: forwarded single-CPU-path guarantee from the caller.
    unsafe { csprng_fill(out) }
}

// ── Syscall handler ──────────────────────────────────────────────────────────

/// `getrandom(buf, buflen, flags)` — fill `buf[..buflen]` with
/// cryptographically secure random bytes and return the number of bytes
/// written.
///
/// # Safety
///
/// Must be called only from the x86-64 SYSCALL dispatch path. `buf_ptr`
/// must be a user-space pointer supplied by the calling process; it is
/// validated before any write.
///
/// # Errors
///
/// - Returns `-14` (`EFAULT`) when the `buflen`-byte span at `buf_ptr`
///   is not a writable user-space region (NULL, non-canonical, below
///   the user base, straddling into kernel space, or unmapped).
/// - Returns `-11` (`EAGAIN`) when the kernel CSPRNG could not be
///   seeded (fail-closed; never emits low-entropy output).
pub unsafe fn sys_getrandom(buf_ptr: u64, buflen: u64, flags: u64) -> i64 {
    let len = buflen as usize;
    if len == 0 {
        return 0;
    }

    // ── Validate user pointer ────────────────────────────────────────
    // Span-check the exact `len` bytes the kernel is about to write.
    if crate::uaccess::verify_user_access(buf_ptr, len as u64, true).is_err() {
        return EFAULT;
    }

    // GRND_RANDOM / GRND_NONBLOCK are accepted; the CSPRNG is a single
    // pool seeded synchronously, so the only observable difference is
    // the fail-closed errno below. Reference the constants so intent is
    // explicit and unused-import lints stay clean.
    let _ = (GRND_RANDOM, GRND_NONBLOCK);
    let _ = flags;

    // ── Generate into a bounded kernel staging buffer, copy to user ──
    //
    // Staging avoids handing a raw user pointer to the CSPRNG and keeps
    // the user-space write confined to validated, volatile stores.
    let dst = buf_ptr as *mut u8;
    let mut staging = [0u8; MAX_CHUNK];
    let mut written = 0usize;

    while written < len {
        let chunk = (len - written).min(MAX_CHUNK);
        let buf = &mut staging[..chunk];

        // SAFETY: single-CPU SYSCALL dispatch path; csprng_fill only
        // touches the kernel-global CSPRNG and the local staging slice.
        if unsafe { csprng_fill(buf) }.is_err() {
            // Fail closed: never fall back to a weak generator.
            return if written == 0 { EAGAIN } else { written as i64 };
        }

        let mut i = 0usize;
        while i < chunk {
            // SAFETY: dst points into validated user space; offset is
            // within [0, len), guaranteed accessible by the EFAULT
            // check above.
            unsafe { dst.add(written + i).write_volatile(buf[i]) };
            i += 1;
        }
        written += chunk;
    }

    // Scrub the staging buffer so no random bytes linger on the stack.
    for b in staging.iter_mut() {
        // SAFETY: `staging` is a live owned local; volatile write keeps
        // the scrub from being optimised away.
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    written as i64
}

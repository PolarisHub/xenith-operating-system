//! Kernel random number generator: hardware entropy, a ChaCha8 CSPRNG, and
//! the `getrandom` syscall hook.
//!
//! This module is the single source of kernel randomness. It layers three
//! pieces, each building on the one below:
//!
//! 1. **Hardware entropy** — `rdrand` / `rdseed` instructions, gated by the
//!    CPUID probes in [`crate::arch::x86_64::cpu`]. [`get_random_u64`] reads a
//!    `u64` directly from the on-die DRBG with a bounded retry loop, and
//!    [`raw_entropy_u64`] pulls raw entropy from `rdseed` (falling back to
//!    `rdrand`) for seeding.
//! 2. **A ChaCha8 CSPRNG** — the [`ChaCha8`] state holds a 256-bit key, a
//!    64-bit block counter, and a 64-bit nonce, and produces a 64-byte
//!    keystream block per ChaCha8 permutation (4 double rounds). This is the
//!    same construction the Linux kernel's `getrandom(2)` uses, chosen because
//!    userspace expects `getrandom` to be cryptographically secure — a plain
//!    xoshiro would not be.
//! 3. **The kernel RNG singleton** — [`KERNEL_RNG`] is a [`SpinLock`]-guarded
//!    [`KernelRng`] seeded once during [`init`] from `rdseed`/`rdrand` (with a
//!    software entropy-mix fallback when neither instruction is available) and
//!    periodically reseeded from hardware as bytes are drawn. [`fill_bytes`]
//!    and [`next_u64`] are the kernel-internal consumers; [`sys_getrandom`] is
//!    the ring-3 surface.
//!
//! # Seeding and forward secrecy
//!
//! [`init`] runs during the devices phase, after the time subsystem (so
//! [`crate::time::uptime_ns`] and [`crate::time::rtc::now`] are live) and
//! before any userspace exists. It prefers `rdseed` for the key and nonce,
//! falls back to `rdrand`, and finally to a software mix of RTC wall time,
//! monotonic uptime, the TSC, the local APIC ID, and a handful of ASLR-style
//! address bits. The mix uses the splitmix64 finalizer, which is a good
//! 64-bit avalanche mixer and is public domain.
//!
//! After seeding, every [`REKEY_BYTES`] of generated output triggers a reseed:
//! 32 bytes of fresh `rdrand` entropy (when available) are XOR'd into the key,
//! the counter is reset, and a new keystream block is generated. This bounds
//! the damage if the DRBG state is ever observed and provides forward secrecy
//! for past output.
//!
//! # Layering
//!
//! `devices::rng` sits above `arch` (CPUID, `rdrand`/`rdseed`, `rdtsc`),
//! `time` (RTC + monotonic clock for the fallback seed), `sync` (the
//! [`SpinLock`] around the CSPRNG), and `mm` (the `USER_MAX` boundary the
//! syscall hook checks). The `pub fn init` here is wired into
//! `devices::init` by the devices-phase owner; the `pub fn sys_getrandom`
//! here is wired into `syscall::table::SYSCALLS` by the syscall-phase owner
//! at the next free syscall number. Both call sites are one-line additions
//! in their owning modules; the implementation and signature live here.

use core::arch::asm;

use crate::arch::x86_64::cpu::{current_cpu_apic_id, has_rdrand, has_rdseed};
use crate::arch::x86_64::instructions::{rdrand, rdseed, RandResult};
use crate::sync::SpinLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// "expand 32-byte k" — the ChaCha constants placed in state words 0..3.
///
/// Spelled as four little-endian u32s the way RFC 8439 defines them. The
/// constant is what makes a ChaCha block's first row identifiable and is
/// fixed for the 256-bit-key variant.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Number of ChaCha8 double rounds. ChaCha8 is ChaCha20 run for 8 rounds
/// instead of 20 — i.e. 4 double rounds (each double round is a column round
/// followed by a diagonal round). It is the round count the Linux kernel
/// uses for `getrandom` and is roughly 2.5x faster than ChaCha20 while
/// retaining a comfortable security margin.
const CHACHA8_DOUBLE_ROUNDS: usize = 4;

/// Bytes of keystream one ChaCha8 block produces (16 u32 words).
const BLOCK_BYTES: usize = 64;

/// Generate this many bytes from the CSPRNG before forcing a reseed from
/// hardware. Bounds the exposure of any single DRBG state and gives forward
/// secrecy for past output once the reseed overwrites the key. 1 MiB is the
/// same order as Linux's `CRNG_RESEED_INTERVAL`.
const REKEY_BYTES: u64 = 1 << 20;

/// Maximum retries for a single `rdrand` draw. Intel's SDM recommends a small
/// bounded retry for `rdrand` (the DRBG almost never underflows); 10 is the
/// conventional value used by glibc and the Linux kernel.
const RDRAND_RETRIES: u32 = 10;

/// Maximum retries for a single `rdseed` draw. The raw entropy source is
/// much slower to refill than the DRBG, so the SDM recommends a longer
/// backoff; 64 is a safe bounded value that still terminates quickly.
const RDSEED_RETRIES: u32 = 64;

/// Largest buffer [`sys_getrandom`] will fill in one call. Hostile userspace
/// could otherwise pin a CPU in the CSPRNG lock for an unbounded time; the
/// cap is generous (1 MiB) and a correct caller that needs more simply loops.
const GETRANDOM_MAX: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Hardware entropy
// ---------------------------------------------------------------------------

/// Read a 64-bit timestamp counter via `rdtsc`.
///
/// `rdtsc` is a non-privileged instruction that writes the current
/// cycle count into EDX:EAX. It is not serializing, so the exact value has
/// some jitter — which is exactly what we want for entropy mixing. The TSC
/// is not a *good* entropy source on its own (it is predictable across
/// reboots and across cores), but folded with the RTC and the uptime it
/// adds independent timing noise to the fallback seed.
#[inline]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is non-privileged and side-effect-free: it reads no
    // memory, touches no control registers, and modifies only EAX/EDX. It
    // does not change EFLAGS, so `preserves_flags` is sound. Callable from
    // any context.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Read a hardware random `u64` from `rdrand`, retrying a bounded number of
/// times.
///
/// `rdrand` draws from the on-die CSPRNG and only fails (CF=0) when the DRBG
/// is temporarily drained. Returns `Some(value)` on success or `None` if the
/// instruction is absent or every retry failed (which is effectively
/// impossible on real hardware within 10 tries). This is the raw hardware
/// path used by callers that want a value *now* without going through the
/// software CSPRNG — e.g. early-boot ASLR before [`init`] has run.
#[must_use]
pub fn get_random_u64() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    // SAFETY: `rdrand` is non-privileged and safe to execute from any
    // context. The `unsafe` is surface uniformity only; see
    // `arch::x86_64::instructions::rdrand`.
    for _ in 0..RDRAND_RETRIES {
        match unsafe { rdrand() } {
            RandResult::Ok(v) => return Some(v),
            RandResult::Retry => core::hint::spin_loop(),
        }
    }
    None
}

/// Pull 64 bits of raw entropy, preferring `rdseed` and falling back to
/// `rdrand`.
///
/// `rdseed` returns unconditioned entropy bits and is the preferred seed
/// source; it fails more often (the entropy source refills slowly), so the
/// retry budget is larger. When `rdseed` is absent or stays empty we fall
/// back to `rdrand`, which is itself DRBG output and still excellent seed
/// material. Returns `None` only if neither instruction is present.
#[must_use]
fn raw_entropy_u64() -> Option<u64> {
    if has_rdseed() {
        // SAFETY: `rdseed` is non-privileged; see `instructions::rdseed`.
        for _ in 0..RDSEED_RETRIES {
            match unsafe { rdseed() } {
                RandResult::Ok(v) => return Some(v),
                RandResult::Retry => core::hint::spin_loop(),
            }
        }
        // `rdseed` stayed empty; fall through to `rdrand` rather than giving
        // up — `rdrand` output is still well-conditioned seed material.
    }
    get_random_u64()
}

/// Fill `out` with raw entropy words, best-effort.
///
/// Repeatedly calls [`raw_entropy_u64`] to populate the slice. If no hardware
/// source is available the slice is left untouched and `false` is returned so
/// the caller can fall back to the software entropy mix. Partial fills (some
/// words written, then the source empties) report `true`; the caller treats
/// any written word as good entropy.
fn fill_raw_entropy(out: &mut [u64]) -> bool {
    let mut any = false;
    for slot in out.iter_mut() {
        match raw_entropy_u64() {
            Some(v) => {
                *slot = v;
                any = true;
            },
            None => break,
        }
    }
    any
}

// ---------------------------------------------------------------------------
// Software entropy mix (fallback seed when RDRAND/RDSEED are absent)
// ---------------------------------------------------------------------------

/// The splitmix64 finalizer: a 64-bit avalanche mixer.
///
/// Given a poorly-distributed input (e.g. a counter or a timestamp) this
/// produces a 64-bit output with every input bit affecting every output bit
/// (the "avalanche" property). It is the standard mixer used to initialize
/// PRNG state from arbitrary seed material and is public domain (Sebastiano
/// Vigna). Used here to fold the RTC/uptime/TSC/APIC-ID mix into uniform
/// seed words.
#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

/// Gather a 256-bit seed and a 64-bit nonce from non-hardware sources.
///
/// This is the fallback path for CPUs without `rdrand`/`rdseed` (e.g. some
/// pre-2012 parts and a few virtual-machine configurations that hide the
/// instructions). The mix combines:
///
/// * the RTC wall clock in Unix nanoseconds — the battery-backed time, which
///   varies across boots,
/// * the monotonic uptime in nanoseconds — timing jitter since boot,
/// * the TSC — cycle-counter jitter,
/// * the local APIC ID — distinguishes CPUs on an SMP boot,
/// * the addresses of a stack local, the static RNG, and the `init` call
///   site — ASLR-style bits placed by the loader and the kernel's own layout,
/// * a monotonic boot counter — distinguishes back-to-back reseed calls
///   within the same tick.
///
/// Each source is run through [`mix64`] and XOR-folded into one of four
/// 64-bit accumulators. The accumulators become the 256-bit ChaCha key; a
/// further fold of two sources supplies the 64-bit nonce. This is not a
/// CSPRNG-grade entropy source, but it is far better than a constant or a
/// single timestamp, and it only runs on hardware that lacks a real one.
fn software_seed() -> ([u8; 32], [u8; 8]) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static BOOT_NONCE: AtomicU64 = AtomicU64::new(0);

    // Accumulator for the 256-bit key (four u64s).
    let mut acc: [u64; 4] = [0; 4];
    // Cheap, always-available sources. Each is mixed before folding so a
    // low-entropy input (e.g. APIC ID 0 on the BSP) still perturbs many
    // output bits.
    let sources: [u64; 6] = [
        crate::time::rtc::now().to_unix_nanos().unwrap_or(0),
        crate::time::uptime_ns(),
        rdtsc(),
        u64::from(current_cpu_apic_id()),
        // Address-ASLR bits: the stack frame and the static's address. These
        // depend on the loader's placement of the kernel and on the current
        // stack pointer, both of which vary across boots and across calls.
        (&acc as *const [u64; 4]) as u64,
        BOOT_NONCE.fetch_add(1, Ordering::Relaxed),
    ];
    for (i, &s) in sources.iter().enumerate() {
        acc[i & 3] ^= mix64(s.wrapping_add(i as u64));
    }

    // Nonce: a 64-bit fold of the TSC and the boot counter. The nonce need
    // not be secret, only unique across reseeds, and the boot counter
    // guarantees that even when two reseeds land in the same tick.
    let nonce_word = mix64(rdtsc().wrapping_add(0x9e37_79b9)) ^ BOOT_NONCE.load(Ordering::Relaxed);

    let mut key = [0u8; 32];
    for (i, word) in acc.iter().enumerate() {
        key[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&nonce_word.to_le_bytes());
    (key, nonce)
}

// ---------------------------------------------------------------------------
// ChaCha8 CSPRNG
// ---------------------------------------------------------------------------

/// 32-bit left rotation. Used by the ChaCha quarter round.
#[inline]
const fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// One ChaCha quarter round on the four named state words.
///
/// This is the building block of both the column and diagonal rounds. The
/// rotation constants 16/12/8/7 are fixed by RFC 8439.
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl32(state[d] ^ state[a], 16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl32(state[b] ^ state[c], 12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = rotl32(state[d] ^ state[a], 8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = rotl32(state[b] ^ state[c], 7);
}

/// A ChaCha8 keystream generator with a 256-bit key, a 64-bit block
/// counter, and a 64-bit nonce.
///
/// The state is the 16 u32 words of the ChaCha matrix. Words 12 and 13 hold
/// the low and high halves of a 64-bit block counter so the generator can
/// produce 2^64 blocks (2^70 bytes) before the counter wraps — a bound that
/// is never reached in practice, especially since the reseed path resets the
/// counter. Words 14 and 15 hold the 64-bit nonce. (RFC 8439 uses a 32-bit
/// counter and a 96-bit nonce; we trade one nonce word for a 64-bit counter
/// so the counter cannot wrap between reseeds even on a wildly busy core.
/// A 64-bit nonce is still more than enough to be unique across reseeds
/// because it is refreshed from the TSC/uptime mix each time.)
#[derive(Debug)]
struct ChaCha8 {
    /// The 16-word ChaCha matrix: constants, key, counter (2 words), nonce
    /// (2 words).
    state: [u32; 16],
    /// The 64-byte keystream of the current block, consumed byte by byte.
    keystream: [u8; BLOCK_BYTES],
    /// Index of the next unread byte in `keystream`. `BLOCK_BYTES` means the
    /// buffer is exhausted and a new block must be generated.
    pos: usize,
}

impl ChaCha8 {
    /// Build a ChaCha8 generator from a 32-byte key and an 8-byte nonce.
    ///
    /// The counter starts at zero; the first block is generated lazily on
    /// the first read so the constructor does no permutation work.
    fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&SIGMA);
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        // Words 12 and 13 form the 64-bit block counter; both start at 0.
        state[12] = 0;
        state[13] = 0;
        // Words 14 and 15 hold the 64-bit nonce (two u32 words).
        state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        Self {
            state,
            keystream: [0; BLOCK_BYTES],
            pos: BLOCK_BYTES,
        }
    }

    /// Increment the 64-bit block counter (words 12 and 13).
    fn bump_counter(&mut self) {
        let (lo, of) = self.state[12].overflowing_add(1);
        self.state[12] = lo;
        if of {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    /// Generate the next 64-byte keystream block into [`keystream`].
    ///
    /// Runs the ChaCha8 permutation on a copy of the state (so the original
    /// counter/nonce words are preserved), adds the original state words
    /// per RFC 8439, and serializes the result little-endian. The block
    /// counter is then advanced so the next call produces a fresh block.
    fn generate_block(&mut self) {
        let mut working = self.state;
        for _ in 0..CHACHA8_DOUBLE_ROUNDS {
            // Column round.
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal round.
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        // Add the original state and serialize. The add+serialize is what
        // turns the permutation's internal state into the keystream block.
        for (i, word) in working.into_iter().enumerate() {
            let sum = word.wrapping_add(self.state[i]);
            self.keystream[i * 4..i * 4 + 4].copy_from_slice(&sum.to_le_bytes());
        }
        self.bump_counter();
        self.pos = 0;
    }

    /// Fill `out` with keystream bytes, generating new blocks as needed.
    fn fill(&mut self, out: &mut [u8]) {
        let mut off = 0;
        while off < out.len() {
            if self.pos >= BLOCK_BYTES {
                self.generate_block();
            }
            let take = (out.len() - off).min(BLOCK_BYTES - self.pos);
            out[off..off + take].copy_from_slice(&self.keystream[self.pos..self.pos + take]);
            self.pos += take;
            off += take;
        }
    }

    /// Read four u32 keystream words as one little-endian `u64`.
    ///
    /// Convenience for [`KernelRng::next_u64`]; pulls 8 bytes through the
    /// normal [`fill`] path so the counter and buffer stay consistent.
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill(&mut buf);
        u64::from_le_bytes(buf)
    }

    /// Overwrite the key (state words 4..12) with `key` and reset the
    /// counter. Used by the reseed path to install fresh entropy without
    /// reallocating the generator.
    fn rekey(&mut self, key: &[u8; 32]) {
        for i in 0..8 {
            self.state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        self.state[12] = 0;
        self.state[13] = 0;
        self.pos = BLOCK_BYTES;
    }
}

// ---------------------------------------------------------------------------
// KernelRng — the seeded singleton backing fill_bytes / next_u64 / getrandom
// ---------------------------------------------------------------------------

/// The kernel CSPRNG: a ChaCha8 generator plus a bytes-since-reseed counter
/// and a "has this been seeded yet" flag.
///
/// The flag lets [`fill_bytes`] lazily seed on a very-early call (before
/// [`init`] has run) rather than hand out the all-zero-key keystream, which
/// would be catastrophic. In practice [`init`] runs before any consumer, so
/// the lazy path is a defence-in-depth backstop.
#[derive(Debug)]
struct KernelRng {
    /// The ChaCha8 generator, or `None` until first seeded.
    chacha: Option<ChaCha8>,
    /// Bytes generated since the last reseed. Compared against
    /// [`REKEY_BYTES`] to decide when to pull fresh entropy.
    bytes_since_reseed: u64,
    /// Whether [`init`] (or a lazy seed) has installed a key.
    seeded: bool,
}

impl KernelRng {
    /// Construct an unseeded RNG. No permutation is run until a key arrives.
    const fn unseeded() -> Self {
        Self {
            chacha: None,
            bytes_since_reseed: 0,
            seeded: false,
        }
    }

    /// Seed the generator from the best available source.
    ///
    /// Tries `rdseed`/`rdrand` first (via [`raw_entropy_u64`]); if no
    /// hardware source is available, falls back to the software mix. Four
    /// 64-bit entropy words form the 32-byte key; a further fold supplies
    /// the 8-byte nonce. The previous generator (if any) is dropped, so
    /// its keystream buffer is not reused.
    fn seed(&mut self) {
        let mut words = [0u64; 4];
        let (key, nonce) = if fill_raw_entropy(&mut words) {
            let mut key = [0u8; 32];
            for (i, &w) in words.iter().enumerate() {
                key[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }
            // Fold the TSC and the APIC ID into an 8-byte nonce so the
            // nonce varies across reseeds even when the key source is the
            // hardware DRBG (which could return identical words on a
            // fast double-seed).
            let nonce_word = mix64(rdtsc()) ^ mix64(u64::from(current_cpu_apic_id()));
            let mut nonce = [0u8; 8];
            nonce.copy_from_slice(&nonce_word.to_le_bytes());
            (key, nonce)
        } else {
            software_seed()
        };
        self.chacha = Some(ChaCha8::new(&key, &nonce));
        self.bytes_since_reseed = 0;
        self.seeded = true;
    }

    /// Ensure the generator is seeded, lazily, on first use.
    fn ensure_seeded(&mut self) {
        if !self.seeded {
            self.seed();
        }
    }

    /// Pull fresh entropy into the key and reset the counter.
    ///
    /// Called every [`REKEY_BYTES`] of output. When hardware entropy is
    /// available, 32 bytes of `rdrand` output are XOR'd into the current
    /// key (so an attacker who captured the old state still cannot predict
    /// the new one). When it is not, the software mix re-derives the key
    /// outright. The nonce is refreshed from the TSC/uptime mix.
    fn reseed(&mut self) {
        // Always refresh the nonce from timing sources so two reseeds in
        // the same tick still differ. The nonce is 64 bits (two ChaCha
        // words); a TSC/uptime fold is plenty of uniqueness across reseeds.
        let nonce_word = mix64(rdtsc()) ^ mix64(crate::time::uptime_ns());
        let new_nonce = nonce_word.to_le_bytes();

        let mut key = [0u8; 32];
        let mut words = [0u64; 4];
        if fill_raw_entropy(&mut words) {
            for (i, &w) in words.iter().enumerate() {
                key[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
            }
            // XOR the new entropy into the old key if a generator already
            // exists, providing forward secrecy for the previous state.
            if let Some(ref mut cc) = self.chacha {
                let mut old = [0u8; 32];
                for i in 0..8 {
                    old[i * 4..i * 4 + 4].copy_from_slice(&cc.state[4 + i].to_le_bytes());
                }
                for i in 0..32 {
                    key[i] ^= old[i];
                }
            }
        } else {
            // No hardware source: re-derive from the software mix. This is
            // only reached on hardware without `rdrand`/`rdseed`.
            let (k, _) = software_seed();
            key = k;
        }

        // Install the key (which resets the counter), then overwrite the
        // two nonce words (14, 15) so the new key starts at a fresh point
        // in keystream space.
        if let Some(ref mut cc) = self.chacha {
            cc.rekey(&key);
            cc.state[14] =
                u32::from_le_bytes([new_nonce[0], new_nonce[1], new_nonce[2], new_nonce[3]]);
            cc.state[15] =
                u32::from_le_bytes([new_nonce[4], new_nonce[5], new_nonce[6], new_nonce[7]]);
        } else {
            self.chacha = Some(ChaCha8::new(&key, &new_nonce));
        }
        self.bytes_since_reseed = 0;
    }

    /// Fill `out` with random bytes, reseeding if the byte budget is spent.
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.ensure_seeded();
        let chacha = self.chacha.as_mut().expect("rng seeded but absent");
        chacha.fill(out);
        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(out.len() as u64);
        if self.bytes_since_reseed >= REKEY_BYTES {
            self.reseed();
        }
    }

    /// Return a single `u64`, reseeding if the byte budget is spent.
    fn next_u64(&mut self) -> u64 {
        self.ensure_seeded();
        let chacha = self.chacha.as_mut().expect("rng seeded but absent");
        let v = chacha.next_u64();
        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(8);
        if self.bytes_since_reseed >= REKEY_BYTES {
            self.reseed();
        }
        v
    }
}

// ---------------------------------------------------------------------------
// Global RNG + init
// ---------------------------------------------------------------------------

/// The kernel RNG singleton.
///
/// Guarded by a [`SpinLock`] because the CSPRNG is shared between every
/// kernel consumer and every `getrandom` syscall. The critical section is
/// short (a ChaCha8 block is ~150 ns), so a plain spinlock is the right
/// primitive — the syscall path runs in process context with interrupts on,
/// matching the [`SpinLock`] contract. A `SpinLockIRQ` would be needed only
/// if an interrupt handler drew randomness, which it must not (handlers
/// should pre-fetch randomness into per-CPU state if they ever need it).
static KERNEL_RNG: SpinLock<KernelRng> = SpinLock::new(KernelRng::unseeded());

/// Bring up the kernel RNG.
///
/// Probes `rdrand`/`rdseed` via CPUID, seeds the ChaCha8 generator from the
/// best available source, and logs the result. Idempotent: a second call
/// re-seeds the generator (which is harmless and useful if new entropy
/// sources appear late). Must run after the time subsystem so the software
/// fallback mix has RTC and uptime available.
pub fn init() {
    let hw_rdrand = has_rdrand();
    let hw_rdseed = has_rdseed();
    {
        let mut rng = KERNEL_RNG.lock();
        rng.seed();
    }
    ::log::info!(
        "xenith.rng: ChaCha8 CSPRNG seeded (rdrand={}, rdseed={})",
        hw_rdrand,
        hw_rdseed,
    );
}

/// Fill `out` with cryptographically random bytes from the kernel CSPRNG.
///
/// This is the kernel-internal consumer: stack canaries, ASLR offsets,
/// allocation nonce, UUID generation. It lazily seeds on the first call if
/// [`init`] has not run yet, so it is safe to call from anywhere at any
/// time. The call blocks on the [`KERNEL_RNG`] lock for the duration of the
/// fill; for very large buffers prefer splitting the work across calls.
pub fn fill_bytes(out: &mut [u8]) {
    let mut rng = KERNEL_RNG.lock();
    rng.fill_bytes(out);
}

/// Return a single random `u64` from the kernel CSPRNG.
///
/// Convenience wrapper around [`fill_bytes`] for callers that need a single
/// word (a randomized delay, a tag, a hash seed). For a raw hardware draw
/// that bypasses the CSPRNG, use [`get_random_u64`].
#[must_use]
pub fn next_u64() -> u64 {
    let mut rng = KERNEL_RNG.lock();
    rng.next_u64()
}

// ---------------------------------------------------------------------------
// getrandom syscall hook
// ---------------------------------------------------------------------------

/// The highest virtual address a user-space mapping may use, re-exported
/// here from `mm::r#virtual` so the syscall hook does not depend on the full
/// paging module. Mirrors the constant in `syscall::handlers`; kept local so
/// this module is self-contained for the syscall-phase owner who wires
/// [`sys_getrandom`] into the table.
const USER_MAX: u64 = crate::mm::r#virtual::USER_MAX;

fn getrandom_flags_supported(flags: u64) -> bool {
    flags & !u64::from(xenith_abi::GRND_NONBLOCK) == 0
}

/// `getrandom(buf, buflen, flags)` — fill a user buffer with random bytes.
///
/// Arguments: `args[0]` = pointer to the buffer, `args[1]` = number of
/// bytes requested, `args[2]` = flags. Zero and
/// [`xenith_abi::GRND_NONBLOCK`] are accepted; every unknown bit is rejected.
///
/// Returns the number of bytes written on success, or `-errno` on failure.
/// The buffer pointer is validated against [`USER_MAX`] before any byte is
/// written, a request larger than [`GETRANDOM_MAX`] yields `-EINVAL`, and
/// the fill is chunked through a 64-byte stack buffer so the user pointer is
/// never held across the CSPRNG lock and a large request cannot pin a CPU.
///
/// The signature matches [`crate::syscall::SyscallFn`] so the syscall-phase
/// owner can drop `Some(crate::devices::rng::sys_getrandom)` straight into
/// `syscall::table::SYSCALLS` at the next free number.
pub fn sys_getrandom(ctx: &crate::syscall::SyscallContext) -> i64 {
    use crate::syscall::Errno;

    let buf = ctx.arg(0);
    let buflen = ctx.arg(1);
    let flags = ctx.arg(2);
    if !getrandom_flags_supported(flags) {
        return Errno::Einval.as_ret();
    }

    if buflen == 0 {
        return 0;
    }
    if buflen > GETRANDOM_MAX {
        return Errno::Einval.as_ret();
    }
    // Validate the full buffer range up front so a pointer near the top of
    // the user region cannot cause an out-of-bounds write partway through.
    let Some(last) = buf.checked_add(buflen - 1) else {
        return Errno::Efault.as_ret();
    };
    if buf == 0 || last > USER_MAX {
        return Errno::Efault.as_ret();
    }

    let mut written = 0u64;
    let mut scratch = [0u8; BLOCK_BYTES];
    while written < buflen {
        let n = (buflen - written).min(BLOCK_BYTES as u64) as usize;
        // Pull `n` bytes from the CSPRNG into the stack scratch buffer, then
        // release the lock before touching user memory. Splitting the lock
        // and the user copy keeps the user pointer out of the critical
        // section and means a faulting user page does not deadlock the RNG.
        {
            let mut rng = KERNEL_RNG.lock();
            rng.fill_bytes(&mut scratch[..n]);
        }
        if crate::arch::x86_64::usercopy::copy_to_user_slice(
            buf + written,
            &scratch[..n],
        ) {
            written += n as u64;
        } else {
            if written == 0 {
                return Errno::Efault.as_ret();
            }
            break;
        }
    }
    written as i64
}

#[cfg(test)]
mod tests {
    use super::getrandom_flags_supported;

    #[test]
    fn getrandom_accepts_only_the_documented_flag_bits() {
        assert!(getrandom_flags_supported(0));
        assert!(getrandom_flags_supported(u64::from(
            xenith_abi::GRND_NONBLOCK
        )));
        assert!(!getrandom_flags_supported(2));
        assert!(!getrandom_flags_supported(1 << 32));
    }
}

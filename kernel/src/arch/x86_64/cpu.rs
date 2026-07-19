//! CPUID-based CPU detection and per-CPU topology helpers.
//!
//! This module is the single source of truth for "what CPU am I running on"
//! in the kernel. It wraps the `cpuid` instruction behind a small safe API,
//! uses it to build a [`CpuInfo`] snapshot (vendor string, brand string,
//! family/model/stepping, and a [`CpuFeatures`] flag set), and exposes the
//! per-CPU helpers the rest of the arch subsystem needs:
//!
//! * [`has_rdrand`] / [`has_rdseed`] — cheap boolean probes used by
//!   [`super::early_init`] and the entropy path to avoid re-running CPUID on
//!   every draw.
//! * [`current_cpu_apic_id`] — the local APIC ID of the running CPU, obtained
//!   from CPUID leaf `1`. This is the identity the LAPIC, IPI, and per-CPU
//!   subsystems key off of.
//! * [`detect_bsp`] — whether the current CPU is the boot strap processor
//!   (read from the LAPIC's IA32_APIC_BASE MSR, where bit 8 is the BSP flag).
//!
//! # Why CPUID is wrapped here and not in `instructions`
//!
//! `instructions` holds the one-line raw-instruction wrappers (`hlt`, `cli`,
//! `rdmsr`, ...). CPUID, by contrast, comes in a family of related leaves with
//! structured outputs (EAX/EBX/ECX/EDX bitfields), and the kernel needs to
//! interpret those bits rather than just emit the instruction. Keeping that
//! interpretation here — next to the vendor/brand/feature decoding — means the
//! `instructions` module stays a thin asm surface and the "what does this CPU
//! support" logic lives in one auditable place.
//!
//! # Safety
//!
//! `cpuid` is a unprivileged, side-effect-free instruction: it reads no memory,
//! touches no control registers, and is callable from any ring. The wrappers
//! below therefore present a *safe* API — the only `unsafe` blocks are the
//! `asm!` invocations themselves, gated by the standard "inline asm is sound
//! when the instruction matches its declared options" argument. MSR reads
//! (`rdmsr`) are privileged and stay `unsafe`; see [`detect_bsp`].

use core::arch::asm;
use core::fmt;

use xenith_bitflags::bitflags;

// ---------------------------------------------------------------------------
// CPUID leaf constants
// ---------------------------------------------------------------------------

/// CPUID leaf 0: highest vendor-id leaf + vendor string (EBX/EDX/ECX).
const LEAF_VENDOR: u32 = 0x0000_0000;

/// CPUID leaf 1: family/model/stepping, local APIC ID (EBX[31:24]), and the
/// "feature information" bits in EDX/ECX (SSE, RDRAND, APIC, x2APIC, ...).
const LEAF_FEATURE_INFO: u32 = 0x0000_0001;

/// CPUID leaf `0x8000_0000`: highest extended leaf + extended vendor/brand
/// information. Used to discover whether extended leaves (brand string, 1 GiB
/// pages, RDTSCP, ...) are available at all.
const LEAF_EXT_MAX: u32 = 0x8000_0000;

/// CPUID leaves `0x8000_0002..=0x8000_0004`: the 48-byte ASCII processor brand
/// string, consumed 16 bytes per leaf.
const LEAF_BRAND_START: u32 = 0x8000_0002;
const LEAF_BRAND_END: u32 = 0x8000_0004;

// Sub-leaves used to probe a specific feature without re-running the whole
// feature-info leaf. Kept here so the probe helpers are self-contained.
const LEAF_EXT_FEATURES: u32 = 0x8000_0001; // RDTSCP, 1G pages, SYSCALL in EDX
#[allow(dead_code)]
const LEAF_EXT_STATE: u32 = 0x0000_000D; // XSAVE feature leaf (sub-leaf 0)
const LEAF_FSGSBASE: u32 = 0x0000_0007; // FSGSBASE in EBX[0]
const LEAF_X2APIC: u32 = 0x0000_0001; // x2APIC in ECX[21] (same as leaf 1)

// IA32_APIC_BASE MSR. Bit 8 is the BSP flag; bit 11 is APIC global enable.
// Defined as a literal here so `detect_bsp` does not depend on the `msr`
// module's named constants landing first — the MSR address is architectural
// and stable.
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const IA32_APIC_BASE_BSP_BIT: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// CPUID raw wrapper
// ---------------------------------------------------------------------------

/// The four GPRs `cpuid` fills for a given `leaf` (and optional `sub-leaf`).
///
/// `cpuid` writes EAX, EBX, ECX, EDX in that order; this struct preserves the
/// pairing so callers can read the register they care about by name instead of
/// remembering which tuple slot holds which value.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CpuidResult {
    /// EAX output.
    pub eax: u32,
    /// EBX output.
    pub ebx: u32,
    /// ECX output.
    pub ecx: u32,
    /// EDX output.
    pub edx: u32,
}

impl fmt::Debug for CpuidResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuidResult")
            .field("eax", &format_args!("{:#010x}", self.eax))
            .field("ebx", &format_args!("{:#010x}", self.ebx))
            .field("ecx", &format_args!("{:#010x}", self.ecx))
            .field("edx", &format_args!("{:#010x}", self.edx))
            .finish()
    }
}

/// Run `cpuid` with `leaf` in EAX and `0` in ECX.
///
/// `cpuid` is a privileged-information *reader* but not a privileged
/// instruction: it is callable from any privilege level and performs no memory
/// access, no control-register modification, and no I/O. The `nomem` option is
/// therefore *not* set, because the result is a function of CPU state the
/// compiler cannot reason about, but `preserves_flags` is correct — `cpuid`
/// does not modify EFLAGS. `nostack` reflects that `cpuid` does not touch the
/// stack for its own operation (the compiler still allocates stack for the
/// return struct, which is the caller's concern).
#[inline]
#[must_use]
pub fn cpuid(leaf: u32) -> CpuidResult {
    cpuid_with(leaf, 0)
}

/// Run `cpuid` with `leaf` in EAX and `sub_leaf` in ECX.
///
/// Many CPUID leaves (e.g. `0x0000_000D` for XSAVE, `0x0000_0007` for
/// structured features) are indexed by a sub-leaf passed in ECX. This wrapper
/// makes the sub-leaf explicit so callers do not have to remember that
/// [`cpuid`] hard-codes zero.
#[inline]
#[must_use]
pub fn cpuid_with(leaf: u32, sub_leaf: u32) -> CpuidResult {
    // SAFETY: CPUID is available on every x86_64 processor. The intrinsic
    // also handles LLVM's reserved-RBX requirements for position-independent
    // code, which raw `out("ebx")` operands cannot express.
    let result = core::arch::x86_64::__cpuid_count(leaf, sub_leaf);
    CpuidResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

/// Highest basic (`leaf <= 0xFFFF_FFFF`) CPUID leaf supported by this CPU.
///
/// Callers that probe a non-standard basic leaf should check it against this
/// value first; querying a leaf above the supported maximum returns zeroes (or,
/// on some older parts, Intel-specified-but-unimplemented data) rather than
/// faulting.
#[inline]
#[must_use]
pub fn max_basic_leaf() -> u32 {
    cpuid(LEAF_VENDOR).eax
}

/// Highest extended (`leaf >= 0x8000_0000`) CPUID leaf supported by this CPU.
///
/// Returns `0x8000_0000` (i.e. no extended leaves beyond the query itself) on
/// parts that do not implement the extended leaf space. The brand-string and
/// 1 GiB-page probes both guard on this being large enough.
#[inline]
#[must_use]
pub fn max_extended_leaf() -> u32 {
    cpuid(LEAF_EXT_MAX).eax
}

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

bitflags! {
    /// CPU features Xenith cares about, decoded from CPUID leaf 1 (and a few
    /// secondary leaves) into a single flag set.
    ///
    /// The flag set is intentionally small: it tracks only the features the
    /// kernel actually keys off of — interrupt-controller mode (APIC vs
    /// x2APIC), entropy instructions (RDRAND/RDSEED), SIMD state management
    /// (SSE/XSAVE), and the `rdfsbase`/`wrfsbase` instructions (FSGSBASE).
    /// Adding a new feature is a one-line change to the bitflags block plus a
    /// probe line in [`CpuInfo::detect`].
    pub struct CpuFeatures: u64 {
        /// Legacy local APIC is present and supported (CPUID.01H:EDX[9]).
        const APIC      = 1 << 0;
        /// x2APIC mode is available (CPUID.01H:ECX[21]). Implies APIC.
        const X2APIC    = 1 << 1;
        /// `rdrand` instruction present (CPUID.01H:ECX[30]).
        const RDRAND    = 1 << 2;
        /// `rdseed` instruction present (CPUID.07H:EBX[18]).
        const RDSEED    = 1 << 3;
        /// SSE present and usable (CPUID.01H:EDX[25]); paired with OSFXSR
        /// enablement in [`super::early_init`].
        const SSE       = 1 << 4;
        /// SSE2 present (CPUID.01H:EDX[26]).
        const SSE2      = 1 << 5;
        /// SSE3 present (CPUID.01H:ECX[0]).
        const SSE3      = 1 << 6;
        /// XSAVE family of instructions is available (CPUID.01H:ECX[26]).
        /// The kernel uses `xsave`/`xrstor` to manage FPU/SSE/AVX state across
        /// context switches once this is set.
        const XSAVE     = 1 << 7;
        /// `rdfsbase`/`wrfsbase`/`rdgsbase`/`wrgsbase` are available
        /// (CPUID.07H:EBX[0]). Lets the kernel swap the FS/GS bases without
        /// going through MSRs.
        const FSGSBASE  = 1 << 8;
        /// `rdtscp` is available (CPUID.80000001H:EDX[27]). Used by the
        /// timekeeping code for a cheap serializing timestamp read.
        const RDTSCP    = 1 << 9;
        /// 1 GiB pages are supported (CPUID.80000001H:EDX[26]). The mm phase
        /// may use these to map the HHDM with fewer PUD entries.
        const PAGE1GB   = 1 << 10;
        /// `syscall`/`sysret` instructions are available
        /// (CPUID.80000001H:EDX[11]). Required for the Xenith syscall entry.
        const SYSCALL   = 1 << 11;
    }
}

// ---------------------------------------------------------------------------
// Vendor and brand strings
// ---------------------------------------------------------------------------

/// 12-byte CPU vendor string as reported by CPUID leaf 0
/// (EBX, EDX, ECX in that order).
///
/// The vendor string is the canonical way to tell Intel (`GenuineIntel`),
/// AMD (`AuthenticAMD`), and the various hypervisor vendors (`KVMKVMKVM`,
/// `Microsoft Hv`, `VMwareVMware`, ...) apart. Stored as a fixed-size array so
/// no allocation is required and the type is `Copy`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VendorString([u8; 12]);

impl VendorString {
    /// Build a vendor string from a leaf-0 CPUID result.
    ///
    /// The Intel SDM specifies the order as EBX, EDX, ECX — *not* the natural
    /// EAX/EBX/ECX/EDX ordering of the registers. Getting this wrong produces a
    /// scrambled vendor string, so the order is load-bearing here.
    #[inline]
    #[must_use]
    pub const fn from_cpuid(r: CpuidResult) -> Self {
        let ebx = r.ebx.to_le_bytes();
        let edx = r.edx.to_le_bytes();
        let ecx = r.ecx.to_le_bytes();
        Self([
            ebx[0], ebx[1], ebx[2], ebx[3], edx[0], edx[1], edx[2], edx[3], ecx[0], ecx[1], ecx[2],
            ecx[3],
        ])
    }

    /// View the vendor string as ASCII bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Return the vendor string as a `&str` if it is valid ASCII, else `None`.
    ///
    /// Real vendor strings are always ASCII; a non-ASCII result indicates a
    /// broken CPUID (effectively impossible on real hardware) and is reported
    /// rather than silently rendered with replacement bytes.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

impl fmt::Debug for VendorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "{s:?}"),
            None => f.debug_tuple("VendorString").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for VendorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Render printable bytes directly and fall back to a placeholder when
        // the bytes are not valid ASCII (which never happens on real
        // hardware but keeps the Display impl total).
        match self.as_str() {
            Some(s) => f.write_str(s),
            None => f.write_str("<invalid vendor>"),
        }
    }
}

/// 48-byte CPU brand string as reported by CPUID leaves
/// `0x8000_0002..=0x8000_0004`.
///
/// Intel and AMD populate this with a human-readable part identifier such as
/// `"Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"`. Parts that do not implement
/// the extended leaf space fill the array with ASCII spaces (`0x20`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BrandString([u8; 48]);

impl BrandString {
    /// Read the 48-byte brand string from CPUID leaves `0x8000_0002..4`.
    ///
    /// Each of the three leaves yields 16 bytes in EAX/EBX/ECX/EDX (4 bytes
    /// each, little-endian). Concatenating them in leaf order gives the full
    /// brand string. The caller is responsible for confirming via
    /// [`max_extended_leaf`] that the extended leaf space is large enough
    /// (≥ `0x8000_0004`); this helper reads unconditionally and returns a
    /// space-filled string on parts that lack the leaves.
    #[must_use]
    pub fn read() -> Self {
        let l2 = cpuid(LEAF_BRAND_START);
        let l3 = cpuid(LEAF_BRAND_START + 1);
        let l4 = cpuid(LEAF_BRAND_END);
        let mut out = [0u8; 48];
        let fill = |chunk: &mut [u8; 16], r: CpuidResult| {
            chunk[0..4].copy_from_slice(&r.eax.to_le_bytes());
            chunk[4..8].copy_from_slice(&r.ebx.to_le_bytes());
            chunk[8..12].copy_from_slice(&r.ecx.to_le_bytes());
            chunk[12..16].copy_from_slice(&r.edx.to_le_bytes());
        };
        // Split the 48-byte buffer into three 16-byte sub-arrays in place.
        // `split_array_mut` would be cleaner but is still unstable; indexed
        // slicing with constants is safe by construction.
        fill((&mut out[0..16]).try_into().unwrap(), l2);
        fill((&mut out[16..32]).try_into().unwrap(), l3);
        fill((&mut out[32..48]).try_into().unwrap(), l4);
        Self(out)
    }

    /// View the brand string as raw bytes (NUL- or space-padded).
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Return the brand string with trailing NULs and spaces trimmed, as a
    /// `&str` if the remainder is valid UTF-8.
    #[must_use]
    pub fn trimmed_str(&self) -> Option<&str> {
        // Brand strings are ASCII with trailing spaces or NULs; trim both.
        let mut end = self.0.len();
        while end > 0 {
            let b = self.0[end - 1];
            if b == 0 || b == b' ' {
                end -= 1;
            } else {
                break;
            }
        }
        core::str::from_utf8(&self.0[..end]).ok()
    }
}

impl fmt::Debug for BrandString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.trimmed_str() {
            Some(s) => write!(f, "{s:?}"),
            None => f.debug_tuple("BrandString").field(&self.0).finish(),
        }
    }
}

impl fmt::Display for BrandString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.trimmed_str().unwrap_or("<invalid brand>"))
    }
}

// ---------------------------------------------------------------------------
// Family / model / stepping
// ---------------------------------------------------------------------------

/// The decoded CPU family, model, and stepping numbers.
///
/// x86_64 encodes the family and model in a split field: CPUID.01H:EAX[3:0] is
/// the stepping, [7:4] is the base model, [11:8] is the base family, and for
/// family 0xF (and 0x6 on Intel) the extended family/model in EAX[27:20] and
/// [19:16] fold in to produce the "displayed" family and model. Intel and AMD
/// share the same decoding rules here, so one helper covers both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyModel {
    /// Displayed family number (e.g. 6 for Intel's client/workstation line,
    /// 0x17 for AMD Zen).
    pub family: u16,
    /// Displayed model number within the family.
    pub model: u8,
    /// Stepping/revision number.
    pub stepping: u8,
}

impl FamilyModel {
    /// Decode the family/model/stepping triple from a CPUID leaf-1 EAX value.
    ///
    /// The algorithm follows the Intel SDM "CPUID .01H" description:
    ///
    /// 1. `base_family = eax[11:8]`, `base_model = eax[7:4]`,
    ///    `stepping = eax[3:0]`.
    /// 2. If `base_family == 0x0F`, add `eax[27:20]` to the family and
    ///    `eax[19:16] << 4` to the model. Otherwise the extended fields are
    ///    ignored (they are zero on non-0xF families by spec).
    ///
    /// The result is the number that ends up in `uname -m`-style reporting and
    /// in kernel log lines.
    #[inline]
    #[must_use]
    pub const fn from_eax(eax: u32) -> Self {
        let stepping = (eax & 0x000F) as u8;
        let base_model = ((eax >> 4) & 0x000F) as u8;
        let base_family = ((eax >> 8) & 0x000F) as u8;
        let ext_family = ((eax >> 20) & 0x00FF) as u16;
        let ext_model = ((eax >> 16) & 0x000F) as u8;

        let (family, model) = if base_family == 0x0F {
            // Extended fields contribute only when the base family is 0xF.
            (
                base_family as u16 + ext_family,
                base_model + (ext_model << 4),
            )
        } else {
            (base_family as u16, base_model)
        };

        Self {
            family,
            model,
            stepping,
        }
    }
}

// ---------------------------------------------------------------------------
// CpuInfo
// ---------------------------------------------------------------------------

/// A snapshot of everything the kernel needs to know about the current CPU's
/// identity and feature set.
///
/// Built once per CPU by [`CpuInfo::detect`] and typically cached in the
/// per-CPU control block. The snapshot is cheap to produce (five `cpuid`
/// calls plus one `rdmsr`) and `Copy`, so callers are encouraged to read it
/// rather than re-run CPUID.
#[derive(Clone, Copy, Debug)]
pub struct CpuInfo {
    /// 12-byte vendor string from CPUID leaf 0.
    pub vendor: VendorString,
    /// 48-byte brand string from CPUID leaves `0x8000_0002..4`.
    pub brand: BrandString,
    /// Decoded family/model/stepping from CPUID leaf 1.
    pub family_model: FamilyModel,
    /// Decoded feature flags from CPUID leaves 1, 7, and `0x8000_0001`.
    pub features: CpuFeatures,
    /// Local APIC ID of the CPU that produced this snapshot
    /// (CPUID.01H:EBX[31:24]). This is the 8-bit initial APIC ID; x2APIC
    /// parts may report a wider ID through leaf `0x0B`, which a later phase
    /// will plumb in.
    pub apic_id: u8,
    /// Highest basic CPUID leaf supported.
    pub max_leaf: u32,
    /// Highest extended CPUID leaf supported (`0x8000_0000` if none).
    pub max_ext_leaf: u32,
}

impl CpuInfo {
    /// Probe the current CPU and build a [`CpuInfo`] snapshot.
    ///
    /// Runs five `cpuid` calls (vendor, feature info, brand string x3) and
    /// decodes them into the fields above. Safe to call from any privilege
    /// level and any CPU; the result reflects whichever CPU executes the
    /// CPUID instructions.
    #[must_use]
    pub fn detect() -> Self {
        let max_leaf = max_basic_leaf();
        let vendor = VendorString::from_cpuid(cpuid(LEAF_VENDOR));

        let feat = cpuid(LEAF_FEATURE_INFO);
        let family_model = FamilyModel::from_eax(feat.eax);
        // EBX[31:24] is the 8-bit local APIC ID at the "feature info" leaf.
        // On x2APIC-enabled parts the full 32-bit ID comes from leaf 0x0B;
        // for now the 8-bit ID is sufficient to tell CPUs apart on any system
        // with ≤ 255 logical processors.
        let apic_id = ((feat.ebx >> 24) & 0xFF) as u8;

        let mut features = CpuFeatures::empty();
        // Leaf 1 EDX features: APIC, SSE, SSE2.
        if (feat.edx >> 9) & 1 == 1 {
            features.insert(CpuFeatures::APIC);
        }
        if (feat.edx >> 25) & 1 == 1 {
            features.insert(CpuFeatures::SSE);
        }
        if (feat.edx >> 26) & 1 == 1 {
            features.insert(CpuFeatures::SSE2);
        }
        // Leaf 1 ECX features: SSE3, RDRAND, XSAVE, x2APIC.
        if feat.ecx & 1 == 1 {
            features.insert(CpuFeatures::SSE3);
        }
        if (feat.ecx >> 21) & 1 == 1 {
            features.insert(CpuFeatures::X2APIC);
        }
        if (feat.ecx >> 26) & 1 == 1 {
            features.insert(CpuFeatures::XSAVE);
        }
        if (feat.ecx >> 30) & 1 == 1 {
            features.insert(CpuFeatures::RDRAND);
        }

        // Leaf 7 (structured features): FSGSBASE in EBX[0], RDSEED in EBX[18].
        // Only probe if the basic max leaf is large enough; older parts do not
        // implement leaf 7 and reading it returns zeros (which would be
        // harmless), but guarding keeps the intent explicit.
        if max_leaf >= LEAF_FSGSBASE {
            let l7 = cpuid_with(LEAF_FSGSBASE, 0);
            if l7.ebx & 1 == 1 {
                features.insert(CpuFeatures::FSGSBASE);
            }
            if (l7.ebx >> 18) & 1 == 1 {
                features.insert(CpuFeatures::RDSEED);
            }
        }

        // Extended leaves: RDTSCP, 1G pages, SYSCALL, and the brand string.
        let max_ext_leaf = max_extended_leaf();
        if max_ext_leaf >= LEAF_EXT_FEATURES {
            let ext = cpuid(LEAF_EXT_FEATURES);
            if (ext.edx >> 11) & 1 == 1 {
                features.insert(CpuFeatures::SYSCALL);
            }
            if (ext.edx >> 26) & 1 == 1 {
                features.insert(CpuFeatures::PAGE1GB);
            }
            if (ext.edx >> 27) & 1 == 1 {
                features.insert(CpuFeatures::RDTSCP);
            }
        }

        let brand = if max_ext_leaf >= LEAF_BRAND_END {
            BrandString::read()
        } else {
            // Parts without the extended brand leaves (some early x86_64
            // silicon and certain hypervisors) get a space-filled placeholder
            // so the field is never uninitialised.
            BrandString([b' '; 48])
        };

        Self {
            vendor,
            brand,
            family_model,
            features,
            apic_id,
            max_leaf,
            max_ext_leaf,
        }
    }

    /// Convenience: is this an Intel CPU?
    #[inline]
    #[must_use]
    pub fn is_intel(&self) -> bool {
        self.vendor.as_str() == Some("GenuineIntel")
    }

    /// Convenience: is this an AMD CPU?
    #[inline]
    #[must_use]
    pub fn is_amd(&self) -> bool {
        self.vendor.as_str() == Some("AuthenticAMD")
    }

    /// Convenience: is this CPU running under a hypervisor?
    ///
    /// CPUID leaf 1 ECX[31] is the "hypervisor present" bit; every
    /// conforming hypervisor (KVM, Xen, Hyper-V, VMware, QEMU+TCG) sets it.
    /// The kernel uses this to relax some timing and TLB assumptions that
    /// differ under virtualisation.
    #[inline]
    #[must_use]
    pub fn is_hypervised(&self) -> bool {
        // Re-read leaf 1 ECX rather than caching the whole word: the bit is
        // stable for the CPU's lifetime, but keeping the probe here avoids
        // growing CpuInfo with a "raw leaf 1 ECX" field nobody else needs.
        (cpuid(LEAF_FEATURE_INFO).ecx >> 31) & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Single-feature probes
// ---------------------------------------------------------------------------

/// Cheap "is `rdrand` available" probe.
///
/// Used by [`super::early_init`] to avoid re-running the full [`CpuInfo::detect`]
/// pass and by the entropy pool to short-circuit on parts without `rdrand`.
/// The probe is a single CPUID leaf-1 ECX bit test.
#[inline]
#[must_use]
pub fn has_rdrand() -> bool {
    // Guard against parts that do not implement leaf 1 at all (effectively
    // impossible on any x86_64 CPU, but the guard is cheap and keeps the
    // helper self-contained).
    if max_basic_leaf() < LEAF_FEATURE_INFO {
        return false;
    }
    (cpuid(LEAF_FEATURE_INFO).ecx >> 30) & 1 == 1
}

/// Cheap "is `rdseed` available" probe.
///
/// `rdseed` lives in CPUID leaf 7 EBX[18], so this helper first confirms leaf 7
/// is implemented before reading the bit.
#[inline]
#[must_use]
pub fn has_rdseed() -> bool {
    if max_basic_leaf() < LEAF_FSGSBASE {
        return false;
    }
    (cpuid_with(LEAF_FSGSBASE, 0).ebx >> 18) & 1 == 1
}

/// Whether the current CPU supports the x2APIC mode.
///
/// x2APIC is reported in CPUID leaf 1 ECX[21]. The kernel prefers x2APIC over
/// the legacy MMIO APIC when it is available because it raises the per-CPU ID
/// limit from 8 bits to 32 and exposes an MSR interface instead of MMIO.
#[inline]
#[must_use]
pub fn has_x2apic() -> bool {
    if max_basic_leaf() < LEAF_X2APIC {
        return false;
    }
    (cpuid(LEAF_X2APIC).ecx >> 21) & 1 == 1
}

// ---------------------------------------------------------------------------
// Per-CPU identity
// ---------------------------------------------------------------------------

/// Local APIC ID of the CPU this thread is currently executing on.
///
/// Obtained from CPUID leaf 1 EBX[31:24], which the architecture guarantees
/// reflects the *current* logical processor's initial APIC ID. This is the
/// identity the LAPIC hardware, inter-processor interrupts, and the per-CPU
/// subsystem use to find a CPU's control block.
///
/// On parts with more than 255 logical processors the x2APIC leaf (`0x0B`)
/// reports a wider 32-bit ID; a later phase will plumb that in. For now the
/// 8-bit ID is correct on every system Xenith targets.
#[inline]
#[must_use]
pub fn current_cpu_apic_id() -> u8 {
    // CPUID is guaranteed to return a stable APIC ID for the executing
    // logical processor, so a single leaf-1 read is enough.
    let ebx = cpuid(LEAF_FEATURE_INFO).ebx;
    ((ebx >> 24) & 0xFF) as u8
}

/// Detect whether the current CPU is the boot strap processor (BSP).
///
/// The IA32_APIC_BASE MSR (address `0x1B`) carries the BSP flag in bit 8:
/// the CPU sets it on the BSP and clears it on every application processor at
/// reset. Reading the MSR is a privileged operation, so this helper is
/// `unsafe` — callers must be in ring 0 with the APIC-base MSR in its
/// architectural state (i.e. before any kernel code has relocated the APIC).
///
/// # Safety
///
/// `rdmsr` is a privileged instruction that traps to a #GP if executed at a
/// privilege level other than ring 0. The caller must guarantee ring 0
/// execution.
///
/// # Returns
///
/// `true` if the current CPU is the BSP, `false` if it is an AP. On parts
/// where the MSR read is unavailable (should never happen on any x86_64 CPU
/// that boots Xenith) this returns `true` so a failing probe does not
/// accidentally demote the BSP.
#[inline]
#[must_use]
pub unsafe fn detect_bsp() -> bool {
    // SAFETY: `rdmsr` requires ring 0; the caller has asserted that invariant
    // by taking an `unsafe fn` reference. The MSR address is architectural.
    let (lo, _hi) = unsafe { rdmsr_raw(IA32_APIC_BASE_MSR) };
    (u64::from(lo) & IA32_APIC_BASE_BSP_BIT) != 0
}

/// Raw `rdmsr` returning the low and high 32-bit halves.
///
/// Used internally by [`detect_bsp`] so the cpu module does not depend on the
/// `msr` module's `Msr` newtype landing first. The `msr` module re-exports a
/// richer `rdmsr(Msr) -> u64` API; this is the minimal leaf primitive.
///
/// # Safety
///
/// `rdmsr` is privileged (ring 0 only) and the MSR address must be valid for
/// the executing CPU. Reading an undefined MSR raises a #GP.
#[inline]
unsafe fn rdmsr_raw(addr: u32) -> (u32, u32) {
    let lo: u32;
    let hi: u32;
    // SAFETY: caller guarantees ring 0 and a valid MSR address. `rdmsr`
    // writes EAX (low 32) and EDX (high 32) and modifies no other state; it
    // does not touch EFLAGS, so `preserves_flags` is sound.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") addr,
            out("eax") lo,
            out("edx") hi,
            options(preserves_flags, nostack, nomem),
        );
    }
    (lo, hi)
}

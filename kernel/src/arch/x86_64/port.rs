//! Typed port I/O (`in` / `out` instructions) for x86_64.
//!
//! The x86 I/O space is a separate 16-bit address space from memory: it is
//! reached through the `in` and `out` instructions, addressed by a 16-bit
//! "port number" rather than a virtual or physical address. There are three
//! widths of access — 8, 16, and 32 bits — selected by the instruction
//! encoding (`in al, dx`, `in ax, dx`, `in eax, dx`). A 64-bit `in` does not
//! exist; if 64 bits must be transferred, the caller does two 32-bit reads.
//!
//! # Why a typed wrapper
//!
//! Raw `out dx, al` in inline asm is easy to get wrong: the port number must
//! be in `dx`, the value in `al`/`ax`/`eax`, and the width must match on both
//! sides. A mismatch compiles but silently corrupts the transaction. The
//! [`Port<IoWidth>`] newtype fixes the width in the type, so a `Port<U8>` can
//! only ever issue 8-bit accesses and a `Port<U32>` only 32-bit ones. The
//! [`PortRead`] / [`PortWrite`] traits carry the actual instruction and are
//! implemented once per width.
//!
//! # Safety
//!
//! `in` and `out` are privileged on most port ranges (some low ports are
//! user-accessible with the IOPL mask, but the kernel never relies on that).
//! The [`Port`] methods are safe because they only encode the instruction;
//! the caller is responsible for knowing that the port number they passed to
//! [`Port::new`] refers to a device the kernel actually owns. Misaddressing a
//! port is a hardware error, not a memory-safety error in Rust's sense, so
//! this split matches the usual kernel convention.
//!
//! # Volatility
//!
//! Port reads have side effects (they advance device state, clear interrupt
//! latches, etc.) and port writes mutate device registers. Every access here
//! is emitted with `options(volatile, preserves_flags, nostack, nomem)` —
//! `volatile` so the compiler does not elide or reorder the access, and
//! `preserves_flags` because `in`/`out` do not modify EFLAGS.

use core::marker::PhantomData;

// ---------------------------------------------------------------------------
// Width markers
// ---------------------------------------------------------------------------

/// A marker trait describing a port-access width and the integer type it
/// carries.
///
/// Each implementor fixes both the width (in bits) used to select the `in` /
/// `out` instruction encoding and the Rust value type returned by a read or
/// accepted by a write. The trait is sealed against downstream impls so only
/// the three widths the hardware supports (`U8`, `U16`, `U32`) can ever be
/// used to parameterise [`Port`].
///
/// # Safety contract for implementors
///
/// `WIDTH` must be one of 8, 16, or 32 — the widths for which the x86
/// architecture provides an `in` / `out` encoding. The implementor's
/// [`PortRead`] / [`PortWrite`] impls must use the matching instruction.
pub trait PortWidth: Copy + Clone + private::Sealed {
    /// The access width in bits. Used purely as a compile-time invariant; the
    /// actual instruction selection lives in the `PortRead` / `PortWrite`
    /// impls.
    const WIDTH: u8;
}

mod private {
    /// Sealing marker. Implementing this trait outside this module is
    /// impossible, which keeps the set of `PortWidth` implementors closed at
    /// the three hardware-supported widths.
    pub trait Sealed {}
}

/// 8-bit port access (`in al, dx` / `out dx, al`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U8;
impl private::Sealed for U8 {}
impl PortWidth for U8 {
    const WIDTH: u8 = 8;
}

/// 16-bit port access (`in ax, dx` / `out dx, ax`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U16;
impl private::Sealed for U16 {}
impl PortWidth for U16 {
    const WIDTH: u8 = 16;
}

/// 32-bit port access (`in eax, dx` / `out dx, eax`).
///
/// There is no 64-bit `in`/`out`; callers that need a 64-bit transfer do two
/// `U32` accesses.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct U32;
impl private::Sealed for U32 {}
impl PortWidth for U32 {
    const WIDTH: u8 = 32;
}

// ---------------------------------------------------------------------------
// Read / Write traits
// ---------------------------------------------------------------------------

/// Read a value of the implementing type from an I/O port.
///
/// The trait is separate from [`PortWrite`] so that read-only or write-only
/// device registers can be modelled by only implementing one of the two. In
/// practice every standard x86 port supports both, but several MMIO-style
/// devices reached through PIO expose a write-only command port and a
/// read-only data port, so the split is worth keeping.
///
/// # Safety
///
/// Implementors must emit a real `in` instruction of the correct width with
/// the port number in `dx`. The instruction is privileged for most port
/// ranges; the trait does not check IOPL because kernel code always runs at
/// IOPL 0 with port access permitted.
pub unsafe trait PortRead {
    /// Read `self` from the I/O port numbered `port`.
    ///
    /// `port` is the 16-bit port number, loaded into `dx`. The returned value
    /// arrives in `al` / `ax` / `eax` depending on the implementing width.
    ///
    /// # Safety
    ///
    /// The caller must ensure `port` refers to a device the kernel may touch.
    /// Issuing an `in` against a port that maps to a bus device the kernel
    /// does not own can trigger undefined device behaviour (a spurious ACK to
    /// a PCI card, a spurious interrupt-controller strobe, etc.). It is not a
    /// Rust memory-safety violation in the strict sense, but it is a kernel
    /// correctness invariant the type system cannot enforce.
    unsafe fn read_from_port(port: u16) -> Self;
}

/// Write a value of the implementing type to an I/O port.
///
/// # Safety
///
/// Implementors must emit a real `out` instruction of the correct width with
/// the port number in `dx` and the value in `al` / `ax` / `eax`. See
/// [`PortRead`] for the privilege discussion.
pub unsafe trait PortWrite {
    /// Write `self` to the I/O port numbered `port`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `port` refers to a device the kernel may drive.
    /// A stray `out` can hard-reset the machine (e.g. writing 0xFE to port
    /// 0x64 trips the keyboard-controller reset line) or mask interrupts in
    /// surprising ways. The type system cannot enforce device ownership.
    unsafe fn write_to_port(self, port: u16);
}

// ---------------------------------------------------------------------------
// Per-width instruction impls
// ---------------------------------------------------------------------------

// SAFETY: Each impl emits the exact `in`/`out` instruction encoding for its
// width, with the port number in `dx` and the value in the correct register.
// `options(volatile, preserves_flags, nostack, nomem)` matches the ISA:
//   - volatile:  port I/O has side effects; do not elide or reorder.
//   - preserves_flags: `in`/`out` do not modify EFLAGS.
//   - nostack:   the insns touch no stack.
//   - nomem:     port space is disjoint from memory; the asm does not alias
//                Rust's memory model. (We keep `volatile` so the access still
//                emits, but we promise the compiler it need not treat the
//                asm as a memory fence.)
unsafe impl PortRead for u8 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") value,
                options(preserves_flags, nostack, nomem),
            );
        }
        value
    }
}

unsafe impl PortWrite for u8 {
    #[inline]
    unsafe fn write_to_port(self, port: u16) {
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") self,
                options(preserves_flags, nostack, nomem),
            );
        }
    }
}

unsafe impl PortRead for u16 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u16 {
        let value: u16;
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                in("dx") port,
                out("ax") value,
                options(preserves_flags, nostack, nomem),
            );
        }
        value
    }
}

unsafe impl PortWrite for u16 {
    #[inline]
    unsafe fn write_to_port(self, port: u16) {
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") self,
                options(preserves_flags, nostack, nomem),
            );
        }
    }
}

unsafe impl PortRead for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u32 {
        let value: u32;
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                in("dx") port,
                out("eax") value,
                options(preserves_flags, nostack, nomem),
            );
        }
        value
    }
}

unsafe impl PortWrite for u32 {
    #[inline]
    unsafe fn write_to_port(self, port: u16) {
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") self,
                options(preserves_flags, nostack, nomem),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Port<IoWidth>
// ---------------------------------------------------------------------------

/// A typed handle to an x86 I/O port.
///
/// The port number is a 16-bit value (`0..=0xFFFF`); the width is fixed in the
/// type parameter `IoWidth`, which selects one of [`U8`], [`U16`], or [`U32`].
/// A `Port<U16>` can only ever issue 16-bit accesses, so the compiler proves
/// at construction time that a device's documented access width is honoured
/// for every read and write through the handle.
///
/// `Port` is `Copy` and zero-cost: it is a single `u16` plus a
/// zero-sized marker. Passing a `Port` by value does not copy any device
/// state; it just hands the port number to the next call site.
///
/// The value type read from or written to a `Port<IoWidth>` is determined by
/// the [`PortWidth`] implementor — `U8` carries `u8`, `U16` carries `u16`,
/// `U32` carries `u32`. This is enforced by the trait bounds on
/// [`Port::read`] and [`Port::write`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Port<IoWidth: PortWidth> {
    /// The 16-bit port number, loaded into `dx` for every access.
    port: u16,
    /// Zero-sized marker pinning the access width.
    _width: PhantomData<IoWidth>,
}

// ---------------------------------------------------------------------------
// Associated value type — maps IoWidth -> register-width integer.
// ---------------------------------------------------------------------------

// We need a bridge from the *marker* type (U8/U16/U32) to the *value* type
// (u8/u16/u32). Because the marker carries no data, the mapping is a single
// associated type per marker. The trait below is the only place the
// marker-to-value mapping is encoded; the Port methods dispatch through it.

/// The register-width integer associated with a port width marker.
///
/// This trait connects the zero-sized width marker to the integer type the
/// `in` / `out` instruction uses for that width. It is implemented once per
/// marker and sealed through [`PortWidth`]'s private module, so only
/// `U8` / `U16` / `U32` can ever be used to parameterise [`Port`].
pub trait PortRegister: PortWidth {
    /// The integer value type read from / written to a port of this width.
    type Value: PortRead + PortWrite + Copy;
}

impl PortRegister for U8 {
    type Value = u8;
}
impl PortRegister for U16 {
    type Value = u16;
}
impl PortRegister for U32 {
    type Value = u32;
}

impl<IoWidth: PortRegister> Port<IoWidth> {
    /// Create a handle to the given I/O port number.
    ///
    /// `port` must be in `0..=0xFFFF`; values outside that range are not
    /// valid x86 port numbers and the high bits would be ignored by the
    /// `in`/`out` encoding anyway, so we truncate explicitly to make the
    /// loss of precision visible at the call site.
    ///
    /// This performs **no** I/O — it only records the port number. Accesses
    /// happen through [`read`](Self::read) and [`write`](Self::write).
    #[inline]
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self {
            port,
            _width: PhantomData,
        }
    }

    /// The raw 16-bit port number this handle addresses.
    ///
    /// Useful for logging, diagnostics, and for passing the number to code
    /// that needs to emit its own `in`/`out` (e.g. the PCI configuration
    /// access helpers, which pack a port number and a datum into a single
    /// transaction).
    #[inline]
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Read a value from this port.
    ///
    /// Issues the `in` instruction of the configured width with the port
    /// number in `dx` and returns the value delivered in `al` / `ax` / `eax`.
    ///
    /// The method is safe because the only invariant the type system cannot
    /// check — "this port number belongs to a device the kernel may touch" —
    /// is a kernel-ownership question, not a Rust memory-safety one. Callers
    /// that construct a `Port` are asserting they have the right to drive
    /// that port.
    #[inline]
    #[must_use]
    pub fn read(self) -> IoWidth::Value {
        // SAFETY: The port number was supplied at construction; the caller of
        // `Port::new` is asserting the device is kernel-owned. The instruction
        // width matches the marker type by construction via `PortRegister`.
        unsafe { IoWidth::Value::read_from_port(self.port) }
    }

    /// Write `value` to this port.
    ///
    /// Issues the `out` instruction of the configured width with the port
    /// number in `dx` and the value in `al` / `ax` / `eax`.
    #[inline]
    pub fn write(self, value: IoWidth::Value) {
        // SAFETY: Same invariant as `read`: the port handle's creator vouches
        // for the port number. The width matches by construction.
        unsafe { value.write_to_port(self.port) }
    }

    /// Read and then immediately write back a value, returning what was read.
    ///
    /// This is the common "read-modify-write" pattern for device registers
    /// where a write-only command port would lose the prior state. The two
    /// accesses are emitted in program order; `volatile` on both prevents the
    /// compiler from fusing or reordering them.
    #[inline]
    #[must_use]
    pub fn read_write(self, value: IoWidth::Value) -> IoWidth::Value {
        let prev = self.read();
        self.write(value);
        prev
    }
}

// ---------------------------------------------------------------------------
// Convenience aliases
// ---------------------------------------------------------------------------

/// An 8-bit I/O port. Reads and writes `u8` values via `in al, dx`.
pub type Port8 = Port<U8>;

/// A 16-bit I/O port. Reads and writes `u16` values via `in ax, dx`.
pub type Port16 = Port<U16>;

/// A 32-bit I/O port. Reads and writes `u32` values via `in eax, dx`.
pub type Port32 = Port<U32>;

/// A small helper for the common pattern of issuing a one-shot port access
/// without keeping a `Port` handle around.
///
/// Defined as a free function rather than a method because it reads from a
/// port number directly, with no width fixed in a handle's type. Callers that
/// reuse the same port should prefer constructing a `Port<U8>` once and
/// calling `read` on it — this is purely for the throwaway case.
///
/// # Safety
///
/// Same invariant as [`Port::read`]: the caller must own the port.
#[inline]
#[must_use]
pub unsafe fn read_port_u8(port: u16) -> u8 {
    // SAFETY: Forwarded to the trait impl; the caller vouches for the port.
    unsafe { u8::read_from_port(port) }
}

/// One-shot 16-bit port read. See [`read_port_u8`].
///
/// # Safety
///
/// The caller must own the port.
#[inline]
#[must_use]
pub unsafe fn read_port_u16(port: u16) -> u16 {
    unsafe { u16::read_from_port(port) }
}

/// One-shot 32-bit port read. See [`read_port_u8`].
///
/// # Safety
///
/// The caller must own the port.
#[inline]
#[must_use]
pub unsafe fn read_port_u32(port: u16) -> u32 {
    unsafe { u32::read_from_port(port) }
}

/// One-shot 8-bit port write. See [`read_port_u8`].
///
/// # Safety
///
/// The caller must own the port.
#[inline]
pub unsafe fn write_port_u8(port: u16, value: u8) {
    unsafe { value.write_to_port(port) }
}

/// One-shot 16-bit port write. See [`read_port_u8`].
///
/// # Safety
///
/// The caller must own the port.
#[inline]
pub unsafe fn write_port_u16(port: u16, value: u16) {
    unsafe { value.write_to_port(port) }
}

/// One-shot 32-bit port write. See [`read_port_u8`].
///
/// # Safety
///
/// The caller must own the port.
#[inline]
pub unsafe fn write_port_u32(port: u16, value: u32) {
    unsafe { value.write_to_port(port) }
}

/// Wait for one I/O cycle to complete by issuing a dummy write to port 0x80.
///
/// The "port 0x80" trick is the canonical x86 way to insert a small delay
/// between back-to-back port accesses: writes to the POST debugging port are
/// guaranteed to take at least one ISA-bus cycle (~1 us on modern chips) and
/// have no other side effect. The 16550 UART and several legacy controllers
/// require this delay between a status read and the following data access.
#[inline]
pub fn io_wait() {
    // SAFETY: Port 0x80 is the POST debug port on all PC-compatible hardware;
    // writing 0 to it is the conventional no-op delay and has no side effect
    // beyond the bus cycle it consumes. The kernel owns this port by
    // convention.
    unsafe { write_port_u8(0x80, 0) }
}

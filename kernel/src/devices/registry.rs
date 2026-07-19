//! Kernel device registry.
//!
//! A central, name-keyed table of every device driver the kernel has brought
//! up: the serial UART, the framebuffer, the VGA text console, the PC
//! speaker, and (as later phases land them) the IOAPIC, HPET, PCI enumerator,
//! and block/input drivers. Each driver registers itself under a stable
//! string name during its `init`; the rest of the kernel looks drivers up by
//! that name when it needs to drive them.
//!
//! # Why a registry
//!
//! Xenith is deliberately monolithic, but the device layer still benefits
//! from a single discovery point:
//!
//! * **Decoupling**: a subsystem that wants to beep (e.g. a panic handler
//!   emitting a fault blip) does not `use crate::devices::pcspk` directly —
//!   it asks the registry for `"pcspk"` and beeps if present. That keeps the
//!   caller compilable when the beeper is absent (e.g. on a headless server
//!   SKU with no speaker gate).
//! * **Enumeration**: a "list devices" diagnostic (the shell's `lsdev`
//!   command, a sysfs-style `/sys/devices` later) walks the registry once
//!   rather than each driver maintaining its own static.
//! * **Bring-up ordering**: `devices::init` registers each driver in the
//!   order it was brought up, so the registry doubles as a record of the
//!   device-init sequence — useful when diagnosing "why did the HPET not come
//!   up?" by inspecting what *did* register.
//!
//! # Type erasure and downcasting
//!
//! Every driver implements the [`Device`] trait, which is `Device: Any`. The
//! registry stores entries as `Kbox<dyn Device>`, and [`DeviceRegistry::lookup`]
//! returns a [`DeviceRef`] that borrows the device. A caller that knows the
//! concrete type can downcast with [`DeviceRef::downcast_ref`] (or the
//! convenience [`DeviceRegistry::lookup_as`]) to recover the original `&T`
//! and call type-specific methods (e.g. `SerialPort::send`). This mirrors
//! `core::any::Any`'s downcast model and avoids a per-driver vtable explosion.
//!
//! # Concurrency
//!
//! The registry is a `SpinLock<KVec<...>>`. Registration happens during
//! single-threaded boot, so the lock is uncontended in practice, but the
//! spinlock keeps lookups from racing a late registration on an AP. Lookups
//! by name are O(n) in the number of devices — fine for the tens of drivers
//! a kernel registers, and preferable to a hash map that would pull in a
//! hasher and a larger allocation for no real win at this scale.
//!
//! A [`DeviceRef`] holds the spinlock guard for its whole lifetime, so a
//! caller that pulls a device out and then drives it does so while holding
//! the registry lock. That is acceptable for the short, infrequent trips the
//! registry is designed for (a beep, a status read); callers that need to
//! hold a device across a long operation should cache the concrete `&'static`
//! pointer obtained once at boot rather than re-looking-up on every use.
//!
//! # Allocation
//!
//! The registry heap-allocates each entry's name (`KString`) and device
//! handle (`Kbox<dyn Device>`), so it requires the kernel heap to be up
//! ([`crate::mm::init`]). Drivers that must register before the heap (the
//! serial console, the framebuffer) are *not* required to go through the
//! registry: they expose their own `static` singletons (e.g.
//! [`crate::devices::serial::COM1`]) for very-early use, and register with
//! this table later in `devices::init` once the heap is live. As with the
//! rest of the kernel, allocation failure aborts via the global allocator's
//! OOM handler rather than being returned as a `Result` — the registry is
//! only fed once, at boot, when the heap is fresh and unfragmented.

use core::any::Any;
use core::ops::Deref;

use crate::mm::{KString, KVec, Kbox};
use crate::sync::{SpinLock, SpinLockGuard};

// ---------------------------------------------------------------------------
// Device trait
// ---------------------------------------------------------------------------

/// A device driver registered with the kernel.
///
/// The trait is intentionally minimal: a stable [`name`](Device::name), a
/// human-readable [`kind`](Device::kind) for diagnostics, and an optional
/// [`init`](Device::init) hook called once at registration time. Everything
/// else a driver does is exposed through its concrete type, recovered via
/// [`DeviceRef::downcast_ref`] or [`DeviceRegistry::lookup_as`].
///
/// The supertrait `Any` is what makes downcasting work: every `impl Device`
/// carries a `TypeId`, so a `&dyn Device` can be upcast to `&dyn Any` and
/// narrowed back to the concrete driver type. Drivers that are `?Sized`
/// cannot implement `Any` (the trait requires `Self: 'static`), so `Device`
/// requires `Sized`.
///
/// `Device` is `'static` (implied by `Any`) so registry entries can outlive
/// any borrow that produced them — a driver registered at boot lives for the
/// kernel's whole lifetime.
pub trait Device: Any + Send + Sync {
    /// The stable name this device is registered under, e.g. `"com1"` or
    /// `"pcspk"`. Lowercase ASCII by convention; looked up case-sensitively
    /// by [`DeviceRegistry::lookup`].
    ///
    /// Returning a `&'static str` (rather than owning a `KString`) keeps the
    /// trait object free of allocations and lets a driver declare its name
    /// as a `const` literal.
    fn name(&self) -> &'static str;

    /// A short human-readable kind label for diagnostics, e.g.
    /// `"16550 UART"` or `"PC speaker"`. Surfaced by `lsdev`-style
    /// enumerations. Distinct from [`name`](Device::name) so a driver can
    /// report a model-specific label without changing its lookup key.
    fn kind(&self) -> &'static str;

    /// One-time initialisation hook invoked by [`DeviceRegistry::register`]
    /// immediately after the device is added to the table.
    ///
    /// The default implementation is a no-op: most drivers perform their
    /// hardware bring-up in their own module `init` before registering, so
    /// by the time they reach the registry the hardware is already
    /// configured. Override this for drivers that prefer to defer bring-up
    /// to registration time (e.g. a PCI device that needs the enumerator's
    /// BAR assignment before it can init).
    fn init(&mut self) {}
}

// ---------------------------------------------------------------------------
// Registered entry
// ---------------------------------------------------------------------------

/// A device plus its registered name, as stored in the registry.
///
/// The name is duplicated here as an owned `KString` even though
/// [`Device::name`] returns a `&'static str`, so that diagnostic code can
/// iterate the registry and print every name without going through the
/// trait object (which would require a `&self` borrow on each device). The
/// duplication is a few bytes per entry and keeps the enumeration path
/// cheap.
struct Entry {
    /// The owned, heap-allocated name. Equal to `device.name()` at
    /// registration time.
    name: KString,
    /// The device itself, type-erased.
    device: Kbox<dyn Device>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The global device registry.
///
/// A single instance lives in [`REGISTRY`] and is reached through
/// [`register`], [`lookup`], [`lookup_as`], and [`iter_names`]. The interior
/// `SpinLock<KVec<Entry>>` makes every operation safe to call from any CPU;
/// registration is serialised so two concurrent `register` callers do not
/// race the `Vec` push, and lookups take a guard so a lookup never observes
/// a half-pushed entry.
pub struct DeviceRegistry {
    entries: SpinLock<KVec<Entry>>,
}

impl DeviceRegistry {
    /// Construct an empty registry. `const`-constructible so the global
    /// [`REGISTRY`] can be declared without an `init_in_place` step.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: SpinLock::new(KVec::new()),
        }
    }

    /// Register `device` under `name`.
    ///
    /// Calls `device.init()` after inserting the entry, so a driver's
    /// `init` hook runs with the device already discoverable by name. If a
    /// device is already registered under `name`, the new one replaces it:
    /// the old `Kbox` is dropped (running the driver's `Drop` if any), and
    /// the new one takes its slot. Re-registration is the mechanism a
    /// hot-replug path would use to swap a failed device for a fresh one.
    ///
    /// Allocation (the name `KString` and the `Vec` push) is infallible:
    /// the kernel's global allocator aborts on OOM, matching the rest of
    /// the device layer. The registry is only fed once at boot when the
    /// heap is fresh, so OOM here indicates a heap sizing bug rather than a
    /// runtime condition worth returning as a `Result`.
    pub fn register(&self, name: &str, device: Kbox<dyn Device>) {
        let mut entries = self.entries.lock();

        // Replace an existing entry with the same name rather than appending
        // a duplicate, so `lookup` never has to disambiguate. The old device
        // is dropped here via the `Kbox` assignment.
        if let Some(slot) = entries.iter_mut().find(|e| e.name.as_str() == name) {
            slot.name = KString::from(name);
            slot.device = device;
            // Run the init hook on the freshly installed device. The
            // assignment above moved it back into the slot, so re-borrow.
            slot.device.init();
            ::log::debug!("devices: re-registered '{}'", name);
            return;
        }

        let entry = Entry {
            name: KString::from(name),
            device,
        };
        entries.push(entry);
        // The push moved the `Kbox`; re-borrow the last entry to call init.
        let last = entries.last_mut().expect("just pushed");
        last.device.init();
        ::log::debug!("devices: registered '{}'", name);
    }

    /// Look up a device by name, returning a borrow that holds the registry
    /// lock for its lifetime.
    ///
    /// The returned [`DeviceRef`] keeps the registry's spinlock guard alive
    /// until it is dropped, so the `&dyn Device` inside stays valid for as
    /// long as the caller holds the `DeviceRef`. Callers that need a
    /// driver's concrete type should call [`lookup_as`](Self::lookup_as) or
    /// [`DeviceRef::downcast_ref`].
    ///
    /// Returns `None` if no device is registered under `name`.
    #[must_use]
    pub fn lookup<'a>(&'a self, name: &str) -> Option<DeviceRef<'a>> {
        let entries = self.entries.lock();
        let idx = entries.iter().position(|e| e.name.as_str() == name)?;

        // The device reference borrows memory reached through the guard, and
        // the guard must move into the returned `DeviceRef` alongside the
        // reference — a self-referential shape the borrow checker rejects.
        // We break the self-reference by capturing a raw pointer (no
        // lifetime) and carrying the guard separately, then re-bless the
        // pointer as `&'a dyn Device` once the guard is owned by the
        // `DeviceRef` for `'a`. See `DeviceRef::device` for the safety case.
        let device_ptr: *const dyn Device = entries[idx].device.as_ref();

        // Extend the guard's lifetime to `'a`. The guard borrows `self.entries`
        // (a `&'a SpinLock`); `self: &'a Self` guarantees that borrow is valid
        // for `'a`, so widening the guard's lifetime parameter from the
        // method's anonymous reborrow to `'a` is sound.
        //
        // SAFETY: `SpinLockGuard<'x, T>` is covariant in `'x` (it holds a
        // `&'x SpinLock<T>` and the atomic lock state is owned, not borrowed).
        // The actual borrow captured by the guard is `&'a SpinLock<...>` from
        // `self`, which outlives `'a`, so the transmute only relaxes the
        // anonymous reborrow lifetime up to the true `'a` — no use-after-free.
        let guard: SpinLockGuard<'a, KVec<Entry>> = unsafe {
            core::mem::transmute::<SpinLockGuard<'_, KVec<Entry>>, SpinLockGuard<'a, KVec<Entry>>>(
                entries,
            )
        };

        Some(DeviceRef { guard, device_ptr })
    }

    /// Look up a device by name and downcast it to a concrete type `T`.
    ///
    /// Returns `Some(&T)` if a device named `name` is registered and its
    /// concrete type is `T`; `None` otherwise (including the case where the
    /// name exists but the type does not match). This is the primary way
    /// subsystems recover a driver's specific API from the registry.
    ///
    /// The returned reference's lifetime is tied to the [`DeviceRef`] guard
    /// produced internally, which the caller drops at the end of the
    /// statement — so the borrow is only valid within the expression that
    /// calls `lookup_as`. For long-lived access, cache the concrete
    /// `&'static` pointer obtained once at boot instead.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::devices::pcspk;
    /// if let Some(spk) = crate::devices::registry::lookup_as::<pcspk::PcSpeaker>("pcspk") {
    ///     spk.beep(880, 200);
    /// }
    /// ```
    #[must_use]
    pub fn lookup_as<'a, T: Device>(&'a self, name: &str) -> Option<&'a T> {
        let entry = self.lookup(name)?;
        // Upcast &dyn Device -> &dyn Any is a stable trait-upcasting coercion
        // on the toolchain Xenith targets (nightly >= 1.86), so `downcast_ref`
        // is reachable without an explicit feature gate.
        downcast_device::<T>(entry.device())
    }

    /// The number of registered devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Whether a device is currently registered under `name`.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.lock().iter().any(|e| e.name.as_str() == name)
    }

    /// Snapshot the names of every registered device, in registration order.
    ///
    /// Allocates a `KVec<KString>` so the caller can iterate the names
    /// without holding the registry lock. Intended for `lsdev`-style
    /// diagnostics; returns an empty vector if the registry is empty.
    #[must_use]
    pub fn names(&self) -> KVec<KString> {
        let entries = self.entries.lock();
        let mut out = KVec::new();
        for e in entries.iter() {
            // Allocation failure here aborts via the global OOM handler; for
            // a diagnostic path that is acceptable, and it never happens in
            // practice because the name count is tiny.
            out.push(KString::from(e.name.as_str()));
        }
        out
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DeviceRef — a borrow of a device that keeps the registry locked
// ---------------------------------------------------------------------------

/// A borrowed reference to a registered device.
///
/// Produced by [`DeviceRegistry::lookup`], this wrapper holds the registry's
/// spinlock guard for the lifetime of the borrow, so the device reference
/// inside stays valid. The guard is released when the `DeviceRef` is dropped.
///
/// The device is reached through a raw pointer captured at lookup time (see
/// [`DeviceRegistry::lookup`] for why) and re-blessed as `&'a dyn Device` on
/// each access. Downcast through [`DeviceRef::downcast_ref`] to reach a
/// driver's concrete type; most callers should prefer
/// [`DeviceRegistry::lookup_as`] which combines the two steps.
pub struct DeviceRef<'a> {
    /// The spinlock guard, dropped when this `DeviceRef` drops. Kept private
    /// so callers cannot accidentally drop it early and dangle `device_ptr`.
    #[allow(dead_code)]
    guard: SpinLockGuard<'a, KVec<Entry>>,
    /// Raw pointer to the trait object inside the guarded `Kbox<dyn Device>`.
    /// Valid for `'a` because `guard` keeps the registry locked and `Kbox`'s
    /// heap allocation is stable (a `Box` never moves its heap content once
    /// allocated, and no mutation can occur while the lock is held).
    device_ptr: *const dyn Device,
}

impl<'a> DeviceRef<'a> {
    /// The borrowed device as `&'a dyn Device`.
    ///
    /// SAFETY (internal): `device_ptr` was captured from `entries[idx].device`
    /// while the registry lock was held. The `guard` field keeps that lock
    /// held for `'a`, so the `KVec<Entry>` — and the `Kbox<dyn Device>` it
    /// owns — remain at their original addresses for the whole of `'a`. A
    /// `Box<dyn Device>` stores its trait object on the heap at a stable
    /// address (the Box's pointer never moves while the Box lives), and the
    /// Box lives as long as the `Entry` lives, which lives as long as the
    /// `KVec` lives, which lives as long as the lock is held. Hence the
    /// pointer is valid for `'a` and the reborrow is sound.
    #[inline]
    #[must_use]
    pub fn device(&self) -> &'a dyn Device {
        // SAFETY: see the method's safety comment — the guard outlives 'a
        // and the pointed-to trait object is heap-stable for that span.
        unsafe { &*self.device_ptr }
    }

    /// Downcast the borrowed device to a concrete type `T`.
    ///
    /// Returns `Some(&'a T)` if the concrete type matches, `None` otherwise.
    /// Uses `core::any::Any::downcast_ref` via the trait-upcasting coercion
    /// from `&dyn Device` to `&dyn Any`.
    #[must_use]
    pub fn downcast_ref<T: Device>(&self) -> Option<&'a T> {
        downcast_device::<T>(self.device())
    }
}

fn downcast_device<T: Device>(device: &dyn Device) -> Option<&T> {
    if device.type_id() != core::any::TypeId::of::<T>() {
        return None;
    }
    // SAFETY: the TypeId equality above proves that the trait object's data
    // pointer was created from a T. The returned borrow is tied to `device`.
    Some(unsafe { &*(device as *const dyn Device as *const T) })
}

impl<'a> Deref for DeviceRef<'a> {
    type Target = dyn Device;
    fn deref(&self) -> &Self::Target {
        self.device()
    }
}

// ---------------------------------------------------------------------------
// Global registry and free-function convenience wrappers
// ---------------------------------------------------------------------------

/// The single kernel-wide device registry.
///
/// Declared `static` and `const`-constructed; first touched by
/// `devices::init` once the heap is up. Free functions [`register`],
/// [`lookup`], [`lookup_as`], [`iter_names`], and [`contains`] operate on
/// this instance so callers do not have to name `REGISTRY` at every site.
pub static REGISTRY: DeviceRegistry = DeviceRegistry::new();

/// Register `device` under `name` in the global [`REGISTRY`].
pub fn register(name: &str, device: Kbox<dyn Device>) {
    REGISTRY.register(name, device)
}

/// Look up a device by name in the global [`REGISTRY`].
#[must_use]
pub fn lookup(name: &str) -> Option<DeviceRef<'static>> {
    REGISTRY.lookup(name)
}

/// Look up and downcast a device in the global [`REGISTRY`].
#[must_use]
pub fn lookup_as<T: Device>(name: &str) -> Option<&'static T> {
    REGISTRY.lookup_as::<T>(name)
}

/// Whether a device is registered under `name` in the global [`REGISTRY`].
#[must_use]
pub fn contains(name: &str) -> bool {
    REGISTRY.contains(name)
}

/// A snapshot of every registered device name, in registration order.
#[must_use]
pub fn iter_names() -> KVec<KString> {
    REGISTRY.names()
}

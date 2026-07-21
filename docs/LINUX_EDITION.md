# Xenith Linux Edition

Xenith has two deliberately separate operating-system tracks:

1. **Xenith Native** keeps the repository's freestanding Rust kernel,
   bootloader, syscall ABI, drivers, emulator, and native validation gates.
2. **Xenith Linux Edition** uses an unmodified or explicitly patched upstream
   Linux kernel beneath Xenith userspace, desktop, applications, and product
   identity. Linux supplies its mature hardware, storage, filesystem,
   networking, input, audio, graphics, and power-management foundations.

The Linux edition is the route to broad real-world compatibility. It does not
replace the native kernel, and Linux drivers are never pasted into the native
kernel.

## Canonical upstream pin

The machine-readable authority is
[`distribution/linux/reference.lock.toml`](../distribution/linux/reference.lock.toml).
The canonical WSL reference checkout is pinned to exactly:

| Field | Value |
| --- | --- |
| Official remote | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` |
| Commit | `b95f03f04d475aa6719d15a636ddf32222d55657` |
| Release identity | Linux `7.2-rc4` |
| Kernel license | `GPL-2.0-only` |

The WSL checkout is an external, disposable reference and build input. The
Linux source tree is not vendored into this repository. Builds must reject a
checkout whose `HEAD`, remote URL, or version identity differs from the lock.
Moving the pin requires a reviewed lock-file change and a complete Linux
edition rebuild and runtime validation pass; a floating branch such as
`master` or `latest` is never a release input.

## Architecture boundary

```text
Xenith Native                         Xenith Linux Edition
-------------                         ---------------------
bootloader/                           Linux firmware/boot path
kernel/                               pinned upstream Linux kernel
xenith-abi + libuser                  Linux UAPI platform backend
        |                                      |
        +---------- shared pure cores --------+
                    desktop renderer/state
                    compositor policy/protocol
                    Files model/renderer
                    Xenith visual identity
```

The existing code already provides useful seams:

- `user/desktop/src/lib.rs` contains allocation-free rendering, layout, input,
  damage, and compositor policy without framebuffer syscalls.
- `user/explorer/src/lib.rs` contains the Files state and renderer without OS
  syscalls.
- `user/libwindow` separates compositor protocol state from its transport.

Linux-specific runtimes should wrap these cores rather than fork their UI
logic. The intended lightweight backend uses Linux DRM/KMS for scanout, evdev
for input, epoll for readiness, and Unix sockets plus memfd-backed buffers for
client transport. Later acceleration may use GBM/EGL without changing the
application protocol.

## Strict GPL boundary

The following rules are mandatory engineering policy:

- No Linux source, internal header, generated kernel object, or derived driver
  implementation may be added below `kernel/`, `bootloader/`, `emu/`,
  `crates/`, or the native userspace runtime.
- The native kernel must not link Linux objects or implement a general shim for
  Linux's unstable in-kernel driver APIs.
- Linux source remains in an external WSL checkout or ignored build cache.
- Any Xenith patch to the Linux kernel belongs only under the Linux
  distribution boundary, carries an appropriate SPDX identifier, and is
  distributed as `GPL-2.0-only`.
- Linux userspace code may use exported UAPI at the syscall boundary. Internal
  kernel headers and private kernel ABI are not a userspace portability layer.
- A Linux edition release must ship or otherwise provide the exact
  corresponding Linux source, Xenith patches, kernel configuration, license
  texts, and reproducible build instructions for the released kernel binary.
- Native and Linux artifacts must never be combined under one ambiguous
  license or edition label. Every release manifest identifies the edition,
  kernel provenance, configuration, and hashes.

This boundary protects both projects: Xenith Native retains its declared
MIT/Apache-2.0 codebase, while the Linux kernel and any kernel-derived changes
are handled under GPL-2.0-only. It is a repository policy, not a substitute for
legal review before public distribution.

## Support priorities

Implementation is ordered by end-user impact:

1. Boot the pinned kernel and a minimal Xenith initramfs under VMware and QEMU
   through separately tested UEFI and legacy-BIOS paths.
2. Enable common VM and PC foundations: ACPI, PCI/PCIe, AHCI, NVMe, virtio,
   xHCI, USB HID/storage, e1000-class and modern Ethernet adapters, and a DRM
   framebuffer path.
3. Add the Linux platform backend and run the existing Xenith desktop core on
   DRM/KMS and evdev without an idle polling loop.
4. Run Files through Linux filesystem calls and preserve Xenith's standard
   user-folder policy on persistent storage.
5. Add device hotplug, networking, ALSA audio, display mode/hotplug handling,
   suspend/resume, and recovery behavior.
6. Add a deliberately selected lightweight system-service set and an
   installer/update path with rollback.
7. Offer Wine/Proton as an optional Windows-application compatibility layer;
   keep the native `xenith-winhost` work as an independent conformance project.
8. Gate releases on a published physical-hardware matrix as well as VM tests.

Native Xenith development continues independently. Its highest-value hardware
work remains a controller-independent block layer, PCI ECAM/MSI-X, virtio,
NVMe, USB hubs/mass storage/generic HID, audible HDA playback, IPv6, and
physical-device validation.

## Artifact and CI separation

The existing native outputs remain authoritative:

- `build/xenith.iso`
- `build/xenith.img`

Linux edition outputs are reserved below a separate directory:

- `build/linux/xenith-linux.iso`
- `build/linux/xenith-linux.img`
- `build/linux/source/` for the release's corresponding-source bundle

Native CI must build and test without a Linux checkout. Linux CI has independent
pin/provenance, configuration, build, license, UEFI boot, BIOS boot, desktop,
storage, network, and hardware-matrix gates. A passing Linux job cannot mask a
native regression, and a native pass cannot be presented as Linux-edition
hardware proof.

## Honest non-goals

- No operating system can promise every device, firmware, application, or
  hardware combination. Support claims require an exact tested matrix.
- The Linux edition does not make arbitrary Windows kernel drivers work.
- Wine/Proton does not guarantee every Windows application, anti-cheat system,
  DRM scheme, installer, or kernel-dependent program.
- A Linux source checkout alone adds no support to the current native ISO.
- The project will not recreate the complete Linux internal driver API inside
  Xenith Native.
- The project will not copy Linux implementation code into native drivers to
  avoid writing native subsystem contracts.
- Linux edition milestones do not prove physical compatibility until the
  released artifact is tested on named physical systems.

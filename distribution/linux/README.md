# Xenith Linux Distribution Boundary

This directory owns the reproducible metadata, configuration, patches,
root-filesystem recipes, packaging, and validation policy for **Xenith Linux
Edition**. It does not contain a vendored Linux source tree.

The canonical WSL reference is locked by
[`reference.lock.toml`](reference.lock.toml):

```text
remote  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
commit  b95f03f04d475aa6719d15a636ddf32222d55657
version Linux 7.2-rc4
license GPL-2.0-only
```

An external checkout may be created in WSL with the official remote and then
detached at the locked commit. Its location is intentionally not encoded here:
developer paths are local state, while the remote and commit are reproducible
project state. Before any build, automation must verify the remote, full
40-character `HEAD`, and release identity against the lock.

## Allowed contents

Future additions may include:

- minimal and hardware-coverage kernel configuration fragments;
- GPL-2.0-only Xenith kernel patches with SPDX identifiers;
- initramfs and persistent-root manifests;
- deterministic build and image-packaging scripts;
- corresponding-source and license packaging rules;
- VM and physical-hardware test manifests.

Do not add a Linux source checkout, copied Linux drivers, generated kernel
objects, release images, unpinned downloads, or native Xenith kernel code here.
Linux implementation material must never be copied into `kernel/` or linked
into the native kernel.

## Expected output boundary

```text
build/xenith.iso                    native Xenith ISO
build/xenith.img                    native Xenith raw image
build/linux/xenith-linux.iso        Linux edition ISO
build/linux/xenith-linux.img        Linux edition raw image
build/linux/source/                 exact corresponding-source release bundle
```

Linux edition CI is independent from native CI. It must validate the locked
source, configuration, GPL material, kernel build, both firmware paths,
desktop startup, storage, networking, shutdown/reboot, and the declared
hardware matrix. Release metadata must include the lock, kernel config,
patches, toolchain identity, artifact hashes, and license texts.

## Current state

This directory currently establishes provenance and policy only. It does not
claim that a Linux edition image has been built, booted, or hardware-tested.
See [`docs/LINUX_EDITION.md`](../../docs/LINUX_EDITION.md) for the architecture,
priorities, licensing boundary, artifact split, and non-goals.

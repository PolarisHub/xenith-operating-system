# `boot/limine/` — Limine bootloader binaries

This directory holds the Limine bootloader binaries that `scripts/make-iso.sh`
copies into the ISO image and that `scripts/run-qemu.sh` (and real-hardware
USB boot) rely on. The binaries are **not** checked into the Xenith repository
— they are downloaded from the upstream Limine release branch into this
directory by each contributor before building an ISO.

## Target version

Xenith targets the **Limine v8.x** line. The boot info structures used by
`crates/xenith-boot` are ABI-stable within a major version, so any v8.x
release is binary-compatible with the kernel's `limine` crate dependency
(pinned to `limine = "0.3"` in the workspace manifest, which maps to the
v8 protocol).

The currently pinned release is:

  **v8.7.0** (the last v8.x release on the upstream `limine-bootloader/limine`
  GitHub).

When bumping the version, update the URL below, re-download the binaries,
and rebuild the ISO. The kernel's `limine` crate version does not need to
change for patch-level bumps within v8.x.

## What to download

Limine ships prebuilt binaries on a separate `-binary` branch per release
tag (the source tarballs on the release page do not contain compiled
artifacts). For v8.7.0 the binary branch is:

  `https://github.com/limine-bootloader/limine/tree/v8.7.0-binary`

You need these files from that branch placed in this directory:

| File              | Purpose                                                  |
|-------------------|----------------------------------------------------------|
| `limine-bios.sys` | BIOS-stage 2 loader loaded by the BIOS boot sector.      |
| `limine-bios-cd.bin` | BIOS El Torito boot image for the ISO (boot catalog). |
| `limine-uefi-cd.bin` | UEFI El Torito boot image for the ISO (EFI image).    |
| `BOOTX64.EFI`     | 64-bit x86 UEFI loader (used for real-hardware USB boot).|
| `BOOTIA32.EFI`    | 32-bit x86 UEFI loader (some older 32-bit UEFI firmware).|

You also need the **`limine`** host tool (the unified CLI that replaces the
older `limine-deploy` binary). It is **not** on the `-binary` branch as a
prebuilt Linux binary; the branch ships `limine.exe` for Windows. For Linux
development hosts, build the tool from the source tarball:

```bash
# From the repository root.
curl -L -o /tmp/limine.tar.xz \
    https://github.com/limine-bootloader/limine/releases/download/v8.7.0/limine-8.7.0.tar.xz
tar -xf /tmp/limine.tar.xz -C /tmp
cd /tmp/limine-8.7.0
./configure
make -j"$(nproc)"
# Install the `limine` binary and the shared data files into a prefix you
# control, then either symlink it into this directory or add it to PATH.
sudo make install PREFIX=/opt/limine
```

After installation, the host tool is invoked as:

```bash
limine bios-install build/xenith.iso
```

This is the v8.x replacement for the older `limine-deploy <iso>` command;
`scripts/make-iso.sh` calls `limine bios-install`.

## Quick download (binary files only)

For contributors who only want to build an ISO and do not need to rebuild the
host tool from source (e.g. their distro ships `limine` >= 8.x, or they
already have it installed), the binary files can be fetched directly from the
`v8.7.0-binary` branch:

```bash
# From the repository root.
cd boot/limine
base="https://raw.githubusercontent.com/limine-bootloader/limine/v8.7.0-binary"
curl -L -O "${base}/limine-bios.sys"
curl -L -O "${base}/limine-bios-cd.bin"
curl -L -O "${base}/limine-uefi-cd.bin"
curl -L -O "${base}/BOOTX64.EFI"
curl -L -O "${base}/BOOTIA32.EFI"
```

## Directory layout after download

```
boot/limine/
    limine-bios.sys        # BIOS stage 2
    limine-bios-cd.bin     # BIOS El Torito image
    limine-uefi-cd.bin     # UEFI El Torito image
    BOOTX64.EFI            # x86_64 UEFI loader
    BOOTIA32.EFI           # i386 UEFI loader
    README.md              # this file
```

The host `limine` tool is expected to be on `PATH` (or at `LIMINE_TOOL`
if you set that environment variable — `scripts/make-iso.sh` honors it).

## Verification (optional but recommended)

Limine release tarballs are signed by the upstream maintainer. To verify the
source tarball before building the host tool:

```bash
gpg --keyserver hkps://keyserver.ubuntu.com \
    --recv-keys 6C222EA6B2BD216AA406516AC868F0B6DE38409D
gpg --verify limine-8.7.0.tar.xz.sig limine-8.7.0.tar.xz
```

The binary branch files are not individually signed; if reproducibility
matters, build the host tool from a verified source tarball and copy the
binaries out of the installed `share/limine/` directory instead of fetching
them from the raw branch.

## Upgrading

1. Pick a new v8.x tag (e.g. `v8.7.1`).
2. Re-download the five binary files from the new `-binary` branch.
3. Rebuild (or reinstall) the `limine` host tool from the matching source
   tarball so `limine bios-install` understands the new image format.
4. Re-run `scripts/make-iso.sh` and boot-test under QEMU before committing
   the updated binaries.

Do **not** mix binaries from different v8.x patch releases — the BIOS stage
2 and the host tool are versioned together, and a mismatch can produce an
ISO that boots on one machine but fails on another.

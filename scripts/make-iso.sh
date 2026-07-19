#!/usr/bin/env bash
#
# make-iso.sh — Build a bootable Xenith ISO image.
#
# This script:
#   1. Builds the kernel (and, when available, the userspace initramfs) via
#      the workspace cargo aliases.
#   2. Assembles an ISO root directory (iso_root/) containing the kernel
#      binary, the Limine config, the Limine BIOS/UEFI boot images, and the
#      EFI System Partition tree.
#   3. Calls xorriso to produce a hybrid BIOS/UEFI bootable ISO.
#   4. Calls `limine bios-install` to install the Limine BIOS boot code onto
#      the ISO image so it boots on real BIOS firmware.
#
# The resulting image is written to build/xenith.iso and is suitable for both
# QEMU (scripts/run-qemu.sh) and `dd` to a USB stick for real hardware
# (see docs/RUNNING.md).
#
# Requirements (see boot/limine/README.md for download instructions):
#   - cargo (nightly, pinned via rust-toolchain.toml)
#   - xorriso
#   - limine >= 8.x host tool on PATH (or at $LIMINE_TOOL)
#
# Usage:
#   scripts/make-iso.sh             # debug kernel, no initramfs
#   scripts/make-iso.sh --release   # release kernel
#   scripts/make-iso.sh --initramfs # also pack build/initramfs if present
#   PROFILE=release scripts/make-iso.sh --initramfs
#
# Exit codes:
#   0  ISO written to build/xenith.iso
#   1  missing dependency or build failure
#   2  limine bios-install failed
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repository root so the script works no matter where it is
# invoked from. We resolve the script's own directory and walk up to the
# workspace root (the directory containing Cargo.toml with a [workspace]
# table).
# ---------------------------------------------------------------------------
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}"

# ---------------------------------------------------------------------------
# Configuration. All paths are relative to the repo root.
# ---------------------------------------------------------------------------
# Output directory and image name. `build/` is the conventional artifact
# root for Xenith; QEMU and the docs both expect build/xenith.iso.
build_dir="${repo_root}/build"
iso_out="${build_dir}/xenith.iso"

# Staging directory for the ISO filesystem. This is recreated on every run
# so stale files from a previous build can never leak into the new image.
iso_root="${build_dir}/iso_root"

# Limine binaries live in boot/limine/ (see boot/limine/README.md). The
# scripts expect the five files documented there.
limine_dir="${repo_root}/boot/limine"
limine_conf="${repo_root}/limine.conf"

# The `limine` host tool. Allow overriding via LIMINE_TOOL for contributors
# who install it to a non-PATH prefix (e.g. /opt/limine/bin/limine).
limine_tool="${LIMINE_TOOL:-limine}"

# Cargo profile: "debug" by default, "release" when --release is passed or
# PROFILE=release is set in the environment. We use the workspace aliases
# `cargo kbuild` (debug) and `cargo kimage` (release) defined in
# .cargo/config.toml so the target triple and build-std flags are always
# correct.
profile="${PROFILE:-debug}"
pack_initramfs="no"

# ---------------------------------------------------------------------------
# Parse command-line flags.
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --release)
            profile="release"
            ;;
        --debug)
            profile="debug"
            ;;
        --initramfs)
            pack_initramfs="yes"
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "make-iso.sh: unknown flag: ${arg}" >&2
            echo "usage: $0 [--release|--debug] [--initramfs] [--help]" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks: verify every external dependency is present before
# doing any work. Failing early with a clear message is much friendlier
# than a cryptic xorriso or cargo error halfway through.
# ---------------------------------------------------------------------------
check_dep() {
    local dep="$1"
    if ! command -v "${dep}" >/dev/null 2>&1; then
        echo "make-iso.sh: missing required tool: ${dep}" >&2
        echo "  install it and ensure it is on PATH" >&2
        return 1
    fi
}

check_dep cargo
check_dep xorriso
# The limine tool may be overridden via LIMINE_TOOL, so only check the
# default name when the override is not in effect.
if [ "${limine_tool}" = "limine" ]; then
    check_dep limine
fi

# Verify the Limine binary files are present. These are downloaded manually
# (see boot/limine/README.md) and are the most commonly forgotten piece.
missing_limine=()
for f in limine-bios.sys limine-bios-cd.bin limine-uefi-cd.bin BOOTX64.EFI; do
    if [ ! -f "${limine_dir}/${f}" ]; then
        missing_limine+=("${f}")
    fi
done
if [ "${#missing_limine[@]}" -gt 0 ]; then
    echo "make-iso.sh: missing Limine binaries in ${limine_dir}:" >&2
    for f in "${missing_limine[@]}"; do
        echo "  - ${f}" >&2
    done
    echo "  see boot/limine/README.md for download instructions" >&2
    exit 1
fi

if [ ! -f "${limine_conf}" ]; then
    echo "make-iso.sh: missing ${limine_conf}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build the kernel.
# ---------------------------------------------------------------------------
echo "==> Building kernel (profile: ${profile})"
if [ "${profile}" = "release" ]; then
    cargo kimage
    kernel_bin="${repo_root}/target/x86_64-xenith/release/kernel"
else
    cargo kbuild
    kernel_bin="${repo_root}/target/x86_64-xenith/debug/kernel"
fi

if [ ! -f "${kernel_bin}" ]; then
    # Some toolchains name the artifact `xenith` after the crate; fall back
    # to that name so a rename in kernel/Cargo.toml does not break the
    # script. We check both rather than guessing.
    crate_name="${repo_root}/target/x86_64-xenith/${profile}/xenith"
    if [ -f "${crate_name}" ]; then
        kernel_bin="${crate_name}"
    else
        echo "make-iso.sh: kernel binary not found at ${kernel_bin}" >&2
        echo "  (also checked ${crate_name})" >&2
        exit 1
    fi
fi

echo "    kernel: ${kernel_bin}"

# ---------------------------------------------------------------------------
# Optionally locate the initramfs. The user/ pipeline produces
# build/initramfs; we only pack it when --initramfs is passed AND the file
# exists, so a missing initramfs never breaks a plain kernel-only ISO build.
# ---------------------------------------------------------------------------
initramfs_src=""
if [ "${pack_initramfs}" = "yes" ]; then
    initramfs_src="${build_dir}/initramfs"
    if [ ! -f "${initramfs_src}" ]; then
        echo "make-iso.sh: --initramfs given but ${initramfs_src} not found" >&2
        echo "  build the initramfs first (see user/README.md)" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Assemble the ISO root filesystem.
#
# Layout (what the firmware and Limine see):
#   /boot/xenith              kernel ELF binary
#   /boot/initramfs           userspace initramfs (optional)
#   /boot/limine/limine.conf  boot config (scanned here first by Limine)
#   /boot/limine/limine-bios.sys  BIOS stage 2 (loaded by the boot sector)
#   /limine-bios-cd.bin       BIOS El Torito boot image (referenced by -b)
#   /limine-uefi-cd.bin       UEFI El Torito boot image (referenced by --efi-boot)
#   /EFI/BOOT/BOOTX64.EFI     x86_64 UEFI loader
#   /EFI/BOOT/BOOTIA32.EFI    i386 UEFI loader (if present)
#
# limine-bios.sys and limine.conf must be in the root, /limine, /boot, or
# /boot/limine — we use /boot/limine so the boot tree is self-contained.
# The El Torito images can live anywhere; we put them at the ISO root so
# the xorriso -b / --efi-boot relative paths are short and stable.
# ---------------------------------------------------------------------------
echo "==> Assembling ISO root at ${iso_root}"
rm -rf "${iso_root}"
mkdir -p "${iso_root}/boot/limine"
mkdir -p "${iso_root}/EFI/BOOT"

# Kernel and (optional) initramfs.
cp "${kernel_bin}" "${iso_root}/boot/xenith"
if [ -n "${initramfs_src}" ]; then
    cp "${initramfs_src}" "${iso_root}/boot/initramfs"
    echo "    initramfs: ${initramfs_src}"
fi

# Limine config and BIOS stage 2 in /boot/limine (the first scan path).
cp "${limine_conf}" "${iso_root}/boot/limine/limine.conf"
cp "${limine_dir}/limine-bios.sys" "${iso_root}/boot/limine/limine-bios.sys"

# El Torito boot images at the ISO root.
cp "${limine_dir}/limine-bios-cd.bin" "${iso_root}/limine-bios-cd.bin"
cp "${limine_dir}/limine-uefi-cd.bin" "${iso_root}/limine-uefi-cd.bin"

# UEFI loaders into the ESP tree.
cp "${limine_dir}/BOOTX64.EFI" "${iso_root}/EFI/BOOT/BOOTX64.EFI"
if [ -f "${limine_dir}/BOOTIA32.EFI" ]; then
    cp "${limine_dir}/BOOTIA32.EFI" "${iso_root}/EFI/BOOT/BOOTIA32.EFI"
fi

# ---------------------------------------------------------------------------
# Build the ISO with xorriso.
#
# We invoke xorriso in mkisofs-compatibility mode (-as mkisofs) so the flags
# match the well-documented mkisofs/genisoimage syntax. The key flags:
#
#   -R -r                  Rock Ridge extensions with relaxed filenames.
#   -J                     Joliet extensions for Windows hosts.
#   -b <path>              BIOS El Torito boot image (no-emulation mode).
#   -no-emul-boot          The BIOS image is not a floppy emulation image.
#   -boot-load-size 4      Load 4 512-byte sectors (2048 bytes) of the boot
#                          image — the documented Limine value.
#   -boot-info-table       Patch a boot info table into the BIOS image so
#                          BIOS firmware can find the ISO.
#   --efi-boot <path>      UEFI El Torito boot image.
#   -efi-boot-part         Mark the EFI boot image as a partition.
#   --efi-boot-image       Use the EFI image as the EFI boot image.
#   --protective-msdos-label  Add a protective MBR so hybrid ISO/USB works.
#
# This produces a single image that boots under both legacy BIOS and UEFI,
# and is also directly `dd`-able to a USB stick (hybrid).
# ---------------------------------------------------------------------------
echo "==> Building ISO with xorriso"
mkdir -p "${build_dir}"
xorriso -as mkisofs \
    -R -r -J \
    -b limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image \
    --protective-msdos-label \
    "${iso_root}" \
    -o "${iso_out}"

# ---------------------------------------------------------------------------
# Install the Limine BIOS boot code onto the generated image.
#
# xorriso only lays out the El Torito boot catalog; it does not write the
# Limine BIOS stage-1 boot sector into the image's first sector. `limine
# bios-install` does that, patching the MBR/VBR so BIOS firmware chains to
# limine-bios.sys on the ISO. Without this step the ISO will boot under
# UEFI (via BOOTX64.EFI) but fail under legacy BIOS.
# ---------------------------------------------------------------------------
echo "==> Installing Limine BIOS boot code"
if ! "${limine_tool}" bios-install "${iso_out}"; then
    echo "make-iso.sh: limine bios-install failed" >&2
    echo "  ensure ${limine_tool} is Limine v8.x (run '${limine_tool} --version')" >&2
    exit 2
fi

echo "==> Done: ${iso_out}"
echo "    boot it with: scripts/run-qemu.sh"
echo "    or write to USB: dd if=${iso_out} of=/dev/sdX bs=4M conv=fsync"

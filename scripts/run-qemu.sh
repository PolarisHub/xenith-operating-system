#!/usr/bin/env bash
#
# run-qemu.sh — Boot the Xenith ISO under QEMU.
#
# This is the primary developer loop: run `scripts/make-iso.sh` then
# `scripts/run-qemu.sh`. The script boots build/xenith.iso with QEMU and
# connects the kernel's serial console to the terminal so log::info! /
# log::debug! output is visible immediately.
#
# QEMU flags:
#   -enable-kvm           Use KVM hardware virtualization when available.
#                         Falls back to TCG (software emulation) if the host
#                         lacks KVM or /dev/kvm is not accessible, so the
#                         script still works inside VMs and on non-Linux
#                         hosts (see the -accel fallback below).
#   -smp 2                Two vCPUs. Xenith is SMP-capable (the sched module
#                         brings up APs via the LAPIC); booting with one CPU
#                         would hide APIC and IPI bugs.
#   -m 512M               512 MiB of RAM. Enough for the kernel + a small
#                         heap + the initramfs; small enough to fit in L2
#                         cache on most dev machines for fast boots.
#   -serial stdio         Route the first serial port (COM1, 0x3F8) to the
#                         terminal. The kernel's serial console writes here.
#   -no-reboot            On triple-fault or kernel panic, QEMU would
#                         normally reboot the guest — which restarts the
#                         kernel and scrolls the failure off screen.
#                         -no-reboot makes QEMU exit instead so the error
#                         stays visible. The kernel's panic handler also
#                         calls hlt in a loop, but -no-reboot is the
#                         belt-and-braces guard.
#   -drive ...,format=raw  Attach the ISO as a raw drive. Using -drive
#                         (rather than -cdrom) lets us attach it as a
#                         hard disk, which is what Limine's BIOS boot code
#                         expects after `limine bios-install` patches the
#                         MBR. The ISO is hybrid (BIOS + UEFI) so this
#                         works for both boot modes.
#
# Usage:
#   scripts/run-qemu.sh                   # default flags
#   scripts/run-qemu.sh --no-kvm          # force TCG software emulation
#   scripts/run-qemu.sh --uefi            # boot via OVMF UEFI firmware
#   scripts/run-qemu.sh --release         # boot build/xenith-release.iso
#   MEM=2048 scripts/run-qemu.sh          # override guest RAM (MiB)
#   CPUS=4 scripts/run-qemu.sh            # override vCPU count
#   EXTRA_QEMU="-d int" scripts/run-qemu.sh   # append raw QEMU flags
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repo root and the ISO image.
# ---------------------------------------------------------------------------
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

# Default to the debug ISO; --release switches to the release ISO. Both are
# produced by scripts/make-iso.sh (the script always writes build/xenith.iso;
# the convention is that you re-run make-iso.sh with --release to overwrite
# it with a release image. If you want both side by side, set ISO=...).
iso="${ISO:-${repo_root}/build/xenith.iso}"
use_kvm="yes"
use_uefi="no"
extra_args=()

# ---------------------------------------------------------------------------
# Parse flags.
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "${arg}" in
        --no-kvm)
            use_kvm="no"
            ;;
        --uefi)
            use_uefi="yes"
            ;;
        --release)
            # Kept for symmetry with make-iso.sh; the ISO path is the same
            # unless the caller sets ISO explicitly.
            iso="${ISO:-${repo_root}/build/xenith.iso}"
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        --)
            shift
            extra_args+=("$@")
            break
            ;;
        -*)
            echo "run-qemu.sh: unknown flag: ${arg}" >&2
            exit 1
            ;;
        *)
            # A bare positional argument is treated as an explicit ISO path.
            iso="${arg}"
            ;;
    esac
done

if [ ! -f "${iso}" ]; then
    echo "run-qemu.sh: ISO not found: ${iso}" >&2
    echo "  build it first with: scripts/make-iso.sh" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve the QEMU binary. On Windows hosts (where this repo is developed)
# the binary is qemu-system-x86_64.exe on PATH; on Linux it is
# qemu-system-x86_64. We rely on PATH resolution to pick the right one.
# ---------------------------------------------------------------------------
qemu_bin="${QEMU:-qemu-system-x86_64}"
if ! command -v "${qemu_bin}" >/dev/null 2>&1; then
    echo "run-qemu.sh: QEMU not found: ${qemu_bin}" >&2
    echo "  install qemu-system-x86_64 and ensure it is on PATH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build the QEMU argument list.
# ---------------------------------------------------------------------------
mem="${MEM:-512}"
cpus="${CPUS:-2}"

qemu_args=(
    # Memory and CPUs.
    -m "${mem}"
    -smp "${cpus}"
    # Serial port routed to stdio so kernel log output appears in the
    # terminal. -serial mon:stdio would also allow Ctrl-A x to quit, but
    # plain -serial stdio is simpler and works on Windows hosts too.
    -serial stdio
    # Do not reboot on triple fault / panic — exit so the error is visible.
    -no-reboot
    # Do not reboot on shutdown either; exit cleanly when the guest halts.
    -no-shutdown
    # Attach the ISO as a raw drive. format=raw avoids QEMU probing the
    # image format (which is safe but noisy). The ISO is hybrid so it boots
    # as either a CD or a hard disk.
    -drive "file=${iso},format=raw,media=cdrom"
)

# ---------------------------------------------------------------------------
# Acceleration: prefer KVM, fall back to TCG. We probe /dev/kvm on Linux;
# on Windows the caller should install QEMU with WHPX and pass
# EXTRA_QEMU="-accel whpx" if they want hardware acceleration.
# ---------------------------------------------------------------------------
if [ "${use_kvm}" = "yes" ]; then
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        qemu_args+=(-enable-kvm -cpu host)
    else
        # KVM not available — fall back to TCG silently so the script works
        # inside nested VMs and on non-Linux hosts. TCG is slower but
        # functionally correct.
        qemu_args+=(-accel tcg -cpu qemu64)
    fi
else
    qemu_args+=(-accel tcg -cpu qemu64)
fi

# ---------------------------------------------------------------------------
# UEFI boot: use OVMF firmware if available. We look for the firmware blob
# in the conventional install locations on Debian/Ubuntu, Fedora, and Arch.
# The caller can override with OVMF=/path/to/OVMF_CODE.fd.
# ---------------------------------------------------------------------------
if [ "${use_uefi}" = "yes" ]; then
    ovmf="${OVMF:-}"
    if [ -z "${ovmf}" ]; then
        for candidate in \
            /usr/share/OVMF/OVMF_CODE.fd \
            /usr/share/ovmf/OVMF_CODE.fd \
            /usr/share/edk2/ovmf/OVMF_CODE.fd \
            /usr/share/ovmf/x64/OVMF_CODE.fd; do
            if [ -f "${candidate}" ]; then
                ovmf="${candidate}"
                break
            fi
        done
    fi
    if [ -z "${ovmf}" ] || [ ! -f "${ovmf}" ]; then
        echo "run-qemu.sh: --uefi requested but OVMF firmware not found" >&2
        echo "  install edk2-ovmf (or set OVMF=/path/to/OVMF_CODE.fd)" >&2
        exit 1
    fi
    # OVMF stores NVRAM state in a separate vars file; we copy a pristine
    # vars file alongside so each boot starts from a clean UEFI variable
    # store. Look for OVMF_VARS.fd next to the code file.
    ovmf_vars="${ovmf%/*}/OVMF_VARS.fd"
    if [ ! -f "${ovmf_vars}" ]; then
        # Some distros ship a template under a different name.
        ovmf_vars="${ovmf%/*}/OVMF_VARS.fd"
    fi
    qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=${ovmf}")
    if [ -f "${ovmf_vars}" ]; then
        # Copy vars to a temp file so the originals stay pristine.
        tmp_vars="$(mktemp -t xenith-ovmf-vars.XXXXXX.fd)"
        cp "${ovmf_vars}" "${tmp_vars}"
        qemu_args+=(-drive "if=pflash,format=raw,readonly=off,file=${tmp_vars}")
    fi
fi

# ---------------------------------------------------------------------------
# Append any caller-supplied extra QEMU flags (e.g. -d int for interrupt
# logging, or -accel whpx on Windows).
# ---------------------------------------------------------------------------
if [ -n "${EXTRA_QEMU:-}" ]; then
    # shellcheck disable=SC2206
    qemu_args+=(${EXTRA_QEMU})
fi
qemu_args+=("${extra_args[@]}")

# ---------------------------------------------------------------------------
# Launch QEMU.
# ---------------------------------------------------------------------------
echo "==> Booting ${iso}"
echo "    qemu: ${qemu_bin} | mem: ${mem}M | cpus: ${cpus} | uefi: ${use_uefi}"
exec "${qemu_bin}" "${qemu_args[@]}"

#!/usr/bin/env bash
#
# debug-qemu.sh — Boot Xenith under QEMU with a GDB server attached.
#
# This launches QEMU with `-S` (freeze CPU at reset) and `-s` (start a GDB
# server on TCP port 1234) so you can attach gdb, set breakpoints, and
# single-step through early boot, page-table setup, or the scheduler.
#
# Workflow:
#   1. In one terminal:  scripts/debug-qemu.sh
#      QEMU starts but the guest is frozen at reset — you will see no
#      serial output yet.
#   2. In another terminal, attach gdb:
#        gdb -ex 'target remote :1234' \
#            -ex 'symbol-file target/x86_64-xenith/debug/kernel' \
#            -ex 'break xenith_kernel_main' \
#            -ex 'continue'
#   3. When you are done, `continue` to let the kernel boot fully, or
#      `kill` / Ctrl-C in gdb and then Ctrl-A x in the QEMU monitor (or
#      just close the QEMU window).
#
# The script shares most of its flag set with run-qemu.sh (same memory,
# CPU, serial, and ISO handling) but:
#   - adds -S (halt at reset) and -gdb tcp::1234 (-s is the short form),
#   - drops -enable-kvm by default (single-stepping under KVM works, but
#     TCG gives more deterministic debugging and lets you inspect the
#     reset vector and firmware boot path),
#   - adds -d int,guest_errors to QEMU's own log so CPU exceptions and
#     triple faults are printed to stderr (useful when the kernel dies
#     before serial is up).
#
# Usage:
#   scripts/debug-qemu.sh                # default flags, gdb on :1234
#   scripts/debug-qemu.sh --kvm          # allow KVM (faster, less precise)
#   scripts/debug-qemu.sh --uefi         # debug UEFI boot via OVMF
#   GDB_PORT=1235 scripts/debug-qemu.sh  # use a non-default gdb port
#   MEM=2048 scripts/debug-qemu.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repo root and the ISO image.
# ---------------------------------------------------------------------------
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

iso="${ISO:-${repo_root}/build/xenith.iso}"
use_kvm="no"
use_uefi="no"
gdb_port="${GDB_PORT:-1234}"
extra_args=()

for arg in "$@"; do
    case "${arg}" in
        --kvm)
            use_kvm="yes"
            ;;
        --uefi)
            use_uefi="yes"
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
            echo "debug-qemu.sh: unknown flag: ${arg}" >&2
            exit 1
            ;;
        *)
            iso="${arg}"
            ;;
    esac
done

if [ ! -f "${iso}" ]; then
    echo "debug-qemu.sh: ISO not found: ${iso}" >&2
    echo "  build it first with: scripts/make-iso.sh" >&2
    exit 1
fi

qemu_bin="${QEMU:-qemu-system-x86_64}"
if ! command -v "${qemu_bin}" >/dev/null 2>&1; then
    echo "debug-qemu.sh: QEMU not found: ${qemu_bin}" >&2
    exit 1
fi

mem="${MEM:-512}"
cpus="${CPUS:-2}"

# ---------------------------------------------------------------------------
# Assemble the QEMU argument list. We intentionally use TCG by default for
# debugging: KVM single-step works but hides the reset vector and firmware
# boot path, and TCG is more deterministic for reproducible bug hunting.
# ---------------------------------------------------------------------------
qemu_args=(
    -m "${mem}"
    -smp "${cpus}"
    # Route serial to stdio so once you `continue` past the breakpoint the
    # kernel log is visible in this same terminal.
    -serial stdio
    -no-reboot
    -no-shutdown
    -drive "file=${iso},format=raw,media=cdrom"
    # Freeze the CPU at reset so gdb can attach before any instruction runs.
    -S
    # Start a GDB remote server on the given TCP port. gdb connects with
    # `target remote :<port>`. -s is the shorthand for -gdb tcp::1234; we
    # use the long form so the port is configurable via GDB_PORT.
    -gdb "tcp::${gdb_port}"
    # Print CPU exceptions, triple faults, and guest errors to QEMU's
    # stderr. This is invaluable when the kernel dies before the serial
    # console is initialized — you see the exact fault vector and RIP.
    -d int,guest_errors
)

if [ "${use_kvm}" = "yes" ]; then
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        qemu_args+=(-enable-kvm -cpu host)
    else
        echo "debug-qemu.sh: --kvm requested but /dev/kvm not available" >&2
        qemu_args+=(-accel tcg -cpu qemu64)
    fi
else
    # TCG with a generic CPU. qemu64 exposes the full set of features QEMU
    # emulates; switch to -cpu max if you need AVX/AVX2 in the guest.
    qemu_args+=(-accel tcg -cpu qemu64)
fi

# UEFI via OVMF (same logic as run-qemu.sh).
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
        echo "debug-qemu.sh: --uefi requested but OVMF firmware not found" >&2
        exit 1
    fi
    ovmf_vars="${ovmf%/*}/OVMF_VARS.fd"
    qemu_args+=(-drive "if=pflash,format=raw,readonly=on,file=${ovmf}")
    if [ -f "${ovmf_vars}" ]; then
        tmp_vars="$(mktemp -t xenith-ovmf-vars.XXXXXX.fd)"
        cp "${ovmf_vars}" "${tmp_vars}"
        qemu_args+=(-drive "if=pflash,format=raw,readonly=off,file=${tmp_vars}")
    fi
fi

if [ -n "${EXTRA_QEMU:-}" ]; then
    # shellcheck disable=SC2206
    qemu_args+=(${EXTRA_QEMU})
fi
qemu_args+=("${extra_args[@]}")

# ---------------------------------------------------------------------------
# Print the attach instructions so the developer does not have to remember
# the port and symbol-file path.
# ---------------------------------------------------------------------------
kernel_sym="${repo_root}/target/x86_64-xenith/debug/kernel"
if [ ! -f "${kernel_sym}" ]; then
    # Fall back to the release artifact if only a release build is present.
    kernel_sym="${repo_root}/target/x86_64-xenith/release/kernel"
fi

cat <<EOF
==> QEMU starting (frozen at reset, waiting for gdb).
    ISO:        ${iso}
    GDB server: tcp::${gdb_port}
    Symbols:    ${kernel_sym}

    In another terminal, run:
      gdb ${kernel_sym} \\
          -ex 'target remote :${gdb_port}' \\
          -ex 'break xenith_kernel_main' \\
          -ex 'continue'

    (If the kernel's entry symbol is named differently, adjust the break
    target. Use 'info functions' in gdb to list symbols after attach.)
EOF

exec "${qemu_bin}" "${qemu_args[@]}"

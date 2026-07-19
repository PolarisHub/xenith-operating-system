# Running Xenith

Build every packaged artifact first:

```text
cargo run -p xenith-build -- all
```

The build emits `build/kernel.elf`, `build/initramfs.cpio`, the manifest disk
`build/xenith.img`, the dual-entry `build/xenith.iso`, and the standalone
`build/bootloader/BOOTX64.EFI`.

## Deterministic interpreter

For the shortest kernel-development loop, use the direct handoff:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --smp 1 --serial stdio --max-instructions 100000000
```

`--smp` accepts 1 through 64. A two-CPU run exercises the guest's actual
INIT-SIPI-SIPI requests, validates the packaged AP trampoline contract, and
then advances both interpreted CPUs deterministically:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --smp 2 --serial stdio --max-instructions 240000000
```

`--max-instructions N` provides a deterministic bound. A guest fault is
printed as a structured decoder, memory, or CPU error and produces a failing
exit status. Unsupported instructions are never skipped. The implemented
loader/kernel FPU subset includes `CLTS`, `FNINIT`, `FXSAVE`, and `FXRSTOR`.

With `--serial stdio` in an interactive terminal, type commands normally after
the shell prompt. Input is read on a background thread and delivered as PS/2
set-1 keystrokes without pausing emulator execution. Windows CRLF is normalized
to one Enter key, and EOF stops only the host input source.

For deterministic automation, put ASCII commands in a file and add:

```text
--input-script commands.txt
```

Redirected stdin is not consumed implicitly. Use `--input-script -` for a
pipeline or `--input-script PATH` for a file. Multi-line scripts are bounded
and paced into the guest. The shell accepts quoting and escapes, `|`, `<`, `>`,
`>>`, and trailing `&`; for example, `cat < source | cat > destination`.
`jobs`, `fg`, and `bg` expose the bounded background-job model.

## Packaged image paths

To validate the manifest, directly load its exact kernel/initramfs extents, and
attach the same image to the ATA model:

```text
cargo run -p xenith-emu -- --image build/xenith.img --disk-read-only --memory 512M --smp 2 --serial stdio --max-instructions 240000000
```

This is a fast image-selected handoff; it does not execute stage1 or stage2.

To execute the packaged BIOS stage streams instead:

```text
cargo run -p xenith-emu -- --bios-image build/xenith.img --disk-read-only --memory 256M --smp 2 --serial stdio --max-instructions 240000000
```

The BIOS runner executes the actual stage1 instructions from `0x7c00`, services
their EDD reads, and executes the actual stage2 assembly through E820, A20,
protected mode, page-table creation, long mode, and its real
`call stage2_main`. Unsupported stage instructions fail closed. The
freestanding Rust `stage2_main` body remains an explicit semantic fallback for
ATA payload reads, ELF loading, handoff construction, and kernel entry.

To execute the packaged UEFI application from the ISO:

```text
cargo run -p xenith-emu -- --uefi-iso build/xenith.iso --memory 256M --smp 2 --serial stdio --max-instructions 240000000
```

This path validates the El Torito catalog and platform-`0xEF` entry, validates
the FAT16 ESP, extracts the exact packaged UEFI/kernel/initramfs files, parses
the PE32+ loader, and executes the actual `BOOTX64.EFI` instructions. Its
strict minimal UEFI environment provides only the services the loader reaches.
The application reads its files, obtains GOP and ACPI state, exits boot
services with the real map-key protocol, installs its native handoff, and
enters the kernel. This path has no semantic loader fallback. It is not a
general firmware emulator.

Omit `--disk-read-only` to permit in-memory ATA writes. Writes never overwrite
the input implicitly; add `--disk-output updated.img` to export the final disk
bytes. With the separate `--kernel` path, `--disk raw.img` attaches any
sector-aligned image without selecting boot payloads from it.

For deterministic final display artifacts, add:

```text
--framebuffer 800x600 --framebuffer-dump screen.ppm
--vga-dump screen.txt
```

These options capture final state; the emulator does not open a live window.
The RTL8139 device similarly has deterministic transmit completion but no host
network backend or inbound-frame source.

## Native debugger and GDB

Start a single-CPU interpreter run with the native debug server:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --smp 1 --debug-listen 127.0.0.1:9000
```

Connect the Xenith debugger from a second terminal:

```text
cargo run -p xenith-debug -- --connect 127.0.0.1:9000 --symbols build/kernel.elf
```

It supports address, ELF-symbol, and DWARF `file:line[:column]` breakpoints,
step/continue, registers, mapped memory reads/writes, bounded software
watchpoints, frame-pointer backtraces, and address/source lookup. Host input
stays bounded while execution is paused.

To bridge the same session to a loopback GDB RSP endpoint:

```text
cargo run -p xenith-debug -- --connect 127.0.0.1:9000 --gdb-listen 127.0.0.1:9001
gdb build/kernel.elf -ex "target remote 127.0.0.1:9001"
```

The bounded adapter supports the x86-64 target description, stop state,
register and memory access, continue, single-step, software breakpoints,
detach, and kill. It presents one thread. GDB Ctrl-C cannot interrupt a
backend `continue` already in progress because the native protocol has no
asynchronous pause. The debug server is interpreter/BSP-only, requires
`--smp 1`, and neither listener has authentication; bind them to loopback.

## Windows Hypervisor Platform

On Windows, `xenith-vmm` selects WHP when it is available and otherwise uses
the deterministic interpreter. Force the interpreter with `--interpreter`.

One virtual CPU:

```text
cargo run -p xenith-vmm -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 128M --smp 1 --timeout-ms 30000
```

Two virtual CPUs with guest INIT-SIPI-SIPI startup:

```text
cargo run -p xenith-vmm -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 256M --smp 2 --timeout-ms 30000
```

The WHP backend maps guest RAM, installs architectural register state, runs
actual WHP virtual processors, handles their exits, and routes I/O and MMIO
through the same PC device bus as `xenith-emu`. One- and two-vCPU fresh-artifact
gates reach the userspace shell; the two-vCPU gate also proves both processors
executed.

For a small one-vCPU WHP memory/register/I/O/HLT capability proof:

```text
cargo run -p xenith-vmm -- --probe --smp 1
```

WHP requires the optional Windows Hypervisor Platform feature and hardware
virtualization. If Windows itself runs inside another virtual machine, that
outer hypervisor must expose nested virtualization. The VMM CLI currently
accepts the direct kernel/initramfs handoff, not the packaged BIOS or UEFI
paths; only one and two vCPUs have artifact-backed runtime proof. VMM debugging,
host networking, and a live GUI are not implemented.

## Raw image and ISO layout

- `build/xenith.img` is the manifest-based BIOS disk consumed by Xenith
  stage1/stage2 and by the image validation path.
- `build/xenith.iso` has an x86 hard-disk-emulation entry containing that
  complete disk and a platform-`0xEF` no-emulation entry containing a FAT16 EFI
  System Partition.
- The ESP installs `EFI/BOOT/BOOTX64.EFI`, `EFI/XENITH/kernel.elf`, and
  `EFI/XENITH/initrd.cpio`.
- `build/bootloader/BOOTX64.EFI` is the same loader as a standalone UEFI
  application.

Writing a raw disk image to removable media is destructive and intentionally
not automated by the repository. Resolve and verify the exact target device
before using a platform imaging tool.

The packaged execution gates prove Xenith's exact BIOS stage streams and its
exact UEFI application under the repository's deterministic service models.
They do not prove arbitrary firmware, option ROMs, physical storage/display/
input devices, or physical hardware. QEMU/Limine scripts remain optional
cross-validation aids and are not required by the primary build/test path.

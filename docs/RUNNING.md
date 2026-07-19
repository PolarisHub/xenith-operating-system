# Running Xenith

Build all artifacts first:

```text
cargo run -p xenith-build -- all
```

## Interpreter

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --serial stdio --max-instructions 100000000
```

Use `--max-instructions N` for a deterministic bound. A guest fault is printed as a structured decoder/memory/CPU error and produces a failing exit status.

With `--serial stdio` in an interactive terminal, type commands normally after
the shell prompt. Stdin is read on a background thread and delivered as PS/2
set-1 keystrokes without pausing emulator execution. The terminal's current
line/raw mode determines when typed bytes become available; Windows CRLF is
normalized to one Enter key. EOF stops input only, not the guest.

For deterministic CLI automation, put ASCII commands in a file and add:

```text
--input-script commands.txt
```

For example, a file containing `echo CLI_INPUT_OK` followed by a newline is
typed through the same PS/2 path once the guest has enabled its keyboard.
Redirected stdin is not consumed implicitly; use `--input-script -` for a
pipeline or `--input-script PATH` for a file. Multi-line scripts are retained
and paced into the guest in bounded slices. The shell accepts single and double
quotes, backslash escapes, `|`, `<`, `>`, `>>`, and a trailing `&`; for example,
`cat < source | cat > destination`. Background jobs are bounded and visible via
`jobs`; `fg` and `bg` accept either the latest job or `%N`.

To boot the payloads embedded in the validated raw image and attach that same
image as the guest's primary-master ATA disk, use:

```text
cargo run -p xenith-emu -- --image build/xenith.img --disk-read-only --memory 512M --serial stdio --max-instructions 100000000
```

To preserve the packaged BIOS stages and native Xenith handoff, select the
firmware shim instead:

```text
cargo run -p xenith-emu -- --bios-image build/xenith.img --disk-read-only --memory 256M --serial stdio --max-instructions 100000000
```

The shim records reset, MBR, EDD, stage2, E820, A20, protected-mode,
long-mode, and kernel-handoff evidence. It executes Xenith's exact image
contract but is not a general-purpose BIOS or 16/32-bit interpreter.

Omit `--disk-read-only` to permit in-memory ATA writes. Writes never overwrite
the input implicitly; add `--disk-output updated.img` to export the final disk
bytes. With the separate `--kernel` path, `--disk raw.img` attaches any
sector-aligned image without selecting boot payloads from it.

For deterministic final display artifacts, add `--framebuffer 800x600
--framebuffer-dump screen.ppm`, or `--vga-dump screen.txt` for the legacy text
plane. The current renderer captures final state rather than opening a live
window.

For debugger control, start with `--debug-listen 127.0.0.1:9000`, then connect:

```text
cargo run -p xenith-debug -- --connect 127.0.0.1:9000 --symbols build/kernel.elf
```

The debugger accepts address, ELF-symbol, or DWARF `file:line` breakpoints,
step/continue, register commands, mapped memory reads/writes, and bidirectional
address/source lookup. See `--help` for batch/script and offline lookup syntax.
Host terminal or input-script data stays bounded while the debugger is paused
and is injected during subsequent step/continue execution.

## Raw image and ISO

- `build/xenith.img` contains the manifest-based BIOS disk layout consumed by Xenith stage1/stage2.
- `build/xenith.iso` has an x86 hard-disk-emulation entry containing the complete manifest image and a platform-`0xEF` no-emulation entry containing a FAT16 EFI System Partition. The ESP installs the loader at `EFI/BOOT/BOOTX64.EFI` and its payloads at `EFI/XENITH/kernel.elf` and `EFI/XENITH/initrd.cpio`.
- `build/bootloader/BOOTX64.EFI` is also emitted as a standalone UEFI application.

Writing a raw disk image to removable media is destructive and intentionally not automated by the repository. Resolve and verify the exact target device before using a platform imaging tool.

The current BIOS loader is limited to boot drive `0x80` and primary-master ATA PIO. The purpose-built interpreter shim covers that reset/stage1/stage2 contract, while external BIOS implementations, UEFI, ISO catalog boot, and physical hardware remain separate validation boundaries. Consult [STATUS](STATUS.md) for recorded runtime proof.

QEMU/Limine scripts are legacy optional cross-validation aids only. They are not required or invoked by the primary build/test path.

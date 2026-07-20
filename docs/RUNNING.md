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

Without `--framebuffer`, init goes directly to the terminal shell. With
`--serial stdio` in an interactive terminal, type commands normally after the
shell prompt. Input is read on a background thread and delivered as PS/2 set-1
keystrokes without pausing emulator execution. Windows CRLF is normalized to
one Enter key, and EOF stops only the host input source.

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

Use `--bios-iso build/xenith.iso` instead to validate and select the x86
hard-disk-emulation entry from the ISO's El Torito catalog before executing the
same stage streams.

The BIOS runner executes the actual stage1 instructions from `0x7c00`, services
the selected EDD or CHS path, and executes stage2's bounded firmware payload
preloads and repeated real/protected-mode bounce-buffer copies before E820,
page-table creation, long mode, and its real `call stage2_main`. Unsupported
stage instructions fail closed. The
freestanding Rust `stage2_main` body remains an explicit semantic fallback for
checksum/ELF loading, handoff construction, and kernel entry. That
boundary also applies to `--bios-iso`; this emulator gate is not evidence of a
complete external-firmware ISO boot.

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

Supplying `--framebuffer` starts `xenith-desktop` instead of the terminal shell.
It presents the procedural glass desktop, sleeps when idle, toggles its empty
launcher with Super, and has no bundled applications. `Ctrl+Alt+Backspace`,
`Ctrl+Alt+F1`, or `Super+Shift+Q` releases the session and enters the terminal
fallback. These options capture final state; the emulator does not open a live
window.

From that fallback shell, the explicit native-window proof is:

```text
/bin/xenith-desktop --window-smoke --smoke-exit
```

This mode alone creates a private channel and launches
`/bin/xenith-window-smoke`; normal desktop startup remains app-free. The launch
uses `spawn_restricted`: the child starts with only stdout, stderr, and its
client endpoint at descriptor 3. The current packaged mode still opens one
connection; the compositor's eight-client coordinator has no general service
rendezvous yet.

The packaged native-thread proof is:

```text
/bin/thread-smoke
```

It maps two independent 64 KiB RW/NX stacks, creates two joinable tasks, checks
three distinct `gettid` values and both exit codes, joins them, then unmaps both
stacks and prints `XENITH_THREAD_OK`. After building all artifacts, run its
booted-guest gate with:

```text
cargo test -p xenith-integration --test shell userspace_threads_create_join_and_teardown_in_guest -- --ignored --exact
```

The packaged bounded Win64 console proof is:

```text
/bin/xenith-winhost /tests/win64-console.exe
```

The fixture calls `KERNEL32.DLL!GetStdHandle`, `WriteFile`, and `ExitProcess`
through the host's bootstrap IAT and returns to the Xenith shell. Its preferred
base deliberately overlaps the host ELF; the build rejects a layout that loses
that collision, and the fixture emits its success line only after its absolute
message pointer has been correctly rebased by a DIR64 relocation. The host
executes it on a dedicated bounded stack with an unmapped lower guard page.

This demonstrates only the documented PE32+ AMD64 console subset. It is not a
sandbox: the trusted fixture executes inside `xenith-winhost` with that
process's Xenith syscall authority and inherited descriptors. After building
all artifacts, run the explicit booted-guest gate with:

```text
cargo test -p xenith-integration --test winhost win64_console_fixture_executes_through_booted_host -- --ignored --exact
```

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

## VMware Workstation BIOS and UEFI

Create a custom VM with guest type **Other / Other 64-bit**, select **BIOS**
firmware, assign any supported count from 1 through 64 vCPUs (subject to the
host and VMware limits) and 512 MiB RAM, and mount `build/xenith.iso` as the
CD/DVD boot medium. Xenith's current architectural limit is 64 logical CPUs;
configurations above 64 are not supported. NAT is optional; Xenith does not
require networking to boot. The IDE/SCSI controller choice shown by VMware's
disk wizard does not affect an ISO boot.

Power on with the virtual CD connected. The legacy-BIOS path selects a VBE
framebuffer when available and now starts the Xenith desktop. If VBE is
unavailable, the loader deliberately falls back to VGA text and init starts
`Xenith shell 0.1` / `xenith$`. From the desktop, use
`Ctrl+Alt+Backspace`, `Ctrl+Alt+F1`, or `Super+Shift+Q` to restore the terminal
shell deliberately.

For UEFI, use the same ISO, select **UEFI**, and leave Secure Boot disabled.
The current ISO identified in [STATUS](STATUS.md) cold-booted in VMware
Workstation 17.6.3 with 512 MiB and 3 vCPUs under both BIOS and UEFI on
2026-07-20. Both reached `XENITH_DESKTOP_READY`, and all three CPUs came online.
The preceding ISO also passed legacy-BIOS boots with 1, 3, 4, 8, 16, and 24
vCPUs. The corresponding cores-per-socket values were 1, 1, 2, 4, 8, and 12;
24 was the tested host's logical-CPU limit. See [STATUS](STATUS.md) for exact
hashes and the distinction between current-artifact and historical topology
proof.

The ISO is the normal VMware path. Booting `build/xenith.img` directly requires
a VMDK wrapper that maps the raw image; VMware does not accept the raw `.img`
as a virtual disk by itself.

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
Separately, VMware Workstation 17.6.3 BIOS and UEFI cold boots on 2026-07-20
proved the current ISO at 3 vCPUs. Legacy BIOS cold boots on 2026-07-19 proved
the preceding externally tested ISO at 1, 3, 4, 8, 16, and 24 vCPUs.
QEMU 11.0.50 with SeaBIOS 1.17 proved every integer CPU count from 1 through
64 for that ISO, its raw image at 64 CPUs, and a 2-socket by 3-core topology
with non-contiguous APIC IDs. Every tested configuration brought the requested
CPUs online and reached `xenith$`. [STATUS](STATUS.md) records the exact hashes
and distinguishes that snapshot from the current repository-owned gates.
These results do not prove arbitrary firmware, option ROMs, physical devices,
or physical hardware. QEMU/Limine scripts remain optional cross-validation
aids and are not required by the primary build/test path.

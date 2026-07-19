# Xenith emulator

`xenith-emu` is a deterministic x86-64 SMP interpreter. It owns CPU registers,
control state and MSRs, four-level translation, physical RAM, MMIO/port
dispatch, dirty tracking, ELF loading, boot metadata, and the shared PC device
model. `--smp` accepts 1 through 64 logical CPUs. Runnable processors advance
one interpreted cycle at a time in deterministic round-robin order; APs remain
stopped until the guest's INIT-SIPI-SIPI sequence validates their trampoline
contract and starts them at its patched 64-bit entry.

The four boot sources are mutually exclusive.

## Direct kernel and manifest image

The fastest development path loads the kernel and initramfs directly:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --smp 2 --serial stdio --max-instructions 240000000
```

The direct loader validates ELF64 program headers, creates guest page tables,
maps identity/HHDM/kernel/stack ranges, installs the accepted boot aggregate and
initramfs module, and enters the ELF entry point. It bypasses both firmware
loaders.

The image-oriented fast path validates the complete LBA1 `XENITHIM` manifest,
including all three payload checksums, selects the exact kernel/initrd extents,
and attaches the same bytes to the primary-master ATA model:

```text
cargo run -p xenith-emu -- --image build/xenith.img --disk-read-only --memory 512M --smp 2 --serial stdio --max-instructions 240000000
```

## Packaged BIOS execution

Use the strict Xenith BIOS runner to preserve and execute the packaged loader
stages:

```text
cargo run -p xenith-emu -- --bios-image build/xenith.img --disk-read-only --memory 256M --smp 2 --serial stdio --max-instructions 240000000
```

To select the x86 hard-disk-emulation entry from the actual El Torito catalog
and validate its ISO extent before entering the same BIOS runner, use:

```text
cargo run -p xenith-emu -- --bios-iso build/xenith.iso --disk-read-only --memory 256M --smp 2 --serial stdio --max-instructions 240000000
```

This path starts from architectural reset state, installs an inspectable reset
ROM stub, and transfers the actual MBR to `0x7c00`. A bounded interpreter
fetches and executes the packaged stage1 bytes, services its EDD reads, executes
the stage2 real/protected/long-mode assembly, builds the actual page tables, and
stops only after executing stage2's real `call stage2_main` instruction.
Unknown instructions fail the boot instead of being skipped. `BiosBootTrace`
retains per-stage instruction and byte counts, execution checksums, BIOS calls,
E820, A20, and mode transitions.

The freestanding Rust `stage2_main` body is the explicit remaining semantic
fallback: the host validates and reads its payloads, loads the kernel ELF,
constructs the native `XenithBootInfo`, and enters the kernel. This proves the
current packaged Xenith stage1 and stage2 instruction streams through the
long-mode Rust-call boundary; it is not an arbitrary BIOS or general 16/32-bit
firmware interpreter. The `--bios-iso` path has this same explicit semantic
boundary; ISO catalog selection does not turn it into external-firmware proof.

## Packaged UEFI ISO execution

`--uefi-iso` executes the UEFI application packaged in the ISO:

```text
cargo run -p xenith-emu -- --uefi-iso build/xenith.iso --memory 256M --smp 2 --serial stdio --max-instructions 240000000
```

The loader validates the El Torito catalog, selects the exact platform-`0xEF`
no-emulation entry, validates its FAT16 EFI System Partition, and extracts the
packaged `EFI/BOOT/BOOTX64.EFI`, kernel, and initramfs bytes. It strictly parses
the PE32+ image, maps its accepted sections, and executes the actual
`BOOTX64.EFI` instructions through the ordinary long-mode interpreter.

The deterministic firmware environment implements only the services and
protocols used by Xenith's loader: page allocation, the memory map and map key,
Loaded Image and Simple File System handle protocols, volume/file
open/get-info/read/close, GOP lookup, console output, the ACPI 2.0 configuration
table, and `ExitBootServices`. Unsupported PE forms, firmware services, and CPU
instructions fail closed. After `ExitBootServices`, the application installs
its native page tables and stack and transfers control to the kernel with its
own `XenithBootInfo`. There is no semantic loader fallback in this UEFI path.
The execution trace retains ISO/FAT payload checksums, PE instruction evidence,
service counts, boot-services exit, GOP/ACPI state, and the final native
handoff. It also records exact execution of the ISO's packaged BIOS catalog
stage streams for cross-entry evidence.

This is a strict model of the services reached by Xenith's current application,
not a general UEFI implementation and not proof against an external firmware.

## CPU and device model

The decoder/encoder is `xenith-x86`. The executed subset includes the integer,
control-flow, stack, port-I/O, control-register, descriptor-table, MSR,
syscall/sysret/swapgs, interrupt-control, and halt forms used by Xenith. The
loader/kernel FPU subset includes `CLTS`, `FNINIT`, `FXSAVE`, and `FXRSTOR`,
including privilege, CR0/CR4, alignment, paging, and MXCSR checks. An unsupported
encoding stops with a structured `CpuFault::Unsupported`; it is never treated
as a NOP.

Paging checks supervisor/user privilege at every level. Maskable delivery
honors IF and the STI shadow, validates 64-bit IDT gates and code selectors,
uses GDT TSS RSP0 for CPL3-to-CPL0 entry or the selected IST pointer, creates
the architectural long-mode frame, and resumes an interruptible `hlt`. `iretq`
restores same-CPL and privilege-changing frames. The APIC model supplies
INIT/SIPI and fixed IPI routing plus deterministic LAPIC timer delivery.

Register-level devices are COM1 serial, CMOS/RTC, PIT, legacy PIC, PS/2,
IOAPIC, per-CPU LAPIC state, a 64-bit one-comparator HPET, PCI configuration
mechanism #1, and a primary-master ATA PIO disk. ATA implements IDENTIFY,
LBA28/LBA48 read/write, flush, software reset, IRQ14, read-only media, and
explicit final-image export with `--disk-output`. PCI exposes a conventional
host/ISA/IDE topology. HPET and all other clocks advance from deterministic
interpreter cycles.

The PCI topology also exposes an RTL8139 with a stable locally administered
MAC, immediate reset, an always-up link, an empty receive ring, and
deterministic transmit completion/INTx. It brings the production RTL8139
driver online and provides a bounded transmit sink, but it has no host network
backend or inbound-frame source.

Repository SMP coverage includes the explicitly invoked artifact gates
`two_processor_kernel_brings_ap_online_and_reaches_shell` and
`three_processor_kernel_brings_every_ap_online_and_reaches_shell`. Fast
topology tests construct 1-, 3-, and 64-CPU machines, verify their MADTs, and
exercise SIPI delivery to every one of the 63 APs at the supported maximum.
These checks preserve the distinction between a complete boot gate and a
focused machine-model test.

The BIOS-ISO artifact gate also boots three CPUs with the native stage2 memory
contract: the whole first MiB remains reserved, so the test requires the exact
`xenith.boot=bios` handoff to select the retired `0x70000` bounce page and then
requires both APs to execute before the shell appears.

## Host input and displays

With `--serial stdio`, an interactive background reader forwards host input
through emulated PS/2 set-1 keys. A fixed 16-message channel with at most 256
bytes per message keeps blocking terminal reads from stopping CPU or device
ticks. CRLF and bare CR become one Enter key; unsupported terminal characters
are reported and ignored. Redirected stdin is not consumed implicitly. Use
`--input-script PATH` or `--input-script -` for repeatable input through the
same bounded path.

`--framebuffer WIDTHxHEIGHT --framebuffer-dump screen.ppm` captures the final
32-bpp framebuffer, and `--vga-dump screen.txt` captures the final 80x25 text
plane. These are deterministic final-state renderers, not a live GUI.

## Debugging

`--debug-listen ADDRESS` exposes the bounded Xenith debug protocol for a
single-CPU interpreter run:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --smp 1 --debug-listen 127.0.0.1:9000
cargo run -p xenith-debug -- --connect 127.0.0.1:9000 --symbols build/kernel.elf
```

The native client resolves ELF symbols and DWARF source lines in both
directions, supports address/symbol/`file:line[:column]` breakpoints,
continue/step, registers, mapped memory, bounded software watchpoints,
frame-pointer backtraces, and explicit PIE load bias.

The same client can expose a bounded single-client GDB Remote Serial Protocol
adapter:

```text
cargo run -p xenith-debug -- --connect 127.0.0.1:9000 --gdb-listen 127.0.0.1:9001
gdb build/kernel.elf -ex "target remote 127.0.0.1:9001"
```

The adapter covers target description and stop queries, general/segment
register and memory reads/writes, continue, single-step, software breakpoints,
detach, and kill. Packets, memory transfers, and breakpoint counts are bounded.
The underlying emulator protocol has no asynchronous pause, so GDB Ctrl-C
cannot interrupt a `continue` already running. Debug control is BSP-only,
requires `--smp 1`, has no authentication, and is not wired to the WHP runner.
There is no physical-machine serial stop-the-world stub, hardware watchpoint
support, DWARF variable/type view, inline-stack view, or CFI unwinder.

## Windows Hypervisor Platform

`xenith-vmm` is an actual Windows Hypervisor Platform runner, with an explicit
interpreter fallback:

```text
cargo run -p xenith-vmm -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 256M --smp 2 --timeout-ms 30000
```

On a WHP-capable Windows host it allocates and maps guest RAM, installs the
architectural register state, runs real WHP virtual processors, handles WHP
memory/I/O/APIC/exception exits, and routes device accesses through the same
`Machine` bus used by the interpreter. Each virtual processor has a worker;
the coordinator serializes shared-device effects. Fresh artifact gates prove
both a one-vCPU shell boot and a two-vCPU INIT-SIPI-SIPI boot in which both VPs
execute.

WHP requires the Windows Hypervisor Platform feature and hardware
virtualization; a Windows guest also needs nested virtualization exposed by its
outer hypervisor. The VMM CLI currently performs the direct kernel/initramfs
handoff, not BIOS or UEFI firmware execution, and its proven SMP configurations
are one and two vCPUs. It has no debugger integration, host network backend, or
live GUI.

Neither emulator path is proof of arbitrary third-party firmware or physical
hardware. External BIOS/UEFI behavior, option ROMs, full chipset reset, real
interrupt timing, physical storage/display/input devices, and live networking
remain separate validation boundaries.

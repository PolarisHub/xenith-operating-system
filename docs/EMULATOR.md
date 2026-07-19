# Xenith emulator

`xenith-emu` is a deterministic x86-64 interpreter. It owns CPU registers/control state/MSRs, four-level translation, physical RAM, MMIO/port dispatch, dirty tracking, ELF loading, boot metadata, and a PC device set.

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --smp 1 --serial stdio --max-instructions 100000000
```

The image-oriented path validates the complete LBA1 manifest (including all
three payload checksums), directly loads the exact kernel/initrd extents, and
attaches the same bytes to the primary-master ATA model:

```text
cargo run -p xenith-emu -- --image build/xenith.img --disk-read-only --memory 512M --serial stdio --max-instructions 100000000
```

The direct `--image` mode remains available for fast kernel work. To exercise
the packaged BIOS path, use the deterministic firmware shim:

```text
cargo run -p xenith-emu -- --bios-image build/xenith.img --disk-read-only --memory 256M --serial stdio --max-instructions 100000000
```

This path starts from architectural reset state, installs an inspectable reset
ROM stub, transfers the actual MBR to `0x7c00`, performs stage1's two EDD reads,
validates and loads the actual stage2 extent at `0x8000`, supplies E820/A20,
reproduces stage2's protected/long-mode page tables and physical ELF loading,
and enters the kernel with a native `XenithBootInfo`. The retained
`BiosBootTrace` records every boundary. It is an explicit firmware-service and
mode-transition shim, not a general 16/32-bit x86 interpreter or an external
PC BIOS.

When `--serial stdio` is connected to an interactive terminal, a background
reader forwards host input through the emulated PS/2 keyboard. The reader uses
a fixed 16-message channel with at most 256 bytes per message, so terminal
reads can block without stopping CPU or device ticks. CRLF and bare CR become
one Enter key, early input remains bounded until the guest enables the 8042,
and EOF closes only the input source while the guest continues. Input is the
US set-1 ASCII subset; unsupported terminal characters are reported and
ignored.

Redirected stdin is deliberately not mistaken for an interactive terminal.
For repeatable input, pass `--input-script PATH` (or `--input-script -` for
redirected stdin); the stream uses the same
bounded reader, CRLF normalization, readiness gate, and
`Machine::inject_keyboard_ascii` path. Script errors fail the CLI instead of
being ignored.

The decoder/encoder is `xenith-x86`. The executed subset includes the integer, control-flow, stack, port-I/O, control-register, descriptor-table, MSR, syscall/sysret/swapgs, interrupt-control, and halt forms implemented in `cpu.rs`. An unsupported encoding stops with a structured `CpuFault::Unsupported`; it is never treated as a NOP.

The direct-kernel loader validates ELF64 program headers, creates guest page tables, maps identity/HHDM/kernel/stack ranges, installs a Limine-compatible boot aggregate and initramfs module, then starts at the ELF entry. `--image` selects those payloads from a fully validated `XENITHIM` disk instead of separate host files. These two fast modes bypass stage1/stage2; `--bios-image` is the separate native-Xenith handoff path. UEFI and ISO catalog execution remain outside the interpreter.

Paging checks supervisor/user privilege at every level. Maskable delivery honors IF and the STI shadow, validates 64-bit IDT gates and code selectors, uses GDT TSS RSP0 for CPL3-to-CPL0 entry or any of the seven TSS IST pointers selected by a gate, creates the five-qword architectural long-mode frame on a 16-byte-aligned stack, and resumes an interruptible `hlt`. `iretq` restores SS:RSP for both same-CPL and privilege-changing returns. The LAPIC model implements divide/initial/current/LVT/SVR/EOI state and deterministic one-shot or periodic delivery.

Register-level devices are COM1 serial, CMOS/RTC, PIT, legacy PIC, PS/2 controller, IOAPIC, LAPIC timer, a 64-bit one-comparator HPET, PCI configuration mechanism #1, and a primary-master ATA PIO disk. ATA implements IDENTIFY, LBA28/LBA48 read/write, flush, software reset, IRQ14, read-only media, and explicit final-image export with `--disk-output`. PCI exposes a conventional host/ISA/IDE topology. HPET and all other clocks advance from deterministic interpreter cycles.

The direct loader can install a 32-bpp linear framebuffer with `--framebuffer WIDTHxHEIGHT`; `--framebuffer-dump screen.ppm` renders its final pixels as PPM. `--vga-dump screen.txt` decodes the final 80x25 text plane. These are deterministic final-state renderers, not a real-time GUI. `Machine::inject_keyboard_ascii` remains the API-level PS/2 set-1 path used by the CLI and shell/coreutils gates.

The PCI topology also exposes an RTL8139 with a stable locally administered MAC, immediate reset, an always-up link, empty receive ring, and deterministic transmit completion/INTx. It brings the production RTL8139 driver online and provides a bounded TX sink, but has no host network backend or inbound-frame source.

There is still no general BIOS/UEFI implementation, arbitrary real/protected-mode instruction execution, full chipset reset sequence, host-backed networking, or AP startup. The purpose-built BIOS shim covers Xenith's packaged reset/stage1/stage2 contract only. The interpreter executes one CPU and rejects `--smp` values other than `1` instead of silently accepting an unused count.

`--debug-listen ADDRESS` exposes the bounded Xenith debug protocol. `xenith-debug` can resolve ELF symbols and DWARF source lines in both directions, set non-invasive address/symbol/`file:line[:column]` breakpoints, continue/step, inspect registers, and read/write mapped guest memory. Terminal/script input remains queued while the debugger is paused and is polled by its interrupt-aware step/continue loop; waiting for a debugger command does not tick the guest. It does not yet expose DWARF variables/types, inline call stacks, unwind-based backtraces, watchpoints, PIE relocation, GDB RSP, serial-hardware debugging, or VMM debugging.

`xenith-vmm` can probe Windows Hypervisor Platform and exercise partition/vCPU lifecycle ownership. It does not yet map guest memory, install registers, run the WHP vCPU, or process WHP exits; all guest execution currently uses the shared interpreter.

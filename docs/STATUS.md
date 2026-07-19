# Status

This file separates implementation, repository-owned runtime proof, and
external firmware or hardware proof. A successful check or parser test is not
a boot result, and an internal firmware model is not a physical-machine result.

## Current implementation

- The freestanding kernel has physical and virtual memory management, a bounded
  heap, refcounted copy-on-write `fork`, transactional `exec`, per-CPU
  scheduling, syscall entry, checked user-copy fixups, ELF processes, and
  x87/SSE/XSAVE task state.
- Signals include standard coalescing, a preallocated 128-entry realtime queue,
  `sigaction`, `sigprocmask`, `sigaltstack`, `sigreturn`, `SA_SIGINFO`,
  `SA_ONSTACK`, bounded `SA_RESTART`, and validated integer plus xstate frames.
  Fork and exec preserve or reset signal state according to their process
  semantics without placing the bounded queues on a 16 KiB kernel stack.
- The VFS provides ramfs/initramfs, read-only FAT32, writable journaled
  XenithFS, pipes, console TTYs, and a mounted `/dev/pts`. PTY slaves share the
  console line discipline, including canonical editing, signals, termios,
  foreground process groups, and all four noncanonical `VMIN`/`VTIME` cases.
- ACPI validates RSDP/RSDT/XSDT, MADT, FADT, HPET, DSDT, and up to 32 SSDTs.
  Its bounded AML namespace/evaluator supplies `_STA`, `_CRS`, `_PRT`, and
  power/resource methods used by discovery and PCI interrupt routing.
- PCI supports bounded capability walking, ACPI `_PRT` plus bridge swizzling,
  single-vector MSI, and routed INTx. RTL8139/e1000 use bounded hard-IRQ cause
  handling with an autonomous polling fallback. AHCI exposes DMA sector I/O
  and cache flush.
- XenithFS shares its disk format with `xenith-mkfs` and `xenith-fsck`. Journal
  commit ordering and filesystem sync issue block-device flush barriers;
  focused memory-disk tests cover persistent-tree replay and remount.
- SMP supports up to 64 logical CPUs. MADT topology drives INIT-SIPI-SIPI, APs
  install CPU-local descriptor/per-CPU/FPU/scheduler state, and reschedule plus
  TLB-shootdown IPIs coordinate per-CPU run queues. Both x2APIC and legacy
  xAPIC register backends are implemented.
- `xenith-build all` owns bootloader, kernel, userspace, initramfs, raw-image,
  and hybrid ISO construction without invoking QEMU, xorriso, Limine deploy,
  NASM, a system C compiler/linker, or GDB. The ISO contains a BIOS
  hard-disk-emulation image and a FAT16 EFI System Partition with exact
  `BOOTX64.EFI`, kernel, and initramfs payload verification.
- `xenith-emu` provides deterministic 1-to-64-CPU execution, direct and
  manifest-image loaders, exact packaged BIOS-stage execution to the Rust
  stage2 boundary, actual packaged `BOOTX64.EFI` PE32+ execution, paging,
  privilege transitions, interrupts, CLTS/FNINIT/FXSAVE/FXRSTOR, and the PC
  device subset documented in `EMULATOR.md`.
- `xenith-vmm` owns a Windows Hypervisor Platform partition, guest RAM,
  architectural register state, one or more real WHP virtual processors, and
  I/O/MMIO exit routing through the shared device model. One- and two-VP
  artifact gates are present.
- `xenith-debug` has native breakpoint, single-step, register/memory editing,
  bounded software watchpoints, frame-pointer backtraces, ELF symbols,
  bidirectional DWARF line lookup, explicit PIE load bias, and a bounded
  single-client GDB Remote Serial Protocol bridge.
- Freestanding init, shell, coreutils, editor, network tools, examples,
  `libuser`, and the C ABI runtime are packaged. The shell supports pipelines,
  redirection, quoting, background jobs, sessions/process groups, and terminal
  job control. The shipped `/bin/c-demo` is compiled through
  `xenith-cc` -> `xenith-asm` -> `xenith-ld`.
- The kernel accepts native `XenithBootInfo` from Xenith's BIOS/UEFI loaders and
  the optional local Limine-compatible input. Xenith records are validated and
  normalized into one internal boot aggregate before subsystem initialization;
  Limine is not used to construct the primary build artifacts.

## Runtime gates

The repository contains the following artifact gates. Older artifact sizes,
addresses, and instruction counts are not carried forward as if they described
the current build.

| Gate | What a passing run proves | Fresh post-change result |
| --- | --- | --- |
| `kernel_reaches_userspace_shell` | Direct kernel/initramfs load reaches ring-3 init and `xenith$` | PASS (2026-07-19) |
| `shell_executes_builtins_and_coreutils_via_ps2` | PS/2 input drives the shell, coreutils, filesystem mutations, VM/RNG, and the ring-3 signal smoke | PASS (2026-07-19) |
| `input_script_proves_shell_pipeline_and_redirection` | Multi-stage pipelines and `<`, `>`, `>>` work through real descriptors and syscalls | PASS (2026-07-19) |
| `xenith_built_c_utility_executes_in_ring3` | C source compiled by Xenith's compiler/assembler/linker executes at CPL3 | PASS (2026-07-19) |
| `manifest_image_reaches_userspace_shell` | The packaged manifest, checksums, kernel, initramfs, and attached ATA image reach the shell | PASS (2026-07-19) |
| `bios_firmware_image_reaches_userspace_shell` | Exact packaged BIOS stage streams execute through their long-mode call boundary, then the explicit semantic stage2 body reaches the shell | PASS (2026-07-19) |
| `uefi_iso_executes_packaged_pe_and_reaches_userspace_shell` | The platform-`0xEF` entry, FAT16 payloads, actual `BOOTX64.EFI`, strict services, `ExitBootServices`, and native handoff reach the shell with `semantic_loader_fallback=false` | PASS (2026-07-19) |
| `two_processor_kernel_brings_ap_online_and_reaches_shell` | The deterministic interpreter observes guest INIT-SIPI-SIPI, brings CPU 1 online, and reaches userspace | PASS (2026-07-19) |
| `built_kernel_supports_bidirectional_dwarf_line_lookup` | The packaged kernel's symbols and line tables resolve address-to-source and source-to-address | PASS (2026-07-19) |
| `gdb_rsp_tcp_bridge_controls_a_live_emulator` | The bounded GDB RSP bridge controls registers, memory, breakpoints, continue, and single-step on a live interpreter | PASS (2026-07-19) |
| `whp_boots_built_kernel_to_userspace_shell` | A real WHP virtual processor executes the direct kernel handoff to the shell | PASS (2026-07-19) |
| `whp_brings_second_processor_online_and_reaches_userspace_shell` | Two real WHP VPs execute and the guest brings its AP online before reaching the shell | PASS (2026-07-19) |

## Validation snapshot — 2026-07-19

- Complete workspace check and the selected native workspace test suite: PASS.
- Kernel host suite: 431 passed, 0 failed.
- Strict native, custom-target kernel/userspace, and standalone bootloader
  Clippy with warnings denied: PASS.
- Standalone bootloader checks/tests and root plus bootloader formatting: PASS.
- `xenith-build all`: PASS; it regenerated the kernel, BIOS stage1/stage2,
  `BOOTX64.EFI`, userspace ELFs, initramfs, raw image, hybrid ISO, and artifact
  inventory through the repository-owned toolchain.
- Every runtime gate in the table above: PASS against the refreshed artifacts.

Native unit/integration tests also exercise the debugger protocol and GDB RSP
bridge, CPL-aware walks and interrupt entry, ATA/PCI/HPET/RTL8139 devices,
realtime signal queue ordering/overflow, COW reference lifetimes, PTY/devpts
lifecycle, SSDT namespace merging, NIC interrupt routing, and XenithFS flush
ordering.

## Remaining boundaries

- No external BIOS/UEFI implementation or physical PC boot is recorded for the
  current artifacts. Physical AHCI, RTL8139/e1000, legacy xAPIC, display, input,
  ACPI, and cache-flush behavior therefore remain hardware-validation work.
- The BIOS runner executes the exact packaged stage1 and stage2 instruction
  streams only through the real long-mode `call stage2_main` boundary. The Rust
  stage2 payload/ELF/handoff body is an explicit semantic fallback. The loader
  accepts boot drive `0x80` and reads legacy primary-master ATA PIO; a complete
  BIOS El Torito boot, AHCI/NVMe/USB boot, drive `0x81`, and arbitrary option
  ROM or firmware execution are not implemented.
- The UEFI runner executes the packaged PE instructions without a semantic
  loader fallback, but implements only the protocols, services, PE form, and
  memory model reached by Xenith's loader. It is not a general UEFI firmware.
- The interpreter covers the x86-64/system/SSE subset required by the current
  kernel and loaders, not the complete architecture. AP startup validates the
  guest's actual INIT-SIPI-SIPI requests and trampoline contract but does not
  execute every AP real-mode trampoline instruction. Its device model uses ATA
  PIO and one RTL8139 model rather than emulated AHCI, e1000, or a PS/2 mouse.
  It has no live GUI or host-backed/inbound network backend; host keyboard input
  remains the documented US set-1 subset.
- WHP requires the optional Windows feature and compatible hardware. Its runner
  uses the direct kernel/initramfs handoff, not BIOS/UEFI firmware, and only the
  one- and two-VP configurations have artifact gates. The debugger is not wired
  to WHP.
- User-copy fixup ranges and SMAP-aware access windows have focused tests, but
  hostile late page faults still need end-to-end fault-injection coverage in a
  booted guest.
- Networking is IPv4-only. MSI-X tables, IPv6/AF_INET6, TCP SACK/window
  scaling, DNS-over-TCP, and DNSSEC remain outside the current stack. The
  physical-network path still needs supported hardware or a sufficiently exact
  VM device backend.
- AML loads DSDT and SSDTs, but opcode, region, and firmware-quirk coverage is
  intentionally bounded rather than ACPI-complete.
- XenithFS has explicit transaction, extent, and directory bounds plus flush
  barriers, but not larger extent trees or an fsck repair mode. Kernel FAT32 is
  read-only.
- Xenith's assembler currently emits flat 64-bit code and lacks 16/32-bit,
  macros, x87/SIMD, relocatable ELF objects, and complete GNU/Intel syntax.
  Stage1 is programmatically encoded while stage2/kernel assembly still uses
  Rust/LLVM's integrated assembler. The linker lacks relocatable-object,
  archive, dynamic-link, TLS, linker-script, and debug-section support. The C
  compiler remains a single-`main` integer/control-flow subset, and the C ABI
  library is not yet a general libc with malloc/printf and the full syscall
  surface. The userspace editor is an `ed`-style editor, not the requested
  vi-like screen editor.
- Debugger source support does not expose DWARF variables/types, inline call
  stacks, or DWARF-CFI unwinding. Watchpoints are interpreter-side comparisons,
  not hardware debug-register watchpoints. There is no physical serial
  stop-the-world stub, WHP attachment, asynchronous pause, authentication, or
  multi-thread GDB view.

Optional QEMU/Limine paths remain cross-validation aids only; they are not
primary build or CI dependencies.

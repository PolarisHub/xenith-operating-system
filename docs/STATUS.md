# Status

This file separates implementation, repository-owned runtime proof, and
external firmware or hardware proof. A successful check or parser test is not
a boot result, and an internal firmware model is not a physical-machine result.

## Current implementation

- The freestanding kernel has physical and virtual memory management, a bounded
  heap, refcounted copy-on-write `fork`, transactional `exec`, per-CPU
  scheduling, syscall entry, checked user-copy fixups, ELF processes, and
  x87/SSE/XSAVE task state.
- The initial heap scales from 8 to 32 MiB instead of reserving 32 MiB on every
  machine. The frame bitmap uses word-scanned next-fit allocation and excludes
  the published heap claim; delayed bootloader-memory reclamation protects all
  live boot structures before returning safe frames. AP boot/IST stacks are
  allocated only for discovered processors instead of reserving 64 stacks in
  `.bss`.
- Signals include standard coalescing, a preallocated 128-entry realtime queue,
  `sigaction`, `sigprocmask`, `sigaltstack`, `sigreturn`, `SA_SIGINFO`,
  `SA_ONSTACK`, bounded `SA_RESTART`, and validated integer plus xstate frames.
  Fork and exec preserve or reset signal state according to their process
  semantics without placing the bounded queues on a 16 KiB kernel stack.
- `waitpid` and stopped processes park instead of yield-spinning. Child state
  changes use a lost-wake-safe process-table/scheduler handoff, and group signal
  delivery wakes only accepted targets and parents whose children actually
  changed state. The process table is explicitly bounded at 256 records.
  Exiting tasks detach their address space before publishing exit, then a
  per-CPU post-switch retirement slot reclaims each dead task and kernel stack
  only after execution has left that stack.
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
- SMP supports configured topologies from 1 through 64 logical CPUs. MADT
  topology drives serialized INIT-SIPI-SIPI startup through one reusable low
  trampoline page; the BSP repatches it only after the preceding AP's online
  acknowledgement. A timeout quarantines that page and stops further AP
  startup so a late AP cannot consume another CPU's state. APs install
  CPU-local descriptor/per-CPU/FPU/scheduler state, and reschedule plus
  TLB-shootdown IPIs coordinate per-CPU run queues. Both x2APIC and legacy
  xAPIC register backends are implemented. CPU 0 owns the single 100 Hz shared
  expiry/aging pass while every CPU retains independent 50 ms time slices.
- `xenith-build all` owns bootloader, kernel, userspace, initramfs, raw-image,
  and hybrid ISO construction without invoking QEMU, xorriso, Limine deploy,
  NASM, a system C compiler/linker, or GDB. The ISO contains a BIOS
  hard-disk-emulation image and a FAT16 EFI System Partition with exact
  `BOOTX64.EFI`, kernel, and initramfs payload verification.
  Multicall initramfs names are CPIO symlinks to one coreutils payload rather
  than duplicate executable bodies.
- BIOS stage2 keeps payload I/O behind the firmware boot-drive contract: it
  reads the kernel and initramfs through bounded EDD packets or a geometry-
  validated, single-sector CHS fallback into conventional memory, copies each
  chunk to its high staging address through explicit real/protected-mode
  transitions, and verifies both manifest checksums. Its direct primary-master
  ATA reader remains only as the drive-`0x80` fallback.
  Optional VBE discovery selects a 32-bpp linear framebuffer up to 1024x768;
  failed or absent VBE falls back to VGA text.
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
- Freestanding init, graphical desktop, shell, coreutils, editor, network
  tools, examples, `libuser`, and the C ABI runtime are packaged. The desktop
  owns one native-format backbuffer, renders glass chrome procedurally, tracks
  at most 12 merged damage rectangles, consumes fixed input batches, and parks
  indefinitely when idle. Init supervises it and restores `/bin/sh` on missing
  framebuffer, clean recovery, or failure. The shell supports pipelines,
  redirection, quoting, background jobs, sessions/process groups, and terminal
  job control. The shipped `/bin/c-demo` is compiled through
  `xenith-cc` -> `xenith-asm` -> `xenith-ld`.
- The display boundary exposes one process-owned framebuffer/input session
  through syscalls 54-57 and matching `libuser` wrappers. Presentation
  uses a private userspace backbuffer plus validated damage copies; keyboard
  and pointer events share one bounded ordered queue with transactional reads,
  overflow reporting, routing epochs, signal-aware waits, and automatic
  release on successful exec, exit, or fatal process teardown. The kernel
  terminal retains its model while suspended and is fully restored on release.
  Event waits use a lost-wake-safe scheduler handoff with no 10 ms polling, and
  PAT-capable CPUs map scanout write-combining with cache-safe WBINVD/SFENCE
  ordering.
- Kernel logging and userspace TTY output share one COM1 serialization lock, so
  exact runtime markers cannot interleave across CPUs on the physical UART.
- `xenith-abi::compositor` defines a separate version-1 transport-neutral wire
  contract for generation-safe handles, shared-surface bounds, roles/state,
  bounded damage commits, configure acknowledgement, focus/input/text/close,
  and frame completion. No IPC transport or multi-process surface server is
  connected yet; this is the boundary intended for native clients and a later
  userspace Windows-compatibility server.
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
| `kernel_reaches_userspace_shell` | Direct kernel/initramfs load reaches ring-3 init and `xenith$` | PASS (2026-07-20) |
| `shell_executes_builtins_and_coreutils_via_ps2` | PS/2 input drives the shell, coreutils, filesystem mutations, VM/RNG, and the ring-3 signal smoke | PASS (2026-07-20) |
| `ring3_ui_smoke_restores_framebuffer_terminal` | Ring 3 acquires scanout, presents full and damaged frames, polls input, releases/unmaps, and the kernel terminal resumes drawing | PASS (2026-07-20) |
| `desktop_renders_stays_stable_and_falls_back_to_shell` | Init starts the desktop; it presents the exact non-flat shell, handles Super through partial damage, reaches repeated halted idle states, survives a bounded idle window, releases cleanly on recovery input, then restores the shell and terminal framebuffer | PASS (2026-07-20) |
| `input_script_proves_shell_pipeline_and_redirection` | Multi-stage pipelines and `<`, `>`, `>>` work through real descriptors and syscalls | PASS (2026-07-20) |
| `xenith_built_c_utility_executes_in_ring3` | C source compiled by Xenith's compiler/assembler/linker executes at CPL3 | PASS (2026-07-20) |
| `manifest_image_reaches_userspace_shell` | The packaged manifest, checksums, kernel, initramfs, and attached ATA image reach the shell | PASS (2026-07-20) |
| `bios_firmware_image_reaches_userspace_shell` | Exact packaged BIOS stage streams execute through their long-mode call boundary; the explicit semantic stage2 body supplies no firmware framebuffer, so init proves the supported text-shell fallback | PASS (2026-07-20) |
| `bios_firmware_image_reaches_shell_with_64_mib` | The compact BIOS payload layout, 8 MiB adaptive heap, and text fallback reach the shell with 64 MiB RAM | PASS (2026-07-20) |
| `bios_iso_catalog_entry_executes_packaged_stages_then_semantic_shell` | The ISO's validated x86 catalog entry executes the packaged BIOS stages, preserves the native reserved-low-memory handoff, exercises the `0x70000` AP-trampoline fallback, brings an odd three-CPU topology online, and reaches the text fallback | PASS (2026-07-20) |
| `uefi_iso_executes_packaged_pe_and_reaches_userspace_shell` | The platform-`0xEF` entry, FAT16 payloads, actual `BOOTX64.EFI`, strict services, `ExitBootServices`, native GOP handoff, graphical desktop/recovery lifecycle, and restored shell complete with `semantic_loader_fallback=false` | PASS (2026-07-20) |
| `two_processor_kernel_brings_ap_online_and_reaches_shell` | The deterministic interpreter observes guest INIT-SIPI-SIPI, brings CPU 1 online, and reaches userspace | PASS (2026-07-20) |
| `three_processor_kernel_brings_every_ap_online_and_reaches_shell` | The deterministic interpreter observes serialized startup of both APs, brings all three CPUs online, and reaches userspace | PASS (2026-07-20) |
| `built_kernel_supports_bidirectional_dwarf_line_lookup` | The packaged kernel's symbols and line tables resolve address-to-source and source-to-address | PASS (2026-07-20) |
| `gdb_rsp_tcp_bridge_controls_a_live_emulator` | The bounded GDB RSP bridge controls registers, memory, breakpoints, continue, and single-step on a live interpreter | PASS (2026-07-20) |
| `whp_boots_built_kernel_to_userspace_shell` | A real WHP virtual processor executes the direct kernel handoff to the shell | PASS (2026-07-20) |
| `whp_brings_second_processor_online_and_reaches_userspace_shell` | Two real WHP VPs execute and the guest brings its AP online before reaching the shell | PASS (2026-07-20) |

## Validation snapshot - 2026-07-20

- Complete workspace check and the selected native workspace test suite: PASS.
- Kernel host suite: 505 passed, 0 failed.
- Shared ABI suite: 12 passed, 0 failed; desktop host suite: 10 passed, 0
  failed; x86 decode/encode suite: 19 passed, 0 failed; emulator library suite:
  64 passed, 0 failed.
- Strict native, custom-target kernel/userspace, and standalone bootloader
  Clippy with warnings denied: PASS.
- Standalone bootloader checks/tests and root plus bootloader formatting: PASS.
- `xenith-build all`: PASS; it regenerated the kernel, BIOS stage1/stage2,
  `BOOTX64.EFI`, userspace ELFs, initramfs, raw image, hybrid ISO, and artifact
  inventory through the repository-owned toolchain.
- Every runtime gate in the table above: PASS against the refreshed artifacts.
- Fresh footprint: 154,496-byte initramfs, 27,688-byte desktop ELF, and
  95,368-byte kernel `.bss`.
- Source inventory: 279 Rust files with 122,860 physical lines; 296 Rust, C,
  assembly, and linker-script files with 124,786 physical lines total.

The repository-owned gates above ran against these refreshed artifacts:

- `xenith.iso`: `3978C060A5E5CD21C5AC25E26EADC6694D8F8FC52A0E685E3243849B0315D968`
- `xenith.img`: `C26375821935B5773AF33B73E2AF70E11DEB5F2A9A420E26B6BF092DD54F33AC`
- `kernel.elf`: `F9D6F374E5D3575FEC24B92FB1C255C18FC6E278B66D10E6613E3389BA996D98`
- `initramfs.cpio`: `038E15B18915E8E1CD1AD3392CD05B611F4368EADE9AF53A5976641B7F758002`
- `stage1.bin`: `A46C1CDD3774064FEFAE8EB5379245900D773A4425FF16B8AA428A39328607C0`
- `stage2.bin`: `A8AAEE751846A29C88D067D33EE9AB94DC2CC09DA3037C5491ED029B1A3CBDB7`
- `BOOTX64.EFI`: `9356A507B45C31BD09ED75F2877EC2289DAF467A12815ACE931E324A7177FA74`
- `xenith-desktop`: `10004A94669065B2AE2DD4F733F7CA28B81D5BB72374780DB6D83E114A146D80`

External VMware Workstation 17.6.3 legacy-BIOS cold boots passed earlier on
2026-07-19 with 512 MiB RAM and 1, 3, 4, 8, 16, and 24 vCPUs. QEMU 11.0.50
with SeaBIOS 1.17 also passed every integer CPU count from 1 through 64, a
64-CPU raw-image boot, and a 2-socket by 3-core topology with non-contiguous
APIC IDs. Those external runs used the preceding ISO
`0949DB89FEF66AAA2A83A96858A5D97F12D5561C76ADD0580352954C9ACC110F`
and raw image
`074298C35B258A57D483D769C5F638D2620FBE505A968A0700BD3E629289FE20`;
they were not rerun after the current desktop/scheduler rebuild and are historical
evidence, not proof of the refreshed hashes above.

Native unit/integration tests also exercise the debugger protocol and GDB RSP
bridge, CPL-aware walks and interrupt entry, ATA/PCI/HPET/RTL8139 devices,
realtime signal queue ordering/overflow, COW reference lifetimes, PTY/devpts
lifecycle, SSDT namespace merging, NIC interrupt routing, and XenithFS flush
ordering.

## Remaining boundaries

- Repository-owned emulator gates prove the refreshed raw disk plus BIOS and
  UEFI ISO entries. VMware Workstation and QEMU/SeaBIOS externally proved the
  immediately preceding SMP artifact, not the current desktop/scheduler
  hashes. Neither result establishes physical-PC compatibility or coverage
  across arbitrary firmware; physical AHCI/NVMe/USB boot, NICs, display/input,
  ACPI quirks, and cache-flush behavior remain hardware-validation work.
- The current desktop is deliberately a single-process software compositor.
  There is no live multi-client window transport, shared client surface
  service, acceleration, page flipping, or default application yet. The
  versioned compositor records are specification only. PE loading, NT/Win32
  APIs, COM, DirectX translation, .NET, and WoW64 are not implemented, so no
  Windows application compatibility is claimed. SMP input timing stress and
  broad real-device validation also remain.
- The current process model has one scheduler task per userspace process.
  Multi-threaded NT compatibility requires last-thread/refcounted address-space
  teardown before adding Windows thread semantics.
- The supported configured CPU range is 1 through 64, including the BSP. CPU
  masks and several per-CPU stores are fixed around `MAX_CPUS=64`; supporting
  more than 64 requires dynamically sized CPU sets and per-CPU storage rather
  than a larger configuration value alone.
- The BIOS runner executes the exact packaged stage1 and stage2 instruction
  streams only through the real long-mode `call stage2_main` boundary. The Rust
  stage2 checksum/ELF/handoff body is an explicit semantic fallback. The real
  loader uses the firmware-provided hard-disk boot drive through EDD or CHS,
  including El Torito emulation, and retains primary-master ATA PIO only when
  firmware preload fails on drive `0x80`. Arbitrary option ROMs and firmware
  are not emulated.
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

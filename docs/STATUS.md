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
- Syscalls 64-67 provide joinable shared-address-space userspace tasks with
  globally unique task IDs. One process may retain at most 32 live plus
  completed-unjoined thread records, subject to a 256-user-task global bound.
  Callers provide distinct page-aligned 16 KiB-8 MiB RW/NX stacks; the entry
  page must be user-executable. Join ownership is single-consumer, thread
  completion wakes its joiner, process termination interrupts peers, and the
  last task detaches its address space before publishing process exit.
  Task-local TLS and complete task-local signal state are not implemented, so
  thread creation and multi-threaded signal/VM/image mutations fail closed
  where their semantics would be ambiguous.
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
- The xHCI driver performs bounded BIOS ownership handoff, controller and
  root-port reset, command/event/transfer ring management, Supported Protocol
  speed and slot-type resolution, direct-port device enumeration, and USB
  boot-protocol keyboard/mouse interrupt input. MSI is preferred, with one
  4 ms task-context polling worker as the fallback. Disconnect teardown
  releases retained input state before reusing each slot's fixed DMA window.
  Hubs, other host-controller families, arbitrary HID descriptors, mass
  storage, USB audio, and isochronous transfers are not implemented.
- The HDA driver brings compatible PCI controllers to D0, validates BAR and
  stream geometry, resets the link, operates CORB/RIRB DMA, queries codec and
  function-group identity, and exposes a checked BDL/PCM stream scaffold. It
  does not yet route a codec output path or produce audible PCM. VMware SVGA II
  `15ad:0405` attachment validates the boot mode and FIFO, and the UI submits
  bounded damage `UPDATE` commands only when that frontbuffer exactly matches
  the boot framebuffer. CPU copying remains authoritative.
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
- Freestanding init, graphical desktop, opt-in window smoke, native thread
  smoke, bounded Win64 console host and fixture, shell, coreutils, editor,
  network tools, examples, `libuser`, and the C ABI runtime are packaged. The
  desktop owns one native-format backbuffer, cover-crops the exact embedded
  Sedat Bucan photo, renders one neutral bottom bar and restrained launcher,
  tracks at most 12 merged damage rectangles, consumes fixed input batches,
  and parks indefinitely when idle. Init supervises it and restores `/bin/sh`
  on missing framebuffer, clean recovery, or failure. The shell supports
  pipelines, redirection, quoting, background jobs, sessions/process groups,
  and terminal job control. The shipped `/bin/c-demo` is compiled through
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
  ordering. The PS/2 mouse runs at 4 counts/mm and 100 Hz with packet
  re-synchronization; PS/2 and USB keyboards use 250 ms/30 Hz typematic.
  Direct-root-port xHCI boot keyboards and relative mice feed the same seat.
- Kernel logging and userspace TTY output share one COM1 serialization lock, so
  exact runtime markers cannot interleave across CPUs on the physical UART.
- Syscalls 58-63 provide bounded local channels, transactional attenuated
  descriptor transfer, fixed-size zero-filled shared memory, allocation-free
  readiness waits across channel/UI sources, and dynamic-mapping `mprotect`.
  Version-1 messages carry an 80-byte header, at most 4096 inline bytes, and at
  most four transfers. Each direction has eight queue slots; the kernel admits
  at most 64 channel pairs, 16 MiB per shared object, and 64 MiB of committed
  shared memory while preserving an 8 MiB physical reserve. Shared mappings
  are permanently non-executable and all mappings obey W^X.
- Syscall 68, `spawn_restricted`, starts from an empty child descriptor table
  and installs at most 16 exact source-to-target mappings after validating the
  complete canonical 288-byte request. Rights may only attenuate; ordinary
  sources require `TRANSFER`, while a channel endpoint may be passed only to
  the immediate child with its existing nonempty `READ|WRITE` subset. Duplicate
  targets and partial publication are rejected, and the same request performs
  atomic process-group placement before the child becomes runnable.
- Descriptor rights are checked at I/O, ioctl, mapping, and transfer
  boundaries. Transfers may only attenuate existing `READ`, `WRITE`, `MAP`, and
  `TRANSFER` rights. Send publication and receive descriptor installation are
  transactional, including user-fault and descriptor-capacity rollback; drops
  that can reclaim objects occur outside the process-table lock.
- `xenith-abi::compositor` and allocation-free `libwindow` are connected to a
  bounded eight-client desktop coordinator with eight surfaces and 64 MiB of
  mapped buffers per client, plus a 256 MiB global mapping quota. It validates
  generation-safe client/surface state, configure acknowledgements, damage,
  and read-only buffers; maintains scene order/focus; routes pointer capture,
  keys, and UTF-8 text; and isolates malformed or stalled clients. Full
  client queues receive at most 50 ms of bounded backpressure before
  isolation. One wait covers UI plus all live channels without polling. The
  on-demand Files path and the opt-in `--window-smoke` path each provision a
  private live connection and use restricted spawn so the child receives
  exactly stdout, stderr, and one client endpoint. Normal boot creates no
  channel until Files is opened from the dock, launcher, or `Super+E`.
- `/bin/xenith-explorer` is a native allocation-free graphical process with
  two release-tracked shared buffers. It browses native absolute paths and the
  `C:\` namespace, sorts folders first, exposes profile shortcuts, address and
  history navigation, keyboard/mouse/wheel selection, new-folder creation,
  and confirmed file or empty-folder deletion. Its fixed limits are 1024-byte
  paths, 96 entries per directory read, and 12 history entries.
- `xenith-pe`, `xenith-winhost-core`, and `xenith-winhost` implement a bounded
  PE32+ AMD64 console path. The host accepts regular files up to 16 MiB and
  images up to 64 MiB, paths up to 1024 bytes, at most 64 bootstrap imports,
  1024 effective DIR64 writes, and 1 MiB per `WriteFile` call. Stack and heap
  reserve/commit values must be nonzero page multiples; stack reserve is capped
  at 8 MiB and heap reserve at 64 MiB. The host rejects contradictory
  `RELOCS_STRIPPED` metadata or a relocation-stripped nonpreferred placement,
  low-alignment sections whose raw file offset differs from their RVA, the COFF
  `32BIT_MACHINE`/`SYSTEM`/`UP_SYSTEM_ONLY` flags, and the optional-header
  `FORCE_INTEGRITY`/`APPCONTAINER`/`WDM_DRIVER`/`GUARD_CF` flags. It binds only
  `KERNEL32.DLL!GetStdHandle`, `WriteFile`, and `ExitProcess`, optional
  `NTDLL.DLL!RtlExitUserProcess`, and `NTDLL.DLL!NtClose`; it changes its
  materialized image from RW to final R/RW/RX mappings, and invokes the Win64
  entry point on a dedicated
  validated stack whose full accepted reserve is committed above an unmapped
  lower guard page. The source-built fixture deliberately collides its preferred
  base with the host ELF, self-checks its relocated absolute pointer before
  printing, and has passed through the booted host. This proves the bounded
  forced-rebase path, not general Windows compatibility or sandbox isolation.
- `xenith-winhost-core` catalogs 13 exact-symbol, pointer-free NT policy
  services for handles, events, mutants, semaphores, caller-clocked timers, and
  ready/zero-timeout single-object waits. Only `NtClose` is guest-wired; the
  other 12 are internal typed policy calls, not decoded x64 entry points or a
  numeric Windows-build syscall table. Blocking/alertable waits, APCs, named
  objects, security descriptors, cross-process duplication, PEB/TEB
  materialization, and Windows thread semantics remain unsupported.
- The kernel mounts a separate `/win` ramfs with O(log n) ASCII
  case-insensitive keys and case-preserving directory entries while retaining
  case-sensitive native filesystems. `C:\` maps to `/win/c`; initramfs seeds
  modern Windows/system/program/profile folders plus a `Users\Xenith` profile,
  and the PE host can open its packaged fixture through that drive path.
  Win32 path normalization, known-folder defaults, redirection policy, and a
  sorted UTF-16 environment-block builder share one bounded profile contract.
  The mount is volatile, and known-folder/environment APIs are not guest-wired;
  no NTFS, reparse, ACL, integrity-label, or full Unicode-case behavior is
  claimed.
- `xenith-windrv-core` implements allocation-free validation/state policy for
  WDM major-function and `CTL_CODE` values, generation-safe driver/device/
  request IDs, image-confined callbacks, bounded linear device stacks, request
  transitions, and rights-attenuated resource descriptors. Its inline bounds
  are 64 drivers, 255 devices, 1024 requests, and 255 grants. It is not packaged
  as a driver host and does not load `.sys` files, execute driver callbacks,
  expose hardware, materialize WDM ABI objects, enforce IOCTL buffer/access
  semantics, emulate cancel spin locks/routines, implement KMDF/UMDF, or make
  arbitrary Windows drivers work.
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
| `desktop_renders_stays_stable_and_falls_back_to_shell` | Init starts the desktop; it presents the photo-backed neutral shell, handles Super through partial damage, reaches repeated halted idle states, survives a bounded idle window, releases cleanly on recovery input, then restores the shell and terminal framebuffer | PASS (2026-07-21) |
| `super_e_launches_a_visible_file_explorer_and_desktop_cleans_it_up` | Super+E restricted-spawns the packaged Files process, presents its native surface, enters `C:\Users\Xenith\AppData` through Ctrl+L, creates `New folder` with Ctrl+Shift+N, deletes it only after two distinct Delete presses, exits cleanly, and lets the desktop restore the shell | PASS (2026-07-21) |
| External QEMU preceding-artifact xHCI boot-HID gate | A q35 VM with `i8042=off` cold-boots the preceding ISO on 3 vCPUs, binds `qemu-xhci` through MSI, enumerates `usb-kbd` and `usb-mouse`, opens the launcher from an injected Super key, moves the visible cursor, and records no QEMU guest error | PASS (2026-07-20) |
| External VMware preceding-artifact BIOS/UEFI gate | VMware Workstation cold-boots the preceding ISO with 512 MiB and 3 vCPUs under legacy BIOS and UEFI, brings 3/3 CPUs online, reaches the desktop, drives SVGA II FIFO damage updates, discovers the HDA codec through CORB/RIRB, and starts the xHCI MSI service worker | PASS (2026-07-20) |
| External VMware current-artifact UEFI gate | VMware Workstation 17.6.3 cold-boots the current ISO with 1096 MiB and 1 vCPU under UEFI, mounts the refreshed native/Windows initramfs, reaches `XENITH_DESKTOP_READY`, activates SVGA II FIFO damage, and leases IPv4 through e1000 MSI | PASS (2026-07-21) |
| `opt_in_window_client_completes_shared_buffer_protocol` | With three CPUs online, the explicit desktop smoke mode restricted-spawns one native client with only stdout/stderr/endpoint 3, maps its attenuated shared buffer, composites client pixels, completes configure/release/frame events, disconnects, and reaps the child | PASS (2026-07-21) |
| `userspace_threads_create_join_and_teardown_in_guest` | With three CPUs online, `/bin/thread-smoke` maps two private stacks, runs two simultaneous workers with distinct task IDs, joins exit codes 41/42, verifies shared atomic state, and unmaps both stacks | PASS (2026-07-20) |
| `win64_console_fixture_executes_through_booted_host` | The same packaged PE bytes execute first by native path and then as `C:\Users\Xenith\Downloads\win64-console.exe`; the latter crosses drive translation and the case-insensitive `/win` mount. Both runs validate the forced DIR64 rebase, guarded stack, console shim, exit, and restored shell prompt | PASS (2026-07-21) |
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

## Validation and artifact identity

The named runtime results above record the verified behavior boundary. Exact
sizes below identify the fresh post-change build used by the repository-owned
runtime gates. `build/ARTIFACTS.txt` remains authoritative for the files
currently in a local build directory. A parser/check-only result is never
promoted to a guest runtime result.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `build/xenith.iso` | 25,833,472 | `7BD79E62D21CBFA3ECAEDB7B824C0CB8CA50E33418AB8756143E66350D189577` |
| `build/xenith.img` | 4,386,816 | `57015662AC6F220163A7286E76C46588603AFF9714FD3F15D68D714D1B964BF8` |
| `build/kernel.elf` | 3,776,472 | `FE809E6789958FA42CDCEBA2D62A6D6DFF10B2398C01EDA97E30CF1B3D11F7EA` |
| `build/initramfs.cpio` | 586,556 | `35C61B1C81CE6C40A092F923A9D105E1E37745972E667BC1D3CDD3C67FAC62D1` |
| `build/bootloader/BOOTX64.EFI` | 624,640 | `6DC80BEA4ED048627618D7D5DCDDD8EA9238648C9BEB19458B40451124CECD0B` |
| `build/user/xenith-desktop` | 230,320 | `74CEC8855F74C7B5B465F6741D2AE38AE2DF6D12A58B9E422EFBC6BCF80C77DB` |
| `build/user/xenith-explorer` | 80,824 | `B640EBFD3146D24E275DB448AD1A5E1407635D6E84F9E7C82357167548111FA0` |

The current ISO above cold-booted in VMware Workstation 17.6.3 on 2026-07-21
using the existing 1096 MiB, 1-vCPU, UEFI/Secure-Boot-disabled VM. Its COM1
log recorded the refreshed 137-entry initramfs, Windows namespace readiness,
SVGA II FIFO damage, e1000 MSI networking with a DHCP lease, and
`XENITH_DESKTOP_READY`. The VM was powered off after the gate. This refresh did
not repeat the legacy-BIOS or wider-vCPU external matrices.

The preceding ISO
`8FCC3B663A6F6546403AE79BD2EE0C5C4897C431344FEE912D69F00BACC6E28C`
cold-booted in VMware Workstation 17.6.3 on 2026-07-20 with 512 MiB RAM and
3 vCPUs under both legacy BIOS and UEFI with Secure Boot disabled. Both
firmware paths brought all three CPUs online, initialized a
framebuffer, spawned `/init` and `/bin/xenith-desktop`, and reached
`XENITH_DESKTOP_READY` on COM1. The legacy path additionally recorded packaged
stage2 entering long mode and selecting VBE; the UEFI path executed the ISO's
EFI boot entry. Both runs attached VMware SVGA II at 1024x768x32 and activated
FIFO damage updates, discovered codec `15ad1975` through the `15ad:1977` HDA
controller with 256-entry CORB/RIRB rings, and started the VMware xHCI 1.20 MSI
service worker. VMware exposed no USB boot-HID interface in these noninteractive
runs, so the QEMU gate above remains the direct proof of USB keyboard and mouse
input rather than PS/2 fallback.

Earlier VMware legacy-BIOS cold boots passed with 1, 3, 4, 8, 16, and 24
vCPUs. QEMU 11.0.50 with SeaBIOS 1.17 also passed every integer CPU count from
1 through 64, a 64-CPU raw-image boot, and a 2-socket by 3-core topology with
non-contiguous APIC IDs. Those broader-topology external runs used the
preceding ISO
`0949DB89FEF66AAA2A83A96858A5D97F12D5561C76ADD0580352954C9ACC110F`
and raw image
`074298C35B258A57D483D769C5F638D2620FBE505A968A0700BD3E629289FE20`;
they remain historical topology evidence rather than proof of those CPU counts
on the current generated artifacts.

Native unit/integration tests also exercise the debugger protocol and GDB RSP
bridge, CPL-aware walks and interrupt entry, ATA/PCI/HPET/RTL8139 devices,
realtime signal queue ordering/overflow, COW reference lifetimes, PTY/devpts
lifecycle, SSDT namespace merging, NIC interrupt routing, and XenithFS flush
ordering.

## Remaining boundaries

- Repository-owned emulator gates prove the refreshed raw disk plus BIOS and
  UEFI ISO entries. VMware Workstation externally proves this exact ISO under
  UEFI at one vCPU; the legacy-BIOS, three-vCPU, wider VMware, and QEMU/SeaBIOS
  CPU matrices belong to preceding artifacts. None establishes
  physical-PC compatibility or coverage across arbitrary firmware; physical
  AHCI/NVMe/USB boot, NICs, physical display/input/audio, ACPI quirks, and
  cache-flush behavior remain hardware-validation work.
- The desktop coordinator implements bounded multi-client scene/focus/input
  policy, and Files plus the packaged smoke exercise private live connections.
  There is no service identity, rendezvous/admission protocol, booted
  simultaneous two-client application gate, generic GPU acceleration, page
  flipping, vsync, or general third-party application launcher. The input ABI
  also lacks enter/leave, client-requested capture, IME/composition, distinct
  logical key codes, horizontal wheel, and a dedicated key-overflow marker.
  USB input is deliberately limited to xHCI direct-root-port boot keyboards
  and relative mice; hubs, generic HID, and absolute tablets are absent.
- The PE host is deliberately limited to AMD64 console executables and five
  guest-wired imports. DLL/GUI images, TLS, SEH, delay imports, Authenticode,
  API sets, ordinal/arbitrary imports, Windows threads, registry, general
  file/process/synchronization APIs, `user32`/`gdi32`, COM, DirectX, .NET,
  installers, and WoW64 are unsupported. The 12 policy-only NT calls beyond
  `NtClose` are not guest APIs. The host is not a sandbox: loaded code shares
  its Xenith syscall authority and inherited descriptors, so only trusted
  conformance images are supported. No broad Windows-application compatibility
  is claimed.
- The seeded Windows folder hierarchy is not application compatibility by
  itself. It resets on reboot and has no guest-wired Windows `CreateFile`,
  directory, known-folder, environment, registry, loader, or shell API surface
  yet. Files reaches the hierarchy through native Xenith filesystem syscalls.
- Files currently caps one directory view at 96 entries because `read_dir`
  has no pagination contract. Rename, copy, move, drag-and-drop, file previews,
  file associations, persistent view settings, and storage persistence remain
  future application/filesystem work.
- Native Xenith threads share descriptors and an address space, but have no TLS,
  detach/cancellation API, or task-local signal state. A clean signal state is
  required before creating a second task; while multi-threaded, caught-handler,
  signal-mask, alternate-stack, `fork`, `exec`, and VM mutation operations fail
  closed. `fork` also rejects active shared mappings until true shared PTE
  semantics are implemented.
- The Windows driver policy crate is not a driver executor. An isolated host,
  checked `.sys` loader/callback ABI, IRQL and PnP/power behavior, capability-
  backed MMIO/port/interrupt/DMA bridges, framework support, and per-driver
  conformance tests are all still required.
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

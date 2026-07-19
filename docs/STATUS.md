# Status

This file records validation boundaries. A compile/test result is not a firmware or hardware result.

## Implemented and validated at build/test level

- Kernel custom-target check and strict Clippy.
- Physical/virtual memory, heap, scheduler/context switch, syscall entry, ELF/process launch, VFS/ramfs/initramfs/FAT32.
- ACPI tables plus bounded DSDT AML evaluation.
- Writable journaled XenithFS with focused memory-disk remount tests. The
  kernel, `xenith-mkfs`, and `xenith-fsck` share one `no_std` format crate;
  host-created images pass current-format superblock, journal, bitmap, inode,
  extent, and directory validation plus read-only explorer parsing.
- PS/2, CMOS, PCI/AHCI foundations, RTL8139/e1000 DMA paths, network protocols/sockets, and VT100 terminal parser.
- BIOS stage1/stage2 and UEFI loader link/format checks.
- ISO9660/El Torito and raw image construction, including an x86 hard-disk-emulation manifest image and platform-`0xEF` FAT16 EFI System Partition with exact-path payload verification.
- x86 decoder/encoder, assembler/disassembler, interpreter, WHP capability/backend ownership, debugger protocol/client, and ELF/DWARF address-to-source indexing.
- Freestanding init/shell/coreutils/editor/net/example programs, Rust `libuser`, and C ABI memory/I/O runtime.
- A converging Intel-syntax x86-64 assembler with sized memory operands,
  immediates, SIB/RIP-relative addressing, data/string/alignment/fill
  directives, and explicit rejection of false 16/32-bit modes.
- A dependency-free static ELF64 linker with page-separated PT_LOAD segments,
  `.bss` tails, W^X enforcement, executable-entry validation, and absolute-64
  plus PC-relative-32 relocations.
- A runtime C subset with signed locals, assignment, arithmetic, comparisons,
  `if`/`else`, `while`, `return`, comments/string escapes, and a freestanding
  `puts` syscall builtin. `xenith-build all` compiles
  `user/c/xenith-c-demo.c` through `xenith-cc` -> `xenith-asm` ->
  `xenith-ld`, validates its W^X ELF, and ships it as `/bin/c-demo`.

## Runtime proof

- The interpreter executes flat x86 port-I/O programs and captures serial output in tests.
- On 2026-07-19, the ignored
  `xenith_built_c_utility_executes_in_ring3` artifact gate passed against a
  fresh full build. It repacked the actual 8,214-byte
  `build/user/xenith-c-demo` as `/init`, booted `build/kernel.elf`, entered the
  ELF at ring 3, and observed `XENITH_C_TOOLCHAIN_OK` from the program's
  `write` syscall. This is runtime proof of the shipped
  C-source -> `xenith-cc` -> `xenith-asm` -> `xenith-ld` path; it does not
  infer execution merely from ELF validation.
- A subsequent 100,000,000-iteration manifest-image run launched the packaged
  `/bin/c-demo` from the interactive shell. Serial showed pid 2 spawning, two
  `XENITH_C_TOOLCHAIN_OK` lines, and a returned `xenith$` prompt. The bounded
  run ended at 99,999,959 guest instructions and 41 timer interrupts with no
  guest fault. This additionally proves lookup and execution from the shipped
  initramfs inside `build/xenith.img`.
- Bootloader parser/format/image-layout tests pass.
- On 2026-07-19, the exact ignored artifact gate
  `kernel_reaches_userspace_shell` passed with a 100,000,000-iteration bound.
  The interpreter directly loaded `build/kernel.elf` and
  `build/initramfs.cpio`; serial contained `xenith: init`, `mm: ready`,
  `scheduler: ready`, `user: init spawned`, `Xenith userspace init`, and
  `xenith$ `. This proves the direct kernel-to-init-to-shell path in
  `xenith-emu`.
- On 2026-07-19, the ignored
  `bios_firmware_image_reaches_userspace_shell` gate booted the current
  6,024-sector `build/xenith.img` with 256 MiB of modeled RAM. The
  deterministic firmware shim installed reset state at `0xffff0`, transferred
  the actual stage1 MBR to `0x7c00`, performed its LBA1/stage2 EDD contract,
  loaded the 32-sector stage2 at `0x8000`, supplied three E820 records and A20,
  reproduced the protected/long-mode page-table transition, and entered the
  packaged kernel at `0xffffffff802003d0` with a native `XenithBootInfo` at
  `0x70000`. The 100,000,000-iteration run reached `xenith$` with no guest
  fault. This proves Xenith's packaged BIOS contract through the purpose-built
  shim; it is not proof under an external BIOS or physical hardware.
- An equivalent direct CLI run with the same 100,000,000-loop budget reached
  the prompt. At the configured limit it reported 99,999,974 executed guest
  instructions and 26 LAPIC interrupts, with no guest fault.
- CPL-aware page walks, IDT gate validation, CPL3-to-CPL0 interrupt entry via
  TSS RSP0, `iretq` restoration, STI interrupt shadow, interruptible `hlt`,
  and periodic LAPIC timer/EOI behavior have focused emulator tests.
- The explicit `shell_executes_builtins_and_coreutils_via_ps2` artifact gate
  passed after the 100,000,000-loop boot gate. Deterministic PS/2 set-1 input
  exercised shell `help`, `echo`, and `pwd`, then ring-3 `echo`, `uname`, `ps`,
  `ls`, `cat`, `mkdir`, `cp`, `mv`, `rm`, and `date`. File creation,
  copy/rename/removal, and directory listing were verified through subsequent
  commands rather than inferred from process launch.
- The ignored artifact CLI gate
  `input_script_proves_shell_pipeline_and_redirection` passed on 2026-07-19
  against a fresh full build. Through real PS/2 input and ring-3 syscalls it
  created `/source` with `>`, ran `cat < /source | cat > /sink`, read the
  result back, appended with `>>`, and verified both markers without an errno
  or guest fault. Host input is retained until PS/2 is ready and injected in
  bounded 32-character slices; the kernel retains 1,024 decoded make/break
  events so multi-line startup scripts are not truncated before the shell can
  read them.
- On 2026-07-19, the ignored `manifest_image_reaches_userspace_shell` artifact
  gate and `xenith-emu --image build/xenith.img` accepted the complete
  1,966,080-byte/3,840-sector artifact, verified the LBA1 manifest plus stage2,
  kernel, and initrd payload checksums, selected the packaged kernel at LBA 40
  (1,638,232 bytes) and initrd at LBA 3,240 (303,856 bytes), attached the same
  read-only bytes as primary-master ATA media, and reached the ring-3
  `xenith$` prompt within the 100,000,000-iteration gate. It completed
  99,999,974 guest instructions and 26 timer interrupts without a guest
  fault. This proves the packaged manifest-to-direct-kernel path, not BIOS
  stage execution.
- Focused emulator tests exercise ATA IDENTIFY plus exact LBA48 PIO read/write
  and read-only rejection, legacy PCI mechanism #1 enumeration, functional
  HPET counter/one-shot delivery, RTL8139 reset/link/transmit completion, and
  framebuffer/VGA final-state rendering. A live image run enumerated four PCI
  functions and bound the kernel RTL8139 driver with MAC
  `02:58:45:4e:49:54`, link up, and one adapter online.
- A live loopback debugger smoke resolved `_start` from `kernel.elf`, stopped
  the running interpreter at `0xffffffff80200370`, single-stepped to
  `0xffffffff80200371`, read registers/status, and disconnected cleanly.
- On 2026-07-19, the debugger's ignored artifact gate passed against a freshly
  rebuilt release `kernel.elf`. The debugger indexed 571 ELF symbols, 21,967
  DWARF address ranges, and 187 source files; `_start` resolved to
  `kernel/src/main.rs:27`, and the exact printed location resolved back to
  `0xffffffff80200370`. The gate also finds and round-trips a DWARF-covered ELF
  function automatically, including a non-zero column when one is present.
- No external BIOS, UEFI firmware, ISO-catalog, or physical-hardware boot result has been recorded.
- On the same host, `xenith-vmm --probe` selected Windows Hypervisor Platform
  and created a partition with one virtual processor. This is a lifecycle
  probe only; it did not execute the guest through WHP.

## Known limits

- The green direct-loader and `--image` gates still bypass BIOS stage1/stage2.
  The separate `--bios-image` gate consumes their exact packaged bytes through
  a purpose-built reset/BIOS-service/mode-transition shim. No interpreter gate
  executes `BOOTX64.EFI` or either `xenith.iso` catalog entry.
- The ISO now structurally satisfies stage1's disk-LBA-1 manifest contract
  through a complete hard-disk-emulation image and contains a verified FAT16
  EFI System Partition. Neither catalog entry has yet been executed by BIOS or
  UEFI firmware, and stage2's primary-master ATA PIO assumption still requires
  runtime compatibility testing on the selected BIOS implementation.
- The emulator runs one interpreted CPU and explicitly rejects `--smp` values
  other than `1`. Arbitrary firmware and general 16/32-bit execution, AP
  startup, live display windows, and host-backed/inbound networking are not
  modeled. Xenith's exact BIOS image contract is covered by the deterministic
  firmware shim. ATA PIO,
  legacy PCI, HPET, an RTL8139 TX-sink/link model, raw-image manifest loading,
  32-bpp PPM output, and VGA text decoding are modeled.
  Host keyboard input is limited to the US set-1 ASCII subset; redirected
  stdin requires the explicit `--input-script` path.
- The WHP path proves capability plus partition/vCPU lifecycle ownership only;
  guest execution still runs through `xenith_emu::Machine` and is not WHP
  accelerated.
- Pure interpreter instruction coverage is smaller than the complete x86-64
  surface.
- `fork` is functional with transactional eager page copying and exact child
  register restoration; `exec` transactionally replaces the current image in
  place while preserving PID/process-tree identity. Copy-on-write fork is a
  performance follow-up. Anonymous pipes are bounded and blocking, preserve
  endpoint lifetime through `dup`/`fork`, and implement EOF, nonblocking
  `EAGAIN`, and `EPIPE`/SIGPIPE behavior. The shell supports multi-stage
  pipelines, `<`, `>`, `>>`, adjacent operators, quoting, escaping, trailing
  `&`, and bounded `jobs`/`fg`/`bg` tracking. Process sessions/groups are
  inherited across spawn/fork, group signals and negative `waitpid` selectors
  are implemented, and stopped/continued states use `WUNTRACED`/`WCONTINUED`.
  The
  console TTY implements canonical records, raw `VMIN`, CR-to-NL mapping,
  echo/erase/kill/EOF/signal controls, cursor editing, `TCGETS`/`TCSETS*`,
  `TIOCGWINSZ`, `FIONREAD`, foreground process-group ownership/signals, and all
  four POSIX noncanonical `VMIN`/`VTIME` timing combinations. `openpty` creates
  a bounded, bidirectional master/slave pair whose slave owns independent
  termios, window, foreground-group, and pending-input state. PTYs are anonymous
  raw byte transports; `/dev/pts` names and console-equivalent canonical editing
  on PTY slaves remain future work.
- Physical NICs are registered automatically and serviced by an autonomous,
  bounded polling worker. DHCPv4 installs/renews/expires interface, connected,
  default-route, gateway, and DNS state; ARP probes are rate-limited and
  bounded; TCP retains and retransmits unacknowledged data with exponential
  RTO, congestion/window limits, fast retransmit, and bounded out-of-order
  reassembly. `ifconfig`, `ping`, DNS A-record `nslookup`, HTTP/1.0
  `httpget`, and basic stream `telnet` use the live syscall/socket path. NIC
  interrupt mode, IPv6/AF_INET6, TCP SACK/window
  scaling, and DNS-over-TCP/DNSSEC remain incomplete; physical-network runtime
  validation still requires supported RTL8139/e1000 hardware or a VM backend.
- AML is DSDT-focused; XenithFS and its journal have explicit extent/directory/transaction bounds, but no hardware flush barrier.
- BIOS loader currently targets boot drive `0x80` and legacy primary-master ATA PIO; El Torito BIOS execution, AHCI/NVMe/USB boot media, and secondary boot disks are not runtime-proven.
- The bootloader, kernel, and mature Rust utilities still use the pinned
  Rust/LLVM backend. Xenith's own toolchain now builds the shipped
  `/bin/c-demo`, but it is not yet a general replacement: `xenith-asm` emits
  flat 64-bit code rather than ELF relocatable objects and lacks 16/32-bit,
  macro, x87/SIMD, and complete GNU/Intel syntax coverage; `xenith-ld` does
  not consume relocatable ELF files or archives and has no symbol-table,
  dynamic-link, TLS, linker-script, or debug-section support; `xenith-cc`
  supports one `int main` with integer locals/control flow and literal `puts`,
  but not preprocessing, pointers/arrays/structs, general functions/calls,
  division, object files, headers, or libc/coreutils-scale source.
- Debugger source support is line-table based. It does not yet expose DWARF
  variables/types, inline call stacks, unwind-based backtraces, watchpoints,
  PIE load-bias handling, or GDB RSP.

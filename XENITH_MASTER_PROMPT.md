# Xenith — Master Build Prompt (fully self-contained ecosystem)

> **This is a hand-off prompt.** Paste it whole into an agentic assistant (Codex / GPT-with-tools / another Claude) that has filesystem and shell access to the repo. It may spawn sub-agents and parallelize. Everything between the top and bottom of this file is the instruction.

Repo root: `c:/Users/Valentino/Documents/GitHub/xenith-os`

---

## 0. The one-paragraph mission

Build **Xenith**: a real, bare-metal x86_64 operating system **and a complete self-contained ecosystem around it with zero external runtime dependencies**. Not a VM, not a simulator, not a hosted toy — a genuine OS that boots on PC hardware. Critically, "own everything": we do not depend on QEMU (we write our own x86_64 emulator + type-2 hypervisor), we do not depend on Limine at runtime (we write our own bootloader + boot protocol), we do not depend on xorriso (we write our own ISO/disk-image builder), we do not depend on gdb (we write our own debugger), we do not depend on a C toolchain for userspace (we write our own libc + linker + tiny compiler), and we ship our own shell, coreutils, editor, network stack, filesystem tools, AML interpreter, and terminal emulator. The kernel is ~75% written already (~44.5k lines); your job is to **finish the kernel, then build the entire surrounding ecosystem, then make the whole workspace compile, pass clippy, and boot end-to-end inside our own emulator.**

---

## 1. Scope — what "own everything" means

| External thing we will NOT depend on | Our replacement (to build) |
|---|---|
| QEMU / KVM (for testing) | `xenith-emu`: a user-space x86_64 emulator (interpreter + optional JIT) with emulated devices, AND `xenith-vmm`: a type-2 hypervisor using VT-x (KVM-style) for near-native speed |
| Limine (bootloader + boot protocol) | `xenith-bootloader`: BIOS + UEFI stage1/stage2 bootloader in Rust+asm, plus the `XenithBootInfo` protocol; the kernel gains a `boot` abstraction supporting BOTH Limine and Xenith protocols |
| xorriso + limine-deploy (image build) | `xenith-iso`: build bootable ISO9660 and raw disk images, install our bootloader |
| NASM/GAS (assembler) | `xenith-asm`: a cross-assembler for x86_64 + a disassembler (shared encoder/decoder lib) |
| gdb (debugger) | `xenith-debug`: source-level debugger attaching to `xenith-emu`, real hardware via serial, or `xenith-vmm` |
| musl/glibc + gcc/ld (userspace toolchain) | `xenith-libc` (freestanding C lib for our userspace), `xenith-ld` (linker), `xenith-cc` (tiny C compiler), plus the existing `libuser` Rust userspace lib |
| bash + coreutils | `xenith-sh` (shell) + `xenith-coreutils` (ls/cat/cp/mv/rm/mkdir/echo/ps/kill/mount/uname/date/ed/vi) |
| (no network) | `xenith-net`: kernel TCP/IP stack + NIC drivers (RTL8139, e1000) + sockets + userspace net utils |
| (no FS tooling) | `xenith-mkfs`, `xenith-fsck`, `xenith-mount` (and our own on-disk FS `xenithfs`) |
| (ACPI without AML) | `xenith-aml`: a real AML bytecode interpreter |
| (VGA text only) | `xenith-term`: a VT100/ANSI terminal emulator on the framebuffer |
| (host test runners) | `xenith-test`: in-kernel test runner + emulator-driven integration tests (our CI uses `xenith-emu`, not QEMU) |

The kernel itself stays `#![no_std]`. The host-side tools (`xenith-emu`, `xenith-iso`, `xenith-asm`, `xenith-debug`, `xenith-cc`, `xenith-ld`, build tools) are **normal std Rust programs** — they run on the developer's machine, not in the kernel. Userspace programs (`xenith-sh`, coreutils, editor, net utils) are `#![no_std]` freestanding ELF linked against `xenith-libc`/`libuser` and run on Xenith.

---

## 2. Hard rules

1. **Kernel + userspace crates: `#![no_std]`, `core`/`alloc` only, `panic = "abort"`, never `std`.** Host-side tool crates (`tools/*`) MAY use `std` — they are developer tools, not OS code.
2. **No external runtime dependencies for booting/testing/building.** The build + test loop must work with only `rustc` (nightly) + our own tools. QEMU/Limine/xorriso may be kept only as *optional* fallback validation paths behind a feature flag, never required.
3. **Idiomatic Rust.** Match the style already in the repo. `unsafe` always wrapped in a safe API with a `// SAFETY:` comment.
4. **Errors:** hand-rolled enums implementing `Debug`, returning `Result<T, E>`. No `thiserror`/`anyhow` in kernel/userspace.
5. **Bitflags** via `xenith-bitflags` macro. **Address/page types** via `xenith-types` (read it before using).
6. **Logging** via the `log` facade.
7. **One module per file**, `mod.rs` re-exports with `pub use`. Comments explain WHY, not WHAT. No `todo!()` spam. Real implementations, 400–800 lines per file.
8. **Nightly allowed.** Features as needed: `asm`, `naked_functions`, `asm_sym`, `core_intrinsics`, `panic_info_message`, `linker_args`, `allocator_api`, `specialization` (host tools only).
9. **Every crate must `cargo check` + `cargo clippy -- -D warnings` + `cargo fmt --check` clean.**

---

## 3. Target repo layout

```
xenith-os/
├── Cargo.toml                      # workspace root (add all new members)
├── rust-toolchain.toml
├── Makefile                        # uses OUR tools, not xorriso/qemu
├── kernel/                         # the OS kernel (mostly done)
│   ├── Cargo.toml, build.rs, x86_64-xenith.json
│   └── src/{arch,mm,sync,sched,time,devices,fs,syscall,user,acpi,log,util,console,power,init,panic,test}.rs
├── crates/
│   ├── xenith-types/               # PhysAddr/VirtAddr/Page/PhysFrame  (done)
│   ├── xenith-bitflags/            # bitflags! macro                  (done)
│   ├── xenith-boot/                # boot info abstraction            (done, extend for XenithBootInfo)
│   ├── xenith-x86/                 # NEW: x86 instruction encode/decode lib (shared by emu, asm, debug)
│   └── xenith-abi/                 # NEW: shared kernel/user ABI (syscall numbers, structs, errno)
├── bootloader/                     # NEW: xenith-bootloader (BIOS + UEFI)
│   ├── stage1/  stage2/  uefi/  common/
├── emu/                            # NEW: xenith-emu (our QEMU) + xenith-vmm (VT-x hypervisor)
│   ├── xenith-emu/      xenith-vmm/   devices/   machine/
├── tools/                          # NEW: host-side build/debug tools (std)
│   ├── xenith-iso/      xenith-asm/   xenith-disasm/   xenith-debug/
│   ├── xenith-cc/       xenith-ld/    xenith-mkfs/     xenith-fsck/
│   └── xenith-build/    # orchestrates: build kernel + bootloader + userspace → bootable image
├── user/                           # userspace programs (run on Xenith)
│   ├── libuser/  libc/xenith-libc/   # Rust + C userspace libs
│   ├── init/  sh/xenith-sh/  coreutils/  editor/  net/
│   └── examples/
├── tests/
│   ├── integration/                # uses xenith-emu, not QEMU
│   └── kernel/                     # in-kernel test runner
└── docs/  scripts/  boot/  limine.conf  # docs + legacy limine fallback
```

---

## 4. Current state (already on disk — 44,516 lines of Rust)

### Done and real (kernel + foundation crates)
- **crates/xenith-types** `{lib(60), address(631), page(786), size(132)}` — `PhysAddr`, `VirtAddr`, `Page`, `PhysFrame`, `PageTableIndex`, `PageTableLevel`.
- **crates/xenith-bitflags** `lib(549)` — `bitflags!` macro.
- **crates/xenith-boot** `{lib(394), region(295)}` — Limine BootInfo wrapper, `MemoryRegion`, `phys_to_virt`.
- **kernel/src** entry/bootstrap: `main(49)`, `lib(66)`, `init(261)`, `panic(332)`, `console(315)`, `power(271)`.
- **kernel/src/log** `{mod(44), logger(357)}`.
- **kernel/src/util** `{mod(38), bitmap(720), ringbuffer(394), linked_list(794)}`.
- **kernel/src/sync** `{mod(57), spinlock(274), spinlock_irq(330), rwlock(364), mutex(233), percpu(293)}`.
- **kernel/src/arch/x86_64** `{mod(188), cpu(727), fpu(1007), gdt(928), idt(404), instructions(809), msr(166), percpu(800), port(488), registers(442), tss(329)}` + `asm/{mod(257), isr.S, context_switch.S}` + `interrupts/{mod(92), apic(988), exceptions(292), handlers(133), ioapic(979), pic(483)}`.
- **kernel/src/devices** `{mod(41), serial(254), serial_ext(575), framebuffer(415), vga(303), fb_font(348), gfx(621), pcspk(336), registry(432), driver(825)}` + `pci/{mod(483), config(600), enumerate(830)}` + `ps2/{mod(613), mouse(872)}`.
- **kernel/src/mm** `{mod(221), allocator(436), heap(1058), kmalloc(358)}` + `physical/buddy(1047)` + `virtual/{mod(99), address_space(1300), page_table(785), paging(934)}`.
- **kernel/src/sched** `{mod(174), context(471), idle(336), kthread(319), preempt(763), scheduler(1652), task(1191)}`.
- **kernel/src/syscall** `{mod(318), table(265), handlers(1195)}`.
- **kernel/src/time** `{mod(151), calibration(152), clock(456), hpet(794), lapic_timer(565), pit(467), rtc(382)}`.
- **kernel/src/user** `{mod(88), ring3(433), signal(1335)}`.
- **kernel/src/acpi** `{mod(280), shutdown(351)}`.
- Build/config/docs: `Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`, `Makefile`, `rustfmt.toml`, `clippy.toml`, `limine.conf`, `boot/limine/README.md`, `scripts/{make-iso,run-qemu,debug-qemu}.sh`, `docs/{ARCHITECTURE,BOOT_FLOW,CONTRIBUTING,RUNNING}.md`, `README.md`.

`kernel/src/lib.rs` declares top-level modules: `acpi, arch, console, devices, fs, log, mm, power, sched, sync, syscall, time, user, util, init, panic`.

### BROKEN / MISSING (kernel does NOT compile yet — fix first)
These submodule files are referenced by existing `mod.rs`/`lib.rs` but do not exist, or are whole missing subsystems:

1. `kernel/src/mm/physical/{mod.rs, bitmap.rs}` — bitmap frame allocator (sibling of `buddy.rs`).
2. `kernel/src/devices/ps2/keyboard.rs` — PS/2 keyboard (`mod.rs` + `mouse.rs` exist).
3. `kernel/src/devices/ahci/{mod.rs, hba.rs}` — AHCI skeleton.
4. `kernel/src/devices/cmos.rs` — CMOS/NVRAM.
5. `kernel/src/sched/{thread.rs, fpu.rs}` — threads + FPU state (`sched/mod.rs` declares them).
6. `kernel/src/syscall/entry.rs` + `kernel/src/arch/x86_64/asm/syscall.S` — syscall entry.
7. `kernel/src/user/{elf.rs, process.rs}` — ELF loader + userspace process.
8. `kernel/src/acpi/{rsdp.rs, rsdt.rs, xsdt.rs, fadt.rs, madt.rs, dsdt.rs}` — ACPI tables.
9. **`kernel/src/fs/` ENTIRELY MISSING** — `lib.rs` declares `pub mod fs;`. Create `mod.rs, vfs.rs, inode.rs, fd.rs, path.rs, ramfs.rs, initramfs.rs, syscalls.rs, fat/{mod,boot_sector,fat,dir,file}.rs`.
10. **`user/` ENTIRELY MISSING at repo root** — userspace crates (see WP-U).
11. Reconcile `kernel/src/devices/mod.rs` declarations (likely declares `ahci`, `cmos`, etc.) with files.
12. `kernel/src/init.rs` still calls stubbed init functions — wire the real sequence.

---

## 5. Conventions (match existing code)

- Idiomatic Rust, `#![no_std]` kernel + userspace; `std` allowed only in `tools/`, `emu/`, `bootloader/` host artifacts.
- Wrap `unsafe` in safe APIs; `// SAFETY:` on every `unsafe fn`.
- Hand-rolled error enums + `Result`; no `thiserror`/`anyhow` in no_std crates.
- Bitflags via `xenith-bitflags`; addresses/pages via `xenith-types`.
- `log::info!/warn!/error!/debug!/trace!` in the kernel.
- One module per file, `mod.rs` re-exports. WHY-comments only. Real impls 400–800 lines/file.

### Shared type cheatsheet (xenith-types)
- `PhysAddr`, `VirtAddr`: `::new(u64)->Option`, `::new_truncate(u64)`, `.as_u64()`, `.align_down(align)->Self`, `.align_up(align)->Option`, `.is_aligned(align)->bool`, `Add<u64>`, `Sub<u64>`.
- `Page`/`PhysFrame` (4 KiB): `containing_addr(...)`, `.start_address()`, `.SIZE = 4096`.
- `PageTableIndex::new(u16)->Option`, `new_truncate(u16)`, `.value()->u16`. `PageTableLevel { Four, Three, Two, One }`.

---

## 6. Work packages

**Read first, before writing anything:** `kernel/src/lib.rs`, `kernel/src/init.rs`, `kernel/src/mm/mod.rs`, `kernel/src/sched/mod.rs`, `kernel/src/syscall/mod.rs`, `kernel/src/user/mod.rs`, `kernel/src/acpi/mod.rs`, `kernel/src/devices/mod.rs`, `kernel/src/devices/ps2/mod.rs`, `crates/xenith-types/src/lib.rs`, `crates/xenith-bitflags/src/lib.rs`, `crates/xenith-boot/src/lib.rs`. Your new code must use the APIs these already expose — do not invent conflicting signatures.

### WP-K — Finish the kernel (do this first; everything else depends on it)
- **WP-K1 Memory gap:** `mm/physical/mod.rs` (`pub mod bitmap; pub mod buddy; pub fn init(boot_info); static FRAME_ALLOCATOR`), `mm/physical/bitmap.rs` (`BitmapFrameAllocator`: `allocate_frame()->Option<PhysFrame>`, `allocate_range(n)`, `deallocate`, `free_count`, `used_count`; SpinLock; built from Limine usable regions; use `util::Bitmap`).
- **WP-K2 Scheduler gap:** `sched/thread.rs` (`Thread { task, tid, state, stack, user_rsp }`; `new`, join/exit; shares address space), `sched/fpu.rs` (`FpuState` xsave; `init_fpu()` CR0.MP/CR4.OSFXSR/CR4.OSXSAVE; `save_state`/`restore_state`; lazy #NM; cpuid detect). Reuse `arch/x86_64/fpu.rs` — delegate, don't duplicate.
- **WP-K3 Syscall gap:** `arch/x86_64/asm/syscall.S` (naked `syscall_entry`: save user RSP via MSR, load kernel RSP from TSS, swapgs, push regs, call `rust_syscall_dispatch`, pop, swapgs, sysretq; export `syscall_entry`), `syscall/entry.rs` (`rust_syscall_dispatch(rax, args...) -> u64`: dispatch via `table::SYSCALLS`; ENOSYS on bad number). `syscall/mod.rs::init()` sets STAR/LSTAR/FMASK MSRs (see `arch/x86_64/msr.rs`).
- **WP-K4 User gap:** `user/elf.rs` (ELF64 parse; `load(image: &[u8], space: &mut AddressSpace) -> entry VirtAddr`: map PT_LOAD, zero BSS, alloc user stack; SAFETY), `user/process.rs` (`UserProcess { pid, address_space, threads, fd_table, parent, children, exit_status, signals }`; `ProcessId(u64)`; `spawn(path, argv) -> Pid`; `exit`, `wait`, `current_pid()`). Read `user/ring3.rs`, `user/signal.rs`, `sched/task.rs`, `mm/virtual/address_space.rs`.
- **WP-K5 ACPI gap:** `acpi/{rsdp,rsdt,xsdt,madt,fadt,dsdt}.rs`. Implement `acpi/mod.rs`'s `hpet_address()`, `madt_ioapics()`, `madt_lapics()`. RSDP via Limine EFI table or BIOS EBDA; checksum; walk XSDT/RSDT; MADT LAPIC+IOAPIC entries; FADT PM1a/b + DSDT ptr; DSDT located-only for now (the real AML interpreter is WP-A below).
- **WP-K6 Driver gaps:** `devices/ps2/keyboard.rs` (scancode set 1, US keymap, `KeyEvent`, bounded buffer, IRQ 1), `devices/ahci/{mod.rs, hba.rs}` (PCI class 0x01/0x06, map ABAR, enumerate ports, `BlockDevice` trait, `read_sector` skeletal), `devices/cmos.rs` (ports 0x70/0x71, NVRAM get/set, RTC helpers, wait update-complete).
- **WP-K7 Filesystem (entire `kernel/src/fs/`):** `mod.rs` (`pub mod vfs,inode,fd,path,ramfs,initramfs,fat,syscalls; pub fn init()`; root mount), `vfs.rs` (`VfsNode`/`FileSystem` traits, `VfsMount`, global `ROOT`), `inode.rs` (`InodeId`, `Inode`, `InodeOps`, inode cache), `fd.rs` (`FileObject`, `FdTable`, `alloc_fd/get/close/dup/dup2`, `OpenFlags`), `path.rs` (`Path`/`PathBuf` no_std, `resolve()`), `ramfs.rs` (in-memory inodes), `initramfs.rs` (cpio newc from Limine module → populate ramfs), `syscalls.rs` (open/close/read/write/lseek/stat/mkdir/chdir/getcwd), `fat/{mod,boot_sector,fat,dir,file}.rs` (FAT32 over `BlockDevice`).
- **WP-K8 Integration (after K1–K7):** reconcile every `mod.rs` declaration with on-disk files; rewrite `kernel/src/init.rs` to call the real init sequence (serial→log→console→arch::early_init→gdt→idt+exceptions→mm→apic→ioapic→hpet/pit→scheduler→devices(pci+ps2)→fs+initramfs→spawn /init) with `log::info!` + error handling; finalize `lib.rs` re-exports.
- **WP-K9 SMP bring-up:** AP boot via LAPIC INIT-SIPI-SIPI, per-CPU GDT/TSS/percpu, scheduler run queues per CPU, IPI-based resched. (Extend `arch/x86_64/percpu.rs`, `sched/scheduler.rs`, `interrupts/apic.rs`.)
- **WP-K10 Real AML interpreter:** `kernel/src/acpi/aml/` — AML bytecode parser + interpreter (opcodes, names, methods, regions, eval), enough to evaluate `_STA`/`_CRS`/`_PRT` for device discovery + IRQ routing.

### WP-B — Own bootloader (`bootloader/`, replaces Limine at runtime)
- **WP-B1 boot protocol:** `crates/xenith-boot` extended with `XenithBootInfo` (memory map, framebuffer, RSDP, modules, HHDM offset, cmdline) — same shape as Limine's so the kernel's `boot` abstraction (`kernel/src/boot.rs`) can consume either. Define in `crates/xenith-abi`.
- **WP-B2 BIOS stage1:** `bootloader/stage1/` — 512-byte MBR/VBR in asm (`boot.S`) that loads stage2 from disk; `stage1.ld`; build via `xenith-asm` or `nasm` fallback.
- **WP-B3 BIOS stage2:** `bootloader/stage2/` — real→protected→long mode, enable PAE/PGE, build identity + higher-half page tables, parse disk for kernel + modules, build `XenithBootInfo`, jump to kernel `_start`. Rust + asm.
- **WP-B4 UEFI loader:** `bootloader/uefi/` — a UEFI application (Rust, `no_std`, uses UEFI runtime services) that sets up long mode, loads kernel + modules, builds `XenithBootInfo`, exits boot services, jumps to kernel. Target `x86_64-unknown-uefi`.
- **WP-B5 bootloader installer:** `tools/xenith-iso` (see WP-T) installs stage1 to a disk image's MBR (replaces `limine-deploy`).
- **WP-B6 kernel boot abstraction:** `kernel/src/boot.rs` — `enum BootSource { Limine(&'static limine::BootInfo), Xenith(&'static XenithBootInfo) }` exposing a uniform `BootInfo` trait (memory map, framebuffer, hhdm, rsdp, modules, cmdline). `init.rs` uses this trait, not Limine directly.

### WP-E — Own x86_64 emulator + VMM (`emu/`, replaces QEMU)
The centerpiece of "own everything". Two crates:
- **WP-E1 `crates/xenith-x86`:** shared x86 instruction encode/decode library. Decoder produces a structured `Insn` enum (operands, prefixes, ModRM, immediates); encoder writes bytes. Used by emu, assembler, disassembler, debugger. Cover the rings-0..3 integer + SSE/system subset needed to boot Xenith. ~3000+ lines.
- **WP-E2 `emu/xenith-emu` core CPU:** `CpuState { regs[16], rip, rflags, segs, gdt, idt, cr0..cr4, efer, syscfg, msrs }`; an interpreter loop that decodes via `xenith-x86` and executes against `CpuState` + a `MemoryBus`. Handle real → long mode transition, paging (4-level), exceptions/interrupts (IDT dispatch), RFLAGS semantics, `syscall`/`sysret`/`swapgs`, `hlt`/`cli`/`sti`. ~5000+ lines.
- **WP-E3 `emu/xenith-emu` memory bus:** `MemoryBus` with physical RAM, MMIO dispatch, page-table walking for virtual → physical, dirty tracking, DMA regions. Loads kernel image + initramfs at configured phys addresses.
- **WP-E4 emulated devices:** `emu/devices/` — `Pic`, `IoApic`, `Lapic`(+timer), `Hpet`, `Pit`, `Serial16550` (stdio backend), `VgaText` + `Framebuffer` (ppm/sdl backend), `Ps2Kbd`/`Ps2Mouse`, `PciHost` (config space), `Ahci` (backed by a host file), `Cmos`. Each implements a `Device` trait (`read_mmio`/`write_mmio`/`read_port`/`write_port`/`tick`). Wire to `MemoryBus` + port IO.
- **WP-E5 `emu/xenith-emu` machine driver:** `Machine` configures RAM size, CPU count, devices, loads `XenithBootInfo` (or Limine-compatible struct) into guest memory, sets the entry RIP, runs the CPU loop with a timer-driven device tick. CLI: `xenith-emu --kernel <elf> --initrd <cpio> --memory 512M --smp 2 --serial stdio`.
- **WP-E6 `emu/xenith-vmm` (VT-x hypervisor):** type-2 using Intel VMX (`vmxon`/`vmlaunch`/`vmresume`), a kernel module (Linux) or a Windows hyperv-platform driver OR a self-contained host process using `Whpx`/`HVF`-style APIs — pick the most portable: implement against the **Hypervisor Platform** APIs (Windows Hypervisor Platform / macOS Hypervisor.framework) with a fallback to the pure interpreter. Guest runs near-native; used for fast CI. Same `Device` model as the interpreter.
- **WP-E7 emulator integration test harness:** `tests/integration/` drives `xenith-emu` (not QEMU): boot the kernel, capture serial, assert boot markers. This is our CI.

### WP-T — Own host build/image tools (`tools/`, replaces xorriso/limine-deploy/nasm/gdb)
- **WP-T1 `tools/xenith-iso`:** build a bootable ISO9660 image (El Torito boot catalog → our stage1/stage2) AND raw `.img` disks. Install stage1 to MBR. CLI: `xenith-iso build --kernel <elf> --initrd <cpio> --bootloader <stage1,stage2> -o xenith.iso`. No xorriso.
- **WP-T2 `tools/xenith-asm` + `tools/xenith-disasm`:** cross-assembler/disassembler built on `crates/xenith-x86`. Assembles `boot.S` and kernel asm; disassembles for the debugger. CLI tools + a lib API.
- **WP-T3 `tools/xenith-debug`:** debugger. Attaches to `xenith-emu` (via a debug IPC/socket protocol), to `xenith-vmm`, or to real hardware via serial (a gdb-remote-protocol-compatible server so *if* someone wants gdb they can, but our own TUI client is primary). Features: sw/hw breakpoints, single-step, register + memory inspect/edit, source-line mapping (DWARF), watchpoints, backtrace. TUI client.
- **WP-T4 `tools/xenith-build`:** the orchestrator. `xenith-build all` → build kernel (cargo + custom target), build bootloader (stage1/stage2/uefi), build userspace (libuser + programs → static ELF), pack initramfs (cpio), build disk image via `xenith-iso`. Replaces the Makefile's xorriso/qemu calls. The Makefile becomes a thin wrapper around `xenith-build`.
- **WP-T5 `tools/xenith-mkfs` + `tools/xenith-fsck`:** create + check `xenithfs` (our own on-disk FS) and FAT32 images.
- **WP-T6 `tools/xenith-cc` + `tools/xenith-ld`:** a tiny freestanding-C compiler (subset: enough to build coreutils + libc) and a static linker producing our userspace ELF. (Stretch: if too large, implement `xenith-ld` first and reuse `crates/xenith-x86`; `xenith-cc` can compile a C subset to our ELF.)

### WP-U — Own userspace (`user/`, runs on Xenith)
- **WP-U1 `user/libuser` (Rust userspace lib):** `Cargo.toml`, `src/{lib,syscall,io,string,stdio,args,env}.rs`. Raw `syscall` instruction + wrappers (read/write/open/close/exit/brk/mmap/munmap/getpid/yield/nanosleep/fork/exec/waitpid/stat/lseek/dup/dup2/pipe/chdir/getcwd/uname/ioctl). `print!`/`println!` via write to fd 1.
- **WP-U2 `user/libc/xenith-libc` (C userspace lib):** freestanding C runtime (memcpy/memset/strlen/printf/malloc over `mmap`) + the syscall wrappers as C functions, with headers, so `xenith-cc`-compiled programs link against it.
- **WP-U3 `user/init`:** `_start` prints banner, fork+exec `/bin/sh`, reaps zombies, loops.
- **WP-U4 `user/sh` (`xenith-sh`):** read line, parse argv, builtins (echo/ls/cat/ps/help/exit/pwd/cd), fork+exec externals with waitpid, prompt, pipelines + redirections (stretch).
- **WP-U5 `user/coreutils`:** `ls, cat, cp, mv, rm, mkdir, rmdir, echo, ps, kill, mount, umount, uname, date, sleep, head, tail, wc, ln, touch, chmod, chown(stub), env, true, false`. One binary per util or a multicall `busybox`-style binary.
- **WP-U6 `user/editor`:** a tiny `ed`-line-editor + a minimal `vi`-like screen editor (uses termios-equivalent syscalls + the framebuffer terminal).
- **WP-U7 `user/net`:** `xenith-net` userspace — `ping`, `ifconfig`, `telnet`/`httpget` (stretch) over the kernel socket API.
- **WP-U8 `user/examples`:** `hello`, `cat`, `ls` minimal programs.
- **WP-U9 `scripts/build-user.sh` → replaced by `tools/xenith-build`:** cross-compile all user crates as static freestanding ELF, pack into `build/initramfs.cpio`.

### WP-N — Own network stack (`kernel/src/net/` + drivers)
- **WP-N1 kernel net core:** `net/{mod,socket,tcp,udp,ip,arp,icmp,eth,loopback}.rs` — a TCP/IP stack (LWIP-ish), socket layer exposed via syscalls (socket/bind/listen/accept/connect/send/recv).
- **WP-N2 NIC drivers:** `devices/net/{rtl8139, e1000}.rs` — PCI NIC drivers (ring buffers, DMA, link state).
- **WP-N3 loopback + routing:** a routing table, loopback interface, DHCP client (stretch).

### WP-FS — Own on-disk filesystem (`kernel/src/fs/xenithfs/` + tools)
- **WP-FS1 `xenithfs` design + impl:** extent-based, journaling (stretch), symlinks, permissions; `fs/xenithfs/{mod,sb,inode,extent,journal,dir}.rs`. Mountable via VFS.
- **WP-FS2 tools:** `tools/xenith-mkfs --type xenithfs`, `tools/xenith-fsck`.

### WP-Term — Own terminal emulator (`kernel/src/devices/term.rs` + `user/editor` uses it)
- **WP-Term1 `xenith-term`:** VT100/ANSI/xterm escape-sequence parser + renderer on the framebuffer (cursor, scroll regions, colors, alt screen). Backs the kernel console + the screen editor.

### WP-Docs-Tests-CI — Docs, tests, CI (all using OUR tools)
- **WP-D1 docs:** `docs/{SUBSYSTEMS, MEMORY_MAP, SYSCALL_ABI, DRIVERS, BOOT_PROTOCOL, EMULATOR, BUILD, ROADMAP, STATUS}.md`. MEMORY_MAP = virtual layout (user 0..0x0000_7FFF_FFFF_FFFF, HHDM 0xFFFF_8000_0000_0000, kernel image/stack/heap) + physical map. SYSCALL_ABI = numbers, arg registers (rdi/rsi/rdx/r10/r8), return convention, errno table. BOOT_PROTOCOL = `XenithBootInfo` layout. EMULATOR = how `xenith-emu` works + device list. BUILD = `xenith-build` usage.
- **WP-D2 in-kernel tests:** `kernel/src/test.rs` behind `cfg(test_kernel)` — `#[kernel_test]` registry, runs over serial, PASS/FAIL.
- **WP-D3 integration tests:** `tests/integration/` drives `xenith-emu` (NOT QEMU): boot, assert serial markers (`xenith: init`, `mm: ready`, `scheduler: ready`, `user: init spawned`). `tests/integration/tests/{boot, shell, smoke}.rs`.
- **WP-D4 CI:** `.github/workflows/ci.yml` — install nightly Rust (from `rust-toolchain.toml`); `cargo build` kernel + workspace; `tools/xenith-build all`; run `xenith-emu` boot smoke test; `cargo clippy -- -D warnings`; `cargo fmt --check`. No QEMU/xorriso/limine install steps (we use our own tools). Keep an *optional* `qemu-fallback` job behind a feature flag for cross-validation only.
- **WP-D5 finalize `Makefile`:** thin wrapper — `make all` → `cargo run -p xenith-build -- all`; `make run` → `xenith-emu --kernel build/xenith --initrd build/initramfs.cpio`; `make iso` → `xenith-iso build ...`; `make test`, `make clippy`, `make fmt`, `make docs`, `make clean`. Remove xorriso/qemu hard deps.
- **WP-D6 finalize `README.md` + `docs/STATUS.md` + `docs/ROADMAP.md`.**

---

## 7. Parallelization plan

Wave 1 (parallel, file-disjoint): **WP-K1..K7** (kernel gaps), **WP-B1** (boot protocol ABI), **WP-E1** (xenith-x86 lib), **WP-T2** (asm/disasm, depends on E1 so after), **WP-U1..U3** (libuser + init + shell), **WP-N1..N2**, **WP-FS1**, **WP-Term1**, **WP-D1**.

Wave 2 (after Wave 1): **WP-K8** (integration/compile-fix — needs all kernel files), **WP-K9** (SMP), **WP-K10** (AML), **WP-B2..B6** (bootloader stages + kernel boot abstraction), **WP-E2..E7** (emu core + devices + vmm + test harness), **WP-T1,T3,T4,T5,T6** (iso/debug/build/mkfs/cc), **WP-U4..U9** (coreutils/editor/net/examples), **WP-FS2**, **WP-D2..D6**.

Wave 3 (final): full-workspace `cargo check` + `cargo clippy -- -D warnings` + `cargo fmt --check`; boot the kernel in `xenith-emu`; fix all remaining issues.

If the assistant cannot parallelize, do strictly: WP-K (all) → WP-E1 → WP-B → WP-E2..7 → WP-T → WP-U → WP-N → WP-FS → WP-Term → WP-D.

---

## 8. Acceptance criteria

1. Every module declared in every `mod.rs`/`lib.rs` has its file(s) on disk — no "file not found for module" errors.
2. `cargo check` passes for **the entire workspace** (kernel + all crates + tools + emu + bootloader + user) with appropriate targets (custom target for kernel/user; native for tools/emu).
3. `cargo clippy -- -D warnings` clean across the workspace.
4. `cargo fmt --check` clean.
5. `tools/xenith-build all` produces: kernel ELF, bootloader (stage1/stage2/uefi), userspace ELFs, `initramfs.cpio`, and a bootable `xenith.iso` / `xenith.img` — **without invoking xorriso, limine-deploy, nasm, or QEMU**.
6. `xenith-emu --kernel build/xenith --initrd build/initramfs.cpio` boots Xenith, prints the init log sequence, and spawns `/init` → `/bin/sh` (the shell prompt appears on the emulated serial). This replaces QEMU for testing.
7. `tests/integration` (driving `xenith-emu`) passes the boot + shell smoke tests — this is the CI gate.
8. `kernel/src/init.rs` wires the real init sequence (no stub init calls for subsystems that now exist).
9. The kernel boots from **our own bootloader** (BIOS stage2 and/or UEFI) producing `XenithBootInfo`; Limine remains an optional alternative path.
10. `xenith-asm` assembles the bootloader/kernel asm; `xenith-debug` can attach to `xenith-emu`, set a breakpoint at `_start`, and single-step.
11. Userspace: `xenith-sh` + at least `ls, cat, echo, ps, mkdir, rm, cp, mv, uname, date` coreutils run on Xenith inside the emulator.
12. Total codebase: ~90k–120k lines of real, idiomatic, coherent Rust (currently 44.5k; the ecosystem adds ~50–75k).
13. Docs complete per WP-D1; CI per WP-D4 uses only our tools.

---

## 9. Target boot flow (fully self-hosted)

```
Power on
  → xenith-bootloader stage1 (MBR, 512B asm) loads stage2 from disk
  → stage2: real → protected → long mode; page tables + HHDM; read kernel + initramfs from disk;
            build XenithBootInfo; jump to kernel _start (higher-half)
   OR
  → xenith-bootloader UEFI: set up long mode, load kernel+modules, XenithBootInfo, ExitBootServices, jump
  → kernel _start(boot_info)  [boot_info is &XenithBootInfo or &limine::BootInfo via boot abstraction]
  → xenith_kernel::init(boot_info)
      serial → log → console (framebuffer via xenith-term or VGA)
      arch::early_init → gdt → idt + exceptions
      mm (physical bitmap+buddy, virtual paging, address space, heap)
      apic (x2apic) → ioapic → pic-disabled → hpet/pit → lapic timer → clock
      scheduler init → idle tasks → kthread
      acpi (rsdp→xsdt→madt/fadt; AML eval for device discovery)
      devices: pci enumerate → drivers (ahci, nic, ps2 kbd/mouse, rng, cmos)
      net stack init (if NIC present)
      fs init → mount ramfs root → initramfs::load (cpio) → mount xenithfs (if disk)
      syscall init (STAR/LSTAR/FMASK)
      spawn /init (ELF load → ring3 jump_to_user)
  → /init: banner → fork+exec /bin/sh → reap
  → /bin/sh: prompt on serial/framebuffer terminal → coreutils work
```

For development/testing, the same kernel binary is booted inside **`xenith-emu`** (our emulator) instead of on metal, with the emulated devices standing in for real hardware. `xenith-build` + `xenith-iso` produce the bootable image; `xenith-emu` runs it; `xenith-debug` inspects it. **No QEMU, no Limine, no xorriso, no gdb required.**

---

## 10. How to start (concrete first actions)

1. `cd c:/Users/Valentino/Documents/GitHub/xenith-os` and read every file listed at the top of §6.
2. Run `cargo check` (with `-Z build-std=core,alloc,compiler_builtins --target kernel/x86_64-xenith.json` for the kernel; plain `cargo check` for host crates) to see the current error list — the missing-module errors are your first targets.
3. Create the WP-K missing files (§4 list). Re-run `cargo check` after each batch. Iterate to zero errors.
4. Add the new workspace members to the root `Cargo.toml` and create the new crate skeletons (`crates/xenith-x86`, `crates/xenith-abi`, `bootloader/`, `emu/xenith-emu`, `emu/xenith-vmm`, `tools/*`, `user/libc/xenith-libc`, `user/coreutils`, `user/editor`, `user/net`, `kernel/src/net/`, `kernel/src/fs/xenithfs/`, `kernel/src/acpi/aml/`, `kernel/src/devices/term.rs`, `kernel/src/devices/net/`).
5. Dispatch the work packages per §7. Build bottom-up: `xenith-x86` → `xenith-emu` core → devices → machine; `xenith-abi` → bootloader + kernel boot abstraction; `libuser`/`xenith-libc` → init/shell/coreutils.
6. Wire `tools/xenith-build` to orchestrate the whole build; replace the Makefile's external-tool calls.
7. Boot in `xenith-emu`; iterate until the shell prompt appears.
8. Clippy + fmt + integration tests green.

---

## 11. Final report to produce

When done, report:
- Files created/modified (grouped by work package), with line counts.
- Final total line count (target ~90k–120k).
- `cargo check` result (whole workspace).
- `cargo clippy -- -D warnings` result.
- `cargo fmt --check` result.
- `xenith-build all` output artifact list.
- `xenith-emu` boot log excerpt showing init sequence + shell prompt.
- `tests/integration` pass/fail.
- A `docs/STATUS.md` summary of what boots, what works, what's stubbed, known issues.

Begin now. Read first, then build. Make it real — no simulations of simulations, no hosted toys. Xenith boots on metal and inside its own emulator, built by its own tools.

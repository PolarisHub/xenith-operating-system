# Xenith

Xenith is a freestanding x86_64 operating-system workspace. It contains a `no_std` kernel and userspace, a lightweight glassy desktop shell, BIOS and UEFI loaders, a deterministic SMP x86 interpreter, a multi-vCPU Windows Hypervisor Platform runner, image/filesystem/assembler/debugger tools, and a dependency-free C/assembly/static-link toolchain that builds a shipped userspace utility.

The default build path does not invoke QEMU, Limine, xorriso, NASM, GCC, GDB, or a system C library. Limine files remain only as a compatibility path.

## Build

The repository pins `nightly-2026-07-01`. Install its source component and the two bootloader targets once:

```text
rustup component add rust-src clippy rustfmt --toolchain nightly-2026-07-01
rustup target add x86_64-unknown-none x86_64-unknown-uefi --toolchain nightly-2026-07-01
cargo run -p xenith-build -- all
```

`xenith-build all` compiles the BIOS/UEFI bootloader, kernel, Rust userspace, and `user/c/xenith-c-demo.c` through `xenith-cc`/`xenith-asm`/`xenith-ld`, packs the initramfs, then writes the raw BIOS layout `build/xenith.img` and a hybrid ISO9660/El Torito image with BIOS hard-disk emulation plus a FAT16 EFI System Partition at `build/xenith.iso`. See [STATUS](docs/STATUS.md) for the separate runtime-proof boundary of each artifact.

Run the kernel directly in the interpreter:

```text
cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --serial stdio --max-instructions 100000000
```

The thin Makefile exposes the same paths as `make all`, `make run`, `make test`, `make clippy`, and `make fmt-check`.

## Components

- `kernel/`: x86_64 kernel, scheduler, virtual memory, VFS, AML, XenithFS, drivers, networking, terminal, syscalls, and ELF processes.
- `bootloader/`: 512-byte stage1 with the `0x55AA` BIOS boot signature, long-mode stage2, and `BOOTX64.EFI`.
- `emu/`: deterministic SMP interpreter/device/firmware model plus a Windows Hypervisor Platform runner that executes the same built kernel and shared device bus.
- `crates/`: boot/ABI/address/bitflag support and shared x86 decoder/encoder.
- `tools/`: build, ISO/disk, assembler/disassembler, debugger, linker/compiler, and filesystem utilities.
- `user/`: allocation-free desktop shell, `libuser`, C ABI runtime, init, terminal shell, coreutils, editor, network utilities, and examples.
- `tests/integration/`: emulator-driven tests; the full built-kernel boot test is an explicit artifact gate.

## Validation

Kernel and userspace require their separate custom targets and build-std flags; host tools use the native target. CI checks the complete workspace, runs host/kernel/bootloader tests and strict Clippy, builds every artifact with `xenith-build all`, then gates the desktop render/input/idle/recovery lifecycle as well as direct, packaged-image, BIOS-stage, UEFI, SMP, shell/coreutils, pipeline, C-toolchain, and debugger execution in Xenith's own emulator.

See [BUILD](docs/BUILD.md), [TOOLCHAIN](docs/TOOLCHAIN.md), [EMULATOR](docs/EMULATOR.md), [BOOT_PROTOCOL](docs/BOOT_PROTOCOL.md), [DESKTOP_FOUNDATION](docs/DESKTOP_FOUNDATION.md), and [STATUS](docs/STATUS.md). `STATUS.md` distinguishes compile-tested code from emulator-, firmware-, or hardware-tested behavior.

## License

MIT OR Apache-2.0.

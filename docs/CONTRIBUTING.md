# Contributing

Preserve subsystem ownership and validation boundaries.

- Kernel, bootloader runtime, and userspace remain `no_std`; host `tools/` and `emu/` may use `std`.
- Use `xenith-types` for addresses/pages, `xenith-bitflags` for kernel flags, `xenith-abi` for wire layouts, `xenith-fs-format` for XenithFS disk structures, and the kernel logger for diagnostics.
- Unsafe operations require a local `SAFETY` explanation and a safe API that states its invariants.
- Parsers validate sizes, counts, offsets, overflow, checksums, and recursion/work bounds before dereference or allocation.
- Unsupported instructions, opcodes, devices, filesystems, or protocols return explicit errors. Do not silently emulate them as success.
- Keep changes compatible with existing public contracts unless the associated callers are migrated in the same change.

Run formatting and stack-matched validation:

```text
cargo fmt --all -- --check
cargo clippy -p xenith-kernel --lib --bin xenith --target kernel/x86_64-xenith.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
cargo clippy -p xenith-init -p xenith-sh -p xenith-coreutils -p xenith-editor -p xenith-net -p xenith-examples -p xenith-libc --target user/x86_64-xenith-user.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
cargo test --target x86_64-pc-windows-msvc -p limine -p xenith-types -p xenith-bitflags -p xenith-boot -p xenith-abi -p xenith-fs-format -p xenith-x86 -p xenith-emu -p xenith-vmm -p xenith-asm -p xenith-disasm -p xenith-iso -p xenith-build -p xenith-mkfs -p xenith-fsck -p xenith-mount -p xenith-ld -p xenith-cc -p xenith-debug -p xenith-integration -p xenith-libc
cargo test -p xenith-kernel --lib --target x86_64-pc-windows-msvc
```

`make check`, `make test`, `make clippy`, and `make fmt-check` additionally
cover the standalone stage1, stage2, and UEFI workspaces with their matching
host or freestanding targets. Run `make integration` after `xenith-build all`
when changing boot, emulator, userspace, image, or debugger behavior.

Before describing a feature as booting or hardware-tested, run the corresponding image/emulator/firmware gate and record the exact result in `docs/STATUS.md`. Parser unit tests, Cargo check, and successful linking are necessary but do not prove runtime behavior.

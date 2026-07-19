.PHONY: all build bootloader userspace image iso run test integration clippy fmt fmt-check docs clean

all build:
	cargo run -p xenith-build -- all

bootloader:
	cargo run -p xenith-build -- bootloader

userspace:
	cargo run -p xenith-build -- userspace

image iso:
	cargo run -p xenith-build -- image

run: all
	cargo run -p xenith-emu -- --kernel build/kernel.elf --initrd build/initramfs.cpio --memory 512M --serial stdio --max-instructions 100000000

test:
	cargo test -p xenith-fs-format -p xenith-x86 -p xenith-emu -p xenith-iso -p xenith-asm -p xenith-build -p xenith-mkfs -p xenith-fsck -p xenith-mount -p xenith-ld -p xenith-cc -p xenith-integration

integration: all
	cargo test -p xenith-integration --test boot kernel_reaches_userspace_shell -- --ignored --exact
	cargo test -p xenith-integration --test shell shell_executes_builtins_and_coreutils_via_ps2 -- --ignored --exact

clippy:
	cargo clippy --workspace --exclude xenith-kernel --exclude xenith-init --exclude xenith-sh --exclude xenith-coreutils --exclude xenith-editor --exclude xenith-net --exclude xenith-examples --exclude xenith-libc --all-targets -- -D warnings
	cargo clippy -p xenith-kernel --lib --bin xenith --target kernel/x86_64-xenith.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
	cargo clippy -p xenith-init -p xenith-sh -p xenith-coreutils -p xenith-editor -p xenith-net -p xenith-examples -p xenith-libc --target user/x86_64-xenith-user.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

docs:
	cargo doc --workspace --exclude xenith-kernel --no-deps

clean:
	cargo run -p xenith-build -- clean
	cargo clean

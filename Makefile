.PHONY: all build bootloader userspace image iso run check test integration clippy fmt fmt-check docs clean

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

check:
	cargo check --workspace --all-targets
	cargo check --manifest-path bootloader/stage1/Cargo.toml --all-targets
	cargo check --manifest-path bootloader/stage2/Cargo.toml --release --target x86_64-unknown-none --features bios-bin --lib --bin xenith-stage2
	cargo check --manifest-path bootloader/uefi/Cargo.toml --release --target x86_64-unknown-uefi --features uefi-app --lib --bin xenith-bootx64

test:
	cargo test --workspace
	cargo test --manifest-path bootloader/common/Cargo.toml
	cargo test --manifest-path bootloader/stage1/Cargo.toml
	cargo test --manifest-path bootloader/stage2/Cargo.toml --features host-tool
	cargo test --manifest-path bootloader/uefi/Cargo.toml

integration: all
	cargo test -p xenith-debug --test dwarf_artifact built_kernel_supports_bidirectional_dwarf_line_lookup -- --ignored --exact
	cargo test -p xenith-integration --test boot kernel_reaches_userspace_shell -- --ignored --exact
	cargo test -p xenith-integration --test shell shell_executes_builtins_and_coreutils_via_ps2 -- --ignored --exact
	cargo test -p xenith-integration --test shell ring3_ui_smoke_restores_framebuffer_terminal -- --ignored --exact
	cargo test -p xenith-integration --test desktop desktop_renders_stays_stable_and_falls_back_to_shell -- --ignored --exact
	cargo test -p xenith-integration --test desktop opt_in_window_client_completes_shared_buffer_protocol -- --ignored --exact
	cargo test -p xenith-integration --test winhost win64_console_fixture_executes_through_booted_host -- --ignored --exact
	cargo test -p xenith-integration --test shell userspace_threads_create_join_and_teardown_in_guest -- --ignored --exact
	cargo test -p xenith-emu --test image_boot manifest_image_reaches_userspace_shell -- --ignored --exact
	cargo test -p xenith-emu --test image_boot bios_firmware_image_reaches_userspace_shell -- --ignored --exact
	cargo test -p xenith-emu --test image_boot bios_firmware_image_reaches_shell_with_64_mib -- --ignored --exact
	cargo test -p xenith-emu --test image_boot bios_iso_catalog_entry_executes_packaged_stages_then_semantic_shell -- --ignored --exact
	cargo test -p xenith-emu --test image_boot uefi_iso_executes_packaged_pe_and_reaches_userspace_shell -- --ignored --exact
	cargo test -p xenith-emu --test cli_input input_script_proves_shell_pipeline_and_redirection -- --ignored --exact
	cargo test -p xenith-emu --test c_toolchain xenith_built_c_utility_executes_in_ring3 -- --ignored --exact
	cargo test -p xenith-emu --test smp_boot two_processor_kernel_brings_ap_online_and_reaches_shell -- --ignored --exact
	cargo test -p xenith-emu --test smp_boot three_processor_kernel_brings_every_ap_online_and_reaches_shell -- --ignored --exact

clippy:
	cargo clippy --workspace --exclude xenith-kernel --exclude xenith-init --exclude xenith-sh --exclude xenith-coreutils --exclude xenith-editor --exclude xenith-net --exclude xenith-examples --exclude xenith-libc --all-targets -- -D warnings
	cargo clippy -p xenith-kernel --lib --bin xenith --target kernel/x86_64-xenith.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
	cargo clippy -p xenith-init -p xenith-desktop -p xenith-winhost-core -p xenith-windrv-core -p xenith-winhost -p xenith-sh -p xenith-coreutils -p xenith-editor -p xenith-net -p xenith-examples -p xenith-libc --target user/x86_64-xenith-user.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
	cargo clippy --manifest-path bootloader/stage1/Cargo.toml --all-targets -- -D warnings
	cargo clippy --manifest-path bootloader/stage2/Cargo.toml --release --target x86_64-unknown-none --features bios-bin --lib --bin xenith-stage2 -- -D warnings
	cargo clippy --manifest-path bootloader/uefi/Cargo.toml --release --target x86_64-unknown-uefi --features uefi-app --lib --bin xenith-bootx64 -- -D warnings

fmt:
	cargo fmt --all
	cargo fmt --manifest-path bootloader/stage1/Cargo.toml --all
	cargo fmt --manifest-path bootloader/stage2/Cargo.toml --all
	cargo fmt --manifest-path bootloader/uefi/Cargo.toml --all

fmt-check:
	cargo fmt --all -- --check
	cargo fmt --manifest-path bootloader/stage1/Cargo.toml --all -- --check
	cargo fmt --manifest-path bootloader/stage2/Cargo.toml --all -- --check
	cargo fmt --manifest-path bootloader/uefi/Cargo.toml --all -- --check

docs:
	cargo doc --workspace --exclude xenith-kernel --no-deps

clean:
	cargo run -p xenith-build -- clean
	cargo clean

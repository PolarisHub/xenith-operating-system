use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=stage2.ld");
    println!("cargo:rerun-if-changed=src/entry.S");
    let target = env::var("TARGET").unwrap_or_default();
    let enabled = env::var_os("CARGO_FEATURE_BIOS_BIN").is_some();
    if enabled && target == "x86_64-unknown-none" {
        let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("stage2.ld");
        println!(
            "cargo:rustc-link-arg-bin=xenith-stage2=-T{}",
            script.display()
        );
        println!("cargo:rustc-link-arg-bin=xenith-stage2=-nostdlib");
        println!("cargo:rustc-link-arg-bin=xenith-stage2=-no-pie");
        println!("cargo:rustc-link-arg-bin=xenith-stage2=--build-id=none");
    }
}

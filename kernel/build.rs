//! Prepare hand-written assembly for Rust's integrated assembler.
//!
//! `global_asm!` keeps kernel builds self-contained on hosts without a C
//! compiler. The sources only need simple constant definitions, handled here
//! before Rust compiles the crate.

use std::fs;
use std::path::{Path, PathBuf};

const ASM_DIR: &str = "src/arch/x86_64/asm";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(test_kernel)");
    let asm_dir = Path::new(ASM_DIR);
    println!("cargo:rerun-if-changed={}", asm_dir.display());

    let mut files = collect_asm_files(asm_dir);
    files.sort();

    let mut combined = String::new();
    let target_msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|env| env == "msvc");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        combined.push_str("\n/* source: ");
        combined.push_str(&path.display().to_string());
        combined.push_str(" */\n");
        combined.push_str(&preprocess(&source, target_msvc));
    }

    let out_dir = std::env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR");
    let output = PathBuf::from(out_dir).join("xenith_asm.S");
    fs::write(&output, combined)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", output.display()));
}

fn collect_asm_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();

    let mut files = Vec::new();
    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            files.extend(collect_asm_files(&path));
        } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "S") {
            files.push(path);
        }
    }
    files
}

fn preprocess(source: &str, target_msvc: bool) -> String {
    let mut output = String::new();

    for line in source.lines() {
        let directive = line.trim_start();
        // LLVM's COFF assembler accepts the actual AT&T instructions and
        // symbol globals but not ELF-only symbol metadata. Omitting `.type`
        // and `.size` makes the same sources usable by host unit tests while
        // preserving them for the freestanding ELF kernel target.
        if target_msvc && (directive.starts_with(".type ") || directive.starts_with(".size ")) {
            continue;
        }
        if let Some(rest) = directive.strip_prefix("#define ") {
            let mut fields = rest.split_whitespace();
            let name = fields.next().expect("#define without a name");
            let value = fields.collect::<Vec<_>>().join(" ");
            output.push_str(".equ ");
            output.push_str(name);
            output.push_str(", ");
            output.push_str(&value);
            output.push('\n');
            continue;
        }
        if directive.starts_with("#include ") {
            panic!("assembly #include is not supported: {directive}");
        }
        output.push_str(line);
        output.push('\n');
    }

    output
}

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    if let Err(error) = run() {
        eprintln!("xenith-stage1: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let output = match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => PathBuf::from("stage1.bin"),
        (Some(flag), Some(path), None) if flag == "-o" || flag == "--output" => path.into(),
        _ => return Err("usage: xenith-stage1 [-o stage1.bin]".into()),
    };
    let sector = xenith_stage1_builder::build_boot_sector()?;
    fs::write(&output, sector)?;
    println!("wrote {} ({} bytes)", output.display(), sector.len());
    Ok(())
}

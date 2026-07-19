use std::path::PathBuf;

use xenith_build::{
    build_all, build_bootloader, build_images, build_kernel, build_userspace, pack_initramfs,
    Layout,
};

fn usage() -> &'static str {
    "xenith-build <all|bootloader|kernel|userspace|image|clean> [--root PATH]"
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xenith-build: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "all".to_owned());
    let mut root = None;
    while let Some(argument) = args.next() {
        if argument == "--root" {
            root = Some(PathBuf::from(args.next().ok_or("--root requires a path")?));
        } else {
            return Err(format!("unknown argument {argument:?}\n{}", usage()).into());
        }
    }
    let start = root.unwrap_or(std::env::current_dir()?);
    let layout = Layout::discover(&start)?;
    match command.as_str() {
        "all" => {
            let artifacts = build_all(&layout)?;
            println!("Xenith build complete ({} artifacts):", artifacts.len());
            for artifact in artifacts {
                println!("  {}", artifact.display());
            }
        },
        "kernel" => println!("{}", build_kernel(&layout)?.display()),
        "bootloader" => {
            for artifact in build_bootloader(&layout)? {
                println!("{}", artifact.display());
            }
        },
        "userspace" => {
            let programs = build_userspace(&layout)?;
            let archive = pack_initramfs(&layout, &programs)?;
            println!("{}", archive.display());
        },
        "image" => {
            let kernel = layout.output.join("kernel.elf");
            let initrd = layout.output.join("initramfs.cpio");
            for path in build_images(&layout, &kernel, &initrd)? {
                println!("{}", path.display());
            }
        },
        "clean" => {
            if layout.output.is_dir() {
                std::fs::remove_dir_all(&layout.output)?;
            }
        },
        "help" | "--help" | "-h" => println!("{}", usage()),
        _ => return Err(usage().into()),
    }
    Ok(())
}

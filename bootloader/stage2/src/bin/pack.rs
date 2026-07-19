use std::path::PathBuf;
use std::{env, fs};

use xenith_boot_common::Elf64;
use xenith_stage2::{BIOS_MAX_TRANSFER_SECTORS, BIOS_SECTOR_SIZE, STAGE2_LOAD_ADDRESS};

fn main() {
    if let Err(error) = run() {
        eprintln!("xenith-stage2-pack: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let input = PathBuf::from(arguments.next().ok_or("missing input ELF")?);
    let output = PathBuf::from(arguments.next().ok_or("missing output path")?);
    if arguments.next().is_some() {
        return Err("usage: xenith-stage2-pack <stage2-elf> <stage2.bin>".into());
    }
    let image = fs::read(&input)?;
    let elf = Elf64::parse(&image).map_err(|error| format!("invalid stage2 ELF: {error:?}"))?;
    let (start, end) = elf
        .physical_span()
        .map_err(|error| format!("invalid stage2 span: {error:?}"))?;
    if start != STAGE2_LOAD_ADDRESS {
        return Err(format!("stage2 must start at physical 0x{STAGE2_LOAD_ADDRESS:x}").into());
    }
    let span = usize::try_from(end - start)?;
    let padded = span
        .checked_add(BIOS_SECTOR_SIZE as usize - 1)
        .ok_or("stage2 size overflow")?
        / BIOS_SECTOR_SIZE as usize
        * BIOS_SECTOR_SIZE as usize;
    let sectors = padded as u64 / BIOS_SECTOR_SIZE;
    if sectors > BIOS_MAX_TRANSFER_SECTORS {
        return Err(format!(
            "stage2 requires {sectors} sectors; BIOS stage1 supports at most {BIOS_MAX_TRANSFER_SECTORS}"
        )
        .into());
    }
    let mut flat = vec![0_u8; padded];
    for segment in elf.load_segments() {
        let segment = segment.map_err(|error| format!("invalid segment: {error:?}"))?;
        let destination = usize::try_from(segment.physical_address - start)?;
        let bytes = segment
            .file_bytes(&image)
            .map_err(|error| format!("invalid segment bytes: {error:?}"))?;
        flat[destination..destination + bytes.len()].copy_from_slice(bytes);
    }
    fs::write(&output, &flat)?;
    println!(
        "wrote {} ({} bytes, {} sectors)",
        output.display(),
        flat.len(),
        sectors
    );
    Ok(())
}

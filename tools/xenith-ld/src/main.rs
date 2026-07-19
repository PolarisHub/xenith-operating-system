use std::path::{Path, PathBuf};
use std::process::ExitCode;

use xenith_ld::{
    link_flat, link_static, LinkOptions, SegmentFlags, StaticLinkOptions, StaticSection,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-ld: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut output = None;
    let mut flat_inputs = Vec::<PathBuf>::new();
    let mut text = None;
    let mut rodata = None;
    let mut data = None;
    let mut bss = None;
    let mut base_address = 0x0040_0000;
    let mut entry_offset = 0;
    let mut writable = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-o" => output = Some(PathBuf::from(arguments.next().ok_or("-o needs a path")?)),
            "--base" => {
                base_address = parse_u64(&arguments.next().ok_or("--base needs an address")?)?
            },
            "--entry-offset" => {
                entry_offset = parse_u64(&arguments.next().ok_or("--entry-offset needs a value")?)?
            },
            "--text" => text = Some(next_path(&mut arguments, "--text")?),
            "--rodata" => rodata = Some(next_path(&mut arguments, "--rodata")?),
            "--data" => data = Some(next_path(&mut arguments, "--data")?),
            "--bss" => bss = Some(parse_u64(&arguments.next().ok_or("--bss needs a size")?)?),
            "--writable" => writable = true,
            "--help" | "-h" => {
                println!(
                    "xenith-ld -o ELF --text TEXT.bin [--rodata FILE] [--data FILE] [--bss SIZE]\n\
                                [--base ADDRESS] [--entry-offset N]\n\
                     legacy: xenith-ld -o ELF [--writable] INPUT.bin..."
                );
                return Ok(());
            },
            value if value.starts_with('-') => return Err(format!("unknown option {value}")),
            value => flat_inputs.push(PathBuf::from(value)),
        }
    }
    let output = output.ok_or("missing -o ELF")?;
    let section_mode = text.is_some() || rodata.is_some() || data.is_some() || bss.is_some();
    let image = if section_mode {
        if !flat_inputs.is_empty() {
            return Err("positional flat inputs cannot be mixed with section options".to_owned());
        }
        if writable {
            return Err("--writable only applies to legacy flat linking".to_owned());
        }
        link_sections(
            text.ok_or("static section mode requires --text FILE")?,
            rodata,
            data,
            bss,
            base_address,
            entry_offset,
        )?
    } else {
        if flat_inputs.is_empty() {
            return Err("no input payloads".to_owned());
        }
        let mut code = Vec::new();
        for input in flat_inputs {
            code.extend(read(&input)?);
        }
        link_flat(&code, LinkOptions {
            base_address,
            entry_offset,
            writable,
        })
        .map_err(|error| error.to_string())?
    };
    std::fs::write(&output, image).map_err(|error| format!("{}: {error}", output.display()))
}

fn next_path(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<PathBuf, String> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{option} needs a path"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn link_sections(
    text_path: PathBuf,
    rodata_path: Option<PathBuf>,
    data_path: Option<PathBuf>,
    bss_size: Option<u64>,
    base_address: u64,
    entry_offset: u64,
) -> Result<Vec<u8>, String> {
    let text = read(&text_path)?;
    let rodata = rodata_path.as_deref().map(read).transpose()?;
    let data = data_path.as_deref().map(read).transpose()?;
    let mut sections = vec![StaticSection {
        name: ".text",
        data: &text,
        memory_size: text.len() as u64,
        flags: SegmentFlags::READ | SegmentFlags::EXECUTE,
    }];
    if let Some(bytes) = rodata.as_deref() {
        sections.push(StaticSection {
            name: ".rodata",
            data: bytes,
            memory_size: bytes.len() as u64,
            flags: SegmentFlags::READ,
        });
    }
    if let Some(bytes) = data.as_deref() {
        sections.push(StaticSection {
            name: ".data",
            data: bytes,
            memory_size: bytes.len() as u64,
            flags: SegmentFlags::READ | SegmentFlags::WRITE,
        });
    }
    if let Some(size) = bss_size {
        sections.push(StaticSection {
            name: ".bss",
            data: &[],
            memory_size: size,
            flags: SegmentFlags::READ | SegmentFlags::WRITE,
        });
    }
    link_static(&sections, &[], StaticLinkOptions {
        base_address,
        entry_section: 0,
        entry_offset,
    })
    .map(|image| image.bytes)
    .map_err(|error| error.to_string())
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse(), |hex| u64::from_str_radix(hex, 16))
        .map_err(|_| format!("invalid integer {value}"))
}

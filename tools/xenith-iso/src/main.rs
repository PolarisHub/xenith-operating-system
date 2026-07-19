use std::path::{Path, PathBuf};
use std::{env, fmt, fs, process};

use xenith_iso::{
    build_disk_image_with_layout, build_iso_image_with_layout, ImageError, IsoConfig,
};

const HELP: &str = "\
xenith-iso - dependency-free Xenith boot image builder

USAGE:
  xenith-iso iso   --kernel FILE --initrd FILE --uefi FILE --bios-disk FILE -o FILE [--volume-id ID]
  xenith-iso disk  --kernel FILE --initrd FILE --stage1 FILE --stage2 FILE -o FILE
  xenith-iso build --kernel FILE --initrd FILE --uefi FILE --bootloader STAGE1,STAGE2 -o FILE

COMMANDS:
  iso      Build a BIOS/UEFI El Torito ISO with manifest disk and FAT16 ESP.
  disk     Build a raw MBR image with the Xenith LBA1 manifest.
  build    Infer iso/disk from -o (.iso or .img), or use --format iso|disk.

OPTIONS:
  --kernel FILE       Kernel payload stored as KERNEL.ELF on ISO or in the manifest.
  --initrd FILE       Initramfs payload stored as INITRD.CPIO on ISO or in the manifest.
  --uefi FILE         BOOTX64.EFI installed at EFI/BOOT/BOOTX64.EFI in the ISO ESP.
  --bios-disk FILE    Complete Xenith manifest raw disk embedded for BIOS boot.
  --boot-image FILE   Backward-compatible alias for --bios-disk.
  --stage1 FILE       Exactly 512-byte MBR stage1; combined with stage2 and payloads.
  --stage2 FILE       BIOS stage2 payload.
  --bootloader VALUE  A comma-separated STAGE1,STAGE2 pair.
  --format FORMAT     Explicit build format: iso or disk.
  --volume-id ID      ISO volume ID (default XENITH; uppercase A-Z, 0-9, _).
  -o, --output FILE   Destination image.
  -h, --help          Show this help.
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Auto,
    Iso,
    Disk,
}

#[derive(Debug, Default)]
struct Arguments {
    format: Option<OutputFormat>,
    kernel: Option<PathBuf>,
    initrd: Option<PathBuf>,
    uefi: Option<PathBuf>,
    bios_disk: Option<PathBuf>,
    stage1: Option<PathBuf>,
    stage2: Option<PathBuf>,
    bootloader: Option<String>,
    output: Option<PathBuf>,
    volume_id: Option<String>,
}

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

impl From<ImageError> for CliError {
    fn from(error: ImageError) -> Self {
        Self(error.to_string())
    }
}

fn main() {
    match run() {
        Ok(()) => {},
        Err(error) => {
            eprintln!("xenith-iso: {error}");
            eprintln!("try 'xenith-iso --help' for usage");
            process::exit(2);
        },
    }
}

fn run() -> Result<(), CliError> {
    let raw: Vec<String> = env::args().skip(1).collect();
    if raw.is_empty()
        || raw
            .iter()
            .any(|argument| argument == "-h" || argument == "--help")
    {
        print!("{HELP}");
        return Ok(());
    }

    let arguments = parse_arguments(&raw)?;
    let output = arguments
        .output
        .as_deref()
        .ok_or_else(|| CliError("missing required -o/--output".to_owned()))?;
    let format = resolve_format(&arguments, output)?;
    let kernel = read_required("kernel", arguments.kernel.as_deref())?;
    let initrd = read_required("initrd", arguments.initrd.as_deref())?;

    match format {
        OutputFormat::Iso => build_iso(&arguments, output, &kernel, &initrd),
        OutputFormat::Disk => build_disk(&arguments, output, &kernel, &initrd),
        OutputFormat::Auto => Err(CliError("could not determine output format".to_owned())),
    }
}

fn parse_arguments(raw: &[String]) -> Result<Arguments, CliError> {
    let mut arguments = Arguments::default();
    let mut index = 0;
    if let Some(command) = raw.first().filter(|value| !value.starts_with('-')) {
        arguments.format = Some(match command.as_str() {
            "iso" => OutputFormat::Iso,
            "disk" | "img" => OutputFormat::Disk,
            "build" => OutputFormat::Auto,
            _ => return Err(CliError(format!("unknown command {command:?}"))),
        });
        index = 1;
    }

    while index < raw.len() {
        let option = raw[index].as_str();
        let value = option_value(raw, &mut index, option)?;
        match option {
            "--kernel" => set_once(&mut arguments.kernel, PathBuf::from(value), option)?,
            "--initrd" => set_once(&mut arguments.initrd, PathBuf::from(value), option)?,
            "--uefi" => set_once(&mut arguments.uefi, PathBuf::from(value), option)?,
            "--bios-disk" | "--boot-image" => {
                set_once(&mut arguments.bios_disk, PathBuf::from(value), option)?
            },
            "--stage1" => set_once(&mut arguments.stage1, PathBuf::from(value), option)?,
            "--stage2" => set_once(&mut arguments.stage2, PathBuf::from(value), option)?,
            "--bootloader" => set_once(&mut arguments.bootloader, value.to_owned(), option)?,
            "-o" | "--output" => set_once(&mut arguments.output, PathBuf::from(value), option)?,
            "--volume-id" => set_once(&mut arguments.volume_id, value.to_owned(), option)?,
            "--format" => {
                let format = match value {
                    "iso" => OutputFormat::Iso,
                    "disk" | "img" => OutputFormat::Disk,
                    _ => return Err(CliError(format!("unknown output format {value:?}"))),
                };
                if arguments
                    .format
                    .is_some_and(|current| current != OutputFormat::Auto)
                {
                    return Err(CliError(
                        "--format conflicts with the selected subcommand".to_owned(),
                    ));
                }
                arguments.format = Some(format);
            },
            _ => return Err(CliError(format!("unknown option {option:?}"))),
        }
    }
    Ok(arguments)
}

fn option_value<'a>(
    raw: &'a [String],
    index: &mut usize,
    option: &str,
) -> Result<&'a str, CliError> {
    if !option.starts_with('-') {
        return Err(CliError(format!(
            "unexpected positional argument {option:?}"
        )));
    }
    let value = raw
        .get(*index + 1)
        .ok_or_else(|| CliError(format!("{option} requires a value")))?;
    *index += 2;
    Ok(value)
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), CliError> {
    if slot.replace(value).is_some() {
        return Err(CliError(format!("{option} was specified more than once")));
    }
    Ok(())
}

fn resolve_format(arguments: &Arguments, output: &Path) -> Result<OutputFormat, CliError> {
    if let Some(format) = arguments
        .format
        .filter(|format| *format != OutputFormat::Auto)
    {
        return Ok(format);
    }
    let extension = output
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("iso") => Ok(OutputFormat::Iso),
        Some("img" | "disk" | "raw") => Ok(OutputFormat::Disk),
        _ if arguments.bios_disk.is_some() || arguments.uefi.is_some() => Ok(OutputFormat::Iso),
        _ if arguments.stage1.is_some() || arguments.stage2.is_some() => Ok(OutputFormat::Disk),
        _ => Err(CliError(
            "build requires --format iso|disk or an .iso/.img output extension".to_owned(),
        )),
    }
}

fn build_iso(
    arguments: &Arguments,
    output: &Path,
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(), CliError> {
    let bios_disk = read_iso_bios_disk(arguments, kernel, initrd)?;
    let bootx64 = read_required("uefi", arguments.uefi.as_deref())?;
    let config = IsoConfig {
        volume_id: arguments
            .volume_id
            .clone()
            .unwrap_or_else(|| "XENITH".to_owned()),
    };
    let (image, layout) =
        build_iso_image_with_layout(&bios_disk, &bootx64, kernel, initrd, &config)?;
    write_output(output, &image)?;
    println!(
        "wrote {}: {} bytes, {} ISO blocks, BIOS LBA {}, EFI LBA {}, kernel LBA {}, initrd LBA {}",
        output.display(),
        image.len(),
        layout.total_blocks,
        layout.bios_boot_image_lba,
        layout.efi_boot_image_lba,
        layout.kernel_lba,
        layout.initrd_lba
    );
    Ok(())
}

fn build_disk(
    arguments: &Arguments,
    output: &Path,
    kernel: &[u8],
    initrd: &[u8],
) -> Result<(), CliError> {
    if arguments.bios_disk.is_some() {
        return Err(CliError(
            "--bios-disk/--boot-image is ISO-only; use --stage1 and --stage2 for a raw disk"
                .to_owned(),
        ));
    }
    if arguments.uefi.is_some() {
        return Err(CliError("--uefi is ISO-only".to_owned()));
    }
    if arguments.volume_id.is_some() {
        return Err(CliError("--volume-id is ISO-only".to_owned()));
    }
    let (stage1, stage2) = read_disk_bootloader(arguments)?;
    let (image, layout) = build_disk_image_with_layout(&stage1, &stage2, kernel, initrd)?;
    write_output(output, &image)?;
    println!(
        "wrote {}: {} bytes, {} sectors, stage2 LBA {}+{}, kernel LBA {}+{}, initrd LBA {}+{}",
        output.display(),
        image.len(),
        layout.total_sectors,
        layout.stage2.start_lba,
        layout.stage2.sector_count,
        layout.kernel.start_lba,
        layout.kernel.sector_count,
        layout.initrd.start_lba,
        layout.initrd.sector_count
    );
    Ok(())
}

fn read_iso_bios_disk(
    arguments: &Arguments,
    kernel: &[u8],
    initrd: &[u8],
) -> Result<Vec<u8>, CliError> {
    let explicit_pair = arguments.stage1.is_some() || arguments.stage2.is_some();
    let selected = usize::from(arguments.bios_disk.is_some())
        + usize::from(arguments.bootloader.is_some())
        + usize::from(explicit_pair);
    if selected != 1 {
        return Err(CliError(
            "ISO requires exactly one of --bios-disk, --bootloader, or --stage1/--stage2"
                .to_owned(),
        ));
    }

    if let Some(path) = arguments.bios_disk.as_deref() {
        return read_file("BIOS disk", path);
    }
    let (stage1, stage2) = read_disk_bootloader(arguments)?;
    xenith_iso::build_disk_image(&stage1, &stage2, kernel, initrd).map_err(Into::into)
}

fn read_disk_bootloader(arguments: &Arguments) -> Result<(Vec<u8>, Vec<u8>), CliError> {
    if arguments.bootloader.is_some() && (arguments.stage1.is_some() || arguments.stage2.is_some())
    {
        return Err(CliError(
            "use either --bootloader STAGE1,STAGE2 or --stage1/--stage2, not both".to_owned(),
        ));
    }
    let (stage1_path, stage2_path) = if let Some(specification) = arguments.bootloader.as_deref() {
        let (stage1, stage2) = split_bootloader_pair(specification)?;
        (Path::new(stage1), Path::new(stage2))
    } else {
        let stage1 = arguments
            .stage1
            .as_deref()
            .ok_or_else(|| CliError("raw disk requires --stage1".to_owned()))?;
        let stage2 = arguments
            .stage2
            .as_deref()
            .ok_or_else(|| CliError("raw disk requires --stage2".to_owned()))?;
        (stage1, stage2)
    };
    Ok((
        read_file("stage1", stage1_path)?,
        read_file("stage2", stage2_path)?,
    ))
}

fn split_bootloader_pair(specification: &str) -> Result<(&str, &str), CliError> {
    let (stage1, stage2) = specification.split_once(',').ok_or_else(|| {
        CliError("raw disk --bootloader must be a comma-separated STAGE1,STAGE2 pair".to_owned())
    })?;
    if stage1.is_empty() || stage2.is_empty() || stage2.contains(',') {
        return Err(CliError(
            "--bootloader must contain exactly two non-empty paths".to_owned(),
        ));
    }
    Ok((stage1, stage2))
}

fn read_required(label: &str, path: Option<&Path>) -> Result<Vec<u8>, CliError> {
    let path = path.ok_or_else(|| CliError(format!("missing required --{label}")))?;
    read_file(label, path)
}

fn read_file(label: &str, path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| {
        CliError(format!(
            "could not read {label} {}: {error}",
            path.display()
        ))
    })
}

fn write_output(path: &Path, image: &[u8]) -> Result<(), CliError> {
    fs::write(path, image).map_err(|error| {
        CliError(format!(
            "could not write output {}: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_command_infers_format_from_extension() {
        let arguments = parse_arguments(&[
            "build".to_owned(),
            "--kernel".to_owned(),
            "kernel".to_owned(),
            "--initrd".to_owned(),
            "initrd".to_owned(),
            "--bootloader".to_owned(),
            "stage1,stage2".to_owned(),
            "-o".to_owned(),
            "xenith.iso".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            resolve_format(&arguments, arguments.output.as_deref().unwrap()).unwrap(),
            OutputFormat::Iso
        );
    }

    #[test]
    fn explicit_subcommand_rejects_conflicting_format() {
        let result = parse_arguments(&["iso".to_owned(), "--format".to_owned(), "disk".to_owned()]);
        assert!(result.is_err());
    }
}

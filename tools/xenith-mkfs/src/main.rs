use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("xenith-mkfs: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut kind = "xenithfs".to_owned();
    let mut size = 64 * 1024 * 1024u64;
    let mut label = "XENITH".to_owned();
    let mut output = None::<PathBuf>;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--type" | "-t" => kind = args.next().ok_or("--type requires a value")?,
            "--size" | "-s" => size = parse_size(&args.next().ok_or("--size requires a value")?)?,
            "--label" | "-L" => label = args.next().ok_or("--label requires a value")?,
            "-o" | "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            },
            "-h" | "--help" => {
                println!("xenith-mkfs --type xenithfs|fat32 --size 64M --label NAME -o IMAGE");
                return Ok(());
            },
            value if !value.starts_with('-') && output.is_none() => output = Some(value.into()),
            _ => return Err(format!("unknown argument {argument:?}").into()),
        }
    }
    let output = output.ok_or("output image path is required")?;
    let bytes = match kind.as_str() {
        "xenithfs" => xenith_mkfs::format_xenithfs(size, &label)?.0,
        "fat32" | "fat" => xenith_mkfs::format_fat32(size, &label)?,
        _ => return Err(format!("unsupported filesystem {kind:?}").into()),
    };
    std::fs::write(&output, &bytes)?;
    println!(
        "formatted {} bytes as {kind} at {}",
        bytes.len(),
        output.display()
    );
    Ok(())
}

fn parse_size(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let (number, scale) = match value.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1024),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1024 * 1024),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 1024 * 1024 * 1024),
        _ => (value, 1),
    };
    Ok(number
        .parse::<u64>()?
        .checked_mul(scale)
        .ok_or("size overflow")?)
}

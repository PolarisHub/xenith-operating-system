use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use xenith_mount::{Error, Explorer, MAX_IMAGE_BYTES};

const USAGE: &str = "\
xenith-mount - bounded, read-only filesystem image explorer

USAGE:
    xenith-mount inspect <image>
    xenith-mount list <image> [image-path]
    xenith-mount extract <image> <image-path> -o <host-file>

The source image is never modified. Extraction refuses to overwrite an
existing host file. This is an image explorer, not a live OS mount.";

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("xenith-mount: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), Error> {
    let Some(command) = arguments.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };
    if matches!(command, "-h" | "--help" | "help") {
        print_usage();
        return Ok(());
    }
    match command {
        "inspect" => {
            if arguments.len() != 2 {
                return Err(Error::InvalidPath("inspect expects exactly one image"));
            }
            let image = read_image(Path::new(&arguments[1]))?;
            let inspection = Explorer::parse(&image)?.inspect();
            println!("filesystem={}", inspection.filesystem.as_str());
            println!("label={}", inspection.label.as_deref().unwrap_or("<none>"));
            println!("logical_block_size={}", inspection.logical_block_size);
            println!("total_bytes={}", inspection.total_bytes);
            println!("root_identifier={}", inspection.root_identifier);
            println!("access=image-explorer-read-only");
        },
        "list" => {
            if !(2..=3).contains(&arguments.len()) {
                return Err(Error::InvalidPath(
                    "list expects an image and optional path",
                ));
            }
            let image = read_image(Path::new(&arguments[1]))?;
            let path = arguments.get(2).map_or("/", String::as_str);
            for entry in Explorer::parse(&image)?.list(path)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    entry.kind.marker(),
                    entry.size,
                    entry.identifier,
                    entry.path.escape_default()
                );
            }
        },
        "extract" => {
            let (image_path, source_path, output_path) = parse_extract(&arguments)?;
            let image = read_image(&image_path)?;
            let contents = Explorer::parse(&image)?.read_file(&source_path)?;
            write_new_file(&output_path, &contents)?;
            println!(
                "extracted {} bytes to {}",
                contents.len(),
                output_path.display()
            );
        },
        _ => return Err(Error::InvalidPath("unknown command; use --help")),
    }
    Ok(())
}

fn parse_extract(arguments: &[String]) -> Result<(PathBuf, String, PathBuf), Error> {
    if arguments.len() != 5 || arguments[3] != "-o" {
        return Err(Error::InvalidPath(
            "extract expects <image> <image-path> -o <host-file>",
        ));
    }
    Ok((
        PathBuf::from(&arguments[1]),
        arguments[2].clone(),
        PathBuf::from(&arguments[4]),
    ))
}

fn read_image(path: &Path) -> Result<Vec<u8>, Error> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(Error::Unsupported("non-file image input"));
    }
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(Error::LimitExceeded("image size exceeds 8 GiB"));
    }
    fs::read(path).map_err(Error::from)
}

fn write_new_file(path: &Path, contents: &[u8]) -> Result<(), Error> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(contents)?;
    output.flush()?;
    Ok(())
}

fn print_usage() {
    println!("{USAGE}");
}

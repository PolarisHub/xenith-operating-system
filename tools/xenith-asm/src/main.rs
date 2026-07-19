use std::process::ExitCode;
use std::{env, fs};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-asm: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = None;
    let mut output = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-o" | "--output" => output = Some(arguments.next().ok_or("missing output path")?),
            "--help" | "-h" => {
                println!("xenith-asm <input.S> -o <output.bin>");
                return Ok(());
            },
            value if input.is_none() => input = Some(value.to_string()),
            value => return Err(format!("unexpected argument {value}").into()),
        }
    }
    let input = input.ok_or("missing input file")?;
    let output = output.ok_or("missing -o <output>")?;
    let source = fs::read_to_string(input)?;
    let binary = xenith_asm::assemble(&source)?;
    fs::write(output, binary)?;
    Ok(())
}

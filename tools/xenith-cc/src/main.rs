use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-cc: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut input = None;
    let mut output = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-o" => output = Some(arguments.next().ok_or("-o needs a path")?),
            "--help" | "-h" => {
                println!("xenith-cc INPUT.c -o OUTPUT.elf");
                return Ok(());
            },
            value if value.starts_with('-') => return Err(format!("unknown option {value}")),
            value if input.is_none() => input = Some(value.to_owned()),
            value => return Err(format!("unexpected input {value}")),
        }
    }
    let input = input.ok_or("missing input C file")?;
    let output = output.ok_or("missing -o OUTPUT.elf")?;
    let source = std::fs::read_to_string(&input).map_err(|error| format!("{input}: {error}"))?;
    let elf = xenith_cc::compile(&source).map_err(|error| error.to_string())?;
    std::fs::write(&output, elf).map_err(|error| format!("{output}: {error}"))
}

use std::io::{self, BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::{env, fs};

use xenith_debug::{CommandTranslator, DebugClient, PreparedCommand, SymbolTable};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-debug: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut address = "127.0.0.1:9000".to_string();
    let mut symbol_path = None;
    let mut commands = Vec::new();
    let mut script_path = None;
    let mut offline = false;
    let mut load_bias = None;
    let mut gdb_listen = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--connect" => address = arguments.next().ok_or("--connect needs an address")?,
            "--symbols" => symbol_path = Some(arguments.next().ok_or("--symbols needs an ELF")?),
            "--load-bias" => {
                let value = arguments.next().ok_or("--load-bias needs an address")?;
                load_bias = Some(parse_address(&value)?);
            },
            "--command" | "-c" => commands.push(arguments.next().ok_or("--command needs text")?),
            "--script" => script_path = Some(arguments.next().ok_or("--script needs a path")?),
            "--lookup" => {
                let expression = arguments.next().ok_or("--lookup needs an expression")?;
                commands.push(format!("lookup {expression}"));
                offline = true;
            },
            "--offline" => offline = true,
            "--gdb-listen" => {
                gdb_listen = Some(arguments.next().ok_or("--gdb-listen needs an address")?)
            },
            "--help" | "-h" => {
                print_help();
                return Ok(());
            },
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    if let Some(path) = script_path {
        commands.extend(
            fs::read_to_string(path)?
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string),
        );
    }
    if load_bias.is_some() && symbol_path.is_none() {
        return Err("--load-bias requires --symbols".into());
    }
    if gdb_listen.is_some() && (offline || !commands.is_empty()) {
        return Err(
            "--gdb-listen cannot be combined with --offline, --command, or --script".into(),
        );
    }
    let symbols = symbol_path
        .map(|path| {
            SymbolTable::load(path)
                .and_then(|symbols| symbols.with_load_bias(load_bias.unwrap_or(0)))
        })
        .transpose()?;
    let translator = CommandTranslator::new(symbols);
    if offline {
        if commands.is_empty() {
            return Err("--offline requires --lookup, --command, or --script".into());
        }
        for command in commands {
            match translator.prepare(&command)? {
                PreparedCommand::Local(output) => println!("{output}"),
                PreparedCommand::Empty => {},
                PreparedCommand::Remote(_) => {
                    return Err(
                        format!("remote command is unavailable with --offline: {command}").into(),
                    );
                },
            }
        }
        return Ok(());
    }
    let mut client = DebugClient::connect(&address)?;
    if let Some(listen) = gdb_listen {
        xenith_debug::rsp::serve_tcp(client, &listen)?;
        return Ok(());
    }
    if !commands.is_empty() {
        for command in commands {
            if execute(&translator, &mut client, &command)? {
                break;
            }
        }
        return Ok(());
    }

    let interactive = io::stdin().is_terminal();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        if interactive {
            eprint!("xenith-debug> ");
            io::stderr().flush()?;
        }
        let Some(line) = lines.next() else {
            break;
        };
        let line = line?;
        match execute(&translator, &mut client, &line) {
            Ok(true) => break,
            Ok(false) => {},
            Err(error) => eprintln!("error: {error}"),
        }
    }
    Ok(())
}

fn execute(
    translator: &CommandTranslator,
    client: &mut DebugClient,
    input: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    match translator.prepare(input)? {
        PreparedCommand::Remote(command) => {
            let quit = command == "quit";
            let response = client.command(&command)?;
            println!("{}", translator.format_response(&command, &response));
            if response.starts_with("error ") {
                return Err(response.into());
            }
            Ok(quit)
        },
        PreparedCommand::Local(output) => {
            println!("{output}");
            Ok(false)
        },
        PreparedCommand::Empty => Ok(false),
    }
}

fn parse_address(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"));
    if let Some(hex) = parsed {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}

fn print_help() {
    println!(
        "xenith-debug [--connect 127.0.0.1:9000] [--symbols kernel.elf] [--load-bias ADDRESS] [--command 'break _start']... [--script commands.txt]"
    );
    println!("xenith-debug --connect 127.0.0.1:9000 --gdb-listen 127.0.0.1:9001");
    println!("xenith-debug --symbols kernel.elf --lookup ADDRESS|SYMBOL|FILE:LINE[:COLUMN]");
    println!("commands: break/delete, watch/unwatch/watchpoints, step, continue [N], backtrace/bt [N], registers, reg/setreg, read/write, breakpoints, status, symbol, lookup, source/where, info, quit");
    println!("break/delete/read/write/lookup accept an address, symbol[+offset], or DWARF file:line[:column]; --offline runs local lookup/info commands without an emulator");
    println!("--gdb-listen exposes a bounded single-client GDB RSP bridge; run `target remote 127.0.0.1:9001` in GDB");
}

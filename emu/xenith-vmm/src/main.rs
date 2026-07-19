use std::process::ExitCode;
use std::time::Duration;
use std::{env, fs};

use xenith_emu::{ExitReason, Machine, MachineConfig, MAX_EMULATED_CPUS};
use xenith_vmm::{preferred_backend, Backend, WhpPartition, WhpRunReason};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xenith-vmm: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut kernel_path = None;
    let mut initrd_path = None;
    let mut config = MachineConfig::default();
    let mut force_interpreter = false;
    let mut probe = false;
    let mut timeout = Duration::from_secs(30);
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--kernel" => kernel_path = Some(arguments.next().ok_or("--kernel needs a path")?),
            "--initrd" => initrd_path = Some(arguments.next().ok_or("--initrd needs a path")?),
            "--memory" => {
                config.memory_bytes = parse_size(&arguments.next().ok_or("--memory needs a size")?)?
            },
            "--smp" => {
                config.cpu_count = arguments
                    .next()
                    .ok_or("--smp needs a count")?
                    .parse()
                    .map_err(|_| "invalid CPU count")?
            },
            "--interpreter" => force_interpreter = true,
            "--timeout-ms" => {
                let milliseconds = arguments
                    .next()
                    .ok_or("--timeout-ms needs a duration")?
                    .parse::<u64>()
                    .map_err(|_| "invalid timeout")?;
                if milliseconds == 0 {
                    return Err("timeout must be greater than zero".to_owned());
                }
                timeout = Duration::from_millis(milliseconds);
            },
            "--probe" => probe = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            },
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !(1..=MAX_EMULATED_CPUS).contains(&config.cpu_count) {
        return Err(format!("CPU count must be in 1..={MAX_EMULATED_CPUS}"));
    }
    if probe {
        if config.cpu_count != 1 {
            return Err(
                "--probe is a one-VP instruction proof and requires --smp 1; use --kernel for multi-VP execution"
                    .to_owned(),
            );
        }
        println!("preferred backend: {:?}", preferred_backend());
        if WhpPartition::is_available() {
            let mut partition = WhpPartition::create(1).map_err(|error| error.to_string())?;
            println!(
                "created WHP partition with {} virtual processor(s)",
                partition.processor_count()
            );
            let proof = partition
                .run_execution_probe()
                .map_err(|error| error.to_string())?;
            println!(
                "executed WHP guest code: {} exits, OUT {:#06x} <- {:#04x}, then HLT",
                proof.exits, proof.port, proof.value
            );
        } else {
            println!("WHP unavailable; interpreter fallback selected");
        }
        return Ok(());
    }
    let backend = if force_interpreter {
        Backend::Interpreter
    } else {
        preferred_backend()
    };
    let kernel_path = kernel_path.ok_or("missing --kernel <ELF>")?;
    let kernel =
        fs::read(&kernel_path).map_err(|error| format!("cannot read {kernel_path}: {error}"))?;
    let initrd = initrd_path
        .as_deref()
        .map(fs::read)
        .transpose()
        .map_err(|error| format!("cannot read initrd: {error}"))?;
    let processor_count = u32::try_from(config.cpu_count).map_err(|_| "CPU count is too large")?;
    let execution_limit = config.instruction_limit;
    let mut machine = Machine::new(config);
    machine
        .load_kernel(&kernel, initrd.as_deref())
        .map_err(|error| error.to_string())?;
    if backend == Backend::WindowsHypervisorPlatform {
        let mut partition =
            WhpPartition::create_machine(processor_count).map_err(|error| error.to_string())?;
        let summary = partition
            .run_machine(&mut machine, timeout, execution_limit)
            .map_err(|error| error.to_string())?;
        eprintln!(
            "\nxenith-vmm: WHP {:?} after {} exits",
            summary.reason, summary.exits
        );
        match summary.reason {
            WhpRunReason::Halted | WhpRunReason::ShellReady => Ok(()),
            other => Err(format!(
                "WHP guest did not reach the shell prompt: {other:?}"
            )),
        }
    } else {
        let summary = machine.run();
        eprintln!(
            "\nxenith-vmm: interpreter {:?} after {} instructions",
            summary.reason, summary.instructions
        );
        match summary.reason {
            ExitReason::Halted | ExitReason::Breakpoint(_) => Ok(()),
            other => Err(format!("guest did not complete: {other:?}")),
        }
    }
}

fn parse_size(value: &str) -> Result<usize, String> {
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1024usize),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1024usize * 1024),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 1024usize * 1024 * 1024),
        _ => (value, 1),
    };
    number
        .parse::<usize>()
        .map_err(|_| format!("invalid size {value}"))?
        .checked_mul(multiplier)
        .ok_or_else(|| "size overflow".to_string())
}

fn print_help() {
    println!(
        "xenith-vmm --kernel <ELF> [--initrd <CPIO>] [--memory 128M] [--smp N] [--timeout-ms 30000] [--interpreter]"
    );
    println!("xenith-vmm --probe [--smp N]  # execute a WHP memory/register/I/O/HLT proof");
}

use std::fs::File;
use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::{env, fs};

use xenith_emu::host_input::{spawn_host_input, HostInput, HostInputEvent};
use xenith_emu::{
    serve_debug_tcp, serve_debug_tcp_with_hook, ExitReason, FramebufferConfig, Machine,
    MachineConfig, MAX_EMULATED_CPUS,
};

const INPUT_POLL_CYCLES: u64 = 100_000;
const MAX_INPUT_INJECT_BYTES: usize = 32;

struct InputSource {
    name: String,
    input: HostInput,
    pending: Option<Vec<u8>>,
    strict: bool,
}

impl InputSource {
    fn new(name: impl Into<String>, input: HostInput, strict: bool) -> Self {
        Self {
            name: name.into(),
            input,
            pending: None,
            strict,
        }
    }

    fn pump(&mut self, machine: &mut Machine) -> Result<(), String> {
        loop {
            if let Some(bytes) = self.pending.take() {
                if !machine.keyboard_input_ready() {
                    self.pending = Some(bytes);
                    return Ok(());
                }
                let inject_length = bytes.len().min(MAX_INPUT_INJECT_BYTES);
                let (inject, remaining) = bytes.split_at(inject_length);
                let text = std::str::from_utf8(inject)
                    .map_err(|_| format!("{} produced invalid UTF-8", self.name))?;
                match machine.inject_keyboard_ascii(text) {
                    Ok(()) => {
                        if !remaining.is_empty() {
                            self.pending = Some(remaining.to_vec());
                        }
                        // Feed at most 32 ASCII characters per execution
                        // slice. Each character expands to make/break
                        // scancodes, so injecting an entire 256-byte host
                        // chunk could otherwise overflow the guest's bounded
                        // decoded-event queue before userspace gets scheduled.
                        return Ok(());
                    },
                    Err(error) if self.strict => {
                        return Err(format!("{}: {error}", self.name));
                    },
                    Err(error) => {
                        eprintln!("xenith-emu: ignoring {} input: {error}", self.name);
                        self.pending = None;
                        return Ok(());
                    },
                }
            }

            match self.input.poll() {
                Some(HostInputEvent::Data(bytes)) => self.pending = Some(bytes),
                Some(HostInputEvent::Error(error)) if self.strict => {
                    return Err(format!("{}: {error}", self.name));
                },
                Some(HostInputEvent::Error(error)) => {
                    eprintln!("xenith-emu: ignoring {} input: {error}", self.name);
                },
                Some(HostInputEvent::Eof) | None => return Ok(()),
            }
        }
    }
}

#[derive(Default)]
struct InputPump {
    sources: Vec<InputSource>,
    next_poll_cycle: u64,
}

impl InputPump {
    fn add(&mut self, source: InputSource) {
        self.sources.push(source);
    }

    fn pump(&mut self, machine: &mut Machine) -> Result<(), String> {
        for source in &mut self.sources {
            source.pump(machine)?;
        }
        Ok(())
    }

    fn pump_if_due(&mut self, machine: &mut Machine) -> Result<(), String> {
        let cycle = machine.cpu.state.cycles;
        if cycle < self.next_poll_cycle {
            return Ok(());
        }
        self.next_poll_cycle = cycle.saturating_add(INPUT_POLL_CYCLES);
        self.pump(machine)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xenith-emu: {message}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut kernel = None;
    let mut initrd = None;
    let mut image = None;
    let mut bios_image = None;
    let mut bios_iso = None;
    let mut uefi_iso = None;
    let mut disk = None;
    let mut disk_output = None;
    let mut disk_read_only = false;
    let mut framebuffer_dump = None;
    let mut vga_dump = None;
    let mut input_script = None;
    let mut debug_listen = None;
    let mut serial_stdio = true;
    let mut memory_explicit = false;
    let mut config = MachineConfig::default();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--kernel" => kernel = Some(arguments.next().ok_or("--kernel needs a path")?),
            "--initrd" => initrd = Some(arguments.next().ok_or("--initrd needs a path")?),
            "--image" => image = Some(arguments.next().ok_or("--image needs a path")?),
            "--bios-image" => {
                bios_image = Some(arguments.next().ok_or("--bios-image needs a path")?)
            },
            "--bios-iso" => bios_iso = Some(arguments.next().ok_or("--bios-iso needs a path")?),
            "--uefi-iso" => uefi_iso = Some(arguments.next().ok_or("--uefi-iso needs a path")?),
            "--disk" => disk = Some(arguments.next().ok_or("--disk needs a path")?),
            "--disk-output" => {
                disk_output = Some(arguments.next().ok_or("--disk-output needs a path")?)
            },
            "--disk-read-only" => disk_read_only = true,
            "--framebuffer" => {
                config.framebuffer = Some(
                    FramebufferConfig::parse(
                        &arguments.next().ok_or("--framebuffer needs WIDTHxHEIGHT")?,
                    )
                    .map_err(str::to_owned)?,
                );
            },
            "--framebuffer-dump" => {
                framebuffer_dump = Some(
                    arguments
                        .next()
                        .ok_or("--framebuffer-dump needs a PPM path")?,
                )
            },
            "--vga-dump" => {
                vga_dump = Some(arguments.next().ok_or("--vga-dump needs a text path")?)
            },
            "--memory" => {
                config.memory_bytes =
                    parse_size(&arguments.next().ok_or("--memory needs a size")?)?;
                memory_explicit = true;
            },
            "--smp" => {
                config.cpu_count = arguments
                    .next()
                    .ok_or("--smp needs a count")?
                    .parse()
                    .map_err(|_| "invalid CPU count")?
            },
            "--max-instructions" => {
                config.instruction_limit = arguments
                    .next()
                    .ok_or("--max-instructions needs a count")?
                    .parse()
                    .map_err(|_| "invalid instruction count")?
            },
            "--serial" => {
                let backend = arguments.next().ok_or("--serial needs a backend")?;
                serial_stdio = match backend.as_str() {
                    "stdio" => true,
                    "none" => false,
                    _ => return Err(format!("unsupported serial backend {backend}")),
                };
                config.mirror_serial = serial_stdio;
            },
            "--input-script" => {
                input_script = Some(arguments.next().ok_or("--input-script needs a path")?)
            },
            "--debug-listen" => {
                debug_listen = Some(arguments.next().ok_or("--debug-listen needs an address")?)
            },
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
    if config.cpu_count > 1 && debug_listen.is_some() {
        return Err("--debug-listen currently requires --smp 1".to_owned());
    }
    if framebuffer_dump.is_some() && config.framebuffer.is_none() && uefi_iso.is_none() {
        return Err("--framebuffer-dump requires --framebuffer WIDTHxHEIGHT".to_owned());
    }
    let boot_sources = usize::from(kernel.is_some())
        + usize::from(image.is_some())
        + usize::from(bios_image.is_some())
        + usize::from(bios_iso.is_some())
        + usize::from(uefi_iso.is_some());
    if boot_sources != 1 {
        return Err(
            "select exactly one of --kernel <ELF>, --image <xenith.img>, --bios-image <xenith.img>, --bios-iso <xenith.iso>, or --uefi-iso <xenith.iso>"
                .to_owned(),
        );
    }
    if (image.is_some() || bios_image.is_some() || bios_iso.is_some())
        && (initrd.is_some() || disk.is_some())
    {
        return Err(
            "--image, --bios-image, and --bios-iso supply their manifest initrd and attached ATA disk"
                .to_owned(),
        );
    }
    if uefi_iso.is_some() && initrd.is_some() {
        return Err("--uefi-iso supplies its packaged initrd".to_owned());
    }
    if (bios_image.is_some() || bios_iso.is_some() || uefi_iso.is_some()) && !memory_explicit {
        // Stage2 uses a 16 MiB kernel staging window at 16 MiB and loads the
        // initrd from 32 MiB. Keep the CLI default comfortably above those
        // compact low-memory ranges so larger development initrds and the
        // kernel's adaptive runtime heap retain useful headroom.
        config.memory_bytes = 256 * 1024 * 1024;
    }
    let debug_limit = config.instruction_limit;
    let mut machine = Machine::new(config);
    if let Some(iso_path) = uefi_iso.as_deref() {
        let bytes = fs::read(iso_path)
            .map_err(|error| format!("cannot read UEFI ISO {iso_path}: {error}"))?;
        machine
            .load_uefi_iso(&bytes)
            .map_err(|error| format!("UEFI ISO boot failed: {error}"))?;
        let trace = machine
            .uefi_boot_trace()
            .ok_or("UEFI ISO boot produced no execution trace")?;
        eprintln!(
            "xenith-emu: UEFI catalog=LBA{} BIOS=LBA{} EFI=LBA{}+{}x512 PE={:#x}@{:#x} {} instructions/{} bytes services=alloc:{} map:{} files:{}/{}/{} exit:{}",
            trace.boot_catalog_lba,
            trace.bios_image_lba,
            trace.efi_image_lba,
            trace.efi_load_sectors,
            trace.image_entry,
            trace.image_load_base,
            trace.pe_instructions,
            trace.pe_fetched_bytes,
            trace.services.allocate_pages,
            trace.services.get_memory_map,
            trace.services.file_open,
            trace.services.file_read,
            trace.services.file_close,
            trace.services.exit_boot_services,
        );
        eprintln!(
            "xenith-emu: UEFI native handoff kernel={:#x} info={:#x} CR3={:#x} GOP={}x{}@{:#x}; exact BIOS catalog stages={}/{} instructions; semantic-fallback={}",
            trace.kernel_entry,
            trace.handoff_address,
            trace.final_cr3,
            trace.gop_width,
            trace.gop_height,
            trace.gop_framebuffer,
            trace.bios_stage1_instructions,
            trace.bios_stage2_instructions,
            trace.semantic_loader_fallback,
        );
        if let Some(disk_path) = disk.as_deref() {
            let bytes = fs::read(disk_path)
                .map_err(|error| format!("cannot read disk {disk_path}: {error}"))?;
            machine
                .attach_ata_disk(bytes, disk_read_only)
                .map_err(|error| format!("attach disk failed: {error}"))?;
        }
    } else if let Some(iso_path) = bios_iso.as_deref() {
        let bytes = fs::read(iso_path)
            .map_err(|error| format!("cannot read BIOS ISO {iso_path}: {error}"))?;
        let manifest = machine
            .load_bios_iso(&bytes, disk_read_only)
            .map_err(|error| format!("BIOS ISO boot failed: {error}"))?;
        let trace = machine
            .bios_boot_trace()
            .ok_or("BIOS ISO boot produced no transition trace")?;
        eprintln!(
            "xenith-emu: BIOS ISO reset={:#x} stage1={:#x} stage2=LBA{}+{}s@{:#x} E820={} long-mode={} kernel={:#x} handoff={:#x} semantic-fallback={}",
            trace.reset_vector,
            trace.stage1_load_address,
            trace.stage2_lba,
            trace.stage2_sectors,
            trace.stage2_load_address,
            trace.e820_entries,
            trace.long_mode_entered,
            trace.kernel_entry,
            trace.handoff_address,
            trace.semantic_stage2_loader_fallback,
        );
        eprintln!(
            "xenith-emu: BIOS ISO disk={} sectors kernel=LBA{}+{}B initrd=LBA{}+{}B",
            manifest.disk_sectors,
            manifest.kernel_lba,
            manifest.kernel_bytes,
            manifest.initrd_lba,
            manifest.initrd_bytes,
        );
    } else if let Some(image_path) = bios_image.as_deref() {
        let bytes = fs::read(image_path)
            .map_err(|error| format!("cannot read BIOS image {image_path}: {error}"))?;
        let manifest = machine
            .load_bios_image(bytes, disk_read_only)
            .map_err(|error| format!("BIOS image boot failed: {error}"))?;
        let trace = machine
            .bios_boot_trace()
            .ok_or("BIOS image boot produced no transition trace")?;
        eprintln!(
            "xenith-emu: BIOS reset={:#x} stage1={:#x} stage2=LBA{}+{}s@{:#x} E820={} long-mode={} kernel={:#x} handoff={:#x}",
            trace.reset_vector,
            trace.stage1_load_address,
            trace.stage2_lba,
            trace.stage2_sectors,
            trace.stage2_load_address,
            trace.e820_entries,
            trace.long_mode_entered,
            trace.kernel_entry,
            trace.handoff_address,
        );
        eprintln!(
            "xenith-emu: BIOS disk={} sectors kernel=LBA{}+{}B initrd=LBA{}+{}B",
            manifest.disk_sectors,
            manifest.kernel_lba,
            manifest.kernel_bytes,
            manifest.initrd_lba,
            manifest.initrd_bytes,
        );
    } else if let Some(image_path) = image.as_deref() {
        let bytes = fs::read(image_path)
            .map_err(|error| format!("cannot read image {image_path}: {error}"))?;
        let manifest = machine
            .load_manifest_image(bytes, disk_read_only)
            .map_err(|error| format!("image load failed: {error}"))?;
        eprintln!(
            "xenith-emu: manifest boot disk={} sectors kernel=LBA{}+{}B initrd=LBA{}+{}B",
            manifest.disk_sectors,
            manifest.kernel_lba,
            manifest.kernel_bytes,
            manifest.initrd_lba,
            manifest.initrd_bytes,
        );
    } else {
        let kernel_path = kernel.as_deref().expect("validated kernel selection");
        let kernel_bytes =
            fs::read(kernel_path).map_err(|error| format!("cannot read {kernel_path}: {error}"))?;
        let initrd_bytes = initrd
            .as_deref()
            .map(fs::read)
            .transpose()
            .map_err(|error| format!("cannot read initrd: {error}"))?;
        machine
            .load_kernel(&kernel_bytes, initrd_bytes.as_deref())
            .map_err(|error| format!("load failed: {error}"))?;
        if let Some(disk_path) = disk.as_deref() {
            let bytes = fs::read(disk_path)
                .map_err(|error| format!("cannot read disk {disk_path}: {error}"))?;
            machine
                .attach_ata_disk(bytes, disk_read_only)
                .map_err(|error| format!("attach disk failed: {error}"))?;
        }
    }

    let mut input = InputPump::default();
    let mut stdin_claimed = false;
    if let Some(path) = input_script {
        if path == "-" {
            stdin_claimed = true;
            let reader = spawn_host_input(io::stdin(), "xenith-emu-input-script")
                .map_err(|error| format!("cannot start stdin script reader: {error}"))?;
            input.add(InputSource::new("input script stdin", reader, true));
        } else {
            let file = File::open(&path)
                .map_err(|error| format!("cannot open input script {path}: {error}"))?;
            let reader = spawn_host_input(file, "xenith-emu-input-script")
                .map_err(|error| format!("cannot start input script reader: {error}"))?;
            input.add(InputSource::new(
                format!("input script {path}"),
                reader,
                true,
            ));
        }
    }
    if !stdin_claimed && serial_stdio && io::stdin().is_terminal() {
        let reader = spawn_host_input(io::stdin(), "xenith-emu-stdin")
            .map_err(|error| format!("cannot start stdin reader: {error}"))?;
        input.add(InputSource::new("stdin", reader, false));
    }

    if let Some(address) = debug_listen {
        // The debug server intentionally remains the sole execution owner.
        // Its continue/step loop polls the same bounded input pump through an
        // execution hook rather than racing the machine from a second thread.
        if !input.sources.is_empty() {
            return serve_debug_with_input(&mut machine, &address, debug_limit, input);
        }
        serve_debug_tcp(&mut machine, &address, debug_limit)
            .map_err(|error| format!("debug server failed: {error}"))?;
        return Ok(());
    }
    let (reason, instructions, interrupts) = run_with_input(&mut machine, &mut input, debug_limit)?;
    if let Some(path) = framebuffer_dump {
        let ppm = machine
            .framebuffer_ppm()
            .map_err(|error| format!("framebuffer render failed: {error}"))?
            .ok_or("framebuffer was not configured")?;
        fs::write(&path, ppm)
            .map_err(|error| format!("cannot write framebuffer dump {path}: {error}"))?;
    }
    if let Some(path) = vga_dump {
        let text = machine
            .vga_text()
            .map_err(|error| format!("VGA render failed: {error}"))?;
        fs::write(&path, text).map_err(|error| format!("cannot write VGA dump {path}: {error}"))?;
    }
    if let Some(path) = disk_output {
        let disk = machine
            .disk_image()
            .ok_or("--disk-output requires --image or --disk")?;
        fs::write(&path, disk.snapshot())
            .map_err(|error| format!("cannot write disk output {path}: {error}"))?;
        eprintln!(
            "xenith-emu: wrote {} disk image to {path}",
            if disk.changed() {
                "modified"
            } else {
                "unchanged"
            }
        );
    }
    let rip = machine.cpu.state.rip;
    eprintln!(
        "\nxenith-emu: {:?} after {} instructions and {} interrupts (RIP {rip:#018x})",
        reason, instructions, interrupts,
    );
    match reason {
        ExitReason::Halted | ExitReason::Breakpoint(_) => Ok(()),
        ExitReason::Fault(fault) => Err(format!("guest fault: {fault:?}")),
        ExitReason::InstructionLimit => Err("instruction limit reached".to_string()),
    }
}

fn run_with_input(
    machine: &mut Machine,
    input: &mut InputPump,
    iteration_limit: u64,
) -> Result<(ExitReason, u64, u64), String> {
    let mut remaining = iteration_limit;
    let mut instructions = 0u64;
    let mut interrupts = 0u64;

    loop {
        input.pump(machine)?;
        if remaining == 0 {
            return Ok((ExitReason::InstructionLimit, instructions, interrupts));
        }
        let slice = remaining.min(INPUT_POLL_CYCLES);
        let summary = machine.run_for(slice);
        instructions = instructions.saturating_add(summary.instructions);
        interrupts = interrupts.saturating_add(summary.interrupts);
        remaining -= slice;
        if !matches!(summary.reason, ExitReason::InstructionLimit) {
            return Ok((summary.reason, instructions, interrupts));
        }
    }
}

fn serve_debug_with_input(
    machine: &mut Machine,
    address: &str,
    continue_limit: u64,
    mut input: InputPump,
) -> Result<(), String> {
    let failure = Arc::new(Mutex::new(None));
    let hook_failure = Arc::clone(&failure);
    let hook = Box::new(move |machine: &mut Machine| {
        if hook_failure.lock().is_ok_and(|error| error.is_some()) {
            return;
        }
        if let Err(error) = input.pump_if_due(machine) {
            eprintln!("xenith-emu: {error}");
            if let Ok(mut failure) = hook_failure.lock() {
                *failure = Some(error);
            }
        }
    });
    serve_debug_tcp_with_hook(machine, address, continue_limit, hook)
        .map_err(|error| format!("debug server failed: {error}"))?;
    let input_error = failure
        .lock()
        .map_err(|_| "debug input state lock poisoned".to_string())?
        .take();
    input_error.map_or(Ok(()), Err)
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
        .ok_or_else(|| "memory size overflow".to_string())
}

fn print_help() {
    println!("xenith-emu (--kernel <ELF> [--initrd <CPIO>] | --image <xenith.img> | --bios-image <xenith.img> | --bios-iso <xenith.iso> | --uefi-iso <xenith.iso>) [--disk <raw.img>] [--disk-read-only] [--disk-output <raw.img>] [--memory 128M] [--smp 1..64] [--framebuffer WIDTHxHEIGHT] [--framebuffer-dump <screen.ppm>] [--vga-dump <screen.txt>] [--serial stdio|none] [--input-script <PATH|->] [--max-instructions N] [--debug-listen 127.0.0.1:9000]");
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn early_host_input_is_retained_until_the_keyboard_is_ready() {
        let reader = spawn_host_input(Cursor::new(b"a\r\n"), "test-cli-input").unwrap();
        let mut source = InputSource::new("test input", reader, true);
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while source.pending.is_none() && Instant::now() < deadline {
            source.pump(&mut machine).unwrap();
            thread::yield_now();
        }
        assert_eq!(source.pending.as_deref(), Some(b"a\n".as_slice()));

        machine.bus.write_port(0x64, 1, 0xAE);
        machine.bus.write_port(0x60, 1, 0xF4);
        assert_eq!(machine.bus.read_port(0x60, 1), 0xFA);
        machine.bus.write_port(0x64, 1, 0x60);
        machine.bus.write_port(0x60, 1, 1);
        assert!(machine.keyboard_input_ready());

        source.pump(&mut machine).unwrap();
        assert!(source.pending.is_none());
        assert_eq!(machine.bus.read_port(0x60, 1), 0x1E);
        assert_eq!(machine.bus.read_port(0x60, 1), 0x9E);
        assert_eq!(machine.bus.read_port(0x60, 1), 0x1C);
        assert_eq!(machine.bus.read_port(0x60, 1), 0x9C);
    }

    #[test]
    fn host_input_is_paced_across_execution_slices() {
        let payload = [b'a'; MAX_INPUT_INJECT_BYTES + 7];
        let reader = spawn_host_input(Cursor::new(payload), "test-paced-input").unwrap();
        let mut source = InputSource::new("paced input", reader, true);
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine.bus.write_port(0x64, 1, 0xAE);
        machine.bus.write_port(0x60, 1, 0xF4);
        assert_eq!(machine.bus.read_port(0x60, 1), 0xFA);
        machine.bus.write_port(0x64, 1, 0x60);
        machine.bus.write_port(0x60, 1, 1);

        let deadline = Instant::now() + Duration::from_secs(1);
        while source.pending.is_none() && Instant::now() < deadline {
            source.pump(&mut machine).unwrap();
            thread::yield_now();
        }
        assert_eq!(source.pending.as_ref().map(Vec::len), Some(7));
        source.pump(&mut machine).unwrap();
        assert!(source.pending.is_none());
    }

    #[test]
    fn sliced_run_preserves_the_requested_iteration_bound() {
        let mut machine = Machine::new(MachineConfig {
            memory_bytes: 1024 * 1024,
            mirror_serial: false,
            ..MachineConfig::default()
        });
        machine.load_flat(0x1000, &[0xEB, 0xFE], 0x80000).unwrap();
        let (reason, instructions, interrupts) =
            run_with_input(&mut machine, &mut InputPump::default(), 250_001).unwrap();
        assert_eq!(reason, ExitReason::InstructionLimit);
        assert_eq!(instructions, 250_001);
        assert_eq!(interrupts, 0);
    }
}

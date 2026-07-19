#![no_std]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

#[cfg(not(test))]
use core::panic::PanicInfo;

use libuser::args::Startup;
use xenith_abi::{DirectoryEntry, OpenFlags, Stat, Timespec, UtsName};

#[cfg(not(test))]
#[no_mangle]
/// # Safety
/// `startup` must point to the loader-created, read-only startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: the process loader maps and validates the startup block before entry.
    let start = unsafe { startup.as_ref() };
    let name = start
        .and_then(|s| unsafe { s.argument(0) })
        .unwrap_or(b"xenith-coreutils");
    let base = name.rsplit(|b| *b == b'/').next().unwrap_or(name);
    let code = match base {
        b"echo" => echo(start),
        b"cat" => cat(start),
        b"ls" => ls(start),
        b"mkdir" => mkdir(start),
        b"rmdir" => rmdir(start),
        b"rm" => rm(start),
        b"cp" => copy(start, false),
        b"mv" => copy(start, true),
        b"ps" => ps(),
        b"uname" => uname(),
        b"date" => date(),
        b"sleep" => sleep(start),
        b"head" => head(start),
        b"tail" => tail(start),
        b"wc" => wc(start),
        b"touch" => touch(start),
        b"env" => env(start),
        b"kill" => kill(start),
        b"mount" => mount(start),
        b"umount" => umount(start),
        b"ln" => ln(start),
        b"chmod" => chmod(start),
        b"chown" => chown(start),
        b"true" => 0,
        b"false" => 1,
        _ => {
            libuser::println!(
                "{}: utility not implemented",
                core::str::from_utf8(base).unwrap_or("coreutils")
            );
            127
        },
    };
    libuser::syscall::exit(code)
}

fn echo(start: Option<&Startup>) -> i32 {
    if let Some(args) = start {
        for index in 1..args.argc {
            if index > 1 {
                libuser::print!(" ");
            }
            // SAFETY: startup block came from the validated loader mapping.
            if let Some(arg) = unsafe { args.argument(index) } {
                libuser::print!("{}", core::str::from_utf8(arg).unwrap_or("?"));
            }
        }
    }
    libuser::println!();
    0
}

fn cat(start: Option<&Startup>) -> i32 {
    let Some(args) = start else {
        return 1;
    };
    let mut buffer = [0u8; 4096];
    if args.argc <= 1 {
        return copy_to_stdout(0, &mut buffer, false);
    }
    for index in 1..args.argc {
        // SAFETY: startup block came from the validated loader mapping.
        let Some(path) = (unsafe { args.argument(index) }) else {
            continue;
        };
        let (fd, close) = match open_input(path) {
            Ok(input) => input,
            Err(e) => {
                libuser::println!("cat: errno {}", e.0);
                return 1;
            },
        };
        if copy_to_stdout(fd, &mut buffer, close) != 0 {
            return 1;
        }
    }
    0
}

fn open_input(path: &[u8]) -> libuser::Result<(i32, bool)> {
    if path == b"-" {
        Ok((0, false))
    } else {
        libuser::syscall::open(path, OpenFlags::RDONLY, 0).map(|fd| (fd, true))
    }
}

fn copy_to_stdout(fd: i32, buffer: &mut [u8], close: bool) -> i32 {
    loop {
        match libuser::syscall::read(fd, buffer) {
            Ok(0) => break,
            Ok(count) if libuser::io::write_all(1, &buffer[..count]).is_ok() => {},
            Ok(_) | Err(_) => {
                if close {
                    let _ = libuser::syscall::close(fd);
                }
                return 1;
            },
        }
    }
    if close {
        let _ = libuser::syscall::close(fd);
    }
    0
}

fn uname() -> i32 {
    let mut value = UtsName::default();
    match libuser::syscall::uname(&mut value) {
        Ok(()) => {
            let end = value
                .system
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(value.system.len());
            libuser::println!(
                "{}",
                core::str::from_utf8(&value.system[..end]).unwrap_or("Xenith")
            );
            0
        },
        Err(e) => {
            libuser::println!("uname: errno {}", e.0);
            1
        },
    }
}

fn ls(start: Option<&Startup>) -> i32 {
    let path = start
        .and_then(|args| unsafe { args.argument(1) })
        .unwrap_or(b".");
    let mut entries = [DirectoryEntry::default(); 32];
    match libuser::syscall::read_dir(path, &mut entries) {
        Ok(count) => {
            for entry in &entries[..count] {
                let length = usize::from(entry.name_len).min(entry.name.len());
                libuser::println!(
                    "{}",
                    core::str::from_utf8(&entry.name[..length]).unwrap_or("?")
                );
            }
            0
        },
        Err(error) => {
            libuser::println!("ls: errno {}", error.0);
            1
        },
    }
}

fn mkdir(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 2 {
        libuser::println!("mkdir: missing operand");
        return 1;
    }
    for index in 1..args.argc {
        let Some(path) = (unsafe { args.argument(index) }) else {
            return 1;
        };
        if let Err(error) = libuser::syscall::mkdir(path, 0o755) {
            libuser::println!("mkdir: errno {}", error.0);
            return 1;
        }
    }
    0
}

fn rm(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 2 {
        libuser::println!("rm: missing operand");
        return 1;
    }
    for index in 1..args.argc {
        let Some(path) = (unsafe { args.argument(index) }) else {
            return 1;
        };
        if let Err(error) = libuser::syscall::unlink(path) {
            libuser::println!("rm: errno {}", error.0);
            return 1;
        }
    }
    0
}

fn copy(start: Option<&Startup>, remove_source: bool) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc != 3 {
        libuser::println!(
            "{}: expected source and destination",
            if remove_source { "mv" } else { "cp" }
        );
        return 1;
    }
    let Some(source) = (unsafe { args.argument(1) }) else {
        return 1;
    };
    let Some(destination) = (unsafe { args.argument(2) }) else {
        return 1;
    };
    let input = match libuser::syscall::open(source, OpenFlags::RDONLY, 0) {
        Ok(fd) => fd,
        Err(error) => {
            libuser::println!("cp: source errno {}", error.0);
            return 1;
        },
    };
    let output = match libuser::syscall::open(
        destination,
        OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        0o644,
    ) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = libuser::syscall::close(input);
            libuser::println!("cp: destination errno {}", error.0);
            return 1;
        },
    };
    let mut buffer = [0u8; 4096];
    let mut result = 0;
    loop {
        match libuser::syscall::read(input, &mut buffer) {
            Ok(0) => break,
            Ok(count) if libuser::io::write_all(output, &buffer[..count]).is_ok() => {},
            Ok(_) | Err(_) => {
                result = 1;
                break;
            },
        }
    }
    let _ = libuser::syscall::close(input);
    let _ = libuser::syscall::close(output);
    if result == 0 && remove_source && libuser::syscall::unlink(source).is_err() {
        result = 1;
    }
    result
}

fn ps() -> i32 {
    match (libuser::syscall::getpid(), libuser::syscall::getppid()) {
        (Ok(pid), Ok(ppid)) => {
            libuser::println!(" PID  PPID COMMAND");
            libuser::println!("{:>4} {:>5} ps", pid, ppid);
            0
        },
        _ => 1,
    }
}

fn date() -> i32 {
    match libuser::syscall::clock_gettime() {
        Ok(now) => {
            libuser::println!("{}.{:09} UTC (Unix)", now.seconds, now.nanoseconds);
            0
        },
        Err(error) => {
            libuser::println!("date: errno {}", error.0);
            1
        },
    }
}

fn rmdir(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 2 {
        libuser::println!("rmdir: missing operand");
        return 1;
    }
    let mut result = 0;
    for index in 1..args.argc {
        // SAFETY: startup block came from the validated loader mapping.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        if let Err(error) = libuser::syscall::rmdir(path) {
            print_errno("rmdir", path, error.0);
            result = 1;
        }
    }
    result
}

fn parse_unsigned(input: &[u8]) -> Option<u64> {
    if input.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for byte in input {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(*byte - b'0'))?;
    }
    Some(value)
}

fn parse_octal(input: &[u8]) -> Option<u32> {
    if input.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for byte in input {
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u32::from(*byte - b'0'))?;
    }
    (value <= 0o7777).then_some(value)
}

fn parse_duration(input: &[u8]) -> Option<Timespec> {
    if input.is_empty() {
        return None;
    }
    let (number, multiplier) = match input.last().copied()? {
        b's' => (&input[..input.len() - 1], 1u128),
        b'm' => (&input[..input.len() - 1], 60u128),
        b'h' => (&input[..input.len() - 1], 3_600u128),
        b'd' => (&input[..input.len() - 1], 86_400u128),
        _ => (input, 1u128),
    };
    if number.is_empty() {
        return None;
    }
    let dot = number.iter().position(|byte| *byte == b'.');
    if dot.is_some_and(|index| number[index + 1..].contains(&b'.')) {
        return None;
    }
    let whole_bytes = dot.map_or(number, |index| &number[..index]);
    let fraction_bytes = dot.map_or(&[][..], |index| &number[index + 1..]);
    if whole_bytes.is_empty() && fraction_bytes.is_empty() || fraction_bytes.len() > 9 {
        return None;
    }
    let whole = if whole_bytes.is_empty() {
        0u128
    } else {
        u128::from(parse_unsigned(whole_bytes)?)
    };
    let fraction = if fraction_bytes.is_empty() {
        0u128
    } else {
        u128::from(parse_unsigned(fraction_bytes)?)
    };
    let mut scale = 1u128;
    for _ in 0..fraction_bytes.len() {
        scale = scale.checked_mul(10)?;
    }
    let whole_ns = whole.checked_mul(multiplier)?.checked_mul(1_000_000_000)?;
    let fraction_ns = fraction
        .checked_mul(multiplier)?
        .checked_mul(1_000_000_000)?
        / scale;
    let total = whole_ns.checked_add(fraction_ns)?;
    let seconds = total / 1_000_000_000;
    if seconds > i64::MAX as u128 {
        return None;
    }
    Some(Timespec {
        seconds: seconds as i64,
        nanoseconds: (total % 1_000_000_000) as i64,
    })
}

fn sleep(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc != 2 {
        libuser::println!("sleep: expected one duration (suffix: s, m, h, or d)");
        return 1;
    }
    // SAFETY: startup block came from the validated loader mapping.
    let Some(input) = (unsafe { args.argument(1) }) else {
        return 1;
    };
    let Some(duration) = parse_duration(input) else {
        libuser::println!("sleep: invalid duration");
        return 1;
    };
    match libuser::syscall::nanosleep(duration) {
        Ok(()) => 0,
        Err(error) => {
            libuser::println!("sleep: errno {}", error.0);
            1
        },
    }
}

fn parse_line_options(args: &Startup, utility: &str) -> Option<(usize, usize)> {
    let mut lines = 10usize;
    let mut index = 1usize;
    while index < args.argc {
        // SAFETY: startup block came from the validated loader mapping.
        let argument = unsafe { args.argument(index) }?;
        if argument == b"--" {
            index += 1;
            break;
        }
        let value = if argument == b"-n" {
            index += 1;
            if index >= args.argc {
                libuser::println!("{}: -n requires a count", utility);
                return None;
            }
            // SAFETY: bounded by argc.
            unsafe { args.argument(index) }?
        } else if argument.starts_with(b"-n") && argument.len() > 2 {
            &argument[2..]
        } else if argument.starts_with(b"-") && argument.len() > 1 {
            &argument[1..]
        } else {
            break;
        };
        let Some(parsed) = parse_unsigned(value).and_then(|value| usize::try_from(value).ok())
        else {
            libuser::println!("{}: invalid line count", utility);
            return None;
        };
        lines = parsed;
        index += 1;
    }
    Some((lines, index))
}

fn head_fd(fd: i32, lines: usize) -> i32 {
    if lines == 0 {
        return 0;
    }
    let mut remaining = lines;
    let mut buffer = [0u8; 4096];
    loop {
        let count = match libuser::syscall::read(fd, &mut buffer) {
            Ok(count) => count,
            Err(_) => return 1,
        };
        if count == 0 {
            return 0;
        }
        let mut output = count;
        for (index, byte) in buffer[..count].iter().enumerate() {
            if *byte == b'\n' {
                remaining -= 1;
                if remaining == 0 {
                    output = index + 1;
                    break;
                }
            }
        }
        if libuser::io::write_all(1, &buffer[..output]).is_err() {
            return 1;
        }
        if remaining == 0 {
            return 0;
        }
    }
}

fn head(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    let Some((lines, first)) = parse_line_options(args, "head") else {
        return 1;
    };
    if first >= args.argc {
        return head_fd(0, lines);
    }
    let multiple = args.argc - first > 1;
    let mut result = 0;
    for index in first..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        if multiple {
            libuser::println!("==> {} <==", display(path));
        }
        let (fd, close) = match open_input(path) {
            Ok(input) => input,
            Err(error) => {
                print_errno("head", path, error.0);
                result = 1;
                continue;
            },
        };
        if head_fd(fd, lines) != 0 {
            print_path_error("head", path, "read failed");
            result = 1;
        }
        if close {
            let _ = libuser::syscall::close(fd);
        }
    }
    result
}

fn read_span(fd: i32, offset: u64, buffer: &mut [u8]) -> Option<usize> {
    libuser::syscall::lseek(fd, i64::try_from(offset).ok()?, 0).ok()?;
    let mut filled = 0usize;
    while filled < buffer.len() {
        let count = libuser::syscall::read(fd, &mut buffer[filled..]).ok()?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Some(filled)
}

fn tail_file_fd(fd: i32, size: u64, lines: usize) -> i32 {
    if lines == 0 || size == 0 {
        return 0;
    }
    let mut last = [0u8; 1];
    if read_span(fd, size - 1, &mut last) != Some(1) {
        return 1;
    }
    let needed = lines.saturating_add(usize::from(last[0] == b'\n'));
    let mut found = 0usize;
    let mut position = size;
    let mut start = 0u64;
    let mut buffer = [0u8; 4096];
    'scan: while position != 0 {
        let chunk_start = position.saturating_sub(buffer.len() as u64);
        let requested = usize::try_from(position - chunk_start).unwrap_or(buffer.len());
        let Some(count) = read_span(fd, chunk_start, &mut buffer[..requested]) else {
            return 1;
        };
        for index in (0..count).rev() {
            if buffer[index] == b'\n' {
                found = found.saturating_add(1);
                if found == needed {
                    start = chunk_start + index as u64 + 1;
                    break 'scan;
                }
            }
        }
        position = chunk_start;
    }
    if libuser::syscall::lseek(fd, i64::try_from(start).unwrap_or(i64::MAX), 0).is_err() {
        return 1;
    }
    copy_to_stdout(fd, &mut buffer, false)
}

fn decimal_path<'a>(storage: &'a mut [u8; 48], prefix: &[u8], mut value: u64) -> Option<&'a [u8]> {
    if prefix.len() >= storage.len() {
        return None;
    }
    storage[..prefix.len()].copy_from_slice(prefix);
    let mut length = prefix.len();
    let mut reversed = [0u8; 20];
    let mut digits = 0usize;
    loop {
        reversed[digits] = b'0' + (value % 10) as u8;
        digits += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    if length.checked_add(digits)? > storage.len() {
        return None;
    }
    for digit in reversed[..digits].iter().rev() {
        storage[length] = *digit;
        length += 1;
    }
    Some(&storage[..length])
}

fn tail_stream(lines: usize) -> i32 {
    let pid = match libuser::syscall::getpid() {
        Ok(pid) => pid,
        Err(error) => {
            libuser::println!("tail: cannot allocate spool name: errno {}", error.0);
            return 1;
        },
    };
    let mut path_storage = [0u8; 48];
    let Some(path) = decimal_path(&mut path_storage, b"/.xenith-tail-", pid) else {
        return 1;
    };
    let fd = match libuser::syscall::open(
        path,
        OpenFlags::RDWR | OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
        0o600,
    ) {
        Ok(fd) => fd,
        Err(error) => {
            print_errno("tail", path, error.0);
            return 1;
        },
    };
    let mut buffer = [0u8; 4096];
    let mut size = 0u64;
    let mut result = loop {
        let count = match libuser::syscall::read(0, &mut buffer) {
            Ok(count) => count,
            Err(_) => break 1,
        };
        if count == 0 {
            break 0;
        }
        if libuser::io::write_all(fd, &buffer[..count]).is_err() {
            libuser::println!("tail: spool write failed");
            break 1;
        }
        let Some(next) = size.checked_add(count as u64) else {
            libuser::println!("tail: input is too large");
            break 1;
        };
        size = next;
    };
    if result == 0 {
        result = tail_file_fd(fd, size, lines);
        if result != 0 {
            libuser::println!("tail: spool read or seek failed");
        }
    }
    let _ = libuser::syscall::close(fd);
    if let Err(error) = libuser::syscall::unlink(path) {
        print_errno("tail", path, error.0);
        result = 1;
    }
    result
}

fn tail(startup: Option<&Startup>) -> i32 {
    let Some(args) = startup else { return 1 };
    let Some((lines, first)) = parse_line_options(args, "tail") else {
        return 1;
    };
    if first >= args.argc {
        return tail_stream(lines);
    }
    let multiple = args.argc - first > 1;
    let mut result = 0;
    for index in first..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        if multiple {
            libuser::println!("==> {} <==", display(path));
        }
        if path == b"-" {
            if tail_stream(lines) != 0 {
                result = 1;
            }
            continue;
        }
        let mut metadata = Stat::default();
        if let Err(error) = libuser::syscall::stat(path, &mut metadata) {
            print_errno("tail", path, error.0);
            result = 1;
            continue;
        }
        let (fd, close) = match open_input(path) {
            Ok(input) => input,
            Err(error) => {
                print_errno("tail", path, error.0);
                result = 1;
                continue;
            },
        };
        if tail_file_fd(fd, metadata.size, lines) != 0 {
            print_path_error("tail", path, "read or seek failed");
            result = 1;
        }
        if close {
            let _ = libuser::syscall::close(fd);
        }
    }
    result
}

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

impl Counts {
    fn add(self, other: Self) -> Self {
        Self {
            lines: self.lines.saturating_add(other.lines),
            words: self.words.saturating_add(other.words),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }
}

fn count_chunk(counts: &mut Counts, in_word: &mut bool, bytes: &[u8]) {
    counts.bytes = counts.bytes.saturating_add(bytes.len() as u64);
    for byte in bytes {
        if *byte == b'\n' {
            counts.lines = counts.lines.saturating_add(1);
        }
        let whitespace = matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
        if whitespace {
            *in_word = false;
        } else if !*in_word {
            counts.words = counts.words.saturating_add(1);
            *in_word = true;
        }
    }
}

fn count_fd(fd: i32) -> Option<Counts> {
    let mut counts = Counts::default();
    let mut in_word = false;
    let mut buffer = [0u8; 4096];
    loop {
        let count = libuser::syscall::read(fd, &mut buffer).ok()?;
        if count == 0 {
            break;
        }
        count_chunk(&mut counts, &mut in_word, &buffer[..count]);
    }
    Some(counts)
}

fn print_counts(
    counts: Counts,
    show_lines: bool,
    show_words: bool,
    show_bytes: bool,
    label: &[u8],
) {
    if show_lines {
        libuser::print!("{:>8}", counts.lines);
    }
    if show_words {
        libuser::print!("{:>8}", counts.words);
    }
    if show_bytes {
        libuser::print!("{:>8}", counts.bytes);
    }
    if !label.is_empty() {
        libuser::print!(" {}", display(label));
    }
    libuser::println!();
}

fn wc(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    let mut show_lines = false;
    let mut show_words = false;
    let mut show_bytes = false;
    let mut index = 1usize;
    while index < args.argc {
        // SAFETY: bounded by argc.
        let Some(argument) = (unsafe { args.argument(index) }) else {
            return 1;
        };
        if argument == b"--" {
            index += 1;
            break;
        }
        if !argument.starts_with(b"-") || argument == b"-" {
            break;
        }
        for option in &argument[1..] {
            match option {
                b'l' => show_lines = true,
                b'w' => show_words = true,
                b'c' => show_bytes = true,
                _ => {
                    libuser::println!("wc: unsupported option");
                    return 1;
                },
            }
        }
        index += 1;
    }
    if !show_lines && !show_words && !show_bytes {
        show_lines = true;
        show_words = true;
        show_bytes = true;
    }
    if index >= args.argc {
        return match count_fd(0) {
            Some(counts) => {
                print_counts(counts, show_lines, show_words, show_bytes, b"");
                0
            },
            None => 1,
        };
    }
    let multiple = args.argc - index > 1;
    let mut total = Counts::default();
    let mut result = 0;
    for argument_index in index..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(argument_index) }) else {
            result = 1;
            continue;
        };
        let (fd, close) = match open_input(path) {
            Ok(input) => input,
            Err(error) => {
                print_errno("wc", path, error.0);
                result = 1;
                continue;
            },
        };
        match count_fd(fd) {
            Some(counts) => {
                print_counts(counts, show_lines, show_words, show_bytes, path);
                total = total.add(counts);
            },
            None => {
                print_path_error("wc", path, "read failed");
                result = 1;
            },
        }
        if close {
            let _ = libuser::syscall::close(fd);
        }
    }
    if multiple {
        print_counts(total, show_lines, show_words, show_bytes, b"total");
    }
    result
}

fn timestamp_ns(value: Timespec) -> Option<u64> {
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanoseconds) {
        return None;
    }
    (value.seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(value.nanoseconds as u64)
}

fn touch(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 2 {
        libuser::println!("touch: missing operand");
        return 1;
    }
    let now = match libuser::syscall::clock_gettime()
        .ok()
        .and_then(timestamp_ns)
    {
        Some(now) => now,
        None => {
            libuser::println!("touch: clock unavailable");
            return 1;
        },
    };
    let mut result = 0;
    for index in 1..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        let mut metadata = Stat::default();
        match libuser::syscall::stat(path, &mut metadata) {
            Ok(()) => {},
            Err(error) if error.0 == 2 => {
                match libuser::syscall::open(path, OpenFlags::WRONLY | OpenFlags::CREATE, 0o644) {
                    Ok(fd) => {
                        let _ = libuser::syscall::close(fd);
                    },
                    Err(create_error) => {
                        print_errno("touch", path, create_error.0);
                        result = 1;
                        continue;
                    },
                }
            },
            Err(error) => {
                print_errno("touch", path, error.0);
                result = 1;
                continue;
            },
        }
        if let Err(error) = libuser::syscall::utimens(path, now, now) {
            print_errno("touch", path, error.0);
            result = 1;
        }
    }
    result
}

fn env(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    // SAFETY: startup block came from the validated loader mapping.
    let environment = unsafe { args.environment() };
    if args.argc == 1 {
        for index in 0..environment.len() {
            if let Some(entry) = environment.entry(index) {
                libuser::println!("{}", display(entry));
            }
        }
        return 0;
    }
    if args.argc == 2 {
        // SAFETY: bounded by argc.
        let Some(name) = (unsafe { args.argument(1) }) else {
            return 1;
        };
        return match environment.get(name) {
            Some(value) => {
                libuser::println!("{}", display(value));
                0
            },
            None => 1,
        };
    }
    libuser::println!("env: command execution and environment mutation are not supported");
    1
}

fn signal_number(value: &[u8]) -> Option<u32> {
    let number = match value {
        b"HUP" | b"SIGHUP" => 1,
        b"INT" | b"SIGINT" => 2,
        b"KILL" | b"SIGKILL" => 9,
        b"TERM" | b"SIGTERM" => 15,
        b"STOP" | b"SIGSTOP" => 19,
        _ => u32::try_from(parse_unsigned(value)?).ok()?,
    };
    (number != 0 && number <= 63).then_some(number)
}

fn kill(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    let mut signal = 15u32;
    let mut index = 1usize;
    if index < args.argc {
        // SAFETY: bounded by argc.
        let argument = unsafe { args.argument(index) }.unwrap_or(b"");
        if argument == b"-s" {
            index += 1;
            // SAFETY: checked below against argc.
            let Some(value) = (index < args.argc)
                .then(|| unsafe { args.argument(index) })
                .flatten()
            else {
                libuser::println!("kill: -s requires a signal");
                return 1;
            };
            let Some(parsed) = signal_number(value) else {
                libuser::println!("kill: invalid signal");
                return 1;
            };
            signal = parsed;
            index += 1;
        } else if argument.starts_with(b"-") && argument.len() > 1 {
            let Some(parsed) = signal_number(&argument[1..]) else {
                libuser::println!("kill: invalid signal");
                return 1;
            };
            signal = parsed;
            index += 1;
        }
    }
    if index >= args.argc {
        libuser::println!("kill: missing pid");
        return 1;
    }
    let mut result = 0;
    for pid_index in index..args.argc {
        // SAFETY: bounded by argc.
        let Some(pid) = (unsafe { args.argument(pid_index) }).and_then(parse_unsigned) else {
            libuser::println!("kill: invalid pid");
            result = 1;
            continue;
        };
        if pid == 0 {
            libuser::println!("kill: pid must be positive");
            result = 1;
            continue;
        }
        let Ok(pid_value) = i64::try_from(pid) else {
            libuser::println!("kill: {}: pid out of range", pid);
            result = 1;
            continue;
        };
        if let Err(error) = libuser::syscall::kill(pid_value, signal) {
            libuser::println!("kill: {}: errno {}", pid, error.0);
            result = 1;
        }
    }
    result
}

fn mount(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    let target = if args.argc == 3 {
        // `mount ramfs /mnt`
        // SAFETY: argc fixes both indices.
        let kind = unsafe { args.argument(1) }.unwrap_or(b"");
        if kind != b"ramfs" {
            libuser::println!("mount: only anonymous ramfs mounts are supported");
            return 1;
        }
        // SAFETY: argc fixes the index.
        unsafe { args.argument(2) }
    } else if args.argc == 5 {
        // `mount -t ramfs none /mnt`
        // SAFETY: argc fixes all indices.
        let option = unsafe { args.argument(1) }.unwrap_or(b"");
        let kind = unsafe { args.argument(2) }.unwrap_or(b"");
        if option != b"-t" || kind != b"ramfs" {
            libuser::println!("mount: only -t ramfs is supported");
            return 1;
        }
        // SAFETY: argc fixes the index.
        unsafe { args.argument(4) }
    } else {
        libuser::println!("mount: usage: mount ramfs DIR | mount -t ramfs none DIR");
        return 1;
    };
    let Some(target) = target else { return 1 };
    match libuser::syscall::mount_ramfs(target) {
        Ok(()) => 0,
        Err(error) => {
            print_errno("mount", target, error.0);
            1
        },
    }
}

fn umount(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc != 2 {
        libuser::println!("umount: expected one mount point");
        return 1;
    }
    // SAFETY: argc fixes the index.
    let Some(path) = (unsafe { args.argument(1) }) else {
        return 1;
    };
    match libuser::syscall::unmount(path) {
        Ok(()) => 0,
        Err(error) => {
            print_errno("umount", path, error.0);
            1
        },
    }
}

fn ln(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc != 4 || unsafe { args.argument(1) } != Some(b"-s") {
        libuser::println!("ln: hard links are unsupported; usage: ln -s TARGET LINK");
        return 1;
    }
    // SAFETY: argc fixes both indices.
    let (Some(target), Some(link)) = (unsafe { args.argument(2) }, unsafe { args.argument(3) })
    else {
        return 1;
    };
    match libuser::syscall::symlink(target, link) {
        Ok(()) => 0,
        Err(error) => {
            print_errno("ln", link, error.0);
            1
        },
    }
}

fn chmod(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 3 {
        libuser::println!("chmod: expected MODE FILE...");
        return 1;
    }
    // SAFETY: argc fixes the index.
    let Some(mode) = unsafe { args.argument(1) }.and_then(parse_octal) else {
        libuser::println!("chmod: mode must be octal (0000..7777)");
        return 1;
    };
    let mut result = 0;
    for index in 2..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        if let Err(error) = libuser::syscall::chmod(path, mode) {
            print_errno("chmod", path, error.0);
            result = 1;
        }
    }
    result
}

fn parse_owner(value: &[u8]) -> Option<(u32, Option<u32>)> {
    let separator = value.iter().position(|byte| *byte == b':');
    let uid_bytes = separator.map_or(value, |index| &value[..index]);
    let uid = u32::try_from(parse_unsigned(uid_bytes)?).ok()?;
    let gid = match separator {
        Some(index) => Some(u32::try_from(parse_unsigned(&value[index + 1..])?).ok()?),
        None => None,
    };
    Some((uid, gid))
}

fn chown(start: Option<&Startup>) -> i32 {
    let Some(args) = start else { return 1 };
    if args.argc < 3 {
        libuser::println!("chown: expected UID[:GID] FILE...");
        return 1;
    }
    // SAFETY: argc fixes the index.
    let Some((uid, requested_gid)) = unsafe { args.argument(1) }.and_then(parse_owner) else {
        libuser::println!("chown: owner and group must be numeric");
        return 1;
    };
    let mut result = 0;
    for index in 2..args.argc {
        // SAFETY: bounded by argc.
        let Some(path) = (unsafe { args.argument(index) }) else {
            result = 1;
            continue;
        };
        let gid = match requested_gid {
            Some(gid) => gid,
            None => {
                let mut metadata = Stat::default();
                if let Err(error) = libuser::syscall::stat(path, &mut metadata) {
                    print_errno("chown", path, error.0);
                    result = 1;
                    continue;
                }
                metadata.gid
            },
        };
        if let Err(error) = libuser::syscall::chown(path, uid, gid) {
            print_errno("chown", path, error.0);
            result = 1;
        }
    }
    result
}

fn display(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("?")
}

fn print_errno(utility: &str, path: &[u8], errno: i32) {
    libuser::println!("{}: {}: errno {}", utility, display(path), errno);
}

fn print_path_error(utility: &str, path: &[u8], message: &str) {
    libuser::println!("{}: {}: {}", utility, display(path), message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_supports_fractional_suffixes() {
        assert_eq!(parse_duration(b"1.25").unwrap().seconds, 1);
        assert_eq!(parse_duration(b"1.25").unwrap().nanoseconds, 250_000_000);
        assert_eq!(parse_duration(b".5m").unwrap().seconds, 30);
        assert!(parse_duration(b"1.2.3").is_none());
        assert!(parse_duration(b"-1").is_none());
    }

    #[test]
    fn word_counter_tracks_chunk_boundaries() {
        let mut counts = Counts::default();
        let mut in_word = false;
        count_chunk(&mut counts, &mut in_word, b"one tw");
        count_chunk(&mut counts, &mut in_word, b"o\nthree\n");
        assert_eq!(counts.lines, 2);
        assert_eq!(counts.words, 3);
        assert_eq!(counts.bytes, 14);
    }

    #[test]
    fn numeric_parsers_reject_overflow_and_bad_modes() {
        assert_eq!(parse_unsigned(b"42"), Some(42));
        assert!(parse_unsigned(b"18446744073709551616").is_none());
        assert_eq!(parse_octal(b"0755"), Some(0o755));
        assert!(parse_octal(b"888").is_none());
        assert_eq!(parse_owner(b"1000:100"), Some((1000, Some(100))));
    }

    #[test]
    fn temporary_path_uses_the_full_decimal_pid() {
        let mut storage = [0u8; 48];
        assert_eq!(
            decimal_path(&mut storage, b"/.tail-", 4_294_967_296),
            Some(&b"/.tail-4294967296"[..])
        );
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::syscall::exit(127)
}

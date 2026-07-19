#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

#[cfg(not(test))]
use core::panic::PanicInfo;

use xenith_abi::OpenFlags;

mod parser;

use parser::{ParsedLine, Stage, MAX_ARGUMENTS, MAX_STAGES};

const LINE_CAPACITY: usize = 512;
const MAX_JOBS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Job {
    id: u32,
    process_group: i64,
    remaining: usize,
    state: JobState,
}

struct JobTable {
    slots: [Option<Job>; MAX_JOBS],
    next_id: u32,
}

impl JobTable {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_JOBS],
            next_id: 1,
        }
    }

    fn insert(&mut self, process_group: i64, remaining: usize, state: JobState) -> Option<u32> {
        let slot = self.slots.iter_mut().find(|slot| slot.is_none())?;
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1).max(1);
        *slot = Some(Job {
            id,
            process_group,
            remaining,
            state,
        });
        Some(id)
    }

    fn put_back(&mut self, job: Job) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(job);
        }
    }

    fn selected_index(&self, argument: Option<&[u8]>) -> Option<usize> {
        if let Some(argument) = argument {
            let id = parse_job_id(argument)?;
            self.slots
                .iter()
                .position(|slot| slot.is_some_and(|job| job.id == id))
        } else {
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.map(|job| (index, job.id)))
                .max_by_key(|(_, id)| *id)
                .map(|(index, _)| index)
        }
    }

    fn print(&self) {
        for job in self.slots.iter().flatten() {
            let state = match job.state {
                JobState::Running => "Running",
                JobState::Stopped => "Stopped",
            };
            libuser::println!("[{}] {} pgid {}", job.id, state, job.process_group);
        }
    }

    fn reap(&mut self) {
        for index in 0..self.slots.len() {
            let Some(mut job) = self.slots[index] else {
                continue;
            };
            let mut done = false;
            loop {
                let mut status = 0i32;
                match libuser::syscall::waitpid(
                    -job.process_group,
                    &mut status,
                    xenith_abi::WNOHANG | xenith_abi::WUNTRACED | xenith_abi::WCONTINUED,
                ) {
                    Ok(0) => break,
                    Ok(_) if wait_status_stopped(status) => job.state = JobState::Stopped,
                    Ok(_) if wait_status_continued(status) => job.state = JobState::Running,
                    Ok(_) => {
                        job.remaining = job.remaining.saturating_sub(1);
                        if job.remaining == 0 {
                            done = true;
                            break;
                        }
                    },
                    Err(error) if error.0 == 10 => {
                        done = true;
                        break;
                    },
                    Err(_) => break,
                }
            }
            if done {
                libuser::println!("[{}] Done pgid {}", job.id, job.process_group);
                self.slots[index] = None;
            } else {
                self.slots[index] = Some(job);
            }
        }
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    libuser::println!("Xenith shell 0.1 (type 'help')");
    let _ = libuser::syscall::setsid();
    let _ = libuser::syscall::setpgid(0, 0);
    let shell_process_group = libuser::syscall::getpgrp()
        .or_else(|_| libuser::syscall::getpid().map(|pid| pid as i64))
        .unwrap_or(0);
    if shell_process_group > 0 {
        let _ = libuser::terminal::set_foreground_process_group(
            libuser::io::STDIN,
            shell_process_group,
        );
    }
    let mut jobs = JobTable::new();
    let mut line = [0u8; LINE_CAPACITY];
    loop {
        jobs.reap();
        libuser::print!("xenith$ ");
        let Some(length) = read_line(&mut line) else {
            libuser::println!();
            libuser::syscall::exit(0);
        };
        let command = trim_line(&line[..length]);
        if command.is_empty() {
            continue;
        }
        let parsed = match parser::parse(command) {
            Ok(parsed) => parsed,
            Err(error) => {
                libuser::println!("sh: syntax error: {:?}", error);
                continue;
            },
        };
        if parsed.stage_count() == 1
            && !parsed.background()
            && run_builtin(&parsed, &mut jobs, shell_process_group)
        {
            continue;
        }
        run_pipeline(&parsed, &mut jobs, shell_process_group);
    }
}

#[cfg(not(test))]
fn read_line(buffer: &mut [u8]) -> Option<usize> {
    match libuser::syscall::read(libuser::io::STDIN, buffer) {
        Ok(0) | Err(_) => None,
        Ok(length) => Some(length),
    }
}

fn trim_line(mut line: &[u8]) -> &[u8] {
    while line
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        line = &line[..line.len() - 1];
    }
    line
}

fn run_builtin(parsed: &ParsedLine, jobs: &mut JobTable, shell_process_group: i64) -> bool {
    let stage = parsed.stage(0).expect("parser always emits one stage");
    let command = parsed.bytes(stage.argument(0).expect("stage has a command"));
    if !matches!(
        command,
        b"help" | b"echo" | b"pid" | b"pwd" | b"cd" | b"jobs" | b"fg" | b"bg" | b"exit"
    ) {
        return false;
    }

    let saved_input = match libuser::syscall::dup(libuser::io::STDIN) {
        Ok(fd) => fd,
        Err(error) => {
            libuser::println!("sh: dup: errno {}", error.0);
            return true;
        },
    };
    let saved_output = match libuser::syscall::dup(libuser::io::STDOUT) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = libuser::syscall::close(saved_input);
            libuser::println!("sh: dup: errno {}", error.0);
            return true;
        },
    };
    let configured = configure_builtin_redirections(parsed, stage);
    if let Err(error) = configured {
        restore_stdio(saved_input, saved_output);
        libuser::println!("sh: redirection: errno {}", error.0);
        return true;
    }

    match command {
        b"help" => libuser::println!(
            "builtins: bg cd echo exit fg help jobs pid pwd; syntax: |, <, >, >>, trailing &, quotes"
        ),
        b"echo" => {
            for index in 1..stage.argument_count() {
                if index > 1 {
                    libuser::print!(" ");
                }
                let value = parsed.bytes(stage.argument(index).expect("argument index checked"));
                if let Ok(value) = core::str::from_utf8(value) {
                    libuser::print!("{}", value);
                }
            }
            libuser::println!();
        },
        b"pid" => match libuser::syscall::getpid() {
            Ok(pid) => libuser::println!("{}", pid),
            Err(error) => libuser::println!("pid: errno {}", error.0),
        },
        b"pwd" => {
            let mut path = [0u8; 256];
            match libuser::syscall::getcwd(&mut path) {
                Ok(length) => {
                    libuser::println!("{}", core::str::from_utf8(&path[..length]).unwrap_or("?"))
                },
                Err(error) => libuser::println!("pwd: errno {}", error.0),
            }
        },
        b"cd" => {
            let path = stage
                .argument(1)
                .map(|span| parsed.bytes(span))
                .unwrap_or(b"/");
            if let Err(error) = libuser::syscall::chdir(path) {
                libuser::println!("cd: errno {}", error.0);
            }
        },
        b"jobs" => jobs.print(),
        b"fg" => foreground_job(parsed, stage, jobs, shell_process_group),
        b"bg" => background_job(parsed, stage, jobs),
        b"exit" => {
            restore_stdio(saved_input, saved_output);
            libuser::syscall::exit(0)
        },
        _ => unreachable!(),
    }
    restore_stdio(saved_input, saved_output);
    true
}

fn foreground_job(
    parsed: &ParsedLine,
    stage: &Stage,
    jobs: &mut JobTable,
    shell_process_group: i64,
) {
    let argument = stage.argument(1).map(|span| parsed.bytes(span));
    let Some(index) = jobs.selected_index(argument) else {
        libuser::println!("fg: no such job");
        return;
    };
    let Some(mut job) = jobs.slots[index].take() else {
        return;
    };
    if let Err(error) =
        libuser::terminal::set_foreground_process_group(libuser::io::STDIN, job.process_group)
    {
        libuser::println!("fg: tcsetpgrp: errno {}", error.0);
        jobs.put_back(job);
        return;
    }
    if let Err(error) = libuser::syscall::kill(-job.process_group, xenith_abi::SIGCONT) {
        libuser::println!("fg: continue: errno {}", error.0);
    }
    job.state = JobState::Running;
    if let Some(stopped) = wait_foreground(job, shell_process_group) {
        jobs.put_back(stopped);
    }
}

fn background_job(parsed: &ParsedLine, stage: &Stage, jobs: &mut JobTable) {
    let argument = stage.argument(1).map(|span| parsed.bytes(span));
    let Some(index) = jobs.selected_index(argument) else {
        libuser::println!("bg: no such job");
        return;
    };
    let Some(mut job) = jobs.slots[index] else {
        return;
    };
    match libuser::syscall::kill(-job.process_group, xenith_abi::SIGCONT) {
        Ok(()) => {
            job.state = JobState::Running;
            jobs.slots[index] = Some(job);
            libuser::println!("[{}] Running pgid {}", job.id, job.process_group);
        },
        Err(error) => libuser::println!("bg: continue: errno {}", error.0),
    }
}

fn wait_foreground(mut job: Job, shell_process_group: i64) -> Option<Job> {
    while job.remaining != 0 {
        let mut status = 0i32;
        match libuser::syscall::waitpid(-job.process_group, &mut status, xenith_abi::WUNTRACED) {
            Ok(_) if wait_status_stopped(status) => {
                job.state = JobState::Stopped;
                break;
            },
            Ok(_) => job.remaining = job.remaining.saturating_sub(1),
            Err(error) if error.0 == 10 => {
                job.remaining = 0;
                break;
            },
            Err(error) => {
                libuser::println!("sh: waitpid: errno {}", error.0);
                break;
            },
        }
    }
    if shell_process_group > 0 {
        let _ = libuser::terminal::set_foreground_process_group(
            libuser::io::STDIN,
            shell_process_group,
        );
    }
    (job.remaining != 0).then_some(job)
}

fn parse_job_id(mut argument: &[u8]) -> Option<u32> {
    if argument.first() == Some(&b'%') {
        argument = &argument[1..];
    }
    if argument.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for &byte in argument {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    (value != 0).then_some(value)
}

fn wait_status_stopped(status: i32) -> bool {
    status & 0xff == 0x7f
}

fn wait_status_continued(status: i32) -> bool {
    status == 0xffff
}

fn configure_builtin_redirections(parsed: &ParsedLine, stage: &Stage) -> libuser::Result<()> {
    if let Some(path) = stage.input {
        let fd = libuser::syscall::open(parsed.bytes(path), OpenFlags::RDONLY, 0)?;
        let result = libuser::syscall::dup2(fd, libuser::io::STDIN).map(|_| ());
        let _ = libuser::syscall::close(fd);
        result?;
    }
    if let Some(output) = stage.output {
        let mut flags = OpenFlags::WRONLY | OpenFlags::CREATE;
        flags = flags
            | if output.append {
                OpenFlags::APPEND
            } else {
                OpenFlags::TRUNCATE
            };
        let fd = libuser::syscall::open(parsed.bytes(output.path), flags, 0o644)?;
        let result = libuser::syscall::dup2(fd, libuser::io::STDOUT).map(|_| ());
        let _ = libuser::syscall::close(fd);
        result?;
    }
    Ok(())
}

fn restore_stdio(saved_input: i32, saved_output: i32) {
    let _ = libuser::syscall::dup2(saved_input, libuser::io::STDIN);
    let _ = libuser::syscall::dup2(saved_output, libuser::io::STDOUT);
    let _ = libuser::syscall::close(saved_input);
    let _ = libuser::syscall::close(saved_output);
}

fn run_pipeline(parsed: &ParsedLine, jobs: &mut JobTable, shell_process_group: i64) {
    let saved_input = match libuser::syscall::dup(libuser::io::STDIN) {
        Ok(fd) => fd,
        Err(error) => {
            libuser::println!("sh: dup: errno {}", error.0);
            return;
        },
    };
    let saved_output = match libuser::syscall::dup(libuser::io::STDOUT) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = libuser::syscall::close(saved_input);
            libuser::println!("sh: dup: errno {}", error.0);
            return;
        },
    };

    let mut previous_read = None;
    let mut children = [0i64; MAX_STAGES];
    let mut child_count = 0usize;
    let mut process_group = 0i64;
    let mut failed = false;

    for index in 0..parsed.stage_count() {
        let stage = parsed.stage(index).expect("stage index checked");
        let mut input = previous_read.take();
        if let Some(path) = stage.input {
            if let Some(fd) = input.take() {
                let _ = libuser::syscall::close(fd);
            }
            input = match libuser::syscall::open(parsed.bytes(path), OpenFlags::RDONLY, 0) {
                Ok(fd) => Some(fd),
                Err(error) => {
                    libuser::println!("sh: input: errno {}", error.0);
                    break;
                },
            };
        }

        let mut output = None;
        let mut next_read = None;
        if let Some(redirection) = stage.output {
            let mut flags = OpenFlags::WRONLY | OpenFlags::CREATE;
            flags = flags
                | if redirection.append {
                    OpenFlags::APPEND
                } else {
                    OpenFlags::TRUNCATE
                };
            output = match libuser::syscall::open(parsed.bytes(redirection.path), flags, 0o644) {
                Ok(fd) => Some(fd),
                Err(error) => {
                    libuser::println!("sh: output: errno {}", error.0);
                    if let Some(fd) = input {
                        let _ = libuser::syscall::close(fd);
                    }
                    break;
                },
            };
        } else if index + 1 < parsed.stage_count() {
            let mut descriptors = [0i32; 2];
            if let Err(error) = libuser::syscall::pipe(&mut descriptors) {
                libuser::println!("sh: pipe: errno {}", error.0);
                if let Some(fd) = input {
                    let _ = libuser::syscall::close(fd);
                }
                break;
            }
            next_read = Some(descriptors[0]);
            output = Some(descriptors[1]);
        }

        let setup = input
            .map_or(Ok(()), |fd| {
                libuser::syscall::dup2(fd, libuser::io::STDIN).map(|_| ())
            })
            .and_then(|()| {
                output.map_or(Ok(()), |fd| {
                    libuser::syscall::dup2(fd, libuser::io::STDOUT).map(|_| ())
                })
            });
        if let Err(error) = setup {
            libuser::println!("sh: dup2: errno {}", error.0);
            failed = true;
        } else {
            match spawn_stage(parsed, stage) {
                Ok(pid) => {
                    children[child_count] = pid;
                    child_count += 1;
                    let group = if process_group == 0 {
                        pid
                    } else {
                        process_group
                    };
                    if let Err(error) = libuser::syscall::setpgid(pid, group) {
                        libuser::println!("sh: setpgid: errno {}", error.0);
                        failed = true;
                    } else if process_group == 0 {
                        process_group = group;
                        if !parsed.background() {
                            if let Err(error) = libuser::terminal::set_foreground_process_group(
                                libuser::io::STDIN,
                                process_group,
                            ) {
                                libuser::println!("sh: tcsetpgrp: errno {}", error.0);
                                failed = true;
                            }
                        }
                    }
                },
                Err(error) => {
                    libuser::println!("sh: spawn: errno {}", error.0);
                    failed = true;
                },
            }
        }

        let _ = libuser::syscall::dup2(saved_input, libuser::io::STDIN);
        let _ = libuser::syscall::dup2(saved_output, libuser::io::STDOUT);
        if let Some(fd) = input {
            let _ = libuser::syscall::close(fd);
        }
        if let Some(fd) = output {
            let _ = libuser::syscall::close(fd);
        }
        previous_read = next_read;
        if failed {
            break;
        }
    }

    if let Some(fd) = previous_read {
        let _ = libuser::syscall::close(fd);
    }
    let _ = libuser::syscall::dup2(saved_input, libuser::io::STDIN);
    let _ = libuser::syscall::dup2(saved_output, libuser::io::STDOUT);
    let _ = libuser::syscall::close(saved_input);
    let _ = libuser::syscall::close(saved_output);

    if child_count == 0 {
        return;
    }
    if process_group == 0 {
        for &pid in &children[..child_count] {
            let mut status = 0;
            let _ = libuser::syscall::waitpid(pid, &mut status, 0);
        }
        return;
    }

    if failed {
        for &pid in &children[..child_count] {
            let mut status = 0;
            let _ = libuser::syscall::waitpid(pid, &mut status, 0);
        }
        if shell_process_group > 0 {
            let _ = libuser::terminal::set_foreground_process_group(
                libuser::io::STDIN,
                shell_process_group,
            );
        }
        return;
    }

    if parsed.background() {
        match jobs.insert(process_group, child_count, JobState::Running) {
            Some(id) => libuser::println!("[{}] {}", id, process_group),
            None => {
                libuser::println!("sh: job table full; waiting in foreground");
                let _ = libuser::terminal::set_foreground_process_group(
                    libuser::io::STDIN,
                    process_group,
                );
                let _ = wait_foreground(
                    Job {
                        id: 0,
                        process_group,
                        remaining: child_count,
                        state: JobState::Running,
                    },
                    shell_process_group,
                );
            },
        }
    } else {
        let job = Job {
            id: 0,
            process_group,
            remaining: child_count,
            state: JobState::Running,
        };
        if let Some(stopped) = wait_foreground(job, shell_process_group) {
            match jobs.insert(stopped.process_group, stopped.remaining, JobState::Stopped) {
                Some(id) => libuser::println!("[{}] Stopped", id),
                None => libuser::println!("sh: stopped job table full"),
            }
        }
    }
}

fn spawn_stage(parsed: &ParsedLine, stage: &Stage) -> libuser::Result<i64> {
    let mut argv = [core::ptr::null(); MAX_ARGUMENTS + 1];
    for (index, slot) in argv.iter_mut().enumerate().take(stage.argument_count()) {
        *slot = parsed.pointer(stage.argument(index).expect("argument index checked"));
    }
    let command = parsed.bytes(stage.argument(0).expect("stage command exists"));
    let mut path = [0u8; 128];
    let path_length = command_path(command, &mut path)?;
    libuser::syscall::spawn(&path[..path_length], argv.as_ptr(), core::ptr::null())
}

fn command_path(command: &[u8], path: &mut [u8]) -> libuser::Result<usize> {
    if command.first() == Some(&b'/') {
        if command.len() > path.len() {
            return Err(libuser::Error(36));
        }
        path[..command.len()].copy_from_slice(command);
        Ok(command.len())
    } else {
        if command.len() > path.len() - 5 {
            return Err(libuser::Error(36));
        }
        path[..5].copy_from_slice(b"/bin/");
        path[5..5 + command.len()].copy_from_slice(command);
        Ok(5 + command.len())
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::println!("sh: panic");
    libuser::syscall::exit(127)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_only_record_terminators() {
        assert_eq!(trim_line(b"echo hi\r\n"), b"echo hi");
        assert_eq!(trim_line(b" echo "), b" echo ");
    }

    #[test]
    fn command_lookup_uses_bin_unless_absolute() {
        let mut path = [0u8; 32];
        let length = command_path(b"cat", &mut path).unwrap();
        assert_eq!(&path[..length], b"/bin/cat");
        let length = command_path(b"/bin/echo", &mut path).unwrap();
        assert_eq!(&path[..length], b"/bin/echo");
    }

    #[test]
    fn job_ids_accept_percent_prefix_and_status_words_are_decoded() {
        assert_eq!(parse_job_id(b"%12"), Some(12));
        assert_eq!(parse_job_id(b"7"), Some(7));
        assert_eq!(parse_job_id(b"%"), None);
        assert!(wait_status_stopped((20 << 8) | 0x7f));
        assert!(wait_status_continued(0xffff));
        assert!(!wait_status_stopped(0));
    }

    #[test]
    fn job_table_is_bounded_and_selects_the_latest_job() {
        let mut jobs = JobTable::new();
        for index in 0..MAX_JOBS {
            assert_eq!(
                jobs.insert(100 + index as i64, 1, JobState::Running),
                Some(index as u32 + 1)
            );
        }
        assert_eq!(jobs.insert(999, 1, JobState::Running), None);
        assert_eq!(jobs.selected_index(None), Some(MAX_JOBS.saturating_sub(1)));
        assert_eq!(jobs.selected_index(Some(b"%2")), Some(1));
    }
}

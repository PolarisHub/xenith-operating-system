#![no_std]
#![no_main]

use core::panic::PanicInfo;

use libuser::args::Startup;
use xenith_abi::OpenFlags;

const CAPACITY: usize = 16 * 1024;

#[no_mangle]
/// # Safety
/// `startup` must point to a loader-created startup block.
pub unsafe extern "C" fn _start(startup: *const Startup) -> ! {
    // SAFETY: required by the entry contract above.
    let startup = unsafe { startup.as_ref() };
    let path = startup.and_then(|args| unsafe { args.argument(1) });
    let mut text = [0u8; CAPACITY];
    let mut used = path.map_or(0, |name| load(name, &mut text));
    libuser::println!("Xenith ed: p=print a=append w=write q=quit");
    let mut command = [0u8; 128];
    loop {
        libuser::print!(":");
        let length = read_line(&mut command);
        match command[..length].first().copied() {
            Some(b'p') => {
                let _ = libuser::io::write_all(1, &text[..used]);
                if text.get(used.wrapping_sub(1)) != Some(&b'\n') {
                    libuser::println!();
                }
            },
            Some(b'a') => {
                libuser::println!("append; a line containing only . ends input");
                loop {
                    let count = read_line(&mut command);
                    if &command[..count] == b"." {
                        break;
                    }
                    if used + count + 1 > text.len() {
                        libuser::println!("? buffer full");
                        break;
                    }
                    text[used..used + count].copy_from_slice(&command[..count]);
                    used += count;
                    text[used] = b'\n';
                    used += 1;
                }
            },
            Some(b'w') => match path {
                Some(name) if save(name, &text[..used]) => libuser::println!("{}", used),
                Some(_) => libuser::println!("? write failed"),
                None => libuser::println!("? no file name"),
            },
            Some(b'q') => libuser::syscall::exit(0),
            Some(_) => libuser::println!("?"),
            None => {},
        }
    }
}

fn read_line(output: &mut [u8]) -> usize {
    let mut used = 0usize;
    while used < output.len() {
        let mut byte = [0u8; 1];
        match libuser::syscall::read(0, &mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => break,
            Ok(_) => {
                output[used] = byte[0];
                used += 1;
            },
        }
    }
    used
}

fn load(path: &[u8], output: &mut [u8]) -> usize {
    let Ok(fd) = libuser::syscall::open(path, OpenFlags::RDONLY, 0) else {
        return 0;
    };
    let mut used = 0usize;
    while used < output.len() {
        match libuser::syscall::read(fd, &mut output[used..]) {
            Ok(0) | Err(_) => break,
            Ok(count) => used += count,
        }
    }
    let _ = libuser::syscall::close(fd);
    used
}

fn save(path: &[u8], bytes: &[u8]) -> bool {
    let Ok(fd) = libuser::syscall::open(
        path,
        OpenFlags::WRONLY | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        0o644,
    ) else {
        return false;
    };
    let result = libuser::io::write_all(fd, bytes).is_ok();
    let _ = libuser::syscall::close(fd);
    result
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    libuser::syscall::exit(127)
}

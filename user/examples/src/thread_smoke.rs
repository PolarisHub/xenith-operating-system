#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use xenith_abi::{ThreadJoinResult, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};

const STACK_SIZE: usize = 64 * 1024;

static READY: AtomicUsize = AtomicUsize::new(0);
static GO: AtomicBool = AtomicBool::new(false);
static SUM: AtomicUsize = AtomicUsize::new(0);
static TID_ONE: AtomicU64 = AtomicU64::new(0);
static TID_TWO: AtomicU64 = AtomicU64::new(0);

extern "C" fn worker(argument: usize) -> i32 {
    let tid = match libuser::gettid() {
        Ok(tid) => tid,
        Err(_) => return -10,
    };
    match argument {
        1 => TID_ONE.store(tid, Ordering::SeqCst),
        2 => TID_TWO.store(tid, Ordering::SeqCst),
        _ => return -11,
    }
    READY.fetch_add(1, Ordering::SeqCst);
    while !GO.load(Ordering::SeqCst) {
        if libuser::syscall::yield_now().is_err() {
            return -12;
        }
    }
    SUM.fetch_add(argument, Ordering::SeqCst);
    40 + argument as i32
}

fn fail(stage: &str, code: i32) -> ! {
    libuser::println!("XENITH_THREAD_FAIL stage={} code={}", stage, code);
    libuser::syscall::exit(1)
}

fn map_stack() -> *mut u8 {
    match libuser::syscall::mmap(
        core::ptr::null_mut(),
        STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    ) {
        Ok(mapping) => mapping,
        Err(libuser::Error(errno)) => fail("mmap", errno),
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let parent_tid = match libuser::gettid() {
        Ok(tid) => tid,
        Err(libuser::Error(errno)) => fail("gettid-parent", errno),
    };
    let stack_one = map_stack();
    let stack_two = map_stack();

    // SAFETY: both mmap results are distinct private RW/NX mappings. The
    // parent does not access either range again until the matching join has
    // consumed that thread's completion.
    let thread_one = unsafe {
        let stack = core::slice::from_raw_parts_mut(stack_one, STACK_SIZE);
        libuser::spawn_thread(worker, 1, stack)
    };
    let thread_one = match thread_one {
        Ok(tid) => tid,
        Err(libuser::Error(errno)) => fail("create-one", errno),
    };

    // SAFETY: same ownership argument as stack_one; this mapping is disjoint.
    let thread_two = unsafe {
        let stack = core::slice::from_raw_parts_mut(stack_two, STACK_SIZE);
        libuser::spawn_thread(worker, 2, stack)
    };
    let thread_two = match thread_two {
        Ok(tid) => tid,
        Err(libuser::Error(errno)) => fail("create-two", errno),
    };

    while READY.load(Ordering::SeqCst) != 2 {
        if libuser::syscall::yield_now().is_err() {
            fail("yield-parent", -1);
        }
    }
    GO.store(true, Ordering::SeqCst);

    let mut first = ThreadJoinResult::default();
    if let Err(libuser::Error(errno)) = libuser::thread_join(thread_one, &mut first) {
        fail("join-one", errno);
    }
    let mut second = ThreadJoinResult::default();
    if let Err(libuser::Error(errno)) = libuser::thread_join(thread_two, &mut second) {
        fail("join-two", errno);
    }

    let observed_one = TID_ONE.load(Ordering::SeqCst);
    let observed_two = TID_TWO.load(Ordering::SeqCst);
    if first.exit_code != 41
        || second.exit_code != 42
        || first.reserved != 0
        || second.reserved != 0
        || observed_one != thread_one
        || observed_two != thread_two
        || parent_tid == thread_one
        || parent_tid == thread_two
        || thread_one == thread_two
        || SUM.load(Ordering::SeqCst) != 3
    {
        fail("result", -2);
    }

    if let Err(libuser::Error(errno)) = libuser::syscall::munmap(stack_one, STACK_SIZE) {
        fail("unmap-one", errno);
    }
    if let Err(libuser::Error(errno)) = libuser::syscall::munmap(stack_two, STACK_SIZE) {
        fail("unmap-two", errno);
    }

    libuser::println!(
        "XENITH_THREAD_OK parent={} first={} second={} sum={}",
        parent_tid,
        thread_one,
        thread_two,
        SUM.load(Ordering::SeqCst)
    );
    libuser::syscall::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    fail("panic", 127)
}

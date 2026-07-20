//! Exclusive userspace display session and ordered desktop input delivery.
//!
//! The first graphical shell must not map firmware-owned video memory into a
//! process: Xenith's current VM teardown treats user mappings as allocator-
//! owned RAM.  Instead, this module lends one process an exclusive *session*.
//! The process renders into an ordinary anonymous backbuffer and submits a
//! bounded list of damaged rectangles; the kernel copies only those rows into
//! the scanout through the fault-recoverable user-copy path.
//!
//! The same session owns keyboard and pointer input.  IRQ handlers route
//! decoded events into one queue, which gives events from both devices a
//! common sequence and timestamp order.  When no userspace session exists,
//! keyboard events continue down the existing TTY path and mouse events stay
//! in the device queue.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use xenith_abi::{
    UiDisplayInfo, UiInputEvent, UiRect, UI_ABI_VERSION, UI_DISPLAY_NATIVE_PIXEL_FORMAT,
    UI_EVENT_FLAG_OVERFLOW, UI_EVENT_FLAG_PRESSED, UI_EVENT_FLAG_REPEAT, UI_EVENT_KEY,
    UI_EVENT_POINTER, UI_MAX_DAMAGE_RECTS, UI_MAX_EVENTS_PER_READ, UI_TIMEOUT_INFINITE,
    WAIT_READY_HANGUP, WAIT_READY_UI_INPUT,
};
use xenith_types::VirtAddr;

use crate::devices::framebuffer::Scanout;
use crate::devices::ps2::keyboard::KeyEvent;
use crate::devices::ps2::mouse::MouseEvent;
use crate::sched::TaskId;
use crate::sync::{Mutex, SpinLockIRQ};
use crate::time::{Duration, Instant};
use crate::user::ProcessId;
use crate::util::RingBuffer;

/// Fixed queue storage. At 48 bytes per event this consumes 24 KiB and holds
/// more than eight seconds of 60 Hz pointer reports without allocating.
const EVENT_QUEUE_CAPACITY: usize = 512;

/// Suppress repeated diagnostics if the optional VMware FIFO path cannot be
/// used. The CPU-copy scanout remains authoritative in either case.
static SVGA_SCANOUT_MISMATCH_WARNED: AtomicBool = AtomicBool::new(false);
static SVGA_PRESENT_WARNED: AtomicBool = AtomicBool::new(false);
static SVGA_PRESENT_CONFIRMED: AtomicBool = AtomicBool::new(false);

/// Errors returned by the kernel UI-session core before errno translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UiError {
    /// No supported linear framebuffer was installed during boot.
    NoDisplay,
    /// A different process already owns the userspace display session.
    Busy,
    /// The caller does not own the current session.
    NotOwner,
    /// Geometry, stride, damage, or another scalar argument is invalid.
    InvalidArgument,
    /// A fault occurred while reading pixels from userspace.
    Fault,
    /// A deliverable signal interrupted an otherwise empty event wait.
    Interrupted,
    /// The call did not originate from a scheduled userspace task.
    NoCurrentTask,
}

#[derive(Clone, Copy)]
struct SessionState {
    scanout: Option<Scanout>,
}

impl SessionState {
    const fn new() -> Self {
        Self { scanout: None }
    }
}

/// Serialises acquire/present/release without disabling device interrupts.
/// Presentation can copy an entire frame, so task-context contenders must
/// yield rather than pinning a CPU behind a preempted owner. IRQ input routing
/// never takes this mutex; it reads `OWNER` and uses its own IRQ-safe lock.
static SESSION: Mutex<SessionState> = Mutex::new(SessionState::new());

/// PID zero is the unowned sentinel. PIDs are monotonic and never reused.
static OWNER: AtomicU64 = AtomicU64::new(0);

/// Nonzero token for the current input-routing epoch. IRQ routing samples the
/// token before taking the queue lock and accepts an event only if that same
/// epoch is still active, so delayed IRQ work cannot cross UI sessions.
static ACTIVE_INPUT_EPOCH: AtomicU64 = AtomicU64::new(0);
static NEXT_INPUT_EPOCH: AtomicU64 = AtomicU64::new(1);

fn next_input_epoch() -> u64 {
    loop {
        let epoch = NEXT_INPUT_EPOCH.fetch_add(1, Ordering::Relaxed);
        if epoch != 0 {
            return epoch;
        }
    }
}

struct EventState {
    events: RingBuffer<UiInputEvent, EVENT_QUEUE_CAPACITY>,
    next_sequence: u64,
    waiter: Option<TaskId>,
    dropped: u64,
    overflow_pending: bool,
}

impl EventState {
    const fn new() -> Self {
        Self {
            events: RingBuffer::new(),
            next_sequence: 1,
            waiter: None,
            dropped: 0,
            overflow_pending: false,
        }
    }

    fn reset(&mut self) -> Option<TaskId> {
        let waiter = self.waiter.take();
        self.events.clear();
        self.dropped = 0;
        self.overflow_pending = false;
        waiter
    }

    fn arm_waiter(&mut self, task: TaskId) {
        debug_assert!(self.waiter.is_none() || self.waiter == Some(task));
        self.waiter = Some(task);
    }

    fn push(&mut self, mut event: UiInputEvent) {
        event.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        if let Err(event) = self.events.push(event) {
            let _ = self.events.pop();
            let _ = self.events.push(event);
            self.dropped = self.dropped.saturating_add(1);
            self.overflow_pending = true;
        }
    }

    fn stage(&self, destination: &mut [UiInputEvent]) -> usize {
        let count = destination.len().min(self.events.len());
        for (index, slot) in destination[..count].iter_mut().enumerate() {
            *slot = *self
                .events
                .get(index)
                .expect("UI event length changed while locked");
        }
        if count != 0 && self.overflow_pending {
            destination[0].flags |= UI_EVENT_FLAG_OVERFLOW;
        }
        count
    }

    fn commit(&mut self, count: usize) {
        debug_assert!(count <= self.events.len());
        for _ in 0..count {
            let _ = self.events.pop();
        }
        if count != 0 {
            self.overflow_pending = false;
        }
    }
}

static EVENTS: SpinLockIRQ<EventState> = SpinLockIRQ::new(EventState::new());

/// Whether a userspace process currently owns display and desktop input.
#[inline]
#[must_use]
pub fn is_owned() -> bool {
    OWNER.load(Ordering::Acquire) != 0
}

/// Snapshot the current input-routing epoch while a device decoder is locked.
#[inline]
#[must_use]
pub(crate) fn input_epoch() -> u64 {
    ACTIVE_INPUT_EPOCH.load(Ordering::Acquire)
}

/// Whether `pid` is the current userspace display/input owner.
#[inline]
#[must_use]
pub fn is_owner(pid: ProcessId) -> bool {
    !pid.is_kernel() && OWNER.load(Ordering::Acquire) == pid.as_u64()
}

/// Acquire the framebuffer and input seat for `pid`.
///
/// Re-acquiring from the current owner is idempotent and preserves pending
/// input. A successful first acquisition drains stale console-side device
/// events after publishing ownership, so all subsequently decoded events go
/// only to the unified queue.
pub fn acquire(pid: ProcessId) -> Result<UiDisplayInfo, UiError> {
    if pid.is_kernel() {
        return Err(UiError::NotOwner);
    }

    let mut session = SESSION.lock();
    let current = OWNER.load(Ordering::Acquire);
    if current == pid.as_u64() {
        return session.scanout.map(display_info).ok_or(UiError::NoDisplay);
    }
    if current != 0 {
        return Err(UiError::Busy);
    }

    let scanout = crate::devices::framebuffer::suspend_for_userspace().ok_or(UiError::NoDisplay)?;
    let mut events = EVENTS.lock();
    let stale_waiter = events.reset();
    debug_assert!(stale_waiter.is_none());
    // Route decisions and these legacy-queue drains share the same lock. An
    // event decoded before the transition is therefore either queued before
    // and cleared here, or rejected when its sampled epoch no longer matches.
    crate::devices::ps2::keyboard::clear_events();
    crate::devices::ps2::mouse::clear_events();
    session.scanout = Some(scanout);
    OWNER.store(pid.as_u64(), Ordering::Release);
    let epoch = next_input_epoch();
    ACTIVE_INPUT_EPOCH.store(epoch, Ordering::Release);
    drop(events);
    drop(session);
    Ok(display_info(scanout))
}

/// Release a session owned by `pid` and repaint the saved terminal surface.
pub fn release(pid: ProcessId) -> Result<(), UiError> {
    release_inner(pid).then_some(()).ok_or(UiError::NotOwner)
}

/// Release `pid` if it owns the session. Used by successful exec and exit.
#[must_use]
pub fn release_if_owner(pid: ProcessId) -> bool {
    release_inner(pid)
}

fn release_inner(pid: ProcessId) -> bool {
    if pid.is_kernel() || OWNER.load(Ordering::Acquire) != pid.as_u64() {
        return false;
    }
    let mut session = SESSION.lock();
    if OWNER.load(Ordering::Acquire) != pid.as_u64() {
        return false;
    }

    let mut events = EVENTS.lock();
    // Publish the routing transition while holding the same lock used to
    // commit IRQ events. A route carrying the prior epoch is then discarded.
    ACTIVE_INPUT_EPOCH.store(0, Ordering::Release);
    OWNER.store(0, Ordering::Release);
    let waiter = events.reset();
    crate::devices::ps2::keyboard::clear_events();
    crate::devices::ps2::mouse::clear_events();
    drop(events);
    session.scanout = None;
    crate::devices::framebuffer::resume_from_userspace();
    drop(session);
    wake_waiter(waiter);
    true
}

fn display_info(scanout: Scanout) -> UiDisplayInfo {
    UiDisplayInfo {
        version: UI_ABI_VERSION,
        width: u32::from(scanout.width),
        height: u32::from(scanout.height),
        stride: scanout.pitch as u32,
        bits_per_pixel: 32,
        red_shift: scanout.format.red_shift(),
        red_size: scanout.format.red_size(),
        green_shift: scanout.format.green_shift(),
        green_size: scanout.format.green_size(),
        blue_shift: scanout.format.blue_shift(),
        blue_size: scanout.format.blue_size(),
        flags: UI_DISPLAY_NATIVE_PIXEL_FORMAT,
        reserved: 0,
    }
}

/// Copy validated damaged rows from a userspace-native backbuffer to scanout.
///
/// An empty damage list means the complete visible surface. The source must
/// still describe a complete framebuffer; this keeps offsets stable across
/// partial presents and lets the safe libuser wrapper prove its slice is long
/// enough before the kernel touches any row.
pub fn present(
    pid: ProcessId,
    source: u64,
    source_len: usize,
    source_stride: usize,
    damage: &[UiRect],
) -> Result<(), UiError> {
    let session = SESSION.lock();
    if OWNER.load(Ordering::Acquire) != pid.as_u64() || pid.is_kernel() {
        return Err(UiError::NotOwner);
    }
    let scanout = session.scanout.ok_or(UiError::NoDisplay)?;
    validate_present(scanout, source_len, source_stride, damage)?;
    let visible_row_bytes = usize::from(scanout.width)
        .checked_mul(4)
        .ok_or(UiError::InvalidArgument)?;
    let required = usize::from(scanout.height.saturating_sub(1))
        .checked_mul(source_stride)
        .and_then(|offset| offset.checked_add(visible_row_bytes))
        .ok_or(UiError::InvalidArgument)?;
    let prepared =
        crate::arch::x86_64::usercopy::prepare_user_read(source, required).ok_or(UiError::Fault)?;

    if damage.is_empty() {
        let full = UiRect {
            x: 0,
            y: 0,
            width: u32::from(scanout.width),
            height: u32::from(scanout.height),
        };
        copy_rect(scanout, &prepared, source_stride, full)?;
    } else {
        for &rect in damage {
            copy_rect(scanout, &prepared, source_stride, rect)?;
        }
    }
    // WC scanout writes may remain buffered after the last row copy. Drain
    // them once per present (not once per row or rectangle) so success means
    // every damaged pixel is globally ordered before userspace reuses the
    // source buffer or submits another frame.
    crate::arch::x86_64::sfence();
    notify_accelerated_display(scanout, damage);
    Ok(())
}

/// Forward the already-validated damage to VMware's FIFO only when Limine's
/// framebuffer is the exact SVGA frontbuffer. A failed optional notification
/// never turns a completed CPU copy into a userspace presentation failure.
fn notify_accelerated_display(scanout: Scanout, damage: &[UiRect]) {
    let Some(info) = crate::devices::display::device_info() else {
        return;
    };
    if scanout.buffer.is_null() {
        return;
    }
    let physical = crate::mm::virt_to_phys(VirtAddr::new_truncate(scanout.buffer as u64)).as_u64();
    let Ok(pitch) = u32::try_from(scanout.pitch) else {
        return;
    };
    if !info.matches_boot_framebuffer(
        physical,
        u32::from(scanout.width),
        u32::from(scanout.height),
        pitch,
        32,
    ) {
        if !SVGA_SCANOUT_MISMATCH_WARNED.swap(true, Ordering::AcqRel) {
            ::log::warn!(
                "ui: VMware SVGA II frontbuffer differs from Limine scanout; FIFO updates disabled"
            );
        }
        return;
    }

    let mut rectangles = [crate::devices::display::Rect::new(0, 0, 1, 1); UI_MAX_DAMAGE_RECTS];
    for (destination, source) in rectangles.iter_mut().zip(damage.iter().copied()) {
        *destination =
            crate::devices::display::Rect::new(source.x, source.y, source.width, source.height);
    }
    match crate::devices::display::present(&rectangles[..damage.len()]) {
        Ok(()) => {
            if !SVGA_PRESENT_CONFIRMED.swap(true, Ordering::AcqRel) {
                ::log::info!("ui: VMware SVGA II FIFO damage updates active");
            }
        },
        Err(error) => {
            if !SVGA_PRESENT_WARNED.swap(true, Ordering::AcqRel) {
                ::log::warn!("ui: VMware SVGA II FIFO update failed: {}", error);
            }
        },
    }
}

fn validate_present(
    scanout: Scanout,
    source_len: usize,
    source_stride: usize,
    damage: &[UiRect],
) -> Result<(), UiError> {
    if damage.len() > UI_MAX_DAMAGE_RECTS {
        return Err(UiError::InvalidArgument);
    }
    let visible_row_bytes = usize::from(scanout.width)
        .checked_mul(4)
        .ok_or(UiError::InvalidArgument)?;
    if source_stride < visible_row_bytes || !source_stride.is_multiple_of(4) {
        return Err(UiError::InvalidArgument);
    }
    let required = usize::from(scanout.height.saturating_sub(1))
        .checked_mul(source_stride)
        .and_then(|offset| offset.checked_add(visible_row_bytes))
        .ok_or(UiError::InvalidArgument)?;
    if source_len < required {
        return Err(UiError::InvalidArgument);
    }
    for &rect in damage {
        validate_rect(scanout, rect)?;
    }
    Ok(())
}

fn validate_rect(scanout: Scanout, rect: UiRect) -> Result<(), UiError> {
    if rect.width == 0 || rect.height == 0 {
        return Err(UiError::InvalidArgument);
    }
    let right = rect
        .x
        .checked_add(rect.width)
        .ok_or(UiError::InvalidArgument)?;
    let bottom = rect
        .y
        .checked_add(rect.height)
        .ok_or(UiError::InvalidArgument)?;
    if right > u32::from(scanout.width) || bottom > u32::from(scanout.height) {
        return Err(UiError::InvalidArgument);
    }
    Ok(())
}

fn copy_rect(
    scanout: Scanout,
    source: &crate::arch::x86_64::usercopy::PreparedUserRead,
    source_stride: usize,
    rect: UiRect,
) -> Result<(), UiError> {
    let x = rect.x as usize;
    let row_bytes = (rect.width as usize) * 4;
    for y in rect.y as usize..(rect.y + rect.height) as usize {
        let source_offset = y
            .checked_mul(source_stride)
            .and_then(|offset| offset.checked_add(x * 4))
            .ok_or(UiError::InvalidArgument)?;
        let destination_offset = y
            .checked_mul(scanout.pitch)
            .and_then(|offset| offset.checked_add(x * 4))
            .ok_or(UiError::InvalidArgument)?;
        // SAFETY: `validate_rect` proved x/width/y are within the visible
        // scanout, boot validation proved pitch covers every visible row, and
        // the framebuffer mapping remains live for the kernel's lifetime.
        let destination = unsafe {
            core::slice::from_raw_parts_mut(scanout.buffer.add(destination_offset), row_bytes)
        };
        if !source.copy_to_kernel(source_offset, destination) {
            return Err(UiError::Fault);
        }
    }
    Ok(())
}

/// Route one decoded keyboard event from IRQ context.
pub(crate) fn route_key_event(epoch: u64, event: KeyEvent) {
    let timestamp = crate::time::uptime_ns();
    let mut flags = 0;
    if event.pressed {
        flags |= UI_EVENT_FLAG_PRESSED;
    }
    if event.repeat {
        flags |= UI_EVENT_FLAG_REPEAT;
    }
    let wire = UiInputEvent {
        sequence: 0,
        timestamp_ns: timestamp,
        kind: UI_EVENT_KEY,
        flags,
        modifiers: event.modifiers.bits(),
        buttons: 0,
        code: u32::from(event.raw_scancode),
        value1: event.character.map_or(0, |character| character as i32),
        value2: 0,
        value3: 0,
        reserved: [0; 2],
    };
    route_event(epoch, wire, || {
        crate::devices::ps2::keyboard::enqueue_console_event(event);
    });
}

/// Route one decoded pointer sample from IRQ context.
pub(crate) fn route_mouse_event(epoch: u64, event: MouseEvent) {
    let wire = UiInputEvent {
        sequence: 0,
        timestamp_ns: crate::time::uptime_ns(),
        kind: UI_EVENT_POINTER,
        flags: 0,
        modifiers: 0,
        buttons: u16::from(event.buttons.bits()),
        code: 0,
        value1: i32::from(event.dx),
        value2: i32::from(event.dy),
        value3: i32::from(event.dz),
        reserved: [0; 2],
    };
    route_event(epoch, wire, || {
        crate::devices::ps2::mouse::enqueue_device_event(event);
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventRoute {
    Userspace,
    Kernel,
    Stale,
}

const fn classify_event_route(sampled_epoch: u64, active_epoch: u64) -> EventRoute {
    if sampled_epoch != active_epoch {
        EventRoute::Stale
    } else if active_epoch == 0 {
        EventRoute::Kernel
    } else {
        EventRoute::Userspace
    }
}

fn route_event<F>(sampled_epoch: u64, event: UiInputEvent, kernel_fallback: F)
where
    F: FnOnce(),
{
    let mut state = EVENTS.lock();
    match classify_event_route(sampled_epoch, ACTIVE_INPUT_EPOCH.load(Ordering::Acquire)) {
        EventRoute::Kernel => {
            // Keep the route lock through the fallback insertion. A following
            // acquire must take this lock before clearing the legacy queue.
            kernel_fallback();
            return;
        },
        EventRoute::Stale => return,
        EventRoute::Userspace => {},
    }
    state.push(event);
    // One queued wake is sufficient for every event now visible in this
    // batch. Taking the registration avoids repeated scheduler/IPI work when
    // multiple device reports arrive before the reader is dispatched.
    let waiter = state.waiter.take();
    drop(state);
    wake_waiter(waiter);
}

/// Wake the UI reader after a signal was accepted for the owning process.
///
/// The process table must not be held by the caller: an empty reader checks
/// effective signal delivery while holding `EVENTS`, so taking the locks in
/// the opposite order would deadlock. Spurious wakes for blocked or ignored
/// signals are harmless; the reader rechecks the effective-delivery predicate
/// and parks again without returning `EINTR`.
pub(crate) fn notify_signal(pid: ProcessId) {
    if OWNER.load(Ordering::Acquire) != pid.as_u64() || pid.is_kernel() {
        return;
    }
    let mut state = EVENTS.lock();
    let waiter = if OWNER.load(Ordering::Acquire) == pid.as_u64() {
        state.waiter.take()
    } else {
        None
    };
    drop(state);
    wake_waiter(waiter);
}

fn wake_waiter(waiter: Option<TaskId>) {
    if let Some(waiter) = waiter {
        crate::sched::scheduler::wake_blocked_task(waiter);
    }
}

#[must_use]
pub(crate) fn wait_ready(pid: ProcessId) -> u32 {
    let state = EVENTS.lock();
    if OWNER.load(Ordering::Acquire) != pid.as_u64() || pid.is_kernel() {
        WAIT_READY_HANGUP
    } else if state.events.is_empty() {
        0
    } else {
        WAIT_READY_UI_INPUT
    }
}

pub(crate) fn arm_external_wait(pid: ProcessId, task: TaskId) -> Result<u32, UiError> {
    let mut state = EVENTS.lock();
    if OWNER.load(Ordering::Acquire) != pid.as_u64() || pid.is_kernel() {
        return Ok(WAIT_READY_HANGUP);
    }
    if !state.events.is_empty() {
        return Ok(WAIT_READY_UI_INPUT);
    }
    match state.waiter {
        None => state.waiter = Some(task),
        Some(existing) if existing == task => {},
        Some(_) => return Err(UiError::Busy),
    }
    Ok(0)
}

pub(crate) fn disarm_external_wait(task: TaskId) {
    let mut state = EVENTS.lock();
    clear_waiter(&mut state, task);
}

/// Copy up to `capacity` ordered events to `destination`, sleeping when empty.
///
/// `timeout_ns == 0` is non-blocking and [`UI_TIMEOUT_INFINITE`] waits until
/// an event or ownership change. Waiter registration and scheduler parking
/// form one IRQ-excluding hand-off, so a producer cannot observe the waiter
/// before it is wakeable and no polling fallback is needed. Events are staged,
/// copied, and only then removed while the queue lock is held, so `EFAULT`
/// never consumes input.
pub fn read_events(
    pid: ProcessId,
    destination: u64,
    capacity: usize,
    timeout_ns: u64,
) -> Result<usize, UiError> {
    if capacity == 0 {
        return Ok(0);
    }
    if capacity > UI_MAX_EVENTS_PER_READ {
        return Err(UiError::InvalidArgument);
    }
    if OWNER.load(Ordering::Acquire) != pid.as_u64() || pid.is_kernel() {
        return Err(UiError::NotOwner);
    }
    let byte_capacity = capacity
        .checked_mul(core::mem::size_of::<UiInputEvent>())
        .ok_or(UiError::InvalidArgument)?;
    // Resolve COW and validate the entire destination before taking EVENTS.
    // The prepared copy used at commit time only rechecks writable PTEs and
    // cannot allocate or initiate a cross-CPU TLB shootdown under the IRQ lock.
    let prepared = crate::arch::x86_64::usercopy::prepare_user_write(destination, byte_capacity)
        .ok_or(UiError::Fault)?;
    // The live scheduler owns current-task identity through TaskNode; the
    // older task-local compatibility slot is not populated by context
    // switches and would reject valid ring-3 callers as `NoCurrentTask`.
    let task = crate::sched::scheduler::with_current_node(|node| node.task.id)
        .ok_or(UiError::NoCurrentTask)?;
    let start = Instant::now();
    let deadline =
        (timeout_ns != UI_TIMEOUT_INFINITE).then(|| start + Duration::from_nanos(timeout_ns));
    let mut staged = [UiInputEvent::default(); UI_MAX_EVENTS_PER_READ];

    loop {
        let mut state = EVENTS.lock();
        if OWNER.load(Ordering::Acquire) != pid.as_u64() {
            clear_waiter(&mut state, task);
            return Err(UiError::NotOwner);
        }
        let count = state.stage(&mut staged[..capacity]);
        if count != 0 {
            // SAFETY: UiInputEvent is repr(C), Copy, and has an explicit
            // zeroed reserved tail, so the staged records contain no implicit
            // padding. The byte slice covers exactly the initialized prefix.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    staged.as_ptr().cast::<u8>(),
                    count * core::mem::size_of::<UiInputEvent>(),
                )
            };
            if !prepared.copy_from_kernel(bytes) {
                clear_waiter(&mut state, task);
                return Err(UiError::Fault);
            }
            state.commit(count);
            clear_waiter(&mut state, task);
            return Ok(count);
        }
        if timeout_ns == 0 {
            clear_waiter(&mut state, task);
            return Ok(0);
        }

        let interrupted = crate::user::process::with_current_process(|process| {
            process.signals.has_interrupting_delivery()
        })
        .unwrap_or(false);
        if interrupted {
            clear_waiter(&mut state, task);
            return Err(UiError::Interrupted);
        }

        let now = Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            clear_waiter(&mut state, task);
            return Ok(0);
        }
        state.arm_waiter(task);
        crate::sched::scheduler::block_current_until_releasing(deadline, state);
    }
}

fn clear_waiter(state: &mut EventState, task: TaskId) {
    if state.waiter == Some(task) {
        state.waiter = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::gfx::PixelFormat;
    use crate::devices::ps2::keyboard::{KeyCode, KeyModifiers};
    use crate::devices::ps2::mouse::MouseButtons;

    fn scanout(width: u16, height: u16, pitch: usize) -> Scanout {
        Scanout {
            buffer: core::ptr::null_mut(),
            pitch,
            width,
            height,
            format: PixelFormat::XRGB8888,
        }
    }

    #[test]
    fn complete_backbuffer_and_damage_are_checked_before_copy() {
        let target = scanout(800, 600, 3200);
        assert_eq!(validate_present(target, 1_920_000, 3200, &[]), Ok(()));
        assert_eq!(
            validate_present(target, 1_919_999, 3200, &[]),
            Err(UiError::InvalidArgument)
        );
        assert_eq!(
            validate_present(target, 1_920_000, 3199, &[]),
            Err(UiError::InvalidArgument)
        );
        assert_eq!(
            validate_present(target, 1_920_000, 3200, &[UiRect {
                x: 799,
                y: 599,
                width: 1,
                height: 1,
            }],),
            Ok(())
        );
    }

    #[test]
    fn invalid_and_overflowing_damage_is_rejected() {
        let target = scanout(64, 48, 256);
        for rect in [
            UiRect {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
            },
            UiRect {
                x: 63,
                y: 0,
                width: 2,
                height: 1,
            },
            UiRect {
                x: u32::MAX,
                y: 0,
                width: 2,
                height: 1,
            },
        ] {
            assert_eq!(
                validate_present(target, 12_288, 256, &[rect]),
                Err(UiError::InvalidArgument)
            );
        }
        let too_many = [UiRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        }; UI_MAX_DAMAGE_RECTS + 1];
        assert_eq!(
            validate_present(target, 12_288, 256, &too_many),
            Err(UiError::InvalidArgument)
        );
    }

    #[test]
    fn event_queue_is_ordered_and_marks_overflow() {
        let mut state = EventState::new();
        for value in 0..=EVENT_QUEUE_CAPACITY {
            state.push(UiInputEvent {
                value1: value as i32,
                ..UiInputEvent::default()
            });
        }
        assert_eq!(state.events.len(), EVENT_QUEUE_CAPACITY);
        assert_eq!(state.dropped, 1);
        assert_eq!(state.events.peek().map(|event| event.sequence), Some(2));

        let mut staged = [UiInputEvent::default(); 1];
        assert_eq!(state.stage(&mut staged), 1);
        assert_eq!(state.events.len(), EVENT_QUEUE_CAPACITY);
        assert_eq!(staged[0].value1, 1);
        assert_ne!(staged[0].flags & UI_EVENT_FLAG_OVERFLOW, 0);

        // A failed userspace copy leaves the staged event and overflow marker
        // untouched. Only an explicit commit advances the queue.
        let mut retry = [UiInputEvent::default(); 1];
        assert_eq!(state.stage(&mut retry), 1);
        assert_eq!(retry, staged);
        state.commit(1);
        assert_eq!(state.events.len(), EVENT_QUEUE_CAPACITY - 1);
        assert!(!state.overflow_pending);
    }

    #[test]
    fn waiter_registration_remains_visible_until_event_or_release_wakes_it() {
        let mut state = EventState::new();
        let task = TaskId(17);
        state.arm_waiter(task);
        state.push(UiInputEvent {
            value1: 42,
            ..UiInputEvent::default()
        });

        // An IRQ producer observes the registered task while the event is
        // queued. In the live path the same EVENTS guard is retained until
        // `block_current_until_releasing` has linked that task as Blocked.
        assert_eq!(state.waiter.take(), Some(task));
        assert!(state.waiter.is_none());
        assert_eq!(state.events.len(), 1);

        // Ownership release extracts (rather than silently discarding) the
        // waiter so it can issue the same guaranteed scheduler wake.
        state.arm_waiter(task);
        assert_eq!(state.reset(), Some(task));
        assert!(state.waiter.is_none());
        assert!(state.events.is_empty());
    }

    #[test]
    fn only_the_registered_task_can_clear_a_wait_registration() {
        let mut state = EventState::new();
        state.arm_waiter(TaskId(23));
        clear_waiter(&mut state, TaskId(24));
        assert_eq!(state.waiter, Some(TaskId(23)));
        clear_waiter(&mut state, TaskId(23));
        assert!(state.waiter.is_none());
    }

    #[test]
    fn input_epoch_changes_drop_delayed_events() {
        assert_eq!(classify_event_route(0, 0), EventRoute::Kernel);
        assert_eq!(classify_event_route(7, 7), EventRoute::Userspace);
        assert_eq!(classify_event_route(7, 0), EventRoute::Stale);
        assert_eq!(classify_event_route(7, 8), EventRoute::Stale);
        assert_eq!(classify_event_route(0, 8), EventRoute::Stale);
    }

    #[test]
    fn device_events_keep_wire_semantics() {
        let key = KeyEvent {
            code: KeyCode::A,
            pressed: true,
            character: Some('A'),
            modifiers: KeyModifiers::LEFT_SHIFT | KeyModifiers::CAPS_LOCK,
            raw_scancode: 0x1e,
            repeat: true,
        };
        let mut flags = 0;
        if key.pressed {
            flags |= UI_EVENT_FLAG_PRESSED;
        }
        if key.repeat {
            flags |= UI_EVENT_FLAG_REPEAT;
        }
        assert_eq!(flags, UI_EVENT_FLAG_PRESSED | UI_EVENT_FLAG_REPEAT);
        assert_eq!(key.modifiers.bits(), (1 << 0) | (1 << 8));
        assert_eq!(key.character.map(|value| value as i32), Some(65));

        let mouse = MouseEvent {
            buttons: MouseButtons::LEFT | MouseButtons::FORWARD,
            dx: 12,
            dy: -7,
            dz: 1,
        };
        assert_eq!(u16::from(mouse.buttons.bits()), 1 | 32);
        assert_eq!((i32::from(mouse.dx), i32::from(mouse.dy)), (12, -7));
    }
}

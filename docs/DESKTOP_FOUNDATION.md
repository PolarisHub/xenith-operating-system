# Desktop Foundation

Xenith now boots a lean full-screen graphical shell, `/bin/xenith-desktop`, on
supported framebuffers. It software-composes a procedural midnight wallpaper,
glass top bar and dock, launcher, status chrome, and pointer cursor without
bundling default applications. Its steady-state loop allocates nothing and
blocks indefinitely when there is no input.

## Ownership model

One process at a time may own a UI session. The session combines the boot
framebuffer scanout and the PS/2 keyboard/pointer input seat so two independent
writers or consumers cannot race. Re-acquiring from the owner is idempotent;
another process receives `EBUSY`.

While userspace owns the session, the kernel terminal continues updating its
saved cell model but stops writing video memory. `ui_release`, a successful
`exec` by the owner, or owner exit returns the session to the kernel. Normal
task-context release redraws the complete current terminal immediately; a
synchronous fatal exception never blocks behind a preempted terminal writer:
it redraws immediately when the renderer lock is free, otherwise the active
writer consumes the pending full redraw either before releasing that lock or
through its mandatory nonblocking retry immediately after unlock. A failed
`exec` does not discard ownership.

Framebuffer memory is never mapped into a process. The desktop renders into a
normal private anonymous userspace backbuffer and `ui_present` copies validated
damaged rows through the fault-recoverable user-copy path. This fits the current
VM teardown rules and gives scanout exactly one active writer.

## Syscalls

The safe wrappers are exported by `libuser`; the shared constants and wire
records are in `xenith-abi`.

| Number | Call | Result and contract |
| ---: | --- | --- |
| 54 | `ui_acquire(info)` | Exclusively acquire display and input, then write one `UiDisplayInfo`. |
| 55 | `ui_present(pixels, length, stride, rects, count, flags)` | Copy a complete native-format backbuffer's damaged rows to scanout. `flags` must be zero. |
| 56 | `ui_read_events(events, capacity, timeout_ns)` | Return an ordered batch count from the shared keyboard/pointer queue. |
| 57 | `ui_release()` | Release the caller's session and restore the kernel terminal. |

`ui_present` accepts at most 64 `UiRect` records. Each rectangle must be
non-empty and entirely inside the display. An empty list presents the full
surface. The byte stride must be a multiple of four and at least `width * 4`;
the supplied slice must cover every visible row. All geometry and source pages
are checked once before the first scanout write; damaged rows then reuse that
prepared read instead of repeating a page-table walk per row.

`ui_read_events` accepts at most 32 records per call. A zero timeout polls,
`u64::MAX` waits indefinitely, and other values are relative nanoseconds. Empty
waits use an allocation-free intrusive blocked queue. Registration and parking
are one IRQ-excluding hand-off; a wake that meets scheduler-lock contention is
atomically deferred and drained as that lock releases, so no polling fallback
or lost-wake window remains. Events are copied to the validated user buffer
before the queue commits them, so `EFAULT` consumes nothing. Ownership release
and signal delivery wake the same waiter. A caught or process-affecting signal
interrupts an empty wait with `EINTR`; ignored and default-ignore signals do not.

## Stable wire layouts

All records use `#[repr(C)]`, ABI version 1.

| Record | Size/alignment | Fields in byte order |
| --- | --- | --- |
| `UiDisplayInfo` | 32/4 bytes | `u32 version, width, height, stride`; `u16 bits_per_pixel`; `u8 red_shift, red_size, green_shift, green_size, blue_shift, blue_size`; `u32 flags, reserved` |
| `UiRect` | 16/4 bytes | `u32 x, y, width, height` |
| `UiInputEvent` | 48/8 bytes | `u64 sequence, timestamp_ns`; `u16 kind, flags, modifiers, buttons`; `u32 code`; `i32 value1, value2, value3`; `u32 reserved[2]` (eight zero bytes) |

The display is a validated 32-bpp direct-colour format. `red_shift/red_size`,
`green_shift/green_size`, and `blue_shift/blue_size` describe non-empty,
non-overlapping bit ranges in each native 32-bit pixel. The
`UI_DISPLAY_NATIVE_PIXEL_FORMAT` flag states that the submitted backbuffer must
use those masks; do not assume one byte order.

The fixed discriminator and bit values are:

| Group | Values |
| --- | --- |
| Display flags | `UI_DISPLAY_NATIVE_PIXEL_FORMAT = 0x0001` |
| Event kinds | `UI_EVENT_KEY = 1`, `UI_EVENT_POINTER = 2` |
| Event flags | `PRESSED = 0x0001`, `REPEAT = 0x0002`, `OVERFLOW = 0x8000` |
| Modifiers | left/right Shift bits 0/1, left/right Ctrl 2/3, left/right Alt 4/5, left/right Super 6/7, Caps/Num/Scroll Lock 8/9/10 |
| Pointer buttons | left bit 0, right 1, middle 2, back 4, forward 5 |

Events from both devices receive one monotonic sequence and uptime-nanosecond
timestamp order. Key events use `kind = UI_EVENT_KEY`, raw Set-1 scancode in
`code` (`0xE000 | code` for extended keys), Unicode scalar or zero in `value1`,
pressed/repeat flags, and modifier bits. Pointer events use
`kind = UI_EVENT_POINTER`, button bits, relative
`dx/dy/wheel` in `value1/value2/value3`, and zero `code`. The queue holds 512
events; on pressure it drops the oldest record and marks the first subsequently
read record with `UI_EVENT_FLAG_OVERFLOW`. Routing epochs discard an IRQ event
that was decoded across a release/acquire boundary, so input from one owner can
never enter the next owner's queue.

## Desktop-shell implementation

The shell validates the native channel masks, maps exactly one anonymous
backbuffer, and packs every RGB colour into the advertised framebuffer format.
Its renderer reconstructs procedural layers only inside a fixed 12-rectangle
damage tracker. The first frame is a full present; cursor movement and launcher
state changes use bounded partial presents. Overflowed input conservatively
forces one full redraw.

Input is read in fixed 32-record batches. Relative pointer movement is
accelerated with integer arithmetic and clamped to the display. Super or the
dock button toggles the launcher; Escape closes it. `Ctrl+Alt+Backspace`,
`Ctrl+Alt+F1`, and `Super+Shift+Q` are deterministic recovery gestures. An
orderly exit releases scanout and unmaps the backbuffer; process teardown is
the crash-safe release path.

Init probes the framebuffer session, supervises the desktop with blocking
`waitpid`, retries signal interruptions without abandoning the live child, and
execs `/bin/sh` if no framebuffer exists or the desktop exits or fails. The
desktop emits `XENITH_DESKTOP_READY` only after its first successful present.
Launcher markers are emitted only after the corresponding damaged frame is
presented, and `XENITH_DESKTOP_CLEAN_EXIT` appears only after release and unmap
both succeed. Failures carry
`XENITH_DESKTOP_FAIL stage=<stage> errno=<number>`.

## Future client protocol

`xenith-abi::compositor` fixes the transport-neutral ABI for the next phase.
It includes a magic/versioned bounded header, generation-safe 64-bit handles,
shared-surface tokens and byte bounds, BGRX/BGRA formats, up to 64 damage
rectangles, create/destroy/attach/commit/role/title/state/configure-ack
requests, configure/close/focus/pointer/key/text/frame-done events, and
canonical zero-reserved validation. All wire fields have fixed widths; no Rust
pointer, `usize`, `bool`, or data-carrying enum crosses the boundary.

This is a wire contract, not a live server. Kernel IPC/shared-memory handles,
desktop client connections, and multi-process window composition remain to be
implemented. The same boundary is intended to keep a future PE/Win32
compatibility server out of the kernel.

## Current limits

- Exactly one process owns the display and input seat; today that is the
  single-process desktop shell.
- Presentation is CPU damage-copy only: no acceleration, page flipping, or
  vertical-sync contract exists.
- There is no connected multi-client compositor transport or shared client
  surface service, and there are no default applications. The wire records for
  that next layer exist but are not executable compatibility support.
- Desktop input currently comes only from the PS/2 keyboard and mouse drivers.
- PAT-capable x86_64 processors use write-combining framebuffer leaves with a
  cache-safe WB-to-WC transition and one store fence per completed present.
  Unsupported processors retain the loader's cache policy.
- VMware/emulator paths are covered separately; broad physical-hardware
  framebuffer and input validation remains pending.
- The four UI syscall paths retain their ring-3 lifecycle gate. A separate
  desktop gate proves the rendered non-flat frame, launcher input and partial
  damage, bounded idle stability, recovery chord, clean release/unmap, shell
  fallback, and terminal repaint.

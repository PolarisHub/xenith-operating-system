# Xenith desktop

`xenith-desktop` is the first allocation-free userspace owner of Xenith's
framebuffer and desktop input session. It maps one native-format backbuffer,
cover-crops the exact embedded 192x225 Sedat Bucan photo as its wallpaper,
draws one neutral bottom bar and a restrained launcher, submits only bounded
damaged rectangles, and contains an eight-client compositor coordinator. When
idle it sleeps indefinitely in one multi-source `wait` across UI input and
every live channel; there is no frame timer or polling loop. Normal launch
allocates no compositor channel and starts no application.

The coordinator retains at most eight surfaces and 64 MiB of mapped buffers
per client, with a 256 MiB global mapping quota. It validates and isolates each
client, composites read-only shared buffers in z-order, routes pointer focus and
implicit multi-button capture, sends keys/text only to the focused surface, and
disconnects only a stalled nonblocking event recipient. Desktop shortcuts and
chrome remain authoritative. There is no general service rendezvous yet, so
the packaged smoke below is currently the only live connection path.

## Runtime contract

- Installed path: `/bin/xenith-desktop`
- Ready marker, emitted after the first successful full present:
  `XENITH_DESKTOP_READY`
- Deterministic recovery: `Ctrl+Alt+Backspace` or `Ctrl+Alt+F1`
- Alternate recovery: `Super+Shift+Q`
- Recovery marker: `XENITH_DESKTOP_EXIT`
- Marker after successful framebuffer release and unmap:
  `XENITH_DESKTOP_CLEAN_EXIT`
- Failure marker: `XENITH_DESKTOP_FAIL stage=<stage> errno=<number>`
- `--smoke-exit` renders once, waits for one bounded event batch, and exits
  through the same release/unmap path.
- `--window-smoke` explicitly provisions one private compositor channel and
  uses `spawn_restricted` to launch `/bin/xenith-window-smoke` with only stdout,
  stderr, and its client endpoint installed as descriptor 3. It is never
  enabled by init or the normal desktop path. Combining it with `--smoke-exit`
  runs the complete shared-buffer protocol gate and then returns to the shell.
- Window smoke success markers: `XENITH_WINDOW_SMOKE_PRESENTED` and
  `XENITH_WINDOW_SMOKE_PASS`.

The launcher can be toggled with either Super key or the bottom-bar button and
closed with Escape. The smoke client is a test utility, not a default app.

The kernel configures the PS/2 mouse for 4 counts/mm at 100 Hz, preserves
in-flight framing across session changes, and resets corrupt packets reported
by the controller. The desktop applies bounded Q8 fixed-point gain while
retaining fractional motion.
The Set-1 US keyboard uses a 250 ms typematic delay and 30 Hz repeat rate.
The same seat also accepts xHCI direct-root-port USB boot-protocol keyboards
and relative mice. USB keys use bounded software typematic, and device removal
releases retained keys, modifiers, and buttons. Generic HID descriptors,
absolute tablets, hubs, and non-xHCI host controllers remain unsupported.

Input protocol limits remain explicit: no pointer enter/leave,
client-requested capture, IME/composition, distinct logical key code,
horizontal wheel, or dedicated key-overflow marker.

The checked-in PNG is the supplied source image. Its exact row-major RGB8
decode is embedded for allocation-free bilinear sampling, and host tests cover
the default sampler, cover-crop geometry, and bounded damaged rendering.

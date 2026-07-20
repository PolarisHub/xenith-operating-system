# Xenith desktop

`xenith-desktop` is the first allocation-free userspace owner of Xenith's
framebuffer and desktop input session. It maps one native-format backbuffer,
renders a procedural desktop, and submits only bounded damaged rectangles.
When idle it sleeps indefinitely in `ui_read_events`; there is no frame timer
or polling loop.

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

The launcher can be toggled with either Super key or the dock button and
closed with Escape. No applications are bundled into the shell.

At the integration resolution (320x200), the unobscured wallpaper pixel at
`(0, 0)` is RGB `(12, 20, 42)`, or `0x000c142a` in XRGB8888. This is covered
by the host renderer test and gives emulator gates a stable visual assertion.

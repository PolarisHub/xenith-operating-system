# Drivers

| Driver | State | Important bounds |
| --- | --- | --- |
| 16550 serial | Polled output and early logging | COM1, 38400 8N1 default. |
| VGA/framebuffer + VMware SVGA II | Pixel-format-aware text rendering, exclusive userspace scanout, CPU damage copy, and bounded SVGA FIFO `UPDATE`/`RECT_COPY`/fence commands | SVGA II `15ad:0405` only; FIFO updates are used only for an exact boot-frontbuffer match. No SVGA3, 3D, screen objects, page flipping, vsync, cursor plane, or generic GPU acceleration. |
| PS/2 controller, keyboard, mouse | Initialization, IRQ decode, bounded device queues, or one ordered UI-session queue | Set-1 US keyboard with 250 ms/30 Hz typematic; relative mouse at 4 counts/mm and 100 Hz with 3/4-byte packet re-synchronization. |
| xHCI + USB boot HID | BIOS handoff, controller reset, command/event/transfer rings, root-port enumeration, descriptors, boot keyboard/mouse interrupt input, MSI or 4 ms task-context polling, hotplug teardown | At most 2 controllers, 16 slots/controller, 4 HID interfaces/device, 2 KiB configuration descriptor, and direct root ports only. No hubs, EHCI/OHCI/UHCI, generic report descriptors, absolute tablets, mass storage, USB audio, isochronous endpoints, or arbitrary classes. |
| Intel HDA-compatible controller | PCI/D0/reset bring-up, CORB/RIRB DMA verb transport, codec/function-group discovery, and validated BDL/PCM stream programming scaffold | Real controller/codec transport, not audible playback. Codec widget routing, converter/pin/amp/EAPD programming, buffer refill, audio interrupt service, and hardware quirks remain. |
| CMOS/RTC | NVRAM and stable RTC reads | Update-in-progress and BCD handling. |
| PCI | Legacy config-space enumeration, bounded capability walking, ACPI `_PRT`/bridge swizzling, INTx and single-vector MSI selection | Segment 0 conventional configuration; ECAM, MSI-X tables, and interrupt remapping remain outside the current backend. |
| AHCI | Controller/port discovery, DMA command tables, sector I/O, and cache flush | Physical-device runtime validation is pending. |
| RTL8139/e1000 | DMA rings, bounded interrupt worker RX/TX, cause acknowledgement/rearm, link/MAC state, DHCPv4 configuration | MSI is used when safe, then ACPI-routed INTx; a 10 ms poll is the fail-safe. Physical-network validation is pending. |
| LAPIC/IOAPIC/PIC | xAPIC/x2APIC programming, per-CPU timers, INIT/SIPI, reschedule and TLB IPIs, GSI routing, legacy PIC masking | Up to 64 logical CPUs; interrupt-remapping hardware is not modeled. |
| HPET/PIT/LAPIC timer | Clock selection/calibration | HPET absence falls back rather than failing boot. |

DMA allocations preserve physical addresses and alignment. MMIO/port access is volatile and contained behind driver APIs. PCI probes match class/vendor/device identifiers before touching device-specific registers.

The terminal is a stateful ANSI/VT100 parser with cursor movement, scroll regions, erase/insert/delete, alternate screen, saved cursor, and 16/256/RGB SGR colors. The parser and framebuffer renderer are separate; cursor blink still needs timer-driven redraw. While a userspace UI session owns scanout, terminal writes update the saved cell model without touching video memory. Release, successful owner `exec`, or owner exit restores ownership and redraws that model.

The UI session routes decoded PS/2 and USB boot-HID key/pointer records through one 512-entry queue with shared sequence numbers and timestamps. The PS/2 mouse decoder checks packet headers, preserves in-flight framing across session queue drains, resets on controller parity/timeout errors, and drops overflow packets instead of converting corrupt bytes into motion. USB boot reports retain state, suppress unchanged reports, provide bounded software typematic, and synthesize releases when a device disconnects. Epoch checks discard input delayed across an ownership transition, and event reads commit only after a successful userspace copy. Empty reads sleep, interrupt delivery wakes the waiter, and a bounded recheck covers scheduler-lock contention. The userspace desktop consumes this single hardware seat, then routes focus, pointer capture, keys, and text across its bounded eight-client compositor coordinator. This does not make the kernel UI queue a multi-seat service or provide generic HID support.

## Windows driver-host policy boundary

`user/windrv-core` is a `no_std`, allocation-free policy crate for a future
isolated Windows driver host. It validates WDM IRP major-function values and
`CTL_CODE` fields, generation-safe driver/device/request identifiers,
image-confined callback addresses, bounded linear device stacks, checked
request transitions, and rights-attenuated port/MMIO/interrupt/DMA resource
descriptors. Fixed inline capacities are 64 drivers, 255 devices, 1024
requests, and 255 grants. These are data and state-machine contracts only;
PnP completion `Information` remains opaque for a future adapter to validate.

Xenith does not currently load or execute `.sys` files, expose those policy
descriptors to hardware, materialize the WDM ABI, enforce IOCTL buffer/access
semantics, emulate cancel spin locks/routines or Windows IRQL/PnP/power
behavior, implement KMDF/UMDF, or provide arbitrary Windows driver
compatibility. Xenith's native AHCI, RTL8139, e1000, PS/2, xHCI/HID, HDA, and controller
drivers remain independent kernel drivers and do not use the Windows policy
crate.

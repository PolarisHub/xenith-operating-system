# Drivers

| Driver | State | Important bounds |
| --- | --- | --- |
| 16550 serial | Polled output and early logging | COM1, 38400 8N1 default. |
| VGA/framebuffer | Pixel-format-aware text rendering and exclusive userspace scanout session | Validated native 32-bpp direct colour, damage-copy presentation, or VGA text fallback. No acceleration, vsync, or write-combining/PAT setup yet. |
| PS/2 controller, keyboard, mouse | Initialization, IRQ decode, bounded device queues, or one ordered UI-session queue | Set-1 US keyboard map and relative pointer packets; no USB/HID input yet. |
| CMOS/RTC | NVRAM and stable RTC reads | Update-in-progress and BCD handling. |
| PCI | Legacy config-space enumeration, bounded capability walking, ACPI `_PRT`/bridge swizzling, INTx and single-vector MSI selection | Segment 0 conventional configuration; ECAM, MSI-X tables, and interrupt remapping remain outside the current backend. |
| AHCI | Controller/port discovery, DMA command tables, sector I/O, and cache flush | Physical-device runtime validation is pending. |
| RTL8139/e1000 | DMA rings, bounded interrupt worker RX/TX, cause acknowledgement/rearm, link/MAC state, DHCPv4 configuration | MSI is used when safe, then ACPI-routed INTx; a 10 ms poll is the fail-safe. Physical-network validation is pending. |
| LAPIC/IOAPIC/PIC | xAPIC/x2APIC programming, per-CPU timers, INIT/SIPI, reschedule and TLB IPIs, GSI routing, legacy PIC masking | Up to 64 logical CPUs; interrupt-remapping hardware is not modeled. |
| HPET/PIT/LAPIC timer | Clock selection/calibration | HPET absence falls back rather than failing boot. |

DMA allocations preserve physical addresses and alignment. MMIO/port access is volatile and contained behind driver APIs. PCI probes match class/vendor/device identifiers before touching device-specific registers.

The terminal is a stateful ANSI/VT100 parser with cursor movement, scroll regions, erase/insert/delete, alternate screen, saved cursor, and 16/256/RGB SGR colors. The parser and framebuffer renderer are separate; cursor blink still needs timer-driven redraw. While a userspace UI session owns scanout, terminal writes update the saved cell model without touching video memory. Release, successful owner `exec`, or owner exit restores ownership and redraws that model.

The UI session routes decoded PS/2 key and pointer records through one 512-entry queue with shared sequence numbers and timestamps. Epoch checks discard input delayed across an ownership transition, and event reads commit only after a successful userspace copy. Empty reads sleep, IRQ delivery wakes the waiter, and a bounded recheck covers scheduler-lock contention. This is the input foundation for one future desktop shell, not a general HID or multi-client event service.

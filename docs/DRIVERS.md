# Drivers

| Driver | State | Important bounds |
| --- | --- | --- |
| 16550 serial | Polled output and early logging | COM1, 38400 8N1 default. |
| VGA/framebuffer | Text rendering | 32-bpp framebuffer or VGA text fallback. |
| PS/2 controller, keyboard, mouse | Initialization, IRQ decode, bounded queues | Set-1 US keyboard map. |
| CMOS/RTC | NVRAM and stable RTC reads | Update-in-progress and BCD handling. |
| PCI | Legacy config-space enumeration and driver binding | Every bus/device/function is bounded. |
| AHCI | Controller/port discovery and command structures | Storage write path is not the primary root path. |
| RTL8139/e1000 | DMA rings, autonomous bounded polling RX/TX, link/MAC state, DHCPv4 configuration | IRQs remain masked; physical-hardware boot/network validation is pending. |
| LAPIC/IOAPIC/PIC | Interrupt-controller programming | BSP path is the validated compile surface. |
| HPET/PIT/LAPIC timer | Clock selection/calibration | HPET absence falls back rather than failing boot. |

DMA allocations preserve physical addresses and alignment. MMIO/port access is volatile and contained behind driver APIs. PCI probes match class/vendor/device identifiers before touching device-specific registers.

The terminal is a stateful ANSI/VT100 parser with cursor movement, scroll regions, erase/insert/delete, alternate screen, saved cursor, and 16/256/RGB SGR colors. The parser and framebuffer renderer are separate; cursor blink still needs timer-driven redraw.

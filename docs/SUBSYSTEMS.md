# Subsystems

Xenith is a monolithic kernel with narrow shared contracts.

1. `arch/x86_64` owns CPU state, GDT/TSS, IDT, interrupt controllers, syscall entry, per-CPU storage, and context-switch assembly.
2. `mm` owns the HHDM, page-table editing, user address spaces, physical allocation, and the 32 MiB kernel heap.
3. `acpi` validates RSDP/RSDT/XSDT/MADT/FADT/DSDT/SSDT tables and hosts the bounded AML namespace/evaluator used for power state, resource, and PCI interrupt routing methods.
4. `time` selects HPET or LAPIC time, calibrates with PIT, and seeds wall time from CMOS.
5. `sched` owns tasks, per-CPU run queues and idle tasks, the sleep queue, kernel stacks, lazy FPU state, and CR3/TSS changes at dispatch.
6. `devices` owns serial, framebuffer/VGA, PS/2, PCI topology/capabilities/routing, AHCI, interrupt-driven RTL8139/e1000, CMOS, and the terminal parser.
7. `net` implements Ethernet, bounded ARP resolution/aging, IPv4, ICMP, UDP,
   reliable TCP state/retransmission/reassembly, routing, DHCPv4, DNS wire
   validation, loopback, live interface enumeration, and socket state. A
   kernel worker services physical adapters independently of socket syscalls.
8. `fs` provides VFS, per-open offsets, ramfs/initramfs, FAT32, and XenithFS.
9. `syscall` validates the register ABI and user ranges before delegating to process, VFS, time, and network services.
10. `user` validates static ELF64 images, maps W^X segments/stacks, owns process resources, and enters ring 3.

Host crates are deliberately outside the kernel layering. `xenith-x86` is shared by the assembler, disassembler, debugger, and interpreter. The bootloader shares only `xenith-abi`-compatible records and its own `no_std` parser library.

SMP startup is complete for up to 64 logical CPUs: MADT topology drives INIT-SIPI-SIPI, each AP installs CPU-local descriptor/per-CPU/FPU/scheduler state, and reschedule/TLB IPIs coordinate per-CPU run queues and address-space invalidation.

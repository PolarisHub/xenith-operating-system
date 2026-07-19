# Subsystems

Xenith is a monolithic kernel with narrow shared contracts.

1. `arch/x86_64` owns CPU state, GDT/TSS, IDT, interrupt controllers, syscall entry, per-CPU storage, and context-switch assembly.
2. `mm` owns the HHDM, page-table editing, user address spaces, physical allocation, and the 32 MiB kernel heap.
3. `acpi` validates RSDP/RSDT/XSDT/MADT/FADT/DSDT and hosts the bounded AML namespace/evaluator.
4. `time` selects HPET or LAPIC time, calibrates with PIT, and seeds wall time from CMOS.
5. `sched` owns tasks, run/sleep queues, kernel stacks, FPU state, and CR3/TSS changes at dispatch.
6. `devices` owns serial, framebuffer/VGA, PS/2, PCI, AHCI, RTL8139, e1000, CMOS, and the terminal parser.
7. `net` implements Ethernet, bounded ARP resolution/aging, IPv4, ICMP, UDP,
   reliable TCP state/retransmission/reassembly, routing, DHCPv4, DNS wire
   validation, loopback, live interface enumeration, and socket state. A
   kernel worker services physical adapters independently of socket syscalls.
8. `fs` provides VFS, per-open offsets, ramfs/initramfs, FAT32, and XenithFS.
9. `syscall` validates the register ABI and user ranges before delegating to process, VFS, time, and network services.
10. `user` validates static ELF64 images, maps W^X segments/stacks, owns process resources, and enters ring 3.

Host crates are deliberately outside the kernel layering. `xenith-x86` is shared by the assembler, disassembler, debugger, and interpreter. The bootloader shares only `xenith-abi`-compatible records and its own `no_std` parser library.

Current concurrency is BSP-first. Scheduler structures are per-CPU capable, but full AP startup and cross-CPU TLB/interrupt coordination remain roadmap work.

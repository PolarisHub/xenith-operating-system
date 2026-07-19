# Architecture

Xenith is a monolithic, freestanding x86_64 kernel. Hardware-facing code is isolated behind architecture, driver, block-device, VFS, network-interface, and clock interfaces; policy remains in scheduler/process/VFS/socket layers.

```text
BIOS stage1/stage2 or UEFI loader
        |
        v  XenithBootInfo
kernel entry -> arch -> memory -> ACPI/controllers/time
                              -> scheduler/syscalls
                              -> devices/network/VFS
                              -> ELF processes -> init -> shell
```

The kernel and userspace are `no_std`. Host programs in `tools/` and `emu/` use `std` because they run on the development host, not in the guest. Shared wire layouts are in `xenith-abi`; shared instruction encoding/decoding is in `xenith-x86`.

Every user process owns a PML4 whose low half contains W^X ELF mappings and a guarded stack. Kernel higher-half entries are copied from the kernel address space. Scheduler dispatch publishes the incoming task, syscall stack, TSS RSP0, and CR3 before assembly restores its context.

Interrupt/syscall entry saves an explicit register frame. User pointers are range checked and copied rather than retained across locks. Device IRQ work is bounded; longer operations use polling or process context.

The VFS presents ramfs/initramfs, FAT32, and XenithFS through common inode operations. Networking presents Ethernet/ARP/IPv4/ICMP/UDP/TCP through interface/routing/socket state. AML evaluation is bounded by namespace, package, recursion, method-step, and loop limits and denies operation-region access until a policy handler is installed.

See [SUBSYSTEMS](SUBSYSTEMS.md), [MEMORY_MAP](MEMORY_MAP.md), [SYSCALL_ABI](SYSCALL_ABI.md), and [STATUS](STATUS.md) for exact boundaries.

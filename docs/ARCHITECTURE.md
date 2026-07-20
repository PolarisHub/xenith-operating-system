# Architecture

Xenith is a monolithic, freestanding x86_64 kernel. Hardware-facing code is isolated behind architecture, driver, block-device, VFS, network-interface, and clock interfaces; policy remains in scheduler/process/VFS/socket layers.

```text
BIOS stage1/stage2 or UEFI loader
        |
        v  XenithBootInfo
kernel entry -> arch -> memory -> ACPI/controllers/time
                              -> scheduler/syscalls
                              -> devices/network/VFS
                              -> ELF processes -> init
                                      |          |
                                      |          +-> terminal shell fallback
                                      v
                              xenith-desktop
                         -> private userspace backbuffer
                         -> bounded software composition
                         -> damage-copy scanout + ordered PS/2 input
```

The kernel and userspace are `no_std`. Host programs in `tools/` and `emu/` use `std` because they run on the development host, not in the guest. Shared wire layouts are in `xenith-abi`; shared instruction encoding/decoding is in `xenith-x86`.

Every user process owns a PML4 whose low half contains W^X ELF mappings and a guarded stack. Kernel higher-half entries are copied from the kernel address space. Scheduler dispatch publishes the incoming task, syscall stack, TSS RSP0, and CR3 before assembly restores its context.

Interrupt/syscall entry saves an explicit register frame. User pointers are range checked and copied rather than retained across locks. Device IRQ work is bounded; longer operations use polling or process context.

The UI boundary gives `xenith-desktop` exclusive ownership of framebuffer scanout and the PS/2 input seat. It renders a procedural wallpaper, glass chrome, launcher, dock, and cursor into one private anonymous backbuffer. The kernel validates bounded damage and copies only affected rows into the native 32-bpp format. Keyboard and pointer IRQs share one ordered queue whose empty reader sleeps and is woken by IRQ delivery. Release, successful owner `exec`, and owner exit restore the stateful kernel console and redraw its saved contents. Init supervises the desktop and execs the terminal shell when no framebuffer exists or the graphical process exits.

`xenith-abi::compositor` separately defines the versioned, transport-neutral records for generation-safe window handles, shared surface metadata, commits/damage, roles/state, configuration, focus/input/text, close, and frame completion. That is a future client/server contract only: no IPC transport or multi-process surface server is connected yet.

The VFS presents ramfs/initramfs, FAT32, and XenithFS through common inode operations. Networking presents Ethernet/ARP/IPv4/ICMP/UDP/TCP through interface/routing/socket state. AML evaluation is bounded by namespace, package, recursion, method-step, and loop limits and denies operation-region access until a policy handler is installed.

See [SUBSYSTEMS](SUBSYSTEMS.md), [MEMORY_MAP](MEMORY_MAP.md), [SYSCALL_ABI](SYSCALL_ABI.md), [DESKTOP_FOUNDATION](DESKTOP_FOUNDATION.md), and [STATUS](STATUS.md) for exact boundaries.

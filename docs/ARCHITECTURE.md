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
                         -> bounded eight-client coordinator
                                  <-> private channels
                                  <-> libwindow shared-memory surfaces

ELF process -> xenith-winhost -> checked PE32+ AMD64 console image
```

The kernel and userspace are `no_std`. Host programs in `tools/` and `emu/` use `std` because they run on the development host, not in the guest. Shared wire layouts are in `xenith-abi`; shared instruction encoding/decoding is in `xenith-x86`.

Every user process owns a PML4 whose low half contains W^X ELF mappings and a guarded stack. Kernel higher-half entries are copied from the kernel address space. Scheduler dispatch publishes the incoming task, syscall stack, TSS RSP0, and CR3 before assembly restores its context.

Interrupt/syscall entry saves an explicit register frame. User pointers are range checked and copied rather than retained across locks. Device IRQ work is bounded; longer operations use polling or process context.

Syscalls 58-63 provide version-1 local channels, fixed-size shared-memory objects, readiness waits, and `mprotect`. Channel records contain an 80-byte header, at most 4096 inline bytes, and at most four attenuated descriptor transfers; each direction has eight preallocated queue slots and the kernel admits at most 64 channel pairs. Send and receive are transactional: an invalid user copy, unavailable descriptor capacity, or failed transfer installation cannot publish a partial message or consume a queued one. Descriptor rights are checked at read, write, ioctl, mapping, and transfer boundaries. Channel endpoints intentionally omit the `TRANSFER` right; shared-memory and ordinary file descriptors may be transferred only with a nonempty subset of their current rights.

Shared-memory objects are zero-filled, page-rounded, fixed-size, and permanently non-executable. Each object is limited to 16 MiB, the global committed quota is 64 MiB, and creation preserves an 8 MiB free-memory reserve. `MAP_SHARED` requires `MAP|READ` and also `WRITE` for a writable mapping; mappings retain the object after its descriptor closes. The multi-source wait accepts at most 32 unique channel/UI records and publishes the complete readiness array transactionally after a lost-wake-safe scheduler handoff. Dynamic anonymous mappings may transition from RW to RX with `mprotect`, but all mappings preserve W^X.

Syscalls 64-67 add joinable userspace threads. Each process may retain at most 32 live plus unjoined thread records, subject to a global 256-user-task bound. A caller supplies a distinct page-aligned 16 KiB-8 MiB private RW/NX stack; the entry page must be user-executable. Tasks share the process address space and descriptors, but task-local TLS and complete task-local signal state do not yet exist. Thread creation therefore requires a zero blocked-signal mask, no alternate stack, and no caught handlers. While more than one task is live, `fork`, `exec`, program-break mutation, `mmap`, `munmap`, and `mprotect` fail closed. A completed thread has one join consumer; the last live task publishes process exit only after detaching its address-space ownership.

Syscall 68, `spawn_restricted`, starts a child with an empty descriptor table and installs at most 16 explicit source-to-target mappings. Requested rights must be a nonempty subset of the parent's rights, target numbers must be unique, and the complete canonical batch is validated before any descriptor reference is cloned or the child is published. Ordinary sources require `TRANSFER`; a channel endpoint is the sole direct-child exception and may grant only its existing `READ|WRITE` subset. The request also carries the ordinary atomic process-group token. Failure leaves the parent table unchanged.

The UI boundary gives `xenith-desktop` exclusive ownership of framebuffer scanout and one ordered input seat shared by the PS/2 and USB boot-HID paths. It cover-crops the exact embedded Sedat Bucan photo, then draws a neutral bottom bar, restrained launcher, and monochrome cursor into one private anonymous backbuffer. The kernel validates bounded damage and copies only affected rows into the native 32-bpp format. On VMware SVGA II, the same validated rectangles are also submitted as FIFO `UPDATE` commands when the boot framebuffer is the exact SVGA frontbuffer; CPU copying remains the authoritative fallback. Keyboard and pointer IRQs share one ordered queue whose empty reader sleeps and is woken by IRQ delivery. PS/2 and USB keyboards use 250 ms/30 Hz typematic, and disconnecting USB devices synthesizes releases for retained keys, modifiers, and mouse buttons. Release, successful owner `exec`, and owner exit restore the stateful kernel console and redraw its saved contents. Init supervises the desktop and execs the terminal shell when no framebuffer exists or the graphical process exits.

`xenith-abi::compositor` defines the versioned records for generation-safe window handles, shared surface metadata, commits/damage, roles/state, configuration, focus/input/text, close, and frame completion. `libwindow` implements an allocation-free client codec and state machine. The desktop coordinator retains at most eight clients and eight surfaces per client, with 64 MiB of mapped buffers per client and 256 MiB total. It isolates malformed client protocol state, maintains scene order and focus, hit-tests pointer input, raises/focuses on the first button press, preserves implicit multi-button capture through the final release, routes keys and UTF-8 text only to the focused surface, and disconnects only a client whose nonblocking event queue stalls. Shell shortcuts and chrome consume input before client routing. One lost-wake-safe wait covers UI input and all live channels without idle polling.

The desktop provisions private live connections for the on-demand Files app and the opt-in `--window-smoke` gate. Both use `spawn_restricted` so a client receives exactly stdout, stderr, and one fixed-number channel endpoint; the desktop maps transferred buffers read-only, composites them, returns buffer-release and frame-done events, and reaps each child. Normal boot creates no channel until Files is launched from the dock, launcher, or `Super+E`. The eight-client coordinator is still a bounded private-launch foundation rather than a discoverable general compositor service; service identity, rendezvous, third-party admission, move/resize chrome, and a booted multi-client application gate remain future work.

`xenith-pe`, `xenith-winhost-core`, and `xenith-winhost` form a separate bounded compatibility experiment in userspace. The host accepts only PE32+ AMD64 console executables: files are limited to 16 MiB, mapped images to 64 MiB, bootstrap imports to 64, effective DIR64 writes to 1024, and one `WriteFile` call to 1 MiB. Stack and heap reserve/commit metadata must be nonzero page multiples; stack reserve is capped at 8 MiB and heap reserve at 64 MiB. It rejects DLL and GUI images, TLS, exception and delay-import directories, Authenticode, API sets, ordinal or arbitrary imports, writable-executable layouts, low-alignment sections whose raw file offset differs from their RVA, `RELOCS_STRIPPED` contradictions, the COFF `32BIT_MACHINE`/`SYSTEM`/`UP_SYSTEM_ONLY` flags, and the optional-header `FORCE_INTEGRITY`/`APPCONTAINER`/`WDM_DRIVER`/`GUARD_CF` flags.

The runtime binds `KERNEL32.DLL!GetStdHandle`, `WriteFile`, and `ExitProcess`, optional `NTDLL.DLL!RtlExitUserProcess`, and `NTDLL.DLL!NtClose`. It applies required DIR64 relocations, changes the materialized image from RW to final R/RW/RX mappings, and invokes its entry point on a dedicated stack whose complete accepted reserve is committed up front above an unmapped lower guard page. The loaded image still executes inside `xenith-winhost` and shares its Xenith syscall authority and inherited descriptors. These structural checks are not a security sandbox; only trusted conformance images belong in this path.

`xenith-winhost-core` separately catalogs 13 exact-symbol, pointer-free NT policy services covering generation-safe handles, events, mutants, semaphores, caller-clocked timers, and ready/zero-timeout single-object waits. Only `NtClose` is guest-wired. The other 12 catalog entries are internal typed policy calls, not decoded x64 NTDLL entry points; there are no numeric Windows-build syscall tables, scheduler-backed/alertable waits, APCs, named objects, security descriptors, cross-process duplication, materialized PEB/TEB state, Windows threads, registry, or general file/process APIs.

The kernel mounts `/win` as a dedicated writable ramfs whose directory keys use ASCII case-insensitive, case-preserving lookup; the native root remains case-sensitive. Initramfs entries below `win/` populate only this mount, and `C:\` drive paths translate to `/win/c`. The packaged tree contains `Windows`, `System32`, program/common-data directories, `Users\Default`, `Users\Public`, and a configurable `Users\Xenith` profile with standard personal and AppData children. `xenith-winhost-core` derives bounded Win32 path, known-folder, and UTF-16 environment-block policies from the same profile configuration. Only executable-argument translation is live in the host today; known-folder/environment APIs, PEB/process-parameter materialization, persistent storage, NTFS metadata, reparse points, ACLs, and Unicode case folding remain outside this slice. See [WINDOWS_FILESYSTEM](WINDOWS_FILESYSTEM.md).

`xenith-windrv-core` is an allocation-free safe-Rust policy crate for a future isolated driver host. It validates WDM major-function identifiers and `CTL_CODE` fields, generation-safe driver/device/request identities, image-confined callback addresses, linear bounded device stacks, request state transitions, and rights-attenuated resource-grant descriptors. Inline capacities are 64 drivers, 255 devices, 1024 requests, and 255 grants. It does not load or execute `.sys` files, expose hardware, materialize WDM ABI objects, enforce IOCTL buffer/access semantics, emulate cancel spin locks/routines or Windows IRQL/PnP/power/DMA behavior, implement KMDF/UMDF, or make arbitrary Windows drivers work.

The VFS presents ramfs/initramfs, FAT32, and XenithFS through common inode operations. Networking presents Ethernet/ARP/IPv4/ICMP/UDP/TCP through interface/routing/socket state. AML evaluation is bounded by namespace, package, recursion, method-step, and loop limits and denies operation-region access until a policy handler is installed.

See [SUBSYSTEMS](SUBSYSTEMS.md), [MEMORY_MAP](MEMORY_MAP.md), [SYSCALL_ABI](SYSCALL_ABI.md), [DESKTOP_FOUNDATION](DESKTOP_FOUNDATION.md), [WINDOWS_FILESYSTEM](WINDOWS_FILESYSTEM.md), and [STATUS](STATUS.md) for exact boundaries.

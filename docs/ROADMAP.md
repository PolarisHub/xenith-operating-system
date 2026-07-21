# Roadmap

The visual desktop, on-demand Files application, restricted descriptor launch,
native thread substrate, and bounded eight-client compositor/input coordinator
are complete. Files and the protocol smoke currently use private desktop-owned
connections. Independent correctness and application-platform work remains
ordered by runtime impact.
Completed work such as COW fork, `/dev/pts`, SSDT loading, NIC interrupt mode,
XenithFS flush barriers, SMP bring-up, native framebuffer-format handling, the
exclusive UI-session ABI, allocation-free photo-backed desktop, transactional
restricted spawn actions, last-thread address-space teardown, bounded xHCI
direct-port boot HID, HDA command transport, and VMware SVGA II FIFO damage
updates are not repeated as future work.

1. Add compositor service identity, rendezvous, and admission. Use the existing
   restricted-spawn actions to grant each child exactly one least-rights client
   endpoint, then define discovery, quotas, authentication policy, and peer
   teardown for independently launched applications.
2. Add a booted multi-client compositor gate and desktop window management.
   Exercise two isolated clients, focus/z-order transitions, implicit pointer
   capture, text routing, stalled-client teardown, and quota faults in one live
   session; add explicit window-close/chrome policy without weakening the fixed
   capacities or allocation-free idle wait.
3. Complete task-local thread semantics. Add architectural TLS, task-local
   signal masks/alternate stacks/handler frames, detach/cancellation policy,
   multi-waiter process semantics, synchronization primitives, and loader state.
   Back restricted-spawn rollback and last-thread teardown with booted-guest
   fault injection before mapping these primitives onto Windows threads.
4. Broaden Windows compatibility as an isolated userspace subsystem. Safely
   persist the seeded `C:\` namespace on an explicitly identified XenithFS
   system volume, add token-backed profiles and per-process cwd/environment,
   and wire exact known-folder, temp-path, and guest file APIs. Then safely
   decode and contain guest x64 arguments/results before wiring the 12
   policy-only NT catalog entries beyond `NtClose`; add scheduler-backed waits,
   PEB/TEB materialization, TLS/SEH, and dynamic-module loading. Then implement
   deliberately tested NT file, registry, process, and virtual-memory behavior
   and layer broader `ntdll`/`kernel32` plus `user32`/`gdi32` through a userspace
   WinServer. PE32, COM/OLE, DirectX translation, .NET, installers, and WoW64
   follow only behind conformance tests; symbol coverage alone is not an
   application-compatibility claim.
5. Build an isolated Windows driver host around `xenith-windrv-core`. Add a
   checked `.sys` loader, contained callback ABI, capability-backed port/MMIO/
   interrupt/DMA bridges, IRQL and cancellation rules, PnP/power management,
   and per-driver conformance tests. KMDF/UMDF and device-class support must be
   added explicitly; policy records alone are not driver compatibility.
6. Remove the BIOS emulator's semantic `stage2_main` boundary by executing the
   complete packaged Rust body after the now-exact EDD preload and mode-
   transition stream.
7. Extend the current VMware legacy-BIOS ISO/raw proof to at least one more
   external firmware implementation, complete standalone/ISO UEFI cross-
   firmware coverage, then test physical hardware. Record exact serial output,
   platform configuration, and artifact hashes without treating internal
   firmware models as equivalent evidence.
8. Expand the emulator from its Xenith-specific firmware/device contract toward
   general 16/32/64-bit execution, including AP trampoline instructions, AHCI,
   e1000, PS/2 mouse, a live display backend, and bounded host networking.
9. Add booted-guest fault injection for user-copy fixups, COW write faults,
   signal-frame/xstate restoration, realtime queue pressure, and fork/exec
   rollback so host structural tests are backed by adversarial runtime proof.
10. Extend hardware coverage without weakening the bounded native-driver
   contracts: add USB hubs and selected mass-storage classes, complete HDA codec
   topology routing and scheduled PCM playback, and add display page-flipping
   or vsync where hardware permits it. Then validate physical USB, audio,
   display, and input devices before claiming broad compatibility. PAT
   write-combining and VMware SVGA II FIFO damage updates are complete; neither
   is a generic GPU stack.
11. Add MSI-X table programming and IPv6/AF_INET6, then extend TCP with SACK and
   window scaling and DNS with TCP fallback. Validate both supported physical
   NIC drivers or equivalent exact device models under interrupt load.
12. Grow XenithFS beyond its current extent/transaction bounds and add a
   conservative `xenith-fsck` repair mode. Add writable FAT32 only with
   crash-consistent allocation and mirrored-FAT updates.
13. Broaden AML opcode, operation-region, synchronization, and firmware-quirk
    coverage while preserving the parser/evaluator's allocation, recursion, and
    execution bounds across merged DSDT/SSDT namespaces.
14. Make `xenith-asm` capable of assembling the BIOS and kernel sources directly
    with 16/32-bit modes and relocatable objects; extend `xenith-ld` accordingly;
    then grow `xenith-cc` to functions, pointers, aggregate types, headers, and a
    general malloc/printf-capable libc. Add the planned vi-like userspace editor.
15. Add DWARF variables/types, inline stacks, CFI unwinding, hardware
    watchpoints, and asynchronous pause to `xenith-debug`, then wire the same
    debugger contract to WHP and a bounded physical serial stop stub.
16. Broaden WHP artifact coverage beyond one and two VPs, add debugger control,
    and evaluate another host hypervisor backend without weakening the pure
    interpreter fallback or making acceleration a build/test dependency. Any
    future increase beyond 64 logical CPUs must replace fixed-width CPU masks
    and fixed per-CPU stores with dynamically sized equivalents.

Optional QEMU/Limine paths may be retained only for cross-validation; they are
not primary build or CI dependencies.

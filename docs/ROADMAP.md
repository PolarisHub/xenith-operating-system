# Roadmap

The first single-process visual desktop shell is complete. Independent
correctness and application-platform work remains ordered by runtime impact.
Completed work such as COW fork, `/dev/pts`, SSDT loading, NIC interrupt mode,
XenithFS flush barriers, SMP bring-up, native framebuffer-format handling, the
exclusive UI-session ABI, and the allocation-free glass desktop is not repeated
as future work.

1. Connect the versioned `xenith-abi::compositor` records to a bounded IPC and
   shared-memory transport. Keep direct scanout ownership in the desktop,
   validate generation-safe object lifetimes, and add multi-process client
   surfaces, configure/acknowledge, focus, input routing, close, and frame-done
   behavior without adding an idle polling loop.
2. Build Windows compatibility as an isolated userspace subsystem. First make
   process address-space teardown last-thread/refcount driven and add the
   thread lifecycle needed by NT semantics. Then add PE32+/PE32 loading,
   relocations/imports/TLS/SEH and NT object, file, registry, synchronization,
   and virtual-memory behavior; layer `ntdll`, `kernel32`, `user32`/`gdi32`
   through a WinServer mapped onto compositor surfaces. COM/OLE, DirectX
   translation, .NET, installers, and WoW64 follow only behind conformance
   tests. Do not claim broad Windows-app compatibility from symbol coverage
   alone.
3. Remove the BIOS emulator's semantic `stage2_main` boundary by executing the
   complete packaged Rust body after the now-exact EDD preload and mode-
   transition stream.
4. Extend the current VMware legacy-BIOS ISO/raw proof to at least one more
   external firmware implementation, complete standalone/ISO UEFI cross-
   firmware coverage, then test physical hardware. Record exact serial output,
   platform configuration, and artifact hashes without treating internal
   firmware models as equivalent evidence.
5. Expand the emulator from its Xenith-specific firmware/device contract toward
   general 16/32/64-bit execution, including AP trampoline instructions, AHCI,
   e1000, PS/2 mouse, a live display backend, and bounded host networking.
6. Add booted-guest fault injection for user-copy fixups, COW write faults,
   signal-frame/xstate restoration, realtime queue pressure, and fork/exec
   rollback so host structural tests are backed by adversarial runtime proof.
7. Add a frame-pacing or vsync contract where hardware permits it, and measured
   physical-display/input validation before claiming broad hardware performance
   or compatibility. PAT write-combining for the current CPU-copy scanout path
   is complete.
8. Add MSI-X table programming and IPv6/AF_INET6, then extend TCP with SACK and
   window scaling and DNS with TCP fallback. Validate both supported physical
   NIC drivers or equivalent exact device models under interrupt load.
9. Grow XenithFS beyond its current extent/transaction bounds and add a
   conservative `xenith-fsck` repair mode. Add writable FAT32 only with
   crash-consistent allocation and mirrored-FAT updates.
10. Broaden AML opcode, operation-region, synchronization, and firmware-quirk
   coverage while preserving the parser/evaluator's allocation, recursion, and
   execution bounds across merged DSDT/SSDT namespaces.
11. Make `xenith-asm` capable of assembling the BIOS and kernel sources directly
   with 16/32-bit modes and relocatable objects; extend `xenith-ld` accordingly;
   then grow `xenith-cc` to functions, pointers, aggregate types, headers, and a
   general malloc/printf-capable libc. Add the planned vi-like userspace editor.
12. Add DWARF variables/types, inline stacks, CFI unwinding, hardware
   watchpoints, and asynchronous pause to `xenith-debug`, then wire the same
   debugger contract to WHP and a bounded physical serial stop stub.
13. Broaden WHP artifact coverage beyond one and two VPs, add debugger control,
    and evaluate another host hypervisor backend without weakening the pure
    interpreter fallback or making acceleration a build/test dependency. Any
    future increase beyond 64 logical CPUs must replace fixed-width CPU masks
    and fixed per-CPU stores with dynamically sized equivalents.

Optional QEMU/Limine paths may be retained only for cross-validation; they are
not primary build or CI dependencies.

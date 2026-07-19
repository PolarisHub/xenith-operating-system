# Roadmap

The next correctness milestones are ordered by runtime impact. Completed work
such as COW fork, `/dev/pts`, SSDT loading, NIC interrupt mode, XenithFS flush
barriers, and SMP bring-up is intentionally not repeated as future work.

1. Remove the BIOS semantic `stage2_main` fallback by executing the complete
   packaged stage2 body, then boot the BIOS El Torito entry end-to-end and
   replace its fixed boot-drive/primary-master ATA contract with a firmware or
   device-independent loader path.
2. Boot the raw BIOS image and standalone/ISO UEFI application on at least two
   external firmware implementations, then on physical hardware. Record exact
   serial output, platform configuration, and artifact hashes without treating
   internal firmware models as equivalent evidence.
3. Expand the emulator from its Xenith-specific firmware/device contract toward
   general 16/32/64-bit execution, including AP trampoline instructions, AHCI,
   e1000, PS/2 mouse, a live display backend, and bounded host networking.
4. Add booted-guest fault injection for user-copy fixups, COW write faults,
   signal-frame/xstate restoration, realtime queue pressure, and fork/exec
   rollback so host structural tests are backed by adversarial runtime proof.
5. Add MSI-X table programming and IPv6/AF_INET6, then extend TCP with SACK and
   window scaling and DNS with TCP fallback. Validate both supported physical
   NIC drivers or equivalent exact device models under interrupt load.
6. Grow XenithFS beyond its current extent/transaction bounds and add a
   conservative `xenith-fsck` repair mode. Add writable FAT32 only with
   crash-consistent allocation and mirrored-FAT updates.
7. Broaden AML opcode, operation-region, synchronization, and firmware-quirk
   coverage while preserving the parser/evaluator's allocation, recursion, and
   execution bounds across merged DSDT/SSDT namespaces.
8. Make `xenith-asm` capable of assembling the BIOS and kernel sources directly
   with 16/32-bit modes and relocatable objects; extend `xenith-ld` accordingly;
   then grow `xenith-cc` to functions, pointers, aggregate types, headers, and a
   general malloc/printf-capable libc. Add the planned vi-like userspace editor.
9. Add DWARF variables/types, inline stacks, CFI unwinding, hardware
   watchpoints, and asynchronous pause to `xenith-debug`, then wire the same
   debugger contract to WHP and a bounded physical serial stop stub.
10. Broaden WHP artifact coverage beyond one and two VPs, add debugger control,
    and evaluate another host hypervisor backend without weakening the pure
    interpreter fallback or making acceleration a build/test dependency.

Optional QEMU/Limine paths may be retained only for cross-validation; they are
not primary build or CI dependencies.

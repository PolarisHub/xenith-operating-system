# Roadmap

The next correctness milestones are ordered by runtime impact:

1. Extend anonymous PTYs with `/dev/pts` pathname allocation and the console's
   complete canonical editing discipline. Process groups, foreground/background
   jobs, foreground terminal signals, bounded master/slave transport, termios
   ownership, and timed raw `VTIME` reads are complete.
2. Replace the purpose-built BIOS reset/stage1/stage2 firmware shim with
   general 16/32-bit execution, then add UEFI protocols. The shim already
   consumes the packaged raw disk and reaches the native long-mode handoff;
   arbitrary firmware binaries remain outside its contract.
3. Execute both structurally validated ISO catalog entries under BIOS and UEFI firmware and remove stage2's primary-master ATA dependency from the El Torito path.
4. Boot the raw BIOS image and UEFI application on at least two firmware implementations, then on physical hardware.
5. Replace eager-copy `fork` with refcounted copy-on-write pages and add the
   corresponding write-fault split path; in-place `exec` is complete.
6. Expand the landed user-copy page-fault fixups and SMAP-aware access windows
   with runtime fault-injection coverage.
7. Complete AP INIT-SIPI-SIPI startup, per-CPU descriptor tables, IPI rescheduling, and TLB shootdown.
8. Add NIC interrupt mode and IPv6/AF_INET6. Autonomous polling, bounded ARP
   retry/expiry, TCP retransmission/congestion/window/out-of-order handling,
   DHCPv4, live interface reporting, and DNS A-record lookup are complete.
9. Add XenithFS block flush barriers, larger extent trees, and repair mode to the now-shared kernel/host format implementation.
10. Extend AML to SSDTs, grow the shipped `xenith-cc` subset into a
    multi-function/object-file compiler, and add DWARF variables/types,
    unwind-based backtraces, inline call stacks, and watchpoints to the
    line-aware `xenith-debug`.

Optional QEMU/Limine paths may be retained only for cross-validation; they are not primary build or CI dependencies.

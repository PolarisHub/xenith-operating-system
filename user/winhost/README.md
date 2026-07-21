# xenith-winhost

`xenith-winhost` is a trusted in-process PE32+ AMD64 console runner. It accepts
only the loader's bounded conformance subset; it is not a Windows sandbox or a
general Windows application layer.

The executable argument may be a native Xenith path or a validated
drive-absolute `C:\...` path. Windows paths are translated to the dedicated
case-insensitive `/win/c` namespace before the file is opened; drive-relative,
UNC, device, verbatim, alternate-stream, reserved-device, and unconfigured
drive forms fail closed. This routing applies only to the host's executable
argument. Guest `CreateFile`/directory/known-folder/environment APIs are not
wired yet.

## Guest imports wired now

| Guest import | Runtime behavior |
|---|---|
| `KERNEL32.DLL!GetStdHandle` | Returns generation-safe typed handles for borrowed Xenith descriptors 0, 1, and 2 |
| `KERNEL32.DLL!WriteFile` | Synchronous console-only write, capped at 1 MiB, with handle/type/right and scalar pointer-range validation |
| `KERNEL32.DLL!ExitProcess` | Exits the current Xenith process |
| `NTDLL.DLL!RtlExitUserProcess` | Exits the current Xenith process |
| `NTDLL.DLL!NtClose` | Closes a generation-safe runtime handle and returns the exact `NTSTATUS` |

`NtClose` is the only synchronization/runtime service newly exposed as a real
guest import in this pass. Its arguments are scalar-only and can be validated
without dereferencing guest memory.

## Policy-only services

The `xenith-winhost-core` dispatcher implements pointer-free semantics for
same-runtime handle duplication, events, mutants, semaphores, relative timers,
and single-object poll/ready waits. They are not bound into a guest IAT yet:
their real entry points require safe x64 ABI decoding, contained guest output
copies, and, for blocking waits, a scheduler bridge. Unknown internal symbols
return `STATUS_NOT_IMPLEMENTED`; unknown PE imports are rejected at load time
instead of being unsafely bound to one generic stub with the wrong signature.

No Windows-build syscall numbers are hard-coded or advertised.
Xenith's native `thread_create`/`thread_join` syscalls are not Windows thread
semantics and are not exposed through this host.

## Safety boundary

- Guest code executes in the host process with the host's mappings, syscall
  authority, and inherited descriptors. Run only trusted conformance images.
- `WriteFile` deterministically rejects null handles, negative/wide handles,
  null required outputs, non-null overlapped requests, oversized writes, and
  low-half range overflow. The input buffer is passed to Xenith's checked
  usercopy syscall.
- Xenith does not yet expose a fault-contained userspace guest-copy primitive
  or SEH. An unmapped/read-only `lpNumberOfBytesWritten` can therefore fault
  the host process rather than become a recoverable Win32 error. The code does
  not claim otherwise.
- PEB/TEB/process-parameter support is currently a checked plan in
  `xenith-winhost-core`; this runner does not materialize it or set GS.

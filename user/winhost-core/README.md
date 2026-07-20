# xenith-winhost-core

`xenith-winhost-core` is the allocation-free, `no_std`, safe-Rust policy core
for Xenith's bounded Win64 host. It is a clean-room foundation, not a claim of
general Windows application compatibility.

## Implemented foundation

- Exact-width `NTSTATUS`, `BOOLEAN`, `LARGE_INTEGER`, client/thread IDs, and
  x64 `UNICODE_STRING` records with strict boundary validation.
- Independent, non-wrapping generations for 32-bit guest handles and 64-bit
  object IDs. Typed references check access masks; duplicate/close operations
  update checked object reference counts transactionally.
- Fixed-capacity event, recursive mutant, semaphore, timer, and borrowed
  console objects. Ready waits and zero-timeout polls are implemented; a wait
  that would need to park a task returns `STATUS_NOT_IMPLEMENTED`.
- A checked planning-only x64 PEB, TEB, process-parameter, environment, guard,
  and initial-stack layout. The planner does not map or populate memory and
  does not install a GS base.
- Existing bounded NT-path, module/import, PE placement, relocation, and W^X
  protection planning.

## Internal service catalog

The catalog contains 13 services. Service identity is the exact `NTDLL.DLL`
export symbol below. Xenith assigns no Windows-build syscall number and does not
treat a numeric syscall table as a stable ABI. Only `NtClose` is currently
wired by `xenith-winhost` as a real guest import; the other 12 entries are typed
pointer-free policy calls inside this crate.

| Symbol | Implemented pointer-free policy |
|---|---|
| `NtClose` | Close a generation-safe handle and release one object reference |
| `NtDuplicateObject` | Same-runtime duplication with access attenuation |
| `NtCreateEvent` | Create notification or synchronization event state |
| `NtSetEvent` / `NtResetEvent` | Checked event state transitions |
| `NtCreateMutant` / `NtReleaseMutant` | Recursive ownership and abandonment state |
| `NtCreateSemaphore` / `NtReleaseSemaphore` | Bounded transactional counts |
| `NtCreateTimer` / `NtSetTimer` / `NtCancelTimer` | Caller-clocked relative timers without APCs |
| `NtWaitForSingleObject` | Ready fast path or zero-timeout poll only |

Unknown module/symbol pairs return `STATUS_NOT_IMPLEMENTED`. Pairing a known
symbol with the wrong typed call returns `STATUS_INVALID_PARAMETER`. Null,
stale, malformed, wrong-type, insufficient-rights, capacity, lifetime, and
arithmetic failures have deterministic status results and are covered by
tests.

## Deliberate boundaries

- `NtServiceCall` is an internal pointer-free semantic contract. It is not a
  decoded Windows x64 ABI and does not read or write guest pointers.
- There are no scheduler-backed blocking waits, wait sets, alertable waits,
  APC delivery, named objects, security descriptors, namespaces, or
  cross-process duplication.
- PEB/TEB and process-parameter constants describe only the documented
  bootstrap prefix retained by the planner; complete undocumented structure
  compatibility is not claimed.
- Path matching folds Basic Latin letters to uppercase. Well-formed non-ASCII
  UTF-16 remains ordinal until Xenith has an explicit compatible upcase table.
- API-set contracts and forwarded exports remain explicitly unsupported.
- All production storage is inline in const-generic fixed arrays. Isolation is
  the caller's responsibility.

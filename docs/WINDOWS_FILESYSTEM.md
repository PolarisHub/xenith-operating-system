# Windows filesystem namespace

Xenith exposes one Windows system drive through a dedicated filesystem mount:

| Windows path | Native Xenith backing path |
| --- | --- |
| `C:\` | `/win/c` |
| `C:\Windows` | `/win/c/Windows` |
| `C:\Windows\System32` | `/win/c/Windows/System32` |
| `C:\Program Files` | `/win/c/Program Files` |
| `C:\ProgramData` | `/win/c/ProgramData` |
| `C:\Users\Xenith` | `/win/c/Users/Xenith` |

`Xenith` is the configurable bootstrap profile name. The packaged namespace
contains the modern system, common-data, default-profile, public-profile, and
active-profile hierarchy. The active profile includes `Desktop`, `Documents`,
`Downloads`, `Music`, `Pictures`, `Videos`, and
`AppData\{Local,LocalLow,Roaming}`, including `AppData\Local\Temp`.

Only the `/win` mount uses ASCII case-insensitive, case-preserving directory
lookup. Native Xenith filesystems remain case-sensitive. The bounded Win32
path policy accepts drive-absolute `C:\...` paths, normalizes `\` and `/`,
resolves `.` and `..` without allowing drive-root escape, and maps the result
to an absolute `/win/c/...` path. It rejects drive-relative paths, unconfigured
UNC/device/verbatim namespaces, alternate data streams, reserved DOS device
names, invalid UTF-8/control characters, and ambiguous trailing dots or
spaces instead of guessing incompatible behavior.

`xenith-winhost-core` also defines known-folder defaults and a sorted UTF-16
environment-block policy derived from the same profile. Those are policy
contracts for future APIs; the current PE host does not yet materialize a PEB,
TEB, process parameters, or guest environment. The graphical Files app browses
this namespace from `C:\Users\Xenith` and accepts validated `C:\...` locations
in its address field. The PE host also consumes Windows executable arguments,
so the packaged conformance fixture can be launched as:

```text
/bin/xenith-winhost 'C:\Users\Xenith\Downloads\win64-console.exe'
```

The namespace is currently seeded from initramfs into writable RAM and is
therefore reset on reboot. It is not NTFS and does not claim NTFS Unicode case
folding, ACLs, security descriptors, integrity labels, reparse points,
junctions, alternate streams, compression, encryption, quotas, or durable
storage. `SysWOW64`, `Sysnative`, and legacy `Documents and Settings` aliases
are deliberately absent until their real redirect/reparse behavior exists.

This directory and path layer does not make arbitrary Windows applications
work by itself. Broader compatibility still requires guest file APIs, DLL and
API-set loading, PEB/TEB and TLS/SEH, registry, processes and threads,
`user32`/`gdi32`, COM, DirectX, .NET, installers, and WoW64. Windows drivers
remain a separate isolated-host project.

# Linux source provenance and integration boundary

This document pins the Linux source inspected for Xenith architecture work and
defines the boundary for any future Linux-based Xenith distribution. It is an
engineering record, not legal advice.

## Current reference pin

| Field | Value |
| --- | --- |
| Component | Linux kernel source |
| Status | Reference only; no Linux source or binary is vendored or shipped by this repository |
| Canonical origin | <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git> |
| Commit | `b95f03f04d475aa6719d15a636ddf32222d55657` |
| Commit date | 2026-07-20 |
| Commit subject | `Merge tag 'mm-hotfixes-stable-2026-07-20-11-37' of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm` |
| Reference acquisition | Shallow, partial clone using `--depth 1 --filter=blob:none --no-tags` |
| Upstream top-level expression | `GPL-2.0 WITH Linux-syscall-note` as written in Linux `COPYING` (normalized SPDX meaning: `GPL-2.0-only WITH Linux-syscall-note`) |
| Xenith paths incorporating Linux source | None |
| Xenith artifacts incorporating Linux binaries | None |
| Last verified | 2026-07-21 |

The reference clone is intentionally outside the Xenith repository. Its object
database is suitable for read-only inspection at the pinned commit, but it is
not a release source package.

### Windows checkout limitation

Linux contains paths that differ only by letter case. A checkout on the current
case-insensitive Windows filesystem immediately reports modifications because
pairs such as `xt_CONNMARK.h`/`xt_connmark.h` and `xt_DSCP.c`/`xt_dscp.c`
collide. Do not build, package, diff, or copy source from that working tree.

Use `git show b95f03f04d475aa6719d15a636ddf32222d55657:<path>` for a single
read-only file. Use a complete checkout on a case-sensitive filesystem, such as
WSL2's ext4 filesystem, for builds, patches, archives, or source delivery.

## Product boundary

The recommended broad-hardware-support architecture keeps these works
separate:

1. A Linux kernel image, configuration, kernel modules, and Linux-derived
   patches are built and distributed as an explicitly GPL-governed component.
2. Xenith desktop, Files, shell, compatibility services, and applications run
   as independent userspace processes and communicate with Linux through normal
   system calls and documented UAPI. Linux's `Linux-syscall-note` explicitly
   describes that userspace boundary.
3. Linux source and GPL-only drivers are not copied, translated line by line,
   or relabeled as MIT OR Apache-2.0 within the native Xenith kernel.
4. A loadable kernel module is not classified as independent userspace merely
   because it is loaded dynamically. Its source license and kernel symbol use
   require a separate review.
5. A file offering an alternative permissive license, for example
   `GPL-2.0 OR MIT`, may be considered under the permissive choice only after
   the exact file, dependencies, notices, and selected license are entered in
   the ledger. An `AND` expression requires compliance with every stated term.
6. UAPI material carrying `Linux-syscall-note` must retain its upstream SPDX
   expression and notices. The exception does not apply automatically to
   internal Linux headers or driver implementation code.

For a native Xenith driver, prefer public hardware specifications and original
tests. If a clean-room process is required, the source analyst must produce a
neutral behavioral specification without Linux code or expressive structure,
and a separate implementer must work from that specification. Record both
roles, inputs, and a similarity review. A direct cross-language translation is
not recorded as clean-room work.

## Linux distribution release record

Add one completed row per component before producing a distributable image.
Do not replace immutable historical rows when a component changes; add a new
row for the new release.

| ID | Status | Component/output | Origin | Exact version or commit | Source/archive checksum | Upstream SPDX expression | Files or patches incorporated | Local modifications | Notices included | Corresponding-source delivery | Reviewer/date |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `linux-reference-20260720` | Reference only | Linux source inspection | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` | `b95f03f04d475aa6719d15a636ddf32222d55657` | Commit-addressed; no release archive created | `GPL-2.0 WITH Linux-syscall-note` at top level; inspect every incorporated file | None | None | Not applicable; not distributed | Not applicable; not distributed | Codex / 2026-07-21 |
| `example-delete-before-release` | Planned | Replace with the actual kernel, module, firmware, library, or tool output | Record canonical source URL | Record immutable tag and full commit | Record SHA-256 of the delivered source archive | Record exact per-component and per-file expressions | Record paths and patch series | Link modification log | List license, copyright, and NOTICE files | Record bundled source path or durable written-offer procedure | Name / YYYY-MM-DD |

Delete the example row once the first real distribution entry is added.

## Required release evidence

For every distributed Linux kernel build, retain alongside the release record:

- the full, case-correct source tree for the exact build, not the partial
  reference clone;
- the complete patch series and a source archive SHA-256;
- the exact kernel `.config`, toolchain identity, build command, and scripts
  used to control compilation and installation;
- upstream `COPYING`, applicable files under `LICENSES/`, copyright notices,
  and any component-specific `NOTICE` material;
- kernel-module source and license records, including separately supplied
  modules;
- an independent per-file license record for firmware and redistribution terms;
- a manifest mapping every shipped binary to its source and license entry; and
- the actual corresponding-source delivery location or written-offer process
  used for the binary distribution.

The release gate must fail when a shipped binary lacks an immutable source pin,
license expression, required notices, or a corresponding-source record.

# Third-party notices

This file records externally sourced components and distribution boundaries for
Xenith. It does not replace an upstream license, copyright notice, or `NOTICE`
file, and it does not relicense third-party work. Release packaging must include
the exact notices and license texts supplied by every component that is shipped.

## Locked Rust dependencies

The following crates are the registry packages currently locked by
`Cargo.lock`. Versions and declared license expressions were checked from the
package metadata. Direct and transitive dependencies are both listed because a
release can contain code from either kind.

| Package | Version | Declared license expression | Upstream repository |
| --- | ---: | --- | --- |
| `addr2line` | 0.25.1 | Apache-2.0 OR MIT | <https://github.com/gimli-rs/addr2line> |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | <https://github.com/oyvindln/adler2> |
| `bitflags` | 2.13.1 | MIT OR Apache-2.0 | <https://github.com/bitflags/bitflags> |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | <https://github.com/rust-lang/cfg-if> |
| `crc32fast` | 1.5.0 | MIT OR Apache-2.0 | <https://github.com/srijs/rust-crc32fast> |
| `fallible-iterator` | 0.3.0 | MIT/Apache-2.0 (upstream metadata spelling) | <https://github.com/sfackler/rust-fallible-iterator> |
| `flate2` | 1.1.9 | MIT OR Apache-2.0 | <https://github.com/rust-lang/flate2-rs> |
| `gimli` | 0.32.3 | MIT OR Apache-2.0 | <https://github.com/gimli-rs/gimli> |
| `libc` | 0.2.186 | MIT OR Apache-2.0 | <https://github.com/rust-lang/libc> |
| `log` | 0.4.33 | MIT OR Apache-2.0 | <https://github.com/rust-lang/log> |
| `memchr` | 2.8.3 | Unlicense OR MIT | <https://github.com/BurntSushi/memchr> |
| `memmap2` | 0.9.11 | MIT OR Apache-2.0 | <https://github.com/RazrFalcon/memmap2-rs> |
| `miniz_oxide` | 0.8.9 | MIT OR Zlib OR Apache-2.0 | <https://github.com/Frommi/miniz_oxide/tree/master/miniz_oxide> |
| `object` | 0.37.3 | Apache-2.0 OR MIT | <https://github.com/gimli-rs/object> |
| `rustc-demangle` | 0.1.28 | MIT/Apache-2.0 (upstream metadata spelling) | <https://github.com/rust-lang/rustc-demangle> |
| `ruzstd` | 0.8.3 | MIT | <https://github.com/KillingSpark/zstd-rs> |
| `simd-adler32` | 0.3.10 | MIT | <https://github.com/mcountryman/simd-adler32> |
| `spin` | 0.9.9 | MIT | <https://github.com/mvdnes/spin-rs> |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 | <https://github.com/storyyeller/stable_deref_trait> |
| `twox-hash` | 2.1.3 | MIT | <https://github.com/shepmaster/twox-hash> |
| `typed-arena` | 2.0.2 | MIT | <https://github.com/SimonSapin/rust-typed-arena> |

Where an upstream component offers a license choice, a distributor must select
and comply with one of the offered licenses. The root `LICENSE-MIT` and
`LICENSE-APACHE` files cover Xenith's own dual-licensed work; they are not a
substitute for preserving each dependency's upstream notices.

Xenith pins Rust `nightly-2026-07-01` and builds freestanding targets with
`rust-src`. A release must inventory any Rust runtime or toolchain material that
is actually incorporated into its binaries and preserve the matching notices
from that exact toolchain. This document does not assume that every installed
toolchain component is redistributed.

## Limine compatibility material

`crates/limine-compat` is repository-local compatibility code and is not a
vendored copy of the crates.io package despite retaining the historical package
name `limine`. The primary Xenith image path uses Xenith's own loaders.

`boot/limine/README.md` describes optional Limine binaries that a developer may
download for cross-validation. Those binaries are not tracked in this
repository. Before distributing any downloaded Limine binary, record its exact
release, source URL, checksum, license, copyright notices, and corresponding
source obligations. No Limine binary license is asserted here without a
specific downloaded artifact to inspect.

## Desktop wallpaper

`user/desktop/assets/README.md` identifies `sedat-wallpaper.png` as a
user-supplied image and `sedat-wallpaper.rgb` as its generated decode. The
repository currently contains no separate copyright or redistribution grant
for that image. A public release must verify and record authorization from the
rights holder, or omit/replace both files. This notice deliberately does not
infer ownership or license terms from the fact that the asset was supplied by
a user.

## Linux reference and future Linux-based distribution

Linux source is not vendored into this repository and is not covered by
Xenith's MIT OR Apache-2.0 choice. The reference pin and integration boundary
are recorded in `distribution/linux/PROVENANCE.md`.

Any Linux kernel, Linux-derived patch, or copied GPL-only driver shipped by a
Linux-based Xenith distribution remains subject to its upstream GPL terms and
must be packaged with the required source and notices. Independently authored
Xenith userspace programs that use Linux through normal system calls remain on
the userspace side of Linux's explicit syscall boundary. Internal kernel APIs
and loadable kernel modules are not treated as that userspace boundary.

Linux driver source does not include every device's firmware. Firmware obtained
from a separate project or vendor must receive its own provenance entry and
per-file redistribution review; no external firmware is approved by this
notice.

This inventory is an engineering compliance aid, not legal advice.

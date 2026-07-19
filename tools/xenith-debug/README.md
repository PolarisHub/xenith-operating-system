# xenith-debug

Start the emulator paused with a debug socket:

```powershell
cargo run -p xenith-emu --target x86_64-pc-windows-msvc -- --kernel build\kernel.elf --initrd build\initramfs.cpio --debug-listen 127.0.0.1:9000
```

In another terminal, load ELF symbols and attach:

```powershell
cargo run -p xenith-debug --target x86_64-pc-windows-msvc -- --connect 127.0.0.1:9000 --symbols build\kernel.elf
```

Useful commands are `break _start`, `continue`, `step`, `registers`, `reg rip`,
`setreg rax 1`, `read _start 16`, `write 0x1000 cc`, `watch counter 8`,
`watchpoints`, `backtrace`, `breakpoints`, and `quit`.
`--command` may be repeated and `--script` runs one command per line for deterministic
tests and CI.

## GDB compatibility bridge

Keep the emulator's native debug socket on port 9000 and expose a separate,
loopback-only GDB Remote Serial Protocol endpoint:

```powershell
cargo run -p xenith-debug --target x86_64-pc-windows-msvc -- --connect 127.0.0.1:9000 --gdb-listen 127.0.0.1:9001
gdb build\kernel.elf -ex "target remote 127.0.0.1:9001"
```

The Xenith CLI remains the primary debugger. The compatibility bridge supports
`qSupported`, no-ack negotiation, target descriptions, stop reasons, complete
general/segment register reads and writes, memory reads and writes, continue,
single-step, software breakpoints, detach, and kill. It presents one x86-64
thread and maps requests onto the existing emulator debug commands. Packets are
checksum-validated and capped at 16 KiB, memory transfers at 4 KiB, and
bridge-owned software breakpoints at 128. Unsupported RSP packets receive the
protocol-defined empty response; malformed or over-limit requests receive a
stable `E..` error.

The library's `rsp::serve_stream` accepts any blocking `Read + Write` byte
stream, so a serial-port implementation can reuse exactly the same bounded RSP
framer. This is only the safe host transport seam today: the kernel does not
yet implement a serial stop-the-world debug stub or the native register,
memory, step, and breakpoint commands on physical hardware. Also, the native
emulator protocol has no asynchronous pause command, so GDB Ctrl-C cannot
interrupt a `continue` already executing in the backend; execution stops at the
emulator's normal stop or configured instruction limit.

When the ELF contains DWARF line tables, addresses and source locations work in
both directions. `break kernel/src/main.rs:120` sets a breakpoint at the first
instruction attributed to that line; `file:line:column` selects an exact DWARF
column and makes printed locations reusable as breakpoint expressions. `lookup _start+4` prints the nearest ELF
symbol and source line, and `source rip_address`/`where rip_address` prints only
the source location. `symbol NAME` includes a source location when one exists;
`info` reports the loaded symbol, line-range, and source-file counts. Offline
inspection does not require a running emulator:

```powershell
cargo run -p xenith-debug --target x86_64-pc-windows-msvc -- --symbols build\kernel.elf --offline --command info --lookup _start
```

`backtrace` (or `bt`) walks the guest's conventional x86-64 frame-pointer chain,
then the client annotates every PC with the nearest ELF symbol and DWARF source
location. `backtrace N` caps the result explicitly; the protocol hard limit is 64
frames. Code built without frame pointers still yields the current instruction,
but cannot be walked reliably without DWARF CFI support.

For an `ET_DYN`/PIE image, pass the runtime relocation explicitly. The bias is
applied consistently to symbols and DWARF line ranges:

```powershell
cargo run -p xenith-debug --target x86_64-pc-windows-msvc -- --symbols build\app.elf --load-bias 0x400000 --lookup _start
```

The TCP protocol is newline-delimited UTF-8. Every command produces exactly one response
line. Canonical commands are `hello`, `status`, `registers`, `read-register`,
`write-register`, `read-memory`, `write-memory`, `break`, `delete`, `breakpoints`,
`watch`, `unwatch`, `watchpoints`, `backtrace`, `step`, `continue`, and `quit`.
Memory addresses are guest virtual addresses; debugger
writes bypass guest write protection but still require a valid mapping. Transfers are
bounded to 4096 bytes and continue requests to 100 million instructions. Software
watchpoints compare memory after each interpreted instruction without modifying guest
code. A session may hold at most 16 watchpoints and 4096 watched bytes in total;
debugger-originated memory writes refresh their baselines.

Symbol support reads defined x86_64 `ET_EXEC` and `ET_DYN` ELF `.symtab` and
`.dynsym` entries.
DWARF `.debug_info` and `.debug_line` data provide address-to-file/line and
file/line-to-address lookup. Release `kernel.elf` keeps line tables but omits the
larger variable/type debug payload. The debugger does not yet expose variables,
types, inline call stacks, DWARF-CFI unwinding, or hardware debug registers.

The current server controls the interpreter emulator's BSP only, accepts one client, and uses
non-invasive address checks rather than patching `int3` into guest code. Neither the native
socket nor the GDB bridge has authentication. VMM debugging still requires the WHP runner
to expose vCPU pause/register/memory/step operations through a backend-neutral target
interface. Bind both listeners to loopback unless the surrounding network is trusted.

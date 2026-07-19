# Xenith Toolchain

The host-side toolchain is implemented entirely by workspace Rust crates and
does not invoke a system assembler, C compiler, linker, libc, or binary
utility. The primary build uses it for a real artifact:

```text
cargo run -p xenith-build -- all
# produces build/user/xenith-c-demo and installs it as /bin/c-demo
cargo test -p xenith-emu --test c_toolchain -- --ignored --nocapture
```

The ignored gate boots the freshly built ELF itself as `/init` and requires
its `XENITH_C_TOOLCHAIN_OK` syscall output from ring 3. It therefore validates
runtime execution rather than only checking the ELF structure.

`xenith-cc` accepts one `int main(void)` or `int main()` definition. Its
runtime subset includes signed `int`/`long` locals, declaration and assignment,
decimal/hexadecimal constants, unary minus, `+`, `-`, `*`, comparisons,
`if`/`else`, `while`, `return`, line/block comments, string escapes, and
`puts("literal")`. The builtin issues Xenith `write(1, ...)`; returning issues
`exit`. The backend emits ordinary Intel-syntax instructions, not `.byte`
dumps.

```text
cargo run -p xenith-cc -- user/c/xenith-c-demo.c -o build/user/c-demo.elf
```

`xenith-asm` supports 64-bit general-purpose register and sized memory
operands, base/index/scale/displacement and symbolic RIP-relative addresses,
integer immediates, labels/branches, stack and integer arithmetic operations,
and the data, string, zero/fill, origin, and power-of-two alignment directives
used by freestanding sources. Symbol layout is iterated to convergence so a
forward memory symbol cannot silently invalidate later label offsets. `.code16`
and `.code32` are rejected instead of producing mislabeled 64-bit bytes.

```text
cargo run -p xenith-asm -- source.S -o source.bin
```

`xenith-ld` has a compatibility flat-payload mode and a production static mode
with one page-aligned PT_LOAD per supplied section. Static mode enforces W^X,
supports zero-filled `.bss`, validates the executable entry, and the library
API applies absolute-64 and PC-relative-32 relocations. `xenith-cc` uses that
API to relocate read-only string data into a separate non-executable segment.

```text
cargo run -p xenith-ld -- -o program.elf --text text.bin --rodata rodata.bin --data data.bin --bss 4096 --entry-offset 0
```

The exact remaining boundary is intentional and explicit. The assembler is
not a 16/32-bit assembler, macro processor, complete GNU/Intel frontend, or
x87/SIMD encoder, and it emits flat section bytes rather than relocatable ELF.
The linker does not parse ELF objects/archives, resolve external symbols, run
linker scripts, or emit dynamic linking, TLS, symbol/debug tables, or shared
objects. The compiler has no preprocessor, pointer/array/aggregate type system,
general function definitions/calls, division, object-file mode, headers, or
full C ABI/libc support. The bootloader, kernel, and larger utilities therefore
continue to use the pinned Rust/LLVM backend while `/bin/c-demo` establishes
real production use of the Xenith path.

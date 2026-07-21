# Xenith Files

`xenith-explorer` is Xenith's native, allocation-free graphical folder app. It is a real ring-3 process using the compositor protocol and filesystem syscalls directly; it is not a desktop-drawn mock window.

## Runtime contract

The desktop launches `/bin/xenith-explorer` with its private compositor channel as argument 1. An optional absolute start path may be supplied as argument 2. The default is `/win/c/Users/Xenith`, displayed as `C:\Users\Xenith`.

The app creates its own toplevel surface and chrome, then renders BGRA8888 pixels into two reusable shared-memory buffers. A buffer is never rewritten until the compositor sends its matching release event. Closing the desktop-side channel is treated as a clean app exit.

## Features and controls

- Browse absolute Xenith paths and the `C:\` Windows namespace.
- Home, Desktop, Documents, Downloads, Music, Pictures, and Videos shortcuts.
- Folder-first name sorting, selection, double-click or Enter to open, mouse-wheel scrolling, and arrow/Home/End/Page navigation.
- Back, Up, Refresh, New folder, `Ctrl+Shift+N`, `F5`, `Alt+Left`, and Backspace navigation.
- `Ctrl+L` selects the address; type an absolute path and press Enter. Escape cancels editing.
- Delete requires a second Delete press. Files use `unlink`; only empty folders can be removed with `rmdir`.
- Regular files stay selected and report that no application is registered; this first version intentionally does not invent a file association layer.

The model uses fixed capacities: 1,024-byte paths, 96 visible directory entries per read, 12 history entries, and no heap allocation. If a directory fills the current read buffer, the app emits a truncation marker instead of silently claiming complete coverage.

## Serial markers

- `XENITH_EXPLORER_READY`
- `XENITH_EXPLORER_DIRECTORY path=... entries=...`
- `XENITH_EXPLORER_DIRECTORY_FAIL path=... errno=...`
- `XENITH_EXPLORER_DIRECTORY_TRUNCATED path=... limit=96`
- `XENITH_EXPLORER_CREATED path=...`
- `XENITH_EXPLORER_DELETED path=...`
- `XENITH_EXPLORER_FAIL stage=... errno=...`
- `XENITH_EXPLORER_CLEAN_EXIT`

## Validation

```powershell
cargo test -p xenith-explorer --lib --target x86_64-pc-windows-msvc
cargo clippy -p xenith-explorer --lib --tests --target x86_64-pc-windows-msvc -- -D warnings
cargo build -p xenith-explorer --bin xenith-explorer --target user/x86_64-xenith-user.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem
cargo clippy -p xenith-explorer --bin xenith-explorer --lib --target user/x86_64-xenith-user.json -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -- -D warnings
```

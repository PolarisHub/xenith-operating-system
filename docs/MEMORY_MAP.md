# Memory map

## Virtual layout

| Range | Purpose |
| --- | --- |
| `0x0000_0000_0000_0000..=0x0000_7fff_ffff_ffff` | User canonical half; individual processes receive private PML4 roots. |
| `0x0000_8000_0000_0000..0xffff_7fff_ffff_ffff` | Non-canonical hole; always rejected. |
| `0xffff_8000_0000_0000 + physical` | Higher-half direct map (HHDM). |
| Loader-selected higher-half ELF addresses | Kernel executable/data segments. |
| Per-task heap allocations | 16 KiB default kernel stacks with guard ownership tracked by the scheduler. |

The ELF loader refuses user segments below its image floor, above `USER_MAX`, with overlapping page permissions, or with `filesz > memsz`. Writable segments are non-executable; executable segments are non-writable. User stacks are writable, non-executable, and guard-separated.

Each process records an initial program break at the first page boundary after
its highest loadable ELF segment. The heap may grow by at most 256 MiB. Bounded
anonymous/private mappings use first-fit placement from 4 GiB, remain below
the stack guard, and are capped at 256 MiB per call and 1 GiB per process.
Fork inherits heap and region metadata alongside copy-on-write PTEs; exec
resets both from the replacement ELF image.

## Physical ownership

Only memory-map entries tagged usable enter the bitmap/buddy allocators. Firmware, ACPI NVS, bad memory, kernel/modules, framebuffer, and bootloader metadata are excluded. The boot heap claims 32 MiB from a sufficiently large usable interval before the allocator bitmap is published, preventing double allocation.

Page-table frames and ordinary user frames are reached through the HHDM. The kernel preserves the higher-half PML4 entries when constructing a process address space. CR3 switches select a process root for user tasks and restore the captured kernel root for kernel tasks.

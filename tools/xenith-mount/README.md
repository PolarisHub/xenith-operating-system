# xenith-mount

`xenith-mount` is a portable, dependency-free, read-only explorer for raw
XenithFS and FAT32 filesystem images. Despite the historical name, it does
**not** create a live host mount point and has no FUSE, WinFsp, or kernel-driver
dependency.

It recognizes both the checksummed, journaled XenithFS v1 layout shared by the
kernel and current `xenith-mkfs`, and historical pre-journal XenithFS images.
FAT32 traversal supports cluster chains, 8.3 names, and validated VFAT long
filenames.

```text
xenith-mount inspect disk.img
xenith-mount list disk.img /
xenith-mount list disk.img /etc
xenith-mount extract disk.img /etc/config -o config.copy
```

The image is always opened through a read-only whole-file read and is never
changed. `extract` is the only write operation: it creates one explicitly
named host file and refuses to overwrite an existing file.

Parser bounds are deliberate: images are limited to 8 GiB by the CLI, a
single materialized file to 512 MiB, directories to 16 MiB (1 MiB for kernel
XenithFS), directory entries to 65,536, path depth to 64, and VFAT long names
to 20 directory slots. All image offsets and chain steps are checked, and FAT
cycles are rejected.

Limitations: this is an image explorer, not a live mount; it does not modify
images, follow XenithFS symlinks, recursively extract directories, interpret
FAT code pages beyond byte-preserving short-name decoding, replay XenithFS
journals, or expose ownership/timestamps/permissions. It reads filesystem
images beginning at byte zero, not a partition selected from a full-disk
partition table.

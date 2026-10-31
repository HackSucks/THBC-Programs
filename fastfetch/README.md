# Fastfetch

[Fastfetch](https://github.com/fastfetch-cli/fastfetch) 2.70.0 for Samsung Tizen
TVs, built as a **statically linked ARM ELF**.

This entry is also a demonstration of the native-program path: Tizen UEP blocks
executing unsigned binaries, so the channel does not `exec()` this file. The
bundled `elf-run` helper loads it inside the signed `dotnet` process instead.

## Run

Launch **Fastfetch** from the channel. The default view is shown in the
terminal; the program's own flags work normally if you add them to the catalog
entry's `args` array.

Useful flags:

```text
fastfetch --logo none          # compact, no ASCII logo
fastfetch --structure title:os:kernel:cpu:memory
fastfetch --help
```

## Build

Built from upstream fastfetch 2.70.0 with a static ARMv7 toolchain (for example
`zig cc -target arm-linux-musleabihf -static`). The result must be an ELF32
little-endian ARM executable (`EM_ARM`). A static build avoids the UEP
restriction on unsigned shared libraries.

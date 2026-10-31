# `elf-run`: running native ARM ELF programs

`elf-run` is the managed ELF loader bundled with `hbc-srv`. It lets the channel
run unsigned native ARM executables on retail Tizen TVs, which otherwise refuse
them through the User Execution Prevention (UEP) policy.

- Source: [`companion/elf-run/Program.cs`](../companion/elf-run/Program.cs)
- Built and staged by `./tools/build-companion.sh`
- Bundled into the widget at `hbc-srv/elf-run/elf-run.dll`
- Used automatically for catalog entries with `"runtime": "elf"`

## Why it exists

UEP rejects unsigned native execution in two places:

| Operation | Result |
| --- | --- |
| `execve()` / `execveat()` / `fexecve()` of an unsigned file | `EPERM` |
| file-backed `mmap()` (`PROT_EXEC`) of an unsigned file | `EPERM` |
| anonymous RWX `mmap()` + jump | **allowed** |

The signed `/usr/bin/dotnet` host is allowed to read the program image, map it
into anonymous RWX memory, and jump to its entry point. `elf-run` does exactly
that: no `execve`, no file `mmap`, so UEP is never consulted. No kernel patch,
SMACK label, or Samsung certificate is needed.

Because the target runs inside the `dotnet` process, its `stdout`, `stderr`,
`stdin`, PTY, arguments, environment and `exit_group()` all behave normally.
When the target exits, the helper process exits with the target's code.

## Invocation

`hbc-srv` runs:

```text
/usr/bin/dotnet .../hbc-srv/elf-run/elf-run.dll <program> [args...]
```

You can run it by hand on the TV through the root shell:

```sh
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
  /usr/bin/dotnet /opt/usr/apps/tizenhbc01/res/wgt/hbc-srv/elf-run/elf-run.dll \
  /opt/usr/home/hbc/programs/fastfetch/fastfetch --logo none
```

The first argument is the ELF path. Every following argument is passed to the
program as `argv[1]`, `argv[2]`, ...; `argv[0]` is the ELF path.

## Supported images

- 32-bit little-endian ELF (`ELFCLASS32`, `ELFDATA2LSB`)
- `e_machine = EM_ARM` (ARMv7)
- `ET_EXEC` (fixed address) and `ET_DYN` (PIE)
- static executables
- dynamic executables that only use libraries already present on the TV

### Static is the safe default

For a static image the loader supplies everything: segments, stack, auxv and
entry point. It works with musl or glibc static builds and does not depend on
the TV's C library version.

For a dynamic image the loader maps `PT_INTERP` and jumps to the real dynamic
linker, which then loads `NEEDED` libraries **from disk**. Those libraries must
be Samsung-signed, so your own `.so` files will still be blocked by UEP. The
program also has to match the TV's glibc:

```text
/lib/libc.so.6: version `GLIBC_2.34' not found
```

Build against the TV's glibc, or link statically. A convenient static build:

```sh
zig cc -target arm-linux-musleabihf -static -O2 -o hello hello.c
```

## Integration

A catalog entry only needs:

```json
{
  "language": "native",
  "runtime": "elf",
  "entry": "hello",
  "files": [
    { "path": "hello", "url": "hello/hello", "size": 12345, "sha256": "..." }
  ]
}
```

`hbc-srv` finds the loader in this order:

1. `HBC_ELF_RUN` (path to `elf-run.dll`), if set;
2. `hbc-srv/elf-run/elf-run.dll` next to `hbc-srv.dll`;
3. `hbc-srv/elf-run.dll`.

If no loader is present, it falls back to `exec()` for older firmware that
still allows it. The startup log prints the resolved path:

```text
elf loader:   /opt/usr/apps/tizenhbc01/res/wgt/hbc-srv/elf-run/elf-run.dll
```

## Limits

- 32-bit ARM only. An AArch64 TV needs a separate arm64 loader.
- The target shares the `dotnet` process. A crash takes the helper down with it;
  that is fine for normal runs but there is no separate PID to attach to.
- The loader does not implement `fork()`/`exec()` emulation. A program that
  spawns children still uses the kernel, and those children face UEP normally.
- Dynamic user libraries remain unsigned and therefore blocked; static linking
  is the supported path.

## Demo

The bundled **Fastfetch** entry is a statically linked ARMv7 fastfetch 2.70.0.
It installs from the widget bundle and runs through this loader.

# LinuxSwitch

Root switcher for UnshackleOS on Samsung Tizen TVs. It mounts `unshackle.squashfs`
from a USB stick **or over the network**, frees RAM, and `chroot`s into a Debian
userspace while Tizen keeps running underneath.

Nothing is written to the boot path or to eMMC. **A reboot always returns to stock Tizen.**

## Requirements

- Root (mount, chroot and loop devices need it).
- About 450 MB of free RAM after Tizen apps are stopped.
- Either a FAT USB stick, or an HTTP server on your LAN hosting the image.

## Quick start

Run it from the terminal app. With no arguments it looks for a source in this order:

1. `unshackle.squashfs` on the USB stick
2. `unshackle.url` on the stick (one line: `http://host:port/unshackle.squashfs`)
3. Otherwise it shows a menu: **1) USB stick, 2) Network URL, 3) Quit**

Pick **2** and type the URL of the image. Only `http://` is supported.

## USB stick layout

| File | Required | Purpose |
|---|---|---|
| `unshackle.squashfs` | yes (or `unshackle.url`) | root image |
| `unshackle.squashfs.sha256` | no | verified before use |
| `unshackle.url` | no | network source, first line is the URL |
| `unshackle.conf` | no | overrides, e.g. `GFX_BACKEND=fbdev` |
| `host-agent.sh` | no | used if the image doesn't ship one |

## Network images

The TV kernel has no NFS, CIFS or NBD, so the image is downloaded (resumable) and
loop-mounted from a cache. The cache goes to the USB stick if one is present,
otherwise to RAM. RAM is refused if the image plus the 450 MB reserve won't fit.

If `<url>.sha256` exists next to the image it is verified automatically.
`unshackle.conf` is also fetched from the same directory when the stick has none.
FAT sticks can't hold files over 4 GB.

Quick server on your PC:

```
cd /path/to/images && python3 -m http.server 8000
```

## Options

| Option | Meaning |
|---|---|
| `--url URL` | fetch the image over `http://` |
| `--sha256 HEX` | expected hash (else `<url>.sha256` is tried) |
| `--cache DIR` | where to store a downloaded image |
| `--prefer-net` | use `unshackle.url` even if a local image exists |
| `--menu` | always show the interactive picker |
| `--download-only` | download and verify, then exit |
| `--agent PATH` | host-agent.sh location |
| `--kill PATTERN` | extra process to stop (repeatable, never touches the keep list) |
| `--kill-streaming` | also stop background Netflix/Cobalt |
| `--min-mem MB` | RAM gate, default 450 |
| `--wait SEC` | wait for a USB stick, default 10 |
| `--timeout SEC` | health-check timeout, default 45 |
| `--smack LABEL` | set the Smack label before chroot (try `System` on `EACCES`) |
| `--logdir DIR` | save failure logs here if no stick is writable |
| `--no-reboot` | don't reboot on failure (debugging) |
| `--teardown [--reboot]` | stop the session and unmount everything |

## If something goes wrong

On failure LinuxSwitch saves `switcher.log`, `session.log`, `gfx-report.txt` and
`fiwd.log` to the stick (or `--logdir`) and reboots into stock Tizen. Logs live in
`/tmp/unshackle/` until then. If nothing was changed yet (no image, bad hash,
download failure with a stick present) it simply exits and Tizen carries on.

## Building

```
zig cc -target arm-linux-musleabi -Os -static -o LinuxSwitch LinuxSwitch.c
```

Soft-float ARM, fully static. Add `-mcpu=<core>` if you get an illegal instruction.

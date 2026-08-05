<p align="center"><img src="https://raw.githubusercontent.com/go-filesystems/brand/main/social/go-filesystems.png" alt="go-filesystems/detect" width="720"></p>

# detect

[![Go Reference](https://pkg.go.dev/badge/github.com/go-filesystems/detect.svg)](https://pkg.go.dev/github.com/go-filesystems/detect)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/go-filesystems/detect/actions/workflows/ci.yml/badge.svg)](https://github.com/go-filesystems/detect/actions/workflows/ci.yml)

Pure-Go (CGO=0), `blkid`-style filesystem-type prober and driver-opener
registry for the [go-filesystems](https://github.com/go-filesystems) family —
no root, no external tools, no libblkid.

`detect` probes on-disk magic signatures to identify the filesystem on an
image, then dispatches to a registered driver to open it. It mirrors the
standard library's [`image.Decode`](https://pkg.go.dev/image#Decode) design:
the **core package depends only on
[`github.com/go-filesystems/interface`](https://github.com/go-filesystems/interface)**
plus the standard library. It never imports a concrete driver, so it composes
cleanly as a meta-importer — the drivers' `replace
github.com/go-filesystems/interface => ../interface` sibling directive does
not survive transitive importing, which is exactly the problem this split
avoids.

Drivers are wired in at the call site, either directly via `Register` or by
blank-importing a thin per-driver adapter sub-package.

## Install

```sh
go get github.com/go-filesystems/detect
```

## Usage

### Probe only

```go
import "github.com/go-filesystems/detect"

t, err := detect.Detect(r, size) // r is an io.ReaderAt, size in bytes (-1 if unknown)
if err == nil {
    fmt.Println("filesystem:", t) // e.g. "fat32"
}
```

`Detect` performs a small number of bounded reads and returns one of the
recognised [`Type`](#detected-types) values, or `(Unknown, ErrUnknown)` when
no signature matches.

### Probe and open

Register the drivers you need, then dispatch with `Open` / `OpenFile`:

```go
import (
    "github.com/go-filesystems/detect"
    _ "github.com/go-filesystems/detect/fat32reg" // registers the FAT32 driver
)

fs, t, err := detect.OpenFile("disk.img")
if err != nil {
    log.Fatal(err)
}
defer fs.Close()
data, _ := fs.ReadFile("/hello.txt")
fmt.Println(t, len(data))
```

`Open` returns `ErrUnknown` if nothing matches, or `ErrUnsupported` if a type
was detected but no `Opener` is registered for it.

### Registering a driver directly

Every `go-filesystems` driver's `Open` is path-based (it needs random-access
read/write on a real file), so an `Opener` — which only gets an `io.ReaderAt`
+ size — stages the image into a temporary file before delegating, the same
way `fat32reg` does:

```go
detect.Register(detect.XFS, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
    tmp, err := os.CreateTemp("", "xfsreg-*.img")
    if err != nil {
        return nil, err
    }
    path := tmp.Name()
    if _, err := io.Copy(tmp, io.NewSectionReader(r, 0, size)); err != nil {
        tmp.Close()
        os.Remove(path)
        return nil, err
    }
    tmp.Close()
    fs, err := xfs.Open(path, -1)
    if err != nil {
        os.Remove(path)
        return nil, err
    }
    return fs, nil // wrap to also os.Remove(path) on Close, as fat32reg.tempFS does
})
```

`Register` is idempotent and safe for concurrent use, so adapter packages call
it from `init`.

## Adapter sub-packages

Thin adapters import exactly one driver and register it in `init`, so a
consumer can wire a driver in with a single blank import:

| Adapter | Driver | Type |
|---|---|---|
| `detect/fat32reg` | [`go-filesystems/fat32`](https://github.com/go-filesystems/fat32) | `fat32` |

Each adapter is its own module: it carries the `replace
github.com/go-filesystems/interface => ../../interface` sibling directive that
the driver needs, while keeping the **core package free of any driver
dependency**.

## Detected types

`fat32`, `exfat`, `ntfs`, `ext4`, `xfs`, `btrfs`, `zfs`, `apfs`, `hfsplus`,
`iso9660`, `squashfs`, `ufs` — and `unknown` when nothing matches.

## Magic-signature table

Every signature below was verified against the corresponding go-filesystems
driver's own on-disk reader (offset, value and byte order). Probes run
most-specific first so nested or ambiguous layouts never produce a false
positive.

| Type | Offset | Magic | Width / order | Notes |
|---|---|---|---|---|
| `btrfs` | `0x10040` (65600) | `_BHRfS_M` (`0x4D5F53665248425F`) | u64 LE | superblock at 64 KiB + 0x40 |
| `squashfs` | `0` | `hsqs` (`0x73717368`) / `sqsh` (`0x68737173`) | u32, LE **or** BE image | both byte orders recognised |
| `xfs` | `0` | `XFSB` (`0x58465342`) | u32 BE | XFS is big-endian on disk |
| `ext4` | `0x438` (1080) | `0xEF53` | u16 LE | ext2/3/4 share the magic; reported as `ext4` |
| `apfs` | `32` | `NXSB` | 4 bytes | NX container superblock |
| `hfsplus` | `1024` | `H+` (`0x482B`) / `HX` (`0x4858`) | u16 BE | HFS+ and HFSX |
| `iso9660` | `0x8001` (32769) | `CD001` | 5 bytes | volume descriptor, logical sector 16 |
| `ufs` | `65536+1372` / `8192+1372` | `0x19540119` / `0x00011954` | u32 LE | UFS2 then UFS1 superblock |
| `zfs` | uberblock ring (label 0) | `0x00bab10c` | u64, LE **or** BE | best-effort — see caveat |
| `exfat` | `3` | `EXFAT   ` | 8 bytes | OEM identifier |
| `ntfs` | `3` + `510` | `NTFS    ` + `0xAA55` | 8 bytes + u16 LE | both required |
| `fat32` | `0x52` + `510` | `FAT32   ` + `0xAA55` | 8 bytes + u16 LE | label at `0x52` distinguishes FAT32 from FAT12/16 (whose label sits at `0x36`) |

### ZFS detection caveat

ZFS recognition is best-effort. `detect` scans the uberblock ring of the
first front vdev label (offset `131072`, 128 slots) for the uberblock magic
`0x00bab10c` in either byte order. This reliably recognises a ZFS-labelled
vdev without reading the whole device, but it does not validate the full
label NVlist or checksum, and it does not search the rear labels. A device
whose front label has been wiped but whose rear labels survive will not be
detected.

## Design notes

- **Bounded reads.** Every probe reads through
  [`go-volumes/safeio`](https://github.com/go-volumes/safeio) with a 1 MiB
  per-read ceiling, so a truncated or hostile image never triggers a large
  allocation, and probing past the end of a small image is not fatal.
- **No false positives.** Container/whole-disk magics are checked before the
  FAT-family boot-sector heuristics, and FAT32 / NTFS require multiple
  corroborating fields.
- **Pure Go, six arches.** CI builds and tests on amd64, arm64, riscv64,
  loong64, ppc64le and s390x (big-endian), exercising the explicit byte-order
  handling.

## License

BSD-3-Clause — see [LICENSE](LICENSE).

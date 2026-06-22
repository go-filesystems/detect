// Package detect is a blkid-style, pure-Go (CGO=0) filesystem-type prober and
// driver-opener registry for the go-filesystems family.
//
// It mirrors the standard library's image.Decode design: the core package
// depends only on github.com/go-filesystems/interface plus the standard
// library (and a bounded-read helper). Detect probes on-disk magic
// signatures and returns a Type; it never imports a concrete driver, so it
// composes cleanly as a meta-importer despite the drivers' use of a
// `replace github.com/go-filesystems/interface => ../interface` sibling
// directive that does not survive transitive importing.
//
// Drivers are wired in at the call site. A consumer registers an Opener for
// each Type it wants to open — either directly via Register, or by
// blank-importing a thin per-driver adapter sub-package (for example
// `import _ "github.com/go-filesystems/detect/fat32reg"`), each of which
// calls Register in its init function.
//
//	t, err := detect.Detect(r, size)            // magic probe only
//	fs, t, err := detect.Open(r, size)          // probe then dispatch
//	fs, t, err := detect.OpenFile("disk.img")   // open path, probe, dispatch
package detect

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/go-volumes/safeio"
)

// Type is a filesystem-type identifier as reported by Detect. The set of
// recognised values is closed and matches the go-filesystems driver family.
type Type string

// The recognised filesystem types. Unknown is the zero value returned
// alongside ErrUnknown when no signature matches.
const (
	Unknown  Type = "unknown"
	FAT32    Type = "fat32"
	ExFAT    Type = "exfat"
	NTFS     Type = "ntfs"
	Ext4     Type = "ext4"
	XFS      Type = "xfs"
	Btrfs    Type = "btrfs"
	ZFS      Type = "zfs"
	APFS     Type = "apfs"
	HFSPlus  Type = "hfsplus"
	ISO9660  Type = "iso9660"
	SquashFS Type = "squashfs"
	UFS      Type = "ufs"
)

// Sentinel errors. Callers should test with errors.Is.
var (
	// ErrUnknown is returned by Detect (and wrapped by Open) when no known
	// magic signature matches the probed image.
	ErrUnknown = errors.New("detect: unknown filesystem")

	// ErrUnsupported is returned by Open when Detect recognised the
	// filesystem type but no Opener has been registered for it.
	ErrUnsupported = errors.New("detect: no opener registered for filesystem type")
)

// maxProbe bounds the highest offset any signature lives at, so that
// safeio reads stay tightly bounded and a truncated image never causes a
// huge allocation. The deepest single-shot probe is the UFS2 superblock
// magic at 65536+1372; btrfs at 0x10040 (65600) is read with its own short
// window. The cap below comfortably covers the largest individual read we
// issue (a UFS superblock-sized window) without ever reading the whole
// device.
const maxProbeRead = 1 << 20 // 1 MiB ceiling per bounded read

// readAt reads exactly n bytes at off, bounded by maxProbeRead. A short or
// out-of-range read yields ok=false (signature simply does not match) rather
// than propagating an error, so probing past the end of a small image is not
// fatal — except that a genuinely broken reader surfaces via err.
func readAt(r io.ReaderAt, size, off, n int64) (buf []byte, ok bool) {
	if off < 0 || n <= 0 || n > maxProbeRead {
		return nil, false
	}
	if size >= 0 && off+n > size {
		return nil, false
	}
	b, err := safeio.ReadAtFull(r, off, n, maxProbeRead)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Detect probes the on-disk magic signatures of r and returns the matching
// Type. size is the logical size of the image in bytes; pass a negative
// value if unknown (probes are then bounded only by maxProbeRead and the
// reader's own extent). Detection is read-only and performs a small number
// of bounded reads. When no signature matches, Detect returns (Unknown,
// ErrUnknown).
//
// Probes run most-specific first so that nested or ambiguous layouts never
// produce a false positive: container/whole-disk magics (btrfs, squashfs,
// xfs, ext, apfs, ufs, zfs) are checked before the FAT-family boot-sector
// heuristics, and FAT32 is only reported when both its boot signature and
// its "FAT32   " filesystem-type label are present.
func Detect(r io.ReaderAt, size int64) (Type, error) {
	if r == nil {
		return Unknown, ErrUnknown
	}
	for _, p := range probes {
		if p.match(r, size) {
			return p.typ, nil
		}
	}
	return Unknown, ErrUnknown
}

// probe pairs a Type with its matcher. The slice order defines probe
// precedence (most-specific first).
type probe struct {
	typ   Type
	match func(r io.ReaderAt, size int64) bool
}

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

// probes lists every recognised signature in precedence order. Each matcher
// was verified against the corresponding go-filesystems driver's own reader
// (offset, value and endianness) — see README for the signature table.
var probes = []probe{
	// btrfs: u64 LE 0x4D5F53665248425F ("_BHRfS_M") at 0x10040 (65600).
	{Btrfs, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 0x10040, 8)
		return ok && le.Uint64(b) == btrfsMagic
	}},
	// squashfs: u32 magic at 0. "hsqs" (0x73717368) on a little-endian
	// image, "sqsh" (0x68737173) on a big-endian one.
	{SquashFS, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 0, 4)
		if !ok {
			return false
		}
		return le.Uint32(b) == squashLE || le.Uint32(b) == squashBE
	}},
	// xfs: u32 BE 0x58465342 ("XFSB") at 0.
	{XFS, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 0, 4)
		return ok && be.Uint32(b) == xfsMagic
	}},
	// ext2/3/4: u16 LE 0xEF53 at 0x438 (1080). Reported as ext4.
	{Ext4, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 0x438, 2)
		return ok && le.Uint16(b) == extMagic
	}},
	// apfs: nx container superblock magic "NXSB" at offset 32 of block 0.
	{APFS, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 32, 4)
		return ok && string(b) == apfsMagic
	}},
	// hfsplus: u16 BE 0x482B ("H+") or 0x4858 ("HX") at 1024.
	{HFSPlus, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 1024, 2)
		if !ok {
			return false
		}
		sig := be.Uint16(b)
		return sig == hfsPlusSig || sig == hfsXSig
	}},
	// iso9660: "CD001" at 0x8001 (32769), the standard identifier of the
	// volume descriptor in logical sector 16.
	{ISO9660, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 0x8001, 5)
		return ok && string(b) == iso9660ID
	}},
	// ufs: fs_magic u32 LE at superblock-offset 1372. The UFS2 superblock
	// lives at 65536, the UFS1 superblock at 8192.
	{UFS, func(r io.ReaderAt, size int64) bool {
		if b, ok := readAt(r, size, ufs2SbOff+ufsMagicOff, 4); ok && le.Uint32(b) == ufs2Magic {
			return true
		}
		if b, ok := readAt(r, size, ufs1SbOff+ufsMagicOff, 4); ok && le.Uint32(b) == ufs1Magic {
			return true
		}
		return false
	}},
	// zfs: best-effort. The uberblock magic 0x00bab10c (read in either
	// endianness) appears at the start of each uberblock slot in the two
	// front vdev labels. We scan the first label's uberblock ring, which is
	// sufficient to recognise a ZFS-labelled vdev without reading the whole
	// device. See README for the partial-detection caveat.
	{ZFS, zfsMatch},
	// exfat: "EXFAT   " (8 bytes) at offset 3.
	{ExFAT, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 3, 8)
		return ok && string(b) == exfatID
	}},
	// ntfs: "NTFS    " (8 bytes) at offset 3, plus the 0xAA55 boot
	// signature at 510 — both required to avoid colliding with other
	// boot-sector layouts.
	{NTFS, func(r io.ReaderAt, size int64) bool {
		b, ok := readAt(r, size, 3, 8)
		if !ok || string(b) != ntfsID {
			return false
		}
		sig, ok := readAt(r, size, 510, 2)
		return ok && le.Uint16(sig) == bootSig
	}},
	// fat32: 0xAA55 boot signature at 510 AND "FAT32   " filesystem-type
	// label at 0x52 (82). The label distinguishes FAT32 from FAT12/16
	// (whose label sits at 0x36 instead), so we never misreport those.
	{FAT32, func(r io.ReaderAt, size int64) bool {
		sig, ok := readAt(r, size, 510, 2)
		if !ok || le.Uint16(sig) != bootSig {
			return false
		}
		label, ok := readAt(r, size, 0x52, 8)
		return ok && string(label) == fat32Label
	}},
}

// zfsMatch scans the uberblock ring of the first front vdev label for the
// uberblock magic, in either byte order. Best-effort by design.
func zfsMatch(r io.ReaderAt, size int64) bool {
	for slot := int64(0); slot < zfsUberSlots; slot++ {
		off := zfsUberRingOff + slot*zfsUberSlotSize
		b, ok := readAt(r, size, off, 8)
		if !ok {
			// Past the end of this image; no point scanning further slots.
			return false
		}
		if le.Uint64(b) == zfsUberMagic || be.Uint64(b) == zfsUberMagic {
			return true
		}
	}
	return false
}

// Verified magic constants (see README signature table).
const (
	btrfsMagic uint64 = 0x4D5F53665248425F // "_BHRfS_M" LE at 0x10040

	squashLE uint32 = 0x73717368 // "hsqs"
	squashBE uint32 = 0x68737173 // "sqsh"

	xfsMagic uint32 = 0x58465342 // "XFSB" BE at 0

	extMagic uint16 = 0xEF53 // LE at 0x438

	apfsMagic = "NXSB" // at 32

	hfsPlusSig uint16 = 0x482B // "H+" BE at 1024
	hfsXSig    uint16 = 0x4858 // "HX"

	iso9660ID = "CD001" // at 0x8001

	ufs2Magic   uint32 = 0x19540119
	ufs1Magic   uint32 = 0x00011954
	ufs2SbOff   int64  = 65536
	ufs1SbOff   int64  = 8192
	ufsMagicOff int64  = 1372 // fs_magic within struct fs

	zfsUberMagic    uint64 = 0x00bab10c
	zfsUberRingOff  int64  = 131072 // VDEV_UBERBLOCK_RING in label 0
	zfsUberSlotSize int64  = 1024
	zfsUberSlots    int64  = 128

	exfatID = "EXFAT   " // at 3
	ntfsID  = "NTFS    " // at 3

	bootSig    uint16 = 0xAA55     // 0x55 @510, 0xAA @511
	fat32Label        = "FAT32   " // at 0x52
)

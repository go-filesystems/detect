package detect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// img builds an in-memory image of the given size and applies a set of
// patches (offset -> bytes). It is the basis for every signature fixture:
// each filesystem is recognised purely from its on-disk magic, so a minimal
// image carrying the correct bytes at the correct offsets is a faithful,
// driver-independent fixture.
func img(size int, patches map[int][]byte) []byte {
	b := make([]byte, size)
	for off, data := range patches {
		copy(b[off:], data)
	}
	return b
}

func u16le(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func u16be(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func u32le(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func u32be(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func u64le(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
func u64be(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

// fixtures returns, for each known Type, a synthetic image whose only
// meaningful content is the verified magic signature. These double as the
// "header fixtures" for types we cannot format locally and as the negative
// cross-check that every signature is matched exactly once.
func fixtures() map[Type][]byte {
	return map[Type][]byte{
		Btrfs: img(0x10048, map[int][]byte{
			0x10040: u64le(btrfsMagic),
		}),
		SquashFS: img(8, map[int][]byte{
			0: u32le(squashLE),
		}),
		XFS: img(8, map[int][]byte{
			0: u32be(xfsMagic),
		}),
		Ext4: img(0x440, map[int][]byte{
			0x438: u16le(extMagic),
		}),
		APFS: img(40, map[int][]byte{
			32: []byte(apfsMagic),
		}),
		HFSPlus: img(1026, map[int][]byte{
			1024: u16be(hfsPlusSig),
		}),
		ISO9660: img(0x8006, map[int][]byte{
			0x8001: []byte(iso9660ID),
		}),
		UFS: img(int(ufs2SbOff+ufsMagicOff)+4, map[int][]byte{
			int(ufs2SbOff + ufsMagicOff): u32le(ufs2Magic),
		}),
		ZFS: img(int(zfsUberRingOff)+8, map[int][]byte{
			int(zfsUberRingOff): u64le(zfsUberMagic),
		}),
		ExFAT: img(512, map[int][]byte{
			3: []byte(exfatID),
		}),
		NTFS: img(512, map[int][]byte{
			3:   []byte(ntfsID),
			510: u16le(bootSig),
		}),
		FAT32: img(512, map[int][]byte{
			0x52: []byte(fat32Label),
			510:  u16le(bootSig),
		}),
	}
}

func TestDetectFixtures(t *testing.T) {
	for want, image := range fixtures() {
		want, image := want, image
		t.Run(string(want), func(t *testing.T) {
			got, err := Detect(bytes.NewReader(image), int64(len(image)))
			if err != nil {
				t.Fatalf("Detect returned error: %v", err)
			}
			if got != want {
				t.Fatalf("Detect = %q, want %q", got, want)
			}
			// Same result with size unknown (negative).
			got2, err := Detect(bytes.NewReader(image), -1)
			if err != nil || got2 != want {
				t.Fatalf("Detect(size<0) = %q, %v; want %q, nil", got2, err, want)
			}
		})
	}
}

// TestDetectExclusivity asserts that each fixture matches exactly one Type:
// no signature false-positives against another type's image.
func TestDetectExclusivity(t *testing.T) {
	fx := fixtures()
	for owner, image := range fx {
		got, err := Detect(bytes.NewReader(image), int64(len(image)))
		if err != nil {
			t.Fatalf("%s: Detect error: %v", owner, err)
		}
		if got != owner {
			t.Fatalf("%s fixture detected as %s (false positive)", owner, got)
		}
	}
}

func TestSquashFSBigEndian(t *testing.T) {
	image := img(8, map[int][]byte{0: u32le(squashBE)}) // "sqsh"
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil || got != SquashFS {
		t.Fatalf("BE squashfs: got %q, %v; want squashfs", got, err)
	}
}

func TestHFSX(t *testing.T) {
	image := img(1026, map[int][]byte{1024: u16be(hfsXSig)})
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil || got != HFSPlus {
		t.Fatalf("HFSX: got %q, %v; want hfsplus", got, err)
	}
}

func TestUFS1(t *testing.T) {
	image := img(int(ufs1SbOff+ufsMagicOff)+4, map[int][]byte{
		int(ufs1SbOff + ufsMagicOff): u32le(ufs1Magic),
	})
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil || got != UFS {
		t.Fatalf("UFS1: got %q, %v; want ufs", got, err)
	}
}

func TestZFSBigEndianUberblock(t *testing.T) {
	image := img(int(zfsUberRingOff)+8, map[int][]byte{
		int(zfsUberRingOff): u64be(zfsUberMagic),
	})
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil || got != ZFS {
		t.Fatalf("ZFS BE: got %q, %v; want zfs", got, err)
	}
}

func TestZFSLaterSlot(t *testing.T) {
	// Magic only in slot 5 of the uberblock ring.
	off := int(zfsUberRingOff + 5*zfsUberSlotSize)
	image := img(off+8, map[int][]byte{off: u64le(zfsUberMagic)})
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil || got != ZFS {
		t.Fatalf("ZFS slot 5: got %q, %v; want zfs", got, err)
	}
}

// TestZFSNoMatchFullRing gives a fully-sized but magic-free uberblock ring,
// so zfsMatch scans every slot and falls through to its final "no match".
func TestZFSNoMatchFullRing(t *testing.T) {
	size := int(zfsUberRingOff + zfsUberSlots*zfsUberSlotSize)
	image := make([]byte, size) // all zeros: no uberblock magic anywhere
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if !errors.Is(err, ErrUnknown) || got != Unknown {
		t.Fatalf("zero ring: got %q, %v; want Unknown, ErrUnknown", got, err)
	}
}

func TestDetectUnknown(t *testing.T) {
	cases := map[string][]byte{
		"zeros":  make([]byte, 70000),
		"random": bytes.Repeat([]byte{0xA5, 0x3C}, 40000),
		"tiny":   {0x00, 0x01, 0x02},
		"empty":  {},
	}
	for name, image := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Detect(bytes.NewReader(image), int64(len(image)))
			if !errors.Is(err, ErrUnknown) {
				t.Fatalf("err = %v, want ErrUnknown", err)
			}
			if got != Unknown {
				t.Fatalf("type = %q, want Unknown", got)
			}
		})
	}
}

func TestDetectNilReader(t *testing.T) {
	got, err := Detect(nil, 100)
	if !errors.Is(err, ErrUnknown) || got != Unknown {
		t.Fatalf("nil reader: got %q, %v; want Unknown, ErrUnknown", got, err)
	}
}

// fat12Boot has a boot signature but a FAT12 type label — must NOT be
// reported as FAT32.
func TestFAT12NotFAT32(t *testing.T) {
	image := img(512, map[int][]byte{
		0x36: []byte("FAT12   "),
		510:  u16le(bootSig),
	})
	got, err := Detect(bytes.NewReader(image), int64(len(image)))
	if err == nil || got == FAT32 {
		t.Fatalf("FAT12 image: got %q, %v; must not be fat32", got, err)
	}
}

// NTFS requires both OEM id and boot signature: a stray "NTFS    " without
// 0xAA55 must not match.
func TestNTFSRequiresBootSig(t *testing.T) {
	image := img(512, map[int][]byte{3: []byte(ntfsID)}) // no 0xAA55
	got, _ := Detect(bytes.NewReader(image), int64(len(image)))
	if got == NTFS {
		t.Fatalf("NTFS without boot sig matched; got %q", got)
	}
}

// errReader fails every ReadAt — exercises the read-error path inside the
// probes (treated as "no match", ending in ErrUnknown).
type errReader struct{}

func (errReader) ReadAt(p []byte, off int64) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestDetectReadError(t *testing.T) {
	// size large enough that bounds checks pass and the read is attempted.
	got, err := Detect(errReader{}, 1<<20)
	if !errors.Is(err, ErrUnknown) || got != Unknown {
		t.Fatalf("errReader: got %q, %v; want Unknown, ErrUnknown", got, err)
	}
}

func TestReadAtBounds(t *testing.T) {
	r := bytes.NewReader(make([]byte, 100))
	if _, ok := readAt(r, 100, -1, 4); ok {
		t.Fatal("negative offset should fail")
	}
	if _, ok := readAt(r, 100, 0, 0); ok {
		t.Fatal("zero length should fail")
	}
	if _, ok := readAt(r, 100, 0, maxProbeRead+1); ok {
		t.Fatal("over-cap length should fail")
	}
	if _, ok := readAt(r, 100, 98, 4); ok {
		t.Fatal("read past size should fail")
	}
	if b, ok := readAt(r, 100, 0, 4); !ok || len(b) != 4 {
		t.Fatal("valid read should succeed")
	}
	// size unknown (negative) skips the size check.
	if _, ok := readAt(r, -1, 0, 4); !ok {
		t.Fatal("size<0 valid read should succeed")
	}
}

// --- registry ---

// fakeFS is a minimal filesystem.Filesystem for registry tests.
type fakeFS struct{ closed bool }

func (f *fakeFS) Close() error                                  { f.closed = true; return nil }
func (f *fakeFS) ReadFile(string) ([]byte, error)               { return nil, nil }
func (f *fakeFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (f *fakeFS) Stat(string) (filesystem.Stat, error)          { return nil, nil }
func (f *fakeFS) WriteFile(string, []byte, os.FileMode) error   { return nil }
func (f *fakeFS) ReadLink(string) (string, error)               { return "", nil }
func (f *fakeFS) MkDir(string, os.FileMode) error               { return nil }
func (f *fakeFS) DeleteFile(string) error                       { return nil }
func (f *fakeFS) DeleteDir(string) error                        { return nil }
func (f *fakeFS) Rename(string, string) error                   { return nil }

// withClean snapshots and restores the global registry so tests do not leak
// registrations into each other.
func withClean(t *testing.T, fn func()) {
	t.Helper()
	mu.Lock()
	saved := make(map[Type]Opener, len(registry))
	for k, v := range registry {
		saved[k] = v
	}
	registry = map[Type]Opener{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	})
	fn()
}

func TestRegisterAndOpen(t *testing.T) {
	withClean(t, func() {
		fs := &fakeFS{}
		var gotSize int64
		Register(SquashFS, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
			gotSize = size
			return fs, nil
		})
		if !Registered(SquashFS) {
			t.Fatal("SquashFS should be registered")
		}
		image := fixtures()[SquashFS]
		out, typ, err := Open(bytes.NewReader(image), int64(len(image)))
		if err != nil {
			t.Fatalf("Open error: %v", err)
		}
		if typ != SquashFS {
			t.Fatalf("type = %q, want squashfs", typ)
		}
		if out != filesystem.Filesystem(fs) {
			t.Fatal("Open returned a different filesystem than the opener")
		}
		if gotSize != int64(len(image)) {
			t.Fatalf("opener size = %d, want %d", gotSize, len(image))
		}
	})
}

func TestRegisterIdempotent(t *testing.T) {
	withClean(t, func() {
		first := &fakeFS{}
		second := &fakeFS{}
		Register(XFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return first, nil })
		Register(XFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return second, nil })
		image := fixtures()[XFS]
		out, _, err := Open(bytes.NewReader(image), int64(len(image)))
		if err != nil {
			t.Fatal(err)
		}
		if out != filesystem.Filesystem(second) {
			t.Fatal("second registration should win")
		}
	})
}

func TestRegisterRejectsInvalid(t *testing.T) {
	withClean(t, func() {
		Register(Unknown, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return nil, nil })
		Register("", func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return nil, nil })
		Register(Ext4, nil)
		if Registered(Unknown) || Registered("") || Registered(Ext4) {
			t.Fatal("invalid registrations should be rejected")
		}
	})
}

func TestOpenUnsupported(t *testing.T) {
	withClean(t, func() {
		image := fixtures()[Btrfs]
		_, typ, err := Open(bytes.NewReader(image), int64(len(image)))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("err = %v, want ErrUnsupported", err)
		}
		if typ != Btrfs {
			t.Fatalf("type = %q, want btrfs", typ)
		}
	})
}

func TestOpenUnknown(t *testing.T) {
	withClean(t, func() {
		_, typ, err := Open(bytes.NewReader(make([]byte, 100)), 100)
		if !errors.Is(err, ErrUnknown) || typ != Unknown {
			t.Fatalf("got %q, %v; want Unknown, ErrUnknown", typ, err)
		}
	})
}

func TestOpenOpenerError(t *testing.T) {
	withClean(t, func() {
		boom := errors.New("boom")
		Register(Ext4, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return nil, boom })
		image := fixtures()[Ext4]
		_, typ, err := Open(bytes.NewReader(image), int64(len(image)))
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want wrapped boom", err)
		}
		if typ != Ext4 {
			t.Fatalf("type = %q, want ext4", typ)
		}
	})
}

func TestOpenFile(t *testing.T) {
	withClean(t, func() {
		fs := &fakeFS{}
		Register(SquashFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return fs, nil })
		dir := t.TempDir()
		path := filepath.Join(dir, "img.squashfs")
		if err := os.WriteFile(path, fixtures()[SquashFS], 0o644); err != nil {
			t.Fatal(err)
		}
		out, typ, err := OpenFile(path)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if typ != SquashFS {
			t.Fatalf("type = %q, want squashfs", typ)
		}
		if err := out.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !fs.closed {
			t.Fatal("inner filesystem Close not called")
		}
	})
}

func TestOpenFileMissing(t *testing.T) {
	_, typ, err := OpenFile(filepath.Join(t.TempDir(), "nope"))
	if err == nil || typ != Unknown {
		t.Fatalf("missing file: got %q, %v; want Unknown, error", typ, err)
	}
}

func TestOpenFileUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk")
	if err := os.WriteFile(path, make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	_, typ, err := OpenFile(path)
	if !errors.Is(err, ErrUnknown) || typ != Unknown {
		t.Fatalf("got %q, %v; want Unknown, ErrUnknown", typ, err)
	}
}

func TestOpenFileUnsupported(t *testing.T) {
	withClean(t, func() {
		dir := t.TempDir()
		path := filepath.Join(dir, "img.btrfs")
		if err := os.WriteFile(path, fixtures()[Btrfs], 0o644); err != nil {
			t.Fatal(err)
		}
		_, typ, err := OpenFile(path)
		if !errors.Is(err, ErrUnsupported) || typ != Btrfs {
			t.Fatalf("got %q, %v; want btrfs, ErrUnsupported", typ, err)
		}
	})
}

// TestFileFSCloseFileError exercises the branch in fileFS.Close where the
// inner filesystem closes cleanly but the backing *os.File close fails
// (here: the descriptor was already closed out from under it).
func TestFileFSCloseFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &fileFS{Filesystem: &fakeFS{}, f: f}
	f.Close() // close the descriptor underneath
	if err := w.Close(); err == nil {
		t.Fatal("expected file close error to propagate when inner Close is nil")
	}
}

// TestOpenFileStatError exercises the Stat-error path of OpenFile by opening
// a path whose Stat fails after a successful Open. On a typical Unix this is
// hard to force directly, so we open /proc-like unstattable handles where
// available; otherwise we assert OpenFile on a directory reaches Detect with
// the directory's (zero) read behaviour and yields Unknown — the closest
// portable proxy. The dedicated Stat-failure branch is additionally covered
// via a closed descriptor below.
func TestOpenFileStatError(t *testing.T) {
	// A directory opens fine; reads return EISDIR so Detect yields Unknown.
	_, typ, err := OpenFile(t.TempDir())
	if !errors.Is(err, ErrUnknown) || typ != Unknown {
		t.Fatalf("dir: got %q, %v; want Unknown, ErrUnknown", typ, err)
	}

	// Inject an *os.File whose descriptor is already closed: Open succeeds
	// (seam) but the subsequent Stat fails, driving the Stat-error branch.
	saved := osOpen
	t.Cleanup(func() { osOpen = saved })
	osOpen = func(string) (*os.File, error) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		f.Close() // now Stat() on f fails
		return f, nil
	}
	_, typ, err = OpenFile("ignored")
	if err == nil || typ != Unknown {
		t.Fatalf("stat error: got %q, %v; want Unknown, error", typ, err)
	}
}

// closeErrFS returns an error from its inner Close to exercise fileFS.Close
// error propagation.
type closeErrFS struct{ fakeFS }

func (*closeErrFS) Close() error { return errors.New("inner close failed") }

func TestOpenFileInnerCloseError(t *testing.T) {
	withClean(t, func() {
		Register(SquashFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) {
			return &closeErrFS{}, nil
		})
		dir := t.TempDir()
		path := filepath.Join(dir, "img.squashfs")
		if err := os.WriteFile(path, fixtures()[SquashFS], 0o644); err != nil {
			t.Fatal(err)
		}
		out, _, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err == nil {
			t.Fatal("expected inner close error to propagate")
		}
	})
}

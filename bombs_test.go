package detect

import (
	"bytes"
	"testing"
)

// Audit of 2026-11-01: every read Detect issues is a fixed, small window at a
// fixed offset, so nothing in an image sizes an allocation. These tests pin that
// down so a future probe cannot quietly read a length or an offset out of the
// image, and fuzz the dispatcher.

// recordingReader serves zeros and remembers every read it was asked for.
type recordingReader struct {
	reads []struct{ off, n int64 }
	total int64
}

func (r *recordingReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads = append(r.reads, struct{ off, n int64 }{off, int64(len(p))})
	r.total += int64(len(p))
	clear(p)
	return len(p), nil
}

func TestDetectReadsAreFixedAndSmall(t *testing.T) {
	for _, size := range []int64{-1, 0, 1 << 20, 1 << 40, 1<<62 - 1} {
		r := &recordingReader{}
		if _, err := Detect(r, size); err != ErrUnknown {
			t.Fatalf("size %d: an image of zeros was detected as something: %v", size, err)
		}
		// A probe reads at most 8 bytes; the whole detection a few KiB (the ZFS
		// ring scan is 128 reads of 8 bytes).
		for _, rd := range r.reads {
			if rd.n <= 0 || rd.n > 8 || rd.off < 0 || rd.off > 1<<20 {
				t.Fatalf("size %d: read of %d bytes at %d is not a fixed small window", size, rd.n, rd.off)
			}
		}
		if len(r.reads) > 256 || r.total > 2048 {
			t.Fatalf("size %d: %d reads, %d bytes: detection must stay a handful of tiny reads", size, len(r.reads), r.total)
		}
	}
}

// FuzzDetect probes arbitrary bytes, with the size known and unknown. Whatever
// the image holds, Detect returns a recognised Type or Unknown+ErrUnknown, and
// Open either dispatches or reports a sentinel: never a panic.
func FuzzDetect(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 4096))
	f.Add(append([]byte("XFSB"), make([]byte, 600)...))
	f.Add(append(make([]byte, 0x438), 0x53, 0xEF))
	f.Add(append(make([]byte, 0x8001), []byte("CD001")...))
	f.Fuzz(func(t *testing.T, img []byte) {
		known := map[Type]bool{FAT32: true, ExFAT: true, NTFS: true, Ext4: true, XFS: true, Btrfs: true,
			ZFS: true, APFS: true, HFSPlus: true, ISO9660: true, SquashFS: true, UFS: true}
		for _, size := range []int64{int64(len(img)), -1, int64(len(img)) + 1<<20} {
			typ, err := Detect(bytes.NewReader(img), size)
			if err != nil {
				if typ != Unknown || err != ErrUnknown {
					t.Fatalf("Detect = %q, %v", typ, err)
				}
				continue
			}
			if !known[typ] {
				t.Fatalf("Detect returned the unrecognised type %q", typ)
			}
		}
		_, _, _ = Open(bytes.NewReader(img), int64(len(img)))
	})
}

package detect

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"testing"
)

// fatBoot builds a 512-byte FAT12/16-layout boot sector (512-byte sectors).
func fatBoot(total uint32, spc uint8, fatSz uint16, rootEnt uint16, rsvd uint16, nfats uint8) []byte {
	b := make([]byte, 512)
	b[0], b[1], b[2] = 0xEB, 0x3C, 0x90
	copy(b[3:], "MSDOS5.0")
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = spc
	binary.LittleEndian.PutUint16(b[14:], rsvd)
	b[16] = nfats
	binary.LittleEndian.PutUint16(b[17:], rootEnt)
	if total < 0x10000 {
		binary.LittleEndian.PutUint16(b[19:], uint16(total))
	} else {
		binary.LittleEndian.PutUint32(b[32:], total)
	}
	b[21] = 0xF8
	binary.LittleEndian.PutUint16(b[22:], fatSz)
	b[510], b[511] = 0x55, 0xAA
	return b
}

func detectBytes(t *testing.T, b []byte, size int64) Type {
	t.Helper()
	typ, _ := Detect(bytes.NewReader(b), size)
	return typ
}

func gunzipFixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Real images, formatted by newfs_msdos (-F 12, 1 MiB; -F 16, 8 MiB) and
// populated by mtools: the same fixtures the fat32 driver reads.
func TestDetectRealFAT12And16Images(t *testing.T) {
	for name, want := range map[string]Type{"fat12.img.gz": FAT12, "fat16.img.gz": FAT16} {
		img := gunzipFixture(t, name)
		for _, size := range []int64{int64(len(img)), -1} {
			typ, err := Detect(bytes.NewReader(img), size)
			if err != nil || typ != want {
				t.Fatalf("%s (size %d): Detect = %q, %v; want %q", name, size, typ, err, want)
			}
		}
	}
}

// The variant is the cluster count, at the specification's thresholds, and the
// label never overrides it.
func TestDetectFATByClusterCount(t *testing.T) {
	// rsvd 1, one FAT, 16 root entries (1 sector): data starts at 1+fat+1.
	cases := []struct {
		name  string
		total uint32
		fat   uint16
		want  Type
		label string
	}{
		{"4084 clusters", 1 + 16 + 1 + 4084, 16, FAT12, "FAT16   "},
		{"4085 clusters", 1 + 256 + 1 + 4085, 256, FAT16, "FAT12   "},
		{"65524 clusters", 1 + 256 + 1 + 65524, 256, FAT16, ""},
	}
	for _, c := range cases {
		b := fatBoot(c.total, 1, c.fat, 16, 1, 1)
		copy(b[0x36:], c.label)
		if got := detectBytes(t, b, int64(len(b))*0+int64(c.total)*512); got != c.want {
			t.Errorf("%s: Detect = %q, want %q", c.name, got, c.want)
		}
		if got := detectBytes(t, b, -1); got != c.want {
			t.Errorf("%s (size unknown): Detect = %q, want %q", c.name, got, c.want)
		}
	}
}

// A FAT-looking boot sector that is not one stays unknown.
func TestDetectFATRefusals(t *testing.T) {
	le := binary.LittleEndian
	base := func() []byte { return fatBoot(4000, 1, 16, 16, 1, 1) }
	if detectBytes(t, base(), -1) != FAT12 {
		t.Fatal("baseline is not FAT12")
	}
	cases := []struct {
		name   string
		mutate func(b []byte)
	}{
		{"no boot signature", func(b []byte) { b[510] = 0 }},
		{"no jump opcode", func(b []byte) { b[0] = 0x00 }},
		{"bytes per sector 0", func(b []byte) { le.PutUint16(b[11:], 0) }},
		{"bytes per sector 1000", func(b []byte) { le.PutUint16(b[11:], 1000) }},
		{"bytes per sector 8192", func(b []byte) { le.PutUint16(b[11:], 8192) }},
		{"sectors per cluster 0", func(b []byte) { b[13] = 0 }},
		{"sectors per cluster 3", func(b []byte) { b[13] = 3 }},
		{"reserved sectors 0", func(b []byte) { le.PutUint16(b[14:], 0) }},
		{"zero FATs", func(b []byte) { b[16] = 0 }},
		{"zero FAT size (the FAT32 layout)", func(b []byte) { le.PutUint16(b[22:], 0) }},
		{"zero root entries", func(b []byte) { le.PutUint16(b[17:], 0) }},
		{"root entries not filling sectors", func(b []byte) { le.PutUint16(b[17:], 17) }},
		{"zero total sectors", func(b []byte) { le.PutUint16(b[19:], 0) }},
		{"media byte 0x00", func(b []byte) { b[21] = 0x00 }},
		{"media byte 0xF7", func(b []byte) { b[21] = 0xF7 }},
		{"data area beyond the volume", func(b []byte) { le.PutUint16(b[19:], 10) }},
		{"FATs beyond the volume", func(b []byte) { b[16] = 255; le.PutUint16(b[22:], 0xFFFF) }},
		{"no data cluster", func(b []byte) { le.PutUint16(b[19:], 19); b[13] = 4 }},
		{"too many clusters for FAT16", func(b []byte) {
			le.PutUint16(b[19:], 0)
			le.PutUint32(b[32:], 1+16+1+65525)
		}},
		{"4 GiB sector count with 255 huge FATs", func(b []byte) {
			le.PutUint16(b[19:], 0)
			le.PutUint32(b[32:], 0xFFFFFFFF)
			b[16] = 255
			le.PutUint16(b[22:], 0xFFFF)
		}},
	}
	for _, c := range cases {
		b := base()
		c.mutate(b)
		if got := detectBytes(t, b, -1); got != Unknown {
			t.Errorf("%s: Detect = %q, want unknown", c.name, got)
		}
	}
	// The label alone proves nothing.
	b := make([]byte, 512)
	copy(b[0x36:], "FAT16   ")
	b[510], b[511] = 0x55, 0xAA
	if got := detectBytes(t, b, -1); got != Unknown {
		t.Errorf("label only: Detect = %q", got)
	}
	// An image smaller than the regions its own BPB places before the data.
	if got := detectBytes(t, base(), 1000); got != Unknown {
		t.Errorf("truncated image: Detect = %q", got)
	}
	// An image too short to hold the boot sector.
	if got := detectBytes(t, base()[:300], 300); got != Unknown {
		t.Errorf("short image: Detect = %q", got)
	}
	// A reader that cannot serve the signature (only the first 64 bytes).
	if got, _ := Detect(io.NewSectionReader(bytes.NewReader(base()), 0, 64), -1); got != Unknown {
		t.Errorf("signature unreadable: Detect = %q", got)
	}
}

// A FAT12 volume's FAT is data: two entries can spell another type's magic at
// its offset. 0xEF53 at 0x438 is the ext superblock magic.
func TestDetectFAT12WithExtLookalikeInItsFAT(t *testing.T) {
	b := make([]byte, 4000*512)
	copy(b, fatBoot(4000, 1, 16, 16, 1, 1))
	binary.LittleEndian.PutUint16(b[0x438:], extMagic)
	if got := detectBytes(t, b, int64(len(b))); got != FAT12 {
		t.Fatalf("Detect = %q, want fat12", got)
	}
}

// A real NTFS boot sector has a BPB and the 0xAA55 signature, but its FAT
// size and root entry fields are zero: it is not a FAT12/16 volume.
func TestDetectNTFSIsNotFAT(t *testing.T) {
	b := make([]byte, 512)
	b[0], b[1], b[2] = 0xEB, 0x52, 0x90
	copy(b[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = 8
	b[21] = 0xF8
	b[510], b[511] = 0x55, 0xAA
	if got := detectBytes(t, b, -1); got != NTFS {
		t.Fatalf("Detect = %q, want ntfs", got)
	}
}

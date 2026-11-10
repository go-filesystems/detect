package fdereg

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-fde/bitlocker"
	"github.com/go-fde/luks"
	"github.com/go-fde/veracrypt"
	"github.com/go-filesystems/detect"
	filesystem "github.com/go-filesystems/interface"
)

// memDev is a read-write-close device in memory, for luks.FormatOn.
type memDev struct{ data []byte }

func (m *memDev) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memDev) WriteAt(p []byte, off int64) (int, error) { return copy(m.data[off:], p), nil }
func (m *memDev) Close() error                             { return nil }

func gunzip(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
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

// fakeFS stands for the driver: the test registers it for FAT16 and
// records the boot sector the opener was handed.
type fakeFS struct{ filesystem.Filesystem }

func (fakeFS) Close() error { return nil }

func registerFAT16(t *testing.T) *[]byte {
	t.Helper()
	var boot []byte
	detect.Register(detect.FAT16, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
		boot = make([]byte, 512)
		if _, err := r.ReadAt(boot, 0); err != nil {
			return nil, err
		}
		return fakeFS{}, nil
	})
	return &boot
}

// TestLUKS: a FAT16 filesystem written into a LUKS container that
// go-fde/luks formats is reported as encrypted without a secret, and
// opened as FAT16 with it, the driver reading the plaintext from the
// payload's start.
func TestLUKS(t *testing.T) {
	fat := gunzip(t, filepath.Join("..", "testdata", "fat16.img.gz"))
	dev := &memDev{data: make([]byte, 4<<20+len(fat))}
	d, err := luks.FormatOn(dev, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteAt(fat, 0); err != nil {
		t.Fatal(err)
	}
	img := dev.data
	r := bytes.NewReader(img)

	if _, _, err := detect.Open(r, int64(len(img))); !errors.Is(err, detect.ErrEncrypted) ||
		!strings.Contains(err.Error(), "luks") {
		t.Fatalf("Open without a secret: %v", err)
	}

	boot := registerFAT16(t)
	_, typ, err := detect.OpenSecret(r, int64(len(img)), []byte("pw"))
	if err != nil || typ != detect.FAT16 {
		t.Fatalf("OpenSecret: %v %v", typ, err)
	}
	if !bytes.Equal(*boot, fat[:512]) {
		t.Fatal("the driver was not handed the plaintext from the payload's start")
	}

	if _, _, err := detect.OpenSecret(r, int64(len(img)), []byte("nope")); err == nil {
		t.Fatal("a wrong passphrase opened the container")
	}
}

// TestBitLocker uses go-fde/fde's fixture (password "fde"): its plaintext
// is a byte pattern, not a filesystem, so OpenSecret unlocks it and then
// finds no filesystem; the unlocker itself is checked against the pattern.
func TestBitLocker(t *testing.T) {
	img := gunzip(t, filepath.Join("testdata", "bitlocker_xts128_password_fde.img.gz"))
	r := bytes.NewReader(img)
	size := int64(len(img))

	if _, _, err := detect.Open(r, size); !errors.Is(err, detect.ErrEncrypted) ||
		!strings.Contains(err.Error(), "bitlocker") {
		t.Fatalf("Open without a secret: %v", err)
	}
	if _, _, err := detect.OpenSecret(r, size, []byte("fde")); !errors.Is(err, detect.ErrUnknown) {
		t.Fatalf("OpenSecret: %v, want ErrUnknown after a successful unlock", err)
	}
	if _, _, err := detect.OpenSecret(r, size, []byte("nope")); !errors.Is(err, bitlocker.ErrWrongSecret) {
		t.Fatalf("wrong password: %v", err)
	}

	plain, psize, err := unlockBitLocker(r, size, []byte("fde"))
	if err != nil || psize != size {
		t.Fatalf("unlock: %d %v", psize, err)
	}
	b := make([]byte, 1024)
	if _, err := plain.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	for i, v := range b {
		if want := byte(i*31 + i/512); v != want {
			t.Fatalf("plaintext byte %d is %#x, want %#x", i, v, want)
		}
	}
}

// TestVeraCrypt uses go-fde/veracrypt's fixture (password "fde", a 1 KiB
// volume holding a byte pattern). Without a probe, OpenSecret and Open see
// no container; OpenContainer unlocks it by name.
func TestVeraCrypt(t *testing.T) {
	img := gunzip(t, filepath.Join("testdata", "veracrypt_aes_sha512_fde.img.gz"))
	r := bytes.NewReader(img)
	size := int64(len(img))

	if _, ok := detect.DetectContainer(r, size); ok {
		t.Fatal("a VeraCrypt volume was detected: its header is ciphertext")
	}
	if _, _, err := detect.OpenContainer(detect.VeraCrypt, r, size, []byte("fde")); !errors.Is(err, detect.ErrUnknown) {
		t.Fatalf("OpenContainer: %v, want ErrUnknown after a successful unlock", err)
	}
	// One wrong password: it costs a trial over every KDF.
	if _, _, err := detect.OpenContainer(detect.VeraCrypt, r, size, []byte("nope")); !errors.Is(err, veracrypt.ErrWrongSecret) {
		t.Fatalf("wrong password: %v", err)
	}

	plain, psize, err := unlockVeraCrypt(r, size, []byte("fde"))
	if err != nil || psize != 1024 {
		t.Fatalf("unlock: %d %v", psize, err)
	}
	b := make([]byte, 1024)
	if _, err := plain.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	for i, v := range b {
		if want := byte(i*31 + i/512); v != want {
			t.Fatalf("plaintext byte %d is %#x, want %#x", i, v, want)
		}
	}
}

func TestProbesAndAdapter(t *testing.T) {
	short := bytes.NewReader([]byte("LU"))
	if isLUKS(short, 2) {
		t.Error("a 2-byte device is LUKS")
	}
	if isBitLocker(short, 2) {
		t.Error("a 2-byte device is BitLocker")
	}
	ro := readOnly{short}
	if _, err := ro.WriteAt([]byte{1}, 0); !errors.Is(err, errReadOnly) {
		t.Errorf("WriteAt: %v", err)
	}
	if err := ro.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// A LUKS magic over garbage: the backend refuses, and so does unlock.
	if _, _, err := unlockLUKS(bytes.NewReader([]byte(luksMagic+strings.Repeat("x", 600))), 606, []byte("pw")); err == nil {
		t.Error("garbage after the LUKS magic unlocked")
	}
}

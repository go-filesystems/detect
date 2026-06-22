package fat32reg

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-filesystems/detect"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
)

// fat32regOpen aliases the adapter's exported Opener for the bounds test.
var fat32regOpen = Open

// fat32TestSize is the smallest size the fat32 driver accepts as a valid
// FAT32 volume (matches the driver's own test constant).
const fat32TestSize = 4 * 1024 * 1024 // 4 MiB

// formatImage produces a real, freshly-formatted FAT32 image on disk and
// returns its bytes. This exercises the genuine driver Format path so the
// detect+open round-trip runs against an authentic on-disk layout, not a
// hand-built header.
func formatImage(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "src.img")
	fs, err := fat32.Format(path, fat32TestSize, fat32.FormatConfig{Label: "DETECT"})
	if err != nil {
		t.Fatalf("fat32.Format: %v", err)
	}
	if err := fs.WriteFile("/hello.txt", []byte("hi"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close formatted fs: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	return data
}

// TestInitRegistersFAT32 confirms the blank import wired the opener in.
func TestInitRegistersFAT32(t *testing.T) {
	if !detect.Registered(detect.FAT32) {
		t.Fatal("fat32reg blank import did not register detect.FAT32")
	}
}

// TestDetectRealFAT32 asserts a real formatted image is detected as fat32.
func TestDetectRealFAT32(t *testing.T) {
	image := formatImage(t)
	got, err := detect.Detect(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != detect.FAT32 {
		t.Fatalf("Detect = %q, want fat32", got)
	}
}

// TestOpenThroughAdapter is the end-to-end path: Detect identifies the image,
// dispatch lands on the fat32reg opener, and the returned filesystem serves
// real reads (the file seeded at format time round-trips).
func TestOpenThroughAdapter(t *testing.T) {
	image := formatImage(t)
	fs, typ, err := detect.Open(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if typ != detect.FAT32 {
		t.Fatalf("type = %q, want fat32", typ)
	}
	defer fs.Close()

	data, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile via adapter: %v", err)
	}
	if string(data) != "hi" {
		t.Fatalf("ReadFile = %q, want %q", data, "hi")
	}
}

// TestOpenFileThroughAdapter exercises the path-based entry point.
func TestOpenFileThroughAdapter(t *testing.T) {
	image := formatImage(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "disk.img")
	if err := os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}
	fs, typ, err := detect.OpenFile(path)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if typ != detect.FAT32 {
		t.Fatalf("type = %q, want fat32", typ)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestOpenerSizeBounds checks the adapter rejects implausible sizes.
func TestOpenerSizeBounds(t *testing.T) {
	if _, err := fat32regOpen(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative size should error")
	}
	if _, err := fat32regOpen(bytes.NewReader(nil), (int64(8)<<30)+1); err == nil {
		t.Fatal("oversize should error")
	}
}

// TestOpenerBadImage feeds the adapter a correctly-detected-but-corrupt image
// so the underlying driver Open fails and the temp file is cleaned up.
func TestOpenerBadImage(t *testing.T) {
	// Build something that passes FAT32 detection (boot sig + label) but is
	// not a valid volume, so fat32.Open rejects it.
	bad := make([]byte, 1024)
	copy(bad[0x52:], []byte("FAT32   "))
	bad[510] = 0x55
	bad[511] = 0xAA
	got, err := detect.Detect(bytes.NewReader(bad), int64(len(bad)))
	if err != nil || got != detect.FAT32 {
		t.Fatalf("precondition: Detect = %q, %v; want fat32", got, err)
	}
	_, _, err = detect.Open(bytes.NewReader(bad), int64(len(bad)))
	if err == nil {
		t.Fatal("expected driver open of corrupt image to fail")
	}
	if errors.Is(err, detect.ErrUnsupported) || errors.Is(err, detect.ErrUnknown) {
		t.Fatalf("expected opener (driver) error, got sentinel: %v", err)
	}
}

// --- seam-driven error-branch coverage ---

func swap[T any](p *T, v T) func() { old := *p; *p = v; return func() { *p = old } }

func TestOpenCreateTempError(t *testing.T) {
	defer swap(&createTemp, func(string, string) (*os.File, error) {
		return nil, errors.New("no temp")
	})()
	if _, err := Open(bytes.NewReader(make([]byte, 16)), 16); err == nil {
		t.Fatal("expected createTemp error")
	}
}

func TestOpenCopyError(t *testing.T) {
	var removed bool
	defer swap(&ioCopy, func(io.Writer, io.Reader) (int64, error) {
		return 0, errors.New("copy fail")
	})()
	defer swap(&osRemove, func(p string) error { removed = true; return os.Remove(p) })()
	if _, err := Open(bytes.NewReader(make([]byte, 16)), 16); err == nil {
		t.Fatal("expected copy error")
	}
	if !removed {
		t.Fatal("temp file should have been removed on copy error")
	}
}

func TestOpenFlushError(t *testing.T) {
	// Make the temp file's Close fail by closing it inside ioCopy.
	defer swap(&ioCopy, func(w io.Writer, _ io.Reader) (int64, error) {
		w.(*os.File).Close() // pre-close so the real Close in Open errors
		return 0, nil
	})()
	defer swap(&osRemove, func(p string) error { return os.Remove(p) })()
	if _, err := Open(bytes.NewReader(make([]byte, 16)), 16); err == nil {
		t.Fatal("expected flush (Close) error")
	}
}

func TestTempFSCloseRemoveError(t *testing.T) {
	defer swap(&osRemove, func(string) error { return errors.New("remove fail") })()
	w := &tempFS{Filesystem: noopFS{}, path: "irrelevant"}
	if err := w.Close(); err == nil {
		t.Fatal("expected remove error to surface when inner Close is nil")
	}
}

// noopFS is a no-op filesystem whose Close returns nil.
type noopFS struct{}

func (noopFS) Close() error                                  { return nil }
func (noopFS) ReadFile(string) ([]byte, error)               { return nil, nil }
func (noopFS) ListDir(string) ([]filesystem.DirEntry, error) { return nil, nil }
func (noopFS) Stat(string) (filesystem.Stat, error)          { return nil, nil }
func (noopFS) WriteFile(string, []byte, os.FileMode) error   { return nil }
func (noopFS) ReadLink(string) (string, error)               { return "", nil }
func (noopFS) MkDir(string, os.FileMode) error               { return nil }
func (noopFS) DeleteFile(string) error                       { return nil }
func (noopFS) DeleteDir(string) error                        { return nil }
func (noopFS) Rename(string, string) error                   { return nil }

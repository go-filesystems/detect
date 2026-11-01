package fat32reg

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Before: the staged copy wrote every byte, so a 256 MiB image of zeros took
// 256 MiB of disk (8 GiB at maxImage) and a sparse source was inflated fully.

func TestSparseWriterRoundTrip(t *testing.T) {
	// Data, a hole of several blocks, data again, a short zero tail, odd write
	// sizes so partial blocks occur.
	src := make([]byte, 0, 40000)
	src = append(src, bytes.Repeat([]byte{0xAB}, 100)...)
	src = append(src, make([]byte, 3*holeBlock+17)...)
	src = append(src, bytes.Repeat([]byte{0xCD}, 5000)...)
	src = append(src, make([]byte, 2*holeBlock)...)
	src = append(src, 0x01)
	src = append(src, make([]byte, 300)...) // trailing zeros: only truncate sets them

	p := filepath.Join(t.TempDir(), "img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := &sparseWriter{f: f}
	for off := 0; off < len(src); {
		n := min(4999, len(src)-off) // not a multiple of the block size
		if got, err := w.Write(src[off : off+n]); err != nil || got != n {
			t.Fatalf("Write: %d, %v", got, err)
		}
		off += n
	}
	if err := f.Truncate(int64(len(src))); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("staged copy differs from the source (len %d vs %d)", len(got), len(src))
	}
}

func TestSparseWriterErrors(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "img"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // every operation now fails
	w := &sparseWriter{f: f}
	if _, err := w.Write(make([]byte, holeBlock)); err == nil {
		t.Fatal("a hole written to a closed file must report the seek error")
	}
	if _, err := w.Write([]byte("data")); err == nil {
		t.Fatal("data written to a closed file must report the write error")
	}
	// Data followed by a hole: the pending run is flushed before the seek.
	run := append(bytes.Repeat([]byte{1}, holeBlock), make([]byte, holeBlock)...)
	if _, err := w.Write(run); err == nil {
		t.Fatal("a data run before a hole, written to a closed file, must report the write error")
	}
}

func TestOpenTruncateError(t *testing.T) {
	var removed bool
	defer swap(&truncate, func(*os.File, int64) error { return errors.New("no truncate") })()
	defer swap(&osRemove, func(p string) error { removed = true; return os.Remove(p) })()
	if _, err := Open(bytes.NewReader(make([]byte, 16)), 16); err == nil {
		t.Fatal("expected truncate error")
	}
	if !removed {
		t.Fatal("temp file should have been removed on truncate error")
	}
}

// BenchmarkStage compares staging a dense image through the sparse writer with a
// plain copy: the zero check must not cost measurably.
func BenchmarkStage(b *testing.B) {
	img := make([]byte, 64<<20)
	for i := range img {
		img[i] = byte(i*7 + 1)
	}
	run := func(b *testing.B, wrap func(*os.File) io.Writer) {
		b.SetBytes(int64(len(img)))
		dir := b.TempDir()
		for i := 0; i < b.N; i++ {
			f, err := os.Create(filepath.Join(dir, "img"))
			if err != nil {
				b.Fatal(err)
			}
			// A SectionReader, as Open uses: no WriterTo, so io.Copy runs its
			// 32 KiB buffer loop either way.
			if _, err := io.Copy(wrap(f), io.NewSectionReader(bytes.NewReader(img), 0, int64(len(img)))); err != nil {
				b.Fatal(err)
			}
			f.Close()
		}
	}
	b.Run("plain", func(b *testing.B) { run(b, func(f *os.File) io.Writer { return f }) })
	b.Run("sparse", func(b *testing.B) { run(b, func(f *os.File) io.Writer { return &sparseWriter{f: f} }) })
}

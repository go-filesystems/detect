//go:build unix

package fat32reg

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func allocated(t *testing.T, p string) (size, onDisk int64) {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size(), st.Sys().(*syscall.Stat_t).Blocks * 512
}

// A declared 256 MiB image of zeros stages as a hole, not as 256 MiB of data.
func TestStagedImageStaysSparse(t *testing.T) {
	// Skip where the temp filesystem does not keep holes.
	probe := filepath.Join(t.TempDir(), "probe")
	f, err := os.Create(probe)
	if err != nil {
		t.Skip("cannot create a file here")
	}
	terr := f.Truncate(16 << 20)
	f.Close()
	if terr != nil {
		t.Skip("cannot create a sparse file here")
	}
	if _, onDisk := allocated(t, probe); onDisk > 1<<20 {
		t.Skipf("the temp filesystem does not keep holes (%d bytes allocated for a 16 MiB hole)", onDisk)
	}

	const size = 256 << 20
	var length, onDisk int64
	defer swap(&osRemove, func(p string) error {
		length, onDisk = allocated(t, p)
		return os.Remove(p)
	})()
	_, err = Open(zeroReaderAt{}, size) // the driver rejects zeros; the staging is what is measured
	if err == nil {
		t.Fatal("the fat32 driver accepted an image of zeros")
	}
	if length != size {
		t.Fatalf("staged length %d, want %d", length, size)
	}
	if onDisk > 4<<20 {
		t.Fatalf("staged 256 MiB of zeros into %d bytes on disk (was 268435456)", onDisk)
	}
}

type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	clear(p)
	return len(p), nil
}

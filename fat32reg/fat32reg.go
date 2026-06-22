// Package fat32reg is a thin adapter that registers the go-filesystems/fat32
// driver with the detect registry. Blank-import it to make detect.Open and
// detect.OpenFile able to open FAT32 images:
//
//	import (
//		"github.com/go-filesystems/detect"
//		_ "github.com/go-filesystems/detect/fat32reg"
//	)
//
//	fs, typ, err := detect.OpenFile("disk.img") // typ == detect.FAT32
//
// It lives in its own module so the core detect package stays free of any
// concrete-driver dependency (the drivers pull in interface via a
// `replace => ../interface` sibling directive that does not compose for a
// meta-importer). The driver's own entry point is path-based and opens the
// image read/write, so this adapter materialises the probed io.ReaderAt to a
// temporary file before delegating. Closing the returned filesystem also
// removes that temporary file.
package fat32reg

import (
	"fmt"
	"io"
	"os"

	"github.com/go-filesystems/detect"
	fat32 "github.com/go-filesystems/fat32"
	filesystem "github.com/go-filesystems/interface"
)

func init() {
	detect.Register(detect.FAT32, Open)
}

// maxImage caps how large an image this adapter will spill to disk, guarding
// against an attacker-supplied size. 8 GiB comfortably covers any real FAT32
// volume (the format tops out at ~2 TiB but practical images are far below
// this), while keeping the bounded-copy honest.
const maxImage = int64(8) << 30

// Seams over the os/io operations so each error branch in Open and Close is
// exercisable in tests. Production code uses the real implementations.
var (
	createTemp = os.CreateTemp
	ioCopy     = io.Copy
	osRemove   = os.Remove
)

// Open implements detect.Opener for FAT32. It copies the whole image from r
// into a temporary file (the fat32 driver opens by path, read/write) and
// returns a filesystem.Filesystem whose Close also unlinks the temp file.
func Open(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
	if size < 0 || size > maxImage {
		return nil, fmt.Errorf("fat32reg: image size %d out of range", size)
	}
	tmp, err := createTemp("", "fat32reg-*.img")
	if err != nil {
		return nil, fmt.Errorf("fat32reg: temp file: %w", err)
	}
	path := tmp.Name()

	if _, err := ioCopy(tmp, io.NewSectionReader(r, 0, size)); err != nil {
		tmp.Close()
		osRemove(path)
		return nil, fmt.Errorf("fat32reg: stage image: %w", err)
	}
	if err := tmp.Close(); err != nil {
		osRemove(path)
		return nil, fmt.Errorf("fat32reg: flush image: %w", err)
	}

	fs, err := fat32.Open(path, -1)
	if err != nil {
		osRemove(path)
		return nil, fmt.Errorf("fat32reg: open: %w", err)
	}
	return &tempFS{Filesystem: fs, path: path}, nil
}

// tempFS wraps the driver filesystem so Close removes the staged temp file.
type tempFS struct {
	filesystem.Filesystem
	path string
}

func (t *tempFS) Close() error {
	err := t.Filesystem.Close()
	if rerr := osRemove(t.path); rerr != nil && err == nil {
		err = rerr
	}
	return err
}

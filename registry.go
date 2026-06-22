package detect

import (
	"fmt"
	"io"
	"os"
	"sync"

	filesystem "github.com/go-filesystems/interface"
)

// Opener constructs a filesystem.Filesystem from an image. It mirrors the
// concrete drivers' Open(rs io.ReaderAt, size int64) entry points. An Opener
// is responsible for its own validation; Open only calls it after Detect has
// already matched the corresponding Type.
type Opener func(r io.ReaderAt, size int64) (filesystem.Filesystem, error)

var (
	mu       sync.RWMutex
	registry = map[Type]Opener{}
)

// Register associates an Opener with a filesystem Type. It is idempotent
// (re-registering the same Type replaces the previous Opener) and safe for
// concurrent use, so a driver adapter may call it from init without
// coordinating with others. A nil Opener, or the Unknown type, is rejected
// to keep the dispatch table well-formed.
func Register(t Type, o Opener) {
	if o == nil || t == Unknown || t == "" {
		return
	}
	mu.Lock()
	registry[t] = o
	mu.Unlock()
}

// Registered reports whether an Opener is currently registered for t.
func Registered(t Type) bool {
	mu.RLock()
	_, ok := registry[t]
	mu.RUnlock()
	return ok
}

// opener returns the registered Opener for t, if any.
func opener(t Type) (Opener, bool) {
	mu.RLock()
	o, ok := registry[t]
	mu.RUnlock()
	return o, ok
}

// Open detects the filesystem type of r and dispatches to the Opener
// registered for that type. The detected Type is always returned, even on
// error, so callers can report it.
//
//   - If no signature matches, Open returns (nil, Unknown, ErrUnknown).
//   - If a type is detected but no Opener is registered for it, Open returns
//     (nil, <type>, ErrUnsupported) wrapped with the type name.
//   - Otherwise the Opener's result is returned with the detected Type.
func Open(r io.ReaderAt, size int64) (filesystem.Filesystem, Type, error) {
	t, err := Detect(r, size)
	if err != nil {
		return nil, t, err
	}
	o, ok := opener(t)
	if !ok {
		return nil, t, fmt.Errorf("%w: %s", ErrUnsupported, t)
	}
	fs, err := o(r, size)
	if err != nil {
		return nil, t, fmt.Errorf("detect: opener for %s failed: %w", t, err)
	}
	return fs, t, nil
}

// osOpen is a seam over os.Open so the OpenFile error paths are testable.
var osOpen = func(path string) (*os.File, error) { return os.Open(path) }

// OpenFile opens the file at path, detects its filesystem type and
// dispatches to the registered Opener. The underlying *os.File is closed
// only on error; on success it is retained by the returned Filesystem (whose
// Close must be called by the caller) — drivers read lazily through the
// io.ReaderAt, so the descriptor must outlive the returned value.
func OpenFile(path string) (filesystem.Filesystem, Type, error) {
	f, err := osOpen(path)
	if err != nil {
		return nil, Unknown, fmt.Errorf("detect: open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, Unknown, fmt.Errorf("detect: stat %s: %w", path, err)
	}
	fs, t, err := Open(f, fi.Size())
	if err != nil {
		f.Close()
		return nil, t, err
	}
	return &fileFS{Filesystem: fs, f: f}, t, nil
}

// fileFS wraps a driver Filesystem so that closing it also closes the
// backing *os.File opened by OpenFile.
type fileFS struct {
	filesystem.Filesystem
	f *os.File
}

func (w *fileFS) Close() error {
	err := w.Filesystem.Close()
	if cerr := w.f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

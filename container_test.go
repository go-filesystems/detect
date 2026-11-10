package detect

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// A fake container for the core's tests: "FAKECRYP" then the plaintext
// XORed with the secret's first byte; it unlocks only with "pw". The real
// containers live in fdereg, which this module does not depend on.
const fakeMagic = "FAKECRYP"

var errFakeSecret = errors.New("fake: wrong secret")

func fakeSeal(plain []byte) []byte {
	out := append([]byte(fakeMagic), plain...)
	for i := len(fakeMagic); i < len(out); i++ {
		out[i] ^= 'p'
	}
	return out
}

func fakeProbe(r io.ReaderAt, size int64) bool {
	b := make([]byte, len(fakeMagic))
	_, err := r.ReadAt(b, 0)
	return err == nil && string(b) == fakeMagic
}

func fakeUnlock(r io.ReaderAt, size int64, secret []byte) (io.ReaderAt, int64, error) {
	if string(secret) != "pw" {
		return nil, 0, errFakeSecret
	}
	plain := make([]byte, size-int64(len(fakeMagic)))
	if _, err := r.ReadAt(plain, int64(len(fakeMagic))); err != nil {
		return nil, 0, err
	}
	for i := range plain {
		plain[i] ^= 'p'
	}
	return bytes.NewReader(plain), int64(len(plain)), nil
}

// squashImage is a plaintext Detect reports as SquashFS.
func squashImage() []byte {
	return append([]byte("hsqs"), make([]byte, 4092)...)
}

// withCleanContainers snapshots and restores the container registry, and
// the filesystem registry through withClean.
func withCleanContainers(t *testing.T, fn func()) {
	t.Helper()
	cmu.Lock()
	saved := containers
	containers = nil
	cmu.Unlock()
	t.Cleanup(func() {
		cmu.Lock()
		containers = saved
		cmu.Unlock()
	})
	withClean(t, fn)
}

func TestOpenSecret(t *testing.T) {
	withCleanContainers(t, func() {
		fs := &fakeFS{}
		var seen []byte
		Register(SquashFS, func(r io.ReaderAt, size int64) (filesystem.Filesystem, error) {
			seen = make([]byte, 4)
			r.ReadAt(seen, 0)
			return fs, nil
		})
		RegisterContainer(LUKS, fakeProbe, fakeUnlock)
		img := fakeSeal(squashImage())
		r := bytes.NewReader(img)

		// Open without a secret names the container instead of probing
		// its ciphertext.
		if _, typ, err := Open(r, int64(len(img))); !errors.Is(err, ErrEncrypted) || typ != Unknown ||
			!strings.Contains(err.Error(), "luks") {
			t.Fatalf("Open: %v %v", typ, err)
		}
		if c, ok := DetectContainer(r, int64(len(img))); !ok || c != LUKS {
			t.Fatalf("DetectContainer: %q %v", c, ok)
		}

		got, typ, err := OpenSecret(r, int64(len(img)), []byte("pw"))
		if err != nil || typ != SquashFS || got != fs {
			t.Fatalf("OpenSecret: %v %v", typ, err)
		}
		if string(seen) != "hsqs" {
			t.Fatalf("the driver read %q, not the plaintext", seen)
		}

		if _, typ, err := OpenSecret(r, int64(len(img)), []byte("nope")); !errors.Is(err, errFakeSecret) || typ != Unknown {
			t.Fatalf("wrong secret: %v %v", typ, err)
		}

		// An image that is no container opens as Open would.
		plain := squashImage()
		if got, typ, err := OpenSecret(bytes.NewReader(plain), int64(len(plain)), []byte("unused")); err != nil || typ != SquashFS || got != fs {
			t.Fatalf("plain image: %v %v", typ, err)
		}
	})
}

// TestOpenContainerWithoutProbe: a container with no recognisable header
// (VeraCrypt) is never detected; the caller names it.
func TestOpenContainerWithoutProbe(t *testing.T) {
	withCleanContainers(t, func() {
		fs := &fakeFS{}
		Register(SquashFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return fs, nil })
		RegisterContainer(VeraCrypt, nil, fakeUnlock)
		img := fakeSeal(squashImage())
		r := bytes.NewReader(img)
		if _, ok := DetectContainer(r, int64(len(img))); ok {
			t.Fatal("a probe-less container was detected")
		}
		if _, _, err := Open(r, int64(len(img))); !errors.Is(err, ErrUnknown) {
			t.Fatalf("Open of an undetectable container: %v", err)
		}
		if got, typ, err := OpenContainer(VeraCrypt, r, int64(len(img)), []byte("pw")); err != nil || typ != SquashFS || got != fs {
			t.Fatalf("OpenContainer: %v %v", typ, err)
		}
		if _, _, err := OpenContainer(BitLocker, r, int64(len(img)), []byte("pw")); !errors.Is(err, ErrNoContainer) {
			t.Fatalf("unregistered container: %v", err)
		}
	})
}

func TestRegisterContainer(t *testing.T) {
	withCleanContainers(t, func() {
		RegisterContainer("", fakeProbe, fakeUnlock)
		RegisterContainer(LUKS, fakeProbe, nil)
		if len(containers) != 0 {
			t.Fatal("an empty name or a nil unlocker was registered")
		}
		boom := errors.New("second")
		RegisterContainer(LUKS, fakeProbe, fakeUnlock)
		RegisterContainer(LUKS, fakeProbe, func(io.ReaderAt, int64, []byte) (io.ReaderAt, int64, error) {
			return nil, 0, boom
		})
		if len(containers) != 1 {
			t.Fatalf("%d entries after re-registering", len(containers))
		}
		img := fakeSeal(squashImage())
		if _, _, err := OpenSecret(bytes.NewReader(img), int64(len(img)), []byte("pw")); !errors.Is(err, boom) {
			t.Fatalf("the replacement unlocker did not run: %v", err)
		}
		if _, ok := DetectContainer(nil, 0); ok {
			t.Fatal("a nil reader holds a container")
		}
	})
}

func TestOpenFileSecret(t *testing.T) {
	withCleanContainers(t, func() {
		fs := &fakeFS{}
		Register(SquashFS, func(io.ReaderAt, int64) (filesystem.Filesystem, error) { return fs, nil })
		RegisterContainer(BitLocker, fakeProbe, fakeUnlock)
		path := filepath.Join(t.TempDir(), "v.img")
		if err := os.WriteFile(path, fakeSeal(squashImage()), 0o600); err != nil {
			t.Fatal(err)
		}
		got, typ, err := OpenFileSecret(path, []byte("pw"))
		if err != nil || typ != SquashFS {
			t.Fatalf("OpenFileSecret: %v %v", typ, err)
		}
		if err := got.Close(); err != nil || !fs.closed {
			t.Fatalf("Close: %v %v", err, fs.closed)
		}
		if _, _, err := OpenFileSecret(path, []byte("nope")); !errors.Is(err, errFakeSecret) {
			t.Fatalf("wrong secret: %v", err)
		}
		if _, _, err := OpenFile(path); !errors.Is(err, ErrEncrypted) {
			t.Fatalf("OpenFile without a secret: %v", err)
		}
	})
}

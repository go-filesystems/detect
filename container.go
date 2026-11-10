package detect

import (
	"errors"
	"fmt"
	"io"
	"sync"

	filesystem "github.com/go-filesystems/interface"
)

// Container identifies an encryption layer that sits under a filesystem:
// a LUKS or BitLocker volume, a VeraCrypt container. Containers are wired in
// like filesystem drivers: the core knows none of them, and a caller who
// wants them imports an adapter (github.com/go-filesystems/detect/fdereg)
// that registers them with RegisterContainer. A caller who never opens
// encrypted images links no cryptography.
type Container string

// The containers the go-fde backends handle. VeraCrypt has no recognisable
// header: it is registered without a probe and only OpenContainer reaches it.
const (
	LUKS      Container = "luks"
	BitLocker Container = "bitlocker"
	VeraCrypt Container = "veracrypt"
)

// Unlocker opens a container with secret and returns the plaintext device:
// a reader whose offset 0 is the first byte of the filesystem inside, and
// its size. Whatever the container's own offset conventions (LUKS counts
// from its payload, BitLocker maps the whole volume), the adapter hands
// drivers a device that starts at the filesystem.
type Unlocker func(r io.ReaderAt, size int64, secret []byte) (plain io.ReaderAt, plainSize int64, err error)

// ContainerProbe reports whether r holds the container's header. It must
// only read, and only a bounded amount.
type ContainerProbe func(r io.ReaderAt, size int64) bool

var (
	// ErrEncrypted is returned by Open when the image is a registered
	// encrypted container: it needs a secret (OpenSecret), and probing its
	// ciphertext for a filesystem would at best find nothing and at worst
	// misread a header (a BitLocker To Go volume starts like FAT32).
	ErrEncrypted = errors.New("detect: encrypted container")

	// ErrNoContainer is returned by OpenContainer for a Container no
	// adapter registered.
	ErrNoContainer = errors.New("detect: no unlocker registered for container")
)

type containerEntry struct {
	c      Container
	probe  ContainerProbe
	unlock Unlocker
}

var (
	cmu        sync.RWMutex
	containers []containerEntry
)

// RegisterContainer associates an Unlocker, and optionally a probe, with a
// Container. Re-registering a Container replaces it; a nil Unlocker or an
// empty name is ignored. probe may be nil for a container that cannot be
// recognised from its header: OpenContainer still reaches it, Open and
// OpenSecret never do.
func RegisterContainer(c Container, probe ContainerProbe, u Unlocker) {
	if u == nil || c == "" {
		return
	}
	cmu.Lock()
	defer cmu.Unlock()
	for i := range containers {
		if containers[i].c == c {
			containers[i] = containerEntry{c, probe, u}
			return
		}
	}
	containers = append(containers, containerEntry{c, probe, u})
}

// DetectContainer reports which registered container, if any, r holds,
// probing in registration order.
func DetectContainer(r io.ReaderAt, size int64) (Container, bool) {
	if r == nil {
		return "", false
	}
	cmu.RLock()
	defer cmu.RUnlock()
	for _, e := range containers {
		if e.probe != nil && e.probe(r, size) {
			return e.c, true
		}
	}
	return "", false
}

func unlocker(c Container) (Unlocker, bool) {
	cmu.RLock()
	defer cmu.RUnlock()
	for _, e := range containers {
		if e.c == c {
			return e.unlock, true
		}
	}
	return nil, false
}

// OpenSecret opens the filesystem in r, unlocking it first when r is a
// registered encrypted container. The secret is a passphrase, a recovery
// key or a key file's contents, as the container defines it. An image that
// is not a container is opened as Open would, and the secret is unused.
func OpenSecret(r io.ReaderAt, size int64, secret []byte) (filesystem.Filesystem, Type, error) {
	c, ok := DetectContainer(r, size)
	if !ok {
		return openPlain(r, size)
	}
	return OpenContainer(c, r, size, secret)
}

// OpenContainer unlocks r as the named container with secret and opens the
// filesystem inside. It is how a container without a recognisable header
// (VeraCrypt) is opened: the caller says what it is.
func OpenContainer(c Container, r io.ReaderAt, size int64, secret []byte) (filesystem.Filesystem, Type, error) {
	u, ok := unlocker(c)
	if !ok {
		return nil, Unknown, fmt.Errorf("%w: %s", ErrNoContainer, c)
	}
	plain, psize, err := u(r, size, secret)
	if err != nil {
		return nil, Unknown, fmt.Errorf("detect: unlock %s: %w", c, err)
	}
	return openPlain(plain, psize)
}

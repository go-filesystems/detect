// Package fdereg registers the go-fde containers with
// github.com/go-filesystems/detect, so that detect.OpenSecret can open a
// filesystem inside them:
//
//	import _ "github.com/go-filesystems/detect/fdereg"
//
//	fs, t, err := detect.OpenSecret(r, size, []byte("passphrase"))
//
// It registers:
//
//   - detect.LUKS: LUKS1 and LUKS2 through github.com/go-fde/luks, detected
//     by the "LUKS\xba\xbe" magic. The plaintext device starts at the
//     payload.
//   - detect.BitLocker: BitLocker (Windows 7+, To Go) through
//     github.com/go-fde/bitlocker, read-only, detected from its volume
//     header. The secret is a password, a recovery password, or a .BEK
//     startup key file's contents.
//   - detect.VeraCrypt: VeraCrypt and TrueCrypt through
//     github.com/go-fde/veracrypt, read-only, without a probe: its header
//     is ciphertext, so only detect.OpenContainer(detect.VeraCrypt, …)
//     reaches it. The secret is the password; every KDF and cipher the
//     backend supports is tried, as VeraCrypt does. Keyfiles, a PIM or a
//     hidden volume need github.com/go-fde/veracrypt directly.
//
// All unlock with their package's default limits on key-derivation work,
// so an untrusted image cannot make an unlock arbitrarily expensive.
package fdereg

import (
	"errors"
	"io"

	"github.com/go-fde/bitlocker"
	"github.com/go-fde/luks"
	"github.com/go-fde/veracrypt"
	"github.com/go-filesystems/detect"
)

func init() {
	detect.RegisterContainer(detect.LUKS, isLUKS, unlockLUKS)
	detect.RegisterContainer(detect.BitLocker, isBitLocker, unlockBitLocker)
	detect.RegisterContainer(detect.VeraCrypt, nil, unlockVeraCrypt)
}

const luksMagic = "LUKS\xba\xbe"

func isLUKS(r io.ReaderAt, _ int64) bool {
	b := make([]byte, len(luksMagic))
	_, err := r.ReadAt(b, 0)
	return err == nil && string(b) == luksMagic
}

func isBitLocker(r io.ReaderAt, _ int64) bool { return bitlocker.Detect(r) }

// errReadOnly is what a write through the adapter returns: detect's
// openers read, and an unlocked container is never written through it.
var errReadOnly = errors.New("fdereg: read-only")

// readOnly adapts the io.ReaderAt detect holds to the read-write-close
// device the go-fde backends take. Close does nothing: detect's caller
// owns r.
type readOnly struct{ io.ReaderAt }

func (readOnly) WriteAt([]byte, int64) (int, error) { return 0, errReadOnly }
func (readOnly) Close() error                       { return nil }

func unlockLUKS(r io.ReaderAt, size int64, secret []byte) (io.ReaderAt, int64, error) {
	d, err := luks.OpenFrom(readOnly{r}, secret)
	if err != nil {
		return nil, 0, err
	}
	// LUKS offsets are relative to the payload already. A header that
	// does not record the payload length means "to the end of the device".
	psize := d.Size()
	if psize <= 0 {
		psize = size - d.PayloadOffset()
	}
	return d, psize, nil
}

func unlockBitLocker(r io.ReaderAt, size int64, secret []byte) (io.ReaderAt, int64, error) {
	d, err := bitlocker.OpenFrom(readOnly{r}, size, secret, bitlocker.DefaultLimits)
	if err != nil {
		return nil, 0, err
	}
	return d, d.Size(), nil
}

// unlockVeraCrypt: VeraCrypt offsets are relative to the data area, so
// offset 0 is the filesystem's first byte, as detect wants.
func unlockVeraCrypt(r io.ReaderAt, size int64, secret []byte) (io.ReaderAt, int64, error) {
	d, err := veracrypt.OpenFrom(readOnly{r}, size, veracrypt.Options{Password: secret})
	if err != nil {
		return nil, 0, err
	}
	return d, d.Size(), nil
}

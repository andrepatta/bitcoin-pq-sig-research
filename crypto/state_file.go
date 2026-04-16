package crypto

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
)

// StateIO is the persistence hook used by ShrincsKey and ShrimpsKey to
// load and atomically rewrite their state blob. It decouples signing
// keys from *where* the blob lives: the filesystem (FileStateIO, below)
// is the default, but the wallet package can inject an encrypted-at-
// rest implementation that routes through a keyed AES-GCM store.
//
// Contract:
//   - Read returns the stored body bytes, or an error wrapping
//     os.ErrNotExist for a fresh key with no prior state. Callers
//     distinguish via errors.Is(err, os.ErrNotExist).
//   - Write atomically replaces the stored body with data. Must be
//     durable enough that a crash after return leaves either the new
//     body visible on next read, or the old — never a partial write.
//   - A nil StateIO value passed to NewShrincsKey / NewShrimpsKey means
//     "no persistence"; the key operates purely in memory.
type StateIO interface {
	Read() ([]byte, error)
	Write(data []byte) error
}

// FileStateIO is the default filesystem-backed StateIO. Body is stored
// with a CRC32-IEEE trailer for integrity (catches single-bit flips the
// cached-root equality check would miss), atomically written via
// write-then-rename with parent-dir fsync.
type FileStateIO struct {
	Path string
}

// Read loads and CRC-verifies the file body. Returns os.ErrNotExist
// (as raised by os.ReadFile) if absent; ErrStateCorrupted on CRC or
// length errors. The body length is not validated here — callers check
// it against their own schema after Read returns.
func (f *FileStateIO) Read() ([]byte, error) {
	if f == nil || f.Path == "" {
		return nil, errors.New("state: nil or empty FileStateIO")
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	if len(data) < stateFileCRCLen {
		return nil, ErrStateCorrupted
	}
	body := data[:len(data)-stateFileCRCLen]
	want := binary.BigEndian.Uint32(data[len(data)-stateFileCRCLen:])
	if crc32.ChecksumIEEE(body) != want {
		return nil, ErrStateCorrupted
	}
	return body, nil
}

// Write delegates to writeStateFile, which performs atomic write-then-
// rename with CRC32 trailer and parent-dir fsync.
func (f *FileStateIO) Write(data []byte) error {
	if f == nil || f.Path == "" {
		return errors.New("state: nil or empty FileStateIO")
	}
	return writeStateFile(f.Path, data)
}

// State-file integrity layout (used by shrincs.go + shrimps.go):
//
//   [N-byte body][4-byte CRC32-IEEE over body, big-endian]
//
// CRC catches single-bit / partial-write corruption that the cached-root
// equality check would miss (e.g. counter byte flips while roots stay
// intact). Combined with the existing root check, any tamper survives
// only if both the CRC and the cached roots are coordinated — vanishingly
// unlikely for natural disk corruption.
//
// Persistence order (atomic, durable):
//   1. write body+CRC into <path>.tmp
//   2. fsync the tmp file
//   3. rename tmp -> path
//   4. fsync the parent directory (so the rename hits disk too)
//
// A crash anywhere before step 3 leaves only the (untracked) tmp file.
// A crash between steps 3 and 4 may, on some filesystems, present the
// rename as un-applied after reboot — readStateFile then sees the old
// body, which is safe (counter never goes backwards).

const stateFileCRCLen = 4

// writeStateFile writes body to path durably with a CRC32 trailer.
func writeStateFile(path string, body []byte) error {
	if path == "" {
		return errors.New("state: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out := make([]byte, len(body)+stateFileCRCLen)
	copy(out, body)
	crc := crc32.ChecksumIEEE(body)
	binary.BigEndian.PutUint32(out[len(body):], crc)

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	// fsync parent dir so the rename is durable. Best-effort: some
	// filesystems (e.g. tmpfs in CI) reject Sync on directories with
	// EINVAL — treat that as benign.
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer dir.Close()
	_ = dir.Sync()
	return nil
}

// AppendCRC returns body with its CRC32-IEEE trailer appended. Exposed
// so alternate StateIO implementations (e.g. the wallet's encrypted
// store) can produce the same on-disk wire shape, which means the CRC
// still protects the plaintext against in-memory flips even when the
// bytes end up living inside an AES-GCM ciphertext.
func AppendCRC(body []byte) []byte {
	out := make([]byte, len(body)+stateFileCRCLen)
	copy(out, body)
	crc := crc32.ChecksumIEEE(body)
	binary.BigEndian.PutUint32(out[len(body):], crc)
	return out
}

// StripAndVerifyCRC is the inverse of AppendCRC. Returns the body
// without the trailer; ErrStateCorrupted on length or checksum error.
func StripAndVerifyCRC(data []byte) ([]byte, error) {
	if len(data) < stateFileCRCLen {
		return nil, ErrStateCorrupted
	}
	body := data[:len(data)-stateFileCRCLen]
	want := binary.BigEndian.Uint32(data[len(data)-stateFileCRCLen:])
	if crc32.ChecksumIEEE(body) != want {
		return nil, ErrStateCorrupted
	}
	return body, nil
}

// readStateFile reads path and verifies the CRC32 trailer. Returns the
// body without the trailer; ErrStateCorrupted on any size or checksum
// mismatch (caller distinguishes file-missing via os.IsNotExist on raw
// os.ReadFile if it needs init-on-absent semantics).
func readStateFile(path string, expectedBodyLen int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != expectedBodyLen+stateFileCRCLen {
		return nil, ErrStateCorrupted
	}
	body := data[:expectedBodyLen]
	want := binary.BigEndian.Uint32(data[expectedBodyLen:])
	if crc32.ChecksumIEEE(body) != want {
		return nil, ErrStateCorrupted
	}
	return body, nil
}

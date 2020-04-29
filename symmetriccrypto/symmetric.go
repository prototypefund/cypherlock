package symmetriccrypto

import (
	"crypto/rand"
	"errors"
	"io"

	"assuredrelease.com/cypherlock-pe/unsafeconvert"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	ErrSize    = errors.New("symmetriccrypto: Padding size corrupt")
	ErrDecrypt = errors.New("symmetriccrypto: Could not decrypt")
)

var RandomSource = rand.Reader

const EncryptionOverhead = 24 + secretbox.Overhead

// EncryptedSize returns the size of msg after encryption.
func EncryptedSize(msg []byte) int {
	return EncryptedSizeLength(len(msg))
}

func EncryptedSizeLength(l int) int {
	return EncryptionOverhead + l
}

// Encrypt symmetrically encrypts msg with key. If out is not nil and has EncryptedSize capacity it is used for output.
// Otherwise a new byteslice from insecure memory is allocated.
func Encrypt(key, msg, out []byte) ([]byte, error) {
	var outT []byte
	if out == nil {
		outT = make([]byte, 24, EncryptedSize(msg)) // Non-secret, since encrypted
	} else {
		if cap(out) < EncryptedSize(msg) {
			panic("symmetriccrypto: Encrypt output too short")
		}
		outT = out[0:24]
	}
	if _, err := io.ReadFull(RandomSource, outT[0:24]); err != nil {
		return nil, err
	}
	if len(key) < 32 {
		return nil, ErrSize
	}
	secretbox.Seal(outT[24:], msg, unsafeconvert.To24(outT[0:24]), unsafeconvert.To32(key))
	return outT[:EncryptedSize(msg)], nil
}

// DecryptedSize returns the size of msg after decryption.
func DecryptedSize(msg []byte) int {
	return DecryptedSizeLength(len(msg))
}

func DecryptedSizeLength(l int) int {
	return l - secretbox.Overhead - 24
}

func EncryptionOffset() int {
	return secretbox.Overhead + 24
}

// Decrypt decrypts msg with key. If out is not nil then output is written there, as long as the capacity of out
// is at least DecryptedSize. If out is nil, a new byteslice from insecure memory will be allocated for output.
func Decrypt(key, msg []byte, out []byte) ([]byte, error) {
	var err error
	var outT []byte
	if len(msg) < 24+secretbox.Overhead {
		return nil, ErrSize
	}
	if len(key) < 32 {
		return nil, ErrSize
	}
	ds := DecryptedSize(msg)
	if out == nil {
		outT = make([]byte, ds)
	} else {
		if cap(out) < ds {
			panic("symmetriccrypto: Decrypt output too short")
		}
		outT = out[0:ds]
	}
	if err != nil {
		return nil, err
	}
	_, ok := secretbox.Open(outT[0:0], msg[24:], unsafeconvert.To24(msg[0:24]), unsafeconvert.To32(key))
	if !ok {
		return nil, ErrDecrypt
	}
	return outT[0:ds], nil
}

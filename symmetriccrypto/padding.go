package symmetriccrypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"assuredrelease.com/cypherlock-pe/unsafeconvert"
	"golang.org/x/crypto/salsa20/salsa"
)

const PaddingOverhead = 8

// PaddedMessageSize returns the length of the padded message.
func PaddedMessageSize(msgLength, padLength int) int {
	_, t := paddedMessageSize(msgLength, padLength)
	return t
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func paddedMessageSize(msgLength, padLength int) (l, t int) {
	// t == total size required
	// l == size of padding
	rl := max(msgLength, padLength)
	l = rl - msgLength
	if l < 0 {
		l = 0
	}
	t = rl + 8
	return
}

var zeroKey = [32]byte{0x00}

// AddPadding will pad msg up to length padLength. The output is at least 8 bytes larger.
// If msg is already padLength long, no padding will be added (but the padding indicator is).
// If padKey is nil, a random one is allocated from insecure memory.
// If padKey is all zeros, it is randomized. Otherwise it is used.
// If out is not nil, it will be used for output, but it must have PaddedMessageSize capacity.
// If out is nil and has enough capacity, it will be used for output. Otherwise the output
// will be a new slice allocated from insecure memory.
func AddPadding(msg, out []byte, padLength int, padKey []byte) ([]byte, error) {
	var outT []byte
	var needCopy bool
	if padKey == nil {
		padKey = make([]byte, 32)
	}
	if bytes.Equal(padKey, zeroKey[:]) {
		_, err := io.ReadFull(RandomSource, padKey)
		if err != nil {
			return nil, err
		}
	}
	m := len(msg)
	l, t := paddedMessageSize(len(msg), padLength)
	if out != nil {
		if cap(out) < t {
			panic("symmetriccrypto: Padding output slice is too short")
		}
		outT = out[0:t]
		needCopy = true
	} else if cap(msg) >= t {
		outT = msg[0:t]
	} else {
		outT = make([]byte, t)
		needCopy = true
	}
	binary.BigEndian.PutUint64(outT[m+l:m+l+PaddingOverhead], uint64(m))
	if l > 0 {
		salsa.XORKeyStream(outT[m:m+l], outT[m:m+l], new([16]byte), unsafeconvert.To32(padKey))
	}
	if needCopy {
		subtle.ConstantTimeCopy(1, outT[0:m], msg)
	}
	return outT, nil
}

// RemovePadding removes the padding from msg. msg may not contain extra bytes.
func RemovePadding(msg []byte) ([]byte, error) {
	if len(msg) < PaddingOverhead {
		return nil, ErrSize
	}
	l := int(binary.BigEndian.Uint64(msg[len(msg)-PaddingOverhead : len(msg)]))
	if len(msg) < PaddingOverhead+l {
		return nil, ErrSize
	}
	return msg[0:l], nil
}

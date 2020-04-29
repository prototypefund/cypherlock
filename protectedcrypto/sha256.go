// Package protectedcrypto implements cryptographic protocols over protected memory.
package protectedcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"time"
)

var RandomSource = rand.Reader

var timeNow = func() int64 { return time.Now().Unix() }

// sha256Self calculates the sha256 of c and returns it in c.
func sha256Self(c []byte) []byte {
	h := sha256.New()
	h.Write(c)
	h.Sum(c[0:0])
	h.Reset()
	return c
}

// // sha256Two calculates the sha256 of c+d and returns it in d.
// func sha256Two(c, d []byte) []byte {
// 	h := sha256.New()
// 	h.Write(c)
// 	h.Write(d)
// 	h.Sum(d[0:0])
// 	h.Reset()
// 	return c
// }

// // sha256HMAC calculates a sha256 "HMAC". It does not apply paddings.
// // It returns the result in message. Do not use as replacement for an actual HMAC. Also, it is not secure for inputs<32byte.
// func sha256HMACSelf(key, message []byte) []byte {
// 	h := sha256.New()
// 	h.Write(key)
// 	h.Write(message)
// 	h.Sum(message[0:0])
// 	h.Reset()
// 	h.Write(key)
// 	h.Write(message)
// 	h.Sum(message[0:0])
// 	return message
// }

var (
	ipad = [32]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}
	opad = [32]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}
)

func applyHMACPad(k []byte, pad byte) {
	for i := 0; i < len(k); i++ {
		k[i] ^= pad
	}
}

// SHA256HMAC calculates a sha256 HMAC using the given input slices. key and output must be writeable. output must be 32byte long. The result is returned
// in output. The key may not be more then 64 bytes long for standard conforming operation.
func SHA256HMAC(key, message, output []byte) []byte {
	h := sha256.New()
	applyHMACPad(key, 0x36)
	h.Write(key)
	if len(key) < 64 {
		h.Write(ipad[0 : 64-len(key)])
	}
	h.Write(message)
	h.Sum(output[0:0])
	h.Reset()
	applyHMACPad(key, 0x6A)
	h.Write(key)
	if len(key) < 64 {
		h.Write(opad[0 : 64-len(key)])
	}
	applyHMACPad(key, 0x5C)
	h.Write(output)
	h.Sum(output[0:0])
	return output
}

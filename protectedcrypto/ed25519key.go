package protectedcrypto

import (
	"crypto/sha512"
	"io"
	"strconv"

	"github.com/agl/ed25519/edwards25519" // BAD, original code refers to golang.org/x/crypto/ed25519/internal/edwards25519. Possibly better to import the complete source.
	// "./internal/edwards25519" // Lifted from golang.org/x/crypto/ed25519/internal/edwards. Needs to be kept up to date.

	"assuredrelease.com/cypherlock-pe/memprotect"

	"golang.org/x/crypto/ed25519"
)

// Lifted from golang.org/x/crypto/ed25519
func newEd25519FromSeed(seed []byte, privateKey []byte) {
	if l := len(seed); l != ed25519.SeedSize {
		panic("protectedcrypto: newEd25519FromSeed bad seed length: " + strconv.Itoa(l))
	}
	if l := len(privateKey); l != ed25519.PrivateKeySize {
		panic("protectedcrypto: newEd25519FromSeed bad privatekey length: " + strconv.Itoa(l))
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)
	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])
}

// ED25519 returns an ED25519 capable protected element.
type ED25519 struct {
	engine  memprotect.Engine
	element memprotect.Element
}

func NewED25519(engine memprotect.Engine) *ED25519 {
	return &ED25519{
		engine: engine,
	}
}

func (self *ED25519) Generate() error {
	self.element = self.engine.Element(ed25519.PrivateKeySize)
	self.element.Melt()
	privkey, err := self.element.Bytes()
	if err != nil {
		self.element.Destroy()
		self.element = nil
		return err
	}
	seedC := self.engine.Cell(ed25519.SeedSize)
	defer seedC.Destroy()
	seed := seedC.Bytes()
	_, err = io.ReadFull(RandomSource, seed)
	if err != nil {
		self.element.Destroy()
		self.element = nil
		return err
	}
	newEd25519FromSeed(seed, privkey)
	self.Seal()
	return nil
}

func (self *ED25519) SetSecure(privateKey memprotect.Element) error {
	if privateKey.Size() < ed25519.PrivateKeySize {
		return memprotect.ErrSize
	}
	self.element = privateKey
	return nil
}

func (self *ED25519) PublicKey() (ed25519.PublicKey, error) {
	x, err := self.element.Bytes()
	if err != nil {
		return nil, err
	}
	pubkey := ed25519.PrivateKey(x).Public().(ed25519.PublicKey)
	self.Seal()
	return pubkey, nil
}

func (self *ED25519) PrivateKey() memprotect.Element {
	return self.element
}

func (self *ED25519) Sign(message []byte) ([]byte, error) {
	b, err := self.element.Bytes()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(b, message)
	self.Seal()
	return sig, nil
}

func (self *ED25519) Seal() {
	self.element.Seal()
}

// ED25519Verify is a convenience function that wraps ed25519.Verify.
func ED25519Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}

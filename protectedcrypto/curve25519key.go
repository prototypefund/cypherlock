package protectedcrypto

import (
	"crypto/subtle"
	"io"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"

	"golang.org/x/crypto/curve25519"
)

// Curve25519Key returns an Curve25519 capable protected element.
type Curve25519 struct {
	engine       memprotect.Engine
	exportEngine memprotect.Engine
	element      memprotect.Element
	pubkey       *[32]byte
}

func NewCurve25519(engine memprotect.Engine, exportEngine ...memprotect.Engine) *Curve25519 {
	r := &Curve25519{
		engine:       engine,
		exportEngine: engine,
	}
	if len(exportEngine) > 0 {
		r.exportEngine = exportEngine[0]
	}
	return r
}

func (self *Curve25519) Generate() error {
	self.element = self.engine.Element(32)
	self.element.Melt()
	b, err := self.element.Bytes()
	if err != nil {
		self.element.Destroy()
		self.element = nil
		return err
	}
	_, err = io.ReadFull(RandomSource, b)
	if err != nil {
		self.element.Destroy()
		self.element = nil
		return err
	}
	self.pubkey = new([32]byte)
	curve25519.ScalarBaseMult(self.pubkey, unsafeconvert.To32(b))
	return nil
}

func (self *Curve25519) SetSecure(privateKey memprotect.Element) error {
	self.element = privateKey
	return nil
}

func (self *Curve25519) PublicKey() *[32]byte {
	return self.pubkey
}

func (self *Curve25519) PrivateKey() memprotect.Element {
	return self.element
}

func (self *Curve25519) SharedSecret(myPublicKey, peerPublicKey *[32]byte) (myPublicKeyCopy *[32]byte, secret memprotect.Cell, err error) {
	if myPublicKey != nil && subtle.ConstantTimeCompare(myPublicKey[:], self.pubkey[:]) != 1 {
		return nil, nil, memprotect.ErrKeyNotFound
	}
	s1 := self.exportEngine.Cell(32)
	p, err := self.element.Bytes()
	if err != nil {
		s1.Destroy()
		return nil, nil, err
	}
	curve25519.ScalarMult(unsafeconvert.To32(s1.Bytes()), unsafeconvert.To32(p), peerPublicKey)
	self.element.Seal()
	sha256Self(s1.Bytes())
	return self.PublicKey(), s1, nil
}

// func (self *Curve25519) SharedSecret2DH(peerPublicKey *[32]byte) (ephemeralPublicKey *[32]byte, secret memprotect.Cell, err error) {
// 	ephemeral := self.exportEngine.Cell(32)
// 	_, err = io.ReadFull(RandomSource, ephemeral.Bytes())
// 	if err != nil {
// 		ephemeral.Destroy()
// 		return nil, nil, err
// 	}
// 	s2 := self.exportEngine.Cell(32)
// 	ephemeralPublicKey = new([32]byte)
// 	curve25519.ScalarBaseMult(ephemeralPublicKey, unsafeconvert.To32(ephemeral.Bytes()))
// 	curve25519.ScalarMult(unsafeconvert.To32(s2.Bytes()), unsafeconvert.To32(ephemeral.Bytes()), peerPublicKey)
// 	sha256Self(s2.Bytes())
// 	s1, err := self.SharedSecret(peerPublicKey)
// 	if err != nil {
// 		ephemeral.Destroy()
// 		s1.Destroy()
// 		return nil, nil, err
// 	}
// 	sha256HMACSelf(s1.Bytes(), s2.Bytes())
// 	s1.Destroy()
// 	return ephemeralPublicKey, s2, nil
// }

// func (self *Curve25519) SharedSecret2DHReceive(peerPublicKey, ephemeralPublicKey *[32]byte) (secret memprotect.Cell, err error) {
// 	s1, err := self.SharedSecret(peerPublicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	s2, err := self.SharedSecret(ephemeralPublicKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	sha256HMACSelf(s1.Bytes(), s2.Bytes())
// 	s1.Destroy()
// 	return s2, nil
// }

func (self *Curve25519) Seal() {
	self.element.Seal()
}

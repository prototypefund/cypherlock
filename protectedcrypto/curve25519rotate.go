package protectedcrypto

import (
	"crypto/subtle"
	"io"

	"golang.org/x/crypto/curve25519"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"
)

type Curve25519Rotating struct {
	engine            memprotect.Engine
	exportEngine      memprotect.Engine
	element           memprotect.Element
	ttl               int64
	currentPublicKey  *[32]byte
	previousPublicKey *[32]byte
	expireTime        int64
}

func NewCurve25519Rotating(timeToExpire int64, engine memprotect.Engine, exportEngine ...memprotect.Engine) (*Curve25519Rotating, error) {
	r := &Curve25519Rotating{
		engine:       engine,
		exportEngine: engine,
		ttl:          timeToExpire,
	}
	if len(exportEngine) > 0 {
		r.exportEngine = exportEngine[0]
	}
	if err := r.generate(); err != nil {
		return nil, err
	}
	return r, nil
}

func (self *Curve25519Rotating) generate() error {
	self.element = self.engine.Element(96)
	if _, err := self.Rotate(); err != nil {
		self.element.Destroy()
		return err
	}
	return nil
}

func (self *Curve25519Rotating) Rotate() (PublicKey *[32]byte, err error) {
	self.expireTime = timeNow() + self.ttl // Calculate time boundary
	self.element.Melt()
	privateKeys, err := self.element.Bytes()
	if err != nil {
		return nil, err
	}
	defer self.Seal()
	_, err = io.ReadFull(RandomSource, privateKeys[0:32])
	if err != nil {
		return nil, err
	}
	subtle.ConstantTimeCopy(1, privateKeys[64:96], privateKeys[32:64]) // Move current private key to old. Order is New,Current,Previous
	subtle.ConstantTimeCopy(1, privateKeys[32:64], privateKeys[0:32])  // Move new to current.
	self.previousPublicKey = self.currentPublicKey                     // Move public keys
	self.currentPublicKey = new([32]byte)
	curve25519.ScalarBaseMult(self.currentPublicKey, unsafeconvert.To32(privateKeys[32:64])) // Calculate new public key.
	return self.currentPublicKey, nil
}

func (self *Curve25519Rotating) PublicKey() (PublicKey *[32]byte) {
	return self.currentPublicKey
}

func (self *Curve25519Rotating) SharedSecret(myPublicKey, peerPublicKey *[32]byte) (myPublicKeyCopy *[32]byte, secret memprotect.Cell, err error) {
	var currentKey bool
	var key []byte
	if subtle.ConstantTimeCompare(myPublicKey[:], self.currentPublicKey[:]) == 1 {
		currentKey = true
	} else if self.expireTime < timeNow() || subtle.ConstantTimeCompare(myPublicKey[:], self.previousPublicKey[:]) != 1 {
		return nil, nil, memprotect.ErrKeyNotFound
	}
	secret = self.exportEngine.Cell(32)
	privateKeys, err := self.element.Bytes()
	if err != nil {
		secret.Destroy()
		return nil, nil, err
	}
	defer self.Seal()
	if currentKey {
		key = privateKeys[32:64]
	} else {
		key = privateKeys[64:96]
	}
	curve25519.ScalarMult(unsafeconvert.To32(secret.Bytes()), unsafeconvert.To32(key), peerPublicKey)
	sha256Self(secret.Bytes())
	return myPublicKey, secret, nil
}

func (self *Curve25519Rotating) Seal() {
	self.element.Seal()
}

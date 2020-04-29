package protectedcrypto

import (
	"io"

	"golang.org/x/crypto/curve25519"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"
)

type Curve25519Ephemeral struct {
	exportEngine memprotect.Engine
}

func NewCurve25519Ephemeral(exportEngine memprotect.Engine) *Curve25519Ephemeral {
	return &Curve25519Ephemeral{
		exportEngine: exportEngine,
	}
}

func (self *Curve25519Ephemeral) SharedSecret(myPublicKey, peerPublicKey *[32]byte) (ephemeralPublicKey *[32]byte, secret memprotect.Cell, err error) {
	ephemeralPublicKey = new([32]byte)
	secret = self.exportEngine.Cell(32)
	ephemeralPrivKey := self.exportEngine.Cell(32)
	defer ephemeralPrivKey.Destroy()
	_, err = io.ReadFull(RandomSource, ephemeralPrivKey.Bytes())
	if err != nil {
		secret.Destroy()
		return nil, nil, err
	}
	curve25519.ScalarBaseMult(ephemeralPublicKey, unsafeconvert.To32(ephemeralPrivKey.Bytes()))
	curve25519.ScalarMult(unsafeconvert.To32(secret.Bytes()), unsafeconvert.To32(ephemeralPrivKey.Bytes()), peerPublicKey)
	sha256Self(secret.Bytes())
	return ephemeralPublicKey, secret, nil
}

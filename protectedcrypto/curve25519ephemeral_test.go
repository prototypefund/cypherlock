package protectedcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

func TestECurve25519Ephemeral(t *testing.T) {
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key := NewCurve25519(engine)
	err := key.Generate()
	if err != nil {
		t.Fatalf("Generate: %s", err)
	}
	eph := NewCurve25519Ephemeral(engine)
	pub, secret, err := eph.SharedSecret(nil, key.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret: %s", err)
	}
	_, secret2, _ := key.SharedSecret(nil, pub)
	if !bytes.Equal(secret.Bytes(), secret2.Bytes()) {
		t.Error("SharedSecret secrets differ")
	}
}

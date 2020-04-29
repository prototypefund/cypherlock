package protectedcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

func TestECurve25519Key(t *testing.T) {
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key := NewCurve25519(engine)
	err := key.Generate()
	if err != nil {
		t.Fatalf("Generate: %s", err)
	}
	key2 := NewCurve25519(engine)
	key2.Generate()
	_, secret, err := key.SharedSecret(nil, key2.PublicKey())
	if err != nil {
		t.Errorf("SharedSecret: %s", err)
	}
	_, secret2, _ := key2.SharedSecret(nil, key.PublicKey())
	if !bytes.Equal(secret.Bytes(), secret2.Bytes()) {
		t.Error("SharedSecret secrets differ")
	}

	// ephemeral, secret3, err := key.SharedSecret2DH(key2.PublicKey())
	// if err != nil {
	// 	t.Errorf("SharedSecret2DH: %s", err)
	// }
	// secret4, err := key2.SharedSecret2DHReceive(key.PublicKey(), ephemeral)
	// if err != nil {
	// 	t.Errorf("SharedSecret2DHReceive: %s", err)
	// }
	// if !bytes.Equal(secret3.Bytes(), secret4.Bytes()) {
	// 	t.Error("SharedSecret2DH secrets differ")
	// }
}

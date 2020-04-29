package protectedcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

func TestCurve25519Ratchet(t *testing.T) {
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()

	myKey := NewCurve25519(engine)
	err := myKey.Generate()
	if err != nil {
		t.Fatalf("myKey.Generate: %s", err)
	}

	timeNow = func() int64 { return 251 }

	key := NewCurve25519Ratchet(engine)
	if err := key.Generate(1, 100); err != nil {
		t.Fatalf("Generate: %s", err)
	}
	d, err := key.Advance()
	if err != nil {
		t.Errorf("Advance: %s", err)
	}
	if d != 50 {
		t.Errorf("Advance wait time calculation wrong: %d", d)
	}
	gen, err := key.Generator()
	if err != nil {
		t.Errorf("Generator: %s", err)
	}
	keys := gen.PublicKeys(10)

	currentKey := keys.SelectKey(timeNow())
	_, secret, err := key.SharedSecret(&currentKey.PublicKey, myKey.PublicKey())
	if err != nil {
		t.Errorf("SharedSecret: %s", err)
	}
	_, secret2, err := myKey.SharedSecret(nil, &currentKey.PublicKey)
	if err != nil {
		t.Errorf("myKey.SharedSecret: %s", err)
	}
	if !bytes.Equal(secret.Bytes(), secret2.Bytes()) {
		t.Error("Shared secret no match")
	}

	timeNow = func() int64 { return 600 }
	currentKey = keys.SelectKey(timeNow())
	_, secret, err = key.SharedSecret(&currentKey.PublicKey, myKey.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret: %s", err)
	}
	_, secret2, err = myKey.SharedSecret(nil, &currentKey.PublicKey)
	if err != nil {
		t.Errorf("myKey.SharedSecret: %s", err)
	}
	if !bytes.Equal(secret.Bytes(), secret2.Bytes()) {
		t.Error("Shared secret no match 2")
	}
}

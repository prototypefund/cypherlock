package protectedcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

func TestECurve25519Rotate(t *testing.T) {
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key := NewCurve25519(engine)
	err := key.Generate()
	if err != nil {
		t.Fatalf("Generate: %s", err)
	}
	timeNow = func() int64 { return 10 }
	rot, err := NewCurve25519Rotating(10, engine)
	if err != nil {
		t.Fatalf("NewCurve25519Rotating: %s", err)
	}
	prevKey := rot.PublicKey()
	_, secret, err := rot.SharedSecret(prevKey, key.PublicKey())
	if err != nil {
		t.Fatalf("SharedSecret: %s", err)
	}
	_, secret2, _ := key.SharedSecret(nil, prevKey)
	if !bytes.Equal(secret.Bytes(), secret2.Bytes()) {
		t.Error("SharedSecret secrets differ")
	}
	secret2.Destroy()
	timeNow = func() int64 { return 15 }
	_, err = rot.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %s", err)
	}
	newKey := rot.PublicKey()
	if bytes.Equal(prevKey[:], newKey[:]) {
		t.Error("Public keys not rotated")
	}
	_, secret3, _ := rot.SharedSecret(prevKey, key.PublicKey())
	if !bytes.Equal(secret.Bytes(), secret3.Bytes()) {
		t.Error("Previous key not accessible")
	}
	secret3.Destroy()
	timeNow = func() int64 { return 26 }
	_, _, err = rot.SharedSecret(prevKey, key.PublicKey())
	if err == nil {
		t.Error("Time limit not enforced")
	}
	_, secret4, _ := rot.SharedSecret(rot.PublicKey(), key.PublicKey())
	_, secret5, _ := key.SharedSecret(nil, rot.PublicKey())
	if !bytes.Equal(secret4.Bytes(), secret5.Bytes()) {
		t.Error("SharedSecret secrets differ. Rotation error")
	}
	secret4.Destroy()
	if bytes.Equal(secret.Bytes(), secret5.Bytes()) {
		t.Error("SharedSecret didn't change")
	}
	secret.Destroy()
	secret5.Destroy()
}

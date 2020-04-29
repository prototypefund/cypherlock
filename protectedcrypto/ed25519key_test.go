package protectedcrypto

import (
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"

	"golang.org/x/crypto/ed25519"
)

func TestED25519Key(t *testing.T) {
	m := []byte("test message")
	// engine := new(memprotect.MemGuard)
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key := NewED25519(engine)
	err := key.Generate()
	if err != nil {
		t.Fatalf("Generate: %s", err)
	}
	pubKey, err := key.PublicKey()
	if err != nil {
		t.Errorf("PublicKey: %s", err)
	}
	sig, err := key.Sign(m)
	if err != nil {
		t.Errorf("Sign: %s", err)
	}
	ok := ed25519.Verify(pubKey, m, sig)
	if !ok {
		t.Error("Verify failed")
	}
}

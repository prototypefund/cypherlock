package memprotect

import (
	"bytes"
	"io"
	"testing"
)

func TestUnprotected(t *testing.T) {
	key := new(Unprotected).Cell(32)
	if _, err := io.ReadFull(RandomSource, key.Bytes()); err != nil {
		t.Fatalf("ReadFull: %s", err)
	}

	engine := new(Unprotected)
	engine.Init(key)
	defer engine.Finish()
	secret := engine.Element(32)
	secret.Melt()
	err := secret.WithBytes(func(out []byte) error {
		if _, err := io.ReadFull(RandomSource, out); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes 2: %s", err)
	}
	encryptedSecret, err := engine.EncryptElement(secret)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	newSecret, err := engine.DecryptElement(encryptedSecret)
	if err != nil {
		t.Fatalf("DecryptElement: %s", err)
	}
	sB, _ := secret.Bytes()
	nsB, _ := newSecret.Bytes()
	if !bytes.Equal(sB, nsB) {
		t.Error("Decryption failure")
	}
}

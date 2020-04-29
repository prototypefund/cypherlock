package symmetriccrypto

import (
	"bytes"
	"testing"
)

func TestEncryption(t *testing.T) {
	msg := []byte("this is a random message")
	key := []byte("12345678901234567890123456789012")
	c, err := Encrypt(key, msg, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %s", err)
	}
	d, err := Decrypt(key, c, nil)
	if err != nil {
		t.Fatalf("Decrypt failed: %s", err)
	}
	if !bytes.Equal(msg, d) {
		t.Error("Messages dont match")
	}
	eOut := make([]byte, 0, EncryptedSize(msg))
	c, err = Encrypt(key, msg, eOut)
	if err != nil {
		t.Fatalf("Encrypt failed, out: %s", err)
	}
	out := make([]byte, 0, DecryptedSize(c))
	d, err = Decrypt(key, c, out)
	if err != nil {
		t.Fatalf("Decrypt failed, out: %s", err)
	}
	if !bytes.Equal(msg, d) {
		t.Error("Messages dont match, out")
	}
}

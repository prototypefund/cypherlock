package hybridcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/protectedcrypto"
)

func TestCalculateEncrypt(t *testing.T) {
	msg := []byte("This is a secret message that is encrypted")
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key1 := protectedcrypto.NewCurve25519(engine)
	if err := key1.Generate(); err != nil {
		t.Fatalf("Generate key1: %s", err)
	}
	key2 := protectedcrypto.NewCurve25519(engine)
	if err := key2.Generate(); err != nil {
		t.Fatalf("Generate key2: %s", err)
	}
	key3 := protectedcrypto.NewCurve25519Ephemeral(engine)
	key4 := protectedcrypto.NewCurve25519Ephemeral(engine)

	tsc := &SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(engine),
		MessageType:        512,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []KeyContainer{
			KeyContainer{
				SecretGenerator: key1,
				MyPublicKey:     key1.PublicKey(),
				PeerPublicKey:   key2.PublicKey(),
			},
			KeyContainer{
				SecretGenerator: key3,
				MyPublicKey:     nil,
				PeerPublicKey:   key2.PublicKey(),
			},
			KeyContainer{
				SecretGenerator: key4,
				MyPublicKey:     nil,
				PeerPublicKey:   key1.PublicKey(),
			},
		},
	}
	encrypted, err := tsc.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}

	tsc2 := &SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(engine),
		DeterministicNonce: nil,
		Keys: []KeyContainer{
			KeyContainer{
				SecretGenerator: key2,
			},
			KeyContainer{
				SecretGenerator: key2,
			},
			KeyContainer{
				SecretGenerator: key1,
			},
		},
	}
	out, err := tsc2.Decrypt(encrypted, nil)
	if err != nil {
		t.Errorf("Decrypt: %s", err)
	}
	if !bytes.Equal(out, msg) {
		t.Error("Message corrupt")
	}
	if tsc.MessageType != tsc2.MessageType {
		t.Error("Message type not parsed")
	}
}

func TestCalculateEncryptBuffer(t *testing.T) {
	msg := []byte("This is a secret message that is encrypted")
	engine := new(memprotect.Unprotected)
	engine.Init(new(memprotect.Unprotected).Cell(32))
	defer engine.Finish()
	key1 := protectedcrypto.NewCurve25519(engine)
	if err := key1.Generate(); err != nil {
		t.Fatalf("Generate key1: %s", err)
	}
	key2 := protectedcrypto.NewCurve25519(engine)
	if err := key2.Generate(); err != nil {
		t.Fatalf("Generate key2: %s", err)
	}
	key3 := protectedcrypto.NewCurve25519Ephemeral(engine)
	key4 := protectedcrypto.NewCurve25519Ephemeral(engine)

	tsc := &SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(engine),
		MessageType:        400,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []KeyContainer{
			KeyContainer{
				SecretGenerator: key1,
				MyPublicKey:     key1.PublicKey(),
				PeerPublicKey:   key2.PublicKey(),
			},
			KeyContainer{
				SecretGenerator: key3,
				MyPublicKey:     nil,
				PeerPublicKey:   key2.PublicKey(),
			},
			KeyContainer{
				SecretGenerator: key4,
				MyPublicKey:     nil,
				PeerPublicKey:   key1.PublicKey(),
			},
		},
	}
	encrypted, err := tsc.Encrypt(msg, make([]byte, 0, tsc.EncryptedSize(msg)))
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}

	tsc2 := &SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(engine),
		MessageType:        400,
		DeterministicNonce: nil,
		Keys: []KeyContainer{
			KeyContainer{
				SecretGenerator: key2,
			},
			KeyContainer{
				SecretGenerator: key2,
			},
			KeyContainer{
				SecretGenerator: key1,
			},
		},
	}
	out, err := tsc2.Decrypt(encrypted, make([]byte, 0, tsc2.DecryptedSize(encrypted)))
	if err != nil {
		t.Errorf("Decrypt: %s", err)
	}
	if !bytes.Equal(out, msg) {
		t.Error("Message corrupt")
	}
	if tsc.MessageType != tsc2.MessageType {
		t.Error("Message type not parsed")
	}
}

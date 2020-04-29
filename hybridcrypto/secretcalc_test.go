package hybridcrypto

import (
	"bytes"
	"testing"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/protectedcrypto"
)

func TestCalculateSecret(t *testing.T) {
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
	defer tsc.DestroySecret()
	secret1, err := tsc.Send()
	if err != nil {
		t.Fatalf("Send: %s", err)
	}

	msg := make([]byte, 10, tsc.HeaderSize()+20)
	headers := tsc.Headers(msg[10:])

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
	defer tsc2.DestroySecret()

	if err := tsc2.ParseHeaders(headers); err != nil {
		t.Fatalf("ParseHeaders: %s", err)
	}
	secret2, err := tsc2.Receive()
	if err != nil {
		t.Fatalf("Receive: %s", err)
	}
	if !bytes.Equal(secret1.Bytes(), secret2.Bytes()) {
		t.Error("Secret calculation failed")
	}
}

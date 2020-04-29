package hybridcrypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

var (
	ErrHeaderSize  = errors.New("hybridcrypto: Headers too short")
	ErrSize        = errors.New("hybridcrypto: Input too short to be plausible")
	ErrMessageType = errors.New("hybridcrypto: Unexpected message type")
)

var protocolConstant = []byte("Cypherlock Prototype Fund Edition 2019")
var RandomSource = rand.Reader
var zeroNonce = new([32]byte)

// KeyContainer describes a keypair for ec25519DH.
type KeyContainer struct {
	SecretGenerator SecretGenerator // Key management
	MyPublicKey     *[32]byte       // My own key. Independent of direction.
	PeerPublicKey   *[32]byte       // The peer's key. Independent of direction.
}

func (self KeyContainer) String() string {
	return fmt.Sprintf("\nMy: %x\nPeer: %x", self.MyPublicKey, self.PeerPublicKey)
}

type SecretGenerator interface {
	SharedSecret(myPublicKey *[32]byte, peerPublicKey *[32]byte) (myPublicKeyCopy *[32]byte, secret memprotect.Cell, err error)
}

// SecretCombiner combines two secrets into one.
type SecretCombiner interface {
	Combine(secret1, secret2 []byte) (combinedSecret memprotect.Cell)
}

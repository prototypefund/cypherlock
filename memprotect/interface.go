// package memprotect implements memory protected cryptography over global secrets.
// Split into two packages. One for keys, one for memory.
//
// ToDo: Implement ratchet keys.
//
// ToDo: Encrypt/Decrypt: Move into Engine. Do keysetting outside of main interface to accomodate future HSMs
package memprotect

import (
	"crypto/rand"
	"errors"

	"assuredrelease.com/cypherlock-pe/types"

	"golang.org/x/crypto/ed25519"
)

// RandomSource is the packet-global source for random data.
var RandomSource = rand.Reader

var safeExit func(c int) = nil
var safePanic func(v interface{}) = nil

var (
	ErrSize            = errors.New("protectedcrypto: Wrong element size for operation")
	ErrDecrypt         = errors.New("protectedcrypto: Could not decrypt element")
	ErrRatchedNotFound = errors.New("protectedcrypto: Ratchet key not found")
	ErrKeyNotFound     = errors.New("protectedcrypto: Key not found")
)

// Element implements secure memory.
type Element interface {
	Size() int                                   // Return the size (in bytes)
	Bytes() ([]byte, error)                      // Return the buffer of the element. Requires sealing after use.
	Melt() error                                 // Make element modifyable. It will become readonly on Sealing.
	WithBytes(func(unsealed []byte) error) error // Execute a function on unsealed data. Will automatically seal after use.
	Destroy() error                              // Destroy the element. NEVER use afterwards. Safe to use on non-allocated Element.
	Seal()                                       // Reseal the element.
	Set(src []byte) error                        // Set the data of the Element. Src is wiped after use.
	Encrypt(key Cell) ([]byte, error)            // Encrypt this element with a key held in another element.
}

// Cell is a short-lived protected memory element.
type Cell interface {
	Load(d []byte)
	Bytes() []byte
	Destroy() // Must be safe to call even if cell has not been allocated.
}

// Engine implements a protected memory engine.
type Engine interface {
	Init(key Cell)            // Must be called at start of program.
	Finish()                  // MUST be called at end of program.
	Exit(c int)               // Call instead of os.Exit in main program.
	Panic(v interface{})      // Call instead of Panic in main program.
	Element(size int) Element // Create a new protected element.
	Cell(size int) Cell
	DecryptElement(encryptedElement []byte) (Element, error) // Decrypt and set element.
	EncryptElement(Element) ([]byte, error)                  // Encrypt an element.
}

// ED25519Key represents an ED25519 capable protected element.
type ED25519Key interface {
	Generate() error                    // Generate new key.
	SetSecure(privateKey Element) error // privkey must be a [ed25519.PrivateKeySize(64)]byte Element.
	PublicKey() (ed25519.PublicKey, error)
	PrivateKey() Element
	Sign(message []byte) ([]byte, error)
	Seal()
}

// Curve25519Key represents a Curve25519 capable protected element.
type Curve25519Key interface {
	Generate() error                    // Generate new key.
	SetSecure(privateKey Element) error // privkey must be a [32]byte Element.
	PublicKey() *[32]byte
	PrivateKey() Element
	// Create a shared secret. If myPublicKey is not nil it will be verified.
	SharedSecret(myPublicKey, peerPublicKey *[32]byte) (myPublicKeyCopy *[32]byte, secret Cell, err error)
	Seal() // Seal the key after use.
	// Moved into combining.
	// SharedSecret2DH(peerPublicKey *[32]byte) (ephemeralPublicKey *[32]byte, secret Cell, err error)
	// SharedSecret2DHReceive(peerPublicKey, ephemeralPublicKey *[32]byte) (secret Cell, err error)
}

// Curve25519Ephemeral represents an ephemeral sender using curve25519.
type Curve25519Ephemeral interface {
	// Create a shared secret. myPublicKey has no meaning and can be nil.
	SharedSecret(myPublicKey, peerPublicKey *[32]byte) (ephemeralPublicKey *[32]byte, secret Cell, err error)
}

// Curve25519Rotating is a rotation (in process) short term key.
type Curve25519Rotating interface {
	Rotate() (PublicKey *[32]byte, err error) // Rotate key.
	PublicKey() (PublicKey *[32]byte)
	SharedSecret(myPublicKey, peerPublicKey *[32]byte) (myPublicKeyCopy *[32]byte, secret Cell, err error) // Create a shared secret.
	Seal()
}

// Curve25519RatchetGenerator is a key generator for a Curve25519Ratchet.
type Curve25519RatchetGenerator interface {
	PublicKeys(count int) *types.RatchetPublicKey
}

// Curve25519Ratchet represents a Curve25519-Ratchet capable protected element.
type Curve25519Ratchet interface {
	// Ratchets have: StartTime, RatchetTime, PrivKey, SecretRatchet
	Generate(startTime, ratchetTime int64) error
	SetSecure(privateKey Element) error
	PrivateKey() Element
	Advance() (int64, error)                                                                                         // Try to advance the ratchet. Returns number of seconds when Advance() should be called again.
	Generator() (Curve25519RatchetGenerator, error)                                                                  // Return a Generator for public key precalculation.
	SharedSecret(ratchetKey *[32]byte, peerPublicKey *[32]byte) (ratchetPublicKey *[32]byte, secret Cell, err error) // Create a shared secret. Will test the relevant keys. (previous, if not more then RatchetTime/10 old, current)
	Seal()                                                                                                           // Seal the key after use.
}

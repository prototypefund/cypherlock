// Package hybridcrypto implements hybrid cryptography methods.
package hybridcrypto

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

// SecretCalculator calculates the symmetric message key from a set of assymetric keypairs.
type SecretCalculator struct {
	Combiner           SecretCombiner // May not be nil.
	MessageType        uint16
	Nonce              *[32]byte       // The message nonce. Must be set for receiving, can be nil (and will be generated) for receiving.
	DeterministicNonce *[32]byte       // Deterministic nonce. If set it will be included in the calculation, otherwise it is ignored.
	Keys               []KeyContainer  // The keys to calculate from.
	Secret             memprotect.Cell // Symmetric secret. Set by calculation.
	isReceiver         bool            // Determines order of public keys
	isCalculated       bool            // Have public keys been generated?
}

func (self *SecretCalculator) initStruct() error {
	if self == nil {
		panic("hybridcrypto: SecretCalculator is nil")
	}
	if self.Combiner == nil {
		panic("hybridcrypto: Combiner not set")
	}
	if len(self.Keys) < 1 {
		panic("hybridcrypto: No keys set")
	}
	if self.Nonce == nil {
		if self.isReceiver {
			panic("hybridcrypto: Nonce not set")
		}
		self.Nonce = new([32]byte)
		if _, err := io.ReadFull(RandomSource, self.Nonce[:]); err != nil {
			return err
		}
	}
	return nil
}

func (self *SecretCalculator) calculateSecret() (err error) {
	if err := self.initStruct(); err != nil {
		return err
	}
	myPublicKey, tsecret, err := self.Keys[0].SecretGenerator.SharedSecret(self.Keys[0].MyPublicKey, self.Keys[0].PeerPublicKey)
	if err != nil {
		return err
	}
	self.Keys[0].MyPublicKey = myPublicKey
	secretState := self.Combiner.Combine(protocolConstant, tsecret.Bytes())
	tsecret.Destroy()
	for i := 1; i < len(self.Keys); i++ {
		myPublicKey, tsecret, err := self.Keys[i].SecretGenerator.SharedSecret(self.Keys[i].MyPublicKey, self.Keys[i].PeerPublicKey)
		if err != nil {
			return err
		}
		self.Keys[i].MyPublicKey = myPublicKey
		secretStateT := self.Combiner.Combine(secretState.Bytes(), tsecret.Bytes())
		tsecret.Destroy()
		secretState.Destroy()
		secretState = secretStateT
	}
	secretStateT := self.Combiner.Combine(secretState.Bytes(), self.calculateNonce())
	secretState.Destroy()
	self.isCalculated = true
	self.Secret = secretStateT
	return nil
}

func swapKeys(myPublicKey, peerPublicKey *[32]byte, isReceiver bool) (senderPublicKey, receiverPublicKey *[32]byte) {
	if isReceiver {
		return peerPublicKey, myPublicKey
	}
	return myPublicKey, peerPublicKey
}

func (self *SecretCalculator) calculateNonce() []byte {
	var mtt [2]byte
	binary.BigEndian.PutUint16(mtt[:], self.MessageType)
	h := sha256.New()
	h.Write(mtt[:])
	h.Write(self.Nonce[:])
	for _, kp := range self.Keys {
		a, b := swapKeys(kp.MyPublicKey, kp.PeerPublicKey, self.isReceiver)
		h.Write(a[:])
		h.Write(b[:])
	}
	if self.DeterministicNonce != nil {
		h.Write(self.DeterministicNonce[:])
	}
	return h.Sum(nil)
}

// Send returns the symmetric key used for sending.
func (self *SecretCalculator) Send() (secret memprotect.Cell, err error) {
	self.isReceiver = false
	err = self.calculateSecret()
	return self.Secret, err
}

// HeaderSize returns the size of the headers for the message.
func (self *SecretCalculator) HeaderSize() int {
	// Nonce, per keypair two public keys at 32 byte each.
	return 32 + len(self.Keys)*64
}

// Headers returns the headers of a message. It must be called after Send or it will panic.
// msg may be a byteslice of at least HeaderSize capacity to be written into. If msg is nil, a new
// byteslice will be created.
func (self *SecretCalculator) Headers(msg []byte) []byte {
	var header []byte
	if !self.isCalculated {
		panic("hybridcrypto: Headers() called before Send()")
	}
	if msg != nil {
		if cap(msg) < self.HeaderSize() {
			panic("hybridcrypto: Given header slice too short")
		}
		header = msg[0:0]
	} else {
		header = make([]byte, 0, self.HeaderSize())
	}
	header = append(header, self.Nonce[:]...)
	for _, kp := range self.Keys {
		a, b := swapKeys(kp.MyPublicKey, kp.PeerPublicKey, self.isReceiver)
		header = append(header, a[:]...)
		header = append(header, b[:]...)
	}
	return header
}

// ParseHeaders parses message headers to set nonces.
func (self *SecretCalculator) ParseHeaders(headers []byte) error {
	if len(self.Keys) <= 0 {
		panic("hybridcrypto: ParseHeaders without configured keys.")
	}
	if len(headers) < self.HeaderSize() {
		return ErrHeaderSize
	}
	self.Nonce = new([32]byte)
	copy(self.Nonce[:], headers[0:32])
	for i := 0; i < len(self.Keys); i++ {
		a, b := new([32]byte), new([32]byte)
		copy(a[:], headers[32+i*64:32+32+i*64])
		copy(b[:], headers[32+32+i*64:32+32+32+i*64])
		self.Keys[i].MyPublicKey, self.Keys[i].PeerPublicKey = swapKeys(a, b, true)
	}
	return nil
}

// Receive returns the symmetric key used for receiving.
func (self *SecretCalculator) Receive() (secret memprotect.Cell, err error) {
	self.isReceiver = true
	err = self.calculateSecret()
	return self.Secret, err
}

func (self *SecretCalculator) DestroySecret() {
	if self.Secret != nil {
		self.Secret.Destroy()
		self.Secret = nil
	}
}

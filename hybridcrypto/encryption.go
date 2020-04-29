package hybridcrypto

import (
	"encoding/binary"

	"assuredrelease.com/cypherlock-pe/symmetriccrypto"
)

// EncryptionSize returns the number of bytes require to write the encryption output of msg.
// The first 2 bytes of an encrypted message are reserved for the message tag.
func (self *SecretCalculator) EncryptedSize(msg []byte) int {
	return self.EncryptedSizeLength(len(msg))
}

func (self *SecretCalculator) EncryptedSizeLength(l int) int {
	return self.HeaderSize() + symmetriccrypto.EncryptedSizeLength(l) + 2
}

func (self *SecretCalculator) DecryptedSize(msg []byte) int {
	return self.DecryptedSizeLength(len(msg))
}

func (self *SecretCalculator) DecryptedSizeLength(l int) int {
	return symmetriccrypto.DecryptedSizeLength(l - self.HeaderSize())
}

// Encrypt message. If out is not nil, it is used for output. Otherwise
// a new slice is allocated from insecure memory.
func (self *SecretCalculator) Encrypt(msg, out []byte) ([]byte, error) {
	var outT []byte
	msgL := self.EncryptedSize(msg)
	if out == nil {
		outT = make([]byte, msgL)
	} else {
		if cap(out) < msgL {
			panic("hybridcrypto: Encrypt output buffer too small")
		}
		outT = out[0:msgL]
	}
	if !self.isCalculated {
		if _, err := self.Send(); err != nil {
			return nil, err
		}
	}
	defer self.Secret.Destroy()
	// Write Headers
	self.Headers(outT[2:])
	// Encrypt into self
	_, err := symmetriccrypto.Encrypt(self.Secret.Bytes(), msg, outT[2+self.HeaderSize():])
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(outT[0:2], self.MessageType)
	return outT[0:msgL], nil
}

// Decrypt a message. If out is not nil, it is used for output. Otherwise
// a new slice is allocated from insecure memory.
func (self *SecretCalculator) Decrypt(msg, out []byte) ([]byte, error) {
	var outT []byte
	msgL := self.DecryptedSize(msg)
	if msgL < 1 {
		return nil, ErrSize
	}
	if out == nil {
		outT = make([]byte, msgL)
	} else {
		if cap(out) < msgL {
			panic("hybridcrypto: Decrypt output buffer too small")
		}
		outT = out[0:msgL]
	}
	mtt := binary.BigEndian.Uint16(msg[0:2])
	if self.MessageType != 0 && self.MessageType != mtt {
		return nil, ErrMessageType
	}
	self.MessageType = mtt
	if err := self.ParseHeaders(msg[2:]); err != nil {
		return nil, err
	}
	if _, err := self.Receive(); err != nil {
		return nil, err
	}
	defer self.Secret.Destroy()
	return symmetriccrypto.Decrypt(self.Secret.Bytes(), msg[2+self.HeaderSize():], outT)
}

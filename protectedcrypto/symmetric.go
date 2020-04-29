package protectedcrypto

import (
	"io"

	"assuredrelease.com/cypherlock-pe/memprotect"
)

// SymmetricKey is a memory protected symmetric key.
type SymmetricKey struct {
	element memprotect.Element
}

func NewSymmetricKey(engine memprotect.Engine) (*SymmetricKey, error) {
	key := new(SymmetricKey)
	key.element = engine.Element(32)
	key.element.Melt()
	b, err := key.element.Bytes()
	if err != nil {
		key.element.Destroy()
		key.element = nil
		return nil, err
	}
	_, err = io.ReadFull(RandomSource, b)
	if err != nil {
		key.element.Destroy()
		key.element = nil
		return nil, err
	}
	return key, nil
}

// Returns the byteslice containing the key. Requires calling Seal after use.
func (self *SymmetricKey) Bytes() ([]byte, error) {
	return self.element.Bytes()
}

func (self *SymmetricKey) Seal() {
	if self.element == nil {
		return
	}
	self.element.Seal()
}

func (self *SymmetricKey) Destroy() {
	if self.element == nil {
		return
	}
	self.element.Destroy()
	self.element = nil
}

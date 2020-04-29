package memprotect

import (
	"assuredrelease.com/cypherlock-pe/symmetriccrypto"
)

func EncryptElement(key Cell, e Element) ([]byte, error) {
	msg, err := e.Bytes()
	if err != nil {
		return nil, err
	}
	defer e.Seal()
	return symmetriccrypto.Encrypt(key.Bytes(), msg, nil)
}

func DecryptElement(key Cell, encryptedElement []byte, e Engine) (element Element, err error) {
	outE := e.Element(symmetriccrypto.DecryptedSize(encryptedElement))
	outE.Melt()
	outB, err := outE.Bytes()
	if err != nil {
		return nil, err
	}
	_, err = symmetriccrypto.Decrypt(key.Bytes(), encryptedElement, outB)
	if err != nil {
		outE.Destroy()
		return nil, err
	}
	outE.Seal()
	return outE, nil
}

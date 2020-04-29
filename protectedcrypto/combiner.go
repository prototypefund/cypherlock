package protectedcrypto

import "assuredrelease.com/cypherlock-pe/memprotect"

// // SecretCombiner combines two secrets into one.
// type SecretCombiner interface {
// 	Combine(secret1, secret2 Cell) (combinedSecret Cell)
// }

type SecretCombiner struct {
	exportEngine memprotect.Engine
}

func NewSecretCombiner(exportEngine memprotect.Engine) *SecretCombiner {
	return &SecretCombiner{
		exportEngine: exportEngine,
	}
}

// Combine two secrets.
func (self *SecretCombiner) Combine(secret1, secret2 []byte) (combinedSecret memprotect.Cell) {
	secretCombined := self.exportEngine.Cell(32)
	SHA256HMAC(secret1, secret2, secretCombined.Bytes())
	return secretCombined
}

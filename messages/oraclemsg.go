package messages

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"assuredrelease.com/cypherlock-pe/binencode"
	"assuredrelease.com/cypherlock-pe/hybridcrypto"
	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/protectedcrypto"
)

// - Encrypted to node short term encryption key (SK: ephemeral. RK: short term):
//   - Single Response Public Key
//   - Response public key.
//   - Encrypted to node long term encryption key: (SK: ephemeral, response public key. RK: Long Term)
// ---------------------------
//     - [0-3]Semaphore Values. If set, verify that semaphores are not set.
//     - [0-3]Semaphore Values with SetFrom/SetTo. If set, set semaphores.
//     - ValidFrom time. 0x00... to disable.
//     - ValidTo time. 0x00... to disable..
//     - Timelock public key. 0x00... to disable.
//     - Ephemeral Public key for timelock encryption. 0x00 to disable
//     - Encrypted (optional) to Timelock Key: (SK: ephemeral, response public key. RK: Timelock key)
//       - ShareMessage

var zero32bytes = [32]byte{}

const OracleMessageEncType = 0xf0
const OracleMsgTypeID = 1098
const OracleMsgContainerTypeID = 1080

// OracleMessage contains the data of an oracle message. Exported fields must be set.
type OracleMessage struct {
	OracleURL               []byte      // URL where the Oracle listens.
	LongTermOraclePublicKey [32]byte    // The long-term oracle public key.
	TimelockPublicKey       [32]byte    // Timelock key to use, ignore if all zeros.
	TestSemaphores          [3][32]byte // Test these for non-existence
	SetSemaphores           [3][32]byte // Set these
	ValidFrom               int64       // Decrypt only after
	ValidTo                 int64       // Decrypt only before

	ResponsePublicKey [32]byte // The public key to which to encrypt the response
	Share             []byte   // Share  to embed
	ShareThreshold    int32    // Reconstruction threshold
}

func (self *OracleMessage) marshal(out []byte) []byte {
	d, err := binencode.Encode(out, 2,
		binencode.SlicePointer(self.ResponsePublicKey[:]),
		binencode.SlicePointer(self.LongTermOraclePublicKey[:]),
		binencode.SlicePointer(self.TimelockPublicKey[:]),
		binencode.SlicePointer(self.TestSemaphores[0][:]),
		binencode.SlicePointer(self.TestSemaphores[1][:]),
		binencode.SlicePointer(self.TestSemaphores[2][:]),
		binencode.SlicePointer(self.SetSemaphores[0][:]),
		binencode.SlicePointer(self.SetSemaphores[1][:]),
		binencode.SlicePointer(self.SetSemaphores[2][:]),
		self.ValidFrom,
		self.ValidTo,
		&self.Share,
	)
	if err != nil {
		panic(err)
	}
	binencode.SetType(d, OracleMsgTypeID)
	return d
}

func (self *OracleMessage) unmarshal(d []byte) (r *OracleMessage, remainder []byte, err error) {
	if err := binencode.GetTypeExpect(d, OracleMsgTypeID); err != nil {
		return nil, nil, err
	}
	if self != nil {
		r = self
	} else {
		r = new(OracleMessage)
	}
	remainder, err = binencode.Decode(d, 2,
		binencode.SlicePointer(r.ResponsePublicKey[:]),
		binencode.SlicePointer(r.LongTermOraclePublicKey[:]),
		binencode.SlicePointer(r.TimelockPublicKey[:]),
		binencode.SlicePointer(r.TestSemaphores[0][:]),
		binencode.SlicePointer(r.TestSemaphores[1][:]),
		binencode.SlicePointer(r.TestSemaphores[2][:]),
		binencode.SlicePointer(r.SetSemaphores[0][:]),
		binencode.SlicePointer(r.SetSemaphores[1][:]),
		binencode.SlicePointer(r.SetSemaphores[2][:]),
		&r.ValidFrom,
		&r.ValidTo,
		&r.Share,
	)
	if err != nil {
		return nil, remainder, err
	}
	return r, remainder, nil
}

func (self *OracleMessage) encrypt(key *protectedcrypto.Curve25519, memEngine memprotect.Engine) ([]byte, error) {
	ephemeralGenerator := protectedcrypto.NewCurve25519Ephemeral(memEngine)
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(memEngine),
		MessageType:        OracleMessageEncType,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: ephemeralGenerator,
				MyPublicKey:     nil,
				PeerPublicKey:   &self.LongTermOraclePublicKey,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: key,
				MyPublicKey:     key.PublicKey(),
				PeerPublicKey:   &self.LongTermOraclePublicKey,
			},
		},
	}
	return tsc.Encrypt(self.marshal(nil), nil)
}

func (self *OracleMessage) decrypt(key *protectedcrypto.Curve25519, memEngine memprotect.Engine, msg []byte) (*OracleMessage, error) {
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(memEngine),
		MessageType:        OracleMessageEncType,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: key,
				MyPublicKey:     key.PublicKey(),
				PeerPublicKey:   nil,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: key,
				MyPublicKey:     key.PublicKey(),
				PeerPublicKey:   nil,
			},
		},
	}
	decrypted, err := tsc.Decrypt(msg, nil)
	if err != nil {
		return nil, err
	}
	ret, _, err := self.unmarshal(decrypted)
	if !bytes.Equal(ret.ResponsePublicKey[:], tsc.Keys[1].PeerPublicKey[:]) {
		return nil, ErrWrongResponseKey
	}
	return ret, err
}

func GenerateSemaphore(longTermOraclePublicKey, semaphore *[32]byte) *[32]byte {
	out := new([32]byte)
	protectedcrypto.SHA256HMAC(longTermOraclePublicKey[:], semaphore[:], out[:])
	return out
}

func (self *OracleMessage) setSemaphores() {
	for i := 0; i < len(self.TestSemaphores); i++ {
		if self.TestSemaphores[i] != zero32bytes {
			a := GenerateSemaphore(&self.LongTermOraclePublicKey, &self.TestSemaphores[i])
			copy(self.TestSemaphores[i][:], a[:])
		}
	}
	for i := 0; i < len(self.SetSemaphores); i++ {
		if self.SetSemaphores[i] != zero32bytes {
			a := GenerateSemaphore(&self.LongTermOraclePublicKey, &self.SetSemaphores[i])
			copy(self.SetSemaphores[i][:], a[:])
		}
	}
}

func (self *OracleMessage) deterministicNonce() *[32]byte {
	rt := new([32]byte)
	valids := make([]byte, 16)
	binary.BigEndian.PutUint64(valids[0:8], uint64(self.ValidFrom))
	binary.BigEndian.PutUint64(valids[8:], uint64(self.ValidTo))
	h := sha256.New()
	h.Write(valids)
	h.Write(self.LongTermOraclePublicKey[:])
	h.Write(self.TimelockPublicKey[:])
	for _, v := range self.TestSemaphores {
		h.Write(v[:])
	}
	for _, v := range self.SetSemaphores {
		h.Write(v[:])
	}
	r := h.Sum(nil)
	h.Reset()
	copy(rt[:], r)
	return rt
}

func (self *OracleMessage) decryptShare(longTermKey *protectedcrypto.Curve25519, timeLockKey *protectedcrypto.Curve25519Ratchet, memEngine memprotect.Engine) error {
	if self.TimelockPublicKey == zero32bytes { // Nothing to do, share is not further encrypted.
		return nil
	}
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(memEngine),
		MessageType:        OracleMessageEncType,
		Nonce:              nil,
		DeterministicNonce: self.deterministicNonce(),
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: timeLockKey,
				MyPublicKey:     nil,
				PeerPublicKey:   nil,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: longTermKey,
				MyPublicKey:     nil,
				PeerPublicKey:   nil,
			},
		},
	}
	decrypted, err := tsc.Decrypt(self.Share, nil)
	if err != nil {
		return err
	}
	self.Share = decrypted
	return nil
}

func (self *OracleMessage) encryptShare(memEngine memprotect.Engine) error {
	if self.TimelockPublicKey == zero32bytes { // Nothing to do, share is not further encrypted.
		return nil
	}
	ephemeralGenerator := protectedcrypto.NewCurve25519Ephemeral(memEngine)
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(memEngine),
		MessageType:        OracleMessageEncType,
		Nonce:              nil,
		DeterministicNonce: self.deterministicNonce(),
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: ephemeralGenerator,
				MyPublicKey:     nil,
				PeerPublicKey:   &self.TimelockPublicKey,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: ephemeralGenerator,
				MyPublicKey:     nil,
				PeerPublicKey:   &self.LongTermOraclePublicKey,
			},
		},
	}
	encrypted, err := tsc.Encrypt(self.Share, nil)
	if err != nil {
		return err
	}
	self.Share = encrypted
	return nil
}

// Encrypt an OracleMessage. It returns the encrypted container of the oracle message.
// It takes care of generating the correct semaphores from the given values.
// The container will be encrypted to containerKey.
func (self *OracleMessage) Encrypt(containerKey []byte, memEngine memprotect.Engine) (oracleContainer []byte, err error) {
	self.setSemaphores()
	container := new(OracleMessageContainer)
	container.OracleURL = self.OracleURL
	container.ValidFrom = self.ValidFrom
	container.ValidTo = self.ValidTo
	container.ShareThreshold = self.ShareThreshold
	container.OracleLongTermKey = self.LongTermOraclePublicKey[:]
	// Generate keys: ephemeral, response public key. Share key.
	responseKey := protectedcrypto.NewCurve25519(memEngine)
	if err = responseKey.Generate(); err != nil {
		return nil, err
	}
	if container.ResponsePrivateKey, err = responseKey.PrivateKey().Bytes(); err != nil {
		responseKey.PrivateKey().Seal()
		return nil, err
	}
	defer responseKey.PrivateKey().Seal()
	responseKeyPublic := responseKey.PublicKey()
	container.ResponsePublicKey = responseKeyPublic[:]
	copy(self.ResponsePublicKey[:], responseKeyPublic[:])
	// Share key.
	shareKey, err := protectedcrypto.NewSymmetricKey(memEngine)
	if err != nil {
		return nil, err
	}
	if container.ShareMsgKey, err = shareKey.Bytes(); err != nil {
		shareKey.Seal()
		return nil, err
	}

	defer shareKey.Seal()
	defer shareKey.Destroy()
	// Encrypt share message.

	shm := &ShareMsg{
		OracleKey: self.LongTermOraclePublicKey,
		Share:     self.Share,
	}
	shareBuffer := memEngine.Element(ShareMsgEncryptBufferSize)
	defer shareBuffer.Seal()
	defer shareBuffer.Destroy()
	shareBufferBytes, err := shareBuffer.Bytes()
	if err != nil {
		return nil, err
	}
	share, err := shm.Encrypt(container.ShareMsgKey, shareBufferBytes)
	if err != nil {
		return nil, err
	}
	self.Share = share
	if err = self.encryptShare(memEngine); err != nil {
		return nil, err
	}
	shareBuffer.Seal()
	shareBuffer.Destroy()
	if container.OracleMessage, err = self.encrypt(responseKey, memEngine); err != nil {
		return nil, err
	}
	// spew.Dump(container)
	return container.encrypt(containerKey)
}

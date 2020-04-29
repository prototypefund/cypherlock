package messages

import (
	"assuredrelease.com/cypherlock-pe/binencode"
	"assuredrelease.com/cypherlock-pe/hybridcrypto"
	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/protectedcrypto"
	"assuredrelease.com/cypherlock-pe/symmetriccrypto"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"
)

// OracleMessageContainer contains an oracle message.
type OracleMessageContainer struct {
	ValidFrom          int64  // Message is valid from
	ValidTo            int64  // Message is valid to
	ShareThreshold     int32  // Reconstruction threshold
	OracleLongTermKey  []byte // Long Term public key of oracle
	ResponsePublicKey  []byte // Public key of message
	ResponsePrivateKey []byte // The private key required to decrypt the response
	ShareMsgKey        []byte // The symmetric key to decrypt the share message
	OracleURL          []byte // The URL to which the message is sent
	OracleMessage      []byte // The encrypted oracle message
}

// Marshal a OracleMessageContainer into a byte slice. If out ==nil, a new output slice will be allocated.
func (self *OracleMessageContainer) marshal(out []byte) []byte {
	d, err := binencode.Encode(out, 2,
		&self.ValidFrom,
		&self.ValidTo,
		&self.OracleLongTermKey,
		&self.ShareThreshold,
		&self.ResponsePublicKey,
		&self.ResponsePrivateKey,
		&self.ShareMsgKey,
		&self.OracleURL,
		&self.OracleMessage,
	)
	if err != nil {
		panic(err)
	}
	binencode.SetType(d, OracleMsgContainerTypeID)
	return d
}

func (self *OracleMessageContainer) unmarshal(d []byte) (r *OracleMessageContainer, remainder []byte, err error) {
	if err := binencode.GetTypeExpect(d, OracleMsgContainerTypeID); err != nil {
		return nil, nil, err
	}
	if self != nil {
		r = self
	} else {
		r = new(OracleMessageContainer)
	}
	remainder, err = binencode.Decode(d, 2,
		&r.ValidFrom,
		&r.ValidTo,
		&r.OracleLongTermKey,
		&r.ShareThreshold,
		&r.ResponsePublicKey,
		&r.ResponsePrivateKey,
		&r.ShareMsgKey,
		&r.OracleURL,
		&r.OracleMessage,
	)
	if err != nil {
		return nil, remainder, err
	}
	return r, remainder, nil
}

func (self *OracleMessageContainer) encrypt(key []byte) ([]byte, error) {
	return symmetriccrypto.Encrypt(key, self.marshal(nil), nil)
}

// Decrypt an OracleMessageContainer.
func (self *OracleMessageContainer) Decrypt(key, d []byte) (*OracleMessageContainer, error) {
	dec, err := symmetriccrypto.Decrypt(key, d, nil)
	if err != nil {
		return nil, err
	}
	r, _, err := self.unmarshal(dec)
	return r, err
}

// ShortTermKeyFactory returns the short term key for an oracle url.
type ShortTermKeyFactory func(url string) (*[32]byte, error)

// OracleFuture contains the information required to send and receive an oraclemessage exchange.
type OracleFuture struct {
	Message                 []byte // The encrypted oracle message
	URL                     []byte // The URL to which the message is sent
	ShareThreshold          int32  // Reconstruction threshold
	ResponsePrivateKey      []byte // The private key required to decrypt the response
	ShareMsgKey             []byte // The symmetric key to decrypt the share message
	SingleResponsePrivatKey []byte // Single-use response decryption key.
	engine                  memprotect.Engine
}

const OracleMessageEnvelopeType = 1020
const OracleResponseMessageType = 1021

func (self *OracleFuture) Receive() ([]byte, error) {
	// tsc2 := &hybridcrypto.SecretCalculator{
	// 	Combiner:           protectedcrypto.NewSecretCombiner(self.exportEngine),
	// 	MessageType:        OracleResponseMessageType,
	// 	Nonce:              nil,
	// 	DeterministicNonce: nil,
	// 	Keys: []hybridcrypto.KeyContainer{
	// 		hybridcrypto.KeyContainer{
	// 			SecretGenerator: self.shortTermKey,
	// 			MyPublicKey:     self.shortTermKey.PublicKey(),
	// 			PeerPublicKey:   nil,
	// 		},
	// 		hybridcrypto.KeyContainer{
	// 			SecretGenerator: self.longTermKey,
	// 			MyPublicKey:     self.longTermKey.PublicKey(),
	// 			PeerPublicKey:   nil,
	// 		},
	// 		hybridcrypto.KeyContainer{
	// 			SecretGenerator: self.shortTermKey,
	// 			MyPublicKey:     self.shortTermKey.PublicKey(),
	// 			PeerPublicKey:   nil,
	// 		},
	// 	},
	// }
	// ToDo
	panic("Not implemented: self *OracleFuture) Receive()")
	return nil, nil
}

// Send an oracle message from a container.
func (self *OracleMessageContainer) Send(key, d []byte, stkf ShortTermKeyFactory, memEngine memprotect.Engine) (*OracleFuture, error) {
	container, err := self.Decrypt(key, d)
	if err != nil {
		return nil, err
	}
	if container.ValidFrom > 0 && container.ValidFrom > timeNow() {
		return nil, ErrTimePolicy
	}
	if container.ValidTo > 0 && container.ValidTo < timeNow() {
		return nil, ErrTimePolicy
	}
	ret := &OracleFuture{
		URL:                container.OracleURL,
		ShareThreshold:     container.ShareThreshold,
		ResponsePrivateKey: container.ResponsePrivateKey,
		ShareMsgKey:        container.ShareMsgKey,
		engine:             memEngine,
	}
	singleResponseKey := protectedcrypto.NewCurve25519(memEngine)
	if err = singleResponseKey.Generate(); err != nil {
		return nil, err
	}
	defer singleResponseKey.PrivateKey().Seal()
	pkt, err := singleResponseKey.PrivateKey().Bytes()
	if err != nil {
		return nil, err
	}
	ret.SingleResponsePrivatKey = make([]byte, len(pkt))
	copy(ret.SingleResponsePrivatKey, pkt)
	shortTermKey, err := stkf(string(ret.URL))
	if err != nil {
		return nil, err
	}
	// Encrypt with the collected keys
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(memEngine),
		MessageType:        OracleMessageEnvelopeType,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: singleResponseKey,
				MyPublicKey:     singleResponseKey.PublicKey(),
				PeerPublicKey:   shortTermKey,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: singleResponseKey,
				MyPublicKey:     singleResponseKey.PublicKey(),
				PeerPublicKey:   unsafeconvert.To32(self.OracleLongTermKey),
			},
		},
	}
	enc, err := tsc.Encrypt(self.OracleMessage, nil)
	if err != nil {
		return nil, err
	}
	ret.Message = enc
	return ret, nil
}

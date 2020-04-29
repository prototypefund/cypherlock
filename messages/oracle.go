package messages

import (
	"errors"
	"time"

	// "assuredrelease.com/cypherlock-pe/hybridcrypto"
	"assuredrelease.com/cypherlock-pe/hybridcrypto"
	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/protectedcrypto"
	"assuredrelease.com/cypherlock-pe/signalstore"
	"assuredrelease.com/cypherlock-pe/types"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"
)

var timeNow = func() int64 { return int64(time.Now().Unix()) }

type Oracle struct {
	engine            memprotect.Engine
	exportEngine      memprotect.Engine
	timeLockKey       *protectedcrypto.Curve25519Ratchet
	timeLockGenerator memprotect.Curve25519RatchetGenerator
	longTermKey       *protectedcrypto.Curve25519
	shortTermKey      *protectedcrypto.Curve25519Rotating
	signals           *signalstore.Store
}

// NewOracle
func NewOracle(storage *signalstore.Store, engine memprotect.Engine, exportEngine ...memprotect.Engine) *Oracle {
	r := &Oracle{
		engine:       engine,
		exportEngine: engine,
		signals:      storage,
	}
	if len(exportEngine) > 0 {
		r.exportEngine = exportEngine[0]
	}
	return r
}

// Generate new oracle keys. Ratchet starts with startTime and refreshes with ratchetTime. timeToExpire determines the
// lifetime of the shortTermKey.
func (self *Oracle) Generate(startTime, ratchetTime, timeToExpire int64) error {
	var err error
	if self.shortTermKey, err = protectedcrypto.NewCurve25519Rotating(timeToExpire, self.engine, self.exportEngine); err != nil {
		return err
	}
	self.timeLockKey = protectedcrypto.NewCurve25519Ratchet(self.engine, self.exportEngine)
	if err = self.timeLockKey.Generate(startTime, ratchetTime); err != nil {
		return err
	}
	if self.timeLockGenerator, err = self.timeLockKey.Generator(); err != nil {
		return err
	}
	self.longTermKey = protectedcrypto.NewCurve25519(self.engine, self.exportEngine)
	if err = self.longTermKey.Generate(); err != nil {
		return err
	}
	return nil
}

func (self *Oracle) PublicKeys() (longTerm, shortTerm *[32]byte) {
	return self.longTermKey.PublicKey(), self.shortTermKey.PublicKey()
}

func (self *Oracle) TimelockKeys(count int) (*types.RatchetPublicKey, error) {
	var err error
	if self.timeLockGenerator, err = self.timeLockKey.Generator(); err != nil {
		return nil, err
	}
	return self.timeLockGenerator.PublicKeys(count), nil
}

func (self *Oracle) Save() (longTermKey, timeLockKey memprotect.Element) {
	return self.longTermKey.PrivateKey(), self.timeLockKey.PrivateKey()
}

func (self *Oracle) Restore(longTermKey, timeLockKey memprotect.Element, timeToExpire int64) error {
	var err error
	if self.shortTermKey, err = protectedcrypto.NewCurve25519Rotating(timeToExpire, self.engine, self.exportEngine); err != nil {
		return err
	}
	self.timeLockKey = protectedcrypto.NewCurve25519Ratchet(self.engine, self.exportEngine)
	if err = self.timeLockKey.SetSecure(timeLockKey); err != nil {
		return err
	}
	self.longTermKey = protectedcrypto.NewCurve25519(self.engine, self.exportEngine)
	if err = self.longTermKey.SetSecure(longTermKey); err != nil {
		return err
	}
	return nil
}

func (self *Oracle) decryptOracleMessage(d []byte) (*OracleMessage, error) {
	var r *OracleMessage
	return r.decrypt(self.longTermKey, self.exportEngine, d)
}

func (self *Oracle) oracleMessageHandler(d []byte) ([]byte, []byte) {
	msg, err := self.decryptOracleMessage(d)
	if err != nil {
		return []byte(err.Error()), nil
	}
	payload, err := self.verifyOracleMessage(msg)
	if err != nil {
		return []byte(err.Error()), msg.ResponsePublicKey[:]
	}
	return payload, msg.ResponsePublicKey[:]
}

var (
	ErrTimePolicy           = errors.New("oracle: Time policy")
	ErrSignalSet            = errors.New("oracle: Signal is set")
	ErrWrongResponseKey     = errors.New("oracle: Wrong response key")
	ErrUnhandledMessageType = errors.New("oracle: Unhandled message type")
)

func (self *Oracle) setSignals(msg *OracleMessage) error {
	var err error
	for _, s := range msg.SetSemaphores {
		terr := self.signals.SetSignal(s[:], 0, 0)
		if err == nil && terr != nil {
			err = terr
		}
	}
	return err
}

func (self *Oracle) testSignals(msg *OracleMessage) error {
	for _, s := range msg.TestSemaphores {
		if !self.signals.TestSignal(s[:]) {
			return ErrSignalSet
		}
	}
	return nil
}

func (self *Oracle) verifyOracleMessage(msg *OracleMessage) ([]byte, error) {
	// Set semaphores first. This is most important to prevent distress to not be suppressed.
	if err := self.setSignals(msg); err != nil {
		return nil, err
	}
	// Verify time policy.
	if msg.ValidFrom > 0 && msg.ValidFrom > timeNow() {
		return nil, ErrTimePolicy
	}
	if msg.ValidTo > 0 && msg.ValidTo < timeNow() {
		return nil, ErrTimePolicy
	}
	// Verify semaphores.
	if err := self.testSignals(msg); err != nil {
		return nil, err
	}
	// Decrypt share
	err := msg.decryptShare(self.longTermKey, self.timeLockKey, self.exportEngine)
	if err != nil {
		return nil, err
	}
	return msg.Share, nil
}

// ReceiveMsg receives and processes a message to the oracle.
func (self *Oracle) ReceiveMsg(d []byte) ([]byte, error) {
	var response, responseKey []byte
	tsc := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(self.exportEngine),
		MessageType:        0,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: self.shortTermKey,
				MyPublicKey:     nil,
				PeerPublicKey:   nil,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: self.longTermKey,
				MyPublicKey:     nil,
				PeerPublicKey:   nil,
			},
		},
	}
	msg, err := tsc.Decrypt(d, nil)
	if err != nil {
		return nil, err
	}
	switch tsc.MessageType {
	case OracleMessageEnvelopeType:
		response, responseKey = self.oracleMessageHandler(msg)
		if responseKey == nil {
			responseKey = tsc.Keys[1].PeerPublicKey[:]
		}
	default:
		return nil, ErrUnhandledMessageType
	}
	tsc2 := &hybridcrypto.SecretCalculator{
		Combiner:           protectedcrypto.NewSecretCombiner(self.exportEngine),
		MessageType:        OracleResponseMessageType,
		Nonce:              nil,
		DeterministicNonce: nil,
		Keys: []hybridcrypto.KeyContainer{
			hybridcrypto.KeyContainer{
				SecretGenerator: self.shortTermKey,
				MyPublicKey:     self.shortTermKey.PublicKey(),
				PeerPublicKey:   tsc.Keys[0].PeerPublicKey,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: self.longTermKey,
				MyPublicKey:     self.longTermKey.PublicKey(),
				PeerPublicKey:   tsc.Keys[1].PeerPublicKey,
			},
			hybridcrypto.KeyContainer{
				SecretGenerator: self.shortTermKey,
				MyPublicKey:     self.shortTermKey.PublicKey(),
				PeerPublicKey:   unsafeconvert.To32(responseKey),
			},
		},
	}
	return tsc2.Encrypt(response, nil)
}

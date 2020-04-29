package protectedcrypto

import (
	"crypto/subtle"
	"io"

	"assuredrelease.com/cypherlock-pe/memprotect"
	"assuredrelease.com/cypherlock-pe/types"
	"assuredrelease.com/cypherlock-pe/unsafeconvert"
	"assuredrelease.com/cypherlock-pe/util"

	"golang.org/x/crypto/curve25519"
)

type RatchetKey struct {
	StartTime          int64 // StartTime points at the time at which PrivateKey was generated.
	RatchetTime        int64 // RatchetType is the time between ratchet advances.
	RatchetConstant    [32]byte
	RatchetGenerator   [32]byte
	RatchetBase        [32]byte // 1. RatchetBase = sha256HMAC(RatchetBase, RatchetConstant)
	PrivateKey         [32]byte // 2. PrivateKey  = sha256HMAC(RatchetBase, RatchetGenerator)
	PublicKey          [32]byte // PublicKey of PrivateKey
	PreviousPrivateKey [32]byte // Previous private key.
	PreviousPublicKey  [32]byte // Previous public key.
	TempKey            [32]byte // Just for secure storage.
	HasPrevious        bool     // True if a previous keypair exists.
}

func (self *RatchetKey) copyPublicKey() *[32]byte {
	ret := new([32]byte)
	copy(ret[:], self.PublicKey[:])
	return ret
}

func (self *RatchetKey) copy(newKey *RatchetKey) {
	newKey.StartTime = self.StartTime
	newKey.RatchetTime = self.RatchetTime
	newKey.HasPrevious = self.HasPrevious
	newKey.TempKey = [32]byte{}
	copy(newKey.RatchetConstant[:], self.RatchetConstant[:])
	copy(newKey.RatchetGenerator[:], self.RatchetGenerator[:])
	copy(newKey.RatchetBase[:], self.RatchetBase[:])
	copy(newKey.PrivateKey[:], self.PrivateKey[:])
	copy(newKey.PublicKey[:], self.PublicKey[:])
	copy(newKey.PreviousPrivateKey[:], self.PreviousPrivateKey[:])
	copy(newKey.PreviousPublicKey[:], self.PreviousPublicKey[:])

}

func (self *RatchetKey) generate(startTime, ratchetTime int64) error {
	self.StartTime = startTime
	self.RatchetTime = ratchetTime
	if _, err := io.ReadFull(RandomSource, self.RatchetConstant[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(RandomSource, self.RatchetGenerator[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(RandomSource, self.RatchetBase[:]); err != nil {
		return err
	}
	// PrivateKey = sha256HMAC(RatchetBase, RatchetGenerator)
	SHA256HMAC(self.RatchetBase[:], self.RatchetGenerator[:], self.PrivateKey[:])
	curve25519.ScalarBaseMult(&self.PublicKey, &self.PrivateKey)
	self.HasPrevious = false
	self.PreviousPrivateKey = [32]byte{}
	self.PreviousPublicKey = [32]byte{}
	return nil
}

func (self *RatchetKey) advance(now int64) {
	if self.StartTime+self.RatchetTime < now {
		self.StartTime = self.StartTime + self.RatchetTime
		// 1. Move keypair to previous keypar
		copy(self.PreviousPrivateKey[:], self.PrivateKey[:])
		copy(self.PreviousPublicKey[:], self.PublicKey[:])
		self.HasPrevious = true
		// 2. RatchetBase = sha256HMAC(RatchetBase, RatchetConstant)
		SHA256HMAC(self.RatchetBase[:], self.RatchetConstant[:], self.TempKey[:])
		copy(self.RatchetBase[:], self.TempKey[:])
		self.TempKey = [32]byte{}
		// 3. PrivateKey  = sha256HMAC(RatchetBase, RatchetGenerator)
		SHA256HMAC(self.RatchetBase[:], self.RatchetGenerator[:], self.PrivateKey[:])
		curve25519.ScalarBaseMult(&self.PublicKey, &self.PrivateKey)
	}
}

// Curve25519RatchetGenerator allows future public key generation without being locked into the same memory as the origin key. That allows
// concurrent execution with the main Curve25519Ratchet.
type Curve25519RatchetGenerator struct {
	ratchetKey *RatchetKey
	cell       memprotect.Cell
}

// PublicKeys generates count number future public keys for the ratchet. It destroys the memory after calculation and cannot be called again.
func (self *Curve25519RatchetGenerator) PublicKeys(count int) *types.RatchetPublicKey {
	if self.ratchetKey == nil {
		panic("Curve25519RatchetGenerator executed twice")
	}
	defer func() {
		self.cell.Destroy()
		self.cell = nil
		self.ratchetKey = nil
	}()
	ret := &types.RatchetPublicKey{
		StartTime:   self.ratchetKey.StartTime,
		RatchetTime: self.ratchetKey.RatchetTime,
		Key:         make([][32]byte, 0, count),
	}
	now := self.ratchetKey.StartTime + self.ratchetKey.RatchetTime + 1
	for i := 0; i < count; i++ {
		pk := self.ratchetKey.copyPublicKey()
		ret.Key = append(ret.Key, *pk)
		if i == count-1 {
			break
		}
		self.ratchetKey.advance(now)
		now = now + self.ratchetKey.RatchetTime
	}
	return ret
}

type Curve25519Ratchet struct {
	engine       memprotect.Engine
	exportEngine memprotect.Engine
	element      memprotect.Element
	ratchetKey   *RatchetKey
	templateType *RatchetKey
	typeSize     int
	isOpen       bool
}

func NewCurve25519Ratchet(engine memprotect.Engine, exportEngine ...memprotect.Engine) *Curve25519Ratchet {
	r := &Curve25519Ratchet{
		engine:       engine,
		exportEngine: engine,
		templateType: new(RatchetKey),
	}
	r.typeSize = util.TypeSize(r.templateType)
	if len(exportEngine) > 0 {
		r.exportEngine = exportEngine[0]
	}
	return r
}

func (self *Curve25519Ratchet) open() error {
	if self.isOpen {
		return nil
	}
	d, err := self.element.Bytes()
	if err != nil {
		return err
	}
	self.ratchetKey = unsafeconvert.Convert(d, self.templateType).(*RatchetKey)
	self.isOpen = true
	return nil
}

// Generate a new RatchetKey. If startTime is less or equal zero it'll be set to the current time.
func (self *Curve25519Ratchet) Generate(startTime, ratchetTime int64) error {
	if startTime <= 0 {
		startTime = timeNow()
	}
	self.element = self.engine.Element(self.typeSize)
	if err := self.open(); err != nil {
		return err
	}
	self.element.Melt()
	if err := self.ratchetKey.generate(startTime, ratchetTime); err != nil {
		return err
	}
	self.Seal()
	_, err := self.Advance()
	return err
}

func (self *Curve25519Ratchet) SetSecure(privateKey memprotect.Element) error {
	self.element = privateKey
	return nil
}

func (self *Curve25519Ratchet) PrivateKey() memprotect.Element {
	return self.element
}

func (self *Curve25519Ratchet) Advance() (int64, error) {
	err := self.open()
	if err != nil {
		return 0, err
	}
	self.element.Melt()
	for i := 0; i < 2; i++ { // We execute twice, just in case that so much time has passed that the calculation takes more than duration.
		now := timeNow()
		for self.ratchetKey.StartTime+self.ratchetKey.RatchetTime < now {
			self.ratchetKey.advance(now)
		}
	}
	d := self.ratchetKey.RatchetTime - (timeNow() - self.ratchetKey.StartTime)
	self.Seal()
	return d, nil
}

func (self *Curve25519Ratchet) Generator() (memprotect.Curve25519RatchetGenerator, error) {
	ret := new(Curve25519RatchetGenerator)
	// Advance
	_, err := self.Advance()
	if err != nil {
		return nil, err
	}
	// Create secure cell
	ret.cell = self.engine.Cell(self.typeSize)
	// Copy RatchetKey
	ret.ratchetKey = unsafeconvert.Convert(ret.cell.Bytes(), self.templateType).(*RatchetKey)
	err = self.open() // Minimum time open.
	if err != nil {
		ret.cell.Destroy()
		ret.ratchetKey = nil
		return nil, err
	}
	self.ratchetKey.copy(ret.ratchetKey)
	self.Seal()
	return ret, nil
}

func (self *Curve25519Ratchet) SharedSecret(ratchetKey *[32]byte, peerPublicKey *[32]byte) (ratchetPublicKey *[32]byte, secret memprotect.Cell, err error) {
	var calcKey *[32]byte
	_, err = self.Advance()
	if err != nil {
		return nil, nil, err
	}
	if err := self.open(); err != nil {
		return nil, nil, err
	}
	defer self.Seal()
	if subtle.ConstantTimeCompare(ratchetKey[:], self.ratchetKey.PublicKey[:]) == 1 {
		calcKey = &self.ratchetKey.PrivateKey
	} else if self.ratchetKey.HasPrevious && subtle.ConstantTimeCompare(ratchetKey[:], self.ratchetKey.PreviousPublicKey[:]) == 1 {
		calcKey = &self.ratchetKey.PreviousPrivateKey
	} else {
		return nil, nil, memprotect.ErrRatchedNotFound
	}
	s1 := self.exportEngine.Cell(32)
	curve25519.ScalarMult(unsafeconvert.To32(s1.Bytes()), calcKey, peerPublicKey)
	sha256Self(s1.Bytes())
	return ratchetKey, s1, nil
}

func (self *Curve25519Ratchet) Seal() {
	self.element.Seal()
	self.isOpen = false
	self.ratchetKey = nil
	return
}

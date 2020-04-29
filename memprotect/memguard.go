package memprotect

import (
	"sync"

	"github.com/awnumar/memguard"
)

// MemGuard implements an Engine with the memguard package.
type MemGuard struct {
	key Cell
}

// Init the engine.
func (self *MemGuard) Init(key Cell) {
	self.key = key
	memguard.CatchInterrupt()
	safeExit = self.Exit
	safePanic = self.Panic
}

// Finish the engine.
func (self *MemGuard) Finish() {
	defer memguard.Purge()
	if r := recover(); r != nil {
		self.Panic(r)
	}
}

func (self *MemGuard) Exit(c int) {
	memguard.SafeExit(c)
}

func (self *MemGuard) Panic(v interface{}) {
	memguard.SafePanic(v)
}

func (self *MemGuard) Element(size int) Element {
	return NewMemGuardElement(size)
}

func (self *MemGuard) Cell(size int) Cell {
	return NewMemGuardCell(size)
}

func (self *MemGuard) DecryptElement(encryptedElement []byte) (Element, error) {
	return DecryptElement(self.key, encryptedElement, self)
}

func (self *MemGuard) EncryptElement(e Element) ([]byte, error) {
	return e.Encrypt(self.key)
}

// MemGuardElement implements Element over a MemGuard engine.
type MemGuardElement struct {
	enclave  *memguard.Enclave
	size     int
	mutex    *sync.Mutex
	unsealed bool
	buffer   *memguard.LockedBuffer
}

func NewMemGuardElement(size int) *MemGuardElement {
	return &MemGuardElement{
		size:    size,
		enclave: memguard.NewEnclaveRandom(size),
		mutex:   new(sync.Mutex),
	}
}

func (self *MemGuardElement) Size() int {
	return self.size
}

func (self *MemGuardElement) open() (err error) {
	if self.unsealed {
		return nil
	}
	self.buffer, err = self.enclave.Open()
	if err != nil {
		self.buffer = nil
		return err
	}
	self.unsealed = true
	return nil
}

func (self *MemGuardElement) Seal() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.unsealed {
		self.enclave = self.buffer.Seal()
		self.buffer = nil
	}
	self.unsealed = false
}

func (self *MemGuardElement) Melt() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.open(); err != nil {
		return err
	}
	self.buffer.Melt()
	return nil
}

func (self *MemGuardElement) Destroy() (err error) {
	if self == nil {
		return nil
	}
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.open(); err != nil {
		return err
	}
	self.buffer.Destroy()
	self.unsealed = false
	self.buffer = nil
	self.enclave = nil
	return nil
}

func (self *MemGuardElement) Bytes() ([]byte, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.open(); err != nil {
		return nil, err
	}
	return self.buffer.Bytes(), nil
}

func (self *MemGuardElement) WithBytes(f func(unsealed []byte) error) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.open(); err != nil {
		return err
	}
	err := f(self.buffer.Bytes())
	self.enclave = self.buffer.Seal()
	self.buffer = nil
	self.unsealed = false
	return err
}

func (self *MemGuardElement) Set(src []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.open(); err != nil {
		return err
	}
	self.buffer.Melt()
	self.buffer.Move(src)
	self.buffer.Freeze()
	return nil
}

func (self *MemGuardElement) Encrypt(key Cell) ([]byte, error) {
	return EncryptElement(key, self)
}

type MemGuardCell struct {
	lockedBuffer *memguard.LockedBuffer
}

func NewMemGuardCell(size int) *MemGuardCell {
	r := &MemGuardCell{
		lockedBuffer: memguard.NewBuffer(size),
	}
	r.lockedBuffer.Melt()
	return r
}

func (self *MemGuardCell) Load(d []byte) {
	self.lockedBuffer.Move(d)
}

func (self *MemGuardCell) Bytes() []byte {
	return self.lockedBuffer.Bytes()
}

func (self *MemGuardCell) Destroy() {
	if self == nil {
		return
	}
	self.lockedBuffer.Destroy()
}

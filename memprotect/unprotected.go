package memprotect

import "os"

// Unprotected memory
type Unprotected struct {
	key Cell
}

func (self *Unprotected) Init(key Cell) {
	self.key = key
}

func (self *Unprotected) Finish() {}

func (self *Unprotected) Exit(c int) {
	if safeExit != nil {
		safeExit(c)
	} else {
		os.Exit(c)
	}
}

func (self *Unprotected) Panic(v interface{}) {
	if safePanic != nil {
		safePanic(v)
	} else {
		panic(v)
	}
}

func (self *Unprotected) Element(size int) Element {
	return &UnprotectedElement{
		d: make([]byte, size),
	}
}

func (self *Unprotected) Cell(size int) Cell {
	return &UnprotectedCell{
		d: make([]byte, size),
	}
}

func (self *Unprotected) DecryptElement(encryptedElement []byte) (Element, error) {
	return DecryptElement(self.key, encryptedElement, self)
}

func (self *Unprotected) EncryptElement(e Element) ([]byte, error) {
	return e.Encrypt(self.key)
}

type UnprotectedCell struct {
	d []byte
}

func (self *UnprotectedCell) Load(d []byte) {
	copy(self.d, d)
}

func (self *UnprotectedCell) Bytes() []byte {
	return self.d
}

func (self *UnprotectedCell) Destroy() {
	if self == nil {
		return
	}
	for i := 0; i < len(self.d); i++ {
		self.d[i] = 0x00
	}
}

type UnprotectedElement struct {
	d []byte
}

func (self *UnprotectedElement) Size() int {
	return len(self.d)
}

func (self *UnprotectedElement) Bytes() ([]byte, error) {
	return self.d, nil
}

func (self *UnprotectedElement) Melt() error {
	return nil
}

func (self *UnprotectedElement) WithBytes(f func(unsealed []byte) error) error {
	return f(self.d)
}

func (self *UnprotectedElement) Destroy() error {
	if self == nil {
		return nil
	}
	for i := 0; i < len(self.d); i++ {
		self.d[i] = 0x00
	}
	return nil
}

func (self *UnprotectedElement) Seal() {}

func (self *UnprotectedElement) Set(src []byte) error {
	copy(self.d, src)
	return nil
}

func (self *UnprotectedElement) Encrypt(key Cell) ([]byte, error) {
	return EncryptElement(key, self)
}

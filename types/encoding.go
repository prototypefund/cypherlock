// Package types implements encoding/decoding interfaces for generic, asn1 compatible types.
package types

import (
	"encoding/asn1"
	"errors"
	"strconv"
	"sync"

	"assuredrelease.com/cypherlock-pe/util"
)

var (
	ErrEncoding      = errors.New("types: Encoding error")
	ErrTypeUnknown   = errors.New("types: Unknown type")
	ErrTypeIDInvalid = errors.New("types: TypeID invalid")
	ErrExtraBytes    = errors.New("types: Extra bytes")
)

// Version is this library's version.
const Version = int32(1000000001)

// Factory is the interface that needs to be implemented by each type handled by this library.
type Factory interface {
	TypeID() int32    // TypeID returns the _unique_ TypeID of this type. Must return a value greater than 0.
	New() interface{} // New returns a new instance of the type, as a pointer value.
}

var typeMap map[int32]Factory // Internal type mapping.
var mutex *sync.Mutex

func init() {
	mutex = new(sync.Mutex)
	typeMap = make(map[int32]Factory)
}

// RegisterType registers a type with this library. It must be called during the type's module init function.
func RegisterType(f Factory) {
	mutex.Lock()
	defer mutex.Unlock()
	typeID := f.TypeID()
	if typeID <= 0 {
		panic("types: Invalid type ID: " + strconv.Itoa(int(typeID)))
	}
	if _, ok := typeMap[typeID]; ok {
		panic("types: Registration of duplicate TypeID: " + strconv.Itoa(int(typeID)))
	}
	typeMap[typeID] = f
}

// FactorType returns a variable of type typeID.
func FactorType(typeID int32) (interface{}, error) {
	if typeID <= 0 {
		return nil, ErrTypeIDInvalid
	}
	mutex.Lock()
	defer mutex.Unlock()
	if f, ok := typeMap[typeID]; ok {
		return f.New(), nil
	}
	return nil, ErrTypeUnknown
}

// Marshal a compatible type that implements the Factory interface.
func Marshal(i Factory) ([]byte, error) {
	typeID := i.TypeID()
	j := util.RemovePointer(i)
	v, _ := asn1.Marshal(Version)
	tD, _ := asn1.Marshal(typeID)
	iD, err := asn1.Marshal(j)
	if err != nil {
		return nil, err
	}
	r := make([]byte, 0, len(v)+len(tD)+len(iD))
	r = append(r, v...)
	r = append(r, tD...)
	return append(r, iD...), nil
}

// Unmarshal a compatible type that is registered with this library.
func Unmarshal(d []byte) (interface{}, error) {
	var versionDec, typeIDDec int32
	r, err := asn1.Unmarshal(d, &versionDec)
	if err != nil {
		return nil, err
	}
	if len(r) == 0 {
		return nil, ErrEncoding
	}
	r, err = asn1.Unmarshal(r, &typeIDDec)
	if err != nil {
		return nil, err
	}
	if len(r) == 0 {
		return nil, ErrEncoding
	}
	f, err := FactorType(typeIDDec)
	if err != nil {
		return nil, err
	}
	r, err = asn1.Unmarshal(r, f)
	if err != nil {
		return nil, err
	}
	if len(r) != 0 {
		return nil, ErrExtraBytes
	}
	return f, nil
}

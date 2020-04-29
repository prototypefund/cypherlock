package merkletree

import (
	"crypto"
	"encoding/binary"
)

// Marshall a PathElement into a byteslice.
func (pe *PathElement) Marshall() []byte {
	return pe.Hash
}

// UnMarshallPathElement returns a PathElement from the given marshalled PathElement and true, false and nil on error.
func UnMarshallPathElement(d []byte, hashSize int) (ok bool, pathElement *PathElement) {
	elemSize := 1 + 1 + 1 + 4 + hashSize // IsLeaf, IsLeft, IsEmpty, Depths, Hash
	if len(d) < elemSize {
		return false, nil
	}
	pe := &PathElement{
		Hash:   d[:elemSize],
		Depths: binary.BigEndian.Uint32(d[3:7]),
	}
	if d[0] == 0x01 {
		pe.IsLeaf = true
	}
	if d[1] == 0x01 {
		pe.IsLeft = true
	}
	if d[2] == 0x01 {
		pe.IsEmpty = true
	}
	return true, pe
}

// Marshall a path into a byteslice.
func (p Path) Marshall() []byte {
	if len(p) == 0 {
		return nil
	}
	ret := make([]byte, 0, len(p[0].Hash)*len(p))
	for _, e := range p {
		ret = append(ret, e.Marshall()...)
	}
	return ret
}

// UnMarshallPath returns a Path from a marshalled path, and true. Or false and nil on error.
func UnMarshallPath(d []byte, hash crypto.Hash) (ok bool, path Path) {
	hashSize := hash.New().Size()
	elemSize := 1 + 1 + 1 + 4 + hashSize // IsLeaf, IsLeft, IsEmpty, Depths, Hash
	path = make(Path, 0, len(d)/elemSize)
	for i := 0; i < len(d); i += elemSize {
		ok, pe := UnMarshallPathElement(d[i:], hashSize)
		if !ok {
			return false, nil
		}
		path = append(path, pe)
	}
	return true, path
}

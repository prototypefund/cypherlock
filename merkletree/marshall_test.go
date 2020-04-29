package merkletree

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"math"
	"testing"
)

func testEqualElements(a, b *PathElement) (ok bool) {
	if a == nil || b == nil {
		return false
	}
	test := a.IsLeaf == b.IsLeaf
	test = test && a.IsEmpty == b.IsEmpty
	test = test && a.IsLeft == b.IsLeft
	test = test && a.Depths == b.Depths
	test = test && bytes.Equal(a.Hash, b.Hash)
	return test
}

func Test_Marshall(t *testing.T) {
	hashSize := crypto.SHA256.New().Size()
	tdata := Path{
		&PathElement{
			IsLeaf:  true,
			IsLeft:  true,
			Depths:  0,
			IsEmpty: true,
		},
		&PathElement{
			IsLeaf:  false,
			IsLeft:  true,
			Depths:  0,
			IsEmpty: true,
		},
		&PathElement{
			IsLeaf:  true,
			IsLeft:  false,
			Depths:  0,
			IsEmpty: true,
		},
		&PathElement{
			IsLeaf:  true,
			IsLeft:  true,
			Depths:  0,
			IsEmpty: false,
		},
		&PathElement{
			IsLeaf:  false,
			IsLeft:  false,
			Depths:  0,
			IsEmpty: true,
		},
		&PathElement{
			IsLeaf:  false,
			IsLeft:  true,
			Depths:  0,
			IsEmpty: false,
		},
		&PathElement{
			IsLeaf:  true,
			IsLeft:  false,
			Depths:  0,
			IsEmpty: false,
		},
		&PathElement{
			IsLeaf:  false,
			IsLeft:  false,
			Depths:  0,
			IsEmpty: false,
		},
		&PathElement{
			IsLeaf:  true,
			IsLeft:  true,
			Depths:  1,
			IsEmpty: true,
		},
		&PathElement{
			IsLeaf:  true,
			IsLeft:  true,
			Depths:  math.MaxUint32,
			IsEmpty: true,
		},
	}
	for _, e := range tdata {
		e.CalcHash(crypto.SHA256, []byte("testdata"), []byte("testdata"))
	}

	mp := tdata.Marshall()
	ok, np := UnMarshallPath(mp, crypto.SHA256)
	if !ok {
		t.Error("Path Marshall/UnMarshall failed 1.")
	}
	if len(np) != len(tdata) {
		t.Error("Path Marshall/UnMarshall failed 2.")
	}
	for i, e := range np {
		if !testEqualElements(e, tdata[i]) {
			t.Errorf("Path Marshall/UnMarshall failed, element %d", i)
		}
	}
	mp = append(mp, 0x01)
	ok, _ = UnMarshallPath(mp, crypto.SHA256)
	if ok {
		t.Error("Path Marshall/UnMarshall failed. Extension not detected.")
	}
	mp = mp[:len(mp)-2]
	ok, _ = UnMarshallPath(mp, crypto.SHA256)
	if ok {
		t.Error("Path Marshall/UnMarshall failed. Shortening not detected.")
	}

	for i, e := range tdata {
		// e.CalcHash(crypto.SHA256, []byte("testdata"), []byte("testdata"))
		m := e.Marshall()
		ok, t1 := UnMarshallPathElement(m, hashSize)
		if !ok {
			t.Errorf("Marshall/UnMarshall: %d", i)
		}
		if !testEqualElements(t1, e) {
			t.Errorf("Marshall/UnMarshall fields: %d \n %v\n %v", i, e, t1)
		}
		e.Hash = append(e.Hash, 0x01)
		ok, t1 = UnMarshallPathElement(e.Marshall(), hashSize)
		if !ok || testEqualElements(t1, e) {
			t.Errorf("Marshall/UnMarshall extend not detected. %d", i)
		}
		e.Hash = e.Hash[:len(e.Hash)-4]
		ok, t1 = UnMarshallPathElement(e.Marshall(), hashSize)
		if ok || t1 != nil {
			t.Errorf("Marshall/UnMarshall shorting not detected 1. %d", i)
		}
		if testEqualElements(t1, e) {
			t.Errorf("Marshall/UnMarshall shorting not detected 2. %d", i)
		}
	}

}

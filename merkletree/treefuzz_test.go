package merkletree

import (
	"crypto"
	"encoding/binary"
	"testing"
)

// Targeted toggle, minus/plus depths, randomize depths, change multiple values, multiple synched nodes.
// Many nodes (1-1k). With and without sparse. modify hashes.

type fuzzData struct {
	elements [][][]byte
	paths    [][]Path
}

func makeFuzzData(numPaths int) (f fuzzData) {
	f.elements = make([][][]byte, numPaths)
	f.paths = make([][]Path, numPaths)
	for i := 0; i < numPaths; i++ {
		f.elements[i] = make([][]byte, i+1)
		for j := 0; j <= i; j++ {
			f.elements[i][j] = make([]byte, 4)
			binary.BigEndian.PutUint32(f.elements[i][j], uint32(j))
		}
		tree := NewMerkleTree(f.elements[i], crypto.SHA256)
		f.paths[i] = tree.Paths()
	}
	return
}

func (f fuzzData) runTest(tfunc func(i, j int, leaf []byte, path Path) bool) {
	for i, s := range f.elements {
		for j, t := range s {
			if !tfunc(i, j, t, f.paths[i][j]) {
				return
			}
		}
	}
}

func (p Path) deepCopy() Path {
	bytecopy := func(d []byte) []byte {
		c := make([]byte, len(d))
		copy(c, d)
		return c
	}
	np := make(Path, 0, len(p))
	for _, e := range p {
		ne := &PathElement{
			IsLeaf:  e.IsLeaf,
			IsLeft:  e.IsLeft,
			IsEmpty: e.IsEmpty,
			Depths:  e.Depths,
			Hash:    bytecopy(e.Hash),
		}
		np = append(np, ne)
	}
	return np
}

func (pe *PathElement) changePrefix() {
	newPrefix := pe.prefix()
	copy(pe.Hash, newPrefix)
}

func (p Path) changePrefix() {
	for _, pe := range p {
		pe.changePrefix()
	}
}

type fuzzPathModifier struct {
	fuzzFunc func(Path) Path
	name     string
}

func destroyRootFuzzer(p Path) Path {
	np := p.deepCopy()
	np[len(np)-1].Hash = []byte{0x00}
	return np
}

var fuzzPathModifiers = []fuzzPathModifier{
	fuzzPathModifier{
		fuzzFunc: destroyRootFuzzer,
		name:     "destroyRootHash",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				np[i].IsEmpty = !np[i].IsEmpty
			}
			return np
		},
		name: "toggleIsEmpty",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					np[i].IsEmpty = !np[i].IsEmpty
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "toggleIsEmpty_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				np[i].IsLeaf = !np[i].IsLeaf
			}
			return np
		},
		name: "toggleIsLeaf",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					np[i].IsLeaf = !np[i].IsLeaf
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "toggleIsLeaf_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				np[i].IsLeft = !np[i].IsLeft
			}
			return np
		},
		name: "toggleIsLeft",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					np[i].IsLeft = !np[i].IsLeft
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "toggleIsLeft_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				np[i].Depths += 1
			}
			return np
		},
		name: "increaseDepth",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					np[i].Depths += 1
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "increaseDepth_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				np[i].Depths -= 1
			}
			return np
		},
		name: "decreaseDepth",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					np[i].Depths -= 1
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "decreaseDepth_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			np := p.deepCopy()
			for i, _ := range np {
				if np[i].Hash[10] == 0x01 {
					np[i].Hash[10] = 0x00
				} else {
					np[i].Hash[10] = 0x01
				}
			}
			return np
		},
		name: "changeHash",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%2 == 0 {
					mod = true
					if np[i].Hash[10] == 0x01 {
						np[i].Hash[10] = 0x00
					} else {
						np[i].Hash[10] = 0x01
					}
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "changeHash_mod2",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i+1 < len(np) {
					if np[i].Depths == np[i+1].Depths {
						mod = true
						h := np[i].Hash
						np[i].Hash = np[i+1].Hash
						np[i+1].Hash = h
					}
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "swapHashesSameDepths",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i+1 < len(np) {
					mod = true
					h := np[i].Hash
					np[i].Hash = np[i+1].Hash
					np[i+1].Hash = h
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "swapHashesNeighbors",
	},
	fuzzPathModifier{
		fuzzFunc: func(p Path) Path {
			mod := false
			np := p.deepCopy()
			for i, _ := range np {
				if i%3 == 0 {
					if i+1 < len(np) {
						mod = true
						h := np[i].Hash
						np[i].Hash = np[i+1].Hash
						np[i+1].Hash = h
					}
				}
			}
			if !mod {
				return destroyRootFuzzer(p)
			}
			return np
		},
		name: "swapHashesNeighbors_mod3",
	},
}

func subTest(testData fuzzData, t *testing.T) {
	// All paths are valid and unmodified.
	testData.runTest(
		func(i, j int, leaf []byte, path Path) (ok bool) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("verify failed: (%d %d) %s", i, j, r)
					ok = false
				}
			}()
			ok = path.Verify1(leaf, crypto.SHA256)
			if !ok {
				t.Errorf("verify failed: %d %d", i, j)
			}
			ok = path.Verify2(leaf, crypto.SHA256)
			if !ok {
				t.Errorf("verify failed: %d %d", i, j)
			}
			return ok
		})
	// Everything after here MUST fail
	// Only struct changed.
	for _, fuzzmod := range fuzzPathModifiers {
		testData.runTest(
			func(i, j int, leaf []byte, path Path) (ok bool) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("verify panic (%s): (%d %d) %s", fuzzmod.name, i, j, r)
						ok = false
					}
				}()
				np := fuzzmod.fuzzFunc(path)
				ok = np.Verify1(leaf, crypto.SHA256)
				if ok {
					t.Errorf("Verify must fail (%s): %d %d", fuzzmod.name, i, j)
				}
				ok = np.Verify2(leaf, crypto.SHA256)
				if ok {
					t.Errorf("Verify must fail (%s): %d %d", fuzzmod.name, i, j)
				}
				return !ok
			})
	}
	// Prefix changed. This triggers asserts since it generates impossible paths.
	for _, fuzzmod := range fuzzPathModifiers {
		testData.runTest(
			func(i, j int, leaf []byte, path Path) (ok bool) {
				okx := func() (okx bool) {
					defer func() {
						if r := recover(); r != nil {
							okx = false
						}
					}()
					np := fuzzmod.fuzzFunc(path)
					np.changePrefix()
					return np.Verify1(leaf, crypto.SHA256) && np.Verify2(leaf, crypto.SHA256)

				}()
				if okx {
					t.Errorf("Verify must fail (%s): %d %d", fuzzmod.name, i, j)
				}
				return !okx
			})
	}
}

func Test_FuzzTree(t *testing.T) {
	testDataDebug := makeFuzzData(128)
	subTest(testDataDebug, t)
}

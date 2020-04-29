package merkletree

import (
	"crypto"
	"encoding/binary"
	"fmt"
)

// PathElement is a single element within a path.
type PathElement struct {
	IsLeaf  bool   // Is this node a leaf?
	IsLeft  bool   // Is the left child of its father.
	Depths  uint32 // Depths to this node.
	Hash    []byte // Hash of content.
	IsEmpty bool   // Is this an empty node.
}

func (pe *PathElement) String() string {
	var empty, leaf, left string
	if pe.IsLeaf {
		leaf = "leaf "
	}
	if pe.IsEmpty {
		empty = "empty "
	}
	if pe.IsLeft {
		left = "left"
	} else {
		left = "right"
	}
	return fmt.Sprintf("%s%s%s %d %x", empty, leaf, left, pe.Depths, pe.Hash)
}

// prefix generates the prefix for the path element.
func (pe *PathElement) prefix() []byte {
	pr := make([]byte, 1+1+1+4) // IsLeaf IsLeft uint32 depths
	if pe.IsLeaf {
		pr[0] = 0x01
	}
	if pe.IsLeft {
		pr[1] = 0x01
	}
	if pe.IsEmpty {
		pr[2] = 0x01
	}
	binary.BigEndian.PutUint32(pr[3:], uint32(pe.Depths))
	return pr
}

// CalcHashFromNodes calculates a new parent node hash from left and right node.
func (pe *PathElement) CalcHashFromNodes(hash crypto.Hash, leftNode, rightNode *PathElement) {
	pe.CalcHash(hash, leftNode.Hash, rightNode.Hash)
}

// CalcHash calculates the Hash field of a PathElement from left and right children,
// both of which could be nil. The input uses 0x00 as prefix and postfix for the data
// to be hashed, and separates left and right by 0x00. Furthermore it includes
// the prefix of the PathElement which encodes Leaf/Interrior, Depths and Left/Right
// position.
func (pe *PathElement) CalcHash(hash crypto.Hash, leftNodeHash, rightNodeHash []byte) {
	h := hash.New()
	h.Write([]byte{0x00})
	if leftNodeHash != nil {
		h.Write(leftNodeHash)
	}
	if leftNodeHash != nil && rightNodeHash != nil {
		h.Write([]byte{0x00})
	}
	if rightNodeHash != nil {
		h.Write(rightNodeHash)
	}
	h.Write([]byte{0x00})
	pe.Hash = h.Sum(pe.prefix())
}

// CalcHashLeaf calculates the Hash field for a leaf.
func (pe *PathElement) CalcHashLeaf(hash crypto.Hash, leafContent []byte) {
	pe.CalcHash(hash, leafContent, nil)
}

// Path is the path to a leaf, including the leaf itself.
type Path []*PathElement

// ParentPathElement creates a new parent from two children.
func ParentPathElement(isLeft bool, leftNode, rightNode *PathElement, hash crypto.Hash) *PathElement {
	if leftNode.Depths != rightNode.Depths {
		panic("Cannot create a parent to children of different depths. Programming error!")
	}
	np := &PathElement{
		IsLeaf:  false, // This is always an interior node.
		IsLeft:  isLeft,
		Depths:  leftNode.Depths - 1,
		IsEmpty: false, // Parent nodes can't be empty because they have at least one child.
	}
	np.CalcHashFromNodes(hash, leftNode, rightNode)
	return np
}

// newParent creates a new parent node from left and right and writes it to the writePosition.
func (tc *treeCache) newParent(leftNode, rightNode *PathElement, writePos int) {
	// Write PathElement to cache
	tc.nodeCache[writePos] = ParentPathElement((writePos%2 == 0), leftNode, rightNode, tc.hash)
}

// Compress a path by removing empty elements which can be inferred.
func (p Path) Compress() Path {
	r := make(Path, 0, len(p))
	for _, e := range p {
		if !e.IsEmpty {
			r = append(r, e)
		}
	}
	return r
}

// GetRoot returns true and the root from a path. False and nil if it has no root.
func (p Path) GetRoot() (root *PathElement, ok bool) {
	root = p[len(p)-1]
	if root.IsLeaf {
		return nil, false
	}
	if root.Depths != 0 {
		return nil, false
	}
	return root, true
}

func (p *PathElement) RootHash(hash crypto.Hash) []byte {
	h := hash.New()
	h.Write(p.Hash)
	return h.Sum(make([]byte, 0))
}

package merkletree

import (
	"bytes"
	"crypto"
)

// Verify returns true if the path given is valid.
func (p Path) Verify1(leafContent []byte, hash crypto.Hash) (ok bool) {
	// Test plausibility of path.
	if !p.isPlausible() {
		return false
	}
	// Check if top element is ok.
	if !p[0].verifyMyLeafConstruction(leafContent, hash) {
		return false
	}
	return verifyPath(p, hash)
}

// verifyer assumes that the path is _plausible_.
type verifyer struct {
	p                           Path
	hash                        crypto.Hash
	hashSize                    int
	mynode, leftNode, rightNode *PathElement // only debug
}

func verifyPath(p Path, hash crypto.Hash) (ok bool) {
	var hasBranch bool
	v := &verifyer{
		p:        p,
		hashSize: hash.New().Size(),
		hash:     hash,
	}
	pos := 1
	mynode := p[0]
	for hasBranch, mynode = v.genBranch(pos, mynode); hasBranch; hasBranch, mynode = v.genBranch(pos, mynode) {
		pos++
	}
	rootNode, test := p.GetRoot()
	test = test && rootNode.IsLeft == mynode.IsLeft
	test = test && rootNode.IsLeaf == mynode.IsLeaf
	test = test && rootNode.Depths == mynode.Depths
	test = test && mynode.Depths == 0
	if test {
		test = test && bytes.Equal(rootNode.Hash, mynode.Hash)
	}
	return test
}

func (v *verifyer) getNextSibling(pos int, mynode *PathElement) (sibling *PathElement) {
	if v.p[pos].Depths == mynode.Depths && v.p[pos].IsEmpty == false { // Found an entry, always ignore empty.
		sibling = v.p[pos]
	} else {
		sibling = emptyNode(!mynode.IsLeft, mynode.IsLeaf, mynode.Depths, v.hashSize, v.hash)
	}
	if mynode.Depths != sibling.Depths || sibling.IsLeft == mynode.IsLeft || mynode.IsLeaf != sibling.IsLeaf {
		panic("merkletree verification, genBranch, conflicting sibling. Programming error!")
	}
	return sibling
}

func (v *verifyer) sortNodes(a, b *PathElement) (leftNode, rightNode *PathElement) {
	if a.IsLeft {
		return a, b
	}
	return b, a
}

func (v *verifyer) nextNodeIsLeft(pos int, depths uint32) bool {
	if pos >= len(v.p) { // There are nodes left over. Must always be true on a plausible path. This is the Root check.
		panic("merkletree verification, genBranch, working on inplausible path. Programming error!")
	}
	if v.p[pos].Depths == depths { // Check if this branch is filled.
		if v.p[pos].Depths == 0 { // Root reached. It's always the last, and always on the left.
			return true
		}
		return !v.p[pos+1].IsLeft
	}
	if pos >= len(v.p)-1 { // There are nodes left over. Must always be true on a plausible path. This is if Root has not been reached.
		panic("merkletree verification, genBranch, working on inplausible path 2. Programming error!")
	}
	if v.p[pos+1].Depths == depths { // Check if next branch is filled.
		if v.p[pos+1].Depths == 0 { // Root reached. It's always the last, and always on the left.
			return true
		}
		return !v.p[pos+1].IsLeft
	}
	return true // Empty sibling means we're left.
}

func (v *verifyer) genBranch(pos int, mynode *PathElement) (ok bool, newNode *PathElement) {
	if mynode.Depths == 0 {
		return false, mynode
	}
GeneratorLoop:
	for {
		sibling := v.getNextSibling(pos, mynode)
		leftnode, rightnode := v.sortNodes(sibling, mynode)
		isLeft := v.nextNodeIsLeft(pos, mynode.Depths-1)
		newNode = ParentPathElement(isLeft, leftnode, rightnode, v.hash)
		if newNode.Depths == 0 { // Root Reached.
			break GeneratorLoop
		}
		if newNode.Depths == v.p[pos+1].Depths { // Check if next node is depths of our, if not, we have to insert empties.
			break GeneratorLoop
		} else {
			mynode = newNode
		}
	}
	return true, newNode
}

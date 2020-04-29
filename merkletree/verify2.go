package merkletree

import (
	"bytes"
	"crypto"
)

type pathStack struct {
	path    Path
	curnode *PathElement
	pos     int
	l       int
}

func newPathStack(p Path) *pathStack {
	ps := &pathStack{
		path: p,
		pos:  0,
		l:    len(p),
	}
	if len(p) > 0 {
		ps.curnode = p[0]
	}
	return ps
}

// get the current top element or nil.
func (ps *pathStack) get() *PathElement {
	return ps.curnode
}

// advance to next element.
func (ps *pathStack) next() *PathElement {
	ps.pos++
	ps.curnode = nil
	if ps.pos < ps.l {
		ps.curnode = ps.path[ps.pos]
	}
	return ps.curnode
}

func getDepths(a, b *PathElement) uint32 {
	if a != nil {
		return a.Depths
	}
	return b.Depths
}

func firstNode(stack *pathStack) (ok bool, left, right *PathElement, depths uint32) {
	f := stack.get()
	s := stack.next()
	if !f.IsLeaf { // First must be a leaf.
		return false, nil, nil, 0
	}
	if f.Depths < s.Depths { // Second must be equal or same depths. It's sibling or ancestor.
		return false, nil, nil, 0
	}
	if f.Depths == s.Depths { // Only if siblings.
		if f.IsLeft == s.IsLeft { // Cannot be both left.
			return false, nil, nil, 0
		}
		if !s.IsLeaf {
			return false, nil, nil, 0 // Sibling must be a leaf as well.
		}
	}
	if f.IsLeft {
		return true, f, nil, f.Depths
	} else {
		return true, nil, f, f.Depths
	}
}

func noNilNode(a, b *PathElement) *PathElement {
	if a == nil && b == nil {
		panic("merkletree. verify2. Programming error. leftnode/rightnode not nilled.")
	}
	if a != nil && b != nil {
		panic("merkletree. verify2. Programming error. leftnode/rightnode not nilled.")
	}
	if a != nil {
		return a
	}
	return b
}

// Verify2 returns true if the path given is valid. Verify2 should always be used since it detects
func (p Path) Verify2(leafContent []byte, hash crypto.Hash) (ok bool) {
	// Test plausibility of path.
	if !p.isPlausible() {
		return false
	}
	// Check if top element is ok.
	if !p.VerifyLeaf(leafContent, hash) {
		return false
	}
	// if !p[0].verifyMyLeafConstruction(leafContent, hash) {
	// 	return false
	// }
	return verifyPath(p, hash)
}

// verifyPath verifies the path. It should be used instead of Verify. VerifyPath does NOT verify the first leaf.
// It should be used in conjunction with VerifyLeaf.
func (p Path) verifyPath(hash crypto.Hash) bool {
	var (
		ok                  bool
		leftnode, rightnode *PathElement
		depths              uint32
		hashSize            int
	)
	hashSize = hash.New().Size()
	if len(p) < 2 { // At least leaf and root.
		return false
	}
	stack := newPathStack(p)
	ok, leftnode, rightnode, depths = firstNode(stack)
	if !ok {
		return false
	}
	// DepthsLoop:
	for depths := depths; depths > 0; depths-- {
		var nextNode, topNode *PathElement
		curnode := stack.get()
		switch {
		case curnode.Depths > depths: // Impossible.
			return false
		case curnode.Depths == depths: // Found branch. Try to fit in
			topNode = noNilNode(leftnode, rightnode)
			if topNode.IsLeaf != curnode.IsLeaf { // Impossible
				return false
			}
			if topNode.IsLeft == curnode.IsLeft { // Impossible.
				return false
			}
			nextNode = curnode
		case curnode.Depths < depths: // We have to insert empty.
			topNode = noNilNode(leftnode, rightnode)
			nextNode = emptyNode(!topNode.IsLeft, topNode.IsLeaf, depths, hashSize, hash)
		default:
			panic("merkletree. verify2. Programming error. DepthsLoop cases.")
		}
		// HashNode. Fit in.
		if nextNode.IsLeft {
			leftnode = nextNode
		} else {
			rightnode = nextNode
		}
		createNode := &PathElement{
			IsEmpty: false,      // We always have children.
			Depths:  depths - 1, // One down.
		}
		distance := depths - curnode.Depths
		switch distance {
		case 0:
			// Sibling. Create template. Get IsLeft from next node. depths--
			curnode = stack.next()
			createNode.IsLeft = !curnode.IsLeft
		case 1:
			// Single empty node. Create template. Get IsLeft from next node. depths--
			createNode.IsLeft = !curnode.IsLeft
		default:
			// More than one empty node. Create template. IsLeft. depths--
			createNode.IsLeft = true
		}
		if createNode.Depths == 0 {
			createNode.IsLeft = true
		}
		createNode.CalcHashFromNodes(hash, leftnode, rightnode)
		if createNode.IsLeft {
			leftnode = createNode
			rightnode = nil
		} else {
			rightnode = createNode
			leftnode = nil
		}
	}
	root := stack.get()
	rootTest := noNilNode(leftnode, rightnode)
	if !bytes.Equal(root.Hash, rootTest.Hash) {
		return false
	}
	if root.Depths != 0 {
		return false
	}
	secondRoot := stack.next()
	if secondRoot != nil {
		// additional elements after root...
		return false
	}
	return true
}

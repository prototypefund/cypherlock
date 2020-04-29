package merkletree

import (
	"bytes"
	"crypto"
)

// isPlausible checks that the given path starts with a leaf and ends with root.
func (p Path) isPlausible() (ok bool) {
	test := true
	if len(p) < 2 {
		return false
	}
	// Leaf element (first in path).
	test = test && p[0].IsLeaf       // Must be a leaf.
	test = test && !p[0].IsEmpty     // Leafs have always data.
	test = test && (p[0].Depths > 0) // May not be depths zero (only root is).
	// Root element (last in path).
	r := len(p) - 1
	test = test && !p[r].IsLeaf     // Must be interior node.
	test = test && p[r].Depths == 0 // Must be depths zero.
	test = test && !p[r].IsEmpty    // Root nodes are never empty.

	// If we have a second leaf in the path.
	if test && p[1].Depths == p[0].Depths {
		test = test && len(p) > 2                 // We have at least three elements.
		test = test && p[1].IsLeaf                // Must be a leaf.
		test = test && p[0].IsLeft != p[1].IsLeft // Leafs on one branch.
	}

	// Verify that path is descending and ends with root node.
	if test {
		var i int // DONT SHADOW _i_ !!!!
		depths := p[0].Depths
	DepthsCheckLoop:
		for i = 1; i < len(p); i++ { // DONT SHADOW _i_ !!!!
			if p[i].IsEmpty { // We skip empty nodes, they are also never used in verification.
				continue DepthsCheckLoop
			}
			nodeDepths := p[i].Depths
			if nodeDepths >= depths { // Depths is ALWAYS decreasing.
				if i == 1 && nodeDepths == depths { // Second leaf is the only exception.
					continue DepthsCheckLoop
				}
				test = false
				break DepthsCheckLoop
			}
			if nodeDepths < 0 {
				test = false
				break DepthsCheckLoop
			}
			depths = nodeDepths
		}
		test = test && i == len(p) // Must exhaust path.
	}

	return test
}

// verifyMyLeafConstruction checks if the given PathElement has been created by the leafcontent.
func (pe PathElement) verifyMyLeafConstruction(leafContent []byte, hash crypto.Hash) (ok bool) {
	ne := createLeafFromContent(leafContent, pe.IsLeft, pe.Depths, hash)
	return bytes.Equal(ne.Hash, pe.Hash)
}

// VerifyLeaf verifies that the leaf in a path matches it's content.
func (p Path) VerifyLeaf(leafContent []byte, hash crypto.Hash) (ok bool) {
	if len(p) <= 1 { // must be always 2 or more. Leaf + Root.
		return false
	}
	return p[0].verifyMyLeafConstruction(leafContent, hash)
}

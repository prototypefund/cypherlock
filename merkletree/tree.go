package merkletree

import (
	"crypto"
	"math"
)

// treeCache contains the caching data for calculating a tree.
type treeCache struct {
	leaves     []Path         // Path to each leave, not including the original value.
	leaveCount int            // number of leaves.
	nodeCache  []*PathElement // The hashes of the current layer of nodes.
	nodeDepths uint32         // The depths of the nodeCache.
	treeDepths uint32         // Depths of the tree.
	hash       crypto.Hash    // Hash function to use.
	hashSize   int            // Size in bytes returned by hash function.
}

func newtreeCache(leaves [][]byte, hash crypto.Hash) *treeCache {
	leaveCount := len(leaves)
	depths := uint32(math.Ceil(math.Log2(float64(leaveCount))))
	if depths == 0 { // Corner case of only one element. Which doesn't make sense in practice but should be captured.
		depths = 1
	}
	tc := &treeCache{
		leaves:     make([]Path, leaveCount),
		leaveCount: leaveCount,
		nodeCache:  make([]*PathElement, leaveCount),
		nodeDepths: depths,
		hash:       hash,
		hashSize:   hash.New().Size(),
	}
	tc.treeDepths = tc.nodeDepths
	for pos, l := range leaves {
		tc.leaves[pos] = make(Path, 1, tc.treeDepths)
		pn := createLeafFromContent(l, (pos%2 == 0), tc.treeDepths, hash)
		tc.leaves[pos][0] = pn
		tc.nodeCache[pos] = pn
	}
	return tc
}

func createLeafFromContent(nodeContent []byte, isLeft bool, depths uint32, hash crypto.Hash) *PathElement {
	pn := &PathElement{
		IsLeaf:  true,
		IsLeft:  isLeft,
		Depths:  depths,
		IsEmpty: false,
	}
	pn.CalcHashLeaf(hash, nodeContent)
	return pn
}

func (tc *treeCache) setPaths(start, count int, pe *PathElement) {
	end := start + count
	if end >= tc.leaveCount {
		end = tc.leaveCount
	}
	for i := start; i < end; i++ {
		tc.leaves[i] = append(tc.leaves[i], pe)
	}
}

// getLeftNode returns the left node at the read position and frees the position.
func (tc *treeCache) getLeftNode(pos int) *PathElement {
	// Save node
	leftNode := tc.nodeCache[pos]
	// Nil the position
	tc.nodeCache[pos] = nil
	// Verify that left node depths is intact.
	if leftNode.Depths != tc.nodeDepths {
		panic("merkletree. Tainted nodeCache. Depths don't match left. Programming error!")
	}
	return leftNode
}

// getRightNode returns the right node at the read position and frees the position. It returns an empty node if
// no node is in the cache. It uses the left node as parameter.
func (tc *treeCache) getRightNode(pos int, leftNode *PathElement) *PathElement {
	var rightNode *PathElement
	if pos < len(tc.nodeCache)-1 && tc.nodeCache[pos+1] != nil {
		rightNode = tc.nodeCache[pos+1]
		tc.nodeCache[pos+1] = nil
		// Verify that left node depths is intact.
		if rightNode.Depths != tc.nodeDepths {
			panic("merkletree. Tainted nodeCache. Depths don't match right. Programming error!")
		}
	} else {
		// Create an empty element.
		rightNode = emptyNode(!leftNode.IsLeft, leftNode.IsLeaf, leftNode.Depths, tc.hashSize, tc.hash)
	}
	return rightNode
}

func emptyNode(isLeft, isLeaf bool, depths uint32, hashSize int, hash crypto.Hash) *PathElement {
	pe := &PathElement{
		IsLeaf:  isLeaf,
		IsLeft:  isLeft,
		Depths:  depths,
		IsEmpty: true,
	}
	if hashSize == 0 {
		hashSize = hash.New().Size()
	}
	pe.CalcHashLeaf(hash, make([]byte, hashSize))
	return pe
}

// distributePaths distributes the paths to the subnodes.
func (tc *treeCache) distributePaths(leftNode, rightNode *PathElement, writePos int) {
	// if !rightNode.IsEmpty  { // Optimization, drop for debugging purposes.
	// Push only happens if we have both left and right subtree. Otherwise the path can be calculated
	// completely from the leaf.
	newDephts := leftNode.Depths - 1
	distance := uint(tc.treeDepths - newDephts)
	treeCount := 1 << distance
	subtreeCount := treeCount / 2
	leftTreeStart := writePos * treeCount
	rightTreeStart := leftTreeStart + subtreeCount
	// Push right node into left subtree.
	tc.setPaths(leftTreeStart, subtreeCount, rightNode)
	// Push left node into right subtree.
	tc.setPaths(rightTreeStart, subtreeCount, leftNode)
	// }
}

// calcLayer calculates the next layer in the tree. It returns true as long
// as more layers are available.
func (tc *treeCache) calcLayer() bool {
	lpos := 0 // Left child of new node
	rpos := 0 // Position in cache where to write result
	calcDepths := int64(tc.nodeDepths)
NodeLoop:
	for {
		rpos = lpos / 2                                             // Write position for new element.
		if lpos >= len(tc.nodeCache) || tc.nodeCache[lpos] == nil { // End of cache
			break NodeLoop
		}
		leftNode := tc.getLeftNode(lpos)
		if leftNode.Depths == 0 {
			tc.setPaths(0, tc.leaveCount, leftNode)
			break NodeLoop
		}
		rightNode := tc.getRightNode(lpos, leftNode)
		tc.distributePaths(leftNode, rightNode, rpos)
		tc.newParent(leftNode, rightNode, rpos)
		lpos += 2 // Advance to next pair.
	}
	// Decrease depths.
	calcDepths--
	// tc.nodeDepths--
	if calcDepths >= 0 {
		tc.nodeDepths = uint32(calcDepths)
		return true
	}
	return false
}

func (tc *treeCache) root() []byte {
	return tc.nodeCache[0].Hash
}

type MerkleTree struct {
	tc *treeCache
}

// NewMerkleTree creates a new MerkleTree, it returns nil if no leaves are given.
func NewMerkleTree(leaves [][]byte, hash crypto.Hash) *MerkleTree {
	if len(leaves) == 0 {
		return nil
	}
	return &MerkleTree{
		tc: newtreeCache(leaves, hash),
	}
}

// Paths calculates and returns the paths of the MerkleTree.
func (mt *MerkleTree) Paths() []Path {
	for more := mt.tc.calcLayer(); more == true; more = mt.tc.calcLayer() {
	}
	return mt.tc.leaves
}

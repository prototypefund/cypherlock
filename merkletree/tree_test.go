package merkletree

import (
	"crypto"
	"testing"

	_ "crypto/sha256"
)

func Test_Tree(t *testing.T) {
	data := [][]byte{
		[]byte("0"),
		[]byte("1"),
		[]byte("2"),
		[]byte("3"),
		[]byte("4"),
		[]byte("5"),
		[]byte("6"),
		[]byte("7"),
		[]byte("8"),
		[]byte("9"),
		[]byte("10"),
	}
	tree := NewMerkleTree(data, crypto.SHA256)
	paths := tree.Paths()

	for i, p := range paths {
		if !p.isPlausible() {
			t.Fatalf("Plausibility check failed: %d", i)
		}

		if !p.Verify1(data[i], crypto.SHA256) {
			t.Fatalf("Verification failed: %d", i)
		}

		if !p.Verify2(data[i], crypto.SHA256) {
			t.Fatalf("Verification failed 2: %d", i)
		}
	}

}

func Test_TreeOneLeaf(t *testing.T) {
	tree := NewMerkleTree([][]byte{[]byte("0")}, crypto.SHA256)
	paths := tree.Paths()

	if !paths[0].Verify1([]byte("0"), crypto.SHA256) {
		t.Fatal("Verification failed")
	}
	if !paths[0].Verify2([]byte("0"), crypto.SHA256) {
		t.Fatalf("Verification failed 2")
	}
}

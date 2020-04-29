package merkletree

// Package merkletree is a simple merkletree implementation that constructs a merkletree from a list of input values.
// All leaves in the tree have the same distance from root, interior nodes are prefixed by 0x00 and leaf nodes by 0x01.
// Furthermore the distance of the node from root is recorded in the node and hashes.

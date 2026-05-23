package policy

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const TreeDepth = 16
const MaxLeaves = 1 << TreeDepth // 65536

// BuildTree builds a Poseidon Merkle tree from issuer leaves.
// Each leaf = Poseidon(pubkey_x, pubkey_y) where pubkey_x/y are Field elements.
// Returns all levels: levels[0] = leaves, levels[TreeDepth] = [root].
func BuildTree(leaves []*big.Int) ([][]*big.Int, error) {
	// Pad to MaxLeaves with zeros
	paddedLeaves := make([]*big.Int, MaxLeaves)
	for i := 0; i < MaxLeaves; i++ {
		if i < len(leaves) {
			paddedLeaves[i] = new(big.Int).Set(leaves[i])
		} else {
			paddedLeaves[i] = big.NewInt(0)
		}
	}

	levels := make([][]*big.Int, TreeDepth+1)
	levels[0] = paddedLeaves

	for d := 0; d < TreeDepth; d++ {
		prevLevel := levels[d]
		nextSize := len(prevLevel) / 2
		nextLevel := make([]*big.Int, nextSize)
		for i := 0; i < nextSize; i++ {
			left := prevLevel[2*i]
			right := prevLevel[2*i+1]
			h, err := poseidon.Hash([]*big.Int{left, right})
			if err != nil {
				return nil, fmt.Errorf("poseidon hash at depth %d, index %d: %w", d, i, err)
			}
			nextLevel[i] = h
		}
		levels[d+1] = nextLevel
	}

	return levels, nil
}

// GetMerklePath extracts the sibling path and direction bits for a given leaf index.
func GetMerklePath(levels [][]*big.Int, leafIndex int) ([]*big.Int, []int) {
	path := make([]*big.Int, TreeDepth)
	bits := make([]int, TreeDepth)

	idx := leafIndex
	for d := 0; d < TreeDepth; d++ {
		if idx%2 == 0 {
			// leaf is left child, sibling is right
			path[d] = levels[d][idx+1]
			bits[d] = 0
		} else {
			// leaf is right child, sibling is left
			path[d] = levels[d][idx-1]
			bits[d] = 1
		}
		idx /= 2
	}
	return path, bits
}

// ComputeLeaf computes a Merkle leaf: Poseidon(pubkey_x, pubkey_y)
func ComputeLeaf(pubkeyX, pubkeyY *big.Int) (*big.Int, error) {
	return poseidon.Hash([]*big.Int{pubkeyX, pubkeyY})
}

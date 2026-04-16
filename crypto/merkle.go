package crypto

// MerkleRoot computes the root over a slice of leaf hashes.
// Odd levels duplicate the last entry (Bitcoin-style).
func MerkleRoot(leaves [][32]byte) [32]byte {
	root, _ := MerkleRootMutated(leaves)
	return root
}

// MerkleRootMutated computes the root and also reports whether the tree
// is susceptible to CVE-2012-2459 second-preimages. A level is "mutated"
// when any two consecutive sibling hashes are equal: Bitcoin's odd-level
// duplicate-last rule means such a level admits a shorter leaf list that
// hashes to the same root, letting an attacker craft two distinct tx
// lists with a matching merkle root. Callers validating untrusted blocks
// must reject when mutated=true. Bitcoin Core equivalent:
// consensus/merkle.cpp::ComputeMerkleRoot.
func MerkleRootMutated(leaves [][32]byte) ([32]byte, bool) {
	if len(leaves) == 0 {
		return [32]byte{}, false
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	mutated := false
	for len(level) > 1 {
		for i := 0; i+1 < len(level); i += 2 {
			if level[i] == level[i+1] {
				mutated = true
			}
		}
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = Hash256Concat(level[i], level[i+1])
		}
		level = next
	}
	return level[0], mutated
}

// MerkleProof returns sibling hashes for the leaf at index.
func MerkleProof(leaves [][32]byte, index int) [][32]byte {
	if len(leaves) == 0 || index < 0 || index >= len(leaves) {
		return nil
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	idx := index
	var proof [][32]byte
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		var sib int
		if idx%2 == 0 {
			sib = idx + 1
		} else {
			sib = idx - 1
		}
		proof = append(proof, level[sib])
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = Hash256Concat(level[i], level[i+1])
		}
		level = next
		idx /= 2
	}
	return proof
}

// VerifyProof verifies a Merkle inclusion proof.
func VerifyProof(root, leaf [32]byte, proof [][32]byte, index int) bool {
	cur := leaf
	idx := index
	for _, sib := range proof {
		if idx%2 == 0 {
			cur = Hash256Concat(cur, sib)
		} else {
			cur = Hash256Concat(sib, cur)
		}
		idx /= 2
	}
	return cur == root
}

package sumhash

import (
	"hash"
)

var algorandCompressor Compressor

func init() {
	matrix, err := RandomMatrixFromSeed([]byte("Algorand"), 8, 1024)
	if err != nil {
		panic(err)
	}
	algorandCompressor = matrix.LookupTable()
}

// New returns a new hash.Hash computing a sumhash512 checksum.
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be 64 bytes, and the hash is computed in salted mode.
func New512(salt []byte) hash.Hash {
	return New(algorandCompressor, salt)
}

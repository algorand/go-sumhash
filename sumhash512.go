package sumhash

import (
	"hash"
)

// SumhashCompressor is a matrix derived from a seed which is used by the
// sumhash512 interface. In order the gain speed, this matrix can be used to compress
// input which have exactly size of InputLen()
var SumhashCompressor Compressor

// Sumhash512DigestSize  The size in bytes of the sumhash checksum
const Sumhash512DigestSize = 64

// Sumhash512DigestBlockSize  is the block size, in bytes,
// of the sumhash hash function
const Sumhash512DigestBlockSize = 64

func init() {
	matrix, err := RandomMatrixFromSeed([]byte("Algorand"), 8, 1024)
	if err != nil {
		panic(err)
	}
	SumhashCompressor = matrix.LookupTable()
}

// New512 creates a new sumhash512 context that computes a sumhash checksum.
// The output of the hash function is 64 bytes (512 bits).
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be 64 bytes, and the hash is computed in salted mode.
// the context returned by this function reference the salt argument. any changes
// might affect the hash calculation
func New512(salt []byte) (hash.Hash, error) {
	return New(SumhashCompressor, salt)
}

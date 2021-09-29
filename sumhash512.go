package sumhash

import (
	"hash"
)

var sumhashCompressor Compressor

const Sumhash512DigestSize, Sumhash512DigestBlockSize = 64, 64

func init() {
	matrix, err := RandomMatrixFromSeed([]byte("Algorand"), 8, 1024)
	if err != nil {
		panic(err)
	}
	sumhashCompressor = matrix.LookupTable()
}

// NewSumhash512 create a new sumhash512 context that compute sumhash checksum with 512 byes blocksize
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be BlockSize(c) bytes, and the hash is computed in salted mode.
func NewSumhash512(salt []byte) hash.Hash {
	return New(sumhashCompressor, salt)
}



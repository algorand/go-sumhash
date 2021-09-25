package sumhash

import (
	"hash"
)

var sumhashCompressor LookupTable

func init() {
	matrix, err := RandomMatrixFromSeed([]byte("Algorand"), 8, 1024)
	if err != nil {
		panic(err)
	}
	sumhashCompressor = matrix.LookupTable()
}

type sumhash215Digest struct {
	d digest
}

// New create a new sumhash512 context that compute sumhash checksum with 512 byes blocksize
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be BlockSize(c) bytes, and the hash is computed in salted mode.
func New(salt []byte) hash.Hash {
	return genericSumhashNew(sumhashCompressor, salt)
}


func (d *sumhash215Digest) Reset() {
	d.Reset()
}

func (d *sumhash215Digest) Size() int      { return d.Size() }

func (d *sumhash215Digest) BlockSize() int { return d.BlockSize() }

func (d *sumhash215Digest) Write(p []byte) (nn int, err error) {
	return d.Write(p)
}
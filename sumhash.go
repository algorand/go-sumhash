// Package sumhash implements the subset-sum hash function.
package sumhash

import (
	"encoding/binary"
	"fmt"
	"hash"
)

// digest implementation is based on https://cs.opensource.google/go/go/+/refs/tags/go1.16.6:src/crypto/sha256/sha256.go
type digest struct {
	c         Compressor
	size      int // number of bytes in a hash output
	blockSize int // number of bytes in an input block, per compression

	h   []byte // hash chain (from last compression, or IV)
	x   []byte // data written since last compression
	nx  int    // number of input bytes written since last compression
	len uint64 // total number of input bytes written overall

	salt []byte // salt block
}

// New returns a new hash.Hash computing a sumhash checksum.
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be BlockSize(c) bytes, and the hash is computed in salted mode.
// the context returned by this function reference the salt argument. any changes
// might affect the hash calculation
func New(c Compressor, salt []byte) (hash.Hash, error) {
	d := new(digest)
	d.c = c
	d.size = d.c.OutputLen()
	d.blockSize = d.c.InputLen() - d.size
	d.x = make([]byte, d.blockSize)
	d.h = make([]byte, c.OutputLen())

	if salt != nil && len(salt) != d.blockSize {
		return nil, fmt.Errorf("bad salt size: want %d, got %d", d.blockSize, len(salt))
	}
	d.salt = salt

	d.Reset()
	return d, nil
}

func (d *digest) Reset() {
	for i := range d.h {
		d.h[i] = 0 // all-zeros initialization vector
	}
	d.nx = 0
	d.len = 0

	if d.salt != nil {
		// Write an initial block of zeros, effectively
		// prepending the salt to the input.
		zeros := make([]byte, d.blockSize)
		d.Write(zeros)
	}
}

func (d *digest) Size() int {
	return d.size
}

func (d *digest) BlockSize() int {
	return d.blockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)

	// Check if the new length (in bits) overflows our counter capacity.
	if uint64(nn) >= (1<<61)-d.len {
		return 0, fmt.Errorf("length overflow: already wrote %d bytes, trying to write %d bytes", d.len, nn)
	}

	d.len += uint64(nn)
	if d.nx > 0 { // continue with existing buffer, if nonempty
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == d.blockSize {
			blocks(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= d.blockSize { // handle any remaining full input blocks
		n := len(p) / d.blockSize * d.blockSize
		blocks(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 { // handle any remaining input
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) copy() *digest {
	dd := &digest{
		c:         d.c,
		size:      d.size,
		blockSize: d.blockSize,
		h:         make([]byte, len(d.h)),
		x:         make([]byte, len(d.x)),
		nx:        d.nx,
		len:       d.len,
		salt:      d.salt,
	}
	copy(dd.h, d.h)
	copy(dd.x, d.x)
	return dd
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := d.copy()
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
	B := uint64(d.blockSize)
	P := B - 16

	bitlen := d.len << 3 // number of input bits written

	// Padding. Add a 1 bit and 0 bits until P bytes mod B.
	tmp := make([]byte, B)
	tmp[0] = 0x80
	if d.len%B < P {
		d.Write(tmp[0 : P-d.len%B])
	} else {
		d.Write(tmp[0 : B+P-d.len%B])
	}

	// Write length in bits, using 128 bits (16 bytes) to represent it.
	// The upper 64 bits are always zero, because bitlen has type uint64.
	binary.LittleEndian.PutUint64(tmp[0:], bitlen)
	binary.LittleEndian.PutUint64(tmp[8:], 0)
	d.Write(tmp[0:16])

	if d.nx != 0 { // buffer must be empty now
		panic("d.nx != 0")
	}

	return d.h
}

// blocks hashes full blocks of data. len(data) must be a multiple of d.blockSize.
func blocks(d *digest, data []byte) {
	cin := make([]byte, d.c.InputLen())
	block := cin[d.size : d.size+d.blockSize]
	for i := 0; i <= len(data)-d.blockSize; i += d.blockSize {
		copy(cin[0:d.size], d.h)

		input := data[i : i+d.blockSize]
		if d.salt != nil {
			xorBytes(block, input, d.salt)
		} else {
			copy(block, input)
		}

		d.c.Compress(d.h, cin)
	}
}

func xorBytes(dst []byte, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

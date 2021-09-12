package sumhash

import (
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/sha3"
)

// Matrix is the n×m sumhash matrix A with elements in Z_q where q=2^64
type Matrix [][]uint64

// LookupTable is the precomputed sums from a matrix for every possible byte of input.
// Its dimensions are [n][m/8][256]uint64.
type LookupTable [][][256]uint64

// RandomMatrix generates a random sumhash matrix by reading from rand.
// n is the number of rows in the matrix and m is the number of bits in the input message.
func RandomMatrix(rand io.Reader, n int, m int) (Matrix, error) {
	A := make([][]uint64, n)
	w := make([]byte, 8)
	for i := range A {
		A[i] = make([]uint64, m)
		for j := range A[i] {
			_, err := rand.Read(w)
			if err != nil {
				return nil, err
			}
			A[i][j] = binary.LittleEndian.Uint64(w)
		}
	}
	return A, nil
}

func RandomMatrixFromSeed(seed []byte, n int, m int) (Matrix, error) {
	xof := sha3.NewShake256()
	binary.Write(xof, binary.LittleEndian, uint16(64)) // u=64
	binary.Write(xof, binary.LittleEndian, uint16(n))
	binary.Write(xof, binary.LittleEndian, uint16(m))
	xof.Write(seed)

	return RandomMatrix(xof, n, m)
}

func (A Matrix) LookupTable() LookupTable {
	n := len(A)
	m := len(A[0])
	At := make(LookupTable, n)
	for i := range A {
		At[i] = make([][256]uint64, m/8)

		for j := 0; j < m; j += 8 {
			for b := 0; b < 256; b++ {
				At[i][j/8][b] = sumBits(A[i][j:j+8], byte(b))
			}
		}
	}
	return At
}

func sumBits(as []uint64, b byte) uint64 {
	var x uint64
	for i := 0; i < 8; i++ {
		if b>>i&1 == 1 {
			x += as[i]
		}
	}
	return x
}

type Compressor interface {
	Compress(dst []uint64, msg []byte)
	InputLen() int  // len(msg)
	OutputLen() int // len(dst)
}

func BlockSize(c Compressor) int {
	return c.InputLen() - c.OutputLen()*8
}

func (A Matrix) InputLen() int  { return len(A[0]) / 8 }
func (A Matrix) OutputLen() int { return len(A) }

func (A Matrix) Compress(dst []uint64, msg []byte) {
	_ = msg[len(A[0])/8-1]
	_ = dst[len(A)-1]

	var x uint64
	for i := range A {
		x = 0
		for j := range msg {
			for b := 0; b < 8; b++ {
				if (msg[j]>>b)&1 == 1 {
					x += A[i][8*j+b]
				}
			}
		}
		dst[i] = x
	}
}

func (A LookupTable) InputLen() int  { return len(A[0]) }
func (A LookupTable) OutputLen() int { return len(A) }

func (A LookupTable) Compress(dst []uint64, msg []byte) {
	_ = msg[len(A[0])-1]
	_ = dst[len(A)-1]

	var x uint64
	for i := range A {
		x = 0
		for j := range A[i] {
			x += A[i][j][msg[j]]
		}
		dst[i] = x
	}
}

// digest implementation is based on https://cs.opensource.google/go/go/+/refs/tags/go1.16.6:src/crypto/sha256/sha256.go
type digest struct {
	c         Compressor
	size      int
	blockSize int

	h   []uint64
	x   []byte
	nx  int
	len uint64

	salt []byte // salt block
}

// New returns a new hash.Hash computing a sumhash checksum.
// If salt is nil, then hash.Hash computes a hash output in unsalted mode.
// Otherwise, salt should be BlockSize(c) bytes, and the hash is computed in salted mode.
func New(c Compressor, salt []byte) hash.Hash {
	d := new(digest)
	d.c = c
	d.size = d.c.OutputLen() * 8
	d.blockSize = d.c.InputLen() - d.size
	d.x = make([]byte, d.blockSize)
	d.h = make([]uint64, c.OutputLen())

	if salt != nil && len(salt) != d.blockSize {
		panic(fmt.Sprintf("bad salt size: want %d, got %d", d.blockSize, len(salt)))
	}
	d.salt = salt

	d.Reset()
	return d
}

func (d *digest) Reset() {
	for i := range d.h {
		d.h[i] = 0
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

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return d.blockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	// Check if the new length (in bits) overflows.
	if uint64(nn) >= (1<<61)-d.len {
		panic("digest length overflows")
	}
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == d.blockSize {
			blocks(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= d.blockSize {
		n := len(p) / d.blockSize * d.blockSize
		blocks(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) copy() *digest {
	dd := &digest{
		c:         d.c,
		size:      d.size,
		blockSize: d.blockSize,
		h:         make([]uint64, len(d.h)),
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
	var B uint64 = uint64(d.blockSize)
	var P uint64 = B - 16

	len := d.len << 3
	// Padding. Add a 1 bit and 0 bits until P bytes mod B.
	tmp := make([]byte, B)
	tmp[0] = 0x80
	if d.len%B < P {
		d.Write(tmp[0 : P-d.len%B])
	} else {
		d.Write(tmp[0 : B+P-d.len%B])
	}

	// Length in bits. Note: sumhash uses 128 bits to represent the length.
	binary.LittleEndian.PutUint64(tmp[0:], len)
	binary.LittleEndian.PutUint64(tmp[8:], 0) // upper 64 bits are always zero, because len variable has type uint64
	d.Write(tmp[0:16])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	digest := make([]byte, d.size)
	for i := range d.h {
		binary.LittleEndian.PutUint64(digest[8*i:8*i+8], d.h[i])
	}
	return digest
}

func blocks(d *digest, data []byte) {
	cin := make([]byte, d.c.InputLen())
	block := cin[d.size : d.size+d.blockSize]
	for i := 0; i <= len(data)-d.blockSize; i += d.blockSize {
		for j := range d.h {
			binary.LittleEndian.PutUint64(cin[8*j:8*j+8], d.h[j])
		}

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

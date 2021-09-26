package sumhash

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/sha3"
)

// Matrix is the n-by-m sumhash matrix A with elements in Z_q where q=2^64
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
	Compress(dst []byte, input []byte)
	InputLen() int  // len(input)
	OutputLen() int // len(dst)
}

func BlockSize(c Compressor) int {
	return c.InputLen() - c.OutputLen()
}

func (A Matrix) InputLen() int  { return len(A[0]) / 8 }
func (A Matrix) OutputLen() int { return len(A) * 8 }

func (A Matrix) Compress(dst []byte, msg []byte) {
	_ = msg[len(A[0])/8-1]
	_ = dst[len(A)*8-1]

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
		binary.LittleEndian.PutUint64(dst[8*i:8*i+8], x)
	}
}

func (A LookupTable) InputLen() int  { return len(A[0]) }
func (A LookupTable) OutputLen() int { return len(A) * 8 }

func (A LookupTable) Compress(dst []byte, msg []byte) {
	_ = msg[len(A[0])-1]
	_ = dst[len(A)*8-1]

	var x uint64
	for i := range A {
		x = 0
		for j := range A[i] {
			x += A[i][j][msg[j]]
		}
		binary.LittleEndian.PutUint64(dst[8*i:8*i+8], x)
	}
}

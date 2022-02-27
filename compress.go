package sumhash

import (
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
)

// Matrix is the n-by-m sumhash matrix A with elements in Z_q where q=2^64
type Matrix [][]uint64

// LookupTable is the precomputed sums from a matrix for every possible byte of input.
// Its dimensions are [n][m/8][256]uint64.
type LookupTable [][][256]uint64

// RandomMatrix generates a random sumhash matrix by reading from rand. n is the
// number of rows in the matrix and m is the number of bits in the input
// message. m must be a multiple of 8. Each byte read from rand is interpreted
// as an 8-bit string in LE/LSB encoding, consistent with SHA-3 (NIST FIPS 202,
// Appendix B). See also: https://keccak.team/keccak_bits_and_bytes.html
func RandomMatrix(rand io.Reader, n int, m int) (Matrix, error) {
	if m%8 != 0 {
		panic(fmt.Errorf("m=%d is not a multiple of 8", m))
	}

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

// RandomMatrixFromSeed creates a random-looking matrix to be used for the
// sumhash function using the seed bytes. n and m are the rows and columns of
// the matrix respectively.
func RandomMatrixFromSeed(seed []byte, n int, m int) (Matrix, error) {
	xof := sha3.NewShake256()
	// SHAKE treats bytes as LSB-first 8-bit strings, so this conforms to the sumhash spec.
	binary.Write(xof, binary.LittleEndian, uint16(64)) // u=64
	binary.Write(xof, binary.LittleEndian, uint16(n))
	binary.Write(xof, binary.LittleEndian, uint16(m))
	xof.Write(seed)

	return RandomMatrix(xof, n, m)
}

// LookupTable generates a lookup table used to increase hash calculation performance.
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
	//the following code is an optimization for this loop
	//	for i := 0; i < 8; i++ {
	//			if b>>i&1 == 1 {
	//					x += as[i]
	//				}
	//		}
	a0 := as[0] & -uint64(b&1)
	a1 := as[1] & -uint64((b>>1)&1)
	a2 := as[2] & -uint64((b>>2)&1)
	a3 := as[3] & -uint64((b>>3)&1)
	a4 := as[4] & -uint64((b>>4)&1)
	a5 := as[5] & -uint64((b>>5)&1)
	a6 := as[6] & -uint64((b>>6)&1)
	a7 := as[7] & -uint64((b>>7)&1)
	return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7
}

// Compressor represents the compression function which is performed on a message
type Compressor interface {
	Compress(dst []byte, input []byte)
	InputLen() int  // len(input)
	OutputLen() int // len(dst)
}

// BlockSize returns the block size in bytes
func BlockSize(c Compressor) int {
	return c.InputLen() - c.OutputLen()
}

// InputLen returns the valid length of a message in bytes
func (A Matrix) InputLen() int {
	return len(A[0]) / 8
}

// OutputLen returns the output len in bytes of the compression function
func (A Matrix) OutputLen() int { return len(A) * 8 }

// Compress performs the compression algorithm on a message and output into dst
func (A Matrix) Compress(dst []byte, msg []byte) {
	if len(msg) != A.InputLen() {
		panic(fmt.Errorf("could not compress message. input size is wrong. size is %d, expected %d", len(msg), A.InputLen()))
	}
	if len(dst) != A.OutputLen() {
		panic(fmt.Errorf("could not compress message. output size is wrong size is %d, expected %d", len(dst), A.OutputLen()))
	}

	// this allows go to eliminate the bound check when accessing the slice
	_ = msg[A.InputLen()-1]
	_ = dst[A.OutputLen()-1]

	var x uint64
	for i := range A {
		x = 0
		for j := range msg {
			//the following code is an optimization for this loop
			//			for b := 0; b < 8; b++ {
			//					if (msg[j]>>b)&1 == 1 {
			//							x += A[i][8*j+b]
			//						}
			//				}
			a0 := A[i][8*j] & -uint64(msg[j]&1)
			a1 := A[i][8*j+1] & -uint64((msg[j]>>1)&1)
			a2 := A[i][8*j+2] & -uint64((msg[j]>>2)&1)
			a3 := A[i][8*j+3] & -uint64((msg[j]>>3)&1)
			a4 := A[i][8*j+4] & -uint64((msg[j]>>4)&1)
			a5 := A[i][8*j+5] & -uint64((msg[j]>>5)&1)
			a6 := A[i][8*j+6] & -uint64((msg[j]>>6)&1)
			a7 := A[i][8*j+7] & -uint64((msg[j]>>7)&1)
			x += a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7
		}
		binary.LittleEndian.PutUint64(dst[8*i:8*i+8], x)
	}
}

// InputLen returns the valid length of a message in bytes
func (A LookupTable) InputLen() int {
	return len(A[0])
}

// OutputLen returns the output len in bytes of the compression function
func (A LookupTable) OutputLen() int {
	return len(A) * 8
}

// Compress performs the compression algorithm on a message and output into dst
func (A LookupTable) Compress(dst []byte, msg []byte) {
	if len(msg) != A.InputLen() {
		panic(fmt.Errorf("could not compress message. input size is wrong. size is %d, expected %d", len(msg), A.InputLen()))
	}
	if len(dst) != A.OutputLen() {
		panic(fmt.Errorf("could not compress message. output size is wrong size is %d, expected %d", len(dst), A.OutputLen()))
	}

	// this allows go to eliminate the bound check when accessing the slice
	_ = msg[A.InputLen()-1]
	_ = dst[A.OutputLen()-1]

	var x uint64
	for i := range A {
		x = 0
		for j := range A[i] {
			x += A[i][j][msg[j]]
		}
		binary.LittleEndian.PutUint64(dst[8*i:8*i+8], x)
	}
}

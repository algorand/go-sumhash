package sumhash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestExpectedOutput(t *testing.T) {
	A, err := RandomMatrixFromSeed([]byte("Algorand"), 10, 10*64*2)
	if err != nil {
		panic(err)
	}
	h := sumhashNew(A, nil)

	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h.Write(input)
	sum := h.Sum(nil)
	expectedSum := "cedae6c2ac201c6d79b5f8af41ceee8d9506adda4f79ab697aed9865773be0912313c6b28b696b219d512b245103830d3e33e541f702d4b9b0395c2dc54781aec9c83c8725e4ee7a608092847d32f037"
	if hex.EncodeToString(sum) != expectedSum {
		t.Fatalf("got %x, want %s", sum, expectedSum)
	}

	salt := make([]byte, BlockSize(A))
	v.Reset()
	v.Write([]byte("sumhash salt"))
	v.Read(salt)

	hs := sumhashNew(A, salt)
	hs.Write(input)
	saltedSum := hs.Sum(nil)
	expectedSaltedSum := "18ff67b5a2f6f864cd046845f036d2a2be5e91c0324610fdf48921c71382decfdba1c0f619b190953f46c9bb68fb4483300af30f86a62fec384f8c9f4ed6da2debaeec681240362ce7c872cd4b82cad1"
	if hex.EncodeToString(saltedSum) != expectedSaltedSum {
		t.Fatalf("got %x, want %s", saltedSum, expectedSaltedSum)
	}
}

func TestHash(t *testing.T) {
	testHashParams(t, 14, 14*64*4)
	testHashParams(t, 10, 10*64*2)
}

func testHashParams(t *testing.T, n int, m int) {
	A, err := RandomMatrix(rand.Reader, n, m)
	if err != nil {
		t.Fatal(err)
	}
	At := A.LookupTable()

	h1 := sumhashNew(A, nil)
	h2 := sumhashNew(At, nil)

	if h1.Size() != n*8 || h1.BlockSize() != m/8-n*8 {
		t.Fatalf("h1 has unexpected size/blocksize values")
	}
	if h2.Size() != n*8 || h2.BlockSize() != m/8-n*8 {
		t.Fatalf("h2 has unexpected size/blocksize values")
	}

	for _, l := range []int{1, 64, 100, 128, A.InputLen(), 6000, 6007} {
		msg := make([]byte, l)
		rand.Read(msg)

		_, err := h1.Write(msg)
		if err != nil {
			panic(err)
		}
		_, err = h2.Write(msg)
		if err != nil {
			panic(err)
		}

		d1 := h1.Sum(nil)
		d2 := h2.Sum(nil)

		if !bytes.Equal(d1, d2) {
			t.Fatalf("matrix and lookup table hashes differ")
		}

		h1.Reset()
		h2.Reset()
	}
}

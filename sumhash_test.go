package sumhash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestHash(t *testing.T) {
	testHashParams(t, 14, 14*64*4)
	testHashParams(t, 10, 10*64*2)
}

func TestHashResult(t *testing.T) {

	var testElement = [...]string{
		"1234567890",
		"87cf194291b5b6e82f5923944aa42a286704930e7e2d2b8d4e98481ceb52b404ef544075d4ea52a1936f75e1b99fab29fe73c59bef74285556ae39274cf01d6018b8cb67118fe0b52e31f68130b614dec2907ed2589ad0be231b84c7dd828167073152d7720175fe6d85c57acb9d4f1c"}

	A, err := RandomMatrixFromSeed([]byte{0x11, 0x22, 0x33, 0x44}, 14, 14*64*4)
	if err != nil {
		t.Error(err)
	}
	At := A.LookupTable()

	h1, err := New(A, nil)
	if err != nil {
		t.Error(err)
	}
	h2, err := New(At, nil)
	if err != nil {
		t.Error(err)
	}

	bytesWritten, err := io.WriteString(h1, testElement[0])
	if err != nil || bytesWritten != len(testElement[0]) {
		t.Error(err)
	}

	bytesWritten, err = io.WriteString(h2, testElement[0])
	if err != nil || bytesWritten != len(testElement[0]) {
		t.Error(err)
	}

	digset1 := h1.Sum(nil)
	digset2 := h2.Sum(nil)

	if !bytes.Equal(digset1, digset2) {
		t.Errorf("matrix and lookup table hashes differ")
	}
	result, err := hex.DecodeString(testElement[1])
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(digset1, result) {

		t.Errorf("result is: %s expected: %s", hex.EncodeToString(digset1), hex.EncodeToString(result))
	}

}

func testHashParams(t *testing.T, n int, m int) {
	A, err := RandomMatrix(rand.Reader, n, m)
	if err != nil {
		t.Fatal(err)
	}
	At := A.LookupTable()

	h1, err := New(A, nil)
	if err != nil {
		t.Error(err)
	}
	h2, err := New(At, nil)
	if err != nil {
		t.Error(err)
	}

	if h1.Size() != n*8 || h1.BlockSize() != m/8-n*8 {
		t.Errorf("h1 has unexpected size/blocksize values")
	}
	if h2.Size() != n*8 || h2.BlockSize() != m/8-n*8 {
		t.Errorf("h2 has unexpected size/blocksize values")
	}

	for _, l := range []int{1, 64, 100, 128, A.InputLen(), 6000, 6007} {
		msg := make([]byte, l)
		rand.Read(msg)

		_, err := h1.Write(msg)
		if err != nil {
			t.Error(err)
		}
		_, err = h2.Write(msg)
		if err != nil {
			t.Error(err)
		}

		digset1 := h1.Sum(nil)

		digset2 := h2.Sum(nil)

		if !bytes.Equal(digset1, digset2) {
			t.Errorf("matrix and lookup table hashes differ")
		}

		h1.Reset()
		h2.Reset()
	}
}

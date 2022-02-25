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
		"fc91828801365750f0267edd5530a301d1471736c485472bbadf22507731a81fd67e0d80cce722a81c6dc690b698f5771713855c5d1927488d79713e3abd81053de2c7db1430b8fb106b3f6aa6b93e54aec351e47bcc176c0df58a0336d24979a064f3acb67a693db399c6402149157b",
	}

	A, err := RandomMatrixFromSeed([]byte{0x11, 0x22, 0x33, 0x44}, 14, 14*64*4)
	if err != nil {
		t.Error(err)
	}
	At := A.LookupTable()

	h1 := New(A, nil)
	h2 := New(At, nil)

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

	h1 := New(A, nil)
	h2 := New(At, nil)

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

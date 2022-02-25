package sumhash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/sha3"
)

type testElement struct {
	input  string
	output string
}

var testVector = []testElement{
	{
		"",
		"591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0",
	},
	{
		"a",
		"ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6",
	},
	{
		"ab",
		"ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694",
	},
	{
		"abc",
		"a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4",
	},
	{
		"abcd",
		"1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b",
	},
	{
		"You must be the change you wish to see in the world. -Mahatma Gandhi",
		"5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5",
	},
	{
		"I think, therefore I am. – Rene Descartes.",
		"2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a",
	},
}

func TestSumHash512TestVector(t *testing.T) {
	for i, element := range testVector {
		h := New512(nil)

		bytesWritten, err := io.WriteString(h, element.input)
		if err != nil {
			t.Errorf("write returned error : %s", err)
		}

		if bytesWritten != len(element.input) {
			t.Errorf("write return %d expected %d", bytesWritten, len(element.input))
		}
		output := h.Sum(nil)
		if hex.EncodeToString(output) != element.output {
			t.Errorf("test vector element mismatched on index %d failed! got %s, want %s", i, hex.EncodeToString(output), element.output)
		}
	}

}

func TestSumHash512(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New512(nil)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6"
	if hex.EncodeToString(sum) != expectedSum {
		t.Errorf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512WithSalt(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	salt := make([]byte, 64)
	v = sha3.NewShake256()
	v.Write([]byte("sumhash salt"))
	v.Read(salt)

	h := New512(salt)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}
	sum := h.Sum(nil)
	expectedSum := "c9be08eed13218c30f8a673f7694711d87dfec9c7b0cb1c8e18bf68420d4682530e45c1cd5d886b1c6ab44214161f06e091b0150f28374d6b5ca0c37efc2bca7"
	if hex.EncodeToString(sum) != expectedSum {
		t.Errorf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512Reset(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash"))
	v.Read(input)

	h := New512(nil)
	h.Write(input)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	input = make([]byte, 6000)
	v = sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h.Reset()
	bytesWritten, err = h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6"
	if hex.EncodeToString(sum) != expectedSum {
		t.Errorf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512ChecksumWithValue(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New512(nil)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Errorf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Errorf("write return %d expected %d", bytesWritten, len(input))
	}

	msgPrefix := make([]byte, 64)
	rand.Read(msgPrefix)
	sum := h.Sum(msgPrefix)
	dec, err := hex.DecodeString("43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6")
	expectedSum := append(msgPrefix, dec...)
	if !bytes.Equal(sum, expectedSum) {
		t.Errorf("got %x, want %x", sum, expectedSum)
	}
}

func TestSumHash512Sizes(t *testing.T) {
	h := New512(nil)
	blockSize := h.BlockSize()
	expectedBlockSizeInBytes := 512 / 8
	if blockSize != expectedBlockSizeInBytes {
		t.Errorf("got block size %d, want %d", blockSize, expectedBlockSizeInBytes)
	}

	size := h.Size()
	expectedSizeInBytes := 512 / 8
	if size != expectedSizeInBytes {
		t.Errorf("got block size %d, want %d", blockSize, expectedBlockSizeInBytes)
	}
}

func BenchmarkHashInterface(b *testing.B) {
	msg := make([]byte, 600)

	rand.Read(msg)
	h := New512(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(msg)
		_ = h.Sum(nil)
	}
}

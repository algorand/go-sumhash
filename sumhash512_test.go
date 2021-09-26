package sumhash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestSumHash512(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New(nil)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Fatalf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Fatalf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa"
	if hex.EncodeToString(sum) != expectedSum {
		t.Fatalf("got %x, want %s", sum, expectedSum)
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

	h := New(salt)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Fatalf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Fatalf("write return %d expected %d", bytesWritten, len(input))
	}
	sum := h.Sum(nil)
	expectedSum := "bc0f4251957352da5102970a32ecad694d88e9f9c4230a2b13d2c7037107245e64e1f7e7dbeca625e2f7d1cd5f63d9070e0255b687301ade29fab952dd44abc7"
	if hex.EncodeToString(sum) != expectedSum {
		t.Fatalf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512Reset(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash"))
	v.Read(input)

	h := New(nil)
	h.Write(input)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Fatalf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Fatalf("write return %d expected %d", bytesWritten, len(input))
	}

	input = make([]byte, 6000)
	v = sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h.Reset()
	bytesWritten, err = h.Write(input)
	if err != nil {
		t.Fatalf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Fatalf("write return %d expected %d", bytesWritten, len(input))
	}

	sum := h.Sum(nil)
	expectedSum := "1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa"
	if hex.EncodeToString(sum) != expectedSum {
		t.Fatalf("got %x, want %s", sum, expectedSum)
	}
}

func TestSumHash512ChecksumWithValue(t *testing.T) {
	input := make([]byte, 6000)
	v := sha3.NewShake256()
	v.Write([]byte("sumhash input"))
	v.Read(input)

	h := New(nil)
	bytesWritten, err := h.Write(input)
	if err != nil {
		t.Fatalf("write returned error : %s", err)
	}

	if bytesWritten != len(input) {
		t.Fatalf("write return %d expected %d", bytesWritten, len(input))
	}

	msgPrefix := make([]byte, 64)
	rand.Read(msgPrefix)
	sum := h.Sum(msgPrefix)
	dec, err := hex.DecodeString("1ad6dafe03f330e06554300ecc24a59d41ec6afe387c34f4d9a2d971e71ae751823f520135cdc766ba7886a0a2a8954fd17ecae64f58e4431e572571e0f0a9aa")
	expectedSum := append(msgPrefix, dec...)
	if !bytes.Equal(sum, expectedSum) {
		t.Fatalf("got %x, want %s", hex.EncodeToString(sum), hex.EncodeToString(expectedSum))
	}
}

func BenchmarkHashInterface(b *testing.B) {
	msg := make([]byte, 600)

	rand.Read(msg)
	h := New(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(msg)
		_ = h.Sum(nil)
	}
}

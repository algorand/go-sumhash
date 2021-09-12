package sumhash

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestCompression(t *testing.T) {
	n := 14
	m := n * 64 * 2
	A, err := RandomMatrix(rand.Reader, n, m)
	if err != nil {
		t.Fatal(err)
	}
	At := A.LookupTable()

	if A.InputLen() != m/8 {
		t.Fatalf("unexpected input len (A): got %d, want %d", A.InputLen(), m/8)
	}
	if At.InputLen() != m/8 {
		t.Fatalf("unexpected input len (At): got %d, want %d", At.InputLen(), m/8)
	}

	if A.OutputLen() != n {
		t.Fatalf("unexpected output len (A): got %d, want %d", A.OutputLen(), n)
	}
	if At.OutputLen() != n {
		t.Fatalf("unexpected output len (At): got %d, want %d", At.OutputLen(), n)
	}

	dst1 := make([]uint64, A.OutputLen())
	dst2 := make([]uint64, A.OutputLen())
	msg := make([]byte, A.InputLen())

	count := 1000
	for i := 0; i < count; i++ {
		rand.Read(msg)
		A.Compress(dst1, msg)
		At.Compress(dst2, msg)
		if !reflect.DeepEqual(dst1, dst2) {
			t.Fatalf("compressed outputs differ")
		}
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

	h1 := New(A, nil)
	h2 := New(At, nil)

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

func BenchmarkMatrix(b *testing.B) {
	A, err := RandomMatrix(rand.Reader, 14, 14*64*2)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, A.InputLen())
	dst := make([]uint64, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		A.Compress(dst, msg)
	}
}

func BenchmarkLookupTable(b *testing.B) {
	A, err := RandomMatrix(rand.Reader, 14, 14*64*2)
	if err != nil {
		b.Fatal(err)
	}
	At := A.LookupTable()
	msg := make([]byte, A.InputLen())
	dst := make([]uint64, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		At.Compress(dst, msg)
	}
}

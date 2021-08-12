package sumhash

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestCompression(t *testing.T) {
	N := 14
	C := 4
	A := RandomMatrix(rand.Reader, N, C)
	At := A.LookupTable()

	expectedInputBytes := C * N * 8
	if A.InputLen() != expectedInputBytes {
		t.Fatalf("unexpected input len (A): got %d, want %d", A.InputLen(), expectedInputBytes)
	}
	if At.InputLen() != expectedInputBytes {
		t.Fatalf("unexpected input len (At): got %d, want %d", At.InputLen(), expectedInputBytes)
	}

	if A.OutputLen() != N {
		t.Fatalf("unexpected output len (A): got %d, want %d", A.OutputLen(), N)
	}
	if At.OutputLen() != N {
		t.Fatalf("unexpected output len (At): got %d, want %d", At.OutputLen(), N)
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
	testHashParams(t, 14, 4)
	testHashParams(t, 10, 2)
}

func testHashParams(t *testing.T, N int, C int) {
	A := RandomMatrix(rand.Reader, N, C)
	At := A.LookupTable()

	h1 := New(A)
	h2 := New(At)

	M := N * C * 64
	if h1.Size() != N*8 || h1.BlockSize() != M/8-N*8 {
		t.Fatalf("h1 has unexpected size/blocksize values")
	}
	if h2.Size() != N*8 || h2.BlockSize() != M/8-N*8 {
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
	A := RandomMatrix(rand.Reader, 14, 4)
	msg := make([]byte, A.InputLen())
	dst := make([]uint64, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		A.Compress(dst, msg)
	}
}

func BenchmarkLookupTable(b *testing.B) {
	A := RandomMatrix(rand.Reader, 14, 4)
	At := A.LookupTable()
	msg := make([]byte, A.InputLen())
	dst := make([]uint64, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		At.Compress(dst, msg)
	}
}

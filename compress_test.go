package sumhash

import (
	"crypto/rand"

	"reflect"
	"testing"
)

func TestCompression(t *testing.T) {
	n := 14
	m := n * 64 * 2
	A, err := RandomMatrix(rand.Reader, n, m)
	if err != nil {
		t.Error(err)
	}
	At := A.LookupTable()

	if A.InputLen() != m/8 {
		t.Errorf("unexpected input len (A): got %d, want %d", A.InputLen(), m/8)
	}
	if At.InputLen() != m/8 {
		t.Errorf("unexpected input len (At): got %d, want %d", At.InputLen(), m/8)
	}

	if A.OutputLen() != n*8 {
		t.Errorf("unexpected output len (A): got %d, want %d", A.OutputLen(), n*8)
	}
	if At.OutputLen() != n*8 {
		t.Errorf("unexpected output len (At): got %d, want %d", At.OutputLen(), n*8)
	}

	dst1 := make([]byte, A.OutputLen())
	dst2 := make([]byte, A.OutputLen())
	msg := make([]byte, A.InputLen())

	count := 1000
	for i := 0; i < count; i++ {
		rand.Read(msg)
		A.Compress(dst1, msg)
		At.Compress(dst2, msg)
		if !reflect.DeepEqual(dst1, dst2) {
			t.Errorf("compressed outputs differ")
		}
	}
}

func BenchmarkMatrix(b *testing.B) {
	A, err := RandomMatrix(rand.Reader, 8, 1024)
	if err != nil {
		b.Error(err)
	}
	msg := make([]byte, A.InputLen())
	dst := make([]byte, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		A.Compress(dst, msg)
		copy(msg[0:64], msg[64:128])
		copy(msg[64:128], dst)
	}
}

func BenchmarkLookupTable(b *testing.B) {
	A, err := RandomMatrix(rand.Reader, 8, 1024)
	if err != nil {
		b.Error(err)
	}

	At := A.LookupTable()

	msg := make([]byte, A.InputLen())
	dst := make([]byte, A.OutputLen())
	rand.Read(msg)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		At.Compress(dst, msg)
		copy(msg[0:64], msg[64:128])
		copy(msg[64:128], dst)
	}
}

func BenchmarkCreateLookupTable(b *testing.B) {
	A, err := RandomMatrix(rand.Reader, 8, 1024)
	if err != nil {
		b.Error(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = A.LookupTable()
	}

}


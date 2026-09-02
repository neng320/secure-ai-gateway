package securegen

import (
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHexPreservesBoundedLengthAndFormat(t *testing.T) {
	for _, length := range []int{20, 32} {
		value, err := Hex(length)
		if err != nil {
			t.Fatalf("Hex(%d): %v", length, err)
		}
		if len(value) != length {
			t.Fatalf("Hex(%d) length=%d", length, len(value))
		}
		if _, err := hex.DecodeString(value); err != nil {
			t.Fatalf("Hex(%d) is not hexadecimal: %q: %v", length, value, err)
		}
	}
}

func TestHexEntropyFailureReturnsNoCredential(t *testing.T) {
	original := entropyReader
	t.Cleanup(func() { entropyReader = original })
	want := errors.New("entropy unavailable")
	entropyReader = failingReader{err: want}

	value, err := Hex(32)
	if !errors.Is(err, want) {
		t.Fatalf("Hex error=%v, want %v", err, want)
	}
	if value != "" {
		t.Fatalf("entropy failure returned credential %q", value)
	}
}

func TestHexShortEntropyReadFailsClosed(t *testing.T) {
	original := entropyReader
	t.Cleanup(func() { entropyReader = original })
	entropyReader = strings.NewReader("short")

	value, err := Hex(32)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Hex error=%v, want io.ErrUnexpectedEOF", err)
	}
	if value != "" {
		t.Fatalf("short read returned partial credential %q", value)
	}
}

func TestHexRejectsInvalidLength(t *testing.T) {
	for _, length := range []int{-1, 0, 4097} {
		value, err := Hex(length)
		if err == nil {
			t.Fatalf("Hex(%d) unexpectedly succeeded with %q", length, value)
		}
		if value != "" {
			t.Fatalf("Hex(%d) returned credential %q on invalid length", length, value)
		}
	}
}

func TestHexRepeatedSuccessesKeepContract(t *testing.T) {
	for i := 0; i < 20; i++ {
		value, err := Hex(32)
		if err != nil || len(value) != 32 {
			t.Fatalf("iteration %d: value=%q err=%v", i, value, err)
		}
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

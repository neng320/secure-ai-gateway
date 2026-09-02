// Package securegen provides bounded credential generation backed by crypto/rand.
package securegen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// entropyReader is package-local so tests can exercise read failures without a
// production flag or mutable credential state. Production uses crypto/rand.Reader.
var entropyReader io.Reader = rand.Reader

// Hex returns exactly length lowercase hexadecimal characters. It never returns
// a partial value when entropy acquisition fails.
func Hex(length int) (string, error) {
	if length <= 0 || length > 4096 {
		return "", fmt.Errorf("secure credential generation: invalid length %d", length)
	}
	bytes := make([]byte, (length+1)/2)
	if _, err := io.ReadFull(entropyReader, bytes); err != nil {
		return "", fmt.Errorf("secure credential generation: %w", err)
	}
	return hex.EncodeToString(bytes)[:length], nil
}

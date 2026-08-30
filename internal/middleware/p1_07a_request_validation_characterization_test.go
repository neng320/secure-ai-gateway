package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestP107A_MaxRequestSizeCurrentHardCap(t *testing.T) {
	const maxSize = int64(10 << 20)
	for _, tc := range []struct {
		name          string
		contentLength int64
	}{
		{name: "content-length", contentLength: maxSize + 1},
		{name: "chunked", contentLength: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := make([]byte, maxSize+1)
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &byteReader{body: body})
			req.ContentLength = tc.contentLength
			var read int
			var readErr error
			h := MaxRequestSize(maxSize)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var data []byte
				data, readErr = io.ReadAll(r.Body)
				read = len(data)
				if readErr != nil {
					// Characterize the current handler-visible error mapping;
					// P1-07B will define a stable 413 contract.
					http.Error(w, readErr.Error(), http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if readErr == nil || read > int(maxSize) {
				t.Fatalf("body cap failed for %s: read=%d err=%v", tc.name, read, readErr)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("current handler-visible oversize mapping for %s: got status %d", tc.name, w.Code)
			}
			t.Logf("[CURRENT] %s body is bounded at %d bytes but caller maps MaxBytesError to HTTP 400", tc.name, maxSize)
		})
	}
}

// byteReader lets the characterization set ContentLength independently from
// the body source without changing the production request path.
type byteReader struct {
	body []byte
	off  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.body) {
		return 0, io.EOF
	}
	n := copy(p, r.body[r.off:])
	r.off += n
	return n, nil
}

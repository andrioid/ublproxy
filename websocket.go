package main

import (
	"io"
	"net/http"
	"strings"
)

// isWebSocketUpgrade returns true if the request is a WebSocket upgrade.
func isWebSocketUpgrade(h http.Header) bool {
	return strings.EqualFold(h.Get("Upgrade"), "websocket")
}

// readerWriter combines separate io.Reader and io.Writer into an
// io.ReadWriter. Used in CONNECT tunnels where reads come from a
// bufio.Reader (which may have buffered data) while writes go to
// the raw TLS connection.
type readerWriter struct {
	r io.Reader
	w io.Writer
}

func (rw *readerWriter) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readerWriter) Write(p []byte) (int, error) { return rw.w.Write(p) }

// bidirectionalCopy copies data in both directions between a and b until
// one side closes or errors. Used for WebSocket and other protocol upgrades.
func bidirectionalCopy(a io.ReadWriter, b io.ReadWriter) {
	done := make(chan struct{}, 1)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

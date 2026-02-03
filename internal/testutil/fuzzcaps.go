package testutil

import (
	"testing"
	"time"
)

const (
	DefaultMaxFuzzBytes = 1 << 16
	DefaultFuzzTimeout  = 100 * time.Millisecond
)

func CapBytes(b []byte, max int) []byte {
	if max <= 0 {
		return b
	}
	if len(b) > max {
		return b[:max]
	}
	return b
}

func WithTimeout(t testing.TB, d time.Duration, fn func()) {
	t.Helper()
	if d <= 0 {
		d = DefaultFuzzTimeout
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("timeout after %s", d)
	}
}

package daemon

import (
	"testing"
	"time"
)

func TestRateLimitBeforeDecrypt(t *testing.T) {
	root := t.TempDir()
	r, err := NewRunner(root, Options{})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	origLimiter := recvHostLimiter
	defer func() { recvHostLimiter = origLimiter }()
	limiter := newRateLimiter(1, time.Minute)
	limiter.buckets["127.0.0.1"] = &rateBucket{count: 1, reset: time.Now().Add(time.Minute)}
	recvHostLimiter = limiter

	debugCount = newDebugCounters()

	_, _, recvErr := r.recvDataWithResponse([]byte(`{"type":"secure"}`), "127.0.0.1:1234")
	if recvErr == nil {
		t.Fatalf("expected recv error")
	}
	debugCount.mu.Lock()
	defer debugCount.mu.Unlock()
	if _, ok := debugCount.decryptFail["secure_envelope"]; ok {
		t.Fatalf("expected no decrypt attempt before rate limit")
	}
	if debugCount.dropReason["rate"] != 1 {
		t.Fatalf("expected rate drop, got %+v", debugCount.dropReason)
	}
}

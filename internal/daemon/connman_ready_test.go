package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestConnManStartsAfterReady(t *testing.T) {
	t.Setenv("WEB4_OUTBOUND_TARGET", "1")
	t.Setenv("WEB4_OUTBOUND_EXPLORE", "0")
	oldTick := connManTick
	connManTick = 50 * time.Millisecond
	defer func() { connManTick = oldTick }()

	runner, err := NewRunner(t.TempDir(), Options{Metrics: metrics.New()})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	id := node.DeriveNodeID(pub)
	addr := "127.0.0.1:1"
	p := peer.Peer{NodeID: id, PubKey: pub, Addr: addr}
	_, _ = runner.Self.Peers.SetAddrUnverified(p, addr, false)
	if err := runner.Self.Peers.Upsert(p, false); err != nil {
		t.Fatalf("upsert peer: %v", err)
	}

	var dialCount int32
	connManDialHook = func() {
		atomic.AddInt32(&dialCount, 1)
	}
	defer func() { connManDialHook = nil }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	startConnManWithReady(ctx, runner, false, ready)

	time.Sleep(120 * time.Millisecond)
	if got := atomic.LoadInt32(&dialCount); got != 0 {
		t.Fatalf("expected no dial before ready, got %d", got)
	}

	close(ready)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&dialCount) > 0 {
			cancel()
			time.Sleep(50 * time.Millisecond)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected dial after ready")
}

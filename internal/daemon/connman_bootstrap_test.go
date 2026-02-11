package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
)

func TestBootstrapDiscoveryGrowth(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")
	t.Setenv("WEB4_CONNMAN_TICK_MS", "100")
	t.Setenv("WEB4_PEX_INTERVAL_MS", "200")
	t.Setenv("WEB4_DIAL_TIMEOUT_MS", "500")

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	errBoot := make(chan error, 1)
	errPeer := make(chan error, 1)
	defer func() {
		cancel()
		deadline := time.Now().Add(2 * time.Second)
		for _, ch := range []chan error{errBoot, errPeer} {
			if ch == nil {
				continue
			}
			select {
			case <-ch:
			case <-time.After(time.Until(deadline)):
				return
			}
		}
	}()

	homeBoot := t.TempDir()
	t.Setenv("HOME", homeBoot)
	bootRoot := filepath.Join(homeBoot, ".web4mvp")
	boot, err := NewRunner(bootRoot, Options{Metrics: metrics.New()})
	if err != nil {
		t.Fatalf("bootstrap runner: %v", err)
	}
	bootReady := make(chan string, 1)
	go func() {
		errBoot <- boot.RunWithContext(ctx, "127.0.0.1:0", true, bootReady)
	}()
	var bootAddr string
	select {
	case bootAddr = <-bootReady:
	case <-ctx.Done():
		t.Fatalf("bootstrap did not start: %v", ctx.Err())
	}
	bootCA := filepath.Join(bootRoot, "devtls_ca.pem")
	waitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitDeadline) {
		if fi, err := os.Stat(bootCA); err == nil && fi.Size() > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if fi, err := os.Stat(bootCA); err != nil || fi.Size() == 0 {
		t.Fatalf("bootstrap devtls ca not ready: %v", err)
	}
	homePeer := t.TempDir()
	t.Setenv("HOME", homePeer)
	t.Setenv("WEB4_BOOTSTRAP_ADDRS", bootAddr)
	t.Setenv("WEB4_DEVTLS_CA_PATH", bootCA)
	peerRoot := filepath.Join(homePeer, ".web4mvp")
	peerRunner, err := NewRunner(peerRoot, Options{Metrics: metrics.New()})
	if err != nil {
		t.Fatalf("peer runner: %v", err)
	}
	peerReady := make(chan string, 1)
	go func() {
		errPeer <- peerRunner.RunWithContext(ctx, "127.0.0.1:0", true, peerReady)
	}()
	select {
	case <-peerReady:
	case <-ctx.Done():
		t.Fatalf("peer did not start: %v", ctx.Err())
	}

	deadline := time.Now().Add(4 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		snap := peerRunner.Metrics.Snapshot()
		if snap.PexRespRecvTotal > 0 && snap.PeerTableSize > 0 {
			cancel()
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("peer discovery timeout: %v", ctx.Err())
		}
	}
	snap := peerRunner.Metrics.Snapshot()
	t.Fatalf("peer discovery not observed: peertable=%d pex_resp=%d", snap.PeerTableSize, snap.PexRespRecvTotal)
}

func TestSeedBootstrapInsertedFromAddrsOnly(t *testing.T) {
	t.Setenv("WEB4_BOOTSTRAP_ADDRS", "127.0.0.1:14001,127.0.0.1:14002")
	t.Setenv("WEB4_BOOTSTRAP_IDS", "")

	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	r := &Runner{Self: self, Root: t.TempDir(), Metrics: metrics.New()}
	cm := newConnMan(r, false)
	cm.seedBootstrap()

	peers := self.Peers.List()
	if len(peers) < 2 {
		t.Fatalf("expected seed peers inserted, got %d", len(peers))
	}
	seen := map[string]bool{
		"127.0.0.1:14001": false,
		"127.0.0.1:14002": false,
	}
	for _, p := range peers {
		if _, ok := seen[p.Addr]; ok && p.Source == "seed" {
			seen[p.Addr] = true
		}
	}
	for addr, ok := range seen {
		if !ok {
			t.Fatalf("missing seed peer for %s", addr)
		}
	}
}

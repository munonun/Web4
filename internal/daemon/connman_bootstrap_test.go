package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	const (
		testTimeout   = 20 * time.Second
		startTimeout  = 8 * time.Second
		startAttempts = 2 // initial + 1 retry
	)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	var stops []context.CancelFunc
	var doneChs []chan error
	defer func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
		deadline := time.Now().Add(3 * time.Second)
		for _, ch := range doneChs {
			if ch == nil {
				continue
			}
			wait := time.Until(deadline)
			if wait <= 0 {
				return
			}
			select {
			case <-ch:
			case <-time.After(wait):
				return
			}
		}
	}()

	startRunnerWithRetry := func(label, root, listenAddr string, m *metrics.Metrics) (*Runner, string, error) {
		var lastErr error
		for attempt := 1; attempt <= startAttempts; attempt++ {
			r, err := NewRunner(root, Options{Metrics: m})
			if err != nil {
				return nil, "", err
			}
			runCtx, runCancel := context.WithCancel(ctx)
			readyCh := make(chan string, 1)
			errCh := make(chan error, 1)
			go func() {
				errCh <- r.RunWithContext(runCtx, listenAddr, true, readyCh)
			}()
			select {
			case readyAddr := <-readyCh:
				stops = append(stops, runCancel)
				doneChs = append(doneChs, errCh)
				return r, readyAddr, nil
			case err := <-errCh:
				runCancel()
				lastErr = fmt.Errorf("%s start error (attempt %d/%d): %w", label, attempt, startAttempts, err)
			case <-time.After(startTimeout):
				runCancel()
				lastErr = fmt.Errorf("%s start timeout (attempt %d/%d)", label, attempt, startAttempts)
			case <-ctx.Done():
				runCancel()
				return nil, "", fmt.Errorf("%s context done: %w", label, ctx.Err())
			}
			select {
			case <-errCh:
			case <-time.After(500 * time.Millisecond):
			}
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("%s failed to start", label)
		}
		return nil, "", lastErr
	}

	homeBoot := t.TempDir()
	t.Setenv("HOME", homeBoot)
	bootRoot := filepath.Join(homeBoot, ".web4mvp")
	_, bootAddr, err := startRunnerWithRetry("bootstrap", bootRoot, "127.0.0.1:0", metrics.New())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping bootstrap discovery growth in restricted environment: %v", err)
		}
		t.Fatalf("bootstrap did not start: %v", err)
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
	peerRunner, _, err := startRunnerWithRetry("peer", peerRoot, "127.0.0.1:0", metrics.New())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping bootstrap discovery growth in restricted environment: %v", err)
		}
		t.Fatalf("peer did not start: %v", err)
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

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
	"web4mvp/internal/peer"
)

func TestOutboundOnlyBootstrapDiscovery(t *testing.T) {
	t.Setenv("WEB4_CONNMAN_TICK_MS", "100")
	t.Setenv("WEB4_PEX_INTERVAL_MS", "200")
	t.Setenv("WEB4_DIAL_TIMEOUT_MS", "500")
	const (
		testTimeout  = 20 * time.Second
		startTimeout = 8 * time.Second
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	startListenerRunner := func(label, root string, m *metrics.Metrics) (*Runner, string, context.CancelFunc, <-chan error, error) {
		prevMode, hadMode := os.LookupEnv("WEB4_NODE_MODE")
		_ = os.Setenv("WEB4_NODE_MODE", "peer")
		if label == "bootstrap" {
			_ = os.Setenv("WEB4_NODE_MODE", "bootstrap")
		}
		r, err := NewRunner(root, Options{Metrics: m})
		if hadMode {
			_ = os.Setenv("WEB4_NODE_MODE", prevMode)
		} else {
			_ = os.Unsetenv("WEB4_NODE_MODE")
		}
		if err != nil {
			return nil, "", nil, nil, err
		}
		runCtx, runCancel := context.WithCancel(ctx)
		readyCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			errCh <- r.RunWithContext(runCtx, "127.0.0.1:0", true, readyCh)
		}()
		select {
		case readyAddr := <-readyCh:
			return r, readyAddr, runCancel, errCh, nil
		case err := <-errCh:
			runCancel()
			return nil, "", nil, nil, fmt.Errorf("%s start error: %w", label, err)
		case <-time.After(startTimeout):
			runCancel()
			return nil, "", nil, nil, fmt.Errorf("%s start timeout", label)
		case <-ctx.Done():
			runCancel()
			return nil, "", nil, nil, ctx.Err()
		}
	}

	homeBoot := t.TempDir()
	t.Setenv("HOME", homeBoot)
	bootRoot := filepath.Join(homeBoot, ".web4mvp")
	bootRunner, bootAddr, stopBoot, bootDone, err := startListenerRunner("bootstrap", bootRoot, metrics.New())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping outbound-only bootstrap discovery in restricted environment: %v", err)
		}
		t.Fatalf("bootstrap did not start: %v", err)
	}
	defer stopBoot()
	defer func() {
		select {
		case <-bootDone:
		case <-time.After(2 * time.Second):
		}
	}()

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
		t.Fatalf("peer runner create failed: %v", err)
	}

	peerCtx, stopPeer := context.WithCancel(ctx)
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- peerRunner.RunOutboundOnlyWithContext(peerCtx, true)
	}()
	defer stopPeer()
	defer func() {
		select {
		case <-peerDone:
		case <-time.After(2 * time.Second):
		}
	}()

	deadline := time.Now().Add(6 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		_, peerLearnedBoot := peerRunner.Self.Peers.Get(bootRunner.Self.ID)
		if peerLearnedBoot {
			if strings.TrimSpace(peerRunner.Self.ListenAddr()) != "" {
				t.Fatalf("expected outbound-only peer to have no listen addr, got %q", peerRunner.Self.ListenAddr())
			}
			if bootRunner.Self.Sessions.Has(peerRunner.Self.ID) {
				t.Fatalf("expected bootstrap to establish no hello session with outbound-only peer")
			}
			stopPeer()
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("outbound-only discovery timeout: %v", ctx.Err())
		}
	}
	_, peerLearnedBoot := peerRunner.Self.Peers.Get(bootRunner.Self.ID)
	t.Fatalf("outbound-only discovery not observed: peer_learned_bootstrap=%t peer_listen_addr=%q bootstrap_session=%t",
		peerLearnedBoot, peerRunner.Self.ListenAddr(), bootRunner.Self.Sessions.Has(peerRunner.Self.ID))
}

func TestOutboundOnlyDialsLearnedPeerNotBootstrap(t *testing.T) {
	t.Setenv("WEB4_CONNMAN_TICK_MS", "100")
	t.Setenv("WEB4_PEX_INTERVAL_MS", "200")
	t.Setenv("WEB4_DIAL_TIMEOUT_MS", "500")
	const (
		testTimeout  = 20 * time.Second
		startTimeout = 8 * time.Second
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	startListenerRunner := func(label, root string, m *metrics.Metrics) (*Runner, string, context.CancelFunc, <-chan error, error) {
		prevMode, hadMode := os.LookupEnv("WEB4_NODE_MODE")
		_ = os.Setenv("WEB4_NODE_MODE", "peer")
		if label == "bootstrap" {
			_ = os.Setenv("WEB4_NODE_MODE", "bootstrap")
		}
		r, err := NewRunner(root, Options{Metrics: m})
		if hadMode {
			_ = os.Setenv("WEB4_NODE_MODE", prevMode)
		} else {
			_ = os.Unsetenv("WEB4_NODE_MODE")
		}
		if err != nil {
			return nil, "", nil, nil, err
		}
		runCtx, runCancel := context.WithCancel(ctx)
		readyCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			errCh <- r.RunWithContext(runCtx, "127.0.0.1:0", true, readyCh)
		}()
		select {
		case readyAddr := <-readyCh:
			return r, readyAddr, runCancel, errCh, nil
		case err := <-errCh:
			runCancel()
			return nil, "", nil, nil, fmt.Errorf("%s start error: %w", label, err)
		case <-time.After(startTimeout):
			runCancel()
			return nil, "", nil, nil, fmt.Errorf("%s start timeout", label)
		case <-ctx.Done():
			runCancel()
			return nil, "", nil, nil, ctx.Err()
		}
	}

	homeBoot := t.TempDir()
	t.Setenv("HOME", homeBoot)
	bootRoot := filepath.Join(homeBoot, ".web4mvp")
	bootRunner, bootAddr, stopBoot, bootDone, err := startListenerRunner("bootstrap", bootRoot, metrics.New())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping outbound-only bootstrap learned-peer test in restricted environment: %v", err)
		}
		t.Fatalf("bootstrap did not start: %v", err)
	}
	defer stopBoot()
	defer func() {
		select {
		case <-bootDone:
		case <-time.After(2 * time.Second):
		}
	}()

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

	t.Setenv("WEB4_DEVTLS_CA_PATH", bootCA)

	homeCandidate := t.TempDir()
	t.Setenv("HOME", homeCandidate)
	candidateRoot := filepath.Join(homeCandidate, ".web4mvp")
	candidateRunner, candidateAddr, stopCandidate, candidateDone, err := startListenerRunner("candidate", candidateRoot, metrics.New())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping outbound-only bootstrap learned-peer test in restricted environment: %v", err)
		}
		t.Fatalf("candidate did not start: %v", err)
	}
	defer stopCandidate()
	defer func() {
		select {
		case <-candidateDone:
		case <-time.After(2 * time.Second):
		}
	}()

	if err := bootRunner.Self.Peers.UpsertUnverified(peer.Peer{
		NodeID: candidateRunner.Self.ID,
		PubKey: candidateRunner.Self.PubKey,
		Addr:   candidateAddr,
		Source: "pex",
	}); err != nil {
		t.Fatalf("bootstrap upsert candidate: %v", err)
	}

	homePeer := t.TempDir()
	t.Setenv("HOME", homePeer)
	t.Setenv("WEB4_BOOTSTRAP_ADDRS", bootAddr)
	peerRoot := filepath.Join(homePeer, ".web4mvp")
	peerRunner, err := NewRunner(peerRoot, Options{Metrics: metrics.New()})
	if err != nil {
		t.Fatalf("peer runner create failed: %v", err)
	}

	peerCtx, stopPeer := context.WithCancel(ctx)
	peerDone := make(chan error, 1)
	go func() {
		peerDone <- peerRunner.RunOutboundOnlyWithContext(peerCtx, true)
	}()
	defer stopPeer()
	defer func() {
		select {
		case <-peerDone:
		case <-time.After(2 * time.Second):
		}
	}()

	deadline := time.Now().Add(8 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		if candidateRunner.Self.Sessions.Has(peerRunner.Self.ID) {
			if bootRunner.Self.Sessions.Has(peerRunner.Self.ID) {
				t.Fatalf("expected learned peer handshake on candidate only, but bootstrap session exists")
			}
			stopPeer()
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("outbound-only learned-peer timeout: %v", ctx.Err())
		}
	}
	t.Fatalf("expected learned peer handshake on candidate only: bootstrap_session=%t candidate_session=%t",
		bootRunner.Self.Sessions.Has(peerRunner.Self.ID), candidateRunner.Self.Sessions.Has(peerRunner.Self.ID))
}

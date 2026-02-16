package daemon

import (
	"testing"
	"time"

	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestConnManRecoveryEnterExit(t *testing.T) {
	t.Setenv("WEB4_RECOVERY_MIN_OUTBOUND", "1")
	t.Setenv("WEB4_RECOVERY_GRACE_SEC", "1")
	t.Setenv("WEB4_RECOVERY_STABLE_SEC", "1")
	t.Setenv("WEB4_RECOVERY_WINDOW_SEC", "2")

	m := metrics.New()
	cm := &connMan{
		metrics:  m,
		outbound: make(map[[32]byte]time.Time),
	}
	now := time.Now()

	cm.updateRecoveryState(now)
	if cm.isRecoveryActive() {
		t.Fatalf("recovery should not be active before grace")
	}

	cm.updateRecoveryState(now.Add(2 * time.Second))
	if !cm.isRecoveryActive() {
		t.Fatalf("recovery should be active after grace")
	}
	snap := m.Snapshot()
	if !snap.RecoveryModeActive || snap.RecoveryEnterTotal != 1 {
		t.Fatalf("unexpected recovery metrics after enter: %+v", snap)
	}

	var id [32]byte
	id[0] = 1
	cm.mu.Lock()
	cm.outbound[id] = now.Add(3 * time.Second)
	cm.mu.Unlock()

	cm.updateRecoveryState(now.Add(3 * time.Second))
	if !cm.isRecoveryActive() {
		t.Fatalf("recovery should stay active until stable period")
	}

	cm.updateRecoveryState(now.Add(5 * time.Second))
	if cm.isRecoveryActive() {
		t.Fatalf("recovery should exit after stable period")
	}
	snap = m.Snapshot()
	if snap.RecoveryModeActive || snap.RecoveryExitTotal != 1 {
		t.Fatalf("unexpected recovery metrics after exit: %+v", snap)
	}
}

func TestConnManShouldDialSeedsInRecovery(t *testing.T) {
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	p := peer.Peer{
		NodeID:    bootstrapSeedNodeID("127.0.0.1:17001"),
		Addr:      "127.0.0.1:17001",
		Source:    "pex",
		SubnetKey: peer.SubnetKeyForAddr("127.0.0.1:17001"),
	}
	if err := self.Peers.UpsertUnverified(p); err != nil {
		t.Fatalf("upsert unverified: %v", err)
	}

	cm := &connMan{
		self:      self,
		bootstrap: []string{"127.0.0.1:17000"},
		outbound:  make(map[[32]byte]time.Time),
	}

	if cm.shouldDialSeeds() {
		t.Fatalf("seed dial should be disabled when pex peers exist outside recovery")
	}
	cm.mu.Lock()
	cm.recovery.active = true
	cm.mu.Unlock()
	if !cm.shouldDialSeeds() {
		t.Fatalf("seed dial should be enabled in recovery mode")
	}
}

func TestConnManShouldTryForceIgnoresBackoff(t *testing.T) {
	cm := &connMan{
		nextTry: make(map[[32]byte]time.Time),
	}
	var id [32]byte
	id[0] = 9
	now := time.Now()
	cm.nextTry[id] = now.Add(1 * time.Hour)

	if cm.shouldTry(id, now, false) {
		t.Fatalf("expected normal shouldTry to respect backoff")
	}
	if !cm.shouldTry(id, now, true) {
		t.Fatalf("expected forced shouldTry to ignore backoff")
	}
}

func TestPeerDialAddrPrefersDialAddr(t *testing.T) {
	p := peer.Peer{
		Addr:     "10.0.0.1:1111",
		DialAddr: "10.0.0.9:9999",
	}
	if got := peerDialAddr(p); got != "10.0.0.9:9999" {
		t.Fatalf("expected DialAddr, got %q", got)
	}
}

package peer_test

import (
	"path/filepath"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestSubnetKeyForAddr(t *testing.T) {
	if got := peer.SubnetKeyForAddr("1.2.3.4:123"); got != "1.2.3" {
		t.Fatalf("expected subnet key, got %q", got)
	}
	if got := peer.SubnetKeyForAddr("[2001:db8::1]:443"); got != "" {
		t.Fatalf("expected empty subnet for ipv6, got %q", got)
	}
}

func TestEvictOrdering(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		Cap:          10,
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	p1 := newPeer(t, "10.0.0.1:1001")
	p2 := newPeer(t, "10.0.1.1:1002")
	p3 := newPeer(t, "10.0.2.1:1003")

	now := time.Now().Unix()
	p1.FailCount = 5
	p1.LastSeenUnix = now - 10
	p2.FailCount = 1
	p2.LastSeenUnix = now - 100
	p3.FailCount = 1
	p3.LastSeenUnix = now - 5

	if err := st.Upsert(p1, false); err != nil {
		t.Fatalf("upsert p1: %v", err)
	}
	if err := st.Upsert(p2, false); err != nil {
		t.Fatalf("upsert p2: %v", err)
	}
	if err := st.Upsert(p3, false); err != nil {
		t.Fatalf("upsert p3: %v", err)
	}
	evicted := st.EvictToMax(2, 0)
	if evicted != 1 {
		t.Fatalf("expected 1 eviction, got %d", evicted)
	}
	remaining := st.List()
	for _, p := range remaining {
		if p.NodeID == p1.NodeID {
			t.Fatalf("expected highest fail_count peer to be evicted")
		}
	}
}

func TestEvictSubnetOver(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		Cap:          10,
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	p1 := newPeer(t, "192.168.1.10:1001")
	p2 := newPeer(t, "192.168.1.11:1002")
	p3 := newPeer(t, "10.0.0.1:1003")
	now := time.Now().Unix()
	p1.FailCount = 0
	p2.FailCount = 0
	p3.FailCount = 0
	p1.LastSeenUnix = now - 10
	p2.LastSeenUnix = now - 10
	p3.LastSeenUnix = now - 10

	if err := st.Upsert(p1, false); err != nil {
		t.Fatalf("upsert p1: %v", err)
	}
	if err := st.Upsert(p2, false); err != nil {
		t.Fatalf("upsert p2: %v", err)
	}
	if err := st.Upsert(p3, false); err != nil {
		t.Fatalf("upsert p3: %v", err)
	}
	evicted := st.EvictToMax(2, 1)
	if evicted != 1 {
		t.Fatalf("expected 1 eviction, got %d", evicted)
	}
	remaining := st.List()
	subnetCount := 0
	for _, p := range remaining {
		if p.SubnetKey == "192.168.1" {
			subnetCount++
		}
	}
	if subnetCount > 1 {
		t.Fatalf("expected subnet cap enforced")
	}
}

func newPeer(t *testing.T, addr string) peer.Peer {
	t.Helper()
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return peer.Peer{
		NodeID:    node.DeriveNodeID(pub),
		PubKey:    pub,
		Addr:      addr,
		SubnetKey: peer.SubnetKeyForAddr(addr),
	}
}

package peer_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestStoreCapEviction(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		Cap:          2,
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub1 := pubWithByte(1)
	pub2 := pubWithByte(2)
	pub3 := pubWithByte(3)
	p1 := peer.Peer{NodeID: node.DeriveNodeID(pub1), PubKey: pub1}
	p2 := peer.Peer{NodeID: node.DeriveNodeID(pub2), PubKey: pub2}
	p3 := peer.Peer{NodeID: node.DeriveNodeID(pub3), PubKey: pub3}

	if err := st.Upsert(p1, false); err != nil {
		t.Fatalf("upsert p1 failed: %v", err)
	}
	if err := st.Upsert(p2, false); err != nil {
		t.Fatalf("upsert p2 failed: %v", err)
	}
	if err := st.Upsert(p1, false); err != nil {
		t.Fatalf("touch p1 failed: %v", err)
	}
	if err := st.Upsert(p3, false); err != nil {
		t.Fatalf("upsert p3 failed: %v", err)
	}
	if st.Len() != 2 {
		t.Fatalf("expected 2 peers, got %d", st.Len())
	}
	peers := st.List()
	if hasPeer(peers, p2.NodeID) {
		t.Fatalf("expected p2 evicted")
	}
	if !hasPeer(peers, p1.NodeID) || !hasPeer(peers, p3.NodeID) {
		t.Fatalf("expected p1 and p3 to remain")
	}
}

func TestStoreAddrConflictMutes(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub1 := pubWithByte(1)
	pub2 := pubWithByte(2)
	id1 := node.DeriveNodeID(pub1)
	id2 := node.DeriveNodeID(pub2)
	if err := st.Upsert(peer.Peer{NodeID: id1, PubKey: pub1}, true); err != nil {
		t.Fatalf("upsert p1 failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id1, PubKey: pub1}, "127.0.0.1:1111", "127.0.0.1:1111", true, true); err != nil {
		t.Fatalf("observe addr failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id2, PubKey: pub2}, "127.0.0.1:1111", "127.0.0.1:1111", true, true); !errors.Is(err, peer.ErrAddrConflict) {
		t.Fatalf("expected addr conflict, got %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id2, PubKey: pub2}, "127.0.0.1:1111", "127.0.0.1:1111", true, true); !errors.Is(err, peer.ErrAddrMuted) {
		t.Fatalf("expected addr muted, got %v", err)
	}
	p1, ok := findPeer(st.List(), id1)
	if !ok || p1.Addr != "127.0.0.1:1111" {
		t.Fatalf("expected p1 addr to remain")
	}
	p2, ok := findPeer(st.List(), id2)
	if !ok || p2.Addr != "" {
		t.Fatalf("expected p2 addr to be empty")
	}
}

func TestStoreAddrCooldown(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		AddrCooldown: time.Hour,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(3)
	id := node.DeriveNodeID(pub)
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:2000", "127.0.0.1:2000", true, true); err != nil {
		t.Fatalf("observe addr failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.2:2001", "127.0.0.2:2001", true, true); !errors.Is(err, peer.ErrAddrCooldown) {
		t.Fatalf("expected cooldown error, got %v", err)
	}
}

func pubWithByte(b byte) []byte {
	_ = b
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		return nil
	}
	return pub
}

func hasPeer(peers []peer.Peer, id [32]byte) bool {
	for _, p := range peers {
		if p.NodeID == id {
			return true
		}
	}
	return false
}

func findPeer(peers []peer.Peer, id [32]byte) (peer.Peer, bool) {
	for _, p := range peers {
		if p.NodeID == id {
			return p, true
		}
	}
	return peer.Peer{}, false
}

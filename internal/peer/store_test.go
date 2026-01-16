package peer_test

import (
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

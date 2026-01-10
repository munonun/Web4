package peer

import (
	"path/filepath"
	"testing"
	"time"

	"web4mvp/internal/crypto"
)

func TestStoreCapEviction(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "peers.jsonl"), Options{
		Cap:       2,
		TTL:       time.Hour,
		LoadLimit: 0,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	p1 := Peer{NodeID: idWithByte(1), PubKey: pubWithByte(1)}
	p2 := Peer{NodeID: idWithByte(2), PubKey: pubWithByte(2)}
	p3 := Peer{NodeID: idWithByte(3), PubKey: pubWithByte(3)}

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
	pub := make([]byte, crypto.PubLen)
	pub[0] = b
	return pub
}

func idWithByte(b byte) [32]byte {
	var id [32]byte
	id[0] = b
	return id
}

func hasPeer(peers []Peer, id [32]byte) bool {
	for _, p := range peers {
		if p.NodeID == id {
			return true
		}
	}
	return false
}

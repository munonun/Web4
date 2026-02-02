package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestPeerExchangeCapAndDeterministicShuffle(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")
	t.Setenv("WEB4_PEER_EXCHANGE_MAX", "3")
	t.Setenv("WEB4_PEER_EXCHANGE_SEED", "42")

	root := t.TempDir()
	r, err := NewRunner(root, Options{})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	for i := 0; i < 5; i++ {
		pub, _, err := crypto.GenKeypair()
		if err != nil {
			t.Fatalf("gen keypair: %v", err)
		}
		id := node.DeriveNodeID(pub)
		p := peer.Peer{NodeID: id, PubKey: pub}
		if err := r.Self.Peers.Upsert(p, true); err != nil {
			t.Fatalf("upsert peer: %v", err)
		}
		addr := "127.0.0.1:" + strconv.Itoa(10000+i)
		if _, err := r.Self.Peers.SetAddrUnverified(p, addr, true); err != nil {
			t.Fatalf("set addr: %v", err)
		}
	}

	resp1, err := buildPeerExchangeResp(r.Self, 10)
	if err != nil {
		t.Fatalf("build resp1: %v", err)
	}
	resp2, err := buildPeerExchangeResp(r.Self, 10)
	if err != nil {
		t.Fatalf("build resp2: %v", err)
	}
	if len(resp1.Peers) != 3 {
		t.Fatalf("expected cap 3, got %d", len(resp1.Peers))
	}
	if len(resp2.Peers) != len(resp1.Peers) {
		t.Fatalf("expected same length, got %d vs %d", len(resp1.Peers), len(resp2.Peers))
	}
	for i := range resp1.Peers {
		if resp1.Peers[i].NodeID != resp2.Peers[i].NodeID {
			t.Fatalf("expected deterministic order at %d", i)
		}
	}

	// Ensure we aren't persisting test history files.
	_ = os.Remove(filepath.Join(root, "peers.jsonl"))
}

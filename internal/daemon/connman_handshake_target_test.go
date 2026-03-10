package daemon

import (
	"context"
	"strings"
	"testing"

	"web4mvp/internal/crypto"
	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

func TestHandshakeRejectsBootstrapAddrForDifferentPeerID(t *testing.T) {
	t.Setenv("WEB4_REJECT_LOOPBACK_DIAL_ADDR", "0")

	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	r := &Runner{Self: self, Root: t.TempDir(), Metrics: metrics.New()}
	cm := newConnMan(r, false)

	bootPub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("bootstrap keypair: %v", err)
	}
	bootID := node.DeriveNodeID(bootPub)
	if err := self.Peers.UpsertUnverified(peer.Peer{
		NodeID: bootID,
		PubKey: bootPub,
		Addr:   "127.0.0.1:17000",
		Source: "seed",
	}); err != nil {
		t.Fatalf("upsert bootstrap peer: %v", err)
	}

	candidatePub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("candidate keypair: %v", err)
	}
	candidateID := node.DeriveNodeID(candidatePub)
	if err := self.Peers.UpsertUnverified(peer.Peer{
		NodeID: candidateID,
		PubKey: candidatePub,
		Source: "pex",
	}); err != nil {
		t.Fatalf("upsert candidate peer: %v", err)
	}

	err = cm.handshake(context.Background(), candidateID, "127.0.0.1:17000", "test", false)
	if err == nil {
		t.Fatalf("expected outbound hello1 target mismatch")
	}
	if !strings.Contains(err.Error(), "outbound hello1 target mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

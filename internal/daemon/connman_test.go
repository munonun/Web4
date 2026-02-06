package daemon

import (
	"math/rand"
	"testing"
	"time"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
)

type zeroSource struct{}

func (zeroSource) Int63() int64 { return 0 }
func (zeroSource) Seed(int64)   {}

func TestNextBackoffDurationMonotonic(t *testing.T) {
	t.Setenv("WEB4_OUTBOUND_MAX_BACKOFF_SEC", "5")
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id := node.DeriveNodeID(pub)
	if err := self.Peers.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert peer: %v", err)
	}
	rng := rand.New(zeroSource{})
	prev := time.Duration(0)
	for i := 0; i < 6; i++ {
		if i > 0 {
			self.Peers.PeerFail(id)
		}
		d := nextBackoffDuration(self, id, rng)
		if d < prev {
			t.Fatalf("expected monotonic backoff, got %v then %v", prev, d)
		}
		prev = d
		if d > 5*time.Second+backoffJitter {
			t.Fatalf("backoff exceeded cap: %v", d)
		}
	}
	for i := 0; i < 20; i++ {
		self.Peers.PeerFail(id)
	}
	d := nextBackoffDuration(self, id, rng)
	if d > 5*time.Second+backoffJitter {
		t.Fatalf("backoff cap exceeded: %v", d)
	}
}

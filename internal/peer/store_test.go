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

func TestStoreDoesNotOverwriteAddrWithEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(4)
	id := node.DeriveNodeID(pub)
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if _, err := st.SetAddrUnverified(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:1111", true); err != nil {
		t.Fatalf("set unverified addr failed: %v", err)
	}
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub, Addr: ""}, true); err != nil {
		t.Fatalf("upsert empty addr failed: %v", err)
	}
	p, ok := findPeer(st.List(), id)
	if !ok || p.Addr != "127.0.0.1:1111" {
		t.Fatalf("expected addr to remain, got %q", p.Addr)
	}
}

func TestStoreUnverifiedUpgradesToVerifiedOnMatch(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(5)
	id := node.DeriveNodeID(pub)
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if _, err := st.SetAddrUnverified(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:2222", true); err != nil {
		t.Fatalf("set unverified addr failed: %v", err)
	}
	if st.IsAddrVerified(id) {
		t.Fatalf("expected addr to be unverified")
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:2222", "127.0.0.1:2222", true, true); err != nil {
		t.Fatalf("observe addr failed: %v", err)
	}
	if !st.IsAddrVerified(id) {
		t.Fatalf("expected addr to be verified")
	}
}

func TestObserveAddrDoesNotOverrideDialAddrFromRemote(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(6)
	id := node.DeriveNodeID(pub)
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if _, err := st.SetAddrUnverified(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:46043", true); err != nil {
		t.Fatalf("set unverified addr failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:32790", "", false, true); err != nil {
		t.Fatalf("observe addr #1 failed: %v", err)
	}
	if _, err := st.ObserveAddr(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:32791", "", false, true); err != nil {
		t.Fatalf("observe addr #2 failed: %v", err)
	}
	p, ok := findPeer(st.List(), id)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Addr != "127.0.0.1:46043" {
		t.Fatalf("dial addr changed unexpectedly: %q", p.Addr)
	}
	if p.ObservedAddr != "127.0.0.1:32791" {
		t.Fatalf("expected last observed addr to track remote endpoint, got %q", p.ObservedAddr)
	}
}

func TestObserveAddrDiscoveryStoresAdvertisedListenAddrWithoutPubKey(t *testing.T) {
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(8)
	id := node.DeriveNodeID(pub)
	if err := st.UpsertUnverified(peer.Peer{NodeID: id}); err != nil {
		t.Fatalf("upsert unverified failed: %v", err)
	}
	changed, err := st.ObserveAddrDiscovery(id, "127.0.0.1:32001", "127.0.0.1:46043", true, true)
	if err != nil {
		t.Fatalf("observe discovery failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected discovery observe to apply advertised addr")
	}
	p, ok := findPeer(st.List(), id)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Addr != "127.0.0.1:46043" {
		t.Fatalf("unexpected addr: %q", p.Addr)
	}
	if p.ObservedAddr != "127.0.0.1:32001" {
		t.Fatalf("unexpected observed addr: %q", p.ObservedAddr)
	}
}

func TestSetAddrUnverifiedRejectsLoopbackWhenEnabled(t *testing.T) {
	t.Setenv("WEB4_REJECT_LOOPBACK_DIAL_ADDR", "1")
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	pub := pubWithByte(7)
	id := node.DeriveNodeID(pub)
	if err := st.Upsert(peer.Peer{NodeID: id, PubKey: pub}, true); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	changed, err := st.SetAddrUnverified(peer.Peer{NodeID: id, PubKey: pub}, "127.0.0.1:46043", true)
	if !errors.Is(err, peer.ErrAddrLoopback) {
		t.Fatalf("expected loopback reject, got changed=%v err=%v", changed, err)
	}
	p, ok := findPeer(st.List(), id)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Addr != "" {
		t.Fatalf("expected empty dial addr after loopback reject, got %q", p.Addr)
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

func TestEconomicDebtIncreaseWithinCreditAccepted(t *testing.T) {
	t.Setenv("WEB4_CREDIT_UNVERIFIED", "10")
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	selfPub := pubWithByte(11)
	peerPub := pubWithByte(12)
	selfID := node.DeriveNodeID(selfPub)
	peerID := node.DeriveNodeID(peerPub)
	if err := st.Upsert(peer.Peer{NodeID: peerID, PubKey: peerPub}, false); err != nil {
		t.Fatalf("upsert peer failed: %v", err)
	}
	deltas := map[[32]byte]int64{selfID: 5, peerID: -5}
	if err := st.ApplyEconomicDelta(selfID, deltas, false); err != nil {
		t.Fatalf("apply economic delta failed: %v", err)
	}
	p, ok := st.Get(peerID)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Economic.Debt != 5 {
		t.Fatalf("expected debt=5 got %d", p.Economic.Debt)
	}
}

func TestEconomicOverCreditRejected(t *testing.T) {
	t.Setenv("WEB4_CREDIT_UNVERIFIED", "3")
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	selfPub := pubWithByte(13)
	peerPub := pubWithByte(14)
	selfID := node.DeriveNodeID(selfPub)
	peerID := node.DeriveNodeID(peerPub)
	if err := st.Upsert(peer.Peer{NodeID: peerID, PubKey: peerPub}, false); err != nil {
		t.Fatalf("upsert peer failed: %v", err)
	}
	deltas := map[[32]byte]int64{selfID: 5, peerID: -5}
	if err := st.ApplyEconomicDelta(selfID, deltas, false); err == nil {
		t.Fatalf("expected over-credit rejection")
	}
}

func TestEconomicRepaymentReducesDebt(t *testing.T) {
	t.Setenv("WEB4_CREDIT_UNVERIFIED", "10")
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	selfPub := pubWithByte(15)
	peerPub := pubWithByte(16)
	selfID := node.DeriveNodeID(selfPub)
	peerID := node.DeriveNodeID(peerPub)
	if err := st.Upsert(peer.Peer{NodeID: peerID, PubKey: peerPub}, false); err != nil {
		t.Fatalf("upsert peer failed: %v", err)
	}
	if err := st.ApplyEconomicDelta(selfID, map[[32]byte]int64{selfID: 5, peerID: -5}, false); err != nil {
		t.Fatalf("initial debt apply failed: %v", err)
	}
	if err := st.ApplyEconomicDelta(selfID, map[[32]byte]int64{selfID: -3, peerID: 3}, false); err != nil {
		t.Fatalf("repay apply failed: %v", err)
	}
	p, ok := st.Get(peerID)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Economic.Debt != 2 {
		t.Fatalf("expected debt=2 got %d", p.Economic.Debt)
	}
	if p.Economic.LastRepayUnix == 0 {
		t.Fatalf("expected last_repay_unix updated")
	}
}

func TestEconomicGraceTimeoutZeroesCredit(t *testing.T) {
	t.Setenv("WEB4_CREDIT_UNVERIFIED", "10")
	t.Setenv("WEB4_GRACE_SEC", "1")
	dir := t.TempDir()
	st, err := peer.NewStore(filepath.Join(dir, "peers.jsonl"), peer.Options{
		TTL:          time.Hour,
		LoadLimit:    0,
		DeriveNodeID: node.DeriveNodeID,
	})
	if err != nil {
		t.Fatalf("new store failed: %v", err)
	}
	selfPub := pubWithByte(17)
	peerPub := pubWithByte(18)
	selfID := node.DeriveNodeID(selfPub)
	peerID := node.DeriveNodeID(peerPub)
	if err := st.Upsert(peer.Peer{NodeID: peerID, PubKey: peerPub}, false); err != nil {
		t.Fatalf("upsert peer failed: %v", err)
	}
	if err := st.ApplyEconomicDelta(selfID, map[[32]byte]int64{selfID: 5, peerID: -5}, false); err != nil {
		t.Fatalf("initial debt apply failed: %v", err)
	}
	changed := st.EnforceEconomicGrace(time.Now().Add(2*time.Second), false)
	if changed == 0 {
		t.Fatalf("expected grace enforcement to change credit")
	}
	p, ok := st.Get(peerID)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Economic.Credit != 0 {
		t.Fatalf("expected credit=0 after grace timeout got %d", p.Economic.Credit)
	}
}

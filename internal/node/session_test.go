package node

import (
	"bytes"
	"testing"
	"time"

	"web4mvp/internal/peer"
)

func TestHandshakeSuccess(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	nodeA, err := NewNode(dirA, Options{PeerStoreTTL: time.Minute})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{PeerStoreTTL: time.Minute})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	if err := nodeA.Peers.Upsert(peer.Peer{NodeID: nodeB.ID, PubKey: nodeB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}
	if err := nodeB.Peers.Upsert(peer.Peer{NodeID: nodeA.ID, PubKey: nodeA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}

	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello2, err := nodeB.HandleHello1(hello1)
	if err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if err := nodeA.HandleHello2(hello2); err != nil {
		t.Fatalf("handle hello2 failed: %v", err)
	}

	sessA, ok := nodeA.Sessions.Get(nodeB.ID)
	if !ok {
		t.Fatalf("missing session A->B")
	}
	sessB, ok := nodeB.Sessions.Get(nodeA.ID)
	if !ok {
		t.Fatalf("missing session B->A")
	}
	if !bytes.Equal(sessA.SendKey, sessB.RecvKey) {
		t.Fatalf("send/recv key mismatch")
	}
	if !bytes.Equal(sessA.RecvKey, sessB.SendKey) {
		t.Fatalf("recv/send key mismatch")
	}
	if !bytes.Equal(sessA.NonceBaseSend, sessB.NonceBaseRecv) {
		t.Fatalf("nonce base send/recv mismatch")
	}
	if !bytes.Equal(sessA.NonceBaseRecv, sessB.NonceBaseSend) {
		t.Fatalf("nonce base recv/send mismatch")
	}
}

func TestHandshakeRejectsBadSig(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	if err := nodeA.Peers.Upsert(peer.Peer{NodeID: nodeB.ID, PubKey: nodeB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}
	if err := nodeB.Peers.Upsert(peer.Peer{NodeID: nodeA.ID, PubKey: nodeA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello1.Sig = "00"
	if _, err := nodeB.HandleHello1(hello1); err == nil {
		t.Fatalf("expected bad signature error")
	}
}

func TestHandshakeRejectsReplay(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	if err := nodeA.Peers.Upsert(peer.Peer{NodeID: nodeB.ID, PubKey: nodeB.PubKey}, true); err != nil {
		t.Fatalf("seed peer B failed: %v", err)
	}
	if err := nodeB.Peers.Upsert(peer.Peer{NodeID: nodeA.ID, PubKey: nodeA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	if _, err := nodeB.HandleHello1(hello1); err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if _, err := nodeB.HandleHello1(hello1); err == nil {
		t.Fatalf("expected replay rejection")
	}
}

func TestHello1UpsertsFromNodeID(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	if _, err := nodeB.HandleHello1From(hello1, "127.0.0.1:12345"); err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if _, ok := findPeer(nodeB.Peers.List(), nodeA.ID); !ok {
		t.Fatalf("expected peer for from_node_id")
	}
	if _, ok := findPeer(nodeB.Peers.List(), nodeB.ID); ok {
		t.Fatalf("did not expect self peer from hello1")
	}
}

func TestHello1RejectsToIDMismatch(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	dirC := t.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	nodeC, err := NewNode(dirC, Options{})
	if err != nil {
		t.Fatalf("new node C failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeC.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	if _, err := nodeB.HandleHello1From(hello1, "127.0.0.1:12345"); err == nil {
		t.Fatalf("expected to_id mismatch rejection")
	}
}

func TestHello1FromAddrPersistsUnverifiedHint(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		t.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		t.Fatalf("new node B failed: %v", err)
	}
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello1.FromAddr = "127.0.0.1:46043"
	if _, err := nodeB.HandleHello1From(hello1, "127.0.0.1:32790"); err != nil {
		t.Fatalf("handle hello1 failed: %v", err)
	}
	if addr, ok := nodeB.Peers.AddrHint(nodeA.ID); !ok || addr != "127.0.0.1:46043" {
		t.Fatalf("expected addr hint to persist, got %q ok=%v", addr, ok)
	}
	if nodeB.Peers.IsAddrVerified(nodeA.ID) {
		t.Fatalf("expected addr to be unverified")
	}
}

func TestRecvSeqRejectsReplay(t *testing.T) {
	st := &SessionState{}
	if err := st.AcceptRecvSeq(1); err != nil {
		t.Fatalf("accept recv seq failed: %v", err)
	}
	if err := st.AcceptRecvSeq(1); err == nil {
		t.Fatalf("expected replay rejection")
	}
}

func findPeer(peers []peer.Peer, id [32]byte) (peer.Peer, bool) {
	for _, p := range peers {
		if p.NodeID == id {
			return p, true
		}
	}
	return peer.Peer{}, false
}

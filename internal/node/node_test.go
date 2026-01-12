package node

import (
	"bytes"
	"encoding/hex"
	"testing"

	"web4mvp/internal/crypto"
)

func TestDeriveNodeID(t *testing.T) {
	pub := []byte("test-pubkey")
	got := DeriveNodeID(pub)
	want := crypto.SHA3_256(pub)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("unexpected node id")
	}
}

func TestVerifyHello(t *testing.T) {
	pub, priv, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen keypair failed: %v", err)
	}
	n := &Node{
		ID:      DeriveNodeID(pub),
		PubKey:  pub,
		PrivKey: priv,
	}
	msg, err := n.Hello(42, "")
	if err != nil {
		t.Fatalf("hello failed: %v", err)
	}
	peerInfo, err := VerifyHello(msg)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if peerInfo.NodeID != n.ID {
		t.Fatalf("node id mismatch")
	}
	if !bytes.Equal(peerInfo.PubKey, n.PubKey) {
		t.Fatalf("pubkey mismatch")
	}

	msg.NodeID = hex.EncodeToString(make([]byte, 32))
	if _, err := VerifyHello(msg); err == nil {
		t.Fatalf("expected error for bad node id")
	}
}

func TestNewNodeGeneratesKeys(t *testing.T) {
	dir := t.TempDir()
	n, err := NewNode(dir, Options{})
	if err != nil {
		t.Fatalf("new node failed: %v", err)
	}
	if len(n.PubKey) == 0 || len(n.PrivKey) == 0 {
		t.Fatalf("expected keypair to be generated")
	}
	if _, _, err := crypto.LoadKeypair(dir); err != nil {
		t.Fatalf("expected keypair persisted: %v", err)
	}
}

package node

import (
	"bytes"
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

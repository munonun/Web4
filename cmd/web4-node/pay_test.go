package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"web4mvp/internal/daemon"
	"web4mvp/internal/node"
	"web4mvp/internal/proto"
	"web4mvp/internal/wallet"
)

func TestPayDeltaEntriesSumZero(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	t.Setenv("HOME", homeA)
	self, err := node.NewNode(homeDir(), node.Options{})
	if err != nil {
		t.Fatalf("self node: %v", err)
	}
	other, err := node.NewNode(homeB, node.Options{})
	if err != nil {
		t.Fatalf("other node: %v", err)
	}
	t.Setenv("WEB4_ZK_MODE", "0")
	claim, msg, _, _, _, _, err := preparePayDelta(self, other.ID, 7)
	if err != nil {
		t.Fatalf("prepare pay delta: %v", err)
	}
	if claim.FromNode == "" || claim.ToNode == "" {
		t.Fatalf("missing claim nodes")
	}
	var sum int64
	for _, e := range msg.Entries {
		sum += e.Delta
	}
	if sum != 0 {
		t.Fatalf("expected sum=0 got %d", sum)
	}
	if len(msg.Entries) != 2 {
		t.Fatalf("expected 2 entries got %d", len(msg.Entries))
	}
}

func TestPayClaimStored(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	self, err := node.NewNode(homeDir(), node.Options{})
	if err != nil {
		t.Fatalf("self node: %v", err)
	}
	other, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("other node: %v", err)
	}
	t.Setenv("WEB4_ZK_MODE", "0")
	args := []string{"pay", "--to", hex.EncodeToString(other.ID[:]), "--amount", "5"}
	if code := run(args, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("pay command failed")
	}
	store, err := wallet.NewStore(filepath.Join(homeDir(), "claims.jsonl"))
	if err != nil {
		t.Fatalf("claim store: %v", err)
	}
	claims, err := store.List(10)
	if err != nil {
		t.Fatalf("claim list: %v", err)
	}
	if len(claims) == 0 {
		t.Fatalf("expected stored claim")
	}
	_ = self
}

func TestPayZKTamperFails(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	t.Setenv("HOME", homeA)
	self, err := node.NewNode(homeDir(), node.Options{})
	if err != nil {
		t.Fatalf("self node: %v", err)
	}
	other, err := node.NewNode(homeB, node.Options{})
	if err != nil {
		t.Fatalf("other node: %v", err)
	}
	t.Setenv("WEB4_ZK_MODE", "1")
	_, msg, _, _, _, viewID, err := preparePayDelta(self, other.ID, 9)
	if err != nil {
		t.Fatalf("prepare pay delta: %v", err)
	}
	if err := daemon.VerifyDeltaBZK(msg, viewID); err != nil {
		t.Fatalf("expected zk verify ok: %v", err)
	}
	msg.ClaimID = strings.Repeat("00", 32)
	if err := daemon.VerifyDeltaBZK(msg, viewID); err == nil {
		t.Fatalf("expected zk verify fail on tamper")
	}
}

func TestPayPayloadIsDeltaB(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()
	t.Setenv("HOME", homeA)
	self, err := node.NewNode(homeDir(), node.Options{})
	if err != nil {
		t.Fatalf("self node: %v", err)
	}
	other, err := node.NewNode(homeB, node.Options{})
	if err != nil {
		t.Fatalf("other node: %v", err)
	}
	t.Setenv("WEB4_ZK_MODE", "0")
	_, msg, payload, _, _, _, err := preparePayDelta(self, other.ID, 3)
	if err != nil {
		t.Fatalf("prepare pay delta: %v", err)
	}
	decoded, err := proto.DecodeDeltaBMsg(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if decoded.Type != "" && decoded.Type != proto.MsgTypeDeltaB {
		t.Fatalf("expected delta_b payload")
	}
	_ = msg
}

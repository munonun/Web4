package daemon

import (
	"encoding/hex"
	"strconv"
	"testing"

	"web4mvp/internal/crypto"
	"web4mvp/internal/node"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

func TestApplyPeerExchangeRespCapAndNormalize(t *testing.T) {
	t.Setenv("WEB4_PEX_INSERT_MAX", "3")
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	resp := proto.PeerExchangeRespMsg{
		Type:         proto.MsgTypePeerExchangeResp,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
	}
	for i := 0; i < 5; i++ {
		pub, _, err := crypto.GenKeypair()
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		id := node.DeriveNodeID(pub)
		addr := "127.0.0.1:0"
		if i == 4 {
			addr = "invalid"
		}
		resp.Peers = append(resp.Peers, proto.PeerExchangePeer{
			Addr:   addr,
			NodeID: hex.EncodeToString(id[:]),
			PubKey: hex.EncodeToString(pub),
		})
	}
	added, err := applyPeerExchangeResp(self, resp)
	if err != nil {
		t.Fatalf("apply peer exchange resp: %v", err)
	}
	if added != 3 {
		t.Fatalf("expected added=3, got %d", added)
	}
	for _, p := range self.Peers.List() {
		if p.Addr == "invalid" {
			t.Fatalf("invalid addr should not be inserted")
		}
	}
}

func TestBuildPeerExchangeRespCapAndDeterministicShuffle(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")
	t.Setenv("WEB4_PEER_EXCHANGE_MAX", "2")
	t.Setenv("WEB4_PEER_EXCHANGE_SEED", "7")
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	for i := 0; i < 4; i++ {
		pub, _, err := crypto.GenKeypair()
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		id := node.DeriveNodeID(pub)
		addr := "127.0.0.1:" + strconv.Itoa(10000+i)
		p := peer.Peer{NodeID: id, PubKey: pub, Addr: addr}
		if err := self.Peers.Upsert(p, true); err != nil {
			t.Fatalf("upsert peer: %v", err)
		}
		if _, err := self.Peers.SetAddrUnverified(p, addr, true); err != nil {
			t.Fatalf("set addr: %v", err)
		}
	}
	respA, err := buildPeerExchangeResp(self, 10, "")
	if err != nil {
		t.Fatalf("build resp A: %v", err)
	}
	respB, err := buildPeerExchangeResp(self, 10, "")
	if err != nil {
		t.Fatalf("build resp B: %v", err)
	}
	if len(respA.Peers) != 2 || len(respB.Peers) != 2 {
		t.Fatalf("expected cap=2, got %d/%d", len(respA.Peers), len(respB.Peers))
	}
	for i := range respA.Peers {
		if respA.Peers[i].NodeID != respB.Peers[i].NodeID {
			t.Fatalf("expected deterministic shuffle under fixed seed")
		}
	}
}

package daemon

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	respA, err := buildPeerExchangeResp(self, 10, "", true)
	if err != nil {
		t.Fatalf("build resp A: %v", err)
	}
	respB, err := buildPeerExchangeResp(self, 10, "", true)
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

func TestBuildPeerExchangeRespTruncatesToByteBudget(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "peer")
	t.Setenv("WEB4_PEER_EXCHANGE_MAX", "64")
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	for i := 0; i < 12; i++ {
		pub, _, err := crypto.GenKeypair()
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		id := node.DeriveNodeID(pub)
		addr := "127.0.0.1:" + strconv.Itoa(20000+i)
		p := peer.Peer{NodeID: id, PubKey: pub, Addr: addr}
		if err := self.Peers.Upsert(p, true); err != nil {
			t.Fatalf("upsert peer: %v", err)
		}
		if _, err := self.Peers.SetAddrUnverified(p, addr, true); err != nil {
			t.Fatalf("set addr: %v", err)
		}
	}
	resp, err := buildPeerExchangeResp(self, 64, "", false)
	if err != nil {
		t.Fatalf("build resp: %v", err)
	}
	if len(resp.Peers) == 0 {
		t.Fatalf("expected non-empty truncated response")
	}
	if len(resp.Peers) >= 12 {
		t.Fatalf("expected truncation by byte budget, got %d peers", len(resp.Peers))
	}
	encoded, err := proto.EncodePeerExchangeResp(resp)
	if err != nil {
		t.Fatalf("encode resp: %v", err)
	}
	if len(encoded) > proto.MaxPeerExchangeRespSize {
		t.Fatalf("encoded resp too large: %d > %d", len(encoded), proto.MaxPeerExchangeRespSize)
	}
}

func TestDecodePeerExchangePeerPrefersListenAddr(t *testing.T) {
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id := node.DeriveNodeID(pub)
	p, err := decodePeerExchangePeer(proto.PeerExchangePeer{
		NodeID:     hex.EncodeToString(id[:]),
		PubKey:     hex.EncodeToString(pub),
		ListenAddr: "127.0.0.1:18081",
		Addr:       "127.0.0.1:9999",
	})
	if err != nil {
		t.Fatalf("decode peer: %v", err)
	}
	if p.Addr != "127.0.0.1:18081" {
		t.Fatalf("expected listen_addr to win, got %q", p.Addr)
	}
}

func TestApplyPeerExchangeRespPersistsLearnedPeer(t *testing.T) {
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id := node.DeriveNodeID(pub)
	resp := proto.PeerExchangeRespMsg{
		Type:         proto.MsgTypePeerExchangeResp,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		Peers: []proto.PeerExchangePeer{
			{
				NodeID:     hex.EncodeToString(id[:]),
				PubKey:     hex.EncodeToString(pub),
				ListenAddr: "127.0.0.1:28081",
			},
		},
	}
	added, err := applyPeerExchangeResp(self, resp)
	if err != nil {
		t.Fatalf("apply peer exchange resp: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected added=1, got %d", added)
	}
	peersPath := filepath.Join(self.Home, "peers.jsonl")
	data, err := os.ReadFile(peersPath)
	if err != nil {
		t.Fatalf("read peers.jsonl: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, hex.EncodeToString(id[:])) {
		t.Fatalf("persisted peers.jsonl missing node_id")
	}
	if !strings.Contains(text, "127.0.0.1:28081") {
		t.Fatalf("persisted peers.jsonl missing listen addr")
	}
}

func TestBootstrapDiscoveryFromUnverifiedPex(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")
	bootstrap, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new bootstrap node: %v", err)
	}
	r := &Runner{Self: bootstrap, Mode: nodeModeBootstrap}

	pubA, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key A: %v", err)
	}
	idA := node.DeriveNodeID(pubA)
	reqA := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            8,
		FromNodeID:   hex.EncodeToString(idA[:]),
	}
	dataA, err := proto.EncodePeerExchangeReq(reqA)
	if err != nil {
		t.Fatalf("encode req A: %v", err)
	}
	if _, _, err := r.recvDataWithResponse(dataA, "127.0.0.1:1111"); err != nil {
		t.Fatalf("recv req A: %v", err)
	}

	pubB, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key B: %v", err)
	}
	idB := node.DeriveNodeID(pubB)
	reqB := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            8,
		FromNodeID:   hex.EncodeToString(idB[:]),
	}
	dataB, err := proto.EncodePeerExchangeReq(reqB)
	if err != nil {
		t.Fatalf("encode req B: %v", err)
	}
	if _, _, err := r.recvDataWithResponse(dataB, "127.0.0.1:2222"); err != nil {
		t.Fatalf("recv req B: %v", err)
	}

	resp, err := buildPeerExchangeResp(bootstrap, 10, "", true)
	if err != nil {
		t.Fatalf("build resp: %v", err)
	}

	client, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new client node: %v", err)
	}
	if _, err := applyPeerExchangeResp(client, resp); err != nil {
		t.Fatalf("apply resp: %v", err)
	}
	foundB := false
	for _, p := range client.Peers.List() {
		if p.NodeID == idB {
			foundB = true
			break
		}
	}
	if foundB {
		t.Fatalf("did not expect unverified peer B without advertised listen_addr")
	}
}

func TestBootstrapDiscoveryFromPexAdvertisedListenAddr(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")
	bootstrap, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new bootstrap node: %v", err)
	}
	r := &Runner{Self: bootstrap, Mode: nodeModeBootstrap}

	pubA, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key A: %v", err)
	}
	idA := node.DeriveNodeID(pubA)
	reqA := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            8,
		FromNodeID:   hex.EncodeToString(idA[:]),
		ListenAddr:   "127.0.0.1:30001",
	}
	dataA, err := proto.EncodePeerExchangeReq(reqA)
	if err != nil {
		t.Fatalf("encode req A: %v", err)
	}
	if _, _, err := r.recvDataWithResponse(dataA, "127.0.0.1:1111"); err != nil {
		t.Fatalf("recv req A: %v", err)
	}

	pubB, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key B: %v", err)
	}
	idB := node.DeriveNodeID(pubB)
	reqB := proto.PeerExchangeReqMsg{
		Type:         proto.MsgTypePeerExchangeReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		K:            8,
		FromNodeID:   hex.EncodeToString(idB[:]),
		ListenAddr:   "127.0.0.1:30002",
	}
	dataB, err := proto.EncodePeerExchangeReq(reqB)
	if err != nil {
		t.Fatalf("encode req B: %v", err)
	}
	if _, _, err := r.recvDataWithResponse(dataB, "127.0.0.1:2222"); err != nil {
		t.Fatalf("recv req B: %v", err)
	}

	resp, err := buildPeerExchangeResp(bootstrap, 10, "", true)
	if err != nil {
		t.Fatalf("build resp: %v", err)
	}
	client, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new client node: %v", err)
	}
	added, err := applyPeerExchangeResp(client, resp)
	if err != nil {
		t.Fatalf("apply resp: %v", err)
	}
	if added == 0 {
		t.Fatalf("expected at least one discovered peer")
	}
	foundB := false
	for _, p := range client.Peers.List() {
		if p.NodeID == idB && p.Addr == "127.0.0.1:30002" {
			foundB = true
			break
		}
	}
	if !foundB {
		t.Fatalf("expected advertised listen_addr peer B to be included in bootstrap response")
	}
}

func TestApplyPeerExchangeRespRejectsLoopbackDialAddrWhenEnabled(t *testing.T) {
	t.Setenv("WEB4_REJECT_LOOPBACK_DIAL_ADDR", "1")
	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	id := node.DeriveNodeID(pub)
	resp := proto.PeerExchangeRespMsg{
		Type:         proto.MsgTypePeerExchangeResp,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		Peers: []proto.PeerExchangePeer{
			{
				NodeID:     hex.EncodeToString(id[:]),
				PubKey:     hex.EncodeToString(pub),
				ListenAddr: "127.0.0.1:40001",
			},
		},
	}
	added, err := applyPeerExchangeResp(self, resp)
	if err != nil {
		t.Fatalf("apply peer exchange resp: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected peer metadata upsert, got added=%d", added)
	}
	p, ok := self.Peers.Get(id)
	if !ok {
		t.Fatalf("peer missing")
	}
	if p.Addr != "" {
		t.Fatalf("expected loopback listen addr to be rejected for dial, got %q", p.Addr)
	}
}

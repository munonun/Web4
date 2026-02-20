package node

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
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
	nodeA.SetListenAddr("127.0.0.1:46043")
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
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

func TestHandshakeRejectsTamperedTranscriptField(t *testing.T) {
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
	// Tamper transcript input field without updating signature.
	hello1.Na = "00" + hello1.Na[2:]
	if _, err := nodeB.HandleHello1(hello1); err == nil {
		t.Fatalf("expected transcript tamper rejection")
	}
}

func TestHandshakeRejectsHello2ReplayAcrossDifferentTranscript(t *testing.T) {
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

	hello1a, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1a failed: %v", err)
	}
	hello2a, err := nodeB.HandleHello1(hello1a)
	if err != nil {
		t.Fatalf("handle hello1a failed: %v", err)
	}

	hello1b, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1b failed: %v", err)
	}
	if _, err := nodeB.HandleHello1(hello1b); err != nil {
		t.Fatalf("handle hello1b failed: %v", err)
	}

	// Replay hello2 from transcript A into transcript B pending state.
	if err := nodeA.HandleHello2(hello2a); err == nil {
		t.Fatalf("expected replayed hello2 rejection for mismatched transcript")
	}
}

func TestHandshakeRejectsForcedDowngradeWhenBothSupportSuite0(t *testing.T) {
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
	hello1.SuiteID = int(SuiteLegacyX25519RSA)
	if _, err := nodeB.HandleHello1(hello1); err == nil {
		t.Fatalf("expected forced downgrade rejection")
	}
}

func TestHandshakeAcceptsLegacyWhenPeerLacksSuite0(t *testing.T) {
	t.Setenv("WEB4_ALLOW_RSA_PSS", "1")
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

	prev := os.Getenv("WEB4_HANDSHAKE_DISABLE_SUITE0")
	_ = os.Setenv("WEB4_HANDSHAKE_DISABLE_SUITE0", "1")
	hello1, err := nodeA.BuildHello1(nodeB.ID)
	if prev == "" {
		_ = os.Unsetenv("WEB4_HANDSHAKE_DISABLE_SUITE0")
	} else {
		_ = os.Setenv("WEB4_HANDSHAKE_DISABLE_SUITE0", prev)
	}
	if err != nil {
		t.Fatalf("build hello1 failed: %v", err)
	}
	hello2, err := nodeB.HandleHello1(hello1)
	if err != nil {
		t.Fatalf("expected legacy compat accept, got: %v", err)
	}
	if err := nodeA.HandleHello2(hello2); err != nil {
		t.Fatalf("handle hello2 failed: %v", err)
	}
}

func TestHandshakeRejectsSuiteTamper(t *testing.T) {
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
	if hello1.SuiteID == int(SuiteHybridMLKEMSPHINCS) {
		hello1.SuiteID = int(SuiteLegacyX25519RSA)
	} else {
		hello1.SuiteID = int(SuiteHybridMLKEMSPHINCS)
	}
	if _, err := nodeB.HandleHello1(hello1); err == nil {
		t.Fatalf("expected suite tamper rejection")
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

func TestMLDSAKeypairPersistsAcrossHandshakes(t *testing.T) {
	t.Setenv("WEB4_HANDSHAKE_DISABLE_SUITE0", "")
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
	h1a, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 a failed: %v", err)
	}
	h1b, err := nodeA.BuildHello1(nodeB.ID)
	if err != nil {
		t.Fatalf("build hello1 b failed: %v", err)
	}
	if h1a.SuiteID != int(SuiteHybridMLKEMMLDSA) || h1b.SuiteID != int(SuiteHybridMLKEMMLDSA) {
		t.Fatalf("expected hybrid suite for ml-dsa path")
	}
	if h1a.PQPub == "" || h1b.PQPub == "" {
		t.Fatalf("missing pq pub in hello messages")
	}
	if h1a.PQPub != h1b.PQPub {
		t.Fatalf("expected persisted pq pub across handshakes")
	}
	if fi, err := os.Stat(filepath.Join(dirA, mldsaPubFile)); err != nil || fi.Size() == 0 {
		t.Fatalf("missing persisted ml-dsa pub file: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dirA, mldsaPrivFile)); err != nil || fi.Size() == 0 {
		t.Fatalf("missing persisted ml-dsa priv file: %v", err)
	}
}

func TestHelloSignatureCacheUsesExactSignedBytes(t *testing.T) {
	t.Setenv("WEB4_ALLOW_RSA_PSS", "1")
	n, err := NewNode(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("new node failed: %v", err)
	}
	fromID := n.ID
	toID := fromID
	input := hello1SigInput(SuiteLegacyX25519RSA, fromID, toID, "127.0.0.1:1", []byte("ea"), []byte("na"), []byte("sid"))
	sig1, err := n.signHelloBySuiteCached(SuiteLegacyX25519RSA, n.PrivKey, nil, input)
	if err != nil {
		t.Fatalf("sign 1 failed: %v", err)
	}
	sig2, err := n.signHelloBySuiteCached(SuiteLegacyX25519RSA, n.PrivKey, nil, input)
	if err != nil {
		t.Fatalf("sign 2 failed: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("expected cached signature for same exact bytes\nsig1=%s\nsig2=%s", hex.EncodeToString(sig1), hex.EncodeToString(sig2))
	}
	changed := hello1SigInput(SuiteLegacyX25519RSA, fromID, toID, "127.0.0.1:2", []byte("ea"), []byte("na"), []byte("sid"))
	sig3, err := n.signHelloBySuiteCached(SuiteLegacyX25519RSA, n.PrivKey, nil, changed)
	if err != nil {
		t.Fatalf("sign 3 failed: %v", err)
	}
	if bytes.Equal(sig1, sig3) {
		t.Fatalf("expected different signature for different exact signed bytes")
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

func BenchmarkBuildHello1(b *testing.B) {
	b.Setenv("WEB4_HANDSHAKE_DISABLE_SUITE0", "")
	dirA := b.TempDir()
	dirB := b.TempDir()
	nodeA, err := NewNode(dirA, Options{})
	if err != nil {
		b.Fatalf("new node A failed: %v", err)
	}
	nodeB, err := NewNode(dirB, Options{})
	if err != nil {
		b.Fatalf("new node B failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := nodeA.BuildHello1(nodeB.ID); err != nil {
			b.Fatalf("BuildHello1 failed: %v", err)
		}
	}
}

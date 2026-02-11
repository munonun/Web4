package daemon

import (
	"strings"
	"testing"
	"time"

	"web4mvp/internal/math4"
	"web4mvp/internal/peer"
	"web4mvp/internal/proto"
)

func TestGossipHello1RateLimitedBeforeVerify(t *testing.T) {
	// Keep this test lightweight while validating limiter order on gossip hello1.
	t.Setenv("WEB4_HANDSHAKE_DISABLE_SUITE0", "1")

	rA, err := NewRunner(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("new runner A: %v", err)
	}
	rB, err := NewRunner(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("new runner B: %v", err)
	}
	rD, err := NewRunner(t.TempDir(), Options{})
	if err != nil {
		t.Fatalf("new runner D: %v", err)
	}

	selfA := rA.Self
	selfB := rB.Self
	selfD := rD.Self
	if selfA == nil || selfB == nil || selfD == nil {
		t.Fatalf("missing runner node")
	}

	if err := selfB.Peers.Upsert(peer.Peer{NodeID: selfA.ID, PubKey: selfA.PubKey}, true); err != nil {
		t.Fatalf("seed peer A failed: %v", err)
	}
	if err := selfB.Members.Add(selfA.ID, false); err != nil {
		t.Fatalf("add member A to B failed: %v", err)
	}

	origHost := recvHostLimiter
	origNode := recvNodeLimiter
	origDebug := debugCount
	recvHostLimiter = newRateLimiter(1000, time.Minute)
	recvNodeLimiter = newRateLimiter(1, time.Minute)
	debugCount = newDebugCounters()
	defer func() {
		recvHostLimiter = origHost
		recvNodeLimiter = origNode
		debugCount = origDebug
	}()

	checker := math4.NewLocalChecker(math4.Options{})
	peerB := peer.Peer{NodeID: selfB.ID, PubKey: selfB.PubKey}

	const attempts = 6
	rateLimited := 0
	verifyFailed := 0
	for i := 0; i < attempts; i++ {
		hello1, err := selfD.BuildHello1(selfA.ID)
		if err != nil {
			t.Fatalf("build hello1 failed: %v", err)
		}
		if len(hello1.Sig) == 0 {
			t.Fatalf("missing hello1 sig")
		}
		last := hello1.Sig[len(hello1.Sig)-1]
		if last == '0' {
			last = '1'
		} else {
			last = '0'
		}
		hello1.Sig = hello1.Sig[:len(hello1.Sig)-1] + string(last)

		hello1Data, err := proto.EncodeHello1Msg(hello1)
		if err != nil {
			t.Fatalf("encode hello1 failed: %v", err)
		}
		gossipData, err := buildGossipPushForPeer(peerB, hello1Data, 2, selfA)
		if err != nil {
			t.Fatalf("build gossip push failed: %v", err)
		}
		_, _, recvErr := handleGossipPush(gossipData, nil, selfB, checker, "127.0.0.1:1111")
		if recvErr == nil || recvErr.err == nil {
			t.Fatalf("expected gossip payload failure")
		}
		errText := strings.ToLower(recvErr.err.Error())
		if strings.Contains(errText, "rate") {
			rateLimited++
		}
		if strings.Contains(errText, "bad hello1 signature") {
			verifyFailed++
		}
	}

	if rateLimited < attempts-2 {
		t.Fatalf("expected most attempts to be rate-limited, got %d/%d", rateLimited, attempts)
	}
	if verifyFailed > 1 {
		t.Fatalf("expected at most one verify failure, got %d", verifyFailed)
	}
	debugCount.mu.Lock()
	verifyCount := debugCount.verifyFail["hello1"]
	debugCount.mu.Unlock()
	if verifyCount > 1 {
		t.Fatalf("expected hello1 verify counter <= 1, got %d", verifyCount)
	}
}

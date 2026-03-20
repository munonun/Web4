package proto

import (
	"encoding/hex"
	"testing"

	"web4mvp/internal/crypto"
)

func TestEncodePeerExchangeReqBudgetedOmitsMLDSAPubKey(t *testing.T) {
	pub, _, err := crypto.GenKeypair()
	if err != nil {
		t.Fatalf("GenKeypair failed: %v", err)
	}
	req := PeerExchangeReqMsg{
		Type:         MsgTypePeerExchangeReq,
		ProtoVersion: ProtoVersion,
		Suite:        Suite,
		K:            8,
		FromNodeID:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		PubKey:       hex.EncodeToString(pub),
	}
	raw, err := EncodePeerExchangeReq(req)
	if err != nil {
		t.Fatalf("EncodePeerExchangeReq failed: %v", err)
	}
	if len(raw) <= MaxPeerExchangeReqSize {
		t.Fatalf("expected oversized raw request, got %d bytes", len(raw))
	}
	budgeted, compacted, err := EncodePeerExchangeReqBudgeted(req)
	if err != nil {
		t.Fatalf("EncodePeerExchangeReqBudgeted failed: %v", err)
	}
	if !compacted {
		t.Fatalf("expected request compaction for oversized pubkey")
	}
	if len(budgeted) > MaxPeerExchangeReqSize {
		t.Fatalf("budgeted request too large: %d > %d", len(budgeted), MaxPeerExchangeReqSize)
	}
	decoded, err := DecodePeerExchangeReq(budgeted)
	if err != nil {
		t.Fatalf("DecodePeerExchangeReq failed: %v", err)
	}
	if decoded.FromNodeID != req.FromNodeID {
		t.Fatalf("from_node_id mismatch after compaction")
	}
	if decoded.PubKey != "" {
		t.Fatalf("expected pubkey to be omitted after compaction")
	}
}

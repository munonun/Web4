package store

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"web4mvp/internal/proto"
)

func TestStoreRotationKeepsLookup(t *testing.T) {
	savedLines := MaxLinesPerFile
	savedBytes := MaxBytesPerFile
	savedRot := MaxRotations
	MaxLinesPerFile = 2
	MaxBytesPerFile = 1 << 20
	MaxRotations = 2
	t.Cleanup(func() {
		MaxLinesPerFile = savedLines
		MaxBytesPerFile = savedBytes
		MaxRotations = savedRot
	})

	dir := t.TempDir()
	st := New(
		filepath.Join(dir, "contracts.jsonl"),
		filepath.Join(dir, "acks.jsonl"),
		filepath.Join(dir, "repayreqs.jsonl"),
	)

	pubA := make([]byte, 32)
	pubB := make([]byte, 32)
	pubA[0] = 1
	pubB[0] = 2

	for i := 0; i < 3; i++ {
		c := proto.Contract{
			IOU:    proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 1, Nonce: uint64(i + 1)},
			Status: "OPEN",
		}
		if err := st.AddContract(c); err != nil {
			t.Fatalf("add contract failed: %v", err)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "contracts.jsonl.1")); err != nil {
		t.Fatalf("expected rotation file, got %v", err)
	}

	contracts, err := st.ListContracts()
	if err != nil {
		t.Fatalf("list contracts failed: %v", err)
	}
	if len(contracts) != 3 {
		t.Fatalf("expected 3 contracts, got %d", len(contracts))
	}

	cid := proto.ContractID(proto.IOU{Creditor: pubA, Debtor: pubB, Amount: 1, Nonce: 1})
	req := proto.RepayReqMsg{
		Type:         proto.MsgTypeRepayReq,
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ContractID:   hex.EncodeToString(cid[:]),
		ReqNonce:     1,
	}
	if err := st.AddRepayReq(req); err != nil {
		t.Fatalf("add repay req failed: %v", err)
	}
	req2 := req
	req2.ReqNonce = 2
	if err := st.AddRepayReq(req2); err != nil {
		t.Fatalf("add repay req failed: %v", err)
	}
	req3 := req
	req3.ReqNonce = 3
	if err := st.AddRepayReq(req3); err != nil {
		t.Fatalf("add repay req failed: %v", err)
	}

	maxNonce, ok, err := st.MaxRepayReqNonce(req.ContractID)
	if err != nil {
		t.Fatalf("max nonce failed: %v", err)
	}
	if !ok || maxNonce != 3 {
		t.Fatalf("expected max nonce 3, got %d", maxNonce)
	}
	found, err := st.FindRepayReq(req.ContractID, 1)
	if err != nil {
		t.Fatalf("find repay req failed: %v", err)
	}
	if found == nil || found.ReqNonce != 1 {
		t.Fatalf("expected to find nonce 1")
	}
}

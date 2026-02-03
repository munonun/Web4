package daemon

import (
	"encoding/hex"
	"testing"
	"time"

	"web4mvp/internal/proto"
	"web4mvp/internal/zk/linear"
)

func TestDeltaBCanonicalizationStable(t *testing.T) {
	idA := makeNodeID(0x01)
	idB := makeNodeID(0x02)
	msg1 := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(idA[:]), Delta: 1},
			{NodeID: hex.EncodeToString(idB[:]), Delta: -1},
		},
	}
	msg2 := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(idB[:]), Delta: -1},
			{NodeID: hex.EncodeToString(idA[:]), Delta: 0},
			{NodeID: hex.EncodeToString(idA[:]), Delta: 1},
		},
	}
	_, data1, id1, err := canonicalDeltaB(msg1)
	if err != nil {
		t.Fatalf("canonical1: %v", err)
	}
	_, data2, id2, err := canonicalDeltaB(msg2)
	if err != nil {
		t.Fatalf("canonical2: %v", err)
	}
	if string(data1) != string(data2) {
		t.Fatalf("expected canonical bytes to match")
	}
	if id1 != id2 {
		t.Fatalf("expected delta_id to match")
	}
}

func TestDeltaBDedupeCache(t *testing.T) {
	cache := newDeltabCache(4, time.Minute)
	var id [32]byte
	id[0] = 7
	if cache.Seen(id) {
		t.Fatalf("expected unseen id")
	}
	cache.Add(id)
	if !cache.Seen(id) {
		t.Fatalf("expected seen id after add")
	}
}

func TestDeltaBZKMissingOrTampered(t *testing.T) {
	idA := makeNodeID(0x03)
	idB := makeNodeID(0x04)
	members := [][32]byte{idA, idB}
	viewID := membersViewID(members)
	msg := proto.DeltaBMsg{
		ProtoVersion: proto.ProtoVersion,
		Suite:        proto.Suite,
		ViewID:       hex.EncodeToString(viewID[:]),
		Entries: []proto.DeltaBEntry{
			{NodeID: hex.EncodeToString(idA[:]), Delta: 1},
			{NodeID: hex.EncodeToString(idB[:]), Delta: -1},
		},
	}
	if err := verifyDeltaBZK(msg, viewID); err == nil {
		t.Fatalf("expected missing proof to fail")
	}
	ctx, err := deltaBContext(msg, viewID)
	if err != nil {
		t.Fatalf("ctx: %v", err)
	}
	values := []int64{1, -1}
	x, err := linear.ScalarsFromInt64(values)
	if err != nil {
		t.Fatalf("scalars: %v", err)
	}
	L := [][]int64{{1, 1}}
	C, _, bundle, err := linear.CommitAndProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	zk, err := linear.EncodeLinearProof(C, bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.ZK = zk
	if err := verifyDeltaBZK(msg, viewID); err != nil {
		t.Fatalf("expected valid proof, got %v", err)
	}
	msg.ZK.Proofs[0].V = msg.ZK.Proofs[0].V + "A"
	if err := verifyDeltaBZK(msg, viewID); err == nil {
		t.Fatalf("expected tampered proof to fail")
	}
}

func makeNodeID(b byte) [32]byte {
	var id [32]byte
	id[0] = b
	return id
}

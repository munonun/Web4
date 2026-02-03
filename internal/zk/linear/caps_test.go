package linear

import (
	"testing"
)

func TestZKCapsProofs(t *testing.T) {
	L := [][]int64{{1, 1}}
	x, err := ScalarsFromInt64([]int64{1, -1})
	if err != nil {
		t.Fatalf("scalars: %v", err)
	}
	C, _, bundle, err := CommitAndProveLinearNullspace(L, x, []byte("ctx"))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if !VerifyLinearNullspace(L, C, bundle, []byte("ctx")) {
		t.Fatalf("expected verify to pass under caps")
	}
	zk, err := EncodeLinearProof(C, bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	over := maxProofs() + 1
	for len(zk.Proofs) < over {
		zk.Proofs = append(zk.Proofs, zk.Proofs[0])
	}
	if _, _, err := DecodeLinearProof(zk); err == nil {
		t.Fatalf("expected cap rejection")
	}
}

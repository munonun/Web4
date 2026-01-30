package linear

import (
	"testing"

	"web4mvp/internal/zk/pedersen"
)

func TestProveVerifyLinearNullspace(t *testing.T) {
	g := pedersen.Group()
	x := []pedersen.Scalar{
		g.NewScalar().SetUint64(1),
		g.NewScalar().SetUint64(1),
		g.NewScalar().SetUint64(1),
	}
	L := [][]int64{
		{1, -1, 0},
		{0, 1, -1},
	}
	ctx := []byte("ctx-valid")

	C, bundle, err := ProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if !VerifyLinearNullspace(L, C, bundle, ctx) {
		t.Fatalf("verify failed")
	}
}

func TestVerifyWrongContextFails(t *testing.T) {
	g := pedersen.Group()
	x := []pedersen.Scalar{
		g.NewScalar().SetUint64(2),
		g.NewScalar().SetUint64(2),
	}
	L := [][]int64{{1, -1}}
	ctx := []byte("ctx-a")

	C, bundle, err := ProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if VerifyLinearNullspace(L, C, bundle, []byte("ctx-b")) {
		t.Fatalf("expected verify to fail with wrong ctx")
	}
}

func TestTamperCommitmentFails(t *testing.T) {
	g := pedersen.Group()
	x := []pedersen.Scalar{
		g.NewScalar().SetUint64(5),
		g.NewScalar().SetUint64(5),
	}
	L := [][]int64{{1, -1}}
	ctx := []byte("ctx-tamper")

	C, bundle, err := ProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	gGen, _, err := pedersen.Generators()
	if err != nil {
		t.Fatalf("generators failed: %v", err)
	}
	Cbad := make([]pedersen.Element, len(C))
	for i := range C {
		Cbad[i] = C[i].Copy()
	}
	Cbad[0].Add(Cbad[0], gGen)
	if VerifyLinearNullspace(L, Cbad, bundle, ctx) {
		t.Fatalf("expected verify to fail after tampering")
	}
}

func TestWrongMatrixFails(t *testing.T) {
	g := pedersen.Group()
	x := []pedersen.Scalar{
		g.NewScalar().SetUint64(7),
		g.NewScalar().SetUint64(7),
	}
	L := [][]int64{{1, -1}}
	ctx := []byte("ctx-matrix")

	C, bundle, err := ProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	Lbad := [][]int64{{1, 1}}
	if VerifyLinearNullspace(Lbad, C, bundle, ctx) {
		t.Fatalf("expected verify to fail with wrong matrix")
	}
}

func TestSignedCoefficients(t *testing.T) {
	g := pedersen.Group()
	x := []pedersen.Scalar{
		g.NewScalar().SetUint64(3),
		g.NewScalar().SetUint64(6),
	}
	L := [][]int64{{2, -1}}
	ctx := []byte("ctx-signed")

	C, bundle, err := ProveLinearNullspace(L, x, ctx)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if !VerifyLinearNullspace(L, C, bundle, ctx) {
		t.Fatalf("verify failed for signed coefficients")
	}
}

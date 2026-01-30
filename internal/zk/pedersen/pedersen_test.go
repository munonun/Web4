package pedersen

import "testing"

func TestCommitVectorDeterministic(t *testing.T) {
	g := Group()
	x := []Scalar{
		g.NewScalar().SetUint64(10),
		g.NewScalar().SetUint64(20),
	}
	r := []Scalar{
		g.NewScalar().SetUint64(1),
		g.NewScalar().SetUint64(2),
	}
	C1 := commitVectorWithR(t, x, r)
	C2 := commitVectorWithR(t, x, r)
	for i := range C1 {
		if !C1[i].IsEqual(C2[i]) {
			t.Fatalf("commitment mismatch at %d", i)
		}
	}
}

// test-only helper for deterministic commitments
func commitVectorWithR(t *testing.T, x []Scalar, r []Scalar) []Element {
	t.Helper()
	if len(x) != len(r) {
		t.Fatalf("dimension mismatch")
	}
	g, h, err := Generators()
	if err != nil {
		t.Fatalf("generators failed: %v", err)
	}
	C := make([]Element, len(x))
	for i := range x {
		C[i] = commit(g, h, x[i], r[i])
	}
	return C
}

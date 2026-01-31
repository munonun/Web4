package linear

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/zk/dl"

	"web4mvp/internal/crypto"
	"web4mvp/internal/zk/pedersen"
)

type ProofBundle struct {
	Proofs []dl.Proof
}

const (
	proofLabel = "web4/zk/linear/proof/v0"
)

// ProveLinearNullspace proves that commitments C open to a hidden vector x
// satisfying Lx = 0, using the corresponding randomness r.
func ProveLinearNullspace(L [][]int64, C []pedersen.Element, r []pedersen.Scalar, ctx []byte) (*ProofBundle, error) {
	if len(L) == 0 {
		return nil, fmt.Errorf("empty matrix")
	}
	if len(C) == 0 || len(r) == 0 {
		return nil, fmt.Errorf("empty commitments")
	}
	rowLen := len(L[0])
	if rowLen != len(C) || rowLen != len(r) {
		return nil, fmt.Errorf("dimension mismatch")
	}
	for i := 1; i < len(L); i++ {
		if len(L[i]) != rowLen {
			return nil, fmt.Errorf("ragged matrix")
		}
	}
	proofs, err := proveRows(L, C, r, ctx)
	if err != nil {
		return nil, err
	}
	return &ProofBundle{Proofs: proofs}, nil
}

// CommitAndProveLinearNullspace commits to x and proves Lx = 0.
// Returns commitments and randomness for caller-side bookkeeping/tests.
func CommitAndProveLinearNullspace(L [][]int64, x []pedersen.Scalar, ctx []byte) ([]pedersen.Element, []pedersen.Scalar, *ProofBundle, error) {
	if len(L) == 0 {
		return nil, nil, nil, fmt.Errorf("empty matrix")
	}
	if len(x) == 0 {
		return nil, nil, nil, fmt.Errorf("empty vector")
	}
	rowLen := len(L[0])
	if rowLen != len(x) {
		return nil, nil, nil, fmt.Errorf("dimension mismatch")
	}
	for i := 1; i < len(L); i++ {
		if len(L[i]) != rowLen {
			return nil, nil, nil, fmt.Errorf("ragged matrix")
		}
	}
	C, r, err := pedersen.CommitVector(x, ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	bundle, err := ProveLinearNullspace(L, C, r, ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return C, r, bundle, nil
}

func VerifyLinearNullspace(L [][]int64, C []pedersen.Element, bundle *ProofBundle, ctx []byte) bool {
	if bundle == nil {
		return false
	}
	if len(L) == 0 || len(C) == 0 {
		return false
	}
	rowLen := len(L[0])
	if rowLen != len(C) {
		return false
	}
	for i := 1; i < len(L); i++ {
		if len(L[i]) != rowLen {
			return false
		}
	}
	if len(bundle.Proofs) != len(L) {
		return false
	}
	_, h, err := pedersen.Generators()
	if err != nil {
		return false
	}

	LHash := hashMatrix(L)
	CHash, err := hashCommitments(C)
	if err != nil {
		return false
	}
	for j, row := range L {
		D, err := rowCommitment(row, C)
		if err != nil {
			return false
		}
		otherInfo := buildOtherInfo(ctx, LHash, CHash, j)
		if !dl.Verify(pedersen.Group(), h, D, bundle.Proofs[j], ctx, otherInfo) {
			return false
		}
	}
	return true
}

func proveRows(L [][]int64, C []pedersen.Element, r []pedersen.Scalar, ctx []byte) ([]dl.Proof, error) {
	if len(L) == 0 {
		return nil, fmt.Errorf("empty matrix")
	}
	_, h, err := pedersen.Generators()
	if err != nil {
		return nil, err
	}

	LHash := hashMatrix(L)
	CHash, err := hashCommitments(C)
	if err != nil {
		return nil, err
	}
	proofs := make([]dl.Proof, len(L))
	for j, row := range L {
		rho, err := rowRandomizer(row, r)
		if err != nil {
			return nil, err
		}
		D, err := rowCommitment(row, C)
		if err != nil {
			return nil, err
		}
		otherInfo := buildOtherInfo(ctx, LHash, CHash, j)
		proofs[j] = dl.Prove(pedersen.Group(), h, D, rho, ctx, otherInfo, rand.Reader)
	}
	return proofs, nil
}

func rowCommitment(row []int64, C []pedersen.Element) (pedersen.Element, error) {
	if len(row) != len(C) {
		return nil, fmt.Errorf("dimension mismatch")
	}
	g := pedersen.Group()
	acc := g.Identity()
	for i, a := range row {
		if a == 0 {
			continue
		}
		if C[i] == nil || C[i].Group() != g {
			return nil, fmt.Errorf("bad commitment at %d", i)
		}
		s := scalarFromInt64(g, a)
		term := g.NewElement().Mul(C[i], s)
		acc.Add(acc, term)
	}
	return acc, nil
}

func rowRandomizer(row []int64, r []pedersen.Scalar) (pedersen.Scalar, error) {
	if len(row) != len(r) {
		return nil, fmt.Errorf("dimension mismatch")
	}
	g := pedersen.Group()
	acc := g.NewScalar().SetUint64(0)
	for i, a := range row {
		if a == 0 {
			continue
		}
		if r[i] == nil || r[i].Group() != g {
			return nil, fmt.Errorf("bad randomizer at %d", i)
		}
		s := scalarFromInt64(g, a)
		term := g.NewScalar().Mul(r[i], s)
		acc.Add(acc, term)
	}
	return acc, nil
}

func scalarFromInt64(g group.Group, v int64) group.Scalar {
	s := g.NewScalar()
	if v == 0 {
		return s
	}
	if v > 0 {
		s.SetUint64(uint64(v))
		return s
	}
	abs := new(big.Int).SetInt64(v)
	abs.Abs(abs)
	s.SetBigInt(abs)
	return s.Neg(s)
}

// ScalarsFromInt64 converts signed int64 values into group scalars.
func ScalarsFromInt64(vals []int64) ([]pedersen.Scalar, error) {
	if len(vals) == 0 {
		return nil, fmt.Errorf("empty values")
	}
	g := pedersen.Group()
	out := make([]pedersen.Scalar, len(vals))
	for i, v := range vals {
		out[i] = scalarFromInt64(g, v)
	}
	return out, nil
}

func hashMatrix(L [][]int64) []byte {
	buf := make([]byte, 0, 16+8*len(L))
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(len(L)))
	buf = append(buf, tmp...)
	if len(L) > 0 {
		binary.BigEndian.PutUint64(tmp, uint64(len(L[0])))
		buf = append(buf, tmp...)
		for _, row := range L {
			for _, v := range row {
				binary.BigEndian.PutUint64(tmp, uint64(v))
				buf = append(buf, tmp...)
			}
		}
	}
	return crypto.SHA3_256(buf)
}

func hashCommitments(C []pedersen.Element) ([]byte, error) {
	g := pedersen.Group()
	buf := make([]byte, 0, len(C)*int(g.Params().CompressedElementLength))
	for i := range C {
		if C[i] == nil || C[i].Group() != g {
			return nil, fmt.Errorf("bad commitment at %d", i)
		}
		b, err := C[i].MarshalBinaryCompress()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return crypto.SHA3_256(buf), nil
}

func buildOtherInfo(ctx, LHash, CHash []byte, row int) []byte {
	buf := make([]byte, 0, len(proofLabel)+len(ctx)+len(LHash)+len(CHash)+4)
	buf = append(buf, []byte(proofLabel)...)
	buf = append(buf, ctx...)
	buf = append(buf, LHash...)
	buf = append(buf, CHash...)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(row))
	buf = append(buf, tmp...)
	return crypto.SHA3_256(buf)
}

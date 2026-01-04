package state

import "fmt"

// State holds the instantaneous imbalance vector (delta).
type State struct {
	Delta []int64
}

// Proposal represents a candidate next imbalance vector.
type Proposal struct {
	Delta []int64
}

func NewState(delta []int64) State {
	return State{Delta: clone(delta)}
}

func (s State) Propose(delta []int64) Proposal {
	return Proposal{Delta: clone(delta)}
}

func (s State) Validate(laplacian [][]int64) error {
	return validateDelta(s.Delta, laplacian)
}

func (p Proposal) Validate(laplacian [][]int64) error {
	return validateDelta(p.Delta, laplacian)
}

func validateDelta(delta []int64, laplacian [][]int64) error {
	var sum int64
	for _, v := range delta {
		sum += v
	}
	if sum != 0 {
		return fmt.Errorf("sum delta != 0")
	}
	if len(laplacian) != len(delta) {
		return fmt.Errorf("laplacian size mismatch")
	}
	for i, row := range laplacian {
		if len(row) != len(delta) {
			return fmt.Errorf("laplacian row %d size mismatch", i)
		}
		var acc int64
		for j, lij := range row {
			acc += lij * delta[j]
		}
		if acc != 0 {
			return fmt.Errorf("laplacian constraint violated at row %d", i)
		}
	}
	return nil
}

func clone(src []int64) []int64 {
	if len(src) == 0 {
		return nil
	}
	dst := make([]int64, len(src))
	copy(dst, src)
	return dst
}

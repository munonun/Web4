package state

import (
	"fmt"
	"sort"
	"sync"
)

type Field struct {
	mu  sync.Mutex
	b   map[[32]byte]int64
	phi map[[32]byte]float64
}

func NewField() *Field {
	return &Field{
		b:   make(map[[32]byte]int64),
		phi: make(map[[32]byte]float64),
	}
}

func (f *Field) ApplyDelta(members [][32]byte, deltas map[[32]byte]int64, iters int) error {
	if len(members) == 0 {
		return fmt.Errorf("empty member set")
	}
	if iters < 0 {
		iters = 0
	}
	sort.Slice(members, func(i, j int) bool {
		return lessNodeID(members[i], members[j])
	})

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, id := range members {
		if _, ok := f.b[id]; !ok {
			f.b[id] = 0
		}
		if _, ok := f.phi[id]; !ok {
			f.phi[id] = 0
		}
	}
	for id, d := range deltas {
		if _, ok := f.b[id]; !ok {
			return fmt.Errorf("delta for unknown member")
		}
		f.b[id] += d
	}

	if iters == 0 {
		return nil
	}
	if len(members) < 2 {
		return nil
	}
	n := float64(len(members))
	denom := n - 1.0
	for k := 0; k < iters; k++ {
		sumPhi := 0.0
		for _, id := range members {
			sumPhi += f.phi[id]
		}
		next := make(map[[32]byte]float64, len(members))
		for _, id := range members {
			phiOld := f.phi[id]
			bi := float64(f.b[id])
			next[id] = (bi + (sumPhi - phiOld)) / denom
		}
		for id, v := range next {
			f.phi[id] = v
		}
	}
	return nil
}

func (f *Field) Snapshot(members [][32]byte) (map[[32]byte]int64, map[[32]byte]float64) {
	outB := make(map[[32]byte]int64)
	outPhi := make(map[[32]byte]float64)
	if f == nil {
		return outB, outPhi
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range members {
		if v, ok := f.b[id]; ok {
			outB[id] = v
		}
		if v, ok := f.phi[id]; ok {
			outPhi[id] = v
		}
	}
	return outB, outPhi
}

func lessNodeID(a, b [32]byte) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		return a[i] < b[i]
	}
	return false
}

package math4

import (
	"fmt"
	"sync"
)

type Update struct {
	A [32]byte // user/party id
	B [32]byte
	V int64 // signed delta magnitude (positive)
}

type LocalChecker interface {
	Check(u Update) error
}

type Options struct {
	MaxAbsV          int64
	MaxAbsS          int64
	AlphaNumerator   int64
	AlphaDenominator int64
}

type Checker struct {
	mu     sync.Mutex
	opts   Options
	scores map[[32]byte]int64
}

// NOTE: These are MVP-level heuristic guards for local constraint checking.
// They are NOT protocol invariants and may become configurable in future versions.
const (
	defaultMaxAbsV        int64 = 1_000_000
	defaultAlphaNumerator int64 = 9
	defaultAlphaDenom     int64 = 10
)

func NewLocalChecker(opts Options) *Checker {
	norm := normalizeOptions(opts)
	return &Checker{
		opts:   norm,
		scores: make(map[[32]byte]int64),
	}
}

func normalizeOptions(opts Options) Options {
	if opts.MaxAbsV <= 0 {
		opts.MaxAbsV = defaultMaxAbsV
	}
	if opts.MaxAbsS <= 0 {
		opts.MaxAbsS = opts.MaxAbsV * 5
	}
	if opts.AlphaNumerator <= 0 || opts.AlphaDenominator <= 0 || opts.AlphaNumerator > opts.AlphaDenominator {
		opts.AlphaNumerator = defaultAlphaNumerator
		opts.AlphaDenominator = defaultAlphaDenom
	}
	return opts
}

func (c *Checker) Check(u Update) error {
	if u.A == u.B {
		return fmt.Errorf("A == B")
	}
	if u.V <= 0 {
		return fmt.Errorf("V must be positive")
	}
	if u.V > c.opts.MaxAbsV {
		return fmt.Errorf("V exceeds MaxAbsV")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	decayA := c.decay(c.scores[u.A])
	decayB := c.decay(c.scores[u.B])
	sA := decayA - u.V
	sB := decayB + u.V
	if abs64(sA) > c.opts.MaxAbsS || abs64(sB) > c.opts.MaxAbsS {
		return fmt.Errorf("smoothness threshold exceeded")
	}
	c.scores[u.A] = sA
	c.scores[u.B] = sB
	return nil
}

func (c *Checker) decay(v int64) int64 {
	return (v * c.opts.AlphaNumerator) / c.opts.AlphaDenominator
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

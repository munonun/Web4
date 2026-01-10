package math4

import (
	"fmt"
	"sync"
	"time"
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
	MaxAbsV           int64
	MaxAbsS           int64
	AlphaNumerator    int64
	AlphaDenominator  int64
	ColdStartMaxAbsV  int64
	ColdStartMaxAbsS  int64
	ColdStartUpdates  int64
	ColdStartDuration time.Duration
	Now               func() time.Time
}

type Checker struct {
	mu     sync.Mutex
	opts   Options
	scores map[[32]byte]int64
	start  time.Time
	count  int64
}

// NOTE: These are MVP-level heuristic guards for local constraint checking.
// They are NOT protocol invariants and may become configurable in future versions.
const (
	defaultMaxAbsV        int64 = 1_000_000
	defaultAlphaNumerator int64 = 9
	defaultAlphaDenom     int64 = 10
	defaultColdUpdates    int64 = 10
)

func NewLocalChecker(opts Options) *Checker {
	norm := normalizeOptions(opts)
	return &Checker{
		opts:   norm,
		scores: make(map[[32]byte]int64),
		start:  norm.Now(),
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
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ColdStartUpdates == 0 && opts.ColdStartDuration == 0 {
		opts.ColdStartUpdates = defaultColdUpdates
	}
	if opts.ColdStartMaxAbsV <= 0 {
		opts.ColdStartMaxAbsV = clampMin(opts.MaxAbsV/2, 1)
	}
	if opts.ColdStartMaxAbsS <= 0 {
		opts.ColdStartMaxAbsS = clampMin(opts.MaxAbsS/2, 1)
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
	c.mu.Lock()
	defer c.mu.Unlock()

	maxV, maxS := c.limits()
	if u.V > maxV {
		return fmt.Errorf("V exceeds MaxAbsV")
	}
	decayA := c.decay(c.scores[u.A])
	decayB := c.decay(c.scores[u.B])
	sA := decayA - u.V
	sB := decayB + u.V
	if abs64(sA) > maxS || abs64(sB) > maxS {
		return fmt.Errorf("smoothness threshold exceeded")
	}
	c.scores[u.A] = sA
	c.scores[u.B] = sB
	c.count++
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

func (c *Checker) limits() (int64, int64) {
	if c.opts.ColdStartUpdates <= 0 && c.opts.ColdStartDuration <= 0 {
		return c.opts.MaxAbsV, c.opts.MaxAbsS
	}
	if c.opts.ColdStartUpdates > 0 && c.count < c.opts.ColdStartUpdates {
		return c.opts.ColdStartMaxAbsV, c.opts.ColdStartMaxAbsS
	}
	if c.opts.ColdStartDuration > 0 && c.opts.Now().Sub(c.start) < c.opts.ColdStartDuration {
		return c.opts.ColdStartMaxAbsV, c.opts.ColdStartMaxAbsS
	}
	return c.opts.MaxAbsV, c.opts.MaxAbsS
}

func clampMin(v, min int64) int64 {
	if v < min {
		return min
	}
	return v
}

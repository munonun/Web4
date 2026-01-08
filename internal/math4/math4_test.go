package math4

import "testing"

func TestCheckerAllowsSingleUpdate(t *testing.T) {
	c := NewLocalChecker(Options{
		MaxAbsV:          10,
		MaxAbsS:          10,
		AlphaNumerator:   1,
		AlphaDenominator: 1,
	})
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	if err := c.Check(Update{A: a, B: b, V: 5}); err != nil {
		t.Fatalf("expected update ok, got %v", err)
	}
}

func TestCheckerRejectsSameParty(t *testing.T) {
	c := NewLocalChecker(Options{MaxAbsV: 10, MaxAbsS: 10})
	var a [32]byte
	a[0] = 1
	if err := c.Check(Update{A: a, B: a, V: 1}); err == nil {
		t.Fatalf("expected same-party rejection")
	}
}

func TestCheckerRejectsZeroOrTooLarge(t *testing.T) {
	c := NewLocalChecker(Options{MaxAbsV: 3, MaxAbsS: 10})
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	if err := c.Check(Update{A: a, B: b, V: 0}); err == nil {
		t.Fatalf("expected zero rejection")
	}
	if err := c.Check(Update{A: a, B: b, V: 4}); err == nil {
		t.Fatalf("expected MaxAbsV rejection")
	}
}

func TestCheckerRejectsBurstUpdates(t *testing.T) {
	c := NewLocalChecker(Options{
		MaxAbsV:          5,
		MaxAbsS:          6,
		AlphaNumerator:   1,
		AlphaDenominator: 1,
	})
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	if err := c.Check(Update{A: a, B: b, V: 4}); err != nil {
		t.Fatalf("expected first update ok, got %v", err)
	}
	if err := c.Check(Update{A: a, B: b, V: 4}); err == nil {
		t.Fatalf("expected burst rejection")
	}
}

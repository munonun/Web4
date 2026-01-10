package math4

import "testing"

func TestCheckerAllowsSingleUpdate(t *testing.T) {
	c := NewLocalChecker(Options{
		MaxAbsV:          10,
		MaxAbsS:          10,
		AlphaNumerator:   1,
		AlphaDenominator: 1,
		ColdStartUpdates: -1,
	})
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	if err := c.Check(Update{A: a, B: b, V: 5}); err != nil {
		t.Fatalf("expected update ok, got %v", err)
	}
}

func TestCheckerRejectsSameParty(t *testing.T) {
	c := NewLocalChecker(Options{MaxAbsV: 10, MaxAbsS: 10, ColdStartUpdates: -1})
	var a [32]byte
	a[0] = 1
	if err := c.Check(Update{A: a, B: a, V: 1}); err == nil {
		t.Fatalf("expected same-party rejection")
	}
}

func TestCheckerRejectsZeroOrTooLarge(t *testing.T) {
	c := NewLocalChecker(Options{MaxAbsV: 3, MaxAbsS: 10, ColdStartUpdates: -1})
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
		ColdStartUpdates: -1,
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

func TestCheckerColdStartRejectsAfterRestart(t *testing.T) {
	cold := Options{
		MaxAbsV:          10,
		MaxAbsS:          10,
		ColdStartMaxAbsV: 3,
		ColdStartMaxAbsS: 3,
		ColdStartUpdates: 2,
	}
	var a, b [32]byte
	a[0] = 1
	b[0] = 2

	c1 := NewLocalChecker(cold)
	if err := c1.Check(Update{A: a, B: b, V: 3}); err != nil {
		t.Fatalf("expected initial update ok, got %v", err)
	}

	c2 := NewLocalChecker(cold)
	if err := c2.Check(Update{A: a, B: b, V: 4}); err == nil {
		t.Fatalf("expected cold-start rejection after restart")
	}
}

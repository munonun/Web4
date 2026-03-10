package daemon

import (
	"testing"
	"time"
)

func TestBootstrapPexInFlightGuard(t *testing.T) {
	cm := &connMan{
		bootstrap:       []string{"seed.example:443"},
		bootPexNext:     make(map[string]time.Time),
		bootPexInFlight: make(map[string]bool),
		bootPexFail:     make(map[string]int),
	}
	now := time.Now()
	if !cm.beginBootstrapPex("seed.example:443", now) {
		t.Fatalf("expected first bootstrap pex to start")
	}
	if cm.beginBootstrapPex("seed.example:443", now.Add(time.Millisecond)) {
		t.Fatalf("expected overlapping bootstrap pex to be blocked")
	}
	cm.finishBootstrapPex("seed.example:443", now, nil)
	if cm.beginBootstrapPex("seed.example:443", now.Add(time.Second)) {
		t.Fatalf("expected min interval to block immediate retry")
	}
}

func TestBootstrapPexFailureBackoff(t *testing.T) {
	t.Setenv("WEB4_BOOTSTRAP_PEX_INTERVAL_SEC", "10")
	t.Setenv("WEB4_BOOTSTRAP_PEX_MAX_BACKOFF_SEC", "40")
	cm := &connMan{
		bootstrap:       []string{"seed.example:443"},
		bootPexNext:     make(map[string]time.Time),
		bootPexInFlight: make(map[string]bool),
		bootPexFail:     make(map[string]int),
	}
	now := time.Now()
	if !cm.beginBootstrapPex("seed.example:443", now) {
		t.Fatalf("expected first bootstrap pex to start")
	}
	cm.finishBootstrapPex("seed.example:443", now, errDialAddrBackoff)
	next1 := cm.bootPexNext["seed.example:443"]
	if got := next1.Sub(now); got < 10*time.Second || got > 11*time.Second {
		t.Fatalf("expected first failure backoff about 10s, got %v", got)
	}
	if !cm.beginBootstrapPex("seed.example:443", next1.Add(time.Millisecond)) {
		t.Fatalf("expected retry after first backoff")
	}
	cm.finishBootstrapPex("seed.example:443", next1.Add(time.Millisecond), errDialAddrBackoff)
	next2 := cm.bootPexNext["seed.example:443"]
	if got := next2.Sub(next1.Add(time.Millisecond)); got < 20*time.Second || got > 21*time.Second {
		t.Fatalf("expected second failure backoff about 20s, got %v", got)
	}
	if !cm.beginBootstrapPex("seed.example:443", next2.Add(time.Millisecond)) {
		t.Fatalf("expected retry after second backoff")
	}
	cm.finishBootstrapPex("seed.example:443", next2.Add(time.Millisecond), errDialAddrBackoff)
	next3 := cm.bootPexNext["seed.example:443"]
	if got := next3.Sub(next2.Add(time.Millisecond)); got < 40*time.Second || got > 41*time.Second {
		t.Fatalf("expected capped failure backoff about 40s, got %v", got)
	}
}

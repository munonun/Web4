package network

import "testing"

func TestIPLimiterConnCap(t *testing.T) {
	lim := newIPLimiter(1, 0)
	if !lim.acquireConn("1.2.3.4") {
		t.Fatalf("expected first conn acquire")
	}
	if lim.acquireConn("1.2.3.4") {
		t.Fatalf("expected conn cap")
	}
	lim.releaseConn("1.2.3.4")
	if !lim.acquireConn("1.2.3.4") {
		t.Fatalf("expected acquire after release")
	}
}

func TestIPLimiterStreamCap(t *testing.T) {
	lim := newIPLimiter(0, 2)
	if !lim.acquireStream("1.2.3.4") || !lim.acquireStream("1.2.3.4") {
		t.Fatalf("expected stream acquire")
	}
	if lim.acquireStream("1.2.3.4") {
		t.Fatalf("expected stream cap")
	}
	lim.releaseStream("1.2.3.4")
	if !lim.acquireStream("1.2.3.4") {
		t.Fatalf("expected acquire after release")
	}
}

func TestIPLimiterSeparateIPs(t *testing.T) {
	lim := newIPLimiter(1, 1)
	if !lim.acquireConn("1.2.3.4") {
		t.Fatalf("expected first conn")
	}
	if !lim.acquireConn("2.3.4.5") {
		t.Fatalf("expected separate ip conn")
	}
	if !lim.acquireStream("1.2.3.4") {
		t.Fatalf("expected stream acquire")
	}
	if !lim.acquireStream("2.3.4.5") {
		t.Fatalf("expected separate ip stream")
	}
}

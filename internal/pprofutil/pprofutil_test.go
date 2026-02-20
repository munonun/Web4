package pprofutil

import "testing"

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{addr: "127.0.0.1:6060", ok: true},
		{addr: "localhost:6060", ok: true},
		{addr: "[::1]:6060", ok: true},
		{addr: "0.0.0.0:6060", ok: false},
		{addr: "192.168.1.10:6060", ok: false},
		{addr: "bad-addr", ok: false},
	}
	for _, tc := range cases {
		if got := isLoopbackBind(tc.addr); got != tc.ok {
			t.Fatalf("isLoopbackBind(%q)=%v want %v", tc.addr, got, tc.ok)
		}
	}
}

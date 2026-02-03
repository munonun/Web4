package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestBannerRoleForMode(t *testing.T) {
	color.NoColor = true
	t.Setenv("WEB4_MAX_CONNS", "10")
	t.Setenv("WEB4_MAX_STREAMS_PER_CONN", "2")
	t.Setenv("WEB4_PEER_EXCHANGE_MAX", "5")

	root := t.TempDir()

	var buf bytes.Buffer
	banner(&buf, root, "peer", nil)
	out := buf.String()
	if !strings.Contains(out, "Mode: peer") {
		t.Fatalf("expected mode line for peer, got: %s", out)
	}
	if !strings.Contains(out, "Role: peer (relay + verifier)") {
		t.Fatalf("expected peer role line, got: %s", out)
	}
	if !ordered(out, "Mode: peer", "Role: peer (relay + verifier)", "Limits:", "Peers:", "Scopes:") {
		t.Fatalf("expected ordered banner fields, got: %s", out)
	}

	buf.Reset()
	banner(&buf, root, "bootstrap", nil)
	out = buf.String()
	if !strings.Contains(out, "Mode: bootstrap") {
		t.Fatalf("expected mode line for bootstrap, got: %s", out)
	}
	if !strings.Contains(out, "Role: bootstrap (peer discovery / exchange only)") {
		t.Fatalf("expected bootstrap role line, got: %s", out)
	}
	if !ordered(out, "Mode: bootstrap", "Role: bootstrap (peer discovery / exchange only)", "Limits:", "Peers:", "Scopes:") {
		t.Fatalf("expected ordered banner fields, got: %s", out)
	}
}

func ordered(s string, parts ...string) bool {
	last := -1
	for _, p := range parts {
		idx := strings.Index(s, p)
		if idx == -1 || idx <= last {
			return false
		}
		last = idx
	}
	return true
}

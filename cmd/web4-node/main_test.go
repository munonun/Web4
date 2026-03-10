package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"--help"}, &out, &out)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "web4-node") {
		t.Fatalf("expected help output to mention web4-node")
	}
}

func TestValidateRunTLSConfigOutboundOnlyAllowsNoTLSFlags(t *testing.T) {
	if err := validateRunTLSConfig(true, false, "", ""); err != nil {
		t.Fatalf("expected outbound-only mode to allow no TLS flags, got: %v", err)
	}
}

func TestValidateRunTLSConfigServerModeRequiresTLSMode(t *testing.T) {
	if err := validateRunTLSConfig(false, false, "", ""); err == nil {
		t.Fatalf("expected TLS mode validation error")
	}
}

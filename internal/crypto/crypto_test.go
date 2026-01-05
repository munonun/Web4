package crypto

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestKDFDeterminismAndContext(t *testing.T) {
	ikm := []byte("ikm")
	ctxA := "web4:v0:quic:tx"
	ctxB := "web4:v0:quic:rx"

	prk1, err := Extract(nil, ikm)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	prk2, err := Extract(nil, ikm)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !bytes.Equal(prk1, prk2) {
		t.Fatalf("Extract not deterministic")
	}

	okm1, err := Expand(prk1, []byte(ctxA), 32)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	okm2, err := Expand(prk2, []byte(ctxA), 32)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	if !bytes.Equal(okm1, okm2) {
		t.Fatalf("Expand not deterministic")
	}

	keyA1, err := DeriveKeyE(ikm, ctxA, 32)
	if err != nil {
		t.Fatalf("DeriveKeyE failed: %v", err)
	}
	keyA2, err := DeriveKeyE(ikm, ctxA, 32)
	if err != nil {
		t.Fatalf("DeriveKeyE failed: %v", err)
	}
	if !bytes.Equal(keyA1, keyA2) {
		t.Fatalf("DeriveKeyE not deterministic")
	}

	keyB, err := DeriveKeyE(ikm, ctxB, 32)
	if err != nil {
		t.Fatalf("DeriveKeyE failed: %v", err)
	}
	if bytes.Equal(keyA1, keyB) {
		t.Fatalf("expected different keys for different contexts")
	}
}

func TestDeriveKeyDomainSeparation(t *testing.T) {
	ikm := []byte("ikm")
	_, err := DeriveKeyE(ikm, "bad:context", 32)
	if err == nil {
		t.Fatalf("expected domain separation error")
	}
}

func TestEphemeralRedactionFormatting(t *testing.T) {
	eph, err := GenerateEphemeral()
	if err != nil {
		t.Fatalf("generate ephemeral failed: %v", err)
	}
	defer eph.Destroy()

	outputs := []string{
		fmt.Sprintf("%v", eph),
		fmt.Sprintf("%+v", eph),
		fmt.Sprintf("%#v", eph),
		fmt.Sprintf("%s", eph),
	}

	reHex := regexp.MustCompile(`[0-9a-fA-F]{64,}`)
	reB64 := regexp.MustCompile(`[A-Za-z0-9+/]{64,}={0,2}`)
	for i, out := range outputs {
		if !strings.Contains(out, "REDACTED") {
			t.Fatalf("output %d missing redaction token: %q", i, out)
		}
		if reHex.MatchString(out) || reB64.MatchString(out) {
			t.Fatalf("output %d contains long key-like material: %q", i, out)
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "priv") || strings.Contains(lower, "seed") || strings.Contains(lower, "key material") {
			t.Fatalf("output %d contains sensitive words: %q", i, out)
		}
		if strings.Contains(out, "0x") || strings.Contains(out, "[]byte") {
			t.Fatalf("output %d looks like raw bytes: %q", i, out)
		}
	}
}

func TestEphemeralDestroyed(t *testing.T) {
	eph, err := GenerateEphemeral()
	if err != nil {
		t.Fatalf("generate ephemeral failed: %v", err)
	}
	peer, err := GenerateEphemeral()
	if err != nil {
		t.Fatalf("generate peer ephemeral failed: %v", err)
	}
	peerPub, err := peer.Public()
	if err != nil {
		t.Fatalf("peer public failed: %v", err)
	}
	peer.Destroy()

	eph.Destroy()
	if _, err := eph.Public(); err == nil {
		t.Fatalf("expected error on Public after destroy")
	}
	if _, err := eph.Shared(peerPub); err == nil {
		t.Fatalf("expected error on Shared after destroy")
	}
}

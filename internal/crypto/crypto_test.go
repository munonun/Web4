package crypto

import (
	"bytes"
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

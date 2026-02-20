package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestSessionKDFVectors(t *testing.T) {
	ss := make([]byte, 32)
	for i := range ss {
		ss[i] = byte(i)
	}
	transcript := make([]byte, 32)
	for i := range transcript {
		transcript[i] = byte(i + 32)
	}

	keys, err := DeriveSessionKeys(ss, transcript)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}

	expect := map[string]string{
		"K_master":   "5d208bbfef5bc355c2ac109fbfa1efd6d1b236469031340eca485980d26bb238",
		"K_send":     "eedd4363c81cb77db1737b70c06eeb27aef18d1f09e36c14a8a6c6693b5b0fdf",
		"K_recv":     "28ca5e6b92fcb0491aedac5775ec87843ee1b946c859e8efe88cb9be00fe2b9a",
		"nonce_send": "c5337caae56ded3ef6e66fe540b4615106358d72978b3a26",
		"nonce_recv": "58651b961c3c0d57604bfd1acd659b0e125e03bee312bfac",
	}

	if got := hex.EncodeToString(keys.Master); got != expect["K_master"] {
		t.Fatalf("K_master mismatch: got %s", got)
	}
	if got := hex.EncodeToString(keys.SendKey); got != expect["K_send"] {
		t.Fatalf("K_send mismatch: got %s", got)
	}
	if got := hex.EncodeToString(keys.RecvKey); got != expect["K_recv"] {
		t.Fatalf("K_recv mismatch: got %s", got)
	}
	if got := hex.EncodeToString(keys.NonceBaseSend); got != expect["nonce_send"] {
		t.Fatalf("nonce_base_send mismatch: got %s", got)
	}
	if got := hex.EncodeToString(keys.NonceBaseRecv); got != expect["nonce_recv"] {
		t.Fatalf("nonce_base_recv mismatch: got %s", got)
	}

	keys2, err := DeriveSessionKeys(ss, transcript)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}
	if !bytes.Equal(keys.SendKey, keys2.SendKey) || !bytes.Equal(keys.RecvKey, keys2.RecvKey) {
		t.Fatalf("DeriveSessionKeys not deterministic")
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

func TestSignDigestDefaultUsesMLDSA(t *testing.T) {
	t.Setenv("WEB4_ALLOW_RSA_PSS", "")
	pub, priv, err := GenMLDSAKeypair()
	if err != nil {
		t.Fatalf("GenMLDSAKeypair failed: %v", err)
	}
	digest := SHA3_256([]byte("mldsa-default-signing"))
	sig, err := SignDigest(priv, digest)
	if err != nil {
		t.Fatalf("SignDigest failed for mldsa key: %v", err)
	}
	if !VerifyDigest(pub, digest, sig) {
		t.Fatalf("VerifyDigest failed for mldsa signature")
	}
}

func TestSignDigestRejectsRSAWithoutFlag(t *testing.T) {
	t.Setenv("WEB4_ALLOW_RSA_PSS", "")
	_, priv, err := GenKeypair()
	if err != nil {
		t.Fatalf("GenKeypair failed: %v", err)
	}
	_, err = SignDigest(priv, SHA3_256([]byte("rsa-disabled")))
	if err == nil {
		t.Fatalf("expected rsa signing to be rejected without WEB4_ALLOW_RSA_PSS")
	}
	if !strings.Contains(err.Error(), "WEB4_ALLOW_RSA_PSS=1") {
		t.Fatalf("expected explicit gate error, got: %v", err)
	}
}

func TestSignDigestAllowsRSAWithFlag(t *testing.T) {
	t.Setenv("WEB4_ALLOW_RSA_PSS", "1")
	pub, priv, err := GenKeypair()
	if err != nil {
		t.Fatalf("GenKeypair failed: %v", err)
	}
	digest := SHA3_256([]byte("rsa-enabled"))
	sig, err := SignDigest(priv, digest)
	if err != nil {
		t.Fatalf("SignDigest failed for rsa key with flag: %v", err)
	}
	if !VerifyDigest(pub, digest, sig) {
		t.Fatalf("VerifyDigest failed for rsa signature")
	}
}

package crypto

import (
	"bytes"
	"testing"
)

func TestSessionAEADSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, XKeySize)
	base := bytes.Repeat([]byte{0x02}, XNonceSize)
	var fromID [32]byte
	var toID [32]byte
	fromID[0] = 0x0a
	toID[0] = 0x0b
	nonce, err := NonceFromBase(base, 7)
	if err != nil {
		t.Fatalf("nonce derivation failed: %v", err)
	}
	aad := BuildAAD("msg", 7, fromID, toID, "chan")
	plain := []byte("payload")
	sealed, err := XSealWithNonce(key, nonce, plain, aad)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	opened, err := XOpen(key, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatalf("payload mismatch")
	}
}

func TestSessionAEADTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, XKeySize)
	base := bytes.Repeat([]byte{0x04}, XNonceSize)
	var fromID [32]byte
	var toID [32]byte
	fromID[0] = 0x0c
	toID[0] = 0x0d
	nonce, err := NonceFromBase(base, 1)
	if err != nil {
		t.Fatalf("nonce derivation failed: %v", err)
	}
	aad := BuildAAD("msg", 1, fromID, toID, "")
	plain := []byte("payload")
	sealed, err := XSealWithNonce(key, nonce, plain, aad)
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	sealed[0] ^= 0xff
	if _, err := XOpen(key, nonce, sealed, aad); err == nil {
		t.Fatalf("expected tamper failure")
	}
}

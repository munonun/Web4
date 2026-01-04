package proto

import (
	"bytes"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	payload := []byte(`{"type":"contract_open","amount":1}`)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}
	got, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatalf("payload mismatch")
	}
}

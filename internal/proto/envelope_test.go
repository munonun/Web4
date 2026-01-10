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

func TestReadFrameWithTypeCapRejectsLarge(t *testing.T) {
	payload := sizedPayload("ack", 200)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}
	_, err = ReadFrameWithTypeCap(bytes.NewReader(frame), 64, func(t string) int {
		if t == "ack" {
			return 100
		}
		return 0
	})
	if err == nil {
		t.Fatalf("expected size rejection")
	}
}

func TestReadFrameWithTypeCapRejectsUnknownTypeLarge(t *testing.T) {
	payload := []byte(`{"pad":"` + string(bytes.Repeat([]byte("a"), 180)) + `"}`)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}
	if _, err := ReadFrameWithTypeCap(bytes.NewReader(frame), 64, func(string) int { return 0 }); err == nil {
		t.Fatalf("expected sniff rejection")
	}
}

func TestReadFrameWithTypeCapAllowsLargeWithinLimit(t *testing.T) {
	payload := sizedPayload("contract_open", 200)
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatalf("EncodeFrame failed: %v", err)
	}
	out, err := ReadFrameWithTypeCap(bytes.NewReader(frame), 64, func(t string) int {
		if t == "contract_open" {
			return 300
		}
		return 0
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch")
	}
}

func sizedPayload(msgType string, total int) []byte {
	head := []byte(`{"type":"` + msgType + `","pad":"`)
	tail := []byte(`"}`)
	padLen := total - len(head) - len(tail)
	if padLen < 0 {
		padLen = 0
	}
	pad := bytes.Repeat([]byte("a"), padLen)
	out := make([]byte, 0, len(head)+len(pad)+len(tail))
	out = append(out, head...)
	out = append(out, pad...)
	out = append(out, tail...)
	return out
}

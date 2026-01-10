package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	MaxFrameSize     = 1 << 20
	SoftMaxFrameSize = 64 << 10
	TypeSniffBytes   = 512
)

func EncodeFrame(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	if len(payload) > MaxFrameSize {
		return nil, fmt.Errorf("payload too large")
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("invalid frame size")
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func ReadFrameWithTypeCap(r io.Reader, softMax int, typeCap func(string) int) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("invalid frame size")
	}
	if softMax <= 0 || int(n) <= softMax {
		payload := make([]byte, int(n))
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		return payload, nil
	}

	prefixLen := int(n)
	if prefixLen > TypeSniffBytes {
		prefixLen = TypeSniffBytes
	}
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, err
	}
	msgType, ok := extractType(prefix)
	if !ok {
		return nil, fmt.Errorf("message too large for type sniff")
	}
	maxSize := 0
	if typeCap != nil {
		maxSize = typeCap(msgType)
	}
	if maxSize > 0 && int(n) > maxSize {
		return nil, fmt.Errorf("payload too large for type %s", msgType)
	}

	payload := make([]byte, int(n))
	copy(payload, prefix)
	if _, err := io.ReadFull(r, payload[len(prefix):]); err != nil {
		return nil, err
	}
	return payload, nil
}

func WriteFrame(w io.Writer, payload []byte) error {
	frame, err := EncodeFrame(payload)
	if err != nil {
		return err
	}
	total := 0
	for total < len(frame) {
		n, err := w.Write(frame[total:])
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		total += n
	}
	return nil
}

func extractType(prefix []byte) (string, bool) {
	var hdr struct {
		Type string `json:"type"`
	}
	dec := json.NewDecoder(bytes.NewReader(prefix))
	if err := dec.Decode(&hdr); err == nil && hdr.Type != "" {
		return hdr.Type, true
	}
	needle := []byte(`"type"`)
	idx := bytes.Index(prefix, needle)
	if idx == -1 {
		return "", false
	}
	rest := prefix[idx+len(needle):]
	colon := bytes.IndexByte(rest, ':')
	if colon == -1 {
		return "", false
	}
	rest = rest[colon+1:]
	rest = bytes.TrimLeft(rest, " \t\r\n")
	if len(rest) == 0 || rest[0] != '"' {
		return "", false
	}
	rest = rest[1:]
	end := bytes.IndexByte(rest, '"')
	if end == -1 {
		return "", false
	}
	return string(rest[:end]), true
}

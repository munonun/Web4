package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

const MaxFrameSize = 1 << 20

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

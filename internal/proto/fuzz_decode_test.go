package proto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"web4mvp/internal/testutil"
)

func FuzzDecodeFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Add([]byte{0, 0, 0, 5, '{', '"', 't', '"', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		data = testutil.CapBytes(data, testutil.DefaultMaxFuzzBytes)
		testutil.WithTimeout(t, testutil.DefaultFuzzTimeout, func() {
			r := bytes.NewReader(data)
			_, _ = ReadFrameWithTypeCap(r, SoftMaxFrameSize, MaxSizeForType)
		})
	})
}

func FuzzDecodeDeltaB(f *testing.F) {
	f.Add([]byte(`{"type":"delta_b","proto_version":"0.0.2","suite":"web4-wire-v1","view_id":"` + strings.Repeat("00", 32) + `","entries":[{"node_id":"` + strings.Repeat("00", 32) + `","delta":1},{"node_id":"` + strings.Repeat("01", 32) + `","delta":-1}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		data = testutil.CapBytes(data, testutil.DefaultMaxFuzzBytes)
		testutil.WithTimeout(t, testutil.DefaultFuzzTimeout, func() {
			m, err := DecodeDeltaBMsg(data)
			if err == nil {
				_, _ = CanonicalizeDeltaBEntries(m.Entries)
				_, _ = EncodeDeltaBMsg(m)
			}
		})
	})
}

func FuzzDecodeInviteCert(f *testing.F) {
	f.Add([]byte(`{"type":"invite_cert","proto_version":"0.0.2","suite":"web4-wire-v1"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		data = testutil.CapBytes(data, testutil.DefaultMaxFuzzBytes)
		testutil.WithTimeout(t, testutil.DefaultFuzzTimeout, func() {
			_, _ = DecodeInviteCertMsg(data)
		})
	})
}

func FuzzDecodeZKProofBundle(f *testing.F) {
	f.Add([]byte(`{"commitments":[],"proofs":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		data = testutil.CapBytes(data, testutil.DefaultMaxFuzzBytes)
		testutil.WithTimeout(t, testutil.DefaultFuzzTimeout, func() {
			var z ZKLinearProof
			if err := json.Unmarshal(data, &z); err != nil {
				return
			}
			_, _ = json.Marshal(z)
		})
	})
}

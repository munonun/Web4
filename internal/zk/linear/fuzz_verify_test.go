package linear

import (
	"encoding/json"
	"testing"

	"web4mvp/internal/proto"
	"web4mvp/internal/testutil"
)

func FuzzVerifyZKBundle(f *testing.F) {
	f.Add([]byte(`{"commitments":[],"proofs":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		data = testutil.CapBytes(data, testutil.DefaultMaxFuzzBytes)
		testutil.WithTimeout(t, testutil.DefaultFuzzTimeout, func() {
			var z proto.ZKLinearProof
			if err := json.Unmarshal(data, &z); err != nil {
				return
			}
			C, bundle, err := DecodeLinearProof(&z)
			if err != nil || len(C) == 0 || bundle == nil {
				return
			}
			L := [][]int64{make([]int64, len(C))}
			ctx := []byte("fuzz")
			_ = VerifyLinearNullspace(L, C, bundle, ctx)
		})
	})
}

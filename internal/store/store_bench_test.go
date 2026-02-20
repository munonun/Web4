package store

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

func BenchmarkAppendJSONL(b *testing.B) {
	b.ReportAllocs()
	dir := b.TempDir()
	path := dir + "/bench.jsonl"
	sample := struct {
		Type string `json:"type"`
		Seq  int    `json:"seq"`
		Msg  string `json:"msg"`
	}{
		Type: "bench",
		Msg:  "append-jsonl-throughput-latency",
	}

	lat := make([]int64, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sample.Seq = i
		start := time.Now()
		if err := AppendJSONL(path, sample); err != nil {
			b.Fatalf("append failed: %v", err)
		}
		lat = append(lat, time.Since(start).Nanoseconds())
	}
	b.StopTimer()

	if len(lat) == 0 {
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p99 := lat[(len(lat)*99)/100]
	b.ReportMetric(float64(p99), "p99-ns/op")
	b.ReportMetric(float64(lat[len(lat)-1]), "max-ns/op")
	b.SetBytes(int64(len(fmt.Sprintf(`{"type":"bench","seq":%d,"msg":"append-jsonl-throughput-latency"}`+"\n", b.N))))
}

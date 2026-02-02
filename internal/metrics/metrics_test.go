package metrics

import "testing"

func TestMetricsCounters(t *testing.T) {
	m := New()
	m.IncDeltaVerified()
	m.IncDeltaVerified()
	m.IncDeltaRelayed()
	m.IncDeltaDropDuplicate()
	m.IncDeltaDropRate()
	m.IncDeltaDropNonMember()
	m.IncDeltaDropZKFail()
	m.IncGossipRelayed()
	snap := m.Snapshot()
	if snap.Delta.Verified != 2 {
		t.Fatalf("expected verified=2, got %d", snap.Delta.Verified)
	}
	if snap.Delta.Relayed != 1 {
		t.Fatalf("expected relayed=1, got %d", snap.Delta.Relayed)
	}
	if snap.Delta.DropDuplicate != 1 || snap.Delta.DropRate != 1 || snap.Delta.DropNonMember != 1 || snap.Delta.DropZKFail != 1 {
		t.Fatalf("unexpected delta drop counts: %+v", snap.Delta)
	}
	if snap.Gossip.Relayed != 1 {
		t.Fatalf("expected gossip relayed=1, got %d", snap.Gossip.Relayed)
	}
}

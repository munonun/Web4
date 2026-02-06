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
	m.IncPexRequestsTotal()
	m.IncPexResponsesTotal()
	m.IncEvictionCountTotal()
	m.IncRecvByType("hello1")
	m.IncRecvByType("hello1")
	m.IncDropByReason("rate")
	m.SetCurrentConns(3)
	m.SetCurrentStreams(7)
	m.SetPeerTableSize(9)
	m.SetOutboundConnected(4)
	m.SetInboundConnected(2)
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
	if snap.PexRequestsTotal != 1 || snap.PexResponsesTotal != 1 {
		t.Fatalf("expected pex counts 1/1, got %d/%d", snap.PexRequestsTotal, snap.PexResponsesTotal)
	}
	if snap.EvictionCountTotal != 1 {
		t.Fatalf("expected eviction count 1, got %d", snap.EvictionCountTotal)
	}
	if snap.RecvByType["hello1"] != 2 {
		t.Fatalf("expected recv_by_type hello1=2, got %d", snap.RecvByType["hello1"])
	}
	if snap.DropByReason["rate"] != 1 {
		t.Fatalf("expected drop_by_reason rate=1, got %d", snap.DropByReason["rate"])
	}
	if snap.CurrentConns != 3 || snap.CurrentStreams != 7 {
		t.Fatalf("expected conns/streams 3/7, got %d/%d", snap.CurrentConns, snap.CurrentStreams)
	}
	if snap.PeerTableSize != 9 {
		t.Fatalf("expected peertable size 9, got %d", snap.PeerTableSize)
	}
	if snap.OutboundConnected != 4 || snap.InboundConnected != 2 {
		t.Fatalf("expected outbound/inbound 4/2, got %d/%d", snap.OutboundConnected, snap.InboundConnected)
	}
}

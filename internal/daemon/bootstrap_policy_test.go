package daemon

import (
	"strings"
	"testing"

	"web4mvp/internal/metrics"
	"web4mvp/internal/node"
	"web4mvp/internal/proto"
)

func TestBootstrapModeRejectsHello1(t *testing.T) {
	t.Setenv("WEB4_NODE_MODE", "bootstrap")

	self, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new self node: %v", err)
	}
	sender, err := node.NewNode(t.TempDir(), node.Options{})
	if err != nil {
		t.Fatalf("new sender node: %v", err)
	}
	r := &Runner{Self: self, Root: t.TempDir(), Metrics: metrics.New(), Mode: nodeModeBootstrap}

	hello1, err := sender.BuildHello1(self.ID)
	if err != nil {
		t.Fatalf("build hello1: %v", err)
	}
	data, err := proto.EncodeHello1Msg(hello1)
	if err != nil {
		t.Fatalf("encode hello1: %v", err)
	}

	_, _, recvErr := r.recvDataWithResponse(data, "127.0.0.1:12000")
	if recvErr == nil {
		t.Fatalf("expected bootstrap hello1 rejection")
	}
	if !strings.Contains(recvErr.Error(), "bootstrap discovery-only: hello forbidden") {
		t.Fatalf("unexpected error: %v", recvErr)
	}
}

package main

import (
	"bytes"
	"io"
	"testing"
)

func TestReplDispatchStatusAndQuit(t *testing.T) {
	var statusCalls int
	handlers := replHandlers{
		status:  func() { statusCalls++ },
		unknown: func(_ io.Writer) {},
	}
	var out bytes.Buffer
	if dispatchRepl("status", &out, handlers) {
		t.Fatalf("status should not exit")
	}
	if !dispatchRepl("quit", &out, handlers) {
		t.Fatalf("quit should exit")
	}
	if statusCalls != 1 {
		t.Fatalf("expected status to be called once, got %d", statusCalls)
	}
}

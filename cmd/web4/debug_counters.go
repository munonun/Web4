package main

import (
	"fmt"
	"os"
	"sync"
)

type debugCounters struct {
	mu          sync.Mutex
	recvByType  map[string]uint64
	dropReason  map[string]uint64
	verifyFail  map[string]uint64
	decryptFail map[string]uint64
	sendFail    map[string]uint64
	addrChange  map[string]uint64
}

func newDebugCounters() *debugCounters {
	return &debugCounters{
		recvByType:  make(map[string]uint64),
		dropReason:  make(map[string]uint64),
		verifyFail:  make(map[string]uint64),
		decryptFail: make(map[string]uint64),
		sendFail:    make(map[string]uint64),
		addrChange:  make(map[string]uint64),
	}
}

func (c *debugCounters) incRecv(msgType string) {
	c.inc(c.recvByType, "recv_by_type", msgType)
}

func (c *debugCounters) incDrop(reason string) {
	c.inc(c.dropReason, "drop_reason", reason)
}

func (c *debugCounters) incVerify(reason string) {
	c.inc(c.verifyFail, "verify_fail", reason)
}

func (c *debugCounters) incDecrypt(reason string) {
	c.inc(c.decryptFail, "decrypt_fail", reason)
}

func (c *debugCounters) incSend(reason string) {
	c.inc(c.sendFail, "send_fail", reason)
}

func (c *debugCounters) incAddrChange(reason string) {
	c.inc(c.addrChange, "addr_change", reason)
}

func (c *debugCounters) inc(m map[string]uint64, kind, key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	m[key]++
	count := m[key]
	c.mu.Unlock()
	if os.Getenv("WEB4_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "counter kind=%s key=%s count=%d\n", kind, key, count)
	}
}

var debugCount = newDebugCounters()

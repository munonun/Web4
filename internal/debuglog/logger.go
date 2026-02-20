package debuglog

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const queueSize = 2048

type logger struct {
	once sync.Once
	ch   chan string
}

var (
	global  logger
	rlMu    sync.Mutex
	rlLast  = make(map[string]time.Time)
	rlSweep = time.Now()
)

func enabled() bool {
	return os.Getenv("WEB4_DEBUG") == "1"
}

func (l *logger) start() {
	l.once.Do(func() {
		l.ch = make(chan string, queueSize)
		go func() {
			for msg := range l.ch {
				_, _ = os.Stderr.WriteString(msg)
			}
		}()
	})
}

func Logf(format string, args ...any) {
	msg := fmt.Sprintf(format+"\n", args...)
	if !enabled() {
		_, _ = os.Stderr.WriteString(msg)
		return
	}
	global.start()
	select {
	case global.ch <- msg:
	default:
		// Drop when saturated to keep network goroutines non-blocking in debug mode.
	}
}

func Debugf(format string, args ...any) {
	if !enabled() {
		return
	}
	Logf(format, args...)
}

func RateLimitedf(key string, interval time.Duration, format string, args ...any) {
	if !enabled() || key == "" {
		return
	}
	now := time.Now()
	rlMu.Lock()
	last := rlLast[key]
	if now.Sub(last) < interval {
		rlMu.Unlock()
		return
	}
	rlLast[key] = now
	if now.Sub(rlSweep) > 2*interval {
		for k, ts := range rlLast {
			if now.Sub(ts) > 4*interval {
				delete(rlLast, k)
			}
		}
		rlSweep = now
	}
	rlMu.Unlock()
	Logf(format, args...)
}

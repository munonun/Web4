package pprofutil

import (
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultAddr = "127.0.0.1:6060"

var (
	startOnce sync.Once
	startErr  error
)

// StartFromEnv starts an optional pprof HTTP server when WEB4_PPROF=1.
func StartFromEnv(logw io.Writer) error {
	if strings.TrimSpace(os.Getenv("WEB4_PPROF")) != "1" {
		return nil
	}
	startOnce.Do(func() {
		addr := strings.TrimSpace(os.Getenv("WEB4_PPROF_ADDR"))
		if addr == "" {
			addr = defaultAddr
		}
		allowPublic := strings.TrimSpace(os.Getenv("WEB4_PPROF_ALLOW_PUBLIC")) == "1"
		if !allowPublic && !isLoopbackBind(addr) {
			startErr = fmt.Errorf("WEB4_PPROF_ADDR must be loopback unless WEB4_PPROF_ALLOW_PUBLIC=1: %s", addr)
			return
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			startErr = fmt.Errorf("pprof listen failed: %w", err)
			return
		}
		actual := ln.Addr().String()
		if logw != nil {
			fmt.Fprintf(logw, "pprof enabled: http://%s/debug/pprof/\n", actual)
		}
		srv := &http.Server{
			Addr:              actual,
			Handler:           http.DefaultServeMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			_ = srv.Serve(ln)
		}()
	})
	return startErr
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

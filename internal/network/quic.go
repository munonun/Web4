package network

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"web4mvp/internal/proto"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type devTLSPaths struct {
	certPath   string
	keyPath    string
	bundlePath string
}

func resolveDevTLSPaths() devTLSPaths {
	p := devTLSPaths{
		certPath:   strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_CERT_PATH")),
		keyPath:    strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_KEY_PATH")),
		bundlePath: strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_BUNDLE_PATH")),
	}
	if legacy := strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_PATH")); legacy != "" {
		if p.certPath == "" {
			p.certPath = legacy
		}
	}
	if p.bundlePath != "" {
		if p.certPath == "" {
			p.certPath = p.bundlePath
		}
		if p.keyPath == "" {
			p.keyPath = p.bundlePath
		}
	}
	return p
}

func devTLSStrictCA() bool {
	return strings.TrimSpace(os.Getenv("WEB4_DEVTLS_STRICT_CA")) == "1"
}

func devTLSHasExplicitSharedCAEnv() bool {
	return strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_CERT_PATH")) != "" ||
		strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_KEY_PATH")) != "" ||
		strings.TrimSpace(os.Getenv("WEB4_DEVTLS_CA_BUNDLE_PATH")) != ""
}

func devTLSCert() (tls.Certificate, []byte, error) {
	return devTLSCertWithIPs(devTLSCertIPs())
}

func devTLSCertWithIPs(ips []net.IP) (tls.Certificate, []byte, error) {
	seed := sha256.Sum256([]byte("web4-quic-dev-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(zeroReader{}, &template, &template, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return cert, der, nil
}

func devTLSCertIPs() []net.IP {
	seen := map[string]struct{}{}
	out := make([]net.IP, 0, 3)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	add("127.0.0.1")
	for _, part := range strings.Split(os.Getenv("WEB4_DEVTLS_CERT_IPS"), ",") {
		add(part)
	}
	return out
}

func serverTLSConfig(devTLS bool) (*tls.Config, error) {
	var cert tls.Certificate
	if devTLS {
		if loaded, ok, err := loadDevTLSCertFromConfiguredPaths(); err != nil {
			return nil, err
		} else if ok {
			cert = loaded
		}
	}
	if len(cert.Certificate) == 0 {
		var err error
		cert, _, err = devTLSCert()
		if err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"web4-quic"},
	}, nil
}

func clientTLSConfig(insecure bool, devTLS bool, devTLSCAPath string) (*tls.Config, error) {
	if insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"web4-quic"},
		}, nil
	}
	if devTLS {
		paths := resolveDevTLSPaths()
		if envPath := os.Getenv("WEB4_DEVTLS_CA_PATH"); envPath != "" {
			if fi, err := os.Stat(envPath); err == nil && fi.Size() > 0 {
				devTLSCAPath = envPath
			}
		}
		if devTLSCAPath == "" && paths.certPath != "" {
			devTLSCAPath = paths.certPath
		}
		var pool *x509.CertPool
		var err error
		if devTLSCAPath != "" {
			pool, err = loadDevTLSCertPoolFromPath(devTLSCAPath)
		} else {
			pool, err = loadDevTLSCertPool()
		}
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			RootCAs:    pool,
			NextProtos: []string{"web4-quic"},
		}, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	return &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"web4-quic"},
	}, nil
}

const (
	maxIncomingStreams    = 64
	maxIncomingUniStreams = 64

	maxConnHandlers   = 128
	maxStreamHandlers = 128
	maxConnsPerIP     = 4
	maxStreamsPerIP   = 32

	streamBusyErrCode quic.StreamErrorCode = 0x10
)

var (
	maxIdleTimeout       = 60 * time.Second
	handshakeIdleTimeout = 10 * time.Second
	acquireTimeout       = 100 * time.Millisecond
	streamRWTimeout      = 5 * time.Second
	streamAcceptTimeout  = 5 * time.Second
	keepAlivePeriod      = 10 * time.Second
	maxConnsPerIPEnv     = maxConnsPerIP
	maxStreamsPerIPEnv   = maxStreamsPerIP
	maxConnHandlersEnv   = maxConnHandlers
	maxStreamHandlersEnv = maxStreamHandlers
	maxStreamsPerConnEnv = maxIncomingStreams
)
var (
	connSeq     uint64
	streamSeq   uint64
	connCount   atomic.Uint64
	streamCount atomic.Uint64
)

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
}

func init() {
	maxIdleTimeout = envDurationSeconds("WEB4_QUIC_IDLE_TIMEOUT_SEC", maxIdleTimeout)
	handshakeIdleTimeout = envDurationSeconds("WEB4_QUIC_HANDSHAKE_TIMEOUT_SEC", handshakeIdleTimeout)
	streamRWTimeout = envDurationSeconds("WEB4_QUIC_STREAM_TIMEOUT_SEC", streamRWTimeout)
	streamAcceptTimeout = envDurationSeconds("WEB4_QUIC_ACCEPT_TIMEOUT_SEC", streamRWTimeout)
	acquireTimeout = envDurationMillis("WEB4_QUIC_ACQUIRE_TIMEOUT_MS", acquireTimeout)
	keepAlivePeriod = envDurationSeconds("WEB4_QUIC_KEEPALIVE_SEC", keepAlivePeriod)
	refreshLimits()
}

func refreshLimits() {
	maxConnsPerIPEnv = envLimiter("WEB4_LIMITER_MAX_CONNS_PER_IP", "WEB4_LIMITER_MULTIPLIER", maxConnsPerIP)
	maxStreamsPerIPEnv = envLimiter("WEB4_LIMITER_MAX_STREAMS_PER_IP", "WEB4_LIMITER_MULTIPLIER", maxStreamsPerIP)
	maxConnHandlersEnv = envInt("WEB4_MAX_CONNS", maxConnHandlers)
	maxStreamsPerConnEnv = envInt("WEB4_MAX_STREAMS_PER_CONN", maxIncomingStreams)
	maxStreamHandlersEnv = envInt("WEB4_MAX_STREAMS", maxStreamHandlers)
	if os.Getenv("WEB4_DISABLE_LIMITER") == "1" {
		maxConnsPerIPEnv = 0
		maxStreamsPerIPEnv = 0
	}
}

func envDurationSeconds(name string, def time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return time.Duration(v) * time.Second
}

func envDurationMillis(name string, def time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return time.Duration(v) * time.Millisecond
}

func envInt(name string, def int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func envLimiter(baseVar string, multVar string, def int) int {
	raw := os.Getenv(baseVar)
	if raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			return v
		}
	}
	multRaw := os.Getenv(multVar)
	if multRaw == "" {
		return def
	}
	mult, err := strconv.Atoi(multRaw)
	if err != nil || mult <= 0 {
		return def
	}
	return def * mult
}

func (s *Semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Semaphore) Release() {
	select {
	case <-s.ch:
	default:
	}
}

func ListenAndServe(addr string, devTLS bool, handle func([]byte)) error {
	return ListenAndServeWithReady(addr, nil, devTLS, handle)
}

func ListenAndServeWithReady(addr string, ready chan<- struct{}, devTLS bool, handle func([]byte)) error {
	return ListenAndServeWithResponder(addr, ready, devTLS, func(data []byte) ([]byte, error) {
		handle(data)
		return nil, nil
	})
}

func ListenAndServeWithResponder(addr string, ready chan<- struct{}, devTLS bool, handle func([]byte) ([]byte, error)) error {
	return ListenAndServeWithResponderFrom(addr, ready, devTLS, func(_ string, data []byte) ([]byte, error) {
		return handle(data)
	})
}

func ListenAndServeWithResponderFrom(addr string, ready chan<- struct{}, devTLS bool, handle func(string, []byte) ([]byte, error)) error {
	if devTLS {
		if err := ensureDevTLSCA(); err != nil {
			return err
		}
	}
	refreshLimits()
	tlsConf, err := serverTLSConfig(devTLS)
	if err != nil {
		return err
	}
	incomingStreams := maxIncomingStreams
	if maxStreamsPerConnEnv > 0 && maxStreamsPerConnEnv < incomingStreams {
		incomingStreams = maxStreamsPerConnEnv
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    int64(incomingStreams),
		MaxIncomingUniStreams: maxIncomingUniStreams,
		MaxIdleTimeout:        maxIdleTimeout,
		KeepAlivePeriod:       keepAlivePeriod,
		HandshakeIdleTimeout:  handshakeIdleTimeout,
	}
	listener, err := quic.ListenAddr(addr, tlsConf, quicConf)
	if err != nil {
		logInfo("quic listen error: %v", err)
		return err
	}
	// Readiness signal is used by check6 to avoid flaky startup races (ports not yet bound).
	readyAddr := addr
	if listener != nil && listener.Addr() != nil {
		readyAddr = listener.Addr().String()
	}
	logInfo("quic listen ready: %s", readyAddr)
	if os.Getenv("WEB4_SUPPRESS_READY") != "1" {
		logInfo("READY addr=%s", readyAddr)
	}
	if ready != nil {
		close(ready)
	}
	connSem := NewSemaphore(maxConnHandlersEnv)
	streamSem := NewSemaphore(maxStreamHandlersEnv)
	ipLimits := newIPLimiter(maxConnsPerIPEnv, maxStreamsPerIPEnv)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logInfo("quic accept error: %v", err)
			return err
		}
		remoteAddr := conn.RemoteAddr().String()
		connToken := fmt.Sprintf("%p", conn)
		connID := atomic.AddUint64(&connSeq, 1)
		ip := remoteIP(conn.RemoteAddr())
		if !ipLimits.acquireConn(ip) {
			_ = conn.CloseWithError(0, "too many connections")
			logInfo("DROP reason=per_ip_limit from=%s type=conn err=too_many_connections", remoteAddr)
			continue
		}
		connCount.Add(1)
		acceptCtx, cancel := context.WithTimeout(context.Background(), acquireTimeout)
		if err := connSem.Acquire(acceptCtx); err != nil {
			cancel()
			ipLimits.releaseConn(ip)
			connCount.Add(^uint64(0))
			_ = conn.CloseWithError(0, "server busy")
			logInfo("quic connection rejected: %v", err)
			continue
		}
		cancel()
		logInfo("accepted connection addr=%s conn_id=%d conn=%s", remoteAddr, connID, connToken)
		go func(connID uint64, remoteAddr string, connToken string) {
			defer connSem.Release()
			defer connCount.Add(^uint64(0))
			defer ipLimits.releaseConn(ip)
			c := conn
			lastStreamAt := time.Now()
			var streamsInConn int32
			for {
				acceptCtx, cancel := context.WithTimeout(context.Background(), streamAcceptTimeout)
				stream, err := c.AcceptStream(acceptCtx)
				cancel()
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						logInfo("quic accept stream timeout conn_id=%d since_last_stream=%s", connID, time.Since(lastStreamAt))
						continue
					}
					if isBenignAcceptErr(err) {
						logInfo("quic accept stream closed: %v", err)
						return
					}
					logInfo("quic accept stream error: %v", err)
					return
				}
				lastStreamAt = time.Now()
				streamID := atomic.AddUint64(&streamSeq, 1)
				logInfo("accepted stream addr=%s conn_id=%d stream_id=%d conn=%s stream=%s", remoteAddr, connID, streamID, connToken, streamIDString(stream))
				debugLog("DEBUG stream accepted addr=%s conn_id=%d stream_id=%d", remoteAddr, connID, streamID)
				if maxStreamsPerConnEnv > 0 && atomic.LoadInt32(&streamsInConn) >= int32(maxStreamsPerConnEnv) {
					closeStreamWithError(stream, streamBusyErrCode, "per-conn stream limit")
					logInfo("DROP reason=per_conn_stream_limit from=%s type=stream err=per_conn_stream_limit", remoteAddr)
					continue
				}
				if !ipLimits.acquireStream(ip) {
					closeStreamWithError(stream, streamBusyErrCode, "per-ip stream limit")
					logInfo("DROP reason=per_ip_stream_limit from=%s type=stream err=per_ip_stream_limit", remoteAddr)
					continue
				}
				streamCtx, streamCancel := context.WithTimeout(context.Background(), acquireTimeout)
				if err := streamSem.Acquire(streamCtx); err != nil {
					streamCancel()
					ipLimits.releaseStream(ip)
					closeStreamWithError(stream, streamBusyErrCode, "server busy")
					logInfo("quic stream rejected: %v", err)
					continue
				}
				streamCancel()
				go func(s *quic.Stream, sender string, connID uint64, streamID uint64) {
					atomic.AddInt32(&streamsInConn, 1)
					streamCount.Add(1)
					defer streamSem.Release()
					defer atomic.AddInt32(&streamsInConn, -1)
					defer streamCount.Add(^uint64(0))
					defer ipLimits.releaseStream(ip)
					defer s.Close()
					logInfo("read start conn_id=%d stream_id=%d", connID, streamID)
					data, err := readFrameWithTimeout(s, streamRWTimeout)
					if err != nil {
						if errors.Is(err, io.EOF) {
							logInfo("quic read error: EOF")
						} else {
							if errors.Is(err, context.DeadlineExceeded) {
								logInfo("DROP message: read timeout before full frame")
							} else if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
								logInfo("DROP message: read timeout before full frame")
							}
							logInfo("quic read error: %v", err)
						}
						return
					}
					logInfo("read conn_id=%d stream_id=%d addr=%s raw_len=%d sha256=%s", connID, streamID, sender, len(data), hashHex(data))
					debugLog("DEBUG read bytes addr=%s conn_id=%d stream_id=%d bytes=%d", sender, connID, streamID, len(data))
					if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
						logInfo("WIRE RECV addr=%s conn_id=%d stream_id=%d conn=%s stream=%s raw_len=%d sha256=%s preview=%s", sender, connID, streamID, connToken, streamIDString(s), len(data), hashHex(data), previewBytes(data, 80))
					}
					msgType := "unknown"
					var hdr struct {
						Type string `json:"type"`
					}
					if err := json.Unmarshal(data, &hdr); err == nil && hdr.Type != "" {
						msgType = hdr.Type
					} else if err != nil && os.Getenv("WEB4_WIRE_DEBUG") == "1" {
						logInfo("quic read type parse error: %v", err)
					}
					logInfo("read %d bytes, type=%s, calling recv conn_id=%d stream_id=%d", len(data), msgType, connID, streamID)
					resp, err := handle(sender, data)
					if err != nil {
						logInfo("quic handler error: %v", err)
						return
					}
					if resp != nil {
						respType := ""
						var respHdr struct {
							Type string `json:"type"`
						}
						if err := json.Unmarshal(resp, &respHdr); err == nil && respHdr.Type != "" {
							respType = respHdr.Type
						}
						if err := writeFrameWithTimeout(s, streamRWTimeout, resp); err != nil {
							logInfo("quic write error: %v", err)
							return
						}
						if respType == proto.MsgTypeHello2 {
							logInfo("sent hello2")
						}
					}
				}(stream, remoteAddr, connID, streamID)
			}
		}(connID, remoteAddr, connToken)
	}
}

func ListenAndServeWithResponderFromContext(ctx context.Context, addr string, ready chan<- string, devTLS bool, handle func(string, []byte) ([]byte, error)) error {
	if devTLS {
		if err := ensureDevTLSCA(); err != nil {
			return err
		}
	}
	refreshLimits()
	tlsConf, err := serverTLSConfig(devTLS)
	if err != nil {
		return err
	}
	incomingStreams := maxIncomingStreams
	if maxStreamsPerConnEnv > 0 && maxStreamsPerConnEnv < incomingStreams {
		incomingStreams = maxStreamsPerConnEnv
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    int64(incomingStreams),
		MaxIncomingUniStreams: maxIncomingUniStreams,
		MaxIdleTimeout:        maxIdleTimeout,
		KeepAlivePeriod:       keepAlivePeriod,
		HandshakeIdleTimeout:  handshakeIdleTimeout,
	}
	listener, err := quic.ListenAddr(addr, tlsConf, quicConf)
	if err != nil {
		logInfo("quic listen error: %v", err)
		return err
	}
	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = listener.Close()
		}()
	}
	readyAddr := addr
	if listener != nil && listener.Addr() != nil {
		readyAddr = listener.Addr().String()
	}
	logInfo("quic listen ready: %s", readyAddr)
	if os.Getenv("WEB4_SUPPRESS_READY") != "1" {
		logInfo("READY addr=%s", readyAddr)
	}
	if ready != nil {
		select {
		case ready <- readyAddr:
		default:
		}
	}
	connSem := NewSemaphore(maxConnHandlersEnv)
	streamSem := NewSemaphore(maxStreamHandlersEnv)
	ipLimits := newIPLimiter(maxConnsPerIPEnv, maxStreamsPerIPEnv)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil
			}
			logInfo("quic accept error: %v", err)
			return err
		}
		remoteAddr := conn.RemoteAddr().String()
		connToken := fmt.Sprintf("%p", conn)
		connID := atomic.AddUint64(&connSeq, 1)
		ip := remoteIP(conn.RemoteAddr())
		if !ipLimits.acquireConn(ip) {
			_ = conn.CloseWithError(0, "too many connections")
			logInfo("DROP reason=per_ip_limit from=%s type=conn err=too_many_connections", remoteAddr)
			continue
		}
		connCount.Add(1)
		acceptCtx, cancel := context.WithTimeout(context.Background(), acquireTimeout)
		if err := connSem.Acquire(acceptCtx); err != nil {
			cancel()
			ipLimits.releaseConn(ip)
			connCount.Add(^uint64(0))
			_ = conn.CloseWithError(0, "server busy")
			logInfo("quic connection rejected: %v", err)
			continue
		}
		cancel()
		logInfo("accepted connection addr=%s conn_id=%d conn=%s", remoteAddr, connID, connToken)
		go func(connID uint64, remoteAddr string, connToken string) {
			defer connSem.Release()
			defer connCount.Add(^uint64(0))
			defer ipLimits.releaseConn(ip)
			c := conn
			lastStreamAt := time.Now()
			var streamsInConn int32
			for {
				acceptCtx, cancel := context.WithTimeout(context.Background(), streamAcceptTimeout)
				stream, err := c.AcceptStream(acceptCtx)
				cancel()
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						logInfo("quic accept stream timeout conn_id=%d since_last_stream=%s", connID, time.Since(lastStreamAt))
						continue
					}
					if isBenignAcceptErr(err) {
						logInfo("quic accept stream closed: %v", err)
						return
					}
					logInfo("quic accept stream error: %v", err)
					return
				}
				lastStreamAt = time.Now()
				streamID := atomic.AddUint64(&streamSeq, 1)
				logInfo("accepted stream addr=%s conn_id=%d stream_id=%d conn=%s stream=%s", remoteAddr, connID, streamID, connToken, streamIDString(stream))
				debugLog("DEBUG stream accepted addr=%s conn_id=%d stream_id=%d", remoteAddr, connID, streamID)
				if maxStreamsPerConnEnv > 0 && atomic.LoadInt32(&streamsInConn) >= int32(maxStreamsPerConnEnv) {
					closeStreamWithError(stream, streamBusyErrCode, "per-conn stream limit")
					logInfo("DROP reason=per_conn_stream_limit from=%s type=stream err=per_conn_stream_limit", remoteAddr)
					continue
				}
				if !ipLimits.acquireStream(ip) {
					closeStreamWithError(stream, streamBusyErrCode, "per-ip stream limit")
					logInfo("DROP reason=per_ip_stream_limit from=%s type=stream err=per_ip_stream_limit", remoteAddr)
					continue
				}
				streamCtx, streamCancel := context.WithTimeout(context.Background(), acquireTimeout)
				if err := streamSem.Acquire(streamCtx); err != nil {
					streamCancel()
					ipLimits.releaseStream(ip)
					closeStreamWithError(stream, streamBusyErrCode, "server busy")
					logInfo("quic stream rejected: %v", err)
					continue
				}
				streamCancel()
				go func(s *quic.Stream, sender string, connID uint64, streamID uint64) {
					atomic.AddInt32(&streamsInConn, 1)
					streamCount.Add(1)
					defer streamSem.Release()
					defer atomic.AddInt32(&streamsInConn, -1)
					defer streamCount.Add(^uint64(0))
					defer ipLimits.releaseStream(ip)
					defer s.Close()
					logInfo("read start conn_id=%d stream_id=%d", connID, streamID)
					data, err := readFrameWithTimeout(s, streamRWTimeout)
					if err != nil {
						if errors.Is(err, io.EOF) {
							logInfo("quic read error: EOF")
						} else {
							if errors.Is(err, context.DeadlineExceeded) {
								logInfo("DROP message: read timeout before full frame")
							} else if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
								logInfo("DROP message: read timeout before full frame")
							}
							logInfo("quic read error: %v", err)
						}
						return
					}
					logInfo("read conn_id=%d stream_id=%d addr=%s raw_len=%d sha256=%s", connID, streamID, sender, len(data), hashHex(data))
					debugLog("DEBUG read bytes addr=%s conn_id=%d stream_id=%d bytes=%d", sender, connID, streamID, len(data))
					if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
						logInfo("WIRE RECV addr=%s conn_id=%d stream_id=%d conn=%s stream=%s raw_len=%d sha256=%s preview=%s", sender, connID, streamID, connToken, streamIDString(s), len(data), hashHex(data), previewBytes(data, 80))
					}
					msgType := "unknown"
					var hdr struct {
						Type string `json:"type"`
					}
					if err := json.Unmarshal(data, &hdr); err == nil && hdr.Type != "" {
						msgType = hdr.Type
					} else if err != nil && os.Getenv("WEB4_WIRE_DEBUG") == "1" {
						logInfo("quic read type parse error: %v", err)
					}
					logInfo("read %d bytes, type=%s, calling recv conn_id=%d stream_id=%d", len(data), msgType, connID, streamID)
					resp, err := handle(sender, data)
					if err != nil {
						logInfo("quic handler error: %v", err)
						return
					}
					if resp != nil {
						respType := ""
						var respHdr struct {
							Type string `json:"type"`
						}
						if err := json.Unmarshal(resp, &respHdr); err == nil && respHdr.Type != "" {
							respType = respHdr.Type
						}
						if err := writeFrameWithTimeout(s, streamRWTimeout, resp); err != nil {
							logInfo("quic write error: %v", err)
							return
						}
						if respType == proto.MsgTypeHello2 {
							logInfo("sent hello2")
						}
					}
				}(stream, remoteAddr, connID, streamID)
			}
		}(connID, remoteAddr, connToken)
	}
}

func ensureDevTLSCA() error {
	if _, ok, err := loadDevTLSCertFromConfiguredPaths(); err != nil {
		return err
	} else if ok {
		return nil
	}
	_, der, err := devTLSCert()
	if err != nil {
		return err
	}
	seed := sha256.Sum256([]byte("web4-quic-dev-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return persistDevTLSMaterial(der, keyDER)
}

func Send(addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) error {
	return SendWithContext(context.Background(), addr, data, insecure, devTLS, devTLSCAPath)
}

func CurrentConns() uint64 {
	return connCount.Load()
}

func CurrentStreams() uint64 {
	return streamCount.Load()
}

func Exchange(addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) ([]byte, error) {
	return ExchangeWithContext(context.Background(), addr, data, insecure, devTLS, devTLSCAPath)
}

func devTLSCertPath() (string, error) {
	paths := resolveDevTLSPaths()
	if paths.certPath != "" {
		return paths.certPath, nil
	}
	if paths.bundlePath != "" {
		return paths.bundlePath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".web4mvp", "devtls_ca.pem"), nil
}

func devTLSKeyPath() (string, error) {
	paths := resolveDevTLSPaths()
	if paths.keyPath != "" {
		return paths.keyPath, nil
	}
	if paths.bundlePath != "" {
		return paths.bundlePath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".web4mvp", "devtls_ca_key.pem"), nil
}

func persistDevTLSMaterial(certDER []byte, keyDER []byte) error {
	path, err := devTLSCertPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		return err
	}
	keyPath, err := devTLSKeyPath()
	if err != nil {
		return err
	}
	if keyPath == path {
		bundle := append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
		return os.WriteFile(path, bundle, 0600)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0600)
}

func persistDevTLSCert(der []byte) error {
	seed := sha256.Sum256([]byte("web4-quic-dev-key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return persistDevTLSMaterial(der, keyDER)
}

func loadDevTLSCertPool() (*x509.CertPool, error) {
	path, err := devTLSCertPath()
	if err != nil {
		return nil, err
	}
	return loadDevTLSCertPoolWithFallback(path, true)
}

func loadDevTLSCertPoolFromPath(path string) (*x509.CertPool, error) {
	return loadDevTLSCertPoolWithFallback(path, false)
}

func loadDevTLSCertFromConfiguredPaths() (tls.Certificate, bool, error) {
	paths := resolveDevTLSPaths()
	if paths.certPath == "" && paths.keyPath == "" && paths.bundlePath == "" {
		return tls.Certificate{}, false, nil
	}
	// Backward-compatible behavior:
	// - Legacy cert-only path (WEB4_DEVTLS_CA_PATH) should not force key-pair mode.
	// - Enforce cert+key only in explicit shared-CA mode or strict mode.
	if !devTLSStrictCA() && !devTLSHasExplicitSharedCAEnv() {
		return tls.Certificate{}, false, nil
	}
	certPath := paths.certPath
	keyPath := paths.keyPath
	if certPath == "" {
		return tls.Certificate{}, false, fmt.Errorf("devtls ca not ready: missing cert path")
	}
	if keyPath == "" {
		return tls.Certificate{}, false, fmt.Errorf("devtls ca not ready: missing key path")
	}
	if fi, err := os.Stat(certPath); err != nil || fi.Size() == 0 {
		return tls.Certificate{}, false, fmt.Errorf("devtls ca not ready: cert missing")
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Size() == 0 {
		return tls.Certificate{}, false, fmt.Errorf("devtls ca not ready: key missing")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("devtls ca not ready: %w", err)
	}
	return cert, true, nil
}

func parseCertIPsCSV(csv string) []net.IP {
	seen := map[string]struct{}{}
	out := make([]net.IP, 0, 8)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	add("127.0.0.1")
	for _, part := range strings.Split(csv, ",") {
		add(part)
	}
	return out
}

func GenerateDeterministicDevTLSCA(outDir string, ipsCSV string) (string, string, error) {
	if strings.TrimSpace(outDir) == "" {
		return "", "", fmt.Errorf("missing out dir")
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", "", err
	}
	ips := parseCertIPsCSV(ipsCSV)
	cert, der, err := devTLSCertWithIPs(ips)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(outDir, "ca_cert.pem")
	keyPath := filepath.Join(outDir, "ca_key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func loadDevTLSCertPoolWithFallback(path string, allowFallback bool) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && allowFallback {
			_, der, err := devTLSCert()
			if err != nil {
				return nil, err
			}
			if err := persistDevTLSCert(der); err != nil {
				return nil, err
			}
			pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		} else {
			return nil, err
		}
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("invalid devtls CA PEM")
	}
	return pool, nil
}

func logInfo(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func debugLog(format string, args ...any) {
	if os.Getenv("WEB4_DEBUG") != "1" {
		return
	}
	logInfo(format, args...)
}

func previewBytes(b []byte, max int) string {
	if max <= 0 {
		return ""
	}
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

func streamIDString(stream *quic.Stream) string {
	if stream == nil {
		return ""
	}
	if s, ok := any(stream).(interface{ StreamID() quic.StreamID }); ok {
		return fmt.Sprintf("%d", s.StreamID())
	}
	return ""
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func readFrameWithTimeout(stream *quic.Stream, timeout time.Duration) ([]byte, error) {
	if d, ok := any(stream).(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		_ = d.SetReadDeadline(time.Now().Add(timeout))
		data, err := proto.ReadFrameWithTypeCap(stream, proto.SoftMaxFrameSize, proto.MaxSizeForType)
		if err == nil {
			debugLog("DEBUG read payload bytes=%d", len(data))
			return data, nil
		}
		if te, ok := err.(interface{ Timeout() bool }); ok && te.Timeout() {
			logInfo("DROP message: read timeout before full frame")
		}
		return data, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := proto.ReadFrameWithTypeCap(stream, proto.SoftMaxFrameSize, proto.MaxSizeForType)
		ch <- result{data: data, err: err}
	}()
	select {
	case res := <-ch:
		if res.err == nil {
			debugLog("DEBUG read payload bytes=%d", len(res.data))
		}
		return res.data, res.err
	case <-ctx.Done():
		logInfo("DROP message: read timeout before full frame")
		closeStreamWithError(stream, streamBusyErrCode, "read timeout")
		return nil, ctx.Err()
	}
}

func writeFrameWithTimeout(stream *quic.Stream, timeout time.Duration, payload []byte) error {
	if d, ok := any(stream).(interface {
		SetWriteDeadline(time.Time) error
	}); ok {
		_ = d.SetWriteDeadline(time.Now().Add(timeout))
		return proto.WriteFrame(stream, payload)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- proto.WriteFrame(stream, payload)
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		closeStreamWithError(stream, streamBusyErrCode, "write timeout")
		return ctx.Err()
	}
}

func closeStreamWithError(stream *quic.Stream, code quic.StreamErrorCode, msg string) {
	type canceler interface {
		CancelRead(quic.StreamErrorCode)
		CancelWrite(quic.StreamErrorCode)
	}
	if c, ok := any(stream).(canceler); ok {
		c.CancelRead(code)
		c.CancelWrite(code)
	}
	_ = stream.Close()
	if msg != "" {
		logInfo("quic stream closed: %s", msg)
	}
}

func isBenignAcceptErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		if appErr.ErrorCode == 0 && appErr.Remote {
			return true
		}
	}
	return false
}

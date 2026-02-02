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

func devTLSCert() (tls.Certificate, []byte, error) {
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
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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

func serverTLSConfig(devTLS bool) (*tls.Config, error) {
	cert, _, err := devTLSCert()
	if err != nil {
		return nil, err
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
)
var (
	connSeq   uint64
	streamSeq uint64
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
	maxConnsPerIPEnv = envLimiter("WEB4_LIMITER_MAX_CONNS_PER_IP", "WEB4_LIMITER_MULTIPLIER", maxConnsPerIP)
	maxStreamsPerIPEnv = envLimiter("WEB4_LIMITER_MAX_STREAMS_PER_IP", "WEB4_LIMITER_MULTIPLIER", maxStreamsPerIP)
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
	tlsConf, err := serverTLSConfig(devTLS)
	if err != nil {
		return err
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    maxIncomingStreams,
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
	connSem := NewSemaphore(maxConnHandlers)
	streamSem := NewSemaphore(maxStreamHandlers)
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
		acceptCtx, cancel := context.WithTimeout(context.Background(), acquireTimeout)
		if err := connSem.Acquire(acceptCtx); err != nil {
			cancel()
			ipLimits.releaseConn(ip)
			_ = conn.CloseWithError(0, "server busy")
			logInfo("quic connection rejected: %v", err)
			continue
		}
		cancel()
		logInfo("accepted connection addr=%s conn_id=%d conn=%s", remoteAddr, connID, connToken)
		go func(connID uint64, remoteAddr string, connToken string) {
			defer connSem.Release()
			defer ipLimits.releaseConn(ip)
			c := conn
			lastStreamAt := time.Now()
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
					defer streamSem.Release()
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
	tlsConf, err := serverTLSConfig(devTLS)
	if err != nil {
		return err
	}
	quicConf := &quic.Config{
		MaxIncomingStreams:    maxIncomingStreams,
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
	connSem := NewSemaphore(maxConnHandlers)
	streamSem := NewSemaphore(maxStreamHandlers)
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
		acceptCtx, cancel := context.WithTimeout(context.Background(), acquireTimeout)
		if err := connSem.Acquire(acceptCtx); err != nil {
			cancel()
			ipLimits.releaseConn(ip)
			_ = conn.CloseWithError(0, "server busy")
			logInfo("quic connection rejected: %v", err)
			continue
		}
		cancel()
		logInfo("accepted connection addr=%s conn_id=%d conn=%s", remoteAddr, connID, connToken)
		go func(connID uint64, remoteAddr string, connToken string) {
			defer connSem.Release()
			defer ipLimits.releaseConn(ip)
			c := conn
			lastStreamAt := time.Now()
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
					defer streamSem.Release()
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
	_, der, err := devTLSCert()
	if err != nil {
		return err
	}
	return persistDevTLSCert(der)
}

func Send(addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) error {
	return SendWithContext(context.Background(), addr, data, insecure, devTLS, devTLSCAPath)
}

func Exchange(addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) ([]byte, error) {
	return ExchangeWithContext(context.Background(), addr, data, insecure, devTLS, devTLSCAPath)
}

func devTLSCertPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".web4mvp", "devtls_ca.pem"), nil
}

func persistDevTLSCert(der []byte) error {
	path, err := devTLSCertPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0600)
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

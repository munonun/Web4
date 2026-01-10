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
	if devTLS {
		if err := persistDevTLSCert(cert.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"web4-quic"},
	}, nil
}

func clientTLSConfig(insecure bool, devTLS bool) (*tls.Config, error) {
	if insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"web4-quic"},
		}, nil
	}
	if devTLS {
		pool, err := loadDevTLSCertPool()
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
	maxIdleTimeout        = 20 * time.Second
	keepAlivePeriod       = 10 * time.Second
	handshakeIdleTimeout  = 10 * time.Second

	maxConnHandlers   = 128
	maxStreamHandlers = 128
	acquireTimeout    = 100 * time.Millisecond
	streamRWTimeout   = 5 * time.Second
	maxConnsPerIP     = 4
	maxStreamsPerIP   = 32

	streamBusyErrCode quic.StreamErrorCode = 0x10
)

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(n int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, n)}
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
	logInfo("quic listen ready: %s", addr)
	if ready != nil {
		close(ready)
	}
	connSem := NewSemaphore(maxConnHandlers)
	streamSem := NewSemaphore(maxStreamHandlers)
	ipLimits := newIPLimiter(maxConnsPerIP, maxStreamsPerIP)
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logInfo("quic accept error: %v", err)
			return err
		}
		ip := remoteIP(conn.RemoteAddr())
		if !ipLimits.acquireConn(ip) {
			_ = conn.CloseWithError(0, "too many connections")
			logInfo("quic connection rejected: per-ip limit")
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
		logInfo("accepted connection")
		go func() {
			defer connSem.Release()
			defer ipLimits.releaseConn(ip)
			c := conn
			for {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					if isBenignAcceptErr(err) {
						logInfo("quic accept stream closed: %v", err)
						return
					}
					logInfo("quic accept stream error: %v", err)
					return
				}
				logInfo("accepted stream")
				if !ipLimits.acquireStream(ip) {
					closeStreamWithError(stream, streamBusyErrCode, "per-ip stream limit")
					logInfo("quic stream rejected: per-ip limit")
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
				go func(s *quic.Stream) {
					defer streamSem.Release()
					defer ipLimits.releaseStream(ip)
					defer s.Close()
					logInfo("read start")
					data, err := readFrameWithTimeout(s, streamRWTimeout)
					if err != nil {
						if errors.Is(err, io.EOF) {
							logInfo("quic read error: EOF")
						} else {
							logInfo("quic read error: %v", err)
						}
						return
					}
					logInfo("read %d bytes", len(data))
					msgType := "unknown"
					var hdr struct {
						Type string `json:"type"`
					}
					if err := json.Unmarshal(data, &hdr); err == nil && hdr.Type != "" {
						msgType = hdr.Type
					}
					logInfo("read %d bytes, type=%s, calling recv", len(data), msgType)
					handle(data)
				}(stream)
			}
		}()
	}
}

func Send(addr string, data []byte, insecure bool, devTLS bool) error {
	tlsConf, err := clientTLSConfig(insecure, devTLS)
	if err != nil {
		return err
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       maxIdleTimeout,
		KeepAlivePeriod:      keepAlivePeriod,
		HandshakeIdleTimeout: handshakeIdleTimeout,
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, quicConf)
	if err != nil {
		return err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return err
	}
	if err := writeFrameWithTimeout(stream, streamRWTimeout, data); err != nil {
		_ = conn.CloseWithError(0, "")
		return err
	}
	if err := stream.Close(); err != nil {
		logInfo("quic stream close error: %v", err)
		_ = conn.CloseWithError(0, "")
		return err
	}
	time.Sleep(100 * time.Millisecond)
	_ = conn.CloseWithError(0, "")
	return nil
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
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
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
		return nil, fmt.Errorf("invalid devtls_ca.pem")
	}
	return pool, nil
}

func logInfo(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
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
		return proto.ReadFrameWithTypeCap(stream, proto.SoftMaxFrameSize, proto.MaxSizeForType)
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
		return res.data, res.err
	case <-ctx.Done():
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

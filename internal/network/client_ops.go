package network

import (
	"context"
	"errors"
	"time"

	quic "github.com/quic-go/quic-go"
)

var clientConns = newClientPool(clientConnIdle)

func SendWithContext(ctx context.Context, addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) error {
	tlsConf, err := clientTLSConfig(insecure, devTLS, devTLSCAPath)
	if err != nil {
		return err
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       maxIdleTimeout,
		KeepAlivePeriod:      keepAlivePeriod,
		HandshakeIdleTimeout: handshakeIdleTimeout,
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt <= clientMaxRetries; attempt++ {
		if ctx.Err() != nil {
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		}
		conn, err := clientConns.get(ctx, addr, tlsConf, quicConf)
		if err != nil {
			lastErr = err
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			lastErr = err
			clientConns.drop(addr, conn, "open stream failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		if err := writeFrameWithTimeout(stream, streamRWTimeout, data); err != nil {
			lastErr = err
			_ = stream.Close()
			clientConns.drop(addr, conn, "write failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		if err := stream.Close(); err != nil {
			logInfo("quic stream close error: %v", err)
		}
		clientConns.touch(addr, conn)
		clientConns.resetFailures(addr)
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("send failed")
	}
	return lastErr
}

func ExchangeWithContext(ctx context.Context, addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) ([]byte, error) {
	tlsConf, err := clientTLSConfig(insecure, devTLS, devTLSCAPath)
	if err != nil {
		return nil, err
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       maxIdleTimeout,
		KeepAlivePeriod:      keepAlivePeriod,
		HandshakeIdleTimeout: handshakeIdleTimeout,
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt <= clientMaxRetries; attempt++ {
		if ctx.Err() != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
		conn, err := clientConns.get(ctx, addr, tlsConf, quicConf)
		if err != nil {
			lastErr = err
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			lastErr = err
			clientConns.drop(addr, conn, "open stream failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		if err := writeFrameWithTimeout(stream, streamRWTimeout, data); err != nil {
			lastErr = err
			_ = stream.Close()
			clientConns.drop(addr, conn, "write failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		resp, err := readFrameWithTimeout(stream, streamRWTimeout)
		if err != nil {
			lastErr = err
			_ = stream.Close()
			clientConns.drop(addr, conn, "read failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		if err := stream.Close(); err != nil {
			logInfo("quic stream close error: %v", err)
		}
		clientConns.touch(addr, conn)
		clientConns.resetFailures(addr)
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("exchange failed")
	}
	return nil, lastErr
}

func ExchangeOnceWithContext(ctx context.Context, addr string, data []byte, insecure bool, devTLS bool, devTLSCAPath string) ([]byte, error) {
	tlsConf, err := clientTLSConfig(insecure, devTLS, devTLSCAPath)
	if err != nil {
		return nil, err
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:       maxIdleTimeout,
		KeepAlivePeriod:      keepAlivePeriod,
		HandshakeIdleTimeout: handshakeIdleTimeout,
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	conn, err := clientConns.get(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		clientConns.drop(addr, conn, "open stream failed")
		return nil, err
	}
	if err := writeFrameWithTimeout(stream, streamRWTimeout, data); err != nil {
		_ = stream.Close()
		clientConns.drop(addr, conn, "write failed")
		return nil, err
	}
	resp, err := readFrameWithTimeout(stream, streamRWTimeout)
	if err != nil {
		_ = stream.Close()
		clientConns.drop(addr, conn, "read failed")
		return nil, err
	}
	if err := stream.Close(); err != nil {
		logInfo("quic stream close error: %v", err)
	}
	clientConns.touch(addr, conn)
	return resp, nil
}

func backoffRetry(ctx context.Context, failures int) bool {
	if failures <= 0 {
		return false
	}
	d := clientBackoffBase
	if failures > 1 {
		d = d * time.Duration(1<<uint(failures-1))
	}
	if d > clientBackoffMax {
		d = clientBackoffMax
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"

	"web4mvp/internal/proto"
)

var clientConns = newClientPool(clientConnIdle)

func check6WireEnabled() bool {
	return os.Getenv("WEB4_CHECK6_DEBUG") == "1"
}

func logWireSend(stage string, addr string, conn *quic.Conn, stream *quic.Stream, payload []byte) {
	frameLen := -1
	if frame, err := proto.EncodeFrame(payload); err == nil {
		frameLen = len(frame)
	}
	connID := fmt.Sprintf("%p", conn)
	localAddr := ""
	remoteAddr := ""
	if conn != nil {
		if la := conn.LocalAddr(); la != nil {
			localAddr = la.String()
		}
		if ra := conn.RemoteAddr(); ra != nil {
			remoteAddr = ra.String()
		}
	}
	logInfo("WIRE SEND %s addr=%s conn=%s stream=%s intended_len=%d written_len=%d sha256=%s preview=%s",
		stage, addr, connID, streamIDString(stream), len(payload), frameLen, hashHex(payload), previewBytes(payload, 80))
	if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
		logInfo("WIRE SEND %s local=%s remote=%s conn=%s stream=%s", stage, localAddr, remoteAddr, connID, streamIDString(stream))
	}
}

func logWireWrite(addr string, conn *quic.Conn, stream *quic.Stream, payload []byte, writtenLen int, closeWriteErr error) {
	if !check6WireEnabled() {
		return
	}
	connID := fmt.Sprintf("%p", conn)
	errStr := ""
	if closeWriteErr != nil {
		errStr = closeWriteErr.Error()
	}
	logInfo("WIRE SEND WRITE addr=%s conn=%s stream=%s written_len=%d sha256=%s close_write_err=%s",
		addr, connID, streamIDString(stream), writtenLen, hashHex(payload), errStr)
}

func closeWrite(stream *quic.Stream) error {
	if stream == nil {
		return nil
	}
	if cw, ok := any(stream).(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func formatRFC3339Nano(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func logSendTiming(addr string, conn *quic.Conn, stream *quic.Stream, connEstablished time.Time, streamOpenStart time.Time, streamOpenEnd time.Time, writeStart time.Time, writeEnd time.Time, frameLen int, writeErr error, streamCloseErr error, connCloseErr error) {
	if os.Getenv("WEB4_WIRE_DEBUG") != "1" {
		return
	}
	connID := fmt.Sprintf("%p", conn)
	connAge := ""
	if !connEstablished.IsZero() {
		connAge = time.Since(connEstablished).String()
	}
	streamOpenDur := streamOpenEnd.Sub(streamOpenStart).String()
	writeDur := writeEnd.Sub(writeStart).String()
	writeErrStr := ""
	if writeErr != nil {
		writeErrStr = writeErr.Error()
	}
	streamCloseErrStr := ""
	if streamCloseErr != nil {
		streamCloseErrStr = streamCloseErr.Error()
	}
	connCloseErrStr := ""
	if connCloseErr != nil {
		connCloseErrStr = connCloseErr.Error()
	}
	logInfo("WIRE SEND META addr=%s conn=%s stream=%s conn_established=%s conn_age=%s stream_open_start=%s stream_open_end=%s stream_open_ms=%s write_start=%s write_end=%s write_ms=%s written_len=%d write_err=%s stream_close_err=%s conn_close_err=%s",
		addr, connID, streamIDString(stream),
		formatRFC3339Nano(connEstablished), connAge,
		formatRFC3339Nano(streamOpenStart), formatRFC3339Nano(streamOpenEnd), streamOpenDur,
		formatRFC3339Nano(writeStart), formatRFC3339Nano(writeEnd), writeDur,
		frameLen, writeErrStr, streamCloseErrStr, connCloseErrStr)
}

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
	usePool := os.Getenv("WEB4_DISABLE_CLIENT_POOL") != "1"
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
		var conn *quic.Conn
		if usePool {
			conn, err = clientConns.get(ctx, addr, tlsConf, quicConf)
		} else {
			debugLog("quic dial to %s", addr)
			conn, err = quic.DialAddr(ctx, addr, tlsConf, quicConf)
			if err == nil {
				debugLog("quic conn established to %s", addr)
			}
		}
		if err != nil {
			lastErr = err
			if !usePool || !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		streamOpenStart := time.Now()
		stream, err := conn.OpenStreamSync(ctx)
		streamOpenEnd := time.Now()
		if err != nil {
			lastErr = err
			if usePool {
				clientConns.drop(addr, conn, "open stream failed")
			} else {
				_ = conn.CloseWithError(0, "open stream failed")
			}
			if !usePool || !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		debugLog("DEBUG client opened stream addr=%s conn=%s stream=%s", addr, fmt.Sprintf("%p", conn), streamIDString(stream))
		if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
			logWireSend("pre", addr, conn, stream, data)
		}
		connEstablished := mustEstablishedAt(addr, conn)
		writeStart := time.Now()
		writeErr := writeFrameWithTimeout(stream, streamRWTimeout, data)
		writeEnd := time.Now()
		frameLen := len(data) + 4
		if frame, err := proto.EncodeFrame(data); err == nil {
			frameLen = len(frame)
		}
		if writeErr != nil {
			lastErr = writeErr
			_ = stream.Close()
			if usePool {
				clientConns.drop(addr, conn, "write failed")
			} else {
				_ = conn.CloseWithError(0, "write failed")
			}
			logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, writeErr, nil, nil)
			if !usePool || !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		debugLog("DEBUG client wrote bytes addr=%s conn=%s stream=%s bytes=%d", addr, fmt.Sprintf("%p", conn), streamIDString(stream), frameLen)
		closeWriteErr := closeWrite(stream)
		if check6WireEnabled() {
			logWireWrite(addr, conn, stream, data, frameLen, closeWriteErr)
		}
		if closeWriteErr != nil {
			debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=%v", addr, fmt.Sprintf("%p", conn), streamIDString(stream), closeWriteErr)
		} else {
			debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=", addr, fmt.Sprintf("%p", conn), streamIDString(stream))
		}
		if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
			logWireSend("post", addr, conn, stream, data)
		}
		streamCloseErr := stream.Close()
		if streamCloseErr != nil {
			logInfo("quic stream close error: %v", streamCloseErr)
		}
		debugLog("DEBUG client closed stream addr=%s conn=%s stream=%s", addr, fmt.Sprintf("%p", conn), streamIDString(stream))
		connCloseErr := error(nil)
		if os.Getenv("WEB4_WIRE_CLOSE_CONN") == "1" {
			connCloseErr = conn.CloseWithError(0, "client done")
			if usePool {
				clientConns.forget(addr, conn)
			}
		} else if usePool {
			clientConns.touch(addr, conn)
		} else {
			time.Sleep(1 * time.Second)
		}
		logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, nil, streamCloseErr, connCloseErr)
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
		streamOpenStart := time.Now()
		stream, err := conn.OpenStreamSync(ctx)
		streamOpenEnd := time.Now()
		if err != nil {
			lastErr = err
			clientConns.drop(addr, conn, "open stream failed")
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
			logWireSend("pre", addr, conn, stream, data)
		}
		connEstablished := mustEstablishedAt(addr, conn)
		writeStart := time.Now()
		writeErr := writeFrameWithTimeout(stream, streamRWTimeout, data)
		writeEnd := time.Now()
		frameLen := len(data) + 4
		if frame, err := proto.EncodeFrame(data); err == nil {
			frameLen = len(frame)
		}
		if writeErr != nil {
			lastErr = writeErr
			_ = stream.Close()
			clientConns.drop(addr, conn, "write failed")
			logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, writeErr, nil, nil)
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		closeWriteErr := closeWrite(stream)
		if check6WireEnabled() {
			logWireWrite(addr, conn, stream, data, frameLen, closeWriteErr)
		}
		if closeWriteErr != nil {
			debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=%v", addr, fmt.Sprintf("%p", conn), streamIDString(stream), closeWriteErr)
		} else {
			debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=", addr, fmt.Sprintf("%p", conn), streamIDString(stream))
		}
		if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
			logWireSend("post", addr, conn, stream, data)
		}
		resp, err := readFrameWithTimeout(stream, streamRWTimeout)
		if err != nil {
			lastErr = err
			_ = stream.Close()
			clientConns.drop(addr, conn, "read failed")
			logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, nil, nil, nil)
			if !backoffRetry(ctx, clientConns.recordFailure(addr)) {
				break
			}
			continue
		}
		streamCloseErr := stream.Close()
		if streamCloseErr != nil {
			logInfo("quic stream close error: %v", streamCloseErr)
		}
		connCloseErr := error(nil)
		if os.Getenv("WEB4_WIRE_CLOSE_CONN") == "1" {
			connCloseErr = conn.CloseWithError(0, "client done")
			clientConns.forget(addr, conn)
		} else {
			clientConns.touch(addr, conn)
		}
		logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, nil, streamCloseErr, connCloseErr)
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
	streamOpenStart := time.Now()
	stream, err := conn.OpenStreamSync(ctx)
	streamOpenEnd := time.Now()
	if err != nil {
		clientConns.drop(addr, conn, "open stream failed")
		return nil, err
	}
	if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
		logWireSend("pre", addr, conn, stream, data)
	}
	connEstablished := mustEstablishedAt(addr, conn)
	writeStart := time.Now()
	writeErr := writeFrameWithTimeout(stream, streamRWTimeout, data)
	writeEnd := time.Now()
	frameLen := len(data) + 4
	if frame, err := proto.EncodeFrame(data); err == nil {
		frameLen = len(frame)
	}
	if writeErr != nil {
		_ = stream.Close()
		clientConns.drop(addr, conn, "write failed")
		logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, writeErr, nil, nil)
		return nil, writeErr
	}
	closeWriteErr := closeWrite(stream)
	if check6WireEnabled() {
		logWireWrite(addr, conn, stream, data, frameLen, closeWriteErr)
	}
	if closeWriteErr != nil {
		debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=%v", addr, fmt.Sprintf("%p", conn), streamIDString(stream), closeWriteErr)
	} else {
		debugLog("DEBUG client close write addr=%s conn=%s stream=%s err=", addr, fmt.Sprintf("%p", conn), streamIDString(stream))
	}
	if os.Getenv("WEB4_WIRE_DEBUG") == "1" {
		logWireSend("post", addr, conn, stream, data)
	}
	resp, err := readFrameWithTimeout(stream, streamRWTimeout)
	if err != nil {
		_ = stream.Close()
		clientConns.drop(addr, conn, "read failed")
		logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, nil, nil, nil)
		return nil, err
	}
	streamCloseErr := stream.Close()
	if streamCloseErr != nil {
		logInfo("quic stream close error: %v", streamCloseErr)
	}
	connCloseErr := error(nil)
	if os.Getenv("WEB4_WIRE_CLOSE_CONN") == "1" {
		connCloseErr = conn.CloseWithError(0, "client done")
		clientConns.forget(addr, conn)
	} else {
		clientConns.touch(addr, conn)
	}
	logSendTiming(addr, conn, stream, connEstablished, streamOpenStart, streamOpenEnd, writeStart, writeEnd, frameLen, nil, streamCloseErr, connCloseErr)
	return resp, nil
}

func mustEstablishedAt(addr string, conn *quic.Conn) time.Time {
	if clientConns == nil {
		return time.Time{}
	}
	if t, ok := clientConns.establishedAt(addr, conn); ok {
		return t
	}
	return time.Time{}
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

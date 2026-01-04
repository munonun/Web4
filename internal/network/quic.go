package network

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
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
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(0, 0).Add(365 * 24 * time.Hour),
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

func serverTLSConfig() (*tls.Config, error) {
	cert, _, err := devTLSCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"web4-quic"},
	}, nil
}

func clientTLSConfig(insecure bool) (*tls.Config, error) {
	_, der, err := devTLSCert()
	if err != nil {
		return nil, err
	}
	if insecure {
		return &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"web4-quic"},
		}, nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"web4-quic"},
	}, nil
}

func ListenAndServe(addr string, handle func([]byte)) error {
	return ListenAndServeWithReady(addr, nil, handle)
}

func ListenAndServeWithReady(addr string, ready chan<- struct{}, handle func([]byte)) error {
	tlsConf, err := serverTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		logInfo("quic listen error: %v", err)
		return err
	}
	logInfo("quic listen ready: %s", addr)
	if ready != nil {
		close(ready)
	}
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			logInfo("quic accept error: %v", err)
			return err
		}
		logInfo("accepted connection")
		go func() {
			c := conn
			for {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					logInfo("quic accept stream error: %v", err)
					return
				}
				logInfo("accepted stream")
				go func(s *quic.Stream) {
					defer s.Close()
					logInfo("read start")
					data, err := io.ReadAll(s)
					if err != nil {
						if errors.Is(err, io.EOF) {
							logInfo("quic read error: EOF")
						} else {
							logInfo("quic read error: %v", err)
						}
					}
					logInfo("read %d bytes", len(data))
					if len(data) == 0 {
						return
					}
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

func Send(addr string, data []byte, insecure bool) error {
	tlsConf, err := clientTLSConfig(insecure)
	if err != nil {
		return err
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
    if err != nil { return err }
    defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(context.Background())
    if err != nil { return err }

    n, err := stream.Write(data)
    if err != nil { return err }
    logInfo("wrote %d bytes", n)

	if err := stream.Close(); err != nil {
        logInfo("quic stream close error: %v", err)
        return err
    }

    time.Sleep(100 * time.Millisecond) // dev/WSL 안정화용(선택)
    return nil
}

func logInfo(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
}

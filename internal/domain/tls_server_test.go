package domain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

type tlsWrite struct {
	server bool
	data   []byte
}

// recordingConn logs each Write, which loopback TCP sends as one segment.
type recordingConn struct {
	net.Conn
	server bool
	mu     *sync.Mutex
	log    *[]tlsWrite
}

func (c recordingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	*c.log = append(*c.log, tlsWrite{c.server, bytes.Clone(b)})
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ignored when SANs exist"},
		DNSNames:    []string{"API.Internal.Test", "*.internal.test"},
		IPAddresses: []net.IP{net.IPv4(192, 0, 2, 1)},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, der}, PrivateKey: key} // A two-entry chain.
}

// replayHandshake runs a crypto/tls handshake over loopback TCP and feeds
// every write, in order, to a Stream as the collector feeds segments. Writes
// are cut into 100-byte segments, so records and the certificate span them.
func replayHandshake(t *testing.T, client, server *tls.Config) Evidence {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var log []tlsWrite
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tls.Server(recordingConn{conn, true, &mu, &log}, server).Handshake()
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tls.Client(recordingConn{conn, false, &mu, &log}, client).Handshake()
	conn.Close()
	<-done

	s := New(1)
	clientSeq, serverSeq := uint32(1), uint32(5000)
	for _, w := range log {
		for segment := range slices.Chunk(w.data, 100) {
			if w.server {
				s.AddServer(serverSeq, segment, len(segment))
				serverSeq += uint32(len(segment))
			} else {
				s.Add(clientSeq, segment)
				clientSeq += uint32(len(segment))
			}
			s.Alert(segment, w.server)
		}
	}
	return s.Evidence()
}

// A client that connects by IP sends no SNI. Before TLS 1.3 the server's
// certificate is plaintext and names the connection instead.
func TestTLS12CertificateNamesConnectionWithoutSNI(t *testing.T) {
	cert := testCertificate(t)
	e := replayHandshake(t,
		&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if !e.NoSNI || e.TLSVersion != "TLS 1.2" || e.ServerALPN != "h2" || len(e.Certificate) != 2 || e.Certificate[1] != "*.internal.test" {
		t.Fatalf("evidence %+v", e)
	}
	if e.Label() != "TLS api.internal.test [cert]" || !e.Named() || e.Alert != "" {
		t.Fatalf("label %q named %v alert %q", e.Label(), e.Named(), e.Alert)
	}
}

func TestTLS13ReportsVersionAndEncryptedCertificate(t *testing.T) {
	e := replayHandshake(t, &tls.Config{InsecureSkipVerify: true}, &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}})
	if e.TLSVersion != "TLS 1.3" || len(e.Certificate) != 0 || e.Label() != "TLS no SNI" {
		t.Fatalf("evidence %+v", e)
	}
	if detail := e.Detail(); detail != "server chose TLS 1.3; no SNI, and TLS 1.3 encrypts the server certificate" {
		t.Fatalf("detail %q", detail)
	}
}

// With SNI the name is known, so the certificate is not read; the client
// still rejects it with a plaintext alert.
func TestTLS12ClientRejectsCertificate(t *testing.T) {
	e := replayHandshake(t,
		&tls.Config{ServerName: "api.internal.test", MaxVersion: tls.VersionTLS12},
		&tls.Config{Certificates: []tls.Certificate{testCertificate(t)}})
	if e.SNI != "api.internal.test" || e.TLSVersion != "TLS 1.2" || len(e.Certificate) != 0 || e.Alert != "client alert: bad certificate" {
		t.Fatalf("evidence %+v", e)
	}
}

func TestServerRejectsVersion(t *testing.T) {
	e := replayHandshake(t,
		&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12},
		&tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, MinVersion: tls.VersionTLS13})
	if e.TLSVersion != "" || e.Alert != "server alert: protocol version" {
		t.Fatalf("evidence %+v", e)
	}
}

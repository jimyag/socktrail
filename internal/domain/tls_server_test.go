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
	"strings"
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
// every write to a Stream as the collector feeds segments. Writes are cut
// into 100-byte segments, so records and the certificate span them. With
// swap, the server's second and third segments arrive in reverse order.
func replayHandshake(t *testing.T, client, server *tls.Config, swap bool) Evidence {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var mu sync.Mutex
	var log []tlsWrite
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = tls.Server(recordingConn{conn, true, &mu, &log}, server).Handshake()
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = tls.Client(recordingConn{conn, false, &mu, &log}, client).Handshake()
	_ = conn.Close()
	<-done

	type segment struct {
		server bool
		seq    uint32
		data   []byte
	}
	var segments []segment
	var serverAt []int
	seq := map[bool]uint32{false: 1, true: 5000}
	for _, w := range log {
		for data := range slices.Chunk(w.data, 100) {
			if w.server {
				serverAt = append(serverAt, len(segments))
			}
			segments = append(segments, segment{w.server, seq[w.server], data})
			seq[w.server] += uint32(len(data))
		}
	}
	if swap {
		a, b := serverAt[1], serverAt[2]
		segments[a], segments[b] = segments[b], segments[a]
	}
	s := New(1)
	for _, g := range segments {
		if g.server {
			s.AddServer(g.seq, g.data, len(g.data))
		} else {
			s.Add(g.seq, g.data)
		}
		s.Alert(g.data, g.server)
	}
	return s.Evidence()
}

// A client that connects by IP sends no SNI. Before TLS 1.3 the server's
// certificate is plaintext and names the connection instead, also when the
// server's segments arrive out of order.
func TestTLS12CertificateNamesConnectionWithoutSNI(t *testing.T) {
	cert := testCertificate(t)
	for _, swap := range []bool{false, true} {
		e := replayHandshake(t,
			&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
			&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}, swap)
		if !e.NoSNI || e.TLSVersion != "TLS 1.2" || e.ServerALPN != "h2" || len(e.Certificate) != 2 || e.Certificate[1] != "*.internal.test" {
			t.Fatalf("swap=%v: evidence %+v", swap, e)
		}
		if e.Label() != "TLS api.internal.test [cert]" || !e.Named() || e.Alert != "" {
			t.Fatalf("swap=%v: label %q named %v alert %q", swap, e.Label(), e.Named(), e.Alert)
		}
	}
}

func TestTLS13ReportsVersionAndEncryptedCertificate(t *testing.T) {
	e := replayHandshake(t, &tls.Config{InsecureSkipVerify: true}, &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}}, false)
	if e.TLSVersion != "TLS 1.3" || len(e.Certificate) != 0 || e.Label() != "TLS no SNI" {
		t.Fatalf("evidence %+v", e)
	}
	if detail := e.Detail(); e.JA4 == nil || !strings.HasPrefix(*e.JA4, "t13i") || detail != "server chose TLS 1.3; no SNI, and TLS 1.3 encrypts the server certificate; JA4 "+*e.JA4 {
		t.Fatalf("detail %q", detail)
	}
}

// With SNI the name is known, so the certificate is not read; the client
// still rejects it with a plaintext alert.
func TestTLS12ClientRejectsCertificate(t *testing.T) {
	e := replayHandshake(t,
		&tls.Config{ServerName: "api.internal.test", MaxVersion: tls.VersionTLS12},
		&tls.Config{Certificates: []tls.Certificate{testCertificate(t)}}, false)
	if e.SNI != "api.internal.test" || e.TLSVersion != "TLS 1.2" || len(e.Certificate) != 0 || e.Alert != "client alert: bad certificate" {
		t.Fatalf("evidence %+v", e)
	}
}

func TestServerRejectsVersion(t *testing.T) {
	e := replayHandshake(t,
		&tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12},
		&tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, MinVersion: tls.VersionTLS13}, false)
	if e.TLSVersion != "" || e.Alert != "server alert: protocol version" {
		t.Fatalf("evidence %+v", e)
	}
}

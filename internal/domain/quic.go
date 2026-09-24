package domain

import "fmt"

// NewQUICClientHello records domain evidence from an authenticated QUIC
// client Initial. handshake includes the four-byte TLS handshake header.
func NewQUICClientHello(handshake []byte) (*Stream, error) {
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, fmt.Errorf("invalid QUIC ClientHello")
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if length != len(handshake)-4 || length > maxPendingBytes {
		return nil, fmt.Errorf("invalid QUIC ClientHello length")
	}
	sni, ech, alpn, err := parseClientHello(handshake[4:])
	if err != nil {
		return nil, err
	}
	return &Stream{parser: parser{evidence: Evidence{Kind: "quic", SNI: sni, NoSNI: sni == "", ECH: ech, ALPN: alpn}}}, nil
}

func NewUnknownQUIC(reason string) *Stream {
	return &Stream{parser: parser{evidence: Evidence{Kind: "quic", ParseError: reason}}}
}

// NewOpenSSLSNI records a hostname read from the local process's OpenSSL
// state. It is TLS SNI evidence, not a decrypted HTTP Host or request count.
func NewOpenSSLSNI(hostname string) *Stream {
	return &Stream{parser: parser{evidence: Evidence{Kind: "openssl", SNI: hostname}}}
}

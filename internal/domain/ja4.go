package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// ja4Fields are the ClientHello values a JA4 fingerprint is built from, in
// the order they were sent, GREASE included.
type ja4Fields struct {
	version    uint16   // legacy_version.
	versions   []uint16 // supported_versions.
	ciphers    []uint16
	extensions []uint16
	signatures []uint16 // signature_algorithms.
	alpn       []byte   // First offered protocol, as sent.
}

// fingerprint computes the JA4 TLS client fingerprint (FoxIO, BSD 3-Clause)
// for a ClientHello carried over transport: 't' for TCP, 'q' for QUIC.
// Clients built on the same TLS library and settings share it, whatever the
// destination.
func (f ja4Fields) fingerprint(transport byte) string {
	ciphers := withoutGREASE(f.ciphers)
	extensions := withoutGREASE(f.extensions)
	sni := byte('i')
	if slices.Contains(extensions, 0) {
		sni = 'd'
	}
	version := f.version
	if versions := withoutGREASE(f.versions); len(versions) > 0 {
		version = slices.Max(versions)
	}
	a := fmt.Sprintf("%c%s%c%02d%02d%s", transport, ja4Version(version), sni, min(len(ciphers), 99), min(len(extensions), 99), ja4ALPN(f.alpn))

	b := "000000000000"
	if len(ciphers) > 0 {
		b = ja4Hash(hexList(slices.Sorted(slices.Values(ciphers))))
	}
	c := "000000000000"
	hashed := slices.DeleteFunc(slices.Clone(extensions), func(e uint16) bool { return e == 0 || e == 16 })
	if len(hashed) > 0 {
		list := hexList(slices.Sorted(slices.Values(hashed)))
		if signatures := withoutGREASE(f.signatures); len(signatures) > 0 {
			list += "_" + hexList(signatures)
		}
		c = ja4Hash(list)
	}
	return a + "_" + b + "_" + c
}

// isGREASE reports a reserved value clients send to keep servers tolerant
// (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func withoutGREASE(values []uint16) []uint16 {
	return slices.DeleteFunc(slices.Clone(values), isGREASE)
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// ja4ALPN is the first and last character of the first offered protocol,
// or of its hex form when either byte is not ASCII alphanumeric.
func ja4ALPN(alpn []byte) string {
	if len(alpn) == 0 {
		return "00"
	}
	first, last := alpn[0], alpn[len(alpn)-1]
	if alphanumeric(first) && alphanumeric(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte{first, last})
	return h[:1] + h[3:]
}

func alphanumeric(b byte) bool {
	return '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
}

func hexList(values []uint16) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func ja4Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

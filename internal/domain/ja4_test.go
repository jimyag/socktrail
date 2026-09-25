package domain

import (
	"encoding/binary"
	"testing"
)

// The example of the JA4 specification: a Chrome ClientHello with GREASE
// values, which the fingerprint ignores.
func TestJA4SpecificationExample(t *testing.T) {
	f := ja4Fields{
		version:    0x0303,
		versions:   []uint16{0x7a7a, 0x0304, 0x0303},
		ciphers:    []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		extensions: []uint16{0x2a2a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0xfafa},
		signatures: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		alpn:       []byte("h2"),
	}
	if got, want := f.fingerprint('t'), "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Fatalf("JA4 = %s, want %s", got, want)
	}
	f.signatures = nil
	if got, want := f.fingerprint('q'), "q13d1516h2_8daaf6152771_6d807ffa2a79"; got != want {
		t.Fatalf("JA4 without signature algorithms = %s, want %s", got, want)
	}
}

func TestJA4Fields(t *testing.T) {
	empty := ja4Fields{version: 0x0301}
	if got := empty.fingerprint('t'); got != "t10i000000_000000000000_000000000000" {
		t.Fatalf("empty ClientHello JA4 = %s", got)
	}
	for _, tc := range []struct {
		alpn []byte
		want string
	}{
		{nil, "00"},
		{[]byte("h"), "hh"},
		{[]byte("http/1.1"), "h1"},
		{[]byte{0xab}, "ab"},
		{[]byte{0x20}, "20"},
		{[]byte{0xab, 0xcd}, "ad"},
		{[]byte{0x20, 0x61}, "21"},
		{[]byte{0x30, 0xab}, "3b"},
		{[]byte{0x61, 0x20}, "60"},
		{[]byte{0x30, 0x31, 0xab, 0xcd}, "3d"},
		{[]byte{0x30, 0xab, 0xcd, 0x31}, "01"},
	} {
		if got := ja4ALPN(tc.alpn); got != tc.want {
			t.Errorf("ja4ALPN(%x) = %q, want %q", tc.alpn, got, tc.want)
		}
	}
	for v, want := range map[uint16]string{0x0304: "13", 0x0300: "s3", 0xfefd: "d2", 0x9999: "00"} {
		if got := ja4Version(v); got != want {
			t.Errorf("ja4Version(%#x) = %q, want %q", v, got, want)
		}
	}
	if !isGREASE(0x0a0a) || !isGREASE(0xfafa) || isGREASE(0x0a1a) || isGREASE(0x1301) {
		t.Fatal("GREASE detection")
	}
}

// A ClientHello on the wire carries its JA4 into the evidence, counting the
// SNI extension and reading the versions and ALPN the client offered.
func TestClientHelloEvidenceCarriesJA4(t *testing.T) {
	hello := clientHello("example.com", false)
	s := New(1)
	s.Add(1, hello)
	e := s.Evidence()
	if e.SNI != "example.com" || e.JA4 == nil || *e.JA4 != "t12d010100_0f2cb44170f4_000000000000" {
		t.Fatalf("evidence %+v ja4 %v", e, e.JA4)
	}

	body := hello[5+4:]
	extensions := append([]byte{0, 43, 0, 5, 4, 0x0a, 0x0a, 3, 4}, // supported_versions: GREASE, TLS 1.3.
		0, 16, 0, 5, 0, 3, 2, 'h', '2') // ALPN h2.
	extensions = append(extensions, 0, 13, 0, 4, 0, 2, 4, 3) // signature_algorithms.
	withExt := append([]byte(nil), body...)
	extLen := int(binary.BigEndian.Uint16(withExt[41:]))
	binary.BigEndian.PutUint16(withExt[41:], uint16(extLen+len(extensions)))
	withExt = append(withExt, extensions...)
	parsed, err := parseClientHello(withExt)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.ja4.fingerprint('t'); got[:10] != "t13d0104h2" || got[len(got)-12:] == "000000000000" {
		t.Fatalf("JA4 = %s", got)
	}
}

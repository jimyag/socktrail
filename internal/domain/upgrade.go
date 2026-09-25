package domain

import "bytes"

const maxUpgradeBytes = 16 << 10

type upgradeState struct {
	data     []byte
	protocol string
	ready    bool
	bytes    int
}

var ldapStartTLSOID = []byte("\x06\x0a\x2b\x06\x01\x04\x01\x8b\x3a\x81\x9c\x45")

func upgradeProtocol(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	c := b[0]
	if c != 0 && c != 0x30 && c != 32 && c != '<' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
		return ""
	}
	upper := bytes.ToUpper(b[:min(len(b), 32)])
	switch {
	case bytes.HasPrefix(upper, []byte("EHLO ")), bytes.HasPrefix(upper, []byte("HELO ")), bytes.HasPrefix(upper, []byte("LHLO ")):
		return "smtp-starttls"
	case bytes.HasPrefix(upper, []byte("CAPA\r\n")), bytes.HasPrefix(upper, []byte("STLS\r\n")):
		return "pop3-stls"
	case bytes.HasPrefix(upper, []byte("AUTH TLS")):
		return "ftp-auth-tls"
	case bytes.HasPrefix(upper, []byte("USER ")):
		return "user-upgrade"
	case bytes.HasPrefix(b, []byte("<stream:stream")), bytes.HasPrefix(b, []byte("<?xml")):
		return "xmpp-starttls"
	case len(b) >= 6 && b[0] == 0x30 && b[2] == 0x02:
		return "ldap-starttls"
	case len(b) >= 8 && bytes.Equal(b[:8], []byte{0, 0, 0, 8, 4, 210, 22, 47}),
		len(b) >= 8 && bytes.Equal(b[:8], []byte{0, 0, 0, 8, 4, 210, 22, 48}):
		return "postgres-ssl"
	case len(b) >= 36 && b[0] == 32 && b[1] == 0 && b[2] == 0 && b[3] == 1 && b[5]&0x08 != 0:
		return "mysql-ssl"
	}
	if space := bytes.IndexByte(upper, ' '); space > 0 && space <= 16 {
		command := upper[space+1:]
		for _, known := range [][]byte{[]byte("CAPABILITY"), []byte("LOGIN"), []byte("STARTTLS"), []byte("AUTHENTICATE"), []byte("SELECT")} {
			if bytes.HasPrefix(command, known) || len(command) >= 3 && bytes.HasPrefix(known, command) {
				return "imap-starttls"
			}
		}
	}
	return ""
}

func (p *parser) feedUpgrade(data []byte) []byte {
	u := p.upgrade
	u.bytes += len(data)
	if u.bytes > maxUpgradeBytes {
		p.evidence.Kind, p.upgrade = "other", nil
		return nil
	}
	u.data = append(u.data, data...)
	if !u.ready {
		end, protocol := upgradePoint(u.data, u.protocol)
		if end == 0 {
			return nil
		}
		u.protocol, u.ready = protocol, true
		u.data = u.data[end:]
	}
	for i := 0; i+5 < len(u.data); i++ {
		if u.data[i] == 22 && u.data[i+1] == 3 && u.data[i+5] == 1 {
			return u.data[i:]
		}
	}
	if len(u.data) > 5 {
		u.data = append([]byte(nil), u.data[len(u.data)-5:]...)
	}
	return nil
}

func upgradePoint(b []byte, protocol string) (int, string) {
	switch protocol {
	case "postgres-ssl":
		return 8, protocol
	case "mysql-ssl":
		return 36, protocol
	case "ldap-starttls":
		if bytes.Contains(b, ldapStartTLSOID) {
			return len(b), protocol
		}
	case "xmpp-starttls":
		if i := bytes.Index(bytes.ToLower(b), []byte("<starttls")); i >= 0 {
			if j := bytes.IndexByte(b[i:], '>'); j >= 0 {
				return i + j + 1, protocol
			}
		}
	default:
		upper := bytes.ToUpper(b)
		for _, marker := range []struct{ word, name string }{
			{"AUTH TLS", "ftp-auth-tls"},
			{"STLS", "pop3-stls"},
			{"STARTTLS", protocol},
		} {
			if i := bytes.Index(upper, []byte(marker.word)); i >= 0 {
				if j := bytes.Index(upper[i:], []byte("\r\n")); j >= 0 {
					return i + j + 2, marker.name
				}
			}
		}
	}
	return 0, protocol
}

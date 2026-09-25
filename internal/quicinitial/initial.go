// Package quicinitial reads the publicly derivable client Initial packets of
// QUIC versions 1 and 2. It does not decrypt QUIC application data.
package quicinitial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	Version1       uint32 = 1
	Version2       uint32 = 0x6b3343cf
	maxCryptoBytes        = 64*1024 + 4
	maxCryptoParts        = 64
)

var (
	v1Salt = [...]byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	v2Salt = [...]byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

type initialKeys struct {
	aead cipher.AEAD
	hp   cipher.Block
	iv   [12]byte
}

type Tracker struct {
	version     uint32
	dcid        []byte
	keys        initialKeys
	largestPN   uint64
	hasPN       bool
	crypto      []byte
	parts       map[uint64][]byte
	pendingSize int
	first       time.Time
	last        time.Time
	done        bool
	failure     string
}

func (t *Tracker) Failure() string { return t.failure }

func (t *Tracker) Fail(reason string) {
	if t.done {
		return
	}
	t.done, t.failure = true, reason
	t.crypto, t.parts, t.dcid = nil, nil, nil
	t.pendingSize = 0
}

func (t *Tracker) Tick(now time.Time) {
	if !t.first.IsZero() && !t.done && now.Sub(t.last) > 10*time.Second {
		t.Fail("QUIC ClientHello gap timeout")
	}
}

// Add returns a complete TLS ClientHello handshake message when available.
// The boolean is true only when a client Initial authenticated successfully.
func (t *Tracker) Add(datagram []byte, now time.Time) ([]byte, bool, error) {
	if t.done || t.failure != "" {
		return nil, false, nil
	}
	if len(datagram) > 65536 {
		return nil, false, nil
	}
	var authenticated bool
	for len(datagram) > 0 {
		packet, consumed, ok := splitLongPacket(datagram)
		if !ok {
			break
		}
		datagram = datagram[consumed:]
		if !packet.initial {
			continue
		}
		plaintext, pn, err := t.open(packet)
		if err != nil {
			continue // A server Initial or unrelated packet is not client evidence.
		}
		authenticated = true
		if t.first.IsZero() {
			t.first = now
		}
		t.last = now
		if !t.hasPN || pn > t.largestPN {
			t.largestPN, t.hasPN = pn, true
		}
		if err := t.frames(plaintext); err != nil {
			t.Fail(err.Error())
			return nil, true, err
		}
		if hello, err := t.clientHello(); err != nil {
			t.Fail(err.Error())
			return nil, true, err
		} else if hello != nil {
			t.done = true
			t.crypto, t.parts, t.dcid = nil, nil, nil
			t.pendingSize = 0
			return hello, true, nil
		}
	}
	return nil, authenticated, nil
}

type longPacket struct {
	raw      []byte
	version  uint32
	dcid     []byte
	pnOffset int
	initial  bool
}

func splitLongPacket(data []byte) (longPacket, int, bool) {
	if len(data) < 7 || data[0]&0xc0 != 0xc0 {
		return longPacket{}, 0, false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if version != Version1 && version != Version2 {
		return longPacket{}, 0, false
	}
	packetType := (data[0] >> 4) & 3
	initialType := byte(0)
	retryType := byte(3)
	if version == Version2 {
		initialType, retryType = 1, 0
	}
	offset := 5
	dcidLength := int(data[offset])
	offset++
	if dcidLength > 20 || len(data)-offset < dcidLength+1 {
		return longPacket{}, 0, false
	}
	dcid := data[offset : offset+dcidLength]
	offset += dcidLength
	scidLength := int(data[offset])
	offset++
	if scidLength > 20 || len(data)-offset < scidLength || packetType == retryType {
		return longPacket{}, 0, false
	}
	offset += scidLength
	if packetType == initialType {
		tokenLength, ok := readVarint(data, &offset)
		//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
		if !ok || tokenLength > uint64(len(data)-offset) {
			return longPacket{}, 0, false
		}
		//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
		offset += int(tokenLength)
	}
	packetLength, ok := readVarint(data, &offset)
	//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
	if !ok || packetLength < 17 || packetLength > uint64(len(data)-offset) {
		return longPacket{}, 0, false
	}
	//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
	end := offset + int(packetLength)
	return longPacket{raw: data[:end], version: version, dcid: dcid, pnOffset: offset, initial: packetType == initialType}, end, true
}

func readVarint(data []byte, offset *int) (uint64, bool) {
	if *offset >= len(data) {
		return 0, false
	}
	length := 1 << (data[*offset] >> 6)
	if length > len(data)-*offset {
		return 0, false
	}
	value := uint64(data[*offset] & 0x3f)
	for i := 1; i < length; i++ {
		value = value<<8 | uint64(data[*offset+i])
	}
	*offset += length
	return value, true
}

func (t *Tracker) open(packet longPacket) ([]byte, uint64, error) {
	changedCID := packet.version != t.version || !bytes.Equal(packet.dcid, t.dcid)
	keys := t.keys
	if changedCID {
		var err error
		keys, err = deriveClientKeys(packet.version, packet.dcid)
		if err != nil {
			return nil, 0, err
		}
	}
	if len(packet.raw)-packet.pnOffset < 20 {
		return nil, 0, errors.New("short QUIC header protection sample")
	}
	var mask [16]byte
	keys.hp.Encrypt(mask[:], packet.raw[packet.pnOffset+4:packet.pnOffset+20])
	first := packet.raw[0] ^ mask[0]&0x0f
	pnLength := int(first&3) + 1
	if len(packet.raw)-packet.pnOffset < pnLength+16 {
		return nil, 0, errors.New("short QUIC Initial")
	}
	header := bytes.Clone(packet.raw[:packet.pnOffset+pnLength])
	header[0] = first
	var truncatedPN uint64
	for i := range pnLength {
		//nolint:gosec // G602: index is bounded by a fixed-size QUIC mask or even-length ICMP message.
		header[packet.pnOffset+i] ^= mask[i+1]
		truncatedPN = truncatedPN<<8 | uint64(header[packet.pnOffset+i])
	}
	pn := truncatedPN
	if !changedCID {
		pn = t.packetNumber(truncatedPN, pnLength)
	}
	nonce := keys.iv
	for i := range 8 {
		//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
		nonce[4+i] ^= byte(pn >> (56 - 8*i))
	}
	plain, err := keys.aead.Open(nil, nonce[:], packet.raw[packet.pnOffset+pnLength:], header)
	if err == nil && changedCID {
		t.version, t.dcid, t.keys = packet.version, bytes.Clone(packet.dcid), keys
		t.hasPN, t.largestPN = false, 0
		t.crypto, t.parts, t.pendingSize = nil, nil, 0
		t.first, t.last = time.Time{}, time.Time{}
	}
	return plain, pn, err
}

func (t *Tracker) packetNumber(truncated uint64, length int) uint64 {
	if !t.hasPN {
		return truncated
	}
	window := uint64(1) << (length * 8)
	expected := t.largestPN + 1
	candidate := expected&^(window-1) | truncated
	if candidate+window/2 <= expected && candidate+window < 1<<62 {
		return candidate + window
	}
	if candidate > expected+window/2 && candidate >= window {
		return candidate - window
	}
	return candidate
}

func deriveClientKeys(version uint32, dcid []byte) (initialKeys, error) {
	var salt []byte
	labelPrefix := "quic "
	switch version {
	case Version1:
		salt = v1Salt[:]
	case Version2:
		salt, labelPrefix = v2Salt[:], "quicv2 "
	default:
		return initialKeys{}, fmt.Errorf("unsupported QUIC version %x", version)
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return initialKeys{}, err
	}
	client, err := expandLabel(secret, "client in", 32)
	if err != nil {
		return initialKeys{}, err
	}
	key, err := expandLabel(client, labelPrefix+"key", 16)
	if err != nil {
		return initialKeys{}, err
	}
	iv, err := expandLabel(client, labelPrefix+"iv", 12)
	if err != nil {
		return initialKeys{}, err
	}
	hpKey, err := expandLabel(client, labelPrefix+"hp", 16)
	if err != nil {
		return initialKeys{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return initialKeys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return initialKeys{}, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return initialKeys{}, err
	}
	var keys initialKeys
	keys.aead, keys.hp = aead, hp
	copy(keys.iv[:], iv)
	return keys, nil
}

func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	if len(fullLabel) > 255 || length > 65535 {
		return nil, errors.New("invalid HKDF label")
	}
	info := make([]byte, 0, 4+len(fullLabel))
	//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0) // Zero-length Context.
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func (t *Tracker) frames(plain []byte) error {
	offset := 0
	for offset < len(plain) {
		kind, ok := readVarint(plain, &offset)
		if !ok {
			return errors.New("truncated QUIC Initial frame type")
		}
		switch kind {
		case 0, 1: // PADDING, PING.
		case 2, 3: // ACK, ACK_ECN.
			for range 2 { // Largest Acknowledged, ACK Delay.
				if _, ok := readVarint(plain, &offset); !ok {
					return errors.New("truncated QUIC ACK")
				}
			}
			ranges, ok := readVarint(plain, &offset)
			if !ok || ranges > 256 {
				return errors.New("invalid QUIC ACK ranges")
			}
			if _, ok := readVarint(plain, &offset); !ok { // First ACK Range.
				return errors.New("truncated QUIC ACK")
			}
			for range ranges * 2 {
				if _, ok := readVarint(plain, &offset); !ok {
					return errors.New("truncated QUIC ACK ranges")
				}
			}
			if kind == 3 {
				for range 3 { // ECN counts.
					if _, ok := readVarint(plain, &offset); !ok {
						return errors.New("truncated QUIC ACK ECN")
					}
				}
			}
		case 6: // CRYPTO.
			start, ok := readVarint(plain, &offset)
			if !ok {
				return errors.New("truncated QUIC CRYPTO offset")
			}
			length, ok := readVarint(plain, &offset)
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			if !ok || length > uint64(len(plain)-offset) {
				return errors.New("truncated QUIC CRYPTO data")
			}
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			if err := t.addCrypto(start, plain[offset:offset+int(length)]); err != nil {
				return err
			}
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			offset += int(length)
		case 0x1c, 0x1d: // CONNECTION_CLOSE.
			fields := 1
			if kind == 0x1c {
				fields++
			}
			for range fields {
				if _, ok := readVarint(plain, &offset); !ok {
					return errors.New("truncated QUIC close")
				}
			}
			reasonLength, ok := readVarint(plain, &offset)
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			if !ok || reasonLength > uint64(len(plain)-offset) {
				return errors.New("truncated QUIC close reason")
			}
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			offset += int(reasonLength)
		default:
			return fmt.Errorf("unsupported QUIC Initial frame %x", kind)
		}
	}
	return nil
}

func (t *Tracker) addCrypto(start uint64, data []byte) error {
	if start > maxCryptoBytes || uint64(len(data)) > maxCryptoBytes-start {
		return errors.New("QUIC ClientHello size limit")
	}
	end := start + uint64(len(data))
	if start < uint64(len(t.crypto)) {
		overlap := min(end, uint64(len(t.crypto))) - start
		//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
		if !bytes.Equal(t.crypto[int(start):int(start+overlap)], data[:overlap]) {
			return errors.New("conflicting QUIC CRYPTO retransmission")
		}
		start += overlap
		data = data[overlap:]
	}
	if len(data) == 0 {
		return nil
	}
	if start == uint64(len(t.crypto)) {
		t.crypto = append(t.crypto, data...)
		t.pullParts()
		return nil
	}
	if t.parts == nil {
		t.parts = make(map[uint64][]byte)
	}
	for existingStart, part := range t.parts {
		sharedStart := max(start, existingStart)
		sharedEnd := min(end, existingStart+uint64(len(part)))
		if sharedStart < sharedEnd && !bytes.Equal(data[sharedStart-start:sharedEnd-start], part[sharedStart-existingStart:sharedEnd-existingStart]) {
			return errors.New("conflicting QUIC CRYPTO overlap")
		}
	}
	if prior, ok := t.parts[start]; ok {
		overlap := min(len(prior), len(data))
		if !bytes.Equal(prior[:overlap], data[:overlap]) {
			return errors.New("conflicting QUIC CRYPTO fragment")
		}
		if len(prior) >= len(data) {
			return nil
		}
		t.pendingSize -= len(prior)
	} else if len(t.parts) >= maxCryptoParts {
		return errors.New("QUIC CRYPTO fragment limit")
	}
	if t.pendingSize+len(data) > maxCryptoBytes {
		return errors.New("QUIC CRYPTO buffer limit")
	}
	t.parts[start] = bytes.Clone(data)
	t.pendingSize += len(data)
	return nil
}

func (t *Tracker) pullParts() {
	for {
		progress := false
		for start, part := range t.parts {
			if start > uint64(len(t.crypto)) {
				continue
			}
			delete(t.parts, start)
			t.pendingSize -= len(part)
			//nolint:gosec // G115: QUIC length was checked against remaining input or is a fixed-width wire field.
			used := int(uint64(len(t.crypto)) - start)
			if used < len(part) {
				t.crypto = append(t.crypto, part[used:]...)
				progress = true
			}
		}
		if !progress {
			return
		}
	}
}

func (t *Tracker) clientHello() ([]byte, error) {
	if len(t.crypto) < 4 {
		return nil, nil
	}
	if t.crypto[0] != 1 {
		return nil, errors.New("first QUIC handshake is not ClientHello")
	}
	length := int(t.crypto[1])<<16 | int(t.crypto[2])<<8 | int(t.crypto[3])
	if length > maxCryptoBytes-4 {
		return nil, errors.New("QUIC ClientHello size limit")
	}
	if len(t.crypto) < length+4 {
		return nil, nil
	}
	return bytes.Clone(t.crypto[:length+4]), nil
}

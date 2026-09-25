package pcapng

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
)

// RecordedPacket is one Ethernet frame from a socktrail recording.
type RecordedPacket struct {
	Interface string
	Frame     []byte
	WireLen   uint32
	At        time.Time
	Comment   string
}

// Read walks a recording without keeping all frames in memory. It accepts the
// little-endian, Ethernet, microsecond-timestamp PCAPNG files Writer creates.
func Read(r io.Reader, packet func(RecordedPacket) error) error {
	var names []string
	var header [8]byte
	seenSection := false
	for {
		_, err := io.ReadFull(r, header[:])
		if err == io.EOF {
			if !seenSection {
				return fmt.Errorf("empty PCAPNG file")
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("read PCAPNG block header: %w", err)
		}
		kind, size := binary.LittleEndian.Uint32(header[:4]), binary.LittleEndian.Uint32(header[4:])
		if size < 12 || size%4 != 0 || size > 1<<20 {
			return fmt.Errorf("invalid PCAPNG block length %d", size)
		}
		body := make([]byte, int(size)-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return fmt.Errorf("read PCAPNG block: %w", err)
		}
		if binary.LittleEndian.Uint32(body[len(body)-4:]) != size {
			return fmt.Errorf("PCAPNG block length mismatch")
		}
		body = body[:len(body)-4]
		if !seenSection && kind != sectionHeader {
			return fmt.Errorf("PCAPNG section header is missing")
		}
		switch kind {
		case sectionHeader:
			if seenSection || len(body) < 16 || binary.LittleEndian.Uint32(body[:4]) != 0x1a2b3c4d {
				return fmt.Errorf("unsupported PCAPNG section")
			}
			seenSection = true
		case interfaceDescription:
			if !seenSection || len(body) < 8 || binary.LittleEndian.Uint16(body[:2]) != ethernetLinkType {
				return fmt.Errorf("unsupported PCAPNG interface")
			}
			var name string
			var resolution byte = 6 // PCAPNG's default is actually 10^-6.
			if err := readOptions(body[8:], func(kind uint16, value []byte) {
				switch kind {
				case 2:
					name = string(value)
				case 9:
					if len(value) == 1 {
						resolution = value[0]
					}
				}
			}); err != nil {
				return err
			}
			if name == "" || resolution != 6 {
				return fmt.Errorf("PCAPNG interface needs a name and microsecond timestamps")
			}
			names = append(names, name)
		case enhancedPacket:
			if !seenSection || len(body) < 20 {
				return fmt.Errorf("invalid PCAPNG packet block")
			}
			id, captured, wire := binary.LittleEndian.Uint32(body[:4]), binary.LittleEndian.Uint32(body[12:16]), binary.LittleEndian.Uint32(body[16:20])
			if uint64(id) >= uint64(len(names)) || captured == 0 || captured > maxSnapLength || wire < captured || 20+int((captured+3)&^uint32(3)) > len(body) {
				return fmt.Errorf("invalid PCAPNG packet length or interface")
			}
			optionStart := 20 + int((captured+3)&^uint32(3))
			var comment string
			if err := readOptions(body[optionStart:], func(kind uint16, value []byte) {
				if kind == 1 {
					comment = string(value)
				}
			}); err != nil {
				return err
			}
			stamp := uint64(binary.LittleEndian.Uint32(body[4:8]))<<32 | uint64(binary.LittleEndian.Uint32(body[8:12]))
			if stamp > math.MaxInt64 {
				return fmt.Errorf("invalid PCAPNG timestamp")
			}
			if err := packet(RecordedPacket{Interface: names[id], Frame: body[20 : 20+captured], WireLen: wire, At: time.UnixMicro(int64(stamp)), Comment: comment}); err != nil {
				return err
			}
		}
	}
}

func readOptions(data []byte, visit func(uint16, []byte)) error {
	for len(data) > 0 {
		if len(data) < 4 {
			return fmt.Errorf("short PCAPNG option")
		}
		kind, size := binary.LittleEndian.Uint16(data[:2]), int(binary.LittleEndian.Uint16(data[2:4]))
		data = data[4:]
		padded := (size + 3) &^ 3
		if len(data) < padded {
			return fmt.Errorf("invalid PCAPNG option length")
		}
		if kind == 0 {
			if size != 0 {
				return fmt.Errorf("invalid PCAPNG option end")
			}
			return nil
		}
		visit(kind, data[:size])
		data = data[padded:]
	}
	return nil
}

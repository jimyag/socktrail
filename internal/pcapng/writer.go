package pcapng

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	sectionHeader        = 0x0a0d0d0a
	interfaceDescription = 1
	enhancedPacket       = 6
	ethernetLinkType     = 1
	maxSnapLength        = 65536
)

var ErrLimit = errors.New("PCAPNG size limit reached")

type Writer struct {
	out        io.Writer
	maxBytes   uint64
	bytes      uint64
	Packets    uint64
	interfaces uint32
}

func New(out io.Writer, interfaceNames []string, maxBytes uint64) (*Writer, error) {
	if len(interfaceNames) == 0 {
		return nil, fmt.Errorf("PCAPNG needs at least one interface")
	}
	w := &Writer{out: out, maxBytes: maxBytes}
	section := binary.LittleEndian.AppendUint32(nil, 0x1a2b3c4d)
	section = binary.LittleEndian.AppendUint16(section, 1)
	section = binary.LittleEndian.AppendUint16(section, 0)
	section = binary.LittleEndian.AppendUint64(section, ^uint64(0))
	if err := w.block(sectionHeader, section); err != nil {
		return nil, err
	}
	for _, interfaceName := range interfaceNames {
		iface := binary.LittleEndian.AppendUint16(nil, ethernetLinkType)
		iface = binary.LittleEndian.AppendUint16(iface, 0)
		iface = binary.LittleEndian.AppendUint32(iface, maxSnapLength)
		iface = appendOption(iface, 2, []byte(interfaceName)) // if_name
		iface = appendOption(iface, 9, []byte{6})             // microsecond timestamps
		iface = appendOption(iface, 0, nil)
		if err := w.block(interfaceDescription, iface); err != nil {
			return nil, err
		}
	}
	w.interfaces = uint32(len(interfaceNames))
	return w, nil
}

func (w *Writer) Packet(interfaceID uint32, frame []byte, at time.Time, comment string) error {
	if interfaceID >= w.interfaces {
		return fmt.Errorf("invalid PCAPNG interface %d", interfaceID)
	}
	if len(frame) == 0 || len(frame) > maxSnapLength {
		return fmt.Errorf("invalid captured frame length %d", len(frame))
	}
	stamp := uint64(at.UnixMicro())
	body := binary.LittleEndian.AppendUint32(nil, interfaceID)
	body = binary.LittleEndian.AppendUint32(body, uint32(stamp>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(stamp))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(frame)))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(frame)))
	body = appendPadded(body, frame)
	if comment != "" {
		body = appendOption(body, 1, []byte(comment))
		body = appendOption(body, 0, nil)
	}
	if err := w.block(enhancedPacket, body); err != nil {
		return err
	}
	w.Packets++
	return nil
}

func (w *Writer) Bytes() uint64 { return w.bytes }

func (w *Writer) block(kind uint32, body []byte) error {
	if len(body)%4 != 0 {
		return fmt.Errorf("PCAPNG block body is not aligned")
	}
	length := uint32(len(body) + 12)
	if w.maxBytes > 0 && w.bytes+uint64(length) > w.maxBytes {
		return ErrLimit
	}
	block := binary.LittleEndian.AppendUint32(nil, kind)
	block = binary.LittleEndian.AppendUint32(block, length)
	block = append(block, body...)
	block = binary.LittleEndian.AppendUint32(block, length)
	n, err := w.out.Write(block)
	w.bytes += uint64(n)
	if err != nil {
		return err
	}
	if n != len(block) {
		return io.ErrShortWrite
	}
	return nil
}

func appendOption(dst []byte, kind uint16, value []byte) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, kind)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(value)))
	return appendPadded(dst, value)
}

func appendPadded(dst, data []byte) []byte {
	dst = append(dst, data...)
	return append(dst, make([]byte, (-len(data))&3)...)
}

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimyag/socktrail/internal/capture"
	"github.com/jimyag/socktrail/internal/pcapng"
)

const (
	recordingDuration = 15 * time.Second
	recordingLimit    = 64 << 20
)

type captureSession struct {
	file       *os.File
	writer     *pcapng.Writer
	path       string
	until      time.Time
	interfaces map[string]uint32
	flow       *flow
	pid        processID
	label      string
}

func startCapture(dir string, interfaces []string, selected *flow, pid processID, collectors map[string]*collector) (*captureSession, error) {
	if pid.PID == 0 && selected == nil {
		return nil, fmt.Errorf("select an active connection first")
	}
	var target *flow
	if pid.PID == 0 {
		var chosenInterface string
		for _, name := range interfaces {
			candidate := collectors[name].flows[selected.Key]
			if candidate == nil || candidate.Closed || selected.SYNSeen && candidate.SYNSeen && selected.SYNSeq != candidate.SYNSeq {
				continue
			}
			if candidate == selected {
				target, chosenInterface = candidate, name
				break
			}
			if selected.Last.Before(candidate.First.Add(-2*time.Second)) || candidate.Last.Before(selected.First.Add(-2*time.Second)) {
				continue
			}
			if target == nil || candidate.RX+candidate.TX > target.RX+target.TX {
				target, chosenInterface = candidate, name
			}
		}
		if target == nil {
			return nil, fmt.Errorf("selected connection is no longer active")
		}
		interfaces = []string{chosenInterface}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create capture directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "socktrail-*.pcapng")
	if err != nil {
		return nil, fmt.Errorf("create PCAPNG file: %w", err)
	}
	writer, err := pcapng.New(file, interfaces, recordingLimit)
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	path, err := filepath.Abs(file.Name())
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	session := &captureSession{file: file, writer: writer, path: path, until: time.Now().Add(recordingDuration), interfaces: make(map[string]uint32), flow: target, pid: pid}
	for index, name := range interfaces {
		session.interfaces[name] = uint32(index)
	}
	if pid.PID > 0 {
		session.label = fmt.Sprintf("PID %d", pid.PID)
	} else {
		session.label = fmt.Sprintf("%s %s", flowProtocol(target), target.Key.A)
	}
	return session, nil
}

func (s *captureSession) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *captureSession) Write(p capture.Packet, observed *flow) error {
	interfaceID, enabled := s.interfaces[p.Interface]
	if !enabled || len(p.Frame) == 0 || observed == nil {
		return nil
	}
	if s.flow != nil && observed != s.flow {
		return nil
	}
	if s.pid.PID > 0 && observed.Client.id() != s.pid && observed.Server.id() != s.pid {
		if _, didIO := observed.IO[s.pid]; !didIO {
			return nil
		}
	}
	packetDirection := "rx"
	if p.Outgoing {
		packetDirection = "tx"
	}
	comment := fmt.Sprintf("socktrail interface=%s packet_direction=%s flow_direction=%s app=%s app_source=%q origin_pid=%d origin_start_ns=%d origin_process=%q target_pid=%d target_start_ns=%d target_process=%q", p.Interface, packetDirection, observed.Direction, observed.AppProtocol, observed.AppSource, observed.Client.PID, observed.Client.StartNS, observed.Client.Name, observed.Server.PID, observed.Server.StartNS, observed.Server.Name)
	if p.Truncated || len(p.Frame) < p.FrameLen {
		comment += " captured_frame_truncated=true"
	}
	if observed.Domain != nil && observed.Domain.Evidence().Listed() {
		comment += fmt.Sprintf(" domain=%q", observed.Domain.Evidence().Label())
	}
	comment = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == 0 {
			return ' '
		}
		return r
	}, comment)
	if len(comment) > 1024 {
		comment = comment[:1024]
	}
	if err := s.writer.Packet(interfaceID, p.Frame, p.FrameLen, p.CapturedAt, comment); err != nil {
		if errors.Is(err, pcapng.ErrLimit) {
			return pcapng.ErrLimit
		}
		return fmt.Errorf("write PCAPNG: %w", err)
	}
	return nil
}

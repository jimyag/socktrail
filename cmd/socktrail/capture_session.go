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
	historyLimit      = 32 << 20 // Frame bytes --record-before keeps.
)

// frameHistory keeps copies of the latest frames, up to an age and
// historyLimit bytes, for a recording to start with.
// ponytail: one allocation per frame, fine for an opt-in debugging aid;
// a preallocated byte ring if it ever runs on busy links by default.
type frameHistory struct {
	frames []historyFrame // Oldest first.
	bytes  int
	maxAge time.Duration
}

type historyFrame struct {
	packet capture.Packet // Only what captureSession.Write reads: Payload points into the ring.
	flow   *flow
}

func (h *frameHistory) add(p capture.Packet, f *flow) {
	if len(p.Frame) == 0 || f == nil {
		return
	}
	kept := capture.Packet{Interface: p.Interface, Frame: p.Frame, FrameLen: p.FrameLen, CapturedAt: p.CapturedAt, Outgoing: p.Outgoing, Truncated: p.Truncated}
	h.frames = append(h.frames, historyFrame{kept, f})
	h.bytes += len(p.Frame)
	h.trim(p.CapturedAt)
}

// trim drops frames older than maxAge before now, and the oldest beyond
// historyLimit.
func (h *frameHistory) trim(now time.Time) {
	drop := 0
	for drop < len(h.frames) && (h.bytes > historyLimit || now.Sub(h.frames[drop].packet.CapturedAt) > h.maxAge) {
		h.bytes -= len(h.frames[drop].packet.Frame)
		h.frames[drop] = historyFrame{}
		drop++
	}
	h.frames = h.frames[drop:]
}

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

func defaultCaptureDir() (string, error) {
	stateHome := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(stateHome) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("find home directory for captures: %w", err)
		}
		stateHome = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(stateHome, "socktrail", "captures"), nil
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
	if dir == "" {
		var err error
		dir, err = defaultCaptureDir()
		if err != nil {
			return nil, err
		}
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

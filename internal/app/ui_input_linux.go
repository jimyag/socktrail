package app

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type mouseAction uint8

const (
	mouseNone mouseAction = iota
	mousePress
	mouseDrag
	mouseRelease
	mouseWheelUp
	mouseWheelDown
	mouseWheelLeft
	mouseWheelRight
)

type mouseInput struct {
	action mouseAction
	button int
	x, y   int // zero-based terminal cell coordinates
	shift  bool
}

type uiInput struct {
	key   string
	mouse mouseInput
}

// readKeys decodes terminal input until the terminal fails or goes away,
// which it reports as a quit: nobody could stop the capture otherwise.
func readKeys(out chan<- uiInput) {
	defer func() { out <- uiInput{key: "quit"} }()
	fd := int32(os.Stdin.Fd())
	buffer := make([]byte, 128)
	var pending []byte
	for {
		timeout := -1
		if len(pending) > 0 {
			timeout = 50 // A lone Escape key must still work.
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: fd, Events: unix.POLLIN}}, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return
		}
		flush := n == 0
		if !flush {
			count, err := os.Stdin.Read(buffer)
			if err != nil || count == 0 {
				return
			}
			pending = append(pending, buffer[:count]...)
		}
		for len(pending) > 0 {
			input, consumed, incomplete := decodeUIInput(pending, flush)
			if incomplete {
				break
			}
			pending = pending[consumed:]
			if input.key != "" || input.mouse.action != mouseNone {
				out <- input
			}
		}
	}
}

func decodeUIInput(data []byte, flush bool) (uiInput, int, bool) {
	if len(data) == 0 {
		return uiInput{}, 0, true
	}
	if data[0] != 27 {
		switch data[0] {
		case 13, 10:
			return uiInput{key: "enter"}, 1, false
		case 9:
			return uiInput{key: "tab"}, 1, false
		case 127, 8:
			return uiInput{key: "backspace"}, 1, false
		case 3:
			return uiInput{key: "quit"}, 1, false
		default:
			if data[0] >= 32 && data[0] < 127 {
				return uiInput{key: string(data[0])}, 1, false
			}
			return uiInput{}, 1, false
		}
	}
	if len(data) == 1 {
		if flush {
			return uiInput{key: "esc"}, 1, false
		}
		return uiInput{}, 0, true
	}
	if data[1] != '[' {
		return uiInput{key: "esc"}, 1, false
	}
	for end := 2; end < len(data) && end < 64; end++ {
		if data[end] < 0x40 || data[end] > 0x7e {
			continue
		}
		if end == 2 {
			switch data[end] {
			case 'A':
				return uiInput{key: "up"}, end + 1, false
			case 'B':
				return uiInput{key: "down"}, end + 1, false
			case 'C':
				return uiInput{key: "right"}, end + 1, false
			case 'D':
				return uiInput{key: "left"}, end + 1, false
			case 'Z':
				return uiInput{key: "shift-tab"}, end + 1, false
			}
		}
		if data[end] == 'Z' && string(data[2:end]) == "1;2" {
			return uiInput{key: "shift-tab"}, end + 1, false
		}
		if data[end] == '~' {
			switch string(data[2:end]) {
			case "5":
				return uiInput{key: "pageup"}, end + 1, false
			case "6":
				return uiInput{key: "pagedown"}, end + 1, false
			}
		}
		if data[2] == '<' && (data[end] == 'M' || data[end] == 'm') {
			return decodeMouse(data[3:end], data[end] == 'm'), end + 1, false
		}
		return uiInput{}, end + 1, false
	}
	if flush || len(data) >= 64 {
		return uiInput{}, len(data), false
	}
	return uiInput{}, 0, true
}

func decodeMouse(payload []byte, release bool) uiInput {
	codeText, rest, ok := strings.Cut(string(payload), ";")
	if !ok {
		return uiInput{}
	}
	xText, yText, ok := strings.Cut(rest, ";")
	if !ok {
		return uiInput{}
	}
	code, errCode := strconv.Atoi(codeText)
	x, errX := strconv.Atoi(xText)
	y, errY := strconv.Atoi(yText)
	if errCode != nil || errX != nil || errY != nil || x < 1 || y < 1 || code < 0 || code > 255 {
		return uiInput{}
	}
	m := mouseInput{button: code & 3, x: x - 1, y: y - 1, shift: code&4 != 0}
	switch {
	case code&64 != 0:
		switch code & 3 {
		case 0:
			m.action = mouseWheelUp
		case 1:
			m.action = mouseWheelDown
		case 2:
			m.action = mouseWheelLeft
		case 3:
			m.action = mouseWheelRight
		}
	case release:
		m.action = mouseRelease
	case code&32 != 0:
		m.action = mouseDrag
	default:
		m.action = mousePress
	}
	return uiInput{mouse: m}
}

package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"sync"
)

// streamClientBuffer is how far one subscriber may fall behind. At roughly
// 1 KiB per flow frame this absorbs a few MiB of jitter; past it the client is
// closed rather than allowed to stall the capture loop.
const streamClientBuffer = 1024

// streamClient is one connected subscriber. Frames reach it through a bounded
// channel written by its own goroutine, so a client that stops reading never
// blocks the capture loop.
type streamClient struct {
	conn    io.WriteCloser
	frames  chan []byte
	closing chan struct{}
	once    sync.Once
}

func newStreamClient(conn io.WriteCloser) *streamClient {
	client := &streamClient{
		conn:    conn,
		frames:  make(chan []byte, streamClientBuffer),
		closing: make(chan struct{}),
	}
	go client.writeLoop()
	return client
}

func (c *streamClient) writeLoop() {
	defer c.close()
	for {
		select {
		case frame := <-c.frames:
			if _, err := c.conn.Write(frame); err != nil {
				return
			}
		case <-c.closing:
			return
		}
	}
}

// offer queues one frame. It reports false when the client is closing or has
// fallen further behind than the buffer allows.
func (c *streamClient) offer(frame []byte) bool {
	select {
	case <-c.closing:
		return false
	default:
	}
	select {
	case c.frames <- frame:
		return true
	default:
		return false
	}
}

func (c *streamClient) close() {
	c.once.Do(func() {
		close(c.closing)
		_ = c.conn.Close()
	})
}

// streamHub serves the frame stream on a Unix domain socket. Listening and
// accepting run on other goroutines; the client set belongs to the capture
// loop alone, so it needs no lock.
type streamHub struct {
	path     string
	listener net.Listener
	joining  chan *streamClient
	clients  map[*streamClient]struct{}
}

func newStreamHub(path string, listener net.Listener) *streamHub {
	return &streamHub{
		path:     path,
		listener: listener,
		joining:  make(chan *streamClient, 16),
		clients:  make(map[*streamClient]struct{}),
	}
}

// listenStreamSocket opens the socket and starts accepting subscribers. A
// socket file left behind by a killed process is replaced; any other file at
// the path is left alone, because removing it could destroy something the user
// put there.
func listenStreamSocket(path string) (*streamHub, error) {
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on socket %s: %w", path, err)
	}
	// The frames carry domains, PIDs and traffic counts, so keep the socket
	// owner-only like the change log.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("protect socket %s: %w", path, err)
	}
	hub := newStreamHub(path, listener)
	go hub.accept(listener)
	return hub, nil
}

// clearStaleSocket removes a socket file no process is listening on. A path
// that still answers belongs to a running instance and is reported as such.
func clearStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("check socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket %s exists and is not a socket", path)
	}
	if conn, err := net.Dial("unix", path); err == nil {
		_ = conn.Close()
		return fmt.Errorf("socket %s is already in use by another socktrail", path)
	}
	return os.Remove(path)
}

func (h *streamHub) accept(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		client := newStreamClient(conn)
		select {
		case h.joining <- client:
		default:
			client.close() // The capture loop is not draining; refuse the client.
		}
	}
}

// adopt takes the clients accepted since the last tick. The capture loop calls
// it before deciding whether anything needs encoding.
func (h *streamHub) adopt() {
	for {
		select {
		case client := <-h.joining:
			h.clients[client] = struct{}{}
		default:
			return
		}
	}
}

func (h *streamHub) active() bool {
	return len(h.clients) > 0
}

// broadcast sends one frame to every subscriber. A client that cannot take the
// frame is closed instead of stalling the loop; it reconnects and receives the
// state again, which beats silently dropping frames it would never notice.
func (h *streamHub) broadcast(frame []byte) {
	if len(h.clients) == 0 {
		return
	}
	// The codec reuses its buffer, so every frame handed to a client is a copy.
	shared := bytes.Clone(frame)
	for client := range h.clients {
		if !client.offer(shared) {
			client.close()
			delete(h.clients, client)
		}
	}
}

func (h *streamHub) close() {
	if h.listener != nil {
		_ = h.listener.Close()
	}
drain:
	for {
		select {
		case client := <-h.joining:
			client.close()
		default:
			break drain
		}
	}
	for client := range h.clients {
		client.close()
	}
	clear(h.clients)
	if h.path != "" {
		// The listener already unlinks on close; this covers a hub without one.
		_ = os.Remove(h.path)
	}
}

// streamSink is where encoded frames go: standard output, the change log, or
// the socket hub.
type streamSink struct {
	codec  *streamCodec
	format string
	writer io.Writer // Standard output or the change log; nil when hub is set.
	hub    *streamHub
}

func newStreamSink(format string, writer io.Writer, hub *streamHub) (*streamSink, error) {
	codec, err := newStreamCodec(format)
	if err != nil {
		return nil, err
	}
	return &streamSink{codec: codec, format: format, writer: writer, hub: hub}, nil
}

// write emits one row. With a hub and no subscribers nothing is encoded at
// all, so a capture that nobody is watching costs no serialization work.
func (s *streamSink) write(row any) error {
	if s.hub != nil {
		s.hub.adopt()
		if !s.hub.active() {
			return nil
		}
		frame, err := s.codec.encode(row)
		if err != nil {
			return err
		}
		s.hub.broadcast(frame)
		return nil
	}
	frame, err := s.codec.encode(row)
	if err != nil {
		return err
	}
	_, err = s.writer.Write(frame)
	return err
}

package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
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
	listener net.Listener
	joining  chan *streamClient
	clients  map[*streamClient]struct{}
	pending  []*streamClient // Adopted but not yet greeted; capture loop only.
}

func newStreamHub(listener net.Listener) *streamHub {
	return &streamHub{
		listener: listener,
		joining:  make(chan *streamClient, 16),
		clients:  make(map[*streamClient]struct{}),
	}
}

// parseSocketMode reads the octal permission bits for the socket file.
func parseSocketMode(value string) (fs.FileMode, error) {
	bits, err := strconv.ParseUint(value, 8, 32)
	if err != nil || bits > 0o777 {
		return 0, fmt.Errorf("invalid --socket-mode %q: use octal bits such as 0600 or 0660", value)
	}
	return fs.FileMode(bits), nil
}

// listenStreamSocket opens the socket and starts accepting subscribers. A
// socket file left behind by a killed process is replaced; any other file at
// the path is left alone, because removing it could destroy something the user
// put there.
func listenStreamSocket(path string, mode fs.FileMode) (*streamHub, error) {
	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on socket %s: %w", path, err)
	}
	// The frames carry domains, PIDs and traffic counts, so the default stays
	// owner-only; --socket-mode widens it for a consumer in another account.
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("set mode %o on socket %s: %w", mode, path, err)
	}
	hub := newStreamHub(listener)
	go hub.accept(listener)
	return hub, nil
}

// clearStaleSocket removes a socket file no process is listening on. Only a
// refused connection proves that: a socket we may not connect to, or a
// datagram socket such as journald's, can still belong to a running service.
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
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("socket %s is already in use", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("socket %s exists and may be in use, so it is left alone: %w", path, err)
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
			h.pending = append(h.pending, client)
		default:
			return
		}
	}
}

// takePending returns the clients that still owe a handshake and clears the
// list. A client that fell behind and was dropped in the meantime is skipped.
func (h *streamHub) takePending() []*streamClient {
	var pending []*streamClient
	for _, client := range h.pending {
		if _, ok := h.clients[client]; ok {
			pending = append(pending, client)
		}
	}
	h.pending = nil
	return pending
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
			h.drop(client)
		}
	}
}

func (h *streamHub) drop(client *streamClient) {
	client.close()
	delete(h.clients, client)
}

// close stops accepting and disconnects every client. Closing the listener
// also removes the socket file, which net.Listen created.
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
	h.pending = nil
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

// flow emits one connection change.
func (s *streamSink) flow(row jsonFlow) error {
	if s.hub == nil {
		return s.writeRow(row)
	}
	return s.writeFrame(streamFrame{Kind: streamKindFlow, Flow: &row})
}

// writeFrame broadcasts one metadata frame. Standard output carries no frame
// kinds, so this is a no-op without a hub.
func (s *streamSink) writeFrame(frame streamFrame) error {
	if s.hub == nil || !s.hub.active() {
		return nil
	}
	raw, err := s.encodeFrame(frame)
	if err != nil {
		return err
	}
	s.hub.broadcast(raw)
	return nil
}

// greet sends the handshake to the clients that connected since the last tick.
// fill runs once, not per client, so the snapshot is built once and shared.
// The handshake is queued as one buffer: the snapshot can hold maxFlows rows,
// far more than a client buffer has slots, and frame by frame it would drop
// every new client of a busy host before the first frame left.
// Without a socket there is no handshake: standard output is a bare row stream.
func (s *streamSink) greet(fill func(send func(any) error) error) error {
	if s.hub == nil {
		return nil
	}
	clients := s.hub.takePending()
	if len(clients) == 0 {
		return nil
	}
	var handshake []byte
	collect := func(v any) error {
		frame, err := s.encodeFrame(v)
		if err != nil {
			return err
		}
		handshake = append(handshake, frame...)
		return nil
	}
	if err := fill(collect); err != nil {
		return err
	}
	for _, client := range clients {
		if !client.offer(handshake) {
			s.hub.drop(client)
		}
	}
	return nil
}

// adoptClients takes the connections accepted since the last tick.
func (s *streamSink) adoptClients() {
	if s.hub != nil {
		s.hub.adopt()
	}
}

// encodeFrame serializes one value for the socket. A bare jsonFlow is wrapped
// in a frame envelope; metadata already carries its kind. The bytes are the
// codec's buffer, valid until the next encode: greet appends them to its
// handshake and broadcast copies them.
func (s *streamSink) encodeFrame(v any) ([]byte, error) {
	if row, ok := v.(jsonFlow); ok {
		v = streamFrame{Kind: streamKindFlow, Flow: &row}
	}
	return s.codec.encode(v)
}

// writeRow writes one bare row, which is what standard output and the change
// log carry. Nothing is encoded while the hub has no subscribers, so a capture
// nobody is watching costs no serialization work.
func (s *streamSink) writeRow(row any) error {
	frame, err := s.codec.encode(row)
	if err != nil {
		return err
	}
	_, err = s.writer.Write(frame)
	return err
}

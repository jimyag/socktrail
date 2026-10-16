package app

import (
	"bytes"
	"errors"
	"io"
)

type streamOutput struct{ io.Writer }

func (streamOutput) Close() error { return nil }

// Buffer a full interface refresh; sustained backpressure waits for the reader.
const streamOutputBuffer = 20_000

// streamWriter buffers brief output stalls. The loop owns Write
// and Close; err is read only after done closes.
type streamWriter struct {
	frames chan []byte
	done   chan struct{}
	err    error
}

func newStreamWriter(out io.WriteCloser) *streamWriter {
	w := &streamWriter{frames: make(chan []byte, streamOutputBuffer), done: make(chan struct{})}
	go func() {
		defer func() {
			w.err = errors.Join(w.err, out.Close())
			close(w.done)
		}()
		for frame := range w.frames {
			n, err := out.Write(frame)
			if err != nil {
				w.err = err
				return
			}
			if n != len(frame) {
				w.err = io.ErrShortWrite
				return
			}
		}
	}()
	return w
}

func (w *streamWriter) Write(frame []byte) (int, error) {
	select {
	case <-w.done:
		if w.err != nil {
			return 0, w.err
		}
		return 0, io.ErrClosedPipe
	default:
	}
	select {
	case w.frames <- bytes.Clone(frame):
		return len(frame), nil
	case <-w.done:
		return 0, w.err
	}
}

func (w *streamWriter) Close() error {
	close(w.frames)
	<-w.done
	return w.err
}

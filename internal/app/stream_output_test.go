package app

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type gatedStreamOutput struct {
	started chan struct{}
	release chan struct{}
	err     error
}

func (w *gatedStreamOutput) Write(p []byte) (int, error) {
	if w.started != nil {
		close(w.started)
		w.started = nil
	}
	<-w.release
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *gatedStreamOutput) Close() error { return nil }

func TestStreamWriterBuffersBurstsAndWaitsForSlowConsumer(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	out := &gatedStreamOutput{started: started, release: release}
	w := newStreamWriter(out)
	if _, err := w.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	<-started
	for range streamOutputBuffer {
		if _, err := w.Write([]byte("queued")); err != nil {
			t.Fatal(err)
		}
	}
	written := make(chan error, 1)
	go func() {
		_, err := w.Write([]byte("overflow"))
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("full queue did not wait for its consumer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamWriterCopiesFramesAndDrainsOnClose(t *testing.T) {
	var out bytes.Buffer
	w := newStreamWriter(streamOutput{&out})
	frame := []byte("before")
	if _, err := w.Write(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame, "after!")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "before" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestStreamWriterPropagatesBackgroundFailure(t *testing.T) {
	want := errors.New("write failed")
	release := make(chan struct{})
	close(release)
	w := newStreamWriter(&gatedStreamOutput{release: release, err: want})
	if _, err := w.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	<-w.done
	if _, err := w.Write([]byte("next")); !errors.Is(err, want) {
		t.Fatalf("write error = %v", err)
	}
	if err := w.Close(); !errors.Is(err, want) {
		t.Fatalf("close error = %v", err)
	}
}

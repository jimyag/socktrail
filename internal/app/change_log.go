package app

import (
	"fmt"
	"os"
)

const maxChangeLogSize int64 = 64 << 20

type changeLog struct {
	path string
	file *os.File
	size int64
}

func openChangeLog(path string) (*changeLog, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // The path is explicitly supplied by the user.
	if err != nil {
		return nil, fmt.Errorf("open change log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect change log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat change log: %w", err)
	}
	return &changeLog{path: path, file: file, size: info.Size()}, nil
}

func (l *changeLog) Write(p []byte) (int, error) {
	if l.size > 0 && l.size+int64(len(p)) > maxChangeLogSize {
		if err := l.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := l.file.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *changeLog) rotate() error {
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close change log: %w", err)
	}
	l.file = nil
	if err := os.Remove(l.path + ".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove old change log: %w", err)
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return fmt.Errorf("rotate change log: %w", err)
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create change log: %w", err)
	}
	l.file = file
	l.size = 0
	return nil
}

func (l *changeLog) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

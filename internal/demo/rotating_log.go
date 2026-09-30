package demo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const maxLogFiles = 16

// LogOptions bounds daemon diagnostics separately from measurement results.
// Zero values select 10 MiB per file, three files and seven days. Age limits
// are applied when opening or writing a log; a stopped role does not run a
// background cleanup process. Numbered archives belong to this policy.
type LogOptions struct {
	MaxBytes int64
	Files    int
	MaxAge   time.Duration
}

func (o LogOptions) defaults() (LogOptions, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = 10 << 20
	}
	if o.Files == 0 {
		o.Files = 3
	}
	if o.MaxAge == 0 {
		o.MaxAge = 7 * 24 * time.Hour
	}
	if o.MaxBytes < 1 || o.MaxBytes > 100<<20 || o.Files < 1 || o.Files > maxLogFiles || o.MaxAge < time.Second || o.MaxAge > 30*24*time.Hour {
		return o, errors.New("log limits require 1..104857600 bytes per file, 1..16 files and an age between 1s and 720h")
	}
	return o, nil
}

// rotatingLog stays attached to os/exec's output copier across rotations.
// After a disk failure it cancels the role and keeps draining until the child
// has joined, so a full filesystem cannot strand a child on its output pipe.
type rotatingLog struct {
	mu      sync.Mutex
	root    *os.Root
	name    string
	file    *os.File
	options LogOptions
	size    int64
	opened  time.Time
	err     error
	onError context.CancelCauseFunc
}

func newRotatingLog(path string, options LogOptions, onError context.CancelCauseFunc) (*rotatingLog, error) {
	options, err := options.defaults()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	log := &rotatingLog{root: root, name: filepath.Base(path), options: options, onError: onError}
	if err := log.expire(time.Now()); err != nil {
		root.Close()
		return nil, err
	}
	if err := log.open(); err != nil {
		root.Close()
		return nil, err
	}
	if log.size > 0 && time.Since(log.opened) >= options.MaxAge {
		if err := log.rotate(time.Now()); err != nil {
			log.Close()
			return nil, err
		}
		if err := log.expire(time.Now()); err != nil {
			log.Close()
			return nil, err
		}
	}
	return log, nil
}

func (l *rotatingLog) archive(index int) string { return l.name + "." + strconv.Itoa(index) }

func (l *rotatingLog) inspect(name string) (os.FileInfo, error) {
	info, err := l.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	names, known := FileNames(info)
	if !info.Mode().IsRegular() || !known || names != 1 {
		return nil, fmt.Errorf("refusing daemon log %s: expected a regular file with one name", name)
	}
	return info, nil
}

func (l *rotatingLog) expire(now time.Time) error {
	for index := 1; index < maxLogFiles; index++ {
		name := l.archive(index)
		info, err := l.inspect(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if index >= l.options.Files || now.Sub(info.ModTime()) >= l.options.MaxAge || info.Size() > l.options.MaxBytes {
			if err := l.root.Remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *rotatingLog) open() error {
	info, err := l.inspect(l.name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	flags := os.O_RDWR | OpenWithoutWaiting
	if errors.Is(err, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := l.root.OpenFile(l.name, flags, 0600)
	if err != nil {
		return err
	}
	stat, err := file.Stat()
	if err == nil && info != nil && !os.SameFile(info, stat) {
		err = errors.New("daemon log was replaced while opening")
	}
	if err == nil {
		err = file.Chmod(0600)
	}
	if err != nil {
		file.Close()
		return err
	}
	l.file, l.size, l.opened = file, stat.Size(), stat.ModTime()
	// A smaller configured limit also bounds pre-existing logs. Keep their
	// newest diagnostics using a fixed-size buffer, then continue appending.
	// Leave expired files untouched for the constructor to rotate and remove:
	// trimming would refresh their modification time and retain expired bytes.
	if l.size > l.options.MaxBytes && time.Since(l.opened) < l.options.MaxAge {
		start := l.size - l.options.MaxBytes
		buffer := make([]byte, 32<<10)
		for offset := int64(0); offset < l.options.MaxBytes; {
			n := min(int64(len(buffer)), l.options.MaxBytes-offset)
			if _, err = file.ReadAt(buffer[:n], start+offset); err != nil {
				break
			}
			if _, err = file.WriteAt(buffer[:n], offset); err != nil {
				break
			}
			offset += n
		}
		if err == nil {
			err = file.Truncate(l.options.MaxBytes)
		}
		l.size = l.options.MaxBytes
	}
	if err == nil {
		_, err = file.Seek(0, io.SeekEnd)
	}
	if err != nil {
		file.Close()
		l.file = nil
	}
	return err
}

func (l *rotatingLog) rotate(now time.Time) error {
	if err := l.file.Close(); err != nil {
		return err
	}
	l.file = nil
	for index := l.options.Files - 1; index >= 1; index-- {
		source := l.name
		if index > 1 {
			source = l.archive(index - 1)
		}
		if _, err := l.inspect(source); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := l.root.Rename(source, l.archive(index)); err != nil {
			return err
		}
	}
	if l.options.Files == 1 {
		if err := l.root.Remove(l.name); err != nil {
			return err
		}
	}
	if err := l.open(); err != nil {
		return err
	}
	l.opened = now
	return l.expire(now)
}

func (l *rotatingLog) Write(data []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(data)
	if l.err == nil {
		now := time.Now()
		l.err = l.expire(now)
		for len(data) > 0 && l.err == nil {
			if l.size >= l.options.MaxBytes || now.Sub(l.opened) >= l.options.MaxAge {
				l.err = l.rotate(now)
				if l.err != nil {
					break
				}
			}
			chunk := min(int64(len(data)), l.options.MaxBytes-l.size)
			written, err := l.file.Write(data[:chunk])
			l.size += int64(written)
			data = data[written:]
			if err == nil && int64(written) != chunk {
				err = io.ErrShortWrite
			}
			l.err = err
		}
		if l.err != nil {
			l.err = fmt.Errorf("write daemon log %s: %w", l.name, l.err)
			l.onError(l.err)
		}
	}
	return n, nil
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.err = errors.Join(l.err, l.file.Close())
		l.file = nil
	}
	return errors.Join(l.err, l.root.Close())
}

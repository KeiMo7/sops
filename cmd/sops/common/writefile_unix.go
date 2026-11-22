//go:build unix

package common

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// fileOwner returns the numeric owner of fi.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// linkCount returns the number of hard links to fi.
func linkCount(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(st.Nlink)
}

// currentUmask returns the process umask.
func currentUmask() os.FileMode {
	// There is no way to read the umask without temporarily changing it.
	mask := syscall.Umask(0)
	syscall.Umask(mask)
	return os.FileMode(mask)
}

// syncDir flushes the directory entry created by renaming the temporary file
// over the target, so that the replacement survives a power loss. Directories
// cannot be opened for reading on every Unix system, so some failures are
// ignored.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EBADF) {
			return nil
		}
		return err
	}
	return nil
}

// guardInterrupt removes the temporary file if sops receives a termination
// signal while it is being written, and then lets the process die from the
// signal as it would have without the guard.
func guardInterrupt(tmpName string) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-ch:
			_ = os.Remove(tmpName)
			signal.Reset(sig)
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(syscall.Getpid(), s)
			}
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

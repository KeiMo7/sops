//go:build !windows && (linux || darwin || dragonfly || freebsd || openbsd)

package atomic

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// isNotASymlink reports whether err is EINVAL from readlink(2), meaning
// the path exists but is not a symbolic link — the ordinary case.
func isNotASymlink(err error) bool {
	return errors.Is(err, unix.EINVAL)
}

// errWouldBlock is matched by WriteFile to translate a contended lock into
// ErrLocked.
var errWouldBlock = unix.EWOULDBLOCK

// OSFileSystem is the real, production backend talking to the kernel.
type OSFileSystem struct{}

func (OSFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

func (OSFileSystem) Writer(f *os.File) io.Writer { return f }

func (OSFileSystem) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

func (OSFileSystem) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (OSFileSystem) Remove(name string) error { return os.Remove(name) }

func (OSFileSystem) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(name) }

func (OSFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (OSFileSystem) SyncFile(f *os.File) error { return f.Sync() }

func (OSFileSystem) SyncDir(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Lock takes an exclusive advisory lock. flock(2) locks are tied to the
// open file description and released automatically on close, so a killed
// process never leaves a lock behind. LOCK_NB makes a contended lock fail
// immediately instead of blocking the CLI.
func (OSFileSystem) Lock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func (OSFileSystem) Unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}

func (OSFileSystem) Chmod(name string, mode os.FileMode) error { return os.Chmod(name, mode) }

func (OSFileSystem) Chown(name string, uid, gid int) error { return os.Chown(name, uid, gid) }

// platformIdentity extracts dev/inode and the inode change time.
func platformIdentity(info os.FileInfo) (dev, ino uint64, ctime int64) {
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		return uint64(stat.Dev), stat.Ino, int64(stat.Ctim.Sec)*1_000_000_000 + int64(stat.Ctim.Nsec)
	}
	return 0, 0, 0
}

func platformOwner(info os.FileInfo) (uid, gid int) {
	if stat, ok := info.Sys().(*unix.Stat_t); ok {
		return int(stat.Uid), int(stat.Gid)
	}
	return -1, -1
}

// AvailableSpace reports free bytes available to an unprivileged user via
// statfs(2). The Statfs_t field names differ across Unix variants, so the
// field extraction lives in per-platform space_*.go files.
func (OSFileSystem) AvailableSpace(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return -1, err
	}
	return statfsAvailable(&st), nil
}

// IsReadOnly checks the W bit on the directory mode. This is a best-effort
// early signal; read-only mounts are still caught authoritatively by the
// actual open/rename calls.
func (OSFileSystem) IsReadOnly(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0200 == 0
}

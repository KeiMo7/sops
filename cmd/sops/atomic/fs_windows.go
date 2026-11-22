//go:build windows

package atomic

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// isNotASymlink reports whether err means the path is not a reparse point.
func isNotASymlink(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER)
}

// errWouldBlock has no direct Windows equivalent; LockFileEx failing with
// a lock violation is translated to this sentinel in Lock.
var errWouldBlock = errors.New("lock contention")

// OSFileSystem is the production backend for Windows.
type OSFileSystem struct{}

func (OSFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

func (OSFileSystem) Writer(f *os.File) io.Writer { return f }

func (OSFileSystem) Stat(name string) (os.FileInfo, error) { return os.Stat(name) }

// Rename uses MoveFileEx with REPLACE_EXISTING and WRITE_THROUGH so the
// replacement is atomic with respect to other processes and flushed to
// disk before the call returns. os.Rename on Windows already does this,
// but we keep the explicit call here to document the guarantee.
func (OSFileSystem) Rename(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func (OSFileSystem) Remove(name string) error { return os.Remove(name) }

func (OSFileSystem) ReadDir(name string) ([]os.DirEntry, error) { return os.ReadDir(name) }

func (OSFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (OSFileSystem) SyncFile(f *os.File) error { return f.Sync() }

// SyncDir is a no-op on Windows: MoveFileEx with MOVEFILE_WRITE_THROUGH
// already flushes the directory metadata.
func (OSFileSystem) SyncDir(name string) error { return nil }

// Lock takes a mandatory byte-range lock on the lock file. A contended
// lock fails immediately with ErrLocked.
func (OSFileSystem) Lock(f *os.File) error {
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1<<32-1, 1<<32-1, &ol)
	if err != nil {
		if errors.Is(err, windows.Errno(windows.ERROR_LOCK_VIOLATION)) {
			return errWouldBlock
		}
		return err
	}
	return nil
}

func (OSFileSystem) Unlock(f *os.File) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1<<32-1, 1<<32-1, &ol)
}

func (OSFileSystem) Chmod(name string, mode os.FileMode) error { return os.Chmod(name, mode) }

func (OSFileSystem) Chown(name string, uid, gid int) error {
	// Windows has no uid/gid model; os.Chown would fail. Preserve nothing.
	return nil
}

func platformIdentity(info os.FileInfo) (dev, ino uint64, ctime int64) {
	if d, ok := info.Sys().(*windows.Win32FileAttributeData); ok {
		return 0, 0, d.CreationTime.Nanoseconds()
	}
	return 0, 0, 0
}

func platformOwner(info os.FileInfo) (uid, gid int) { return -1, -1 }

func (OSFileSystem) AvailableSpace(path string) (int64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return -1, err
	}
	var free, total, totalFree uint64
	if err = windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return -1, err
	}
	return int64(free), nil
}

func (OSFileSystem) IsReadOnly(dir string) bool {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false
	}
	var attrs uint32
	attrs, err = windows.GetFileAttributes(p)
	if err != nil {
		return false
	}
	return attrs&windows.FILE_ATTRIBUTE_READONLY != 0
}

// CopyXAttr is a no-op on Windows, whose alternate data streams are not
// the POSIX xattr model and are intentionally not propagated.
func (OSFileSystem) CopyXAttr(src, dst string) error { return nil }

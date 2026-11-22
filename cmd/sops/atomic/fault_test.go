package atomic

import (
	"errors"
	"io"
	"os"
	"sync"
)

// ErrInjected is the marker error returned by FaultyFileSystem whenever a
// configured fault fires. Tests assert on this sentinel through errors.Is.
var ErrInjected = errors.New("injected I/O fault")

// errNoSpace is the disk-full error used by ENOSPC rules.
var errNoSpace = errors.New("no space left on device")

// FaultPoint names a single operation the fault layer can sabotage.
type FaultPoint string

const (
	FaultOpenFile  FaultPoint = "openfile"
	FaultWrite     FaultPoint = "write"
	FaultSync      FaultPoint = "sync"
	FaultRename    FaultPoint = "rename"
	FaultRemove    FaultPoint = "remove"
	FaultStat      FaultPoint = "stat"
	FaultChmod     FaultPoint = "chmod"
	FaultChown     FaultPoint = "chown"
	FaultLock      FaultPoint = "lock"
	FaultDirSync   FaultPoint = "dirsync"
	FaultAvailable FaultPoint = "available"
	FaultCopyXAttr FaultPoint = "copyxattr"
)

// FaultRule describes one sabotage: after Count good calls to the fault
// point, fire. A zero Count means "on the first call".
type FaultRule struct {
	Point FaultPoint
	Count int
	// ShortWrite makes the staging-file writer report half of the requested
	// bytes without an error, simulating a partial write. Only meaningful
	// for FaultWrite.
	ShortWrite bool
	// Enospc makes the fault return a disk-full-class error.
	Enospc bool
	// Match, when non-nil, only fires the rule when the path matches. This
	// lets a rule target the staging file while leaving the lock file
	// alone.
	Match func(path string) bool
}

// FaultyFileSystem wraps the real backend and applies FaultRules. It is
// test-only support and therefore lives in a _test.go file.
type FaultyFileSystem struct {
	Inner FileSystem
	mu    sync.Mutex
	rules []FaultRule
	calls map[FaultPoint]int
}

// NewFaultyFileSystem builds a fault layer over the production backend.
func NewFaultyFileSystem(rules ...FaultRule) *FaultyFileSystem {
	return &FaultyFileSystem{
		Inner: OSFileSystem{},
		rules: rules,
		calls: map[FaultPoint]int{},
	}
}

// AddRule appends a rule after construction.
func (f *FaultyFileSystem) AddRule(rule FaultRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule)
}

func (f *FaultyFileSystem) fire(point FaultPoint, path string) (FaultRule, bool) {
	// Count only the calls that are eligible to match a rule for this
	// point; calls filtered out by Match must not consume an attempt,
	// otherwise unrelated operations (e.g. removing the lock file) would
	// make the intended fault never fire.
	eligible := false
	for _, r := range f.rules {
		if r.Point == point && (r.Match == nil || r.Match(path)) {
			eligible = true
			break
		}
	}
	if !eligible {
		return FaultRule{}, false
	}
	f.calls[point]++
	n := f.calls[point]
	for _, r := range f.rules {
		if r.Point == point && n == r.Count+1 && (r.Match == nil || r.Match(path)) {
			return r, true
		}
	}
	return FaultRule{}, false
}

func (f *FaultyFileSystem) errFor(r FaultRule) error {
	if r.Enospc {
		return &os.PathError{Op: "injected", Path: "", Err: errNoSpace}
	}
	return ErrInjected
}

func (f *FaultyFileSystem) ReadDir(name string) ([]os.DirEntry, error) {
	return f.Inner.ReadDir(name)
}

func (f *FaultyFileSystem) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	f.mu.Lock()
	r, ok := f.fire(FaultOpenFile, name)
	f.mu.Unlock()
	if ok {
		return nil, f.errFor(r)
	}
	return f.Inner.OpenFile(name, flag, perm)
}

// Writer returns a fault-aware writer for the staging file and the raw
// file for everything else (lock files must not be sabotaged).
func (f *FaultyFileSystem) Writer(file *os.File) io.Writer {
	f.mu.Lock()
	armed := false
	for _, r := range f.rules {
		if r.Point == FaultWrite && (r.Match == nil || r.Match(file.Name())) {
			armed = true
			break
		}
	}
	f.mu.Unlock()
	if !armed {
		return file
	}
	return &faultWriter{fs: f, path: file.Name(), inner: file}
}

type faultWriter struct {
	fs    *FaultyFileSystem
	path  string
	inner io.Writer
}

func (w *faultWriter) Write(p []byte) (int, error) {
	w.fs.mu.Lock()
	r, fired := w.fs.fire(FaultWrite, w.path)
	w.fs.mu.Unlock()
	if fired {
		if r.ShortWrite && len(p) > 1 {
			n, err := w.inner.Write(p[:len(p)/2])
			return n, err
		}
		return 0, w.fs.errFor(r)
	}
	return w.inner.Write(p)
}

func (f *FaultyFileSystem) Stat(name string) (os.FileInfo, error) {
	f.mu.Lock()
	r, ok := f.fire(FaultStat, name)
	f.mu.Unlock()
	if ok {
		return nil, f.errFor(r)
	}
	return f.Inner.Stat(name)
}

func (f *FaultyFileSystem) Rename(oldpath, newpath string) error {
	f.mu.Lock()
	r, ok := f.fire(FaultRename, oldpath)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.Rename(oldpath, newpath)
}

func (f *FaultyFileSystem) Remove(name string) error {
	f.mu.Lock()
	r, ok := f.fire(FaultRemove, name)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.Remove(name)
}

func (f *FaultyFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return f.Inner.MkdirAll(path, perm)
}

func (f *FaultyFileSystem) SyncFile(file *os.File) error {
	f.mu.Lock()
	r, ok := f.fire(FaultSync, file.Name())
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.SyncFile(file)
}

func (f *FaultyFileSystem) SyncDir(name string) error {
	f.mu.Lock()
	r, ok := f.fire(FaultDirSync, name)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.SyncDir(name)
}

func (f *FaultyFileSystem) Lock(file *os.File) error {
	f.mu.Lock()
	r, ok := f.fire(FaultLock, file.Name())
	f.mu.Unlock()
	if ok {
		if r.Enospc {
			return f.errFor(r)
		}
		return errWouldBlock
	}
	return f.Inner.Lock(file)
}

func (f *FaultyFileSystem) Unlock(file *os.File) error { return f.Inner.Unlock(file) }

func (f *FaultyFileSystem) Chmod(name string, mode os.FileMode) error {
	f.mu.Lock()
	r, ok := f.fire(FaultChmod, name)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.Chmod(name, mode)
}

func (f *FaultyFileSystem) Chown(name string, uid, gid int) error {
	f.mu.Lock()
	r, ok := f.fire(FaultChown, name)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.Chown(name, uid, gid)
}

func (f *FaultyFileSystem) CopyXAttr(src, dst string) error {
	f.mu.Lock()
	r, ok := f.fire(FaultCopyXAttr, src)
	f.mu.Unlock()
	if ok {
		return f.errFor(r)
	}
	return f.Inner.CopyXAttr(src, dst)
}

func (f *FaultyFileSystem) AvailableSpace(path string) (int64, error) {
	f.mu.Lock()
	r, ok := f.fire(FaultAvailable, path)
	f.mu.Unlock()
	if ok {
		if r.Enospc {
			return 0, nil
		}
		return -1, f.errFor(r)
	}
	return f.Inner.AvailableSpace(path)
}

func (f *FaultyFileSystem) IsReadOnly(dir string) bool { return f.Inner.IsReadOnly(dir) }

// Calls reports how many times a fault point was consulted. Test helper.
func (f *FaultyFileSystem) Calls(point FaultPoint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[point]
}

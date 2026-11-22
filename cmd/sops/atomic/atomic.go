// Package atomic provides crash-safe, atomic replacement semantics for
// every SOPS subcommand that rewrites a file on disk.
//
// The guarantee is: at any point in time, the target path either points at
// the complete previous version or at the complete new version. A process
// killed by a signal, a power loss or an I/O failure can never leave a
// truncated or half-written file behind, and plaintext is never written to
// a world-readable location.
//
// All staging happens in a hidden file in the same directory as the target,
// so the final commit never crosses a mount point. On Unix the commit is a
// rename(2), which is atomic on POSIX filesystems; on Windows it is a
// MoveFileEx with MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH, which
// provides the same "old or new, never mixed" guarantee on NTFS. Filesystem
// specific caveats are documented in PLATFORM.md.
package atomic

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// tempPrefix / tempSuffix mark files that belong to an in-flight or
// interrupted atomic write. They are deliberately ugly so that they can be
// told apart from user data, and CleanupStaleArtifacts only ever touches
// names matching this pattern.
const (
	tempPrefix = ".sops-tmp-"
	tempSuffix = ".tmp"
	lockSuffix = ".lock"
)

// ErrConflict is returned when the target file changed between the moment
// the write started and the moment the replacement is about to be
// committed. The caller must reload the file and retry instead of
// overwriting the other writer's result.
var ErrConflict = errors.New("the target file was modified by another process; reloading and retrying is required")

// ErrLocked is returned when another SOPS process already holds the write
// lock for the target file.
var ErrLocked = errors.New("another sops process is already writing to this file")

// Stage identifies at which point of the write pipeline an error happened,
// so that user-facing messages can describe the failure precisely instead
// of dumping the raw syscall error.
type Stage string

const (
	StagePreflight Stage = "preflight"
	StageTempFile  Stage = "temporary file creation"
	StageWrite     Stage = "data write"
	StageSync      Stage = "data flush"
	StageVerify    Stage = "result verification"
	StageMetadata  Stage = "metadata preservation"
	StageCommit    Stage = "atomic commit"
	StageDirSync   Stage = "directory flush"
	StageLock      Stage = "write lock"
	StageCleanup   Stage = "cleanup"
)

// WriteError wraps a failure with the pipeline Stage it occurred in.
type WriteError struct {
	Stage Stage
	Op    string
	Err   error
}

func (e *WriteError) Error() string {
	return fmt.Sprintf("atomic write failed during %s (%s): %s", e.Stage, e.Op, e.Err.Error())
}

func (e *WriteError) Unwrap() error { return e.Err }

func wrapError(stage Stage, op string, err error) error {
	if err == nil {
		return nil
	}
	return &WriteError{Stage: stage, Op: op, Err: err}
}

// Verifier is invoked on the fully written, fsynced staging file before it
// is committed. It must return an error if the staged content does not
// satisfy the caller (for an encrypted SOPS file: it cannot be decrypted).
// A failed verification aborts the write and leaves the previous target
// completely untouched.
type Verifier func(path string) error

// WriteOptions controls a single atomic replacement.
type WriteOptions struct {
	// Path is the file that will be replaced.
	Path string
	// Data is the complete new content.
	Data []byte
	// NewFileMode is used when Path does not exist yet. It is ignored when
	// replacing an existing file, whose mode is preserved.
	NewFileMode os.FileMode
	// Verify, when non-nil, runs against the staging file before commit.
	Verify Verifier
	// Baseline, when set, is the identity recorded before processing
	// started. The commit is refused with ErrConflict if the target moved
	// away from it. When nil, a baseline is captured right after the lock
	// is acquired (a weaker guarantee that still catches writers
	// serializing through the same lock).
	Baseline *Baseline
}

// Baseline captures the on-disk identity of a target at the moment the
// caller loaded it. Pass the value from SnapshotBaseline taken before any
// processing begins so that a writer which committed in the meantime is
// detected even if the current process acquired the lock only afterwards.
type Baseline struct {
	inner targetIdentity
}

// SnapshotBaseline records the current identity of path. A non-existent
// path is a valid baseline (the file is expected to be created).
func SnapshotBaseline(path string) (Baseline, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Baseline{}, err
	}
	id, err := identityOf(defaultFS, abs)
	if err != nil {
		return Baseline{}, err
	}
	return Baseline{inner: id}, nil
}

// FileSystem is the subset of filesystem operations the atomic writer
// relies on. Production code uses OSFileSystem; tests inject a faulting
// implementation (short writes, ENOSPC, ...) without touching the real
// disk layer.
type FileSystem interface {
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	// Writer returns the io.Writer the write loop must push bytes through
	// for the given handle. The production backend returns the file
	// itself; faulting backends return a wrapper that can perform short
	// writes or fail mid-stream.
	Writer(f *os.File) io.Writer
	Stat(name string) (os.FileInfo, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error
	ReadDir(name string) ([]os.DirEntry, error)
	MkdirAll(path string, perm os.FileMode) error
	SyncFile(f *os.File) error
	SyncDir(name string) error
	Lock(f *os.File) error
	Unlock(f *os.File) error
	Chmod(name string, mode os.FileMode) error
	Chown(name string, uid, gid int) error
	CopyXAttr(src, dst string) error
	// AvailableSpace returns the number of free bytes usable by regular
	// files in the filesystem backing path. A negative return value means
	// the information is unavailable and the check is skipped.
	AvailableSpace(path string) (int64, error)
	// IsReadOnly returns true if the directory cannot be written to.
	IsReadOnly(dir string) bool
}

// defaultFS is swapped out by tests through SetFileSystem.
var defaultFS FileSystem = OSFileSystem{}

// SetFileSystem replaces the filesystem backend. It is intended for tests
// that need to inject I/O faults. Passing nil restores the real backend.
func SetFileSystem(fs FileSystem) {
	if fs == nil {
		fs = OSFileSystem{}
	}
	defaultFS = fs
}

// targetIdentity captures the on-disk identity of the target at write
// start. It is compared again right before the commit to detect concurrent
// writers that replaced the file while we were working.
type targetIdentity struct {
	exists bool
	dev    uint64
	ino    uint64
	size   int64
	mode   os.FileMode
	mtime  int64
	ctime  int64
}

func identityOf(fs FileSystem, path string) (targetIdentity, error) {
	info, err := fs.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return targetIdentity{}, nil
		}
		return targetIdentity{}, wrapError(StagePreflight, "stat target", err)
	}
	id := targetIdentity{
		exists: true,
		size:   info.Size(),
		mode:   info.Mode().Perm(),
		mtime:  info.ModTime().UnixNano(),
	}
	id.dev, id.ino, id.ctime = platformIdentity(info)
	return id, nil
}

func (id targetIdentity) changed(fs FileSystem, path string) (bool, error) {
	current, err := identityOf(fs, path)
	if err != nil {
		return false, err
	}
	if current.exists != id.exists {
		return true, nil
	}
	if !current.exists {
		return false, nil
	}
	// Device/inode change means the path was replaced (rename by another
	// writer). Size/mtime changes catch in-place modifications.
	return current.dev != id.dev || current.ino != id.ino ||
		current.size != id.size || current.mtime != id.mtime ||
		current.ctime != id.ctime, nil
}

// WriteFile atomically replaces opts.Path with opts.Data.
//
// The sequence is: lock, preflight, write staging file in the target
// directory, fsync, verify, restore metadata, re-check the baseline,
// rename, fsync the directory, unlock. Any error before the rename leaves
// the previous target byte-for-byte untouched and removes the staging
// file.
func WriteFile(opts WriteOptions) (err error) {
	if opts.Path == "" {
		return wrapError(StagePreflight, "validate options", errors.New("empty target path"))
	}
	target, err := filepath.Abs(opts.Path)
	if err != nil {
		return wrapError(StagePreflight, "resolve target path", err)
	}
	// Follow a symlink instead of replacing the link itself: os.Create
	// historically truncated the link target, and users reasonably expect
	// their symlink to survive. Staging/lock files then live next to the
	// real file (never on a different mount point).
	if _, lerr := os.Readlink(target); lerr == nil {
		resolved, rerr := filepath.EvalSymlinks(target)
		if rerr != nil {
			return wrapError(StagePreflight, "resolve target symlink", rerr)
		}
		target = resolved
	} else if !errors.Is(lerr, os.ErrInvalid) && !isNotASymlink(lerr) && !os.IsNotExist(lerr) {
		return wrapError(StagePreflight, "inspect target symlink", lerr)
	}
	dir := filepath.Dir(target)
	fs := defaultFS

	if err = preflight(fs, dir, target, len(opts.Data)); err != nil {
		return err
	}

	// The lock file lives next to the target: same directory, same
	// filesystem. It serializes concurrent SOPS writers on this path.
	lockPath := lockName(target)
	lockFile, err := fs.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return wrapError(StageLock, "open lock file", err)
	}
	// Closing the handle releases the lock on every platform. The lock
	// path itself is intentionally kept: a stable lock inode is what makes
	// the mutual exclusion reliable across rapid successive writes. A
	// stale lock from a crashed process is harmless (the flock died with
	// its process) and is reclaimed via CleanupStaleArtifacts.
	defer func() {
		_ = fs.Unlock(lockFile)
		_ = lockFile.Close()
	}()
	if err = fs.Lock(lockFile); err != nil {
		if errors.Is(err, errWouldBlock) {
			return &WriteError{Stage: StageLock, Op: "acquire lock", Err: ErrLocked}
		}
		return wrapError(StageLock, "acquire lock", err)
	}

	baseline, err := identityOf(fs, target)
	if err != nil {
		return err
	}
	// A caller-supplied baseline was captured before the lock, so it
	// covers the full processing window and detects writers that committed
	// while we were waiting.
	if opts.Baseline != nil {
		baseline = opts.Baseline.inner
	}

	// Remove leftovers from earlier, interrupted runs before we create our
	// own staging file, so they can never be confused with real data.
	if err = CleanupStaleArtifacts(target); err != nil {
		return err
	}

	tmpPath, tmpFile, err := createStagingFile(fs, dir, target)
	if err != nil {
		return err
	}
	// Hold an exclusive lock on the staging file for the whole write.
	// CleanupStaleArtifacts uses the same lock to tell a live write apart
	// from a crashed process's leftover. It is released on close.
	if err = fs.Lock(tmpFile); err != nil {
		_ = tmpFile.Close()
		_ = fs.Remove(tmpPath)
		return wrapError(StageLock, "lock staging file", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// Best-effort cleanup of our own staging file. The path carries a
		// random suffix unique to this run, so this can never remove a
		// staging file created by a concurrent process; a missing path
		// simply means the file was already moved or reclaimed.
		_ = fs.Unlock(tmpFile)
		_ = tmpFile.Close()
		if rerr := fs.Remove(tmpPath); rerr != nil && !os.IsNotExist(rerr) {
			// Nothing actionable left: the write failed and the caller has
			// the real error. The next run reclaims any leftover via
			// CleanupStaleArtifacts.
			_ = rerr
		}
	}()

	if err = writeAndSync(fs, tmpFile, tmpPath, opts.Data); err != nil {
		return err
	}

	if opts.Verify != nil {
		if err = opts.Verify(tmpPath); err != nil {
			return wrapError(StageVerify, "decrypt staged result", err)
		}
	}

	if err = preserveMetadata(fs, target, tmpPath, baseline, opts.NewFileMode); err != nil {
		return err
	}

	// Re-check the baseline under the lock. If another writer committed
	// first, refuse to clobber their result.
	changed, err := baseline.changed(fs, target)
	if err != nil {
		return err
	}
	if changed {
		return &WriteError{Stage: StageCommit, Op: "baseline comparison", Err: ErrConflict}
	}

	if err = fs.Rename(tmpPath, target); err != nil {
		return wrapError(StageCommit, "rename staging file into place", err)
	}
	committed = true
	if err = tmpFile.Close(); err != nil {
		return wrapError(StageCommit, "close staging file", err)
	}

	// Flush the directory entry so the rename survives a power loss.
	if err = fs.SyncDir(dir); err != nil {
		return wrapError(StageDirSync, "fsync parent directory", err)
	}
	return nil
}

func preflight(fs FileSystem, dir, target string, dataLen int) error {
	if info, err := fs.Stat(dir); err != nil {
		return wrapError(StagePreflight, "stat target directory", err)
	} else if !info.IsDir() {
		return wrapError(StagePreflight, "stat target directory", fmt.Errorf("%s is not a directory", dir))
	}
	if fs.IsReadOnly(dir) {
		return wrapError(StagePreflight, "check directory writability",
			fmt.Errorf("directory %s is read-only", dir))
	}
	// Note: a read-only *target* mode (e.g. 0400) is not a preflight
	// failure here. The replacement is a rename in the parent directory,
	// which needs directory write permission but not write permission on
	// the file itself; the original mode is then restored onto the new
	// inode.
	avail, err := fs.AvailableSpace(dir)
	if err != nil {
		// If the platform cannot report free space, let the actual write
		// surface ENOSPC with a stage-annotated message.
		return nil
	}
	if avail >= 0 && int64(dataLen) > avail {
		return wrapError(StagePreflight, "check available disk space",
			fmt.Errorf("not enough space: need %d bytes, %d available", dataLen, avail))
	}
	return nil
}

func stagingName(target string) string {
	base := filepath.Base(target)
	return filepath.Join(filepath.Dir(target),
		tempPrefix+base+"-"+strconv.Itoa(os.Getpid())+"-"+randomSuffix()+tempSuffix)
}

func lockName(target string) string {
	return filepath.Join(filepath.Dir(target), tempPrefix+filepath.Base(target)+lockSuffix)
}

func createStagingFile(fs FileSystem, dir, target string) (string, *os.File, error) {
	tmpPath := stagingName(target)
	// 0600: the staging file may contain plaintext-adjacent material and
	// must never be group/world readable while it exists.
	f, err := fs.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return "", nil, wrapError(StageTempFile, "create staging file in "+dir, err)
	}
	return tmpPath, f, nil
}

func writeAndSync(fs FileSystem, f *os.File, tmpPath string, data []byte) error {
	writer := fs.Writer(f)
	var n int
	for len(data) > 0 {
		written, err := writer.Write(data)
		n += written
		if err != nil {
			return wrapError(StageWrite, "write staging file", err)
		}
		if written == 0 {
			return wrapError(StageWrite, "write staging file",
				errors.New("short write: the filesystem accepted 0 bytes"))
		}
		data = data[written:]
	}
	if err := fs.SyncFile(f); err != nil {
		return wrapError(StageSync, "fsync staging file", err)
	}
	// Re-open read-only and compare lengths: a successful Write+fsync must
	// have persisted every byte. This also catches filesystems that lie
	// about short writes.
	info, err := fs.Stat(tmpPath)
	if err != nil {
		return wrapError(StageSync, "stat staging file", err)
	}
	if info.Size() != int64(n) {
		return wrapError(StageSync, "verify staging file size",
			fmt.Errorf("staging file is %d bytes, expected %d", info.Size(), n))
	}
	return nil
}

func preserveMetadata(fs FileSystem, target, tmpPath string, baseline targetIdentity, newFileMode os.FileMode) error {
	if !baseline.exists {
		mode := newFileMode
		if mode == 0 {
			mode = 0600
		}
		if err := fs.Chmod(tmpPath, mode); err != nil {
			return wrapError(StageMetadata, "set mode of new file", err)
		}
		return nil
	}
	if err := fs.Chmod(tmpPath, baseline.mode); err != nil {
		return wrapError(StageMetadata, "restore file mode", err)
	}
	if info, err := fs.Stat(target); err == nil {
		uid, gid := platformOwner(info)
		if uid >= 0 || gid >= 0 {
			if err := fs.Chown(tmpPath, uid, gid); err != nil {
				return wrapError(StageMetadata, "restore file owner", err)
			}
		}
	}
	if err := fs.CopyXAttr(target, tmpPath); err != nil {
		return wrapError(StageMetadata, "copy extended attributes", err)
	}
	return nil
}

// CleanupStaleArtifacts removes staging files and lock files left behind
// by earlier, interrupted runs for the given target path. Only names with
// the package's own tempPrefix/tempSuffix pattern are touched, so user
// data is never at risk. A staging file whose owning process is still
// alive is protected by an exclusive flock on the file itself and is
// left alone; files from crashed processes carry no live lock and are
// reclaimed. It is safe to call when nothing is stale.
func CleanupStaleArtifacts(target string) error {
	fs := defaultFS
	dir := filepath.Dir(target)
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return wrapError(StageCleanup, "read target directory", err)
	}
	base := filepath.Base(target)
	stalePrefix := tempPrefix + base
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, stalePrefix) {
			continue
		}
		isStaging := strings.HasSuffix(name, tempSuffix)
		// Lock files are never auto-removed: they are the stable inode that
		// makes mutual exclusion reliable, and a leftover one is harmless
		// because its flock died with the crashed process.
		if !isStaging {
			continue
		}
		artPath := filepath.Join(dir, name)
		if !isReclaimable(fs, artPath) {
			// Another, still-running writer owns this staging file.
			continue
		}
		if rerr := fs.Remove(artPath); rerr != nil && !os.IsNotExist(rerr) && firstErr == nil {
			firstErr = wrapError(StageCleanup, "remove stale artifact "+name, rerr)
		}
	}
	return firstErr
}

// isReclaimable opens a staging file and attempts a non-blocking exclusive
// lock. Success means no live process holds it (the creating process
// keeps the handle open for the whole write), so it is safe to delete.
func isReclaimable(fs FileSystem, path string) bool {
	f, err := fs.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		// If it cannot be opened, leave it for a later run rather than
		// risking anything.
		return false
	}
	defer f.Close()
	if err := fs.Lock(f); err != nil {
		return false
	}
	_ = fs.Unlock(f)
	return true
}

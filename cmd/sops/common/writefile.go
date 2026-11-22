package common

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/getsops/sops/v3/logging"
)

// writeLog reports problems that do not abort an in-place write, such as being
// unable to restore a file's owner, to the user.
var writeLog = logging.NewLogger("FS")

// testHookAfterTempCreate and testHookVerify are nil outside of tests. They
// make it possible to observe and fail the write at specific points.
var (
	testHookAfterTempCreate func(tmpName string)
	testHookVerify          func(tmp *os.File, data []byte) error
)

// AtomicWriteOpts describes an atomic, in-place replacement of a file.
//
// The data is written to a temporary file in the same directory as the target,
// flushed to disk, verified, given the same mode and owner as the file it
// replaces, and finally renamed over the target. If any step before the rename
// fails, the target is left untouched.
type AtomicWriteOpts struct {
	// Path is the file to replace. If the path is a symbolic link, the link's
	// target is replaced and the link itself is left untouched.
	Path string

	// Data is the complete new content of the file.
	Data []byte

	// Private forces the resulting file to be readable and writable by no one
	// but its owner: the permission bits for group and others are cleared,
	// regardless of the previous mode and of the process umask. It must be set
	// when Data is plaintext.
	Private bool
}

// AtomicWriteOpenError is returned when the target or the replacement file
// cannot be opened for writing. Callers use it to keep reporting these
// failures the same way the previous os.Create based implementations did.
type AtomicWriteOpenError struct{ Err error }

func (e *AtomicWriteOpenError) Error() string { return e.Err.Error() }

// Unwrap returns the underlying error.
func (e *AtomicWriteOpenError) Unwrap() error { return e.Err }

// WriteFileAtomic atomically replaces opts.Path with opts.Data.
//
// The data is written to a temporary file in the same directory as the target,
// flushed to disk, verified, given the same mode and owner as the file it
// replaces, and finally renamed over the target. The temporary file is created
// with mode 0600 and a recognisable name, so concurrent writes to different
// files in the same directory cannot collide and other users can never read
// the content while it is being written. If any step before the rename fails,
// the target is left unmodified and the temporary file is removed, except when
// the verification of the written data fails: in that case the temporary file
// is retained for inspection.
func WriteFileAtomic(opts AtomicWriteOpts) error {
	target, err := resolveWriteTarget(opts.Path)
	if err != nil {
		return err
	}

	existing, err := statExisting(target)
	if err != nil {
		return fmt.Errorf("could not inspect %q: %w; the original file was not modified", opts.Path, err)
	}
	if existing != nil && !existing.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace %q: it is not a regular file; the original file was not modified", opts.Path)
	}
	if existing != nil {
		if n := linkCount(existing); n > 1 {
			writeLog.Warnf("%q has %d hard links; atomically replacing it leaves the other names pointing at the previous content", opts.Path, n)
		}
		// Keep the previous behaviour for files that cannot be opened for
		// writing, even though replacing them would only require write
		// permission on the containing directory.
		f, err := os.OpenFile(target, os.O_WRONLY, 0)
		if err != nil {
			return &AtomicWriteOpenError{Err: err}
		}
		f.Close()
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, tempPattern(target))
	if err != nil {
		return &AtomicWriteOpenError{Err: err}
	}
	tmpName := tmp.Name()
	if testHookAfterTempCreate != nil {
		testHookAfterTempCreate(tmpName)
	}

	committed := false
	keepTemp := false
	defer func() {
		if committed {
			return
		}
		tmp.Close()
		if keepTemp {
			return
		}
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			writeLog.Warnf("Could not remove temporary file %q: %s", tmpName, rmErr)
		}
	}()

	// Clean up the temporary file if sops is interrupted while writing. The
	// original file is not affected by an interruption at this stage.
	stop := guardInterrupt(tmpName)
	defer stop()

	if _, err := io.Copy(tmp, bytes.NewReader(opts.Data)); err != nil {
		return fmt.Errorf("could not write temporary file %q for %q: %w; the original file was not modified", tmpName, opts.Path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("could not flush temporary file %q for %q: %w; the original file was not modified", tmpName, opts.Path, err)
	}
	verify := verifyTempFile
	if testHookVerify != nil {
		verify = testHookVerify
	}
	if err := verify(tmp, opts.Data); err != nil {
		keepTemp = true
		if opts.Private {
			return fmt.Errorf("verification of the data written for %q failed: %w; the original file was not modified and the temporary file %q was retained for inspection (it contains the plaintext output, restrict access to it)", opts.Path, err, tmpName)
		}
		return fmt.Errorf("verification of the data written for %q failed: %w; the original file was not modified and the temporary file %q was retained for inspection", opts.Path, err, tmpName)
	}

	// A new file is created with the same permissions os.Create used to give
	// it: 0666 restricted by the umask. The temporary file is kept private
	// until this point.
	mode := os.FileMode(0666) &^ currentUmask()
	if existing != nil {
		mode = existing.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	}
	if opts.Private {
		// Removing the bits for group and others leaves the setuid and setgid
		// bits alone: they matter on directories and executables, and a
		// plaintext copy of an executable is still an executable.
		mode &^= 0077
	}
	if existing != nil {
		restoreOwner(tmp, existing, opts.Path)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("could not set permissions of the replacement file for %q: %w; the original file was not modified", opts.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not close temporary file %q for %q: %w; the original file was not modified", tmpName, opts.Path, err)
	}

	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("could not replace %q: %w; the original file was not modified", opts.Path, err)
	}
	committed = true

	if err := syncDir(dir); err != nil {
		writeLog.Warnf("Could not sync directory %q after replacing %q: %s; the new content may not survive a power loss", dir, opts.Path, err)
	}
	return nil
}

// restoreOwner gives tmp the owner of existing, warning if that is not
// possible. A change is only attempted when the owner actually differs, as
// changing the owner of a file normally requires privileges.
func restoreOwner(tmp *os.File, existing os.FileInfo, path string) {
	wantUID, wantGID, ok := fileOwner(existing)
	if !ok {
		return
	}
	tmpInfo, err := tmp.Stat()
	if err != nil {
		writeLog.Warnf("Could not inspect the replacement file for %q: %s. Ownership may not be preserved.", path, err)
		return
	}
	uid, gid, ok := fileOwner(tmpInfo)
	if !ok {
		return
	}
	chownUID, chownGID := -1, -1
	if uid != wantUID {
		chownUID = wantUID
	}
	if gid != wantGID {
		chownGID = wantGID
	}
	if chownUID == -1 && chownGID == -1 {
		return
	}
	// Restore the owner before the mode, as changing the owner may clear the
	// setuid and setgid bits.
	if err := tmp.Chown(chownUID, chownGID); err != nil {
		writeLog.Warnf("Could not preserve ownership %d:%d of %q: %s. The file will keep its current owner instead.", wantUID, wantGID, path, err)
	}
}

// resolveWriteTarget returns the real file a write should go to. Symbolic
// links are followed so that the link itself is kept and its target is
// replaced.
func resolveWriteTarget(path string) (string, error) {
	current := path
	for i := 0; i < 255; i++ {
		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return current, nil
			}
			return "", fmt.Errorf("could not inspect %q: %w; the original file was not modified", path, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return current, nil
		}
		link, err := os.Readlink(current)
		if err != nil {
			return "", fmt.Errorf("could not read symbolic link %q: %w; the original file was not modified", current, err)
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(current), link)
		}
		current = filepath.Clean(link)
	}
	return "", fmt.Errorf("refusing to write through %q: too many levels of symbolic links; the original file was not modified", path)
}

func statExisting(path string) (os.FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return fi, nil
}

// tempPattern builds the name of the temporary file. os.CreateTemp replaces
// the last "*" with a random string, which keeps concurrent writers apart.
func tempPattern(target string) string {
	base := filepath.Base(target)
	const maxBase = 100
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	return "." + base + ".sops-*.tmp"
}

// verifyTempFile checks that the temporary file holds exactly data. The file
// offset is left at the end of the file.
func verifyTempFile(tmp *os.File, data []byte) error {
	want := sha256.Sum256(data)
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, tmp)
	if err != nil {
		return err
	}
	if n != int64(len(data)) {
		return fmt.Errorf("wrote %d bytes instead of %d", n, len(data))
	}
	if !bytes.Equal(h.Sum(nil), want[:]) {
		return errors.New("written content does not match the intended content")
	}
	return nil
}

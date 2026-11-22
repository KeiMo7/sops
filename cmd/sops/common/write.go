package common

import (
	"errors"
	"fmt"
	"os"

	"github.com/getsops/sops/v3/cmd/sops/atomic"
	"github.com/getsops/sops/v3/cmd/sops/codes"
)

// WriteFileOptions is the CLI-facing counterpart of atomic.WriteOptions.
type WriteFileOptions struct {
	// Path of the file to replace.
	Path string
	// Data is the complete new content.
	Data []byte
	// NewFileMode applies only when Path does not exist yet.
	NewFileMode os.FileMode
	// Verify runs against the staged, fsynced file before the commit. When
	// it fails, the previous target is left untouched. Pass nil for
	// non-encrypted output.
	Verify VerifierFunc
	// Baseline, when set, makes the write fail with a conflict if another
	// process replaced the file after the baseline was taken.
	Baseline *atomic.Baseline
}

// VerifierFunc is the CLI-facing alias of atomic.Verifier.
type VerifierFunc = atomic.Verifier

// SnapshotBaseline records the current on-disk identity of path so that a
// later WriteFile can detect a concurrent modification.
func SnapshotBaseline(path string) (atomic.Baseline, error) {
	return atomic.SnapshotBaseline(path)
}

// WriteFile atomically replaces an output file, translating any failure
// into the CLI's existing exit code (codes.CouldNotWriteOutputFile) with a
// message that names the failed pipeline stage instead of dumping the raw
// syscall error. Public parameters, exit codes and the "File written
// successfully" log line emitted by callers remain unchanged.
func WriteFile(opts WriteFileOptions) error {
	err := atomic.WriteFile(atomic.WriteOptions{
		Path:        opts.Path,
		Data:        opts.Data,
		NewFileMode: opts.NewFileMode,
		Verify:      opts.Verify,
		Baseline:    opts.Baseline,
	})
	if err == nil {
		return nil
	}
	var writeErr *atomic.WriteError
	if errors.As(err, &writeErr) {
		return NewExitError(
			fmt.Sprintf("Could not write output file: failed during %s: %s",
				writeErr.Stage, writeErr.Err),
			codes.CouldNotWriteOutputFile)
	}
	return NewExitError(fmt.Sprintf("Could not write output file: %s", err),
		codes.CouldNotWriteOutputFile)
}

// IsWriteConflict reports whether an error means another process won the
// race for this file. Callers use it to produce an explicit, readable
// message instead of a generic write failure.
func IsWriteConflict(err error) bool {
	return errors.Is(err, atomic.ErrConflict)
}

// IsWriteLocked reports whether another SOPS process currently holds the
// write lock for the target.
func IsWriteLocked(err error) bool {
	return errors.Is(err, atomic.ErrLocked)
}

// CleanupStaleArtifacts removes staging files and locks left behind by
// interrupted runs for target.
func CleanupStaleArtifacts(target string) error {
	return atomic.CleanupStaleArtifacts(target)
}

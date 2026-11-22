package atomic

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFS makes sure every test starts and ends on the real backend even
// if an earlier test panicked while a fault layer was installed.
func resetFS(t *testing.T) {
	t.Helper()
	SetFileSystem(nil)
	t.Cleanup(func() { SetFileSystem(nil) })
}

func writeSample(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o640))
}

// --- Basic replacement semantics -------------------------------------------------

func TestWriteFileReplacesContentAtomically(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, `{"old":true}`)

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte(`{"new":true}`)}))

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, `{"new":true}`, string(got))
}

func TestWriteFileCreatesNewFile(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "fresh.json")

	require.NoError(t, WriteFile(WriteOptions{
		Path:        target,
		Data:        []byte("created"),
		NewFileMode: 0o644,
	}))
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestWriteFileEmptyFile(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "empty.json")
	writeSample(t, target, "")

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("")}))
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestWriteFileLargeFile(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "big.bin")
	writeSample(t, target, "old")

	payload := make([]byte, 32*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: payload}))

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Len(t, got, len(payload))
	assert.Equal(t, payload, got)
}

func TestWriteFileSingleByteFile(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "one.json")
	writeSample(t, target, "x")
	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("y")}))
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "y", string(got))
}

// --- No partial state on failure --------------------------------------------------

func TestWriteFailurePreservesPreviousContent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "precious-original")

	for _, fault := range []FaultPoint{FaultWrite, FaultSync, FaultRename, FaultChmod} {
		t.Run(string(fault), func(t *testing.T) {
			resetFS(t)
			fs := NewFaultyFileSystem(FaultRule{Point: fault, Match: func(p string) bool {
				return !strings.HasSuffix(p, lockSuffix)
			}})
			SetFileSystem(fs)

			err := WriteFile(WriteOptions{Path: target, Data: []byte("half-written")})
			require.Error(t, err)

			got, readErr := os.ReadFile(target)
			require.NoError(t, readErr, "original file must remain readable")
			assert.Equal(t, "precious-original", string(got),
				"a failure during %s must never touch the previous version", fault)

			assertNoStagingFiles(t, dir)
		})
	}
}

func TestShortWriteStillProducesCompleteFile(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")

	fs := NewFaultyFileSystem(FaultRule{Point: FaultWrite, ShortWrite: true})
	SetFileSystem(fs)

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("0123456789-complete")}))
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "0123456789-complete", string(got))
}

func TestDiskFullAtWriteLeavesOriginalUntouched(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "keep-me")

	fs := NewFaultyFileSystem(FaultRule{Point: FaultWrite, Enospc: true})
	SetFileSystem(fs)

	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), string(StageWrite)))

	got, _ := os.ReadFile(target)
	assert.Equal(t, "keep-me", string(got))
	assertNoStagingFiles(t, dir)
}

func TestPreflightDiskFullFailsBeforeTouchingTarget(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "keep-me")

	fs := NewFaultyFileSystem(FaultRule{Point: FaultAvailable, Enospc: true})
	SetFileSystem(fs)

	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	var we *WriteError
	require.True(t, errors.As(err, &we))
	assert.Equal(t, StagePreflight, we.Stage)

	got, _ := os.ReadFile(target)
	assert.Equal(t, "keep-me", string(got))
}

func TestReadOnlyDirectoryFailsPreflight(t *testing.T) {
	resetFS(t)
	if os.Geteuid() == 0 {
		t.Skip("read-only directory checks are meaningless for root")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "keep-me")
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	var we *WriteError
	require.True(t, errors.As(err, &we))
	assert.Equal(t, StagePreflight, we.Stage)

	got, _ := os.ReadFile(target)
	assert.Equal(t, "keep-me", string(got))
}

// --- Metadata preservation --------------------------------------------------------

func TestWriteFilePreservesMode(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400} {
		target := filepath.Join(dir, "m"+mode.String())
		writeSample(t, target, "old")
		require.NoError(t, os.Chmod(target, mode))

		require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))

		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm(), "mode not preserved for %s", mode)
	}
}

func TestWriteFilePreservesOwner(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "owned.json")
	writeSample(t, target, "old")
	orig, err := os.Stat(target)
	require.NoError(t, err)

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))

	after, err := os.Stat(target)
	require.NoError(t, err)
	assertOwnerUnchanged(t, orig, after)
}

func TestWriteFilePreservesSymlink(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	writeSample(t, real, "old")
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.Symlink(real, link))

	require.NoError(t, WriteFile(WriteOptions{Path: link, Data: []byte("via-link")}))

	// The symlink itself must still be a symlink pointing at the same target.
	target, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, real, target)
	got, err := os.ReadFile(real)
	require.NoError(t, err)
	assert.Equal(t, "via-link", string(got))
}

func TestHardLinkBehaviorIsDocumented(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	writeSample(t, a, "shared-original")
	require.NoError(t, os.Link(a, b))

	require.NoError(t, WriteFile(WriteOptions{Path: a, Data: []byte("rewritten-a")}))

	// Rename-based replacement gives `a` a fresh inode; the other hard link
	// keeps the previous content by design (see PLATFORM.md).
	ia, err := os.Stat(a)
	require.NoError(t, err)
	ib, err := os.Stat(b)
	require.NoError(t, err)
	assert.NotEqual(t, inodeOf(ia), inodeOf(ib))
	assert.NotZero(t, inodeOf(ia))
	assert.NotZero(t, inodeOf(ib))
	gotB, _ := os.ReadFile(b)
	assert.Equal(t, "shared-original", string(gotB))
}

func TestStagingFileIsNeverWorldReadable(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")

	var seenModes []os.FileMode
	fs := &recordingFS{Inner: OSFileSystem{}, onChmod: func(name string, mode os.FileMode) {
		if strings.HasPrefix(filepath.Base(name), tempPrefix) {
			seenModes = append(seenModes, mode)
		}
	}}
	SetFileSystem(fs)

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))
	require.NotEmpty(t, seenModes)
	for _, m := range seenModes {
		assert.Equal(t, os.FileMode(0o640), m, "staging file must never be made looser than the original 0640")
	}
	// And the final file keeps the original mode.
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

// --- Verification gate ------------------------------------------------------------

func TestVerifierFailureAbortsReplacement(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "good-version")

	err := WriteFile(WriteOptions{
		Path:   target,
		Data:   []byte("would-be-bad"),
		Verify: func(path string) error { return errors.New("cannot decrypt staged file") },
	})
	require.Error(t, err)
	var we *WriteError
	require.True(t, errors.As(err, &we))
	assert.Equal(t, StageVerify, we.Stage)

	got, _ := os.ReadFile(target)
	assert.Equal(t, "good-version", string(got))
	assertNoStagingFiles(t, dir)
}

func TestVerifierSuccessAllowsReplacement(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")

	called := false
	require.NoError(t, WriteFile(WriteOptions{
		Path: target,
		Data: []byte("new"),
		Verify: func(path string) error {
			called = true
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "new", string(data))
			return nil
		},
	}))
	assert.True(t, called)
}

// --- Concurrency ------------------------------------------------------------------

func TestConcurrentWritersOneWinsOneGetsConflictOrLock(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "v0")

	const writers = 8
	var wg sync.WaitGroup
	results := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every writer loads the same v0 baseline before any work
			// starts, mirroring a real CLI that reads the file, processes
			// it, then writes it back.
			baseline, berr := SnapshotBaseline(target)
			if berr != nil {
				results <- berr
				return
			}
			<-start
			err := WriteFile(WriteOptions{
				Path:     target,
				Data:     []byte("v" + strings.Repeat(string(rune('1'+i)), i+1)),
				Baseline: &baseline,
			})
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict) || errors.Is(err, ErrLocked):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one writer must commit")
	assert.Equal(t, writers-1, conflicts)

	// The surviving content must be one complete, self-consistent version,
	// never mixed bytes from two writers.
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.NotEmpty(t, got)
	assert.Equal(t, "v", string(got[0]))
	// Exactly one writer's payload survived: payloads are "v", "v11",
	// "v222", ... so the tail must be a single repeated rune.
	tail := string(got[1:])
	if len(tail) > 0 {
		for _, r := range tail {
			assert.Equal(t, rune(tail[0]), r, "surviving file mixes bytes from two writers")
		}
	}
	assertNoStagingFiles(t, dir)
}

func TestExternalBaselineChangeIsDetected(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "baseline")

	// Sabotage the baseline between identity capture and commit: another
	// process replaced the file while we staged.
	inner := OSFileSystem{}
	fs := &baselineChangingFS{Inner: inner, target: target}
	SetFileSystem(fs)

	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConflict), "got %v", err)

	got, _ := os.ReadFile(target)
	assert.Equal(t, "external-writer", string(got))
}

// --- Stale artifact handling ------------------------------------------------------

func TestCleanupStaleArtifacts(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "current")

	stale := stagingName(target)
	require.NoError(t, os.WriteFile(stale, []byte("leftover"), 0o600))
	staleLock := lockName(target)
	require.NoError(t, os.WriteFile(staleLock, []byte(""), 0o600))
	// An unrelated temp file must be left alone.
	untouched := filepath.Join(dir, tempPrefix+"other.json"+tempSuffix)
	require.NoError(t, os.WriteFile(untouched, []byte("x"), 0o600))

	require.NoError(t, CleanupStaleArtifacts(target))
	// The crashed process's staging file is reclaimed...
	_, err := os.Stat(stale)
	assert.True(t, os.IsNotExist(err))
	// ...but the lock file is deliberately kept (stable mutex inode).
	_, err = os.Stat(staleLock)
	assert.NoError(t, err)
	// ...and other files' staging files are never touched.
	_, err = os.Stat(untouched)
	assert.NoError(t, err)
}

func TestInterruptedRunArtifactsCleanedOnNextRun(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "current")

	// Simulate a crash at the rename step: the staging file survives
	// because the deferred cleanup also fails through the same fault
	// layer, exactly like a process killed before its cleanup ran.
	fs := NewFaultyFileSystem(
		FaultRule{Point: FaultRename},
		FaultRule{Point: FaultRemove, Match: func(p string) bool {
			return strings.HasSuffix(p, tempSuffix)
		}},
	)
	SetFileSystem(fs)
	require.Error(t, WriteFile(WriteOptions{Path: target, Data: []byte("first")}))
	entries, _ := os.ReadDir(dir)
	require.True(t, containsStaging(entries), "a staging file should remain after the crash")

	// Second run reclaims the leftover and succeeds.
	SetFileSystem(nil)
	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("second")}))
	assertNoStagingFiles(t, dir)
	got, _ := os.ReadFile(target)
	assert.Equal(t, "second", string(got))
}

func TestNoStagingArtifactsAfterSuccessfulWrite(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")
	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))
	assertNoStagingFiles(t, dir)
}

// A batch processes files one by one: a failure on one file must leave it
// untouched while the others still commit, mirroring updatekeys behavior.
func TestBatchFailureIsolatesFiles(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	files := make([]string, 4)
	for i := range files {
		files[i] = filepath.Join(dir, fmt.Sprintf("file%d.json", i))
		writeSample(t, files[i], "original")
	}

	for i, path := range files {
		if i == 2 {
			// This file's directory becomes unwritable only for its write:
			// simulate a per-file failure by pointing the verifier at a
			// broken document instead.
			err := WriteFile(WriteOptions{
				Path: path,
				Data: []byte("new"),
				Verify: func(string) error {
					return errors.New("per-file verification failure")
				},
			})
			require.Error(t, err)
			continue
		}
		require.NoError(t, WriteFile(WriteOptions{
			Path: path,
			Data: []byte("updated"),
		}))
	}

	for i, path := range files {
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		if i == 2 {
			assert.Equal(t, "original", string(got), "failed file must keep its previous version")
		} else {
			assert.Equal(t, "updated", string(got), "sibling files must still commit")
		}
	}
	assertNoStagingFiles(t, dir)
}

// --- Error shape ------------------------------------------------------------------

func TestWriteErrorNamesStageAndUnwraps(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")
	fs := NewFaultyFileSystem(FaultRule{Point: FaultSync, Enospc: true})
	SetFileSystem(fs)

	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	var we *WriteError
	require.True(t, errors.As(err, &we))
	assert.Equal(t, StageSync, we.Stage)
	assert.Contains(t, we.Error(), "atomic write failed during")
}

func TestLockContentionReportsLocked(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeSample(t, target, "old")

	fs := NewFaultyFileSystem(FaultRule{
		Point: FaultLock,
		Match: func(p string) bool { return strings.HasSuffix(p, lockSuffix) },
	})
	SetFileSystem(fs)
	err := WriteFile(WriteOptions{Path: target, Data: []byte("new")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLocked))
}

// --- Helpers ----------------------------------------------------------------------

func assertNoStagingFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		// Only staging files must disappear. The lock file is a stable
		// mutex inode and is intentionally retained.
		if strings.HasPrefix(name, tempPrefix) && strings.HasSuffix(name, tempSuffix) {
			t.Fatalf("stale staging file left behind: %s", name)
		}
	}
}

func containsStaging(entries []os.DirEntry) bool {
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) && strings.HasSuffix(e.Name(), tempSuffix) {
			return true
		}
	}
	return false
}

// recordingFS delegates everything but records Chmod calls for assertions.
type recordingFS struct {
	Inner   FileSystem
	onChmod func(name string, mode os.FileMode)
}

func (r *recordingFS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return r.Inner.OpenFile(name, flag, perm)
}
func (r *recordingFS) Writer(f *os.File) io.Writer {
	return f
}
func (r *recordingFS) Stat(name string) (os.FileInfo, error) { return r.Inner.Stat(name) }
func (r *recordingFS) Rename(o, n string) error              { return r.Inner.Rename(o, n) }
func (r *recordingFS) Remove(name string) error              { return r.Inner.Remove(name) }
func (r *recordingFS) ReadDir(name string) ([]os.DirEntry, error) {
	return r.Inner.ReadDir(name)
}
func (r *recordingFS) MkdirAll(p string, m os.FileMode) error { return r.Inner.MkdirAll(p, m) }
func (r *recordingFS) SyncFile(f *os.File) error              { return r.Inner.SyncFile(f) }
func (r *recordingFS) SyncDir(name string) error              { return r.Inner.SyncDir(name) }
func (r *recordingFS) Lock(f *os.File) error                  { return r.Inner.Lock(f) }
func (r *recordingFS) Unlock(f *os.File) error                { return r.Inner.Unlock(f) }
func (r *recordingFS) Chmod(name string, mode os.FileMode) error {
	if r.onChmod != nil {
		r.onChmod(name, mode)
	}
	return r.Inner.Chmod(name, mode)
}
func (r *recordingFS) Chown(name string, u, g int) error { return r.Inner.Chown(name, u, g) }
func (r *recordingFS) CopyXAttr(s, d string) error       { return r.Inner.CopyXAttr(s, d) }
func (r *recordingFS) AvailableSpace(p string) (int64, error) {
	return r.Inner.AvailableSpace(p)
}
func (r *recordingFS) IsReadOnly(p string) bool { return r.Inner.IsReadOnly(p) }

// baselineChangingFS rewrites the target from an "external" writer on the
// second Stat of the target: the first Stat is the baseline capture, the
// second is the pre-commit comparison.
type baselineChangingFS struct {
	Inner     FileSystem
	target    string
	statCount int
	mu        sync.Mutex
}

func (b *baselineChangingFS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return b.Inner.OpenFile(name, flag, perm)
}
func (b *baselineChangingFS) Writer(f *os.File) io.Writer { return f }
func (b *baselineChangingFS) Stat(name string) (os.FileInfo, error) {
	if name == b.target {
		b.mu.Lock()
		b.statCount++
		fire := b.statCount == 2
		b.mu.Unlock()
		if fire {
			_ = os.WriteFile(b.target, []byte("external-writer"), 0o640)
			_ = os.Chtimes(b.target, time.Now().Add(time.Second), time.Now().Add(time.Second))
		}
	}
	return b.Inner.Stat(name)
}
func (b *baselineChangingFS) Rename(o, n string) error { return b.Inner.Rename(o, n) }
func (b *baselineChangingFS) Remove(name string) error { return b.Inner.Remove(name) }
func (b *baselineChangingFS) ReadDir(name string) ([]os.DirEntry, error) {
	return b.Inner.ReadDir(name)
}
func (b *baselineChangingFS) MkdirAll(p string, m os.FileMode) error {
	return b.Inner.MkdirAll(p, m)
}
func (b *baselineChangingFS) SyncFile(f *os.File) error { return b.Inner.SyncFile(f) }
func (b *baselineChangingFS) SyncDir(name string) error { return b.Inner.SyncDir(name) }
func (b *baselineChangingFS) Lock(f *os.File) error     { return b.Inner.Lock(f) }
func (b *baselineChangingFS) Unlock(f *os.File) error   { return b.Inner.Unlock(f) }
func (b *baselineChangingFS) Chmod(name string, mode os.FileMode) error {
	return b.Inner.Chmod(name, mode)
}
func (b *baselineChangingFS) Chown(name string, u, g int) error {
	return b.Inner.Chown(name, u, g)
}
func (b *baselineChangingFS) CopyXAttr(s, d string) error { return b.Inner.CopyXAttr(s, d) }
func (b *baselineChangingFS) AvailableSpace(p string) (int64, error) {
	return b.Inner.AvailableSpace(p)
}
func (b *baselineChangingFS) IsReadOnly(p string) bool { return b.Inner.IsReadOnly(p) }

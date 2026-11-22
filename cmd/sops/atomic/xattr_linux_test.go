//go:build linux

package atomic

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWriteFilePreservesXAttr(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "xattr.json")
	writeSample(t, target, "old")

	require.NoError(t, unix.Setxattr(target, "user.sops-test", []byte("attr-value"), 0))
	// Probe whether the filesystem actually supports user xattrs.
	if _, err := unix.Getxattr(target, "user.sops-test", nil); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
			t.Skip("filesystem does not support user extended attributes")
		}
	}

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))

	buf := make([]byte, 64)
	n, err := unix.Getxattr(target, "user.sops-test", buf)
	require.NoError(t, err)
	assert.Equal(t, "attr-value", string(buf[:n]))
}

func TestWriteFilePreservesMultipleXAttrs(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "multi.json")
	writeSample(t, target, "old")

	attrs := map[string]string{
		"user.sops-a": "one",
		"user.sops-b": "two-two",
	}
	for name, value := range attrs {
		if err := unix.Setxattr(target, name, []byte(value), 0); err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				t.Skip("xattr not supported")
			}
			require.NoError(t, err)
		}
	}

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))

	buf := make([]byte, 64)
	for name, want := range attrs {
		n, err := unix.Getxattr(target, name, buf)
		require.NoError(t, err)
		assert.Equal(t, want, string(buf[:n]), "attribute %s", name)
	}
}

func TestStagingFileModeIsRestricted(t *testing.T) {
	resetFS(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "mode.json")
	writeSample(t, target, "old")

	var stagingModes []os.FileMode
	fs := &modeRecordingFS{Inner: OSFileSystem{}, onStat: func(name string) {
		if filepath.Dir(name) == dir && len(filepath.Base(name)) > len(tempPrefix) &&
			name[:len(dir)+1+len(tempPrefix)] == dir+"/"+tempPrefix &&
			hasSuffix(name, tempSuffix) {
			if info, err := os.Stat(name); err == nil {
				stagingModes = append(stagingModes, info.Mode().Perm())
			}
		}
	}}
	SetFileSystem(fs)

	require.NoError(t, WriteFile(WriteOptions{Path: target, Data: []byte("new")}))
	require.NotEmpty(t, stagingModes)
	for _, m := range stagingModes {
		assert.Equal(t, os.FileMode(0o600), m, "staging file must be 0600 while content is written")
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

type modeRecordingFS struct {
	Inner  FileSystem
	onStat func(name string)
}

func (m *modeRecordingFS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return m.Inner.OpenFile(name, flag, perm)
}
func (m *modeRecordingFS) Writer(f *os.File) io.Writer { return f }
func (m *modeRecordingFS) Stat(name string) (os.FileInfo, error) {
	if m.onStat != nil {
		m.onStat(name)
	}
	return m.Inner.Stat(name)
}
func (m *modeRecordingFS) Rename(o, n string) error { return m.Inner.Rename(o, n) }
func (m *modeRecordingFS) Remove(name string) error { return m.Inner.Remove(name) }
func (m *modeRecordingFS) ReadDir(name string) ([]os.DirEntry, error) {
	return m.Inner.ReadDir(name)
}
func (m *modeRecordingFS) MkdirAll(p string, mode os.FileMode) error {
	return m.Inner.MkdirAll(p, mode)
}
func (m *modeRecordingFS) SyncFile(f *os.File) error { return m.Inner.SyncFile(f) }
func (m *modeRecordingFS) SyncDir(name string) error { return m.Inner.SyncDir(name) }
func (m *modeRecordingFS) Lock(f *os.File) error     { return m.Inner.Lock(f) }
func (m *modeRecordingFS) Unlock(f *os.File) error   { return m.Inner.Unlock(f) }
func (m *modeRecordingFS) Chmod(name string, mode os.FileMode) error {
	return m.Inner.Chmod(name, mode)
}
func (m *modeRecordingFS) Chown(name string, u, g int) error { return m.Inner.Chown(name, u, g) }
func (m *modeRecordingFS) CopyXAttr(s, d string) error       { return m.Inner.CopyXAttr(s, d) }
func (m *modeRecordingFS) AvailableSpace(p string) (int64, error) {
	return m.Inner.AvailableSpace(p)
}
func (m *modeRecordingFS) IsReadOnly(p string) bool { return m.Inner.IsReadOnly(p) }
